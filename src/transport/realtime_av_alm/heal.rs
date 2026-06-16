//! ALM-C — multi-parent subscription + rapid re-parenting state machine
//! for application-layer multicast realtime A/V (CIRISEdge v3.8.0).
//!
//! ## Churn problem
//!
//! In an ALM tree, when a parent relay drops mid-call, ALL of its
//! downstream peers lose stream. Recovery via re-parenting takes
//! seconds; for interactive video at 30 fps that's catastrophic.
//!
//! ## Mitigation
//!
//! 1. **Multi-parent subscription** — each receiver subscribes to
//!    `N_PARENTS` (default 2) parents for the same (stream,
//!    sub_stream_path). Duplicate chunks arrive; the receiver dedups
//!    by `(epoch, chunk_seq)` (the stream + sub-stream are implicit —
//!    one subscription instance owns one (stream, sub-stream)). A
//!    primary drop is masked by the backup.
//! 2. **Rapid re-parenting** — heartbeat per parent; on parent silence
//!    past [`PARENT_SILENCE_HEAL_MS`], drop subscription, query for a
//!    fresh candidate, and subscribe to a new one within ~RTT.
//! 3. **Bandwidth overhead** — multi-parent subscription doubles
//!    incoming bandwidth (≈ 2× downlink) per subscription instance.
//!    With MDC (CIRISEdge#128), a receiver running K sub-streams
//!    spins up K subscription instances → K × 2 × bandwidth overall.
//!    This overhead is **accepted** for interactive video — the
//!    alternative (single-parent + reparent on drop) loses seconds of
//!    stream at 30 fps, which is catastrophic for interactivity.
//!
//! ## HNDL posture
//!
//! The chunks themselves are already AEAD-protected by the substrate
//! (outer AEAD with per-link transit keys; inner with epoch DEK).
//! Multi-parent doesn't change this — each parent's chunks are sealed
//! with that parent's transit key. The dedup is on `(epoch, chunk_seq)`
//! which sits in the cleartext header of
//! [`super::super::realtime_av::SealedAvChunk`]. No new HNDL surface.
//!
//! ## MDC mode — CIRISEdge#128
//!
//! [`MultiParentSubscription`] carries a `sub_stream_path` field —
//! empty for opaque mode, non-empty for MDC. The dedup key on
//! incoming chunks remains `(epoch, chunk_seq)` because the
//! sub_stream_path is implicit per-subscription (each instance owns
//! one sub-stream). A receiver running K MDC sub-streams creates K
//! [`MultiParentSubscription`] instances, each with its own
//! `sub_stream_path` + dedup ring.
//!
//! ## Composition
//!
//! - This module is **pure state machine** — no async, no Tokio task
//!   driver. The caller drives [`MultiParentSubscription::tick`].
//! - Wire-level subscribe / unsubscribe to the new parent's
//!   [`super::super::realtime_av_relay::RelayNode`] is the **caller's**
//!   responsibility — ALM-C returns [`HealAction`]s describing the
//!   recovery steps; the caller invokes the relay subscribe surface
//!   and reports back via [`MultiParentSubscription::apply_heal`].

use std::collections::{HashMap, HashSet, VecDeque};

use crate::transport::realtime_av::{ChunkSeq, Epoch, StreamId};

use super::capacity::{PeerKeyId, SubStreamPath};
use super::join::JoinPlan;

// ─── Constants ───────────────────────────────────────────────────────

/// Dedup-ring capacity in chunks. At 30 fps this covers roughly 33 s
/// of stream history.
pub const DEDUP_RING_CAPACITY: usize = 1024;

/// Threshold (unix ms) after which a parent's silence triggers a heal.
/// Cancels three missed heartbeats at the default
/// [`HEARTBEAT_INTERVAL_MS`] cadence.
pub const PARENT_SILENCE_HEAL_MS: u64 = 1_500;

/// Expected heartbeat / chunk-flow interval (unix ms).
pub const HEARTBEAT_INTERVAL_MS: u64 = 500;

/// Minimum delay between successive re-parenting attempts (unix ms).
pub const REPARENT_BACKOFF_MS: u64 = 250;

// ─── Dedup ring ──────────────────────────────────────────────────────

/// Bounded FIFO ring buffer of recently-seen chunk keys. Order matters
/// (FIFO eviction); the receiver tolerates out-of-order chunk delivery
/// within the ring window.
///
/// The ring is keyed by `(epoch, chunk_seq)` — the `stream_id` +
/// `sub_stream_path` are implicit because one
/// [`MultiParentSubscription`] owns exactly one (stream, sub-stream).
#[derive(Debug, Clone)]
pub struct DedupRing {
    buf: VecDeque<(Epoch, ChunkSeq)>,
    seen: HashSet<(Epoch, ChunkSeq)>,
    capacity: usize,
}

impl DedupRing {
    /// Construct an empty ring with the given capacity.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: VecDeque::with_capacity(capacity),
            seen: HashSet::with_capacity(capacity),
            capacity,
        }
    }

    /// Observe a `(epoch, chunk_seq)` key. Returns `true` if this is
    /// the first time the key has been seen since (re-)entering the
    /// ring window; `false` if the key is currently in the ring.
    pub fn observe(&mut self, epoch: Epoch, chunk_seq: ChunkSeq) -> bool {
        let key = (epoch, chunk_seq);
        if !self.seen.insert(key) {
            return false;
        }
        self.buf.push_back(key);
        if self.buf.len() > self.capacity {
            if let Some(evicted) = self.buf.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }

    /// Current number of keys retained in the ring.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Whether the ring currently retains any keys.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

// ─── Outcomes / actions ──────────────────────────────────────────────

/// Classification returned by [`MultiParentSubscription::observe_chunk`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObserveOutcome {
    /// First time we've seen this chunk; caller should deliver to the
    /// consumer (decrypt, hand to the codec, etc.).
    FirstDelivery,
    /// Duplicate from a backup parent; caller drops silently.
    Duplicate,
    /// Chunk arrived from a peer we don't have subscribed (rare;
    /// either a stale subscription that the wire layer hasn't torn
    /// down yet, or attacker injection). Caller drops; the key is NOT
    /// inserted into the dedup ring (an attacker must not be able to
    /// poison the ring).
    UnknownParent,
}

/// A recovery action emitted by [`MultiParentSubscription::tick`]. The
/// caller is responsible for the actual wire-level work (querying the
/// ALM-B planner, subscribing / unsubscribing the relay) and reports
/// back via [`MultiParentSubscription::apply_heal`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealAction {
    /// A parent has been silent past [`PARENT_SILENCE_HEAL_MS`]. The
    /// caller should:
    ///   1. Query ALM-B's [`super::join::AlmJoinPlanner`] for a
    ///      replacement candidate (use [`super::join::AlmJoinPlanner::plan_for_substream`]
    ///      when this subscription is in MDC mode).
    ///   2. Subscribe to the new parent's [`super::super::realtime_av_relay::RelayNode`].
    ///   3. Report the outcome via
    ///      [`MultiParentSubscription::apply_heal`] —
    ///      `RemoveParent(dead)` then `AddParent(new)`.
    ReParent {
        /// Federation `key_id` of the silent parent.
        dead: PeerKeyId,
    },
    /// All backups have been promoted and the primary is gone too; the
    /// subscription is in a degraded state. The caller should emit an
    /// upstream-rebuild signal to the UX layer and ask ALM-B for a
    /// fresh top-level [`JoinPlan`].
    UpstreamRebuildRequired,
}

/// Outcome the caller reports back to
/// [`MultiParentSubscription::apply_heal`] after acting on a
/// [`HealAction`] (or after a planner-initiated reshuffle).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealApplyOutcome {
    /// Caller successfully subscribed to a new parent (added to
    /// `active_parents`). The parent's liveness timestamp is seeded
    /// to `0` (the public path is wall-clock-agnostic; use
    /// [`MultiParentSubscription::add_parent_with_liveness`] to seed
    /// from a specific clock).
    AddParent(PeerKeyId),
    /// Caller unsubscribed from a parent (removed from
    /// `active_parents`). Liveness state for the removed parent is
    /// dropped.
    RemoveParent(PeerKeyId),
    /// Caller promoted a backup to the primary slot.
    PromoteToPrimary(PeerKeyId),
}

// ─── Multi-parent subscription ───────────────────────────────────────

/// Per-(receiver, stream, sub_stream_path) multi-parent subscription
/// state. Owns the dedup ring + per-parent liveness clock; emits
/// [`HealAction`]s on [`Self::tick`].
///
/// MDC mode (CIRISEdge#128): one instance per sub-stream the receiver
/// consumes. A receiver running full-holographic 4-way MDC creates 4
/// instances, each with its own `sub_stream_path` + dedup ring.
/// Empty `sub_stream_path` = opaque-mode subscription (whole stream).
#[derive(Debug, Clone)]
pub struct MultiParentSubscription {
    /// The stream this subscription is for.
    pub stream_id: StreamId,
    /// MDC sub-stream path this subscription owns. Empty for
    /// opaque-mode (whole-stream) subscriptions; non-empty for MDC.
    /// See [`SubStreamPath`].
    pub sub_stream_path: SubStreamPath,
    /// Current primary parent. On a primary drop the caller may
    /// promote a backup via [`HealApplyOutcome::PromoteToPrimary`].
    pub primary_parent: PeerKeyId,
    /// Backup parents in priority order. ALM-B seeds this; the
    /// caller walks it for replacements on heal.
    pub backup_parents: Vec<PeerKeyId>,
    /// All parents this receiver is currently subscribed to. Equals
    /// `{primary_parent} ∪ backup_parents` in steady state.
    pub active_parents: HashSet<PeerKeyId>,
    /// Seen-chunks dedup ring. See [`DedupRing`].
    pub seen_chunks: DedupRing,
    /// Per-parent last-chunk-received timestamp (unix ms).
    pub parent_liveness: HashMap<PeerKeyId, u64>,
}

impl MultiParentSubscription {
    /// Construct a new multi-parent subscription from a `JoinPlan`.
    ///
    /// `sub_stream_path` is the MDC dyadic path (empty for opaque-mode
    /// / whole-stream). The receiver is subscribed to the primary +
    /// every entry in the backup list at construction time; liveness
    /// for each parent is seeded to `0`.
    ///
    /// Liveness is left at `0` rather than the construction-time wall
    /// clock so that callers who *want* immediate heal on a parent
    /// that never delivers can simply skip the "warmup" tick.
    #[must_use]
    pub fn new(stream_id: StreamId, sub_stream_path: SubStreamPath, plan: JoinPlan) -> Self {
        let JoinPlan {
            primary_parent,
            backup_parents,
            stream_bitrate_mbps: _,
        } = plan;
        let mut active_parents = HashSet::with_capacity(1 + backup_parents.len());
        active_parents.insert(primary_parent.clone());
        for p in &backup_parents {
            active_parents.insert(p.clone());
        }
        let mut parent_liveness = HashMap::with_capacity(active_parents.len());
        for p in &active_parents {
            parent_liveness.insert(p.clone(), 0);
        }
        Self {
            stream_id,
            sub_stream_path,
            primary_parent,
            backup_parents,
            active_parents,
            seen_chunks: DedupRing::with_capacity(DEDUP_RING_CAPACITY),
            parent_liveness,
        }
    }

    /// Receiver-side hook: called when a chunk arrives from any
    /// parent.
    pub fn observe_chunk(
        &mut self,
        from_parent: &PeerKeyId,
        epoch: Epoch,
        chunk_seq: ChunkSeq,
        wall_clock_unix_ms: u64,
    ) -> ObserveOutcome {
        if !self.active_parents.contains(from_parent) {
            return ObserveOutcome::UnknownParent;
        }
        self.parent_liveness
            .insert(from_parent.clone(), wall_clock_unix_ms);
        if self.seen_chunks.observe(epoch, chunk_seq) {
            ObserveOutcome::FirstDelivery
        } else {
            ObserveOutcome::Duplicate
        }
    }

    /// Periodic tick — caller invokes every ~[`HEARTBEAT_INTERVAL_MS`].
    /// Detects silent parents and emits heal actions.
    pub fn tick(&mut self, wall_clock_unix_ms: u64) -> Vec<HealAction> {
        let cutoff = wall_clock_unix_ms.saturating_sub(PARENT_SILENCE_HEAL_MS);

        let mut actions = Vec::new();
        let mut dead_count = 0;
        let mut parents: Vec<PeerKeyId> = self.active_parents.iter().cloned().collect();
        parents.sort();
        for parent in parents {
            let last = self.parent_liveness.get(&parent).copied().unwrap_or(0);
            if last < cutoff {
                actions.push(HealAction::ReParent {
                    dead: parent.clone(),
                });
                dead_count += 1;
            }
        }
        if dead_count > 0 && dead_count == self.active_parents.len() {
            actions.push(HealAction::UpstreamRebuildRequired);
        }
        actions
    }

    /// Apply a heal-action outcome.
    pub fn apply_heal(&mut self, outcome: HealApplyOutcome) {
        match outcome {
            HealApplyOutcome::AddParent(peer) => self.add_parent_at(peer, 0),
            HealApplyOutcome::RemoveParent(peer) => self.remove_parent(&peer),
            HealApplyOutcome::PromoteToPrimary(peer) => self.promote_to_primary(peer),
        }
    }

    /// Apply [`HealApplyOutcome::AddParent`] with an explicit wall
    /// clock for the liveness seed.
    pub fn add_parent_with_liveness(&mut self, peer: PeerKeyId, wall_clock_unix_ms: u64) {
        self.add_parent_at(peer, wall_clock_unix_ms);
    }

    fn add_parent_at(&mut self, peer: PeerKeyId, liveness_seed: u64) {
        self.active_parents.insert(peer.clone());
        self.parent_liveness.insert(peer, liveness_seed);
    }

    fn remove_parent(&mut self, peer: &PeerKeyId) {
        self.active_parents.remove(peer);
        self.parent_liveness.remove(peer);
        self.backup_parents.retain(|p| p != peer);
    }

    fn promote_to_primary(&mut self, peer: PeerKeyId) {
        let was_in_backups = self.backup_parents.iter().any(|p| p == &peer);
        if was_in_backups {
            self.backup_parents.retain(|p| p != &peer);
        }
        let previous_primary = std::mem::replace(&mut self.primary_parent, peer.clone());
        if previous_primary != peer {
            self.backup_parents.insert(0, previous_primary);
        }
        self.active_parents.insert(peer);
    }

    /// Number of parents this subscription is currently subscribed to.
    #[must_use]
    pub fn active_parent_count(&self) -> usize {
        self.active_parents.len()
    }
}

// ─── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sid() -> StreamId {
        StreamId([7u8; 32])
    }

    fn ep(n: u64) -> Epoch {
        Epoch(n)
    }

    fn seq(n: u64) -> ChunkSeq {
        ChunkSeq(n)
    }

    fn plan(primary: &str, backups: &[&str]) -> JoinPlan {
        JoinPlan {
            primary_parent: primary.into(),
            backup_parents: backups.iter().map(|s| (*s).to_string()).collect(),
            stream_bitrate_mbps: 2.5,
        }
    }

    fn sub_one_backup() -> MultiParentSubscription {
        // Opaque-mode subscription: empty sub_stream_path.
        MultiParentSubscription::new(sid(), Vec::new(), plan("primary", &["backup-a"]))
    }

    #[test]
    fn dedup_ring_first_delivery_then_duplicate() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let now = 10_000;

        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(0), now),
            ObserveOutcome::FirstDelivery
        );
        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(0), now + 1),
            ObserveOutcome::Duplicate
        );
    }

    #[test]
    fn dedup_ring_fifo_eviction() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let now = 10_000;

        let first_epoch = ep(1);
        let first_seq = seq(0);
        assert_eq!(
            s.observe_chunk(&primary, first_epoch, first_seq, now),
            ObserveOutcome::FirstDelivery
        );

        for i in 1..=DEDUP_RING_CAPACITY as u64 {
            assert_eq!(
                s.observe_chunk(&primary, ep(1), seq(i), now + i),
                ObserveOutcome::FirstDelivery
            );
        }

        assert_eq!(
            s.observe_chunk(&primary, first_epoch, first_seq, now + 10_000),
            ObserveOutcome::FirstDelivery
        );
    }

    #[test]
    fn dedup_ring_out_of_order_within_window_dedups() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let now = 10_000;

        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(5), now),
            ObserveOutcome::FirstDelivery
        );
        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(3), now + 1),
            ObserveOutcome::FirstDelivery
        );
        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(5), now + 2),
            ObserveOutcome::Duplicate
        );
    }

    #[test]
    fn dedup_ring_unknown_parent_classified() {
        let mut s = sub_one_backup();
        let attacker: PeerKeyId = "attacker".into();
        let primary: PeerKeyId = "primary".into();
        let now = 10_000;

        assert_eq!(
            s.observe_chunk(&attacker, ep(1), seq(42), now),
            ObserveOutcome::UnknownParent
        );
        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(42), now + 1),
            ObserveOutcome::FirstDelivery
        );
    }

    #[test]
    fn tick_emits_reparent_for_silent_parent() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let backup: PeerKeyId = "backup-a".into();
        let now = 10_000;

        s.parent_liveness.insert(primary.clone(), now - 2_000);
        s.parent_liveness.insert(backup.clone(), now - 100);

        let actions = s.tick(now);
        assert_eq!(
            actions,
            vec![HealAction::ReParent {
                dead: primary.clone()
            }]
        );
    }

    #[test]
    fn tick_emits_upstream_rebuild_when_all_dead() {
        let mut s = sub_one_backup();
        let now = 10_000;

        for p in s.active_parents.clone() {
            s.parent_liveness.insert(p, now - 2_000);
        }

        let actions = s.tick(now);
        assert_eq!(actions.len(), 3);
        let reparent_count = actions
            .iter()
            .filter(|a| matches!(a, HealAction::ReParent { .. }))
            .count();
        assert_eq!(reparent_count, 2);
        assert!(actions.contains(&HealAction::UpstreamRebuildRequired));
    }

    #[test]
    fn apply_heal_add_parent_grows_active_set() {
        let mut s = sub_one_backup();
        let now = 10_000;
        let start = s.active_parent_count();
        let new_peer: PeerKeyId = "new-parent".into();

        s.add_parent_with_liveness(new_peer.clone(), now);

        assert_eq!(s.active_parent_count(), start + 1);
        assert!(s.active_parents.contains(&new_peer));
        assert_eq!(s.parent_liveness.get(&new_peer).copied(), Some(now));
    }

    #[test]
    fn apply_heal_remove_parent_shrinks_active_set() {
        let mut s = sub_one_backup();
        let backup: PeerKeyId = "backup-a".into();
        let start = s.active_parent_count();

        s.apply_heal(HealApplyOutcome::RemoveParent(backup.clone()));

        assert_eq!(s.active_parent_count(), start - 1);
        assert!(!s.active_parents.contains(&backup));
        assert_eq!(
            s.observe_chunk(&backup, ep(1), seq(0), 10_000),
            ObserveOutcome::UnknownParent
        );
    }

    #[test]
    fn multi_parent_dedups_chunks_from_2_parents() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let backup: PeerKeyId = "backup-a".into();
        let now = 10_000;

        assert_eq!(
            s.observe_chunk(&primary, ep(2), seq(7), now),
            ObserveOutcome::FirstDelivery
        );
        assert_eq!(
            s.observe_chunk(&backup, ep(2), seq(7), now + 5),
            ObserveOutcome::Duplicate
        );
    }

    #[test]
    fn promotion_to_primary_preserves_subscription() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();
        let backup: PeerKeyId = "backup-a".into();
        let initial_size = s.active_parent_count();

        s.apply_heal(HealApplyOutcome::PromoteToPrimary(backup.clone()));

        assert_eq!(s.active_parent_count(), initial_size);
        assert_eq!(s.primary_parent, backup);
        assert!(s.backup_parents.contains(&primary));
        assert!(!s.backup_parents.contains(&backup));
    }

    #[test]
    fn heal_threshold_not_triggered_within_window() {
        let mut s = sub_one_backup();
        let now = 10_000;

        for p in s.active_parents.clone() {
            s.parent_liveness.insert(p, now - 100);
        }

        let actions = s.tick(now);
        assert!(actions.is_empty(), "unexpected heal actions: {actions:?}");
    }

    #[test]
    fn observe_chunk_refreshes_liveness() {
        let mut s = sub_one_backup();
        let primary: PeerKeyId = "primary".into();

        s.parent_liveness.insert(primary.clone(), 0);

        let now = 10_000;
        assert_eq!(
            s.observe_chunk(&primary, ep(1), seq(0), now),
            ObserveOutcome::FirstDelivery
        );
        assert_eq!(s.parent_liveness.get(&primary).copied(), Some(now));
    }

    #[test]
    fn tick_actions_are_deterministic() {
        let mut s = sub_one_backup();
        let now = 10_000;
        for p in s.active_parents.clone() {
            s.parent_liveness.insert(p, now - 2_000);
        }
        let a = s.tick(now);
        let b = s.tick(now);
        assert_eq!(a, b);
    }

    // ─── MDC sub-stream tests (CIRISEdge#128) ───────────────────────

    #[test]
    fn multi_parent_subscription_carries_sub_stream_path() {
        // Opaque-mode subscription has empty path.
        let opaque = MultiParentSubscription::new(sid(), Vec::new(), plan("p", &["b"]));
        assert!(opaque.sub_stream_path.is_empty());

        // MDC sub-stream [0, 1] subscription carries that path.
        let mdc = MultiParentSubscription::new(sid(), vec![0u8, 1u8], plan("p", &["b"]));
        assert_eq!(mdc.sub_stream_path, vec![0u8, 1u8]);
    }

    #[test]
    fn dedup_per_substream_subscription_is_independent() {
        // Two subscriptions to the same stream but different
        // sub-stream paths share NO state; observing (epoch, chunk_seq)
        // on one MUST NOT dedupe it on the other.
        let mut sub_a = MultiParentSubscription::new(sid(), vec![0u8], plan("p-a", &["b-a"]));
        let mut sub_b = MultiParentSubscription::new(sid(), vec![1u8], plan("p-b", &["b-b"]));

        let p_a: PeerKeyId = "p-a".into();
        let p_b: PeerKeyId = "p-b".into();
        let now = 10_000;

        assert_eq!(
            sub_a.observe_chunk(&p_a, ep(1), seq(42), now),
            ObserveOutcome::FirstDelivery
        );
        // Same (epoch, chunk_seq) on the other subscription is fresh —
        // each subscription owns its own dedup ring.
        assert_eq!(
            sub_b.observe_chunk(&p_b, ep(1), seq(42), now),
            ObserveOutcome::FirstDelivery
        );
        // But on sub_a itself it's a duplicate.
        assert_eq!(
            sub_a.observe_chunk(&p_a, ep(1), seq(42), now + 1),
            ObserveOutcome::Duplicate
        );
    }
}
