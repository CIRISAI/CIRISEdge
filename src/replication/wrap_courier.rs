//! **The wrap courier** (45.1.5, star rooms) — a minter carries its own
//! key-grant wraps to a room member that is not one of its replication peers.
//!
//! # Why
//!
//! A room member that writes mints its own epoch and wraps it to every member
//! device (`key_grant:*` rows, one wrap per recipient). persist serves a wrap
//! to its recipient ONLY (`replication_audience::may_receive`: "a wrap is
//! useful to nobody else"), so no third node can relay it. The host's peer set
//! is its consent peers. In a star room the members are contacts of the
//! founder, not of each other, so a non-founder minter runs no round toward
//! the other members and its wraps never leave it: the server's star6 harness
//! read every non-founder's messages `NotGranted` for good (0/3).
//!
//! # What it carries, to whom, and how
//!
//! - **Scope.** Only key-grant rows THIS node signed whose recipient
//!   (`attested_key_id`) is that member, and each one only if persist's own
//!   `may_receive(recipient, row)` says yes. Nothing else: the one-shot
//!   exchange offers those refs and wants nothing back.
//! - **To whom.** A recipient this node has no Attestation initiator toward.
//!   When the recipient is (or becomes) a peer, the ordinary round carries its
//!   wraps and the courier drops it.
//! - **How.** One ordinary anti-entropy round (Summary, Diff, Deliver) on a
//!   coordinator of its own, registered only while no initiator holds the
//!   `(recipient, Attestation)` slot, over whatever route the transport has to
//!   the recipient (a #805 direct link when one is up). No new wire message.
//!   The recipient's #312 responder answers it like any other round.
//! - **When.** Woken by the host's kicks (`round_now`, `round_now_all`: the
//!   room seat kicks after it grants) and once at start; between wakes it
//!   reads nothing. Coalesced (one task, one round per recipient at a time),
//!   retried with a doubling backoff, and given up after
//!   [`MAX_ATTEMPTS`] with a counter.
//! - **Booked.** `replication_io` `attestation:wrap_courier_{sent,admitted,
//!   refused,gave_up}` (rows). Never addresses.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ciris_persist::federation::{Attestation, FederationDirectory};
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::coordinator::ReplicationCoordinator;
use super::protocol::{EnvelopeKind, EnvelopeRef};
use super::registry::ReplicationRegistry;
use super::session::SessionRole;
use super::summary::{StalenessSignal, StateApplier, StateProvider};
use crate::transport::Transport;

/// Rows read per page of this node's own wraps, newest first.
const SCAN_PAGE: u32 = 128;
/// Pages read per wake at most.
const SCAN_PAGES: usize = 4;
/// Recipients waiting at once, at most.
const MAX_RECIPIENTS: usize = 256;
/// Wraps carried to one recipient in one round, at most.
const MAX_ROWS_PER_RECIPIENT: usize = 64;
/// Hashes remembered as delivered or given up (a restart forgets them, which
/// costs one in-sync round per non-peer recipient).
const MAX_REMEMBERED: usize = 65_536;
/// Rounds to one recipient before the courier gives its wraps up.
pub const MAX_ATTEMPTS: u32 = 6;
/// The first retry's delay; doubles per attempt.
const RETRY_BASE: Duration = Duration::from_secs(10);
/// The longest retry delay.
const RETRY_CAP: Duration = Duration::from_mins(5);
/// The coalescing window after a wake.
const DEBOUNCE: Duration = Duration::from_millis(250);

/// What the courier needs from the runtime.
pub(crate) struct WrapCourierDeps {
    pub directory: Arc<dyn FederationDirectory>,
    pub registry: Arc<ReplicationRegistry>,
    pub transport: Arc<dyn Transport>,
    pub applier: Arc<dyn StateApplier>,
    pub local_key_id: String,
    pub metrics: Option<crate::observability::EdgeMetrics>,
    pub round_timeout: Duration,
}

/// A recipient's wraps waiting to cross.
struct Pending {
    rows: Vec<(Attestation, Vec<u8>, [u8; 32])>,
    attempts: u32,
    next_at: Instant,
}

/// The courier's own memory: one task owns it, so nothing is shared.
struct Courier {
    deps: WrapCourierDeps,
    pending: HashMap<String, Pending>,
    done: HashSet<[u8; 32]>,
}

/// Spawn the courier, stopped with the runtime's cancel channel.
pub(crate) fn spawn_wrap_courier(
    deps: WrapCourierDeps,
    wake: Arc<Notify>,
    mut cancel: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut courier = Courier {
            deps,
            pending: HashMap::new(),
            done: HashSet::new(),
        };
        // The start pass: wraps minted before this process.
        let mut scan = true;
        loop {
            if *cancel.borrow() {
                break;
            }
            if scan {
                courier.scan().await;
            }
            courier.deliver_due().await;
            let next = courier.pending.values().map(|p| p.next_at).min();
            scan = tokio::select! {
                () = wake.notified() => {
                    tokio::select! {
                        () = tokio::time::sleep(DEBOUNCE) => {}
                        _ = cancel.changed() => {}
                    }
                    let _ = tokio::time::timeout(Duration::ZERO, wake.notified()).await;
                    true
                }
                () = sleep_until_or_forever(next) => false,
                changed = cancel.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    false
                }
            };
        }
    })
}

async fn sleep_until_or_forever(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

impl Courier {
    fn book(&self, label: &'static str, n: usize) {
        if let Some(m) = &self.deps.metrics {
            m.add_replication_io(
                EnvelopeKind::Attestation,
                label,
                u64::try_from(n).unwrap_or(u64::MAX),
            );
        }
    }

    fn remember(&mut self, hash: [u8; 32]) {
        if self.done.len() >= MAX_REMEMBERED {
            self.done.clear();
        }
        self.done.insert(hash);
    }

    /// Read this node's own wraps, newest first, until a page holds nothing
    /// new; queue each one whose recipient is not a peer.
    async fn scan(&mut self) {
        use ciris_persist::federation::attestation_query::AttestationQuery;
        use ciris_persist::federation::key_grant::{is_key_grant_row, KEY_GRANT_DIMENSION_PREFIX};
        let Some(page) = std::num::NonZeroU32::new(SCAN_PAGE) else {
            return;
        };
        let mut pages = AttestationQuery::by(&self.deps.local_key_id, page)
            .dimension_prefix(KEY_GRANT_DIMENSION_PREFIX)
            .pages();
        for _ in 0..SCAN_PAGES {
            let rows = match pages.next(&*self.deps.directory).await {
                Ok(Some(rows)) => rows,
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(error = %e, "wrap courier: own wraps not served");
                    break;
                }
            };
            let mut fresh = 0usize;
            for row in rows {
                if !is_key_grant_row(&row)
                    || row.attesting_key_id != self.deps.local_key_id
                    || row.attested_key_id == self.deps.local_key_id
                {
                    continue;
                }
                let Ok(bytes) = serde_json::to_vec(&row) else {
                    continue;
                };
                let hash = super::wire_ref::envelope_ref(EnvelopeKind::Attestation, &bytes);
                if self.done.contains(&hash) {
                    continue;
                }
                let recipient = row.attested_key_id.clone();
                if !self.pending.contains_key(&recipient) && self.pending.len() >= MAX_RECIPIENTS {
                    continue;
                }
                let entry = self.pending.entry(recipient).or_insert_with(|| Pending {
                    rows: Vec::new(),
                    attempts: 0,
                    next_at: Instant::now(),
                });
                if entry.rows.iter().any(|(_, _, h)| *h == hash) {
                    continue;
                }
                if entry.rows.len() < MAX_ROWS_PER_RECIPIENT {
                    entry.rows.push((row, bytes, hash));
                    // A new wrap is worth a prompt round.
                    entry.next_at = Instant::now();
                    fresh += 1;
                }
            }
            if fresh == 0 {
                break;
            }
        }
    }

    /// One round to each recipient whose turn it is.
    async fn deliver_due(&mut self) {
        let now = Instant::now();
        let due: Vec<String> = self
            .pending
            .iter()
            .filter(|(_, p)| p.next_at <= now)
            .map(|(r, _)| r.clone())
            .collect();
        for recipient in due {
            self.deliver(&recipient).await;
        }
    }

    async fn deliver(&mut self, recipient: &str) {
        // A peer's ordinary round carries its wraps: not the courier's.
        if self
            .deps
            .registry
            .get_initiator(recipient, EnvelopeKind::Attestation)
            .await
            .is_some()
        {
            self.pending.remove(recipient);
            return;
        }
        let Some(pending) = self.pending.get(recipient) else {
            return;
        };
        // persist's own gate: may this recipient receive this row here?
        let mut carry = Vec::new();
        for (row, bytes, hash) in &pending.rows {
            let allowed = ciris_persist::federation::replication_audience::may_receive(
                &*self.deps.directory,
                recipient,
                row,
            )
            .await
            .is_ok_and(ciris_persist::federation::replication_audience::Verdict::allowed);
            if allowed {
                carry.push((bytes.clone(), *hash));
            }
        }
        let outcome = if carry.is_empty() {
            Err("no wrap is in the recipient's audience here yet".to_owned())
        } else {
            self.book("wrap_courier_sent", carry.len());
            self.round(recipient, &carry).await
        };
        match outcome {
            Ok(Carried::BecamePeer) => {
                self.pending.remove(recipient);
            }
            Ok(Carried::Held) => {
                self.book("wrap_courier_admitted", carry.len());
                let carried: HashSet<[u8; 32]> = carry.iter().map(|(_, h)| *h).collect();
                for h in &carried {
                    self.remember(*h);
                }
                if let Some(p) = self.pending.get_mut(recipient) {
                    p.rows.retain(|(_, _, h)| !carried.contains(h));
                    if p.rows.is_empty() {
                        self.pending.remove(recipient);
                    }
                }
                tracing::debug!(
                    rows = carried.len(),
                    "wrap courier: a member that is not a peer holds this node's wraps"
                );
            }
            Ok(Carried::NotHeld) => {
                self.book("wrap_courier_refused", carry.len());
                self.retry_or_give_up(recipient, None);
            }
            Err(e) => self.retry_or_give_up(recipient, Some(&e)),
        }
    }

    fn retry_or_give_up(&mut self, recipient: &str, error: Option<&str>) {
        let Some(p) = self.pending.get_mut(recipient) else {
            return;
        };
        p.attempts = p.attempts.saturating_add(1);
        if p.attempts >= MAX_ATTEMPTS {
            let given: Vec<[u8; 32]> = p.rows.iter().map(|(_, _, h)| *h).collect();
            self.pending.remove(recipient);
            self.book("wrap_courier_gave_up", given.len());
            for h in given {
                self.remember(h);
            }
            tracing::info!(
                attempts = MAX_ATTEMPTS,
                error = error.unwrap_or("refused"),
                "wrap courier gave up on a member's wraps after its bound; a later \
                 round between the two (or a restart) carries them"
            );
            return;
        }
        p.next_at = Instant::now() + retry_delay(p.attempts);
    }

    /// One round to `recipient` offering `carry`.
    async fn round(
        &self,
        recipient: &str,
        carry: &[(Vec<u8>, [u8; 32])],
    ) -> Result<Carried, String> {
        let provider = Arc::new(WrapProvider::new(carry));
        let coord = Arc::new(ReplicationCoordinator::new(
            Arc::clone(&self.deps.transport),
            recipient.to_owned(),
            EnvelopeKind::Attestation,
            SessionRole::Initiator,
            provider,
            Arc::clone(&self.deps.applier),
        ));
        if !self
            .deps
            .registry
            .register_initiator_if_absent(recipient, EnvelopeKind::Attestation, &coord)
            .await
        {
            return Ok(Carried::BecamePeer);
        }
        let report = super::scheduler::run_courier_round(&coord, self.deps.round_timeout).await;
        self.deps
            .registry
            .deregister_initiator_if(recipient, EnvelopeKind::Attestation, &coord)
            .await;
        report.map(|r| {
            if r.staleness == StalenessSignal::InSync {
                Carried::Held
            } else {
                Carried::NotHeld
            }
        })
    }
}

/// How a courier round ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carried {
    /// The recipient holds every row offered.
    Held,
    /// The round completed and the recipient still lacks some: refused there.
    NotHeld,
    /// The recipient became a peer before the round opened: its own round
    /// carries the wraps.
    BecamePeer,
}

/// The delay before attempt `attempts + 1`: [`RETRY_BASE`] doubling, capped
/// at [`RETRY_CAP`].
fn retry_delay(attempts: u32) -> Duration {
    RETRY_BASE
        .saturating_mul(1u32 << attempts.saturating_sub(1).min(8))
        .min(RETRY_CAP)
}

/// The courier round's provider: it offers exactly the wraps it carries and
/// wants nothing back.
struct WrapProvider {
    refs: Vec<EnvelopeRef>,
    bodies: HashMap<[u8; 32], Vec<u8>>,
}

impl WrapProvider {
    fn new(carry: &[(Vec<u8>, [u8; 32])]) -> Self {
        let refs = carry
            .iter()
            .zip(1u64..)
            .map(|((_, h), seq)| EnvelopeRef {
                envelope_hash: *h,
                seq,
            })
            .collect();
        let bodies = carry.iter().map(|(b, h)| (*h, b.clone())).collect();
        Self { refs, bodies }
    }
}

#[async_trait]
impl StateProvider for WrapProvider {
    async fn local_refs(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        if kind == EnvelopeKind::Attestation {
            self.refs.clone()
        } else {
            Vec::new()
        }
    }
    async fn local_holdings(&self, kind: EnvelopeKind) -> Vec<EnvelopeRef> {
        self.local_refs(kind).await
    }
    async fn local_want(&self, _kind: EnvelopeKind, _remote: &[EnvelopeRef]) -> Vec<[u8; 32]> {
        Vec::new()
    }
    async fn fetch_envelope(
        &self,
        kind: EnvelopeKind,
        envelope_hash: &[u8; 32],
    ) -> Option<Vec<u8>> {
        if kind == EnvelopeKind::Attestation {
            self.bodies.get(envelope_hash).cloned()
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The retry schedule doubles from [`RETRY_BASE`], never past
    /// [`RETRY_CAP`], and the courier stops after [`MAX_ATTEMPTS`]: the total
    /// it can spend on one recipient is bounded.
    #[test]
    fn the_courier_backs_off_and_its_attempts_are_bounded() {
        assert_eq!(retry_delay(1), RETRY_BASE);
        assert_eq!(retry_delay(2), RETRY_BASE * 2);
        assert_eq!(retry_delay(3), RETRY_BASE * 4);
        assert_eq!(retry_delay(40), RETRY_CAP);
        let total: Duration = (1..MAX_ATTEMPTS).map(retry_delay).sum();
        assert!(total <= RETRY_CAP * MAX_ATTEMPTS, "{total:?}");
    }

    /// The courier round offers exactly the wraps it carries, serves only
    /// their bodies, and wants nothing back: the recipient-only rule holds in
    /// the round itself, not just in what was chosen.
    #[tokio::test]
    async fn the_courier_round_offers_only_what_it_carries_and_wants_nothing() {
        let carry = vec![
            (b"wrap-1".to_vec(), [1u8; 32]),
            (b"wrap-2".to_vec(), [2u8; 32]),
        ];
        let p = WrapProvider::new(&carry);
        let refs = p.local_refs(EnvelopeKind::Attestation).await;
        assert_eq!(
            refs.iter().map(|r| r.envelope_hash).collect::<Vec<_>>(),
            vec![[1u8; 32], [2u8; 32]]
        );
        assert!(p.local_refs(EnvelopeKind::Key).await.is_empty());
        let remote = [EnvelopeRef {
            envelope_hash: [9u8; 32],
            seq: 1,
        }];
        assert!(p
            .local_want(EnvelopeKind::Attestation, &remote)
            .await
            .is_empty());
        assert_eq!(
            p.fetch_envelope(EnvelopeKind::Attestation, &[2u8; 32])
                .await,
            Some(b"wrap-2".to_vec())
        );
        assert_eq!(
            p.fetch_envelope(EnvelopeKind::Attestation, &[9u8; 32])
                .await,
            None
        );
    }
}
