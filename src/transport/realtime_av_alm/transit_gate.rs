//! CIRISEdge#430 — the fail-closed `infra:transport` hop-eligibility gate for
//! A/V relay parent selection.
//!
//! A relay hop is a **position** of trust: an unvetted node that volunteers as a
//! forwarding hop gets traffic-analysis visibility (who publishes, who
//! subscribes, when, at what rate) and an availability lever over its subtree.
//! (Not a confidentiality hole — the relay only ever holds hop-tier transit
//! keys, never the epoch DEK, and that is structural.) So choosing a hop is a
//! trust decision, and this gate makes it one.
//!
//! ## What the gate asks
//!
//! Eligibility is resolved entirely by persist's
//! [`resolve_transit_eligibility`](ciris_persist::federation::trust_root::resolve_transit_eligibility)
//! (CIRISPersist#561) — edge holds **zero** trust logic. A hop is eligible iff
//! it is (A) in the federation directory, (B) an `identity_type == node`, (C)
//! self-offers `infra:transport`, and (D) trusts a trust root **we** also trust
//! (shared-root overlap, the candidate set bounded by *our* own edges so a
//! hostile peer cannot inflate the walk). Deliberately weaker than the
//! `infra:serve` conferral walk: the exposure is position, not content, so
//! shared-root anchoring is the proportionate bar — and it keeps relaying
//! decentralized.
//!
//! ## Why a cache — and how it stays honest
//!
//! Selection is a hot path (re-parent on peer churn, per-substream in MDC), and
//! the resolution is cryptographic. So the verdict is resolved **once** per peer
//! and cached; [`AlmJoinPlanner::plan`](super::join::AlmJoinPlanner::plan) stays
//! pure, sync, and crypto-free — this gate does the async pre-resolution and
//! hands `plan` a pre-filtered pool (the `deterministic_topology`
//! "resolve upstream, feed it in" pattern).
//!
//! The cache TTL is persist's authoritative `valid_until` (the min expiry across
//! the attestations the walk counted, at persist's own `is_expired` reference
//! time — the caller's TTL cannot drift from the authority). Two honesty rules:
//!
//! * A **granted** verdict with `valid_until == None` is time-unbounded — it
//!   holds until a withdrawal event ([`Self::invalidate`]) drops it.
//! * A **denied** verdict also carries `None`, but persist ships it that way
//!   precisely so a caller does not cache the refusal ("a TTL on a refusal would
//!   invite a caller to cache the refusal"). Caching a refusal forever would
//!   pin a peer ineligible across the exact fleet event that makes it eligible
//!   (the genesis re-mint conferring `infra:transport`). So refusals get a
//!   short bounded TTL ([`NEGATIVE_VERDICT_TTL`]): long enough to spare the hot
//!   path a per-selection re-walk, short enough that flip-to-eligible lands
//!   within one window of the grant.
//!
//! ## Fail-closed
//!
//! No local identity to anchor the shared-root walk, or any resolver error →
//! **not eligible**. A transport gate never fails open.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Duration, Utc};
use ciris_persist::federation::trust_root::resolve_transit_eligibility;
use ciris_persist::federation::FederationDirectory;

use super::capacity::PeerKeyId;
use super::join::ParentCandidate;

/// How long a **denied** verdict is cached before re-resolution. Bounds the
/// hot-path re-walk rate for ineligible peers without pinning them ineligible
/// across the grant event that would flip them (see the module docs).
pub const NEGATIVE_VERDICT_TTL: Duration = Duration::seconds(30);

/// One cached transit verdict for one peer.
#[derive(Debug, Clone)]
struct CachedVerdict {
    /// The gate outcome.
    eligible: bool,
    /// When this verdict stops being trustworthy. `None` = time-unbounded
    /// (a granted verdict with no expiry) — held until [`VerdictCache::invalidate`].
    /// A denied verdict is always stamped with a bounded expiry, never `None`.
    expires_at: Option<DateTime<Utc>>,
    /// The shared root that satisfied conjunct (D), if any — the second
    /// invalidation key: a withdrawal naming this root drops the entry.
    via_root: Option<String>,
}

/// The pure, directory-free verdict cache. Split out from [`TransitGate`] so the
/// freshness / negative-TTL / invalidation rules are unit-testable without a
/// full trust fixture — the resolution correctness is persist's, tested there.
#[derive(Debug, Default)]
struct VerdictCache {
    by_peer: HashMap<PeerKeyId, CachedVerdict>,
}

impl VerdictCache {
    /// The cached eligibility for `peer` iff a **fresh** verdict exists. `None`
    /// means "no usable verdict — resolve." A `None`-expiry entry is fresh
    /// forever (until invalidated); a stamped entry is fresh while `now < expiry`.
    fn get_fresh(&self, peer: &str, now: DateTime<Utc>) -> Option<bool> {
        let v = self.by_peer.get(peer)?;
        let fresh = match v.expires_at {
            Some(expiry) => now < expiry,
            None => true,
        };
        fresh.then_some(v.eligible)
    }

    /// Record a freshly-resolved verdict. A granted verdict keeps persist's
    /// authoritative `valid_until` (possibly `None` = unbounded). A denied
    /// verdict is stamped `now + NEGATIVE_VERDICT_TTL` regardless of what the
    /// resolver returned, so a refusal is never cached unboundedly.
    fn put(
        &mut self,
        peer: &str,
        eligible: bool,
        valid_until: Option<DateTime<Utc>>,
        via_root: Option<String>,
        now: DateTime<Utc>,
    ) {
        let expires_at = if eligible {
            valid_until
        } else {
            Some(now + NEGATIVE_VERDICT_TTL)
        };
        self.by_peer.insert(
            peer.to_string(),
            CachedVerdict {
                eligible,
                expires_at,
                via_root,
            },
        );
    }

    /// Drop every entry a withdrawal of `key_id` could falsify: the peer whose
    /// verdict it is, and any peer whose eligibility was satisfied *via* `key_id`
    /// as the shared root. Event-driven invalidation from the replication apply
    /// path; the TTL is the backstop if an event is ever missed.
    fn invalidate(&mut self, key_id: &str) {
        self.by_peer
            .retain(|peer, v| peer != key_id && v.via_root.as_deref() != Some(key_id));
    }
}

/// The `infra:transport` hop-eligibility gate (CIRISEdge#430). Wraps persist's
/// [`resolve_transit_eligibility`] with a hot-path cache; see the module docs.
pub struct TransitGate {
    directory: Arc<dyn FederationDirectory>,
    /// "us" — the selecting node's federation `key_id`, the anchor for the
    /// shared-root walk. `None` ⇒ the gate cannot resolve ⇒ every hop is refused
    /// (fail-closed).
    local_key_id: Option<String>,
    cache: Mutex<VerdictCache>,
}

impl TransitGate {
    /// Build a gate over `directory`, anchored at `local_key_id` (our federation
    /// key). Pass `None` for `local_key_id` to hold the gate fully closed (no
    /// identity to root the shared-root walk).
    #[must_use]
    pub fn new(directory: Arc<dyn FederationDirectory>, local_key_id: Option<String>) -> Self {
        Self {
            directory,
            local_key_id,
            cache: Mutex::new(VerdictCache::default()),
        }
    }

    /// Is `peer` an eligible transit hop as of `now`? Cache-first: a fresh cached
    /// verdict returns without a walk. A miss or an expired entry resolves via
    /// persist, caches, and returns. **Fail-closed**: no local identity, or any
    /// resolver error → `false`.
    pub async fn is_eligible_hop(&self, peer: &str, now: DateTime<Utc>) -> bool {
        let Some(us) = self.local_key_id.as_deref() else {
            // No identity to anchor conjunct (D) — nothing is eligible.
            return false;
        };

        // Cache hit (fresh) short-circuits the crypto walk. Lock is dropped
        // before the await below — never held across it.
        if let Some(cached) = self
            .cache
            .lock()
            .expect("transit verdict cache poisoned")
            .get_fresh(peer, now)
        {
            return cached;
        }

        let verdict = match resolve_transit_eligibility(&*self.directory, us, peer).await {
            Ok(v) => v,
            Err(e) => {
                // Fail-closed on an unresolvable trust read: refuse the hop, and
                // do NOT cache — a transient directory error must not pin a peer
                // ineligible past the error.
                tracing::warn!(
                    peer,
                    error = %e,
                    "transit eligibility resolve failed — refusing hop (fail-closed, #430)"
                );
                return false;
            }
        };

        self.cache
            .lock()
            .expect("transit verdict cache poisoned")
            .put(
                peer,
                verdict.eligible,
                verdict.valid_until,
                verdict.via_root,
                now,
            );
        verdict.eligible
    }

    /// Filter a candidate pool to the eligible hops, resolving each (cache-first).
    /// This is the async pre-resolution seam that keeps
    /// [`AlmJoinPlanner::plan`](super::join::AlmJoinPlanner::plan) pure and sync:
    /// the caller runs `plan(&gate.eligible_candidates(pool, now).await, …)`.
    pub async fn eligible_candidates(
        &self,
        candidates: Vec<ParentCandidate>,
        now: DateTime<Utc>,
    ) -> Vec<ParentCandidate> {
        let mut kept = Vec::with_capacity(candidates.len());
        for c in candidates {
            if self.is_eligible_hop(c.peer_key_id(), now).await {
                kept.push(c);
            }
        }
        kept
    }

    /// Drop cached verdicts a withdrawal/revocation of `key_id` could falsify —
    /// the peer itself, or a shared root (`via_root`) that satisfied a peer's
    /// conjunct (D). Wire this to the replication apply path's Revocation handling
    /// so an in-band un-trust takes effect before the TTL would expire.
    pub fn invalidate(&self, key_id: &str) {
        self.cache
            .lock()
            .expect("transit verdict cache poisoned")
            .invalidate(key_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_800_000_000 + secs, 0).expect("valid timestamp")
    }

    // ─── VerdictCache: the freshness / negative-TTL / invalidation rules ──

    #[test]
    fn granted_unbounded_verdict_is_fresh_forever_until_invalidated() {
        let mut c = VerdictCache::default();
        // eligible + valid_until None = time-unbounded grant.
        c.put("peer-a", true, None, Some("root-1".into()), t(0));
        assert_eq!(c.get_fresh("peer-a", t(0)), Some(true));
        // Still fresh a very long time later — no TTL on an unbounded grant.
        assert_eq!(c.get_fresh("peer-a", t(1_000_000)), Some(true));
    }

    #[test]
    fn granted_bounded_verdict_expires_at_persist_valid_until() {
        let mut c = VerdictCache::default();
        c.put("peer-a", true, Some(t(100)), Some("root-1".into()), t(0));
        assert_eq!(
            c.get_fresh("peer-a", t(99)),
            Some(true),
            "fresh before expiry"
        );
        assert_eq!(
            c.get_fresh("peer-a", t(100)),
            None,
            "expired AT valid_until"
        );
        assert_eq!(c.get_fresh("peer-a", t(101)), None, "expired after");
    }

    #[test]
    fn denied_verdict_is_cached_only_for_the_negative_ttl_never_unbounded() {
        let mut c = VerdictCache::default();
        // Resolver hands a denial with valid_until None (its documented shape).
        c.put("peer-a", false, None, None, t(0));
        // Cached briefly (spares the hot path a per-selection re-walk)…
        assert_eq!(c.get_fresh("peer-a", t(0)), Some(false));
        assert_eq!(
            c.get_fresh("peer-a", t(NEGATIVE_VERDICT_TTL.num_seconds() - 1)),
            Some(false),
            "still cached just before the negative TTL"
        );
        // …but NOT unboundedly: it must re-resolve after the window, so the peer
        // can flip to eligible once the grant lands.
        assert_eq!(
            c.get_fresh("peer-a", t(NEGATIVE_VERDICT_TTL.num_seconds())),
            None,
            "denied verdict re-resolves after the negative TTL — never pinned"
        );
    }

    #[test]
    fn invalidate_drops_the_named_peer_and_any_peer_via_that_root() {
        let mut c = VerdictCache::default();
        c.put("peer-a", true, None, Some("root-1".into()), t(0));
        c.put("peer-b", true, None, Some("root-2".into()), t(0));
        c.put("peer-c", true, None, Some("root-1".into()), t(0));

        // Withdraw root-1: every peer that was eligible VIA root-1 drops.
        c.invalidate("root-1");
        assert_eq!(
            c.get_fresh("peer-a", t(0)),
            None,
            "peer-a used root-1 → dropped"
        );
        assert_eq!(
            c.get_fresh("peer-c", t(0)),
            None,
            "peer-c used root-1 → dropped"
        );
        assert_eq!(
            c.get_fresh("peer-b", t(0)),
            Some(true),
            "peer-b used root-2 → kept"
        );

        // Withdraw the peer itself.
        c.invalidate("peer-b");
        assert_eq!(
            c.get_fresh("peer-b", t(0)),
            None,
            "peer-b withdrawn → dropped"
        );
    }

    #[test]
    fn a_miss_is_none_not_a_default() {
        let c = VerdictCache::default();
        assert_eq!(c.get_fresh("never-seen", t(0)), None);
    }

    // ─── TransitGate: fail-closed, through the real resolver ─────────────

    #[tokio::test]
    async fn no_local_identity_refuses_every_hop() {
        use ciris_persist::store::MemoryBackend;
        // With no "us" to anchor conjunct (D), the gate refuses before any walk —
        // the empty directory here is never consulted (the `else` returns first).
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = TransitGate::new(dir, None);
        assert!(
            !gate.is_eligible_hop("any-peer", t(0)).await,
            "no local identity ⇒ every hop refused, fail-closed"
        );
    }

    /// CIRISEdge#430 — the ALLOW path, end to end, against persist's OWN
    /// seeded trust state (the #435 lesson: prove the allow, not just the
    /// deny). Gated on `test-anchor` because the seeding surface
    /// (`exercise_transit_eligibility`, `sign_envelope`) lives behind
    /// persist's test fence; the CI test-anchor lane runs it.
    ///
    /// The fixture: persist's 7-witness `exercise_transit_eligibility` runs
    /// first (re-validating the pinned contract inside OUR build), which ends
    /// with witness (f) — the user's trust edge withdrawn. ONE restored
    /// user→root `trust:accepts` edge (byte-shaped exactly as persist's
    /// `emit_trust_edge` mints it, signed with persist's own `sign_envelope`)
    /// re-greens the walk. Then the gate + the gated planner:
    /// - `gate-peer` (node + infra:transport + shared root) → kept, selected.
    /// - `gate-flooded` (witness (e)'s peer: registered, self-claims the
    ///   role, rooted only to its own 50 bogus roots) → refused.
    #[cfg(feature = "test-anchor")]
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // exercise + restore + gate + planner: one scenario
    async fn transit_gate_allows_shared_root_peer_and_refuses_self_claimed() {
        use ciris_persist::federation::accord_test_support::exercise_transit_eligibility;
        use ciris_persist::federation::trust_root::{INFRA_SERVE_SCOPE, TRUST_ACCEPTS_DIMENSION};
        use ciris_persist::store::MemoryBackend;

        /// Verbatim replication of persist's `tier_ingest::test_support::
        /// sign_envelope` (which is `pub(crate)`) from its public pieces: the
        /// SAME `[0x11; 32]`-overlay deterministic seed, the same
        /// `ceg_produce_canonicalize` bytes, the same CC 3.1.2.1 bound-PQC
        /// payload (`canonical ‖ ed25519_sig`). Keys therefore match the
        /// records the exercise registered for the same key_id.
        fn sign_envelope_like_persist(
            signing_key_id: &str,
            envelope: &serde_json::Value,
        ) -> (String, String, Option<String>) {
            use base64::Engine as _;
            use ciris_crypto::{ClassicalSigner as _, PqcSigner as _};
            use sha2::Digest as _;
            let mut seed = [0x11u8; 32];
            for (i, b) in signing_key_id.bytes().take(32).enumerate() {
                seed[i] = b;
            }
            let ed = ciris_crypto::Ed25519Signer::from_seed(&seed).expect("ed seed");
            let mldsa = ciris_crypto::MlDsa65Signer::from_seed(&seed).expect("mldsa seed");
            let canonical = ciris_persist::verify::canonical::ceg_produce_canonicalize(envelope)
                .expect("canonicalize");
            let och = hex::encode(sha2::Sha256::digest(&canonical));
            let ed_sig = ed.sign(&canonical).expect("ed sign");
            let mut bound = canonical.clone();
            bound.extend_from_slice(&ed_sig);
            let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
            let b64 = base64::engine::general_purpose::STANDARD;
            (och, b64.encode(&ed_sig), Some(b64.encode(&pqc_sig)))
        }

        let backend = Arc::new(MemoryBackend::new());
        exercise_transit_eligibility(&*backend, "gate")
            .await
            .expect("persist's transit-eligibility exercise holds on the pinned build");

        // Restore green after witness (f): re-emit the user's trust edge,
        // unbounded, in the exact shape persist's `emit_trust_edge` mints
        // (envelope + Attestation field layout copied from operational.rs
        // test_support; the signature is persist's own sign_envelope).
        let id = "gate-restore-user-edge";
        let envelope = serde_json::json!({
            "references_attestation_id": id,
            "dimension": TRUST_ACCEPTS_DIMENSION,
            "scope": [INFRA_SERVE_SCOPE],
        });
        let (och, sc, sp) = sign_envelope_like_persist("gate-user", &envelope);
        let now = Utc::now();
        let edge = ciris_persist::federation::Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: "gate-user".to_owned(),
            attested_key_id: "gate-root".to_owned(),
            attestation_type: ciris_persist::federation::types::attestation_type::DELEGATES_TO
                .to_owned(),
            weight: Some(1.0),
            asserted_at: now,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: "gate-user".to_owned(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: Vec::new(),
            withdraws_admission_rule: None,
            cohort_scope: ciris_persist::federation::types::cohort_scope::FEDERATION.to_owned(),
            tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        };
        FederationDirectory::put_attestation(
            &*backend,
            ciris_persist::federation::SignedAttestation { attestation: edge },
        )
        .await
        .expect("restore user trust edge");

        let dir: Arc<dyn FederationDirectory> = backend;
        let gate = TransitGate::new(dir, Some("gate-user".to_string()));

        // The gate, per peer: ALLOW the shared-root peer, refuse the
        // self-claimed one (witness (e)'s peer — registered + role string +
        // 50 bogus roots, exactly what AV-75 says buys nothing).
        assert!(
            gate.is_eligible_hop("gate-peer", now).await,
            "node + infra:transport + shared valid root ⇒ eligible hop (ALLOW)"
        );
        assert!(
            !gate.is_eligible_hop("gate-flooded", now).await,
            "self-claimed infra:transport rooted only to its own bogus roots ⇒ refused"
        );

        // The pool filter + the GATED planner: only the eligible hop is
        // plannable, and it is selected as the primary parent.
        let mk = |peer: &str| super::super::join::ParentCandidate {
            signed_capacity: super::super::capacity::SignedRelayCapacity {
                advertiser_key_id: peer.to_string(),
                capacity: super::super::capacity::RelayCapacity::new(
                    100.0,
                    16,
                    64,
                    crate::transport::realtime_av::ReceiverLayerPolicy::UNCAPPED,
                    1_000,
                ),
                stream_id: crate::transport::realtime_av::StreamId([0xA1; 32]),
                epoch: crate::transport::realtime_av::Epoch(1),
                signature_ed25519_base64: String::new(),
                signature_ml_dsa_65_base64: String::new(),
            },
            reachability_ratio: Some(0.99),
            rtt_ms_estimate: Some(20),
        };
        let kept = gate
            .eligible_candidates(vec![mk("gate-peer"), mk("gate-flooded")], now)
            .await;
        assert_eq!(
            kept.len(),
            1,
            "exactly the eligible hop survives the filter"
        );
        assert_eq!(kept[0].peer_key_id(), "gate-peer");

        let plan = crate::transport::realtime_av_runtime::AvSubscriber::plan_parent_gated(
            &gate,
            vec![mk("gate-peer"), mk("gate-flooded")],
            2.5,
            crate::transport::realtime_av::ReceiverLayerPolicy::UNCAPPED,
            1_500,
            now,
        )
        .await
        .expect("the gated planner plans over the filtered pool");
        assert_eq!(
            plan.primary_parent, "gate-peer",
            "the ineligible hop is unselectable no matter its capacity ad"
        );
    }

    #[tokio::test]
    async fn unknown_peer_is_ineligible_and_the_denial_caches_briefly() {
        use ciris_persist::store::MemoryBackend;
        // Peer absent from the directory → conjunct (A) fails → persist denies →
        // gate refuses. Exercises the real resolve_transit_eligibility path.
        let dir: Arc<dyn FederationDirectory> = Arc::new(MemoryBackend::new());
        let gate = TransitGate::new(dir, Some("us".to_string()));
        assert!(
            !gate.is_eligible_hop("ghost-peer", t(0)).await,
            "peer not in the directory ⇒ ineligible"
        );
        // The denial is cached (negative TTL) — a second call is a cache hit and
        // stays refused. (Freshness of the negative cache is unit-tested above.)
        assert!(
            !gate.is_eligible_hop("ghost-peer", t(1)).await,
            "cached denial stays refused within the negative TTL"
        );
    }
}
