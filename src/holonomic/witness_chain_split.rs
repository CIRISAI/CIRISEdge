//! §3.4 witness chain split (CIRISEdge#175, v6.1.0).
//!
//! The CEWP `SCOPE_PRIVACY.md` §3.4 construction splits the
//! pre-v6.1.0 federation-wide `WholenessWitness` singleton at
//! [`super::wholeness_witness::WholenessWitness`] into TWO
//! distinct witness chains:
//!
//! ## Federation witness chain (federation-public)
//!
//! Signed federation-public. Commits to federation-scope
//! `record_id`s **plus a single rate-smoothed counter** for
//! non-federation activity. The counter ticks on a federation-wide
//! constant schedule (1 tick / federation epoch). At each tick the
//! witness commits to `count mod target_rate`:
//!
//! - **Real leaves below target** are padded by cover leaves to the
//!   target — `HMAC-SHA3(witness_signing_key, leaf_position ||
//!   epoch_id)` via verify v6.3.0's
//!   [`crate::scope_privacy::witness_cover_leaf`]. The cover-leaf
//!   bytes are cryptographically indistinguishable from real
//!   Merkle roots under the IND of HMAC-SHA3.
//! - **Real leaves above target** back-pressure into the next
//!   tick (the over-budget remainder rides the next tick's leaf
//!   set first).
//!
//! Deviation from the constant tick is a federation-tier slashing
//! condition (CC 13.3 governance hook). The constant-tick
//! enforcement is a federation-tier substrate decision —
//! [`FederationWitness`] surfaces the bookkeeping, the slashing
//! decision lives in CIRISNodeCore.
//!
//! ## Per-community witness chain (signed INSIDE the community MLS)
//!
//! Commits to the community's `record_id` set with member-only
//! visibility. Per-community anti-entropy of witness leaves; the
//! signature is computed inside the community MLS encryption
//! boundary so non-members cannot read it.
//!
//! Consumer-side disambiguation at verification:
//!
//! - federation peers verify [`FederationWitness`] against the
//!   federation-public ML-DSA-65 + Ed25519 hybrid signature path
//!   (the existing `WholenessWitness` verify surface).
//! - community members verify [`CommunityWitness`] against the
//!   community's MLS ratchet — the wire envelope is an MLS
//!   `PrivateMessage` whose plaintext is the witness body.
//!
//! # v6.1.0 surface
//!
//! - [`FederationWitness`] — federation-public witness body with
//!   the rate-smoothed counter built in.
//! - [`CommunityWitness`] — per-community witness body. Carries
//!   the community's `record_id` leaf set and the community-MLS
//!   epoch the body was signed under.
//! - [`pad_to_target`] — the §3.4 cover-leaf padding helper.
//!   Real-leaf-count, padding-leaf-count, and the resulting leaf
//!   multiset are returned so the caller can feed
//!   [`super::wholeness_witness::compute_merkle_root`] without
//!   re-deriving the constant-tick rule.

use crate::scope_privacy::witness_cover_leaf;

use super::wholeness_witness::WholenessWitness;

/// Default federation-tier constant target-rate (leaves per tick).
/// Operators can override per [`FederationWitness::with_target_rate`];
/// the default is the substrate-wide v6.1.0 value.
///
/// The §3.4 rule: `count mod target_rate`. Below target, real
/// leaves are padded by cover leaves to the target; above target,
/// the over-budget remainder back-pressures into the next tick.
pub const DEFAULT_FEDERATION_TARGET_RATE: u32 = 64;

/// Outcome of [`pad_to_target`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PaddedLeafSet {
    /// All leaves (real + cover) ready to feed `compute_merkle_root`.
    pub leaves: Vec<Vec<u8>>,
    /// Number of real (caller-provided) leaves committed to this
    /// tick. May be less than `caller_provided.len()` if the
    /// caller's input exceeded `target_rate` and the over-budget
    /// remainder back-pressured into the next tick.
    pub real_committed: u32,
    /// Number of cover leaves (HMAC-SHA3 padding) injected to bring
    /// the multiset to `target_rate`.
    pub cover_injected: u32,
    /// Leaves that back-pressured into the next tick because the
    /// caller's real-leaf count exceeded `target_rate`.
    pub backpressure: Vec<Vec<u8>>,
}

/// §3.4 pad-to-target helper. Pads `real_leaves` to `target_rate`
/// with HMAC-SHA3 cover leaves; if the real count exceeds the
/// target, returns the over-budget remainder as `backpressure`.
///
/// `witness_signing_key` is the federation witness's HMAC key (the
/// key MUST NOT be the same as the federation signing key — see
/// CC 1.13.5 vocabulary-boundary discipline; the HMAC key is a
/// distinct derived key the operator owns).
///
/// `epoch_id` is the federation epoch this tick is for.
///
/// Cover leaves are `HMAC-SHA3-256(key, leaf_position || epoch_id)`
/// per [`witness_cover_leaf`]; `leaf_position` is a `u32`
/// starting at the first cover slot.
#[must_use]
pub fn pad_to_target(
    real_leaves: Vec<Vec<u8>>,
    witness_signing_key: &[u8; 32],
    epoch_id: u64,
    target_rate: u32,
) -> PaddedLeafSet {
    let target_usize = target_rate as usize;

    // Over-budget split: only the first `target_rate` real leaves
    // commit; remainder back-pressures.
    let (committed, backpressure) = if real_leaves.len() > target_usize {
        let bp = real_leaves[target_usize..].to_vec();
        (real_leaves[..target_usize].to_vec(), bp)
    } else {
        (real_leaves, Vec::new())
    };

    // `committed.len() <= target_usize = target_rate as usize`,
    // and `target_rate: u32`, so the cast is safe by construction.
    let real_committed =
        u32::try_from(committed.len()).expect("committed.len() ≤ target_rate ≤ u32::MAX");
    let cover_slots = target_rate.saturating_sub(real_committed);

    let mut leaves = committed;
    for i in 0..cover_slots {
        let pos = real_committed + i;
        let cover = witness_cover_leaf(witness_signing_key, pos, epoch_id);
        leaves.push(cover.to_vec());
    }

    PaddedLeafSet {
        leaves,
        real_committed,
        cover_injected: cover_slots,
        backpressure,
    }
}

/// Federation-public witness chain body (§3.4).
///
/// Wraps a [`WholenessWitness`] (the existing federation-public
/// Merkle witness primitive) PLUS the §3.4 constant-tick
/// counter for non-federation activity. The wrapped witness's
/// `leaf_count` always equals `target_rate` — the cover-padding
/// is part of the Merkle leaf set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationWitness {
    /// The federation-public witness whose leaves include the
    /// constant-tick cover padding. The signature on this body is
    /// the federation-public ML-DSA-65 + Ed25519 hybrid pair (per
    /// the existing [`WholenessWitness`] discipline).
    pub witness: WholenessWitness,
    /// Number of real (non-cover) leaves committed in this tick.
    /// Cover leaves number `witness.leaf_count - real_count`.
    pub real_count: u32,
    /// Federation-wide constant target rate.
    pub target_rate: u32,
}

impl FederationWitness {
    /// Construct with the v6.1.0 default
    /// [`DEFAULT_FEDERATION_TARGET_RATE`].
    #[must_use]
    pub fn new(witness: WholenessWitness, real_count: u32) -> Self {
        Self {
            witness,
            real_count,
            target_rate: DEFAULT_FEDERATION_TARGET_RATE,
        }
    }

    /// Construct with an operator-tuned target rate.
    #[must_use]
    pub fn with_target_rate(witness: WholenessWitness, real_count: u32, target_rate: u32) -> Self {
        Self {
            witness,
            real_count,
            target_rate,
        }
    }

    /// `count mod target_rate` — the value the §3.4 federation
    /// witness commits to (alongside the real-leaf Merkle root).
    /// Surface for consumer-side rate-tick verification.
    #[must_use]
    pub fn rate_smoothed_counter(&self) -> u32 {
        self.real_count % self.target_rate
    }

    /// Number of cover-padding leaves injected for this tick.
    #[must_use]
    pub fn cover_count(&self) -> u32 {
        self.witness.leaf_count.saturating_sub(self.real_count)
    }
}

/// Per-community witness chain body (§3.4).
///
/// Distinct from [`FederationWitness`]: the body is signed INSIDE
/// the community MLS encryption boundary. The wrapped
/// [`WholenessWitness`] body is the message plaintext of an MLS
/// `PrivateMessage`; non-members cannot read it.
///
/// `community_id` and `mls_group_epoch` are not part of the
/// federation-public observation — they're the in-MLS context the
/// receiver verifies against its own MLS state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommunityWitness {
    /// The witness body. Carries the community's `record_id`
    /// Merkle root (FSD §2.4 HMAC-SHA3 record_id leaves).
    ///
    /// **Important**: the `signature*` / `pqc_key_id` fields on
    /// this body are NOT used at the federation-public layer —
    /// the community-MLS sender authentication supersedes the
    /// hybrid-pair signature surface. Producers MAY still fill
    /// them as a defense-in-depth measure (the body is then
    /// independently verifiable by another member who has
    /// extracted it from the MLS plaintext); they MAY leave them
    /// empty if the community policy is "MLS sender-auth
    /// suffices".
    pub witness: WholenessWitness,
    /// Community identifier (the same `cohort_id` carried in
    /// [`crate::cohort_scope::CohortScope::Cohort`]).
    pub community_id: String,
    /// MLS group epoch the body was signed under.
    pub mls_group_epoch: u64,
}

impl CommunityWitness {
    /// Construct a per-community witness body.
    #[must_use]
    pub fn new(
        witness: WholenessWitness,
        community_id: impl Into<String>,
        mls_group_epoch: u64,
    ) -> Self {
        Self {
            witness,
            community_id: community_id.into(),
            mls_group_epoch,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(b: u8) -> Vec<u8> {
        vec![b; 32]
    }

    #[test]
    fn pad_below_target_injects_cover() {
        let key = [0x55u8; 32];
        let real = vec![leaf(1), leaf(2), leaf(3)];
        let padded = pad_to_target(real.clone(), &key, 7, 10);
        assert_eq!(padded.real_committed, 3);
        assert_eq!(padded.cover_injected, 7);
        assert_eq!(padded.leaves.len(), 10);
        assert!(padded.backpressure.is_empty());
        // First three leaves are the real bytes.
        assert_eq!(&padded.leaves[..3], &real[..]);
    }

    #[test]
    fn pad_above_target_back_pressures() {
        let key = [0x11u8; 32];
        let real = vec![leaf(1), leaf(2), leaf(3), leaf(4), leaf(5)];
        let padded = pad_to_target(real.clone(), &key, 7, 3);
        assert_eq!(padded.real_committed, 3);
        assert_eq!(padded.cover_injected, 0);
        assert_eq!(padded.leaves.len(), 3);
        assert_eq!(padded.backpressure, vec![leaf(4), leaf(5)]);
    }

    #[test]
    fn pad_at_target_no_padding_no_backpressure() {
        let key = [0u8; 32];
        let real = vec![leaf(1); 4];
        let padded = pad_to_target(real, &key, 0, 4);
        assert_eq!(padded.real_committed, 4);
        assert_eq!(padded.cover_injected, 0);
        assert!(padded.backpressure.is_empty());
    }

    #[test]
    fn cover_leaves_deterministic_per_key_epoch() {
        let key = [0xAAu8; 32];
        let p1 = pad_to_target(vec![], &key, 99, 8);
        let p2 = pad_to_target(vec![], &key, 99, 8);
        assert_eq!(p1.leaves, p2.leaves, "same key+epoch → same cover leaves");
        let p3 = pad_to_target(vec![], &key, 100, 8);
        assert_ne!(p1.leaves, p3.leaves, "different epoch → different leaves");
    }

    #[test]
    fn rate_smoothed_counter_modulo() {
        let body = WholenessWitness {
            peer_id: "fed".into(),
            epoch_id: 1,
            merkle_root: [0; 32],
            leaf_count: 64,
            claim_namespaces: vec![],
            observed_at_unix_ms: 0,
            witness_version: 1,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        };
        let fw = FederationWitness::with_target_rate(body, 70, 64);
        assert_eq!(fw.rate_smoothed_counter(), 70 % 64);
        assert_eq!(fw.cover_count(), 0);
    }

    #[test]
    fn cover_count_reflects_padding() {
        let body = WholenessWitness {
            peer_id: "fed".into(),
            epoch_id: 1,
            merkle_root: [0; 32],
            leaf_count: 64,
            claim_namespaces: vec![],
            observed_at_unix_ms: 0,
            witness_version: 1,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        };
        let fw = FederationWitness::new(body, 10);
        assert_eq!(fw.target_rate, DEFAULT_FEDERATION_TARGET_RATE);
        assert_eq!(fw.cover_count(), 54);
    }

    #[test]
    fn community_witness_carries_mls_context() {
        let body = WholenessWitness {
            peer_id: "alice".into(),
            epoch_id: 9,
            merkle_root: [1; 32],
            leaf_count: 3,
            claim_namespaces: vec!["holding_claim".into()],
            observed_at_unix_ms: 0,
            witness_version: 1,
            signature: String::new(),
            signature_ml_dsa_65: String::new(),
            pqc_key_id: String::new(),
        };
        let cw = CommunityWitness::new(body, "community-A", 42);
        assert_eq!(cw.community_id, "community-A");
        assert_eq!(cw.mls_group_epoch, 42);
    }
}
