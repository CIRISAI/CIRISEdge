//! v7.0.0 (CIRISEdge#191 / #194 / #195) — explicit-hash addressing
//! parity + AnnounceControl policy coverage.
//!
//! Closes the N1 cryptographic-addressing half of CIRISEdge#191 with
//! the load-bearing primitive
//! `crate::transport::addressing::reticulum_destination_for_pubkey`:
//! given any 32-byte federation Ed25519 pubkey, every transport
//! (packet-radio, IP/Reticulum, HTTP) derives the IDENTICAL 16-byte
//! routable destination hash. The IP transport's v7.0.0 explicit-hash
//! adoption is the closure event — the dial side now indexes by the
//! same hash the receive side registers under via
//! `Destination::with_explicit_hash(..)` + `register_destination_at(..)`.
//!
//! This file exercises:
//!
//! 1. Byte-equal determinism: two operators with the same `fed_pubkey`,
//!    in two independent processes, derive the SAME destination hash
//!    without inter-process coordination. (`addressing` is pure +
//!    deterministic — no salts.)
//! 2. Sensitivity: a single-bit flip in `fed_pubkey` flips ≥1 bit in
//!    the derived hash (the SHA-256 avalanche property the hash relies
//!    on for collision-resistant routing).
//! 3. Cross-transport parity: the byte-equal derivation is the same
//!    primitive every transport calls. (Pure-function test — the
//!    transport modules are gated behind feature flags, so the
//!    parity check is against the primitive itself, not each
//!    transport's wiring.)
//! 4. Wire-break confirmation: the legacy
//!    `Destination::compute_destination_hash(name_hash, identity_hash)`
//!    derivation is NOT equal to the v7.0.0 explicit-hash derivation
//!    for the same `fed_pubkey`. Sending to the OLD address from a
//!    v7.0.0-explicit-hash receiver fails to land.
//! 5. AnnounceControl policy dispatch:
//!    - `CryptoTier::InvisibleEncrypted` (`SelfOnly`, `Family`) →
//!      suppress.
//!    - `CryptoTier::CommunityDek` (`Cohort{..}`) → suppress.
//!    - `CryptoTier::Plaintext` (`Public`) → allow.
//! 6. ExplicitHashCannotAnnounce: a `with_explicit_hash` destination
//!    returns `AnnounceError::ExplicitHashCannotAnnounce` from
//!    `Destination::announce(..)` — the Leviculum v0.7.0 guard that
//!    makes the default-suppress AnnounceControl posture safe.

#![cfg(feature = "transport-reticulum")]

use ciris_edge::announce_suppression::ScopePrivacyAnnouncePolicy;
use ciris_edge::cohort_scope::CohortScope;
use ciris_edge::transport::addressing::{
    destination_from_pubkey_bytes, reticulum_destination_for_pubkey, RETICULUM_DEST_LEN,
};
use leviculum_core::{
    AnnounceControl, AnnounceError, Destination, DestinationHash, DestinationType, Direction,
    Identity,
};
use rand::rngs::OsRng;
use rand::RngCore;

// ─── 1. Byte-equal determinism ──────────────────────────────────────

#[test]
fn explicit_hash_is_deterministic_across_independent_callers() {
    // The same fed_pubkey produces byte-identical destinations from
    // two independent constructions — no salts, no per-process state.
    let mut pk = [0u8; 32];
    OsRng.fill_bytes(&mut pk);
    let a = reticulum_destination_for_pubkey(&pk);
    let b = reticulum_destination_for_pubkey(&pk);
    assert_eq!(a, b, "deterministic derivation must be byte-equal");
    assert_eq!(a.len(), RETICULUM_DEST_LEN);
}

// ─── 2. Sensitivity / SHA-256 avalanche ─────────────────────────────

#[test]
fn explicit_hash_flips_on_single_bit_pubkey_change() {
    let mut pk = [0u8; 32];
    OsRng.fill_bytes(&mut pk);
    let h0 = reticulum_destination_for_pubkey(&pk);
    pk[0] ^= 0x01;
    let h1 = reticulum_destination_for_pubkey(&pk);
    assert_ne!(
        h0, h1,
        "a single-bit pubkey flip must change the destination hash",
    );
}

// ─── 3. Cross-transport parity ──────────────────────────────────────

#[test]
fn explicit_hash_byte_equal_across_pubkey_input_shapes() {
    // The 32-byte specialization (hot path for IP transport,
    // `reticulum_destination_for_pubkey`) and the slice form
    // (`destination_from_pubkey_bytes`, used by HTTP / packet-radio
    // transports' addressing) hash through the SAME SHA-256 truncation
    // — bytes are bytes, no shape distinction at the wire.
    let mut pk = [0u8; 32];
    OsRng.fill_bytes(&mut pk);
    let h32 = reticulum_destination_for_pubkey(&pk);
    let h_slice = destination_from_pubkey_bytes(&pk);
    assert_eq!(
        h32, h_slice,
        "32-byte specialization + slice form must produce byte-equal hashes \
         — the primitive is shape-agnostic so every transport (IP, packet-radio, HTTP) \
         routes to the SAME bytes",
    );
}

// ─── 4. Wire-break confirmation ─────────────────────────────────────

#[test]
fn explicit_hash_diverges_from_legacy_announce_bound_hash() {
    // v6.x legacy formula: `Destination::compute_destination_hash(
    //     compute_name_hash(app, aspect), identity.hash())`.
    // v7.0.0 formula: `sha256(fed_pubkey)[..16]`.
    // The two are computed over disjoint preimages — there is no
    // pubkey value for which they collide except by ~2^-128 chance.
    let identity = Identity::generate(&mut OsRng);
    let ed_bytes = identity.ed25519_verifying().to_bytes();
    let name_hash = Destination::compute_name_hash("ciris.edge", &["edge_v1"]);
    let legacy_hash = Destination::compute_destination_hash(&name_hash, identity.hash());
    let v7_hash = reticulum_destination_for_pubkey(&ed_bytes);
    assert_ne!(
        legacy_hash.as_bytes(),
        &v7_hash,
        "v7.0.0 explicit-hash derivation must differ from the legacy \
         announce-bound formula for the same pubkey — this is the \
         intentional wire-break (CIRISEdge#191).",
    );
}

// ─── 5. AnnounceControl policy dispatch ─────────────────────────────

#[test]
fn announce_control_suppresses_invisible_encrypted_scopes() {
    let policy = ScopePrivacyAnnouncePolicy::new();
    // SelfOnly → InvisibleEncrypted → suppress.
    let h_self = DestinationHash::new([0x11u8; 16]);
    policy.register_destination_scope(*h_self.as_bytes(), CohortScope::SelfOnly);
    assert!(
        policy.should_suppress_announce(&h_self),
        "SelfOnly destinations MUST be announce-suppressed",
    );
    // Family → InvisibleEncrypted → suppress.
    let h_family = DestinationHash::new([0x22u8; 16]);
    policy.register_destination_scope(*h_family.as_bytes(), CohortScope::Family);
    assert!(
        policy.should_suppress_announce(&h_family),
        "Family destinations MUST be announce-suppressed",
    );
}

#[test]
fn announce_control_suppresses_community_dek_scopes() {
    let policy = ScopePrivacyAnnouncePolicy::new();
    let h_cohort = DestinationHash::new([0x33u8; 16]);
    policy.register_destination_scope(
        *h_cohort.as_bytes(),
        CohortScope::Cohort {
            cohort_id: "alpha".into(),
        },
    );
    assert!(
        policy.should_suppress_announce(&h_cohort),
        "Cohort{{..}} destinations (CryptoTier::CommunityDek) MUST be announce-suppressed",
    );
}

#[test]
fn announce_control_allows_commons_plaintext_scopes() {
    let policy = ScopePrivacyAnnouncePolicy::new();
    let h_public = DestinationHash::new([0x44u8; 16]);
    policy.register_destination_scope(*h_public.as_bytes(), CohortScope::Public);
    assert!(
        !policy.should_suppress_announce(&h_public),
        "Public (Commons/federation) destinations MUST announce — \
         CryptoTier::Plaintext means structurally inspectable",
    );
}

#[test]
fn announce_control_unregistered_defaults_to_suppress() {
    // Safer-than-leak: an unregistered hash returns suppress. This
    // also closes the explicit-hash interlock — a destination
    // constructed via `with_explicit_hash` cannot be announced at all
    // (`AnnounceError::ExplicitHashCannotAnnounce`), so the policy
    // refusing unknown hashes never produces a wrong call.
    let policy = ScopePrivacyAnnouncePolicy::new();
    let h_unknown = DestinationHash::new([0x99u8; 16]);
    assert!(
        policy.should_suppress_announce(&h_unknown),
        "unregistered destination MUST default-suppress",
    );
}

// ─── 6. ExplicitHashCannotAnnounce ──────────────────────────────────

#[test]
fn explicit_hash_destination_refuses_to_announce() {
    // Leviculum v0.7.0 returns `AnnounceError::ExplicitHashCannotAnnounce`
    // on any attempt to announce a `with_explicit_hash` destination —
    // the load-bearing guard that keeps the explicit-hash route from
    // ever appearing in the wire-format announce stream (where every
    // Python-RNS peer would recompute the standard formula and
    // reject).
    let identity = Identity::generate(&mut OsRng);
    let mut pk = [0u8; 32];
    OsRng.fill_bytes(&mut pk);
    let explicit = reticulum_destination_for_pubkey(&pk);
    let mut dest = Destination::with_explicit_hash(
        Some(identity),
        Direction::In,
        DestinationType::Single,
        "ciris.edge",
        &["edge_v1"],
        explicit,
    )
    .expect("with_explicit_hash construction succeeds");
    let mut rng = OsRng;
    let now_ms: u64 = 1_700_000_000_000;
    let err = dest
        .announce(None, &mut rng, now_ms)
        .expect_err("explicit-hash destination must refuse announce");
    assert!(
        matches!(err, AnnounceError::ExplicitHashCannotAnnounce),
        "expected AnnounceError::ExplicitHashCannotAnnounce, got {err:?}",
    );
}
