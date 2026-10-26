//! v6.2.0 (#179, CIRISPersist#249 Cut D) — `fan_out_for_member`
//! combinator equivalence + dispatch-completeness invariants.
//!
//! The bridge's 9 per-kind cohort fan-outs collapsed into a single
//! parameterized combinator (`fan_out_for_member`). This integration
//! test fences the refactor by asserting:
//!
//! 1. **Dispatch completeness** — `list_envelope_refs(kind)` returns a
//!    well-formed `Vec<EnvelopeRef>` (possibly empty) for every
//!    `EnvelopeKind` variant. No panics, no `unimplemented!()`. This is
//!    the structural invariant the per-kind unrolling provided
//!    implicitly via the `match` arms.
//!
//! 2. **Empty-backend → empty refs across ALL kinds** — the combinator
//!    handles the no-rows case identically to the v6.1.0 hand-unrolled
//!    code. (The v6.1.0 implementation used per-block
//!    `if let Ok(rows) = ...` which silently absorbed errors; the
//!    combinator uses `unwrap_or_default()` for the same semantics.)
//!
//! 3. **Cohort-iteration shape preserved** — repeated cohort entries
//!    yielding the same `key_id` deduplicate per the
//!    `seen: HashSet<[u8; 32]>` dedupe; this invariant matters for the
//!    9 base kinds + the 3 `*_since` operational kinds (which also
//!    dedupe by hash, just from a different source).
//!
//! 4. **Key-kind round-trip continues to work** — the seeded-key
//!    round-trip exercises `list_keys` (still hand-written; not part of
//!    the combinator collapse since it's a point-read shape, not a
//!    fan-out shape). This serves as the canary that the broader
//!    refactor didn't perturb the shared cache + dispatch surface.
//!
//! ## What's NOT asserted here (intentional)
//!
//! - The persist-side `put_attestation` admission gate requires real
//!   hybrid PQC signatures (per the existing
//!   `federation_present_attestation_appears_in_list_envelope_refs`
//!   `#[ignore]` annotation). This test does not synthesize those; the
//!   existing per-kind unit tests inside `src/replication/bridge.rs`
//!   already cover the seed-and-list round trip for keys, and the
//!   structural shape this file asserts is what the combinator
//!   refactor needs to preserve.
//!
//! - Wire-format byte stability across the refactor is covered by
//!   `tests/replication_wire_proptest.rs` (which proptests the
//!   serialization/deserialization round-trip of every `EnvelopeKind`
//!   variant) — the combinator does not touch wire-frame serialization;
//!   it only changes the host-side enumeration shape.

use std::sync::Arc;

use ciris_persist::federation::types::{identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::SqliteBackend;

use ciris_edge::replication::bridge::{CohortProvider, FederationDirectoryReplicationBridge};
use ciris_edge::replication::{EnvelopeKind, ReplicationDirectory};

// ─── Helpers ────────────────────────────────────────────────────────

fn fresh_bridge(cohort: Vec<String>) -> (Arc<SqliteBackend>, FederationDirectoryReplicationBridge) {
    let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort_cb: CohortProvider = Arc::new(move || cohort.clone());
    let bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb);
    (backend, bridge)
}

/// A persist-minted, self-scrubbed hybrid key record (proof of possession
/// over its own registration envelope). persist #1103 (CC 2.6.8): its
/// `key_id` is DERIVED by persist's engine from the signer's own Ed25519
/// pubkey (`derive_key_id(label, pubkey)`), never hand-written; and since
/// persist v59 only a verifiable record has the `key:record:v1` row the Key
/// plane carries. Tests reference the returned record's `key_id`.
async fn minted_key_record(label: &str, identity_type_: &str, seed: u8) -> KeyRecord {
    use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
    let classical: Arc<dyn HardwareSigner> =
        Arc::new(Ed25519SoftwareSigner::from_bytes(&[seed; 32], label).expect("ed25519 from seed"));
    let pqc: Arc<dyn PqcSigner> = Arc::new(
        MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{label}-pqc"))
            .expect("ml-dsa-65 from seed"),
    );
    let signer = ciris_persist::prelude::LocalSigner::from_hardware_parts(
        classical,
        label.to_owned(),
        Some(pqc),
        Some(format!("{label}-pqc")),
    )
    .await
    .expect("hybrid local signer");
    let engine = ciris_persist::Engine::with_signer(Arc::new(signer), "sqlite::memory:")
        .await
        .expect("throwaway engine");
    let key_id = engine
        .register_self_federation_key(
            identity_type_,
            label,
            None,
            serde_json::json!({}),
            Vec::new(),
        )
        .await
        .expect("mint a self-signed, subject-bound key record");
    FederationDirectory::lookup_public_key(&*engine.federation_directory(), &key_id)
        .await
        .expect("read back")
        .expect("the minted record exists")
}

/// Every `EnvelopeKind` variant — both the 9 base kinds the v6.2.0
/// combinator collapses AND the 3 operational `*_since` kinds (which
/// also went through the same structural review per #179).
fn all_envelope_kinds() -> &'static [EnvelopeKind] {
    &[
        EnvelopeKind::Key,
        EnvelopeKind::Attestation,
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::Family,
        EnvelopeKind::Community,
        EnvelopeKind::IdentityOccurrenceRevocation,
        EnvelopeKind::FamilyMembershipRevocation,
        EnvelopeKind::CommunityMembershipRevocation,
        EnvelopeKind::LocationProof,
        EnvelopeKind::Organization,
        EnvelopeKind::OrgMembership,
        EnvelopeKind::PartnerRecord,
    ]
}

// ─── Invariant 1 — dispatch completeness ────────────────────────────

/// Every `EnvelopeKind` resolves to a well-formed (possibly empty) ref
/// list. This is the load-bearing invariant the combinator must
/// preserve: each per-kind site of the v6.1.0 9× unrolling becomes ONE
/// call site through the combinator, and missing one would surface as a
/// `match`-arm gap in `list_envelope_refs`.
#[tokio::test]
async fn every_envelope_kind_dispatches_through_combinator() {
    let (_backend, bridge) = fresh_bridge(vec!["agent-alpha".to_string()]);
    for kind in all_envelope_kinds() {
        let refs = bridge.list_envelope_refs(*kind).await;
        // No panic; empty is fine — backend is empty.
        assert!(
            refs.is_empty(),
            "kind={kind:?} empty-backend MUST yield empty refs, got {refs:?}"
        );
    }
}

// ─── Invariant 2 — empty backend, every kind ────────────────────────

/// Empty cohort + empty backend: every kind yields empty. Sanity that
/// the combinator's early `cohort.is_empty()` shortcut + the directory
/// trait's empty-list response don't perturb each other.
#[tokio::test]
async fn empty_cohort_yields_empty_refs_across_all_kinds() {
    let (_backend, bridge) = fresh_bridge(Vec::new());
    for kind in all_envelope_kinds() {
        let refs = bridge.list_envelope_refs(*kind).await;
        assert!(refs.is_empty(), "kind={kind:?} expected empty");
    }
}

// ─── Invariant 3 — cohort dedupe via the combinator's HashSet ────────

/// The combinator's `seen: HashSet<[u8; 32]>` dedupe fires when the
/// cohort callback yields the same `key_id` more than once. Seed one
/// Key, list with a cohort that names that key 3 times — exactly one
/// ref surfaces.
#[tokio::test]
async fn cohort_duplicates_dedupe_to_single_ref() {
    let record = minted_key_record("agent-bravo", identity_type::AGENT, 0x2b).await;
    let key_id = record.key_id.clone();
    let (backend, bridge) = fresh_bridge(vec![key_id.clone(), key_id.clone(), key_id]);
    backend
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("seed key");

    let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
    assert_eq!(
        refs.len(),
        1,
        "3 cohort entries → 1 ref (dedupe via HashSet<envelope_hash>)"
    );
}

// ─── Invariant 4 — key round-trip through the broader surface ───────

/// Seed → list → fetch → apply round-trip. `list_keys` is unchanged
/// from v6.1.0 (it's a point-read shape, not a fan-out — not part of
/// the combinator collapse); this serves as a canary that the shared
/// cache + dispatch surface still composes correctly post-refactor.
#[tokio::test]
async fn key_round_trips_across_combinator_refactor() {
    let record = minted_key_record("agent-charlie", identity_type::AGENT, 0x2c).await;
    let key_id = record.key_id.clone();
    let (backend, bridge) = fresh_bridge(vec![key_id.clone()]);
    backend
        .put_public_key(SignedKeyRecord { record })
        .await
        .expect("seed key");

    // 1. list_envelope_refs surfaces the seeded key.
    let refs = bridge.list_envelope_refs(EnvelopeKind::Key).await;
    assert_eq!(refs.len(), 1);
    let hash = refs[0].envelope_hash;

    // 2. fetch_envelope_bytes returns the cached canonical bytes.
    let bytes = bridge
        .fetch_envelope_bytes(EnvelopeKind::Key, &hash)
        .await
        .expect("bytes cached during list");

    // 3. Bytes decode to the same record — persist v59: the bytes are the
    //    key's `key:record:v1` row, which carries the record.
    let row: ciris_persist::federation::Attestation =
        serde_json::from_slice(&bytes).expect("decode row");
    let decoded =
        ciris_persist::federation::key_plane::key_record_of_row(&row).expect("the row's record");
    assert_eq!(decoded.key_id, key_id);

    // 4. apply_envelope_bytes is idempotent on matching content: a
    //    byte-identical re-apply of a row this node already holds is the
    //    receiver holding what was offered — `Unchanged` ⇒ `Duplicate`, never
    //    an error and never a refusal. Since persist v44.7.0 (#864) the memory
    //    backend runs the same key plan sqlite does, so this is the verdict
    //    on every backend (before, the plan-less memory default reported a
    //    first-seen Inserted for the same bytes).
    let outcome = bridge
        .apply_envelope_bytes(EnvelopeKind::Key, &bytes, Some("self"))
        .await;
    assert!(
        matches!(outcome, ciris_edge::replication::ApplyOutcome::Duplicate),
        "idempotent re-apply is a Duplicate, got {outcome:?}"
    );
}

// ─── Invariant 5 — no key in cohort means no refs ───────────────────

/// A cohort entry that does NOT resolve to a backend row yields no
/// refs (silent skip on `Err(_)` from the directory). This was the
/// v6.1.0 `if let Ok(rows) = ...` semantics; the combinator preserves
/// it via `unwrap_or_default()`. Asserted across every kind.
#[tokio::test]
async fn unresolved_cohort_member_silently_skipped_across_kinds() {
    let (_backend, bridge) = fresh_bridge(vec!["nonexistent-key-id".to_string()]);
    for kind in all_envelope_kinds() {
        let refs = bridge.list_envelope_refs(*kind).await;
        assert!(
            refs.is_empty(),
            "kind={kind:?} with unresolved cohort member MUST be empty"
        );
    }
}
