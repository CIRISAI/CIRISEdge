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

use ciris_persist::federation::types::{algorithm, identity_type, KeyRecord, SignedKeyRecord};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::MemoryBackend;

use ciris_edge::replication::bridge::{CohortProvider, FederationDirectoryReplicationBridge};
use ciris_edge::replication::{EnvelopeKind, ReplicationDirectory};

// ─── Helpers ────────────────────────────────────────────────────────

fn fresh_bridge(cohort: Vec<String>) -> (Arc<MemoryBackend>, FederationDirectoryReplicationBridge) {
    let backend = Arc::new(MemoryBackend::new());
    let dir: Arc<dyn FederationDirectory> = backend.clone();
    let cohort_cb: CohortProvider = Arc::new(move || cohort.clone());
    let bridge = FederationDirectoryReplicationBridge::new(dir, cohort_cb);
    (backend, bridge)
}

fn fixture_key_record(key_id: &str, identity_type_: &str) -> KeyRecord {
    let now = chrono::Utc::now();
    KeyRecord {
        key_id: key_id.to_string(),
        pubkey_ed25519_base64: "0".repeat(44),
        pubkey_ml_dsa_65_base64: None,
        algorithm: algorithm::HYBRID.to_string(),
        identity_type: identity_type_.to_string(),
        identity_ref: format!("{identity_type_}-ref-{key_id}"),
        valid_from: now,
        valid_until: None,
        registration_envelope: serde_json::json!({
            "key_id": key_id,
            "identity_type": identity_type_,
        }),
        original_content_hash: "0".repeat(64),
        scrub_signature_classical: "x".repeat(88),
        scrub_signature_pqc: None,
        scrub_key_id: key_id.to_string(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        roles: Vec::new(),
        attestation_evidence: None,
    }
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
    let key_id = "agent-bravo";
    let (backend, bridge) = fresh_bridge(vec![
        key_id.to_string(),
        key_id.to_string(),
        key_id.to_string(),
    ]);
    backend
        .put_public_key(SignedKeyRecord {
            record: fixture_key_record(key_id, identity_type::AGENT),
        })
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
    let key_id = "agent-charlie";
    let (backend, bridge) = fresh_bridge(vec![key_id.to_string()]);
    backend
        .put_public_key(SignedKeyRecord {
            record: fixture_key_record(key_id, identity_type::AGENT),
        })
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

    // 3. Bytes decode to the same record.
    let decoded: SignedKeyRecord = serde_json::from_slice(&bytes).expect("decode");
    assert_eq!(decoded.record.key_id, key_id);

    // 4. apply_envelope_bytes is idempotent on matching content
    //    (persist returns Ok on dedup).
    let admitted = bridge.apply_envelope_bytes(EnvelopeKind::Key, &bytes).await;
    assert!(admitted, "idempotent re-apply succeeds");
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
