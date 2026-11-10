//! **CIRISEdge#971 — every persist door that writes `signed_wire_index`, one
//! witness each.** The door table is in [`super::holdings_index`]'s module
//! docs; each row there names the witness here (or in
//! `holdings_index_971_tests`) that drives the door over a real sqlite store
//! and asserts the holdings set equals a full drain of the index afterwards,
//! on both planes, with no audit (spacing zero, audit an hour) unless the
//! door is a REMOVE, whose repair is the audit by design.
//!
//! Rows authored here are signed with persist's deterministic test keys
//! (`tier_ingest::test_support`, behind edge's `test-anchor` dev feature),
//! registered first, as persist's own invariants do.
//!
//! `cargo test --lib holdings_doors_971`

use std::sync::Arc;
use std::time::Duration;

use ciris_persist::federation::tier_ingest::test_support as ts;
use ciris_persist::federation::types::{attestation_type, cohort_scope, identity_type};
use ciris_persist::federation::{FederationDirectory, SignedAttestation};
use ciris_persist::store::sqlite::SqliteBackend;

use super::holdings_index_971_tests::{
    assert_index_equal, bridge_with, counter, index_drain, index_on, refs_of, NO_TEST_OUTLIVES,
};
use super::park_fresh_858_tests::substrate;
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

/// A bridge whose every ask brings the feeds current (spacing zero) and that
/// never audits on its own (an hour), warmed: every record keyed, both
/// planes Ready.
async fn warmed(
    dir: &Arc<SqliteBackend>,
    me: &str,
    metrics: Option<obs::EdgeMetrics>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let bridge = bridge_with(
        Arc::clone(dir) as Arc<dyn FederationDirectory>,
        me,
        vec![me.to_owned()],
        BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            holdings_audit_every: NO_TEST_OUTLIVES,
            ..index_on()
        },
        metrics,
    );
    bridge.warm_holdings_index().await;
    assert_index_equal(&bridge, &**dir, &[], "warmed").await;
    bridge
}

/// A store with persist test keys `ids` registered under `role`.
async fn store_with(ids: &[&str], role: &str) -> Arc<SqliteBackend> {
    let dir = substrate().await;
    for id in ids {
        ts::register_hybrid_key_as(&*dir, id, id, role).await;
    }
    dir
}

/// **Door: promotion** (`enter_mesh`, persist sqlite.rs:7590). A local-tier
/// row has no index entry; its crossing re-stamps the serve position and
/// indexes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_promotion_971() {
    use ciris_persist::federation::types::LocalAttestationInput;
    let dir = store_with(&["door-pro-a", "door-pro-b"], identity_type::AGENT).await;
    let bridge = warmed(&dir, "door-pro-a", None).await;
    let id = dir
        .attestation_insert_local(LocalAttestationInput {
            attestation_id: None,
            attesting_key_id: "door-pro-a".to_owned(),
            attested_key_id: Some("door-pro-b".to_owned()),
            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
            weight: Some(1.0),
            expires_at: None,
            attestation_envelope: ciris_persist::federation::envelope::EnvelopeCore::from_value(
                serde_json::json!({
                    "dimension": ciris_persist::federation::self_at_login::DIMENSION_DELEGATES_TO,
                    "scope": ["act_on_behalf"],
                }),
            )
            .expect("envelope"),
            subject_key_ids: Vec::new(),
            cohort_scope: cohort_scope::SELF.to_owned(),
            scrub_signature_classical: None,
            scrub_signature_pqc: None,
        })
        .await
        .expect("the local door");
    assert_index_equal(&bridge, &*dir, &[], "promotion: local, no entry").await;
    let local = dir.get_attestation(&id).await.expect("read").expect("held");
    let ci = ts::describe_own(
        &local,
        ciris_persist::federation::CrossingBasis::ProducerAuthority,
    );
    dir.enter_mesh(&id, &ci, &ts::actor_reseal(&local))
        .await
        .expect("crossed");
    assert_index_equal(&bridge, &*dir, &[], "promotion: crossed").await;
}

/// **Door: holder claim** (`index_holder_claim`, persist sqlite.rs:2834, from
/// `store_planned_blob` and `store_holding_claim`). The commons
/// store-and-claim path, then a second holder's claim on the same bytes.
/// (`store_planned_announcement` is reachable only from persist's own tests:
/// no witness can drive it from here, see the door table.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_holder_claim_971() {
    use ciris_persist::federation::blobs::{BlobBody, BlobStorage as _};
    use ciris_persist::federation::holding_claim::{sign_holding_claim, ClaimScope};
    use ciris_persist::federation::types::cohort_scope::CryptoTier;
    use sha2::Digest as _;
    let dir = store_with(&["door-hold-h", "door-hold-p"], identity_type::NODE).await;
    let h = ts::local_signer("door-hold-h");
    let h_key = h.derived_key_id();
    ts::register_hybrid_key_as(&*dir, &h_key, "door-hold-h", identity_type::NODE).await;
    let p = ts::local_signer("door-hold-p");
    let p_key = p.derived_key_id();
    ts::register_hybrid_key_as(&*dir, &p_key, "door-hold-p", identity_type::NODE).await;
    let bridge = warmed(&dir, &h_key, None).await;

    let body = b"door-hold-971".to_vec();
    let sha: [u8; 32] = sha2::Sha256::digest(&body).into();
    dir.put_blob_signing(
        &sha,
        BlobBody::Inline(body.clone()),
        None,
        &h_key,
        &h,
        chrono::Utc::now(),
        uuid::Uuid::new_v4(),
    )
    .await
    .expect("the commons store-and-claim");
    assert_index_equal(&bridge, &*dir, &[], "holder claim: first holder").await;

    let scope = ClaimScope::of_content(CryptoTier::Plaintext, cohort_scope::FEDERATION, None)
        .expect("scope");
    let claim = sign_holding_claim(
        &p,
        &sha,
        uuid::Uuid::new_v4(),
        chrono::Utc::now(),
        u64::try_from(body.len()).expect("fits"),
        &scope,
    )
    .await
    .expect("sign the claim");
    dir.put_holding_claim(&sha, claim, &scope)
        .await
        .expect("the second holder's claim");
    assert_index_equal(&bridge, &*dir, &[], "holder claim: second holder").await;
}

/// An owner binding signed with persist test keys, its PQC half not yet
/// attached; returns the row id and the PQC signature to attach.
async fn pqc_pending_binding(dir: &SqliteBackend, owner: &str, node: &str) -> (String, String) {
    let id = uuid::Uuid::new_v4().to_string();
    let mut row = ts::owner_binding_attestation(&id, owner, node);
    let pqc = row
        .scrub_signature_pqc
        .clone()
        .expect("the fixture row is hybrid-signed");
    row.pqc_completed_at = None;
    dir.put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("admit the binding, PQC pending");
    (id, pqc)
}

/// **Door: PQC completion** (`store_pqc_completion`, persist sqlite.rs:15008).
/// The row is held and keyed BEFORE the bridge boots (the warm-up's walk keys
/// it), so the completion replaces its hash in the set at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_pqc_completion_971() {
    let dir = store_with(&["door-pqc-o"], identity_type::USER).await;
    ts::register_hybrid_key_as(&*dir, "door-pqc-n", "door-pqc-n", identity_type::NODE).await;
    let (id, pqc) = pqc_pending_binding(&dir, "door-pqc-o", "door-pqc-n").await;
    let bridge = warmed(&dir, "door-pqc-n", None).await;
    let before = index_drain(&*dir, "Attestation").await;
    dir.attach_attestation_pqc_signature(&id, &pqc)
        .await
        .expect("attach the PQC half");
    let after = index_drain(&*dir, "Attestation").await;
    assert_ne!(before, after, "the completion re-indexed the row");
    assert_index_equal(&bridge, &*dir, &[], "pqc completion").await;
}

/// **Door: re-seal** (`store_planned_reseal`, persist sqlite.rs:15562). The
/// federation-tier row re-signed with its identity unchanged (persist's
/// `restamped` recipe, reseal_race_invariants.rs:46), held and keyed before
/// boot. persist has no test of a federation-tier re-seal; if this door
/// refuses the recipe, the witness names it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_reseal_971() {
    let dir = store_with(&["door-rs-o"], identity_type::USER).await;
    ts::register_hybrid_key_as(&*dir, "door-rs-n", "door-rs-n", identity_type::NODE).await;
    let id = uuid::Uuid::new_v4().to_string();
    let row = ts::owner_binding_attestation(&id, "door-rs-o", "door-rs-n");
    dir.put_attestation(SignedAttestation { attestation: row })
        .await
        .expect("admit the binding");
    let bridge = warmed(&dir, "door-rs-n", None).await;
    let stored = dir.get_attestation(&id).await.expect("read").expect("held");
    let mut resealed = stored.clone();
    resealed.attestation_envelope["restamped"] = serde_json::json!(true);
    ts::seal_row_in_place("door-rs-o", &mut resealed);
    ciris_persist::federation::canonical_at_rest::canonicalize_in_place(
        &mut resealed.attestation_envelope,
    )
    .expect("canonical");
    let (och, classical, pqc) = ts::sign_envelope("door-rs-o", &resealed.attestation_envelope);
    resealed.original_content_hash = och;
    resealed.scrub_signature_classical = classical;
    resealed.scrub_signature_pqc = pqc;
    let landed = dir
        .reseal_attestation_v31(&resealed)
        .await
        .expect("the re-seal door");
    assert!(landed, "the re-seal landed");
    assert_index_equal(&bridge, &*dir, &[], "re-seal").await;
}

/// **Door: group-plane link** (`link_group_plane_row`, persist
/// sqlite.rs:23199), through `put_family` (persist I1484's founding).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_group_plane_link_971() {
    use ciris_persist::federation::types::{Family, FamilyMember};
    let members = ["door-fam-ann", "door-fam-ben", "door-fam-cat"];
    let dir = store_with(&members, identity_type::USER).await;
    let bridge = warmed(&dir, "door-fam-ann", None).await;
    let founded_at = chrono::Utc::now();
    let family = Family {
        family_key_id: "door-fam-971".to_owned(),
        family_name: "household".to_owned(),
        members: members
            .iter()
            .map(|m| FamilyMember {
                key_id: (*m).to_owned(),
                joined_at: founded_at,
                role: Some("member".to_owned()),
            })
            .collect(),
        founded_at,
        consensus_protocol: "quorum:2/3".to_owned(),
        consensus_protocol_entrenched: false,
        prev_head_digest: String::new(),
        charter_digest: String::new(),
        dissolved_at: None,
        persist_row_hash: String::new(),
    };
    dir.put_family(ts::sign_family("door-fam-ann", family))
        .await
        .expect("the founding");
    assert_index_equal(&bridge, &*dir, &[], "group-plane link").await;
}

/// **Door: consent role** (`store_planned_consent_role`, persist
/// sqlite.rs:26501). It re-indexes the key's `key:record:v1` row, whose
/// bytes do not carry the role, so the index does not change; the witness is
/// that the set still equals it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn door_consent_role_971() {
    let dir = store_with(&["door-role-n"], identity_type::NODE).await;
    let bridge = warmed(&dir, "door-role-n", None).await;
    let before = index_drain(&*dir, "Attestation").await;
    dir.set_consent_role("door-role-n", Some("peer"))
        .await
        .expect("set the role");
    assert_eq!(
        index_drain(&*dir, "Attestation").await,
        before,
        "the role is not in the key row's bytes"
    );
    assert_index_equal(&bridge, &*dir, &[], "consent role").await;
}

/// **Removes: the projection purge and a purge execution** (persist
/// sqlite.rs:4829 and 24255). No cursor carries a remove: between audits the
/// set keeps the hash (the `extra` direction; a purged row is refused at
/// admission by its tombstone and erasure requires that this node not
/// re-acquire it, so not wanting it is the right want), and the audit removes
/// it (`drift_extra`), after which the set equals the index again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn removes_converge_at_the_audit_971() {
    use ciris_persist::federation::steward_purge::{PurgeExecution, PurgePlane, PurgeTombstone};
    let dir = store_with(&["door-rm-o", "door-rm-o2"], identity_type::USER).await;
    for n in ["door-rm-n", "door-rm-n2"] {
        ts::register_hybrid_key_as(&*dir, n, n, identity_type::NODE).await;
    }
    let first = uuid::Uuid::new_v4().to_string();
    dir.put_attestation(SignedAttestation {
        attestation: ts::owner_binding_attestation(&first, "door-rm-o", "door-rm-n"),
    })
    .await
    .expect("first row");
    let second = uuid::Uuid::new_v4().to_string();
    dir.put_attestation(SignedAttestation {
        attestation: ts::owner_binding_attestation(&second, "door-rm-o2", "door-rm-n2"),
    })
    .await
    .expect("second row");
    let metrics = obs::EdgeMetrics::new();
    let bridge = warmed(&dir, "door-rm-n", Some(metrics.clone())).await;
    let held = index_drain(&*dir, "Attestation").await;

    // 1. The projection purge drops the first row's entry.
    dir.purge_attestation_projections(&first)
        .await
        .expect("projection purge");
    // 2. A purge execution drops the second's.
    let now = chrono::Utc::now();
    let notice_id = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(b"door-rm-971"));
    let exec = PurgeExecution {
        notice_id: notice_id.clone(),
        selection_digest: "ab".repeat(32),
        claimant_key_id: "moderator-1".to_owned(),
        legal_basis: "ncmec_csam".to_owned(),
        record_count: 1,
        notice_jcs: "{}".to_owned(),
        cosignatures_json: "[]".to_owned(),
        executed_by: "door-rm-n".to_owned(),
        origin: ciris_persist::federation::steward_purge::origin::LOCAL.to_owned(),
        executed_at: now,
        admitted_at: now,
        finalized_at: None,
    };
    dir.purge_put_execution(
        &exec,
        &[PurgeTombstone {
            notice_id,
            ordinal: 0,
            plane: PurgePlane::Attestation,
            record_ref: second.clone(),
            derived_from: None,
        }],
    )
    .await
    .expect("purge execution");
    let after = index_drain(&*dir, "Attestation").await;
    let gone: Vec<[u8; 32]> = held.difference(&after).copied().collect();
    assert_eq!(gone.len(), 2, "both entries left the index");

    // Between audits: the set still holds them, so a peer offering them is
    // not asked for them (the extra direction).
    let offered = refs_of(&gone.iter().copied().collect());
    assert!(
        bridge
            .holdings_want(EnvelopeKind::Attestation, &offered)
            .await
            .is_empty(),
        "a purged hash is not wanted between audits"
    );

    // The audit removes them and counts them.
    bridge.holdings_audit_due_now();
    let _ = bridge.holdings_want(EnvelopeKind::Attestation, &[]).await;
    assert_eq!(counter(&metrics, obs::HOLDINGS_DRIFT_EXTRA[0]), 2);
    assert_index_equal(&bridge, &*dir, &[], "removes, after the audit").await;
}

/// **The retired-carrier class (condition 2).** A held row whose type is a
/// retired carrier (`holds_bytes:*`) is in the index and never on the serve
/// cursor. A PQC completion of it is not refused by type, re-stamps it and
/// re-indexes it under a new hash, which no feed sees: the set keeps the old
/// hash and lacks the new one until the audit (at most
/// [`super::holdings_index::DEFAULT_AUDIT_EVERY`]). The missing direction is
/// waste, and the seat shows it: a peer's offer of the new hash is wanted,
/// its apply is a `Duplicate`, and `duplicate_unheld` moves. The audit then
/// repairs both hashes (`drift_missing` 1, `drift_extra` 1).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_retired_carrier_row_rewritten_is_repaired_by_the_audit_971() {
    let dir = store_with(&["door-ret-o"], identity_type::USER).await;
    ts::register_hybrid_key_as(&*dir, "door-ret-n", "door-ret-n", identity_type::NODE).await;
    let (id, pqc) = pqc_pending_binding(&dir, "door-ret-o", "door-ret-n").await;
    dir.test_seam_set_attestation_type(&id, "holds_bytes:v1", None)
        .await
        .expect("retire the row's type");
    let metrics = obs::EdgeMetrics::new();
    let bridge = warmed(&dir, "door-ret-n", Some(metrics.clone())).await;
    let before = index_drain(&*dir, "Attestation").await;

    dir.attach_attestation_pqc_signature(&id, &pqc)
        .await
        .expect("the completion is not refused by type");
    let after = index_drain(&*dir, "Attestation").await;
    let new: Vec<[u8; 32]> = after.difference(&before).copied().collect();
    assert_eq!(new.len(), 1, "one new hash for the rewritten row");

    // Between audits the new hash is wanted: the missing direction.
    let offered = vec![EnvelopeRef {
        envelope_hash: new[0],
        seq: 0,
    }];
    assert_eq!(
        bridge
            .holdings_want(EnvelopeKind::Attestation, &offered)
            .await,
        vec![new[0]],
        "the set lacks the rewritten hash until the audit"
    );
    // The peer's delivery of those bytes is a Duplicate the seat counts. (If
    // persist refuses a retired type at the apply door before its dedup, the
    // seat's signal is that refusal instead; the first run says which, and
    // this assertion follows it.)
    let row = dir.get_attestation(&id).await.expect("read").expect("held");
    let bytes = serde_json::to_vec(&row).expect("encode");
    let _ = bridge
        .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, Some("door-ret-peer"))
        .await;
    assert_eq!(
        counter(&metrics, obs::HOLDINGS_DUPLICATE_UNHELD[0]),
        1,
        "duplicate_unheld shows the hole on the seat"
    );

    bridge.holdings_audit_due_now();
    let _ = bridge.holdings_want(EnvelopeKind::Attestation, &[]).await;
    assert_eq!(counter(&metrics, obs::HOLDINGS_DRIFT_MISSING[0]), 1);
    assert_eq!(counter(&metrics, obs::HOLDINGS_DRIFT_EXTRA[0]), 1);
    assert_index_equal(&bridge, &*dir, &[], "retired class, after the audit").await;
}

/// Seeds of the differential.
const SEEDS: u64 = 32;
/// Operations per seed.
const OPS: usize = 200;

/// What the differential's store holds, for the ops that act on it.
#[derive(Default)]
struct World {
    /// Owner-binding rows held at B: (row id, owner test key).
    bindings: Vec<(String, String)>,
    /// Bindings held with their PQC half pending: (row id, signature).
    pqc_pending: Vec<(String, String)>,
    /// Test keys registered at B.
    keys: Vec<String>,
    /// Hashes that left the index since the last audit (a remove's).
    removed: std::collections::HashSet<[u8; 32]>,
    /// A counter for fresh ids.
    n: u64,
}

impl World {
    fn fresh(&mut self, seed: u64, what: &str) -> String {
        self.n += 1;
        format!("dif971-{seed}-{what}-{}", self.n)
    }
}

/// The invariant between audits: every hash the index holds is in the set
/// (never missing a held hash), and every hash the set holds beyond the index
/// is one a remove took since the last audit. The want over the index's
/// hashes, the removed ones and foreign ones is the oracle's (a bridge with
/// the index OFF, the pre-v45 drain) minus exactly the removed hashes. After
/// an audit (`removed` empty) both are equalities.
async fn assert_tracks(
    on: &FederationDirectoryReplicationBridge,
    off: &FederationDirectoryReplicationBridge,
    dir: &dyn FederationDirectory,
    removed: &std::collections::HashSet<[u8; 32]>,
    step: &str,
) {
    let foreign = [[0xeeu8; 32], [0xefu8; 32]];
    for (kind, index) in [
        (EnvelopeKind::Attestation, "Attestation"),
        (EnvelopeKind::TransportDestination, "TransportDestination"),
    ] {
        let held = index_drain(dir, index).await;
        let mut offered: Vec<EnvelopeRef> = refs_of(&held);
        offered.extend(removed.iter().chain(foreign.iter()).map(|h| EnvelopeRef {
            envelope_hash: *h,
            seq: 0,
        }));
        let mut want_on = on.holdings_want(kind, &offered).await;
        let mut want_off = off.holdings_want(kind, &offered).await;
        want_on.sort_unstable();
        want_on.dedup();
        want_off.sort_unstable();
        want_off.dedup();
        let set = on
            .holdings_index_set(kind)
            .unwrap_or_else(|| panic!("{step} {index}: the set is Ready"));
        let missing: Vec<_> = held.difference(&set).collect();
        assert!(
            missing.is_empty(),
            "{step} {index}: the set lacks held hashes {missing:?}"
        );
        let extra: Vec<_> = set
            .difference(&held)
            .filter(|h| !removed.contains(*h))
            .collect();
        assert!(
            extra.is_empty(),
            "{step} {index}: the set holds unremoved extras {extra:?}"
        );
        let expected: Vec<[u8; 32]> = want_off
            .iter()
            .filter(|h| !(removed.contains(*h) && set.contains(*h)))
            .copied()
            .collect();
        assert_eq!(
            want_on, expected,
            "{step} {index}: the want is the oracle's"
        );
    }
}

/// **The differential (condition 5).** For each of [`SEEDS`] seeds, [`OPS`]
/// operations drawn from every door of the door table: the key door, an owner
/// binding (half of them PQC-pending), a route or its supersession, rows
/// authored at a peer and replicated in through the choke, a promotion, a
/// holder claim, a PQC completion, a re-seal, a group-plane founding, a
/// consent role, the projection purge, a purge execution, and an AUDIT as an
/// op of its own. After every op [`assert_tracks`] holds against a second
/// bridge with the index off (the oracle), and the four key-plane listings
/// equal that bridge's with its listing cache off ([`assert_key_planes_equal`]);
/// after every audit the set equals the index exactly. The seed and step are in every failure message.
/// Spacing zero and an audit cadence of an hour, so every add is caught by a
/// feed and only the audit op repairs.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // one op table
async fn the_set_tracks_the_index_through_every_door_971() {
    use super::holdings_index_971_tests::{route_at, splitmix, COVERED};
    use super::key_plane_v59_tests::{round, NodeA};
    use super::park_fresh_858_tests::{hold, Ident};
    let started = std::time::Instant::now();
    for seed in 0..SEEDS {
        let base = u8::try_from(seed % 60).expect("fits") * 4;
        let a = NodeA::build(&format!("dif971a{seed}"), base).await;
        let b_dir = substrate().await;
        for id in [&a.p, &a.n, &a.k] {
            hold(&b_dir, id).await;
        }
        let b_me = Ident::mint(&format!("dif971-b-{seed}"), "node", base + 3).await;
        hold(&b_dir, &b_me).await;
        let bridge_a = bridge_with(
            Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
            a.n.key_id(),
            vec![
                a.p.key_id().to_owned(),
                a.n.key_id().to_owned(),
                a.k.key_id().to_owned(),
            ],
            index_on(),
            None,
        );
        let publish = vec![b_me.key_id().to_owned(), a.n.key_id().to_owned()];
        let quiet = BridgeConfig {
            feed_probe_spacing: Duration::ZERO,
            holdings_audit_every: NO_TEST_OUTLIVES,
            ..index_on()
        };
        let on = bridge_with(
            Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
            b_me.key_id(),
            publish.clone(),
            quiet,
            None,
        );
        let off = bridge_with(
            Arc::clone(&b_dir) as Arc<dyn FederationDirectory>,
            b_me.key_id(),
            publish,
            BridgeConfig {
                holdings_index: false,
                key_plane_listing_cache: false,
                ..quiet
            },
            None,
        );
        on.warm_holdings_index().await;
        let mut w = World::default();
        let owner = w.fresh(seed, "owner");
        ts::register_hybrid_key_as(&*b_dir, &owner, &owner, identity_type::USER).await;
        ts::register_hybrid_key_as(&*a.dir, &owner, &owner, identity_type::USER).await;
        let mut epoch = 10u64;
        let mut rng = 0x5eed_0000_u64 + seed;
        assert_tracks(&on, &off, &*b_dir, &w.removed, &format!("seed {seed} boot")).await;
        for step in 0..OPS {
            let op = splitmix(&mut rng) % 13;
            let pick = usize::try_from(splitmix(&mut rng)).unwrap_or(0);
            let label = format!("seed {seed} step {step} op {op}");
            match op {
                // The key door.
                0 => {
                    let k = w.fresh(seed, "key");
                    ts::register_hybrid_key_as(&*b_dir, &k, &k, identity_type::NODE).await;
                    w.keys.push(k);
                }
                // An owner binding through `put_attestation`, PQC-pending half the time.
                1 => {
                    let node = w.fresh(seed, "node");
                    ts::register_hybrid_key_as(&*b_dir, &node, &node, identity_type::NODE).await;
                    w.keys.push(node.clone());
                    let id = uuid::Uuid::new_v4().to_string();
                    let mut row = ts::owner_binding_attestation(&id, &owner, &node);
                    if pick % 2 == 0 {
                        if let Some(pqc) = row.scrub_signature_pqc.clone() {
                            row.pqc_completed_at = None;
                            w.pqc_pending.push((id.clone(), pqc));
                        }
                    }
                    b_dir
                        .put_attestation(SignedAttestation { attestation: row })
                        .await
                        .unwrap_or_else(|e| panic!("{label}: binding: {e}"));
                    w.bindings.push((id, owner.clone()));
                }
                // A route at B or its supersession.
                2 => {
                    epoch += 1;
                    b_dir
                        .put_signed_transport_destination(&route_at(&b_me, epoch).await)
                        .await
                        .unwrap_or_else(|e| panic!("{label}: route: {e}"));
                }
                // Rows authored at A, replicated in through the choke.
                3 => {
                    let node = w.fresh(seed, "anode");
                    for d in [&a.dir, &b_dir] {
                        ts::register_hybrid_key_as(&**d, &node, &node, identity_type::NODE).await;
                    }
                    let id = uuid::Uuid::new_v4().to_string();
                    a.dir
                        .put_attestation(SignedAttestation {
                            attestation: ts::owner_binding_attestation(&id, &owner, &node),
                        })
                        .await
                        .unwrap_or_else(|e| panic!("{label}: binding at A: {e}"));
                    epoch += 1;
                    a.dir
                        .put_signed_transport_destination(&route_at(&a.n, epoch).await)
                        .await
                        .unwrap_or_else(|e| panic!("{label}: A supersedes N's route: {e}"));
                    for kind in COVERED {
                        round(kind, &bridge_a, a.n.key_id(), &on, b_me.key_id()).await;
                    }
                }
                // A promotion.
                4 => {
                    use ciris_persist::federation::types::LocalAttestationInput;
                    let (from, to) = (w.fresh(seed, "pfrom"), w.fresh(seed, "pto"));
                    for k in [&from, &to] {
                        ts::register_hybrid_key_as(&*b_dir, k, k, identity_type::AGENT).await;
                    }
                    let id = b_dir
                        .attestation_insert_local(LocalAttestationInput {
                            attestation_id: None,
                            attesting_key_id: from.clone(),
                            attested_key_id: Some(to),
                            attestation_type: attestation_type::DELEGATES_TO.to_owned(),
                            weight: Some(1.0),
                            expires_at: None,
                            attestation_envelope:
                                ciris_persist::federation::envelope::EnvelopeCore::from_value(
                                    serde_json::json!({
                                        "dimension": ciris_persist::federation::self_at_login::DIMENSION_DELEGATES_TO,
                                        "scope": ["act_on_behalf"],
                                    }),
                                )
                                .expect("envelope"),
                            subject_key_ids: Vec::new(),
                            cohort_scope: cohort_scope::SELF.to_owned(),
                            scrub_signature_classical: None,
                            scrub_signature_pqc: None,
                        })
                        .await
                        .unwrap_or_else(|e| panic!("{label}: local row: {e}"));
                    let local = b_dir
                        .get_attestation(&id)
                        .await
                        .expect("read")
                        .expect("held");
                    let ci = ts::describe_own(
                        &local,
                        ciris_persist::federation::CrossingBasis::ProducerAuthority,
                    );
                    b_dir
                        .enter_mesh(&id, &ci, &ts::actor_reseal(&local))
                        .await
                        .unwrap_or_else(|e| panic!("{label}: promotion: {e}"));
                }
                // A holder claim (the commons store-and-claim).
                5 => {
                    use ciris_persist::federation::blobs::{BlobBody, BlobStorage as _};
                    use sha2::Digest as _;
                    let alias = w.fresh(seed, "holder");
                    let signer = ts::local_signer(&alias);
                    let key = signer.derived_key_id();
                    ts::register_hybrid_key_as(&*b_dir, &alias, &alias, identity_type::NODE).await;
                    ts::register_hybrid_key_as(&*b_dir, &key, &alias, identity_type::NODE).await;
                    let body = alias.clone().into_bytes();
                    let sha: [u8; 32] = sha2::Sha256::digest(&body).into();
                    b_dir
                        .put_blob_signing(
                            &sha,
                            BlobBody::Inline(body),
                            None,
                            &key,
                            &signer,
                            chrono::Utc::now(),
                            uuid::Uuid::new_v4(),
                        )
                        .await
                        .unwrap_or_else(|e| panic!("{label}: holder claim: {e:?}"));
                }
                // A PQC completion.
                6 => {
                    if !w.pqc_pending.is_empty() {
                        let (id, pqc) = w.pqc_pending.swap_remove(pick % w.pqc_pending.len());
                        b_dir
                            .attach_attestation_pqc_signature(&id, &pqc)
                            .await
                            .unwrap_or_else(|e| panic!("{label}: pqc completion: {e}"));
                    }
                }
                // A re-seal of a held, PQC-complete binding.
                7 => {
                    let complete: Vec<&(String, String)> = w
                        .bindings
                        .iter()
                        .filter(|(id, _)| !w.pqc_pending.iter().any(|(p, _)| p == id))
                        .collect();
                    if let Some((id, attester)) = complete.get(pick % complete.len().max(1)) {
                        if let Some(stored) = b_dir.get_attestation(id).await.expect("read") {
                            let mut r = stored.clone();
                            r.attestation_envelope["restamped"] = serde_json::json!(step);
                            ts::seal_row_in_place(attester, &mut r);
                            ciris_persist::federation::canonical_at_rest::canonicalize_in_place(
                                &mut r.attestation_envelope,
                            )
                            .expect("canonical");
                            let (och, sc, sp) =
                                ts::sign_envelope(attester, &r.attestation_envelope);
                            r.original_content_hash = och;
                            r.scrub_signature_classical = sc;
                            r.scrub_signature_pqc = sp;
                            b_dir
                                .reseal_attestation_v31(&r)
                                .await
                                .unwrap_or_else(|e| panic!("{label}: re-seal: {e}"));
                        }
                    }
                }
                // A group-plane founding.
                8 => {
                    use ciris_persist::federation::types::{Family, FamilyMember};
                    let members: Vec<String> = (0..3).map(|_| w.fresh(seed, "fam")).collect();
                    for m in &members {
                        ts::register_hybrid_key_as(&*b_dir, m, m, identity_type::USER).await;
                    }
                    let at = chrono::Utc::now();
                    let family = Family {
                        family_key_id: w.fresh(seed, "family"),
                        family_name: "household".to_owned(),
                        members: members
                            .iter()
                            .map(|m| FamilyMember {
                                key_id: m.clone(),
                                joined_at: at,
                                role: Some("member".to_owned()),
                            })
                            .collect(),
                        founded_at: at,
                        consensus_protocol: "quorum:2/3".to_owned(),
                        consensus_protocol_entrenched: false,
                        prev_head_digest: String::new(),
                        charter_digest: String::new(),
                        dissolved_at: None,
                        persist_row_hash: String::new(),
                    };
                    b_dir
                        .put_family(ts::sign_family(&members[0], family))
                        .await
                        .unwrap_or_else(|e| panic!("{label}: family: {e}"));
                }
                // A consent role.
                9 => {
                    if let Some(k) = w.keys.get(pick % w.keys.len().max(1)) {
                        b_dir
                            .set_consent_role(k, Some("peer"))
                            .await
                            .unwrap_or_else(|e| panic!("{label}: consent role: {e}"));
                    }
                }
                // The projection purge, or a purge execution.
                10 | 11 => {
                    if !w.bindings.is_empty() {
                        let (id, _) = w.bindings.swap_remove(pick % w.bindings.len());
                        w.pqc_pending.retain(|(p, _)| *p != id);
                        let before = index_drain(&*b_dir, "Attestation").await;
                        if op == 10 {
                            b_dir
                                .purge_attestation_projections(&id)
                                .await
                                .unwrap_or_else(|e| panic!("{label}: projection purge: {e}"));
                        } else {
                            purge_execution(&b_dir, &id, &w.fresh(seed, "notice")).await;
                        }
                        let after = index_drain(&*b_dir, "Attestation").await;
                        w.removed.extend(before.difference(&after).copied());
                    }
                }
                // The audit.
                _ => {
                    on.holdings_audit_due_now();
                    let _ = on.holdings_want(EnvelopeKind::Attestation, &[]).await;
                    let _ = on
                        .holdings_want(EnvelopeKind::TransportDestination, &[])
                        .await;
                    w.removed.clear();
                    assert_index_equal(&on, &*b_dir, &[], &format!("{label} audit")).await;
                }
            }
            assert_tracks(&on, &off, &*b_dir, &w.removed, &label).await;
            assert_key_planes_equal(&on, &off, &label).await;
        }
    }
    eprintln!(
        "the_set_tracks_the_index_through_every_door_971: {SEEDS} seeds x {OPS} ops in {:?}",
        started.elapsed()
    );
}

/// CIRISEdge#971 — the key-plane listing cache rides the same differential:
/// `on` lists with the cache, `off` (the oracle bridge) without it, over the
/// same store after the same op, and the four listings are equal as sets.
async fn assert_key_planes_equal(
    on: &FederationDirectoryReplicationBridge,
    off: &FederationDirectoryReplicationBridge,
    step: &str,
) {
    for kind in [
        EnvelopeKind::Key,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
    ] {
        let set = |refs: Vec<EnvelopeRef>| {
            refs.into_iter()
                .map(|r| (r.envelope_hash, r.seq))
                .collect::<std::collections::BTreeSet<_>>()
        };
        let got_on = set(on.list_envelope_refs(kind).await);
        let got_off = set(off.list_envelope_refs(kind).await);
        assert_eq!(got_on, got_off, "{step} {kind:?}: the listing cache");
    }
}

/// A purge execution tombstoning `id` (persist I1547's shape).
async fn purge_execution(dir: &SqliteBackend, id: &str, notice: &str) {
    use ciris_persist::federation::steward_purge::{PurgeExecution, PurgePlane, PurgeTombstone};
    let now = chrono::Utc::now();
    let notice_id = hex::encode(<sha2::Sha256 as sha2::Digest>::digest(notice.as_bytes()));
    dir.purge_put_execution(
        &PurgeExecution {
            notice_id: notice_id.clone(),
            selection_digest: "ab".repeat(32),
            claimant_key_id: "moderator-1".to_owned(),
            legal_basis: "ncmec_csam".to_owned(),
            record_count: 1,
            notice_jcs: "{}".to_owned(),
            cosignatures_json: "[]".to_owned(),
            executed_by: "dif971".to_owned(),
            origin: ciris_persist::federation::steward_purge::origin::LOCAL.to_owned(),
            executed_at: now,
            admitted_at: now,
            finalized_at: None,
        },
        &[PurgeTombstone {
            notice_id,
            ordinal: 0,
            plane: PurgePlane::Attestation,
            record_ref: id.to_owned(),
            derived_from: None,
        }],
    )
    .await
    .expect("purge execution");
}
