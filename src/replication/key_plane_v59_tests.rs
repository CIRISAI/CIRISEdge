//! **persist v59.0.0 (sealed-transport floor, operator ruling 2026-10-19) —
//! the key plane travels only as its attestation rows.**
//!
//! The witnesses beside the bridge's own
//! `a_framed_key_plane_object_is_refused_terminal_under_the_retired_token_v59`
//! (the inbound half), over real sqlite directories and the real bridge:
//!
//! - **the outbound serve** — every retired kind's session plane offers and
//!   serves only its own family's `key:record:v1` / `identity:occurrence:v1` /
//!   `key:revocation:v1` ROW, never a framed object; the retired occurrence
//!   revocation plane offers nothing; a row of another family is never served
//!   on a key-plane plane, so the #402 bootstrap planes cannot hand out general
//!   attestations by hash;
//! - **two-node convergence** — a fresh node pulls a node's key, its
//!   occurrence and its route over the Key / IdentityOccurrence /
//!   TransportDestination planes through the replication `Session`, and ends
//!   holding all three: the rows carry what the framed objects carried, so
//!   routes still form;
//! - **a wrong-family row** on a key-plane plane is refused terminal and never
//!   applied;
//! - **the revocation planes keep their global reach** — a key's
//!   `key:revocation:v1` row reaches a stranger that holds the key and
//!   consents to nothing, and an occurrence's `withdraws` reaches a node that
//!   holds the occurrence, each over its own session plane.
//!
//! `cargo test --lib key_plane_v59`

use std::sync::Arc;

use ciris_persist::federation::key_plane::KeyPlaneFamily;
use ciris_persist::federation::types::{Attestation, Revocation, SignedRevocation};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;

use super::park_fresh_858_tests::{hold, occurrence, substrate, Ident};
use crate::replication::summary::ApplyOutcome;
use crate::replication::{
    BridgeConfig, DirectoryStateAdapter, EnvelopeKind, FederationDirectoryReplicationBridge,
    MutableDirectoryStateAdapter, ReplicationDirectory, ReplicationMessage, ReplicationOutcome,
    RetryDisposition, Session, SessionRole,
};

fn bridge(
    dir: &Arc<SqliteBackend>,
    me: &str,
    publish: Vec<String>,
    metrics: Option<crate::observability::EdgeMetrics>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let cohort = publish.clone();
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(dir) as Arc<dyn FederationDirectory>,
            Arc::new(move || cohort.clone()),
            BridgeConfig::default(),
        )
        .with_local_key_id(Some(me.to_owned()))
        .with_self_provider(Some(Arc::new(move || publish.clone())))
        .with_metrics(metrics),
    )
}

/// `key`'s self-revocation, hybrid-signed by `key` over persist's bound
/// envelope (the path a self-revocation takes; no `slash` conferral needed).
async fn self_revocation(dir: &SqliteBackend, key: &Ident) -> Revocation {
    use sha2::Digest as _;
    let now = chrono::DateTime::<chrono::Utc>::from_timestamp_micros(
        chrono::Utc::now().timestamp_micros(),
    )
    .expect("micros");
    let held = dir
        .lookup_public_key(key.key_id())
        .await
        .expect("lookup")
        .expect("held");
    let mut revocation = Revocation {
        revocation_id: uuid::Uuid::new_v4().to_string(),
        revoked_key_id: Some(key.key_id().to_owned()),
        revoked_key_sha256_ed25519_raw:
            ciris_persist::federation::key_digest::Sha256Ed25519Raw::from_pubkey_base64(
                &held.pubkey_ed25519_base64,
            )
            .expect("digest")
            .to_hex(),
        revoking_key_id: key.key_id().to_owned(),
        reason: None,
        revoked_at: now,
        effective_at: now,
        revocation_envelope: serde_json::json!({}),
        original_content_hash: String::new(),
        scrub_signature_classical: String::new(),
        scrub_signature_pqc: None,
        scrub_key_id: key.key_id().to_owned(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        observed_region: "us".to_owned(),
        revoked_after: None,
    };
    ciris_persist::federation::admission::bind_revocation_into_envelope(&mut revocation)
        .expect("bind");
    let canonical =
        ciris_verify_core::jcs::canonicalize(&revocation.revocation_envelope).expect("jcs");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&key.signer(), &canonical, "revocation")
        .await
        .expect("sign");
    revocation.original_content_hash = hex::encode(sha2::Sha256::digest(&canonical));
    revocation.scrub_signature_classical = ed;
    revocation.scrub_signature_pqc = pqc;
    revocation
}

/// `node`'s hybrid-signed reticulum route.
async fn route(
    node: &Ident,
) -> ciris_persist::federation::self_at_login::SignedTransportDestination {
    use base64::Engine as _;
    use ciris_persist::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let row = TransportDestination {
        occurrence_key_id: node.key_id().to_owned(),
        transport_kind: "reticulum".to_owned(),
        destination: "a0".repeat(16),
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_micros(
            chrono::Utc::now().timestamp_micros(),
        )
        .expect("micros"),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(b64.encode([0xbb; 32])),
        transport_x25519_pubkey_base64: Some(b64.encode([0xcc; 32])),
        binding_provenance: BindingProvenance::Rooted,
        epoch: 1,
        retired_at: None,
    };
    let envelope = serde_json::to_value(&row).expect("route");
    let canonical = ciris_verify_core::jcs::canonicalize(&envelope).expect("jcs");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&node.signer(), &canonical, "route")
        .await
        .expect("sign");
    SignedTransportDestination {
        attesting_key_id: node.key_id().to_owned(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    }
}

/// Node A: a person P, its node N (P's occurrence of N, attested by P), a key
/// K that revoked itself, and N's route — each written through the LOCAL
/// authoring door, which mints the key-plane rows.
struct NodeA {
    p: Ident,
    n: Ident,
    k: Ident,
    dir: Arc<SqliteBackend>,
}

impl NodeA {
    async fn build(tag: &str, seed: u8) -> Self {
        let p = Ident::mint(&format!("person-p-{tag}"), "user", seed).await;
        let n = Ident::mint(&format!("node-n-{tag}"), "node", seed + 1).await;
        let k = Ident::mint(&format!("node-k-{tag}"), "node", seed + 2).await;
        let dir = substrate().await;
        for id in [&p, &n, &k] {
            hold(&dir, id).await;
        }
        dir.put_identity_occurrence(occurrence(p.key_id(), n.key_id(), &p).await)
            .await
            .expect("A authors P's occurrence of N");
        let revocation = self_revocation(&dir, &k).await;
        dir.put_revocation(SignedRevocation { revocation })
            .await
            .expect("A authors K's self-revocation");
        dir.put_signed_transport_destination(&route(&n).await)
            .await
            .expect("A holds N's route");
        Self { p, n, k, dir }
    }

    fn bridge(&self) -> Arc<FederationDirectoryReplicationBridge> {
        bridge(
            &self.dir,
            self.n.key_id(),
            vec![
                self.p.key_id().to_owned(),
                self.n.key_id().to_owned(),
                self.k.key_id().to_owned(),
            ],
            None,
        )
    }
}

impl NodeA {
    /// P withdraws its occurrence of N: the `withdraws` of N's
    /// `identity:occurrence:v1` row (persist v59.0.0's occurrence revocation),
    /// authored at A. Returns the row.
    async fn withdraw_occurrence(&self) -> Attestation {
        let target =
            crate::replication::key_plane_rows::occurrence_rows_about(&*self.dir, self.p.key_id())
                .await
                .expect("rows")
                .into_iter()
                .find(|r| {
                    crate::replication::key_plane_rows::occurrence_key_of(r).as_deref()
                        == Some(self.n.key_id())
                })
                .expect("P's occurrence row of N");
        let withdraws = crate::replication::attestation_bind::withdraws_attestation(
            &target,
            "device_retired",
            chrono::Utc::now(),
            &self.p.signer(),
        )
        .await
        .expect("build the withdraws");
        self.dir
            .apply_replicated_attestation(ciris_persist::federation::SignedAttestation {
                attestation: withdraws.clone(),
            })
            .await
            .expect("A admits P's withdraws");
        withdraws
    }
}

fn messages(outcome: ReplicationOutcome) -> Vec<ReplicationMessage> {
    match outcome {
        ReplicationOutcome::Send(msgs)
        | ReplicationOutcome::SendAndComplete { msgs, .. }
        | ReplicationOutcome::SendThenApplied { msgs, .. } => msgs,
        _ => Vec::new(),
    }
}

/// One `kind` round: B initiates against A, and the two sessions exchange
/// until neither has anything to say.
async fn round(
    kind: EnvelopeKind,
    a: &Arc<FederationDirectoryReplicationBridge>,
    a_id: &str,
    b: &Arc<FederationDirectoryReplicationBridge>,
    b_id: &str,
) {
    let dir_a: Arc<dyn ReplicationDirectory> = Arc::clone(a) as _;
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(b) as _;
    let prov_a = DirectoryStateAdapter::new(Arc::clone(&dir_a)).with_peer(b_id);
    let prov_b = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a_id);
    let app_a = MutableDirectoryStateAdapter::new(dir_a);
    let app_b = MutableDirectoryStateAdapter::new(dir_b);
    let mut sa = Session::new(SessionRole::Responder, kind);
    let mut sb = Session::new(SessionRole::Initiator, kind);
    let mut to_a = messages(sb.start_round(&prov_b).await);
    for _ in 0..8 {
        let mut to_b = Vec::new();
        for m in to_a.drain(..) {
            to_b.extend(messages(
                sa.on_message(m, &prov_a, &app_a, Some(b_id)).await,
            ));
        }
        if to_b.is_empty() {
            break;
        }
        for m in to_b {
            to_a.extend(messages(
                sb.on_message(m, &prov_b, &app_b, Some(a_id)).await,
            ));
        }
        if to_a.is_empty() {
            break;
        }
    }
}

/// **The outbound serve offers no framed key-plane object: each key-plane
/// plane serves only its own family's row, the key travels as its
/// `key:record:v1` row, and the retired plane offers nothing.**
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbound_serve_offers_no_framed_key_plane_object_v59() {
    const PEER: &str = "peer-b-v59";
    let a = NodeA::build("v59-serve", 0x31).await;
    let withdraws = a.withdraw_occurrence().await;
    let bridge = a.bridge();

    let mut served_on: Vec<(EnvelopeKind, [u8; 32])> = Vec::new();
    for kind in EnvelopeKind::ALL
        .into_iter()
        .filter(|k| k.is_framed_retired())
    {
        let refs = bridge.list_envelope_refs_for_peer(kind, Some(PEER)).await;
        let Some(family) = kind.key_plane_family() else {
            // The occurrence-revocation plane: only the occurrence's withdraws.
            assert_eq!(refs.len(), 1, "{kind:?}: the one withdraws: {refs:?}");
            let bytes = bridge
                .fetch_envelope_bytes_for_peer(kind, &refs[0].envelope_hash, Some(PEER))
                .await
                .expect("served");
            let row: Attestation = serde_json::from_slice(&bytes).expect("a row");
            assert_eq!(row.attestation_id, withdraws.attestation_id);
            continue;
        };
        assert!(!refs.is_empty(), "{kind:?}: A has a row to offer");
        for r in &refs {
            let bytes = bridge
                .fetch_envelope_bytes_for_peer(kind, &r.envelope_hash, Some(PEER))
                .await
                .unwrap_or_else(|| panic!("{kind:?}: an offered ref is served"));
            let row: Attestation = serde_json::from_slice(&bytes)
                .unwrap_or_else(|e| panic!("{kind:?}: the served body is a row: {e}"));
            assert_eq!(
                KeyPlaneFamily::of_row(&row),
                Some(family),
                "{kind:?}: only the plane's own family is served"
            );
            for framed in ["record", "revocation", "identity_occurrence_revocation"] {
                assert!(
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .expect("json")
                        .get(framed)
                        .is_none(),
                    "{kind:?}: no framed `{framed}` object on the wire"
                );
            }
            served_on.push((kind, r.envelope_hash));
        }
    }

    // The key travels as ITS row: the Key plane's refs include the content hash
    // of the `key:record:v1` row persist minted for N.
    let n_row = crate::replication::key_plane_rows::key_record_rows(&*a.dir, a.n.key_id())
        .await
        .expect("read N's rows")
        .into_iter()
        .next()
        .expect("N's key:record:v1 row");
    let n_hash: [u8; 32] =
        <sha2::Sha256 as sha2::Digest>::digest(serde_json::to_vec(&n_row).expect("encode")).into();
    assert!(
        served_on.contains(&(EnvelopeKind::Key, n_hash)),
        "N's key is offered as its key:record:v1 row"
    );

    // A row of another family is never served on a key-plane plane: the
    // occurrence row's hash asked for on the Key plane (a #402 bootstrap plane)
    // resolves to nothing.
    let (_, occ_hash) = served_on
        .iter()
        .find(|(k, _)| *k == EnvelopeKind::IdentityOccurrence)
        .expect("an occurrence row was served");
    assert!(
        bridge
            .fetch_envelope_bytes_for_peer(EnvelopeKind::Key, occ_hash, Some(PEER))
            .await
            .is_none(),
        "the Key plane never serves another family's row"
    );
}

/// **Two-node replication of a key record and an occurrence over the row
/// plane converges, so routes still form.** B, fresh, pulls A's Key,
/// IdentityOccurrence and TransportDestination planes through the replication
/// `Session` and ends holding N's key, P's occurrence of N and N's route,
/// with nothing refused retired.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_nodes_converge_a_key_and_an_occurrence_over_the_row_plane_v59() {
    let a = NodeA::build("v59-pair", 0x41).await;
    let b_ident = Ident::mint("node-b-v59-pair", "node", 0x51).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let metrics = crate::observability::EdgeMetrics::new();
    let b = bridge(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        Some(metrics.clone()),
    );
    let a_bridge = a.bridge();

    assert!(
        b_dir
            .lookup_public_key(a.n.key_id())
            .await
            .expect("lookup")
            .is_none(),
        "precondition: B has never met N"
    );
    for _ in 0..2 {
        for kind in [
            EnvelopeKind::Key,
            EnvelopeKind::IdentityOccurrence,
            EnvelopeKind::TransportDestination,
        ] {
            round(kind, &a_bridge, a.n.key_id(), &b, b_ident.key_id()).await;
        }
    }

    for id in [&a.p, &a.n] {
        assert!(
            b_dir
                .lookup_public_key(id.key_id())
                .await
                .expect("lookup")
                .is_some(),
            "B holds {}'s key, carried as its key:record:v1 row",
            id.key_id()
        );
    }
    assert!(
        b_dir
            .list_identity_occurrences_active(a.p.key_id())
            .await
            .expect("occurrences")
            .iter()
            .any(|o| o.occurrence_key_id == a.n.key_id()),
        "B holds P's occurrence of N, carried as its identity:occurrence:v1 row"
    );
    assert!(
        !b_dir
            .list_signed_transport_destinations_for(a.n.key_id())
            .await
            .expect("routes")
            .is_empty(),
        "B holds N's route: the key and occurrence it needs landed first"
    );
    assert!(
        metrics.snapshot().envelope_kind_retired_refusals.is_empty(),
        "nothing framed crossed"
    );
}

/// **A row of another family on a key-plane plane is refused terminal and
/// never applied** — the bootstrap planes do not become a path for general
/// attestations, nor for another key-plane family.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wrong_family_row_on_a_key_plane_plane_is_refused_terminal_v59() {
    let a = NodeA::build("v59-wrong", 0x61).await;
    let occ_row = crate::replication::key_plane_rows::occurrence_rows_about(&*a.dir, a.p.key_id())
        .await
        .expect("rows")
        .into_iter()
        .next()
        .expect("P's occurrence row");
    let bytes = serde_json::to_vec(&occ_row).expect("encode");

    let f_ident = Ident::mint("node-f-v59-wrong", "node", 0x71).await;
    let f_dir = substrate().await;
    for id in [&f_ident, &a.p, &a.n] {
        hold(&f_dir, id).await;
    }
    let f = bridge(
        &f_dir,
        f_ident.key_id(),
        vec![f_ident.key_id().to_owned()],
        None,
    );
    for kind in [EnvelopeKind::Key, EnvelopeKind::Revocation] {
        let outcome = f.apply_envelope_bytes(kind, &bytes, Some("peer-x")).await;
        let ApplyOutcome::Refused { retry, reason, .. } = &outcome else {
            panic!("{kind:?}: a wrong-family row is refused, got {outcome:?}");
        };
        assert_eq!(*retry, RetryDisposition::Terminal, "{kind:?}: {reason}");
        assert!(reason.contains("identity:occurrence:v1"), "{reason}");
    }
    assert!(
        f_dir
            .get_attestation(&occ_row.attestation_id)
            .await
            .expect("read")
            .is_none(),
        "never applied"
    );
    // On its own plane the same row admits.
    let own = f
        .apply_envelope_bytes(EnvelopeKind::IdentityOccurrence, &bytes, Some("peer-x"))
        .await;
    assert!(own.is_admitted(), "{own:?}");
}

/// **A key's revocation reaches a stranger that holds the key.** S holds K's
/// key and nothing else of A's: no consent grant, no cohort, not a subject of
/// the revoker's rows — exactly the node the consent-gated Attestation plane
/// would never reach. One Revocation round over the replication `Session`
/// and S holds K's revocation (the #311 tombstone rule, kept by the
/// Revocation plane carrying the `key:revocation:v1` row).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_revocation_row_reaches_a_stranger_holding_the_key_v59() {
    let a = NodeA::build("v59-revoke", 0x81).await;
    let s_ident = Ident::mint("node-s-v59-revoke", "node", 0x91).await;
    let s_dir = substrate().await;
    hold(&s_dir, &s_ident).await;
    hold(&s_dir, &a.k).await;
    let metrics = crate::observability::EdgeMetrics::new();
    let s = bridge(
        &s_dir,
        s_ident.key_id(),
        vec![s_ident.key_id().to_owned()],
        Some(metrics.clone()),
    );
    assert!(
        s_dir
            .revocations_for(a.k.key_id())
            .await
            .expect("read")
            .is_empty(),
        "precondition: S does not know K is revoked"
    );
    assert!(
        s_dir
            .list_live_consent_grants_by(a.n.key_id())
            .await
            .unwrap_or_default()
            .is_empty(),
        "precondition: S holds no consent grant from A"
    );

    round(
        EnvelopeKind::Revocation,
        &a.bridge(),
        a.n.key_id(),
        &s,
        s_ident.key_id(),
    )
    .await;

    let revocations = s_dir.revocations_for(a.k.key_id()).await.expect("read");
    assert_eq!(
        revocations.len(),
        1,
        "S holds K's revocation, carried as its key:revocation:v1 row"
    );
    let snap = metrics.snapshot();
    assert_eq!(
        snap.replication_applied_total
            .get(&EnvelopeKind::Revocation)
            .copied(),
        Some(1),
        "admitted on the Revocation plane"
    );
    assert!(snap.envelope_kind_retired_refusals.is_empty());
}

/// **An occurrence's revocation reaches a node holding the occurrence**, over
/// the IdentityOccurrenceRevocation plane (the occurrence's own tombstone
/// plane), as the `withdraws` of its `identity:occurrence:v1` row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_occurrence_withdrawal_reaches_a_node_holding_the_occurrence_v59() {
    let a = NodeA::build("v59-occrev", 0xa1).await;
    let b_ident = Ident::mint("node-b-v59-occrev", "node", 0xb1).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let b = bridge(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        None,
    );
    let a_bridge = a.bridge();
    for kind in [EnvelopeKind::Key, EnvelopeKind::IdentityOccurrence] {
        round(kind, &a_bridge, a.n.key_id(), &b, b_ident.key_id()).await;
    }
    let active = |dir: Arc<SqliteBackend>, p: String, n: String| async move {
        dir.list_identity_occurrences_active(&p)
            .await
            .expect("occurrences")
            .iter()
            .any(|o| o.occurrence_key_id == n)
    };
    assert!(
        active(
            Arc::clone(&b_dir),
            a.p.key_id().to_owned(),
            a.n.key_id().to_owned()
        )
        .await,
        "precondition: B holds P's occurrence of N"
    );

    a.withdraw_occurrence().await;
    round(
        EnvelopeKind::IdentityOccurrenceRevocation,
        &a_bridge,
        a.n.key_id(),
        &b,
        b_ident.key_id(),
    )
    .await;
    assert!(
        !active(
            Arc::clone(&b_dir),
            a.p.key_id().to_owned(),
            a.n.key_id().to_owned()
        )
        .await,
        "B no longer holds P's occurrence of N active: the withdraws landed"
    );
}
