//! CC 5.3.4 (rc9 0d9e7f0) — the OFFLINE emit of a node's signed
//! `transport_destination` row WITH its transit KEX pair, for the bundle
//! re-mint (`edge_node emit-transport-destination`).
//!
//! - the offline row equals the row the running node self-emits, except for
//!   `asserted_at` and `last_seen_at` (and is byte-equal when `asserted_at`
//!   is pinned to the live row's);
//! - (the offline row resolving a Rooted pair once a v4 genesis bundle pins
//!   it lives in `sealed_cut_bundle_e1`, which arms the test anchor in its
//!   own process);
//! - a node with no transit pair gets no row: a named error and a non-zero
//!   exit.
//!
//! The command's half needs the `edge_node` binary, which builds only with
//! `mesh-harness` + `test-anchor`; without them the library half (the very
//! function the command calls) still runs.
//!
//! `cargo test --features "transport-reticulum mesh-harness test-anchor" --test offline_route_e1`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::transport::reticulum::{
    offline_route_material, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::self_route::{sign_route_offline, OfflineEmitError};
use ciris_edge::verify::RootingDirectory;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::self_at_login::SignedTransportDestination;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;

const ED_SEED: [u8; 32] = [0x31; 32];
const PQC_SEED: [u8; 32] = [0x32; 32];

/// The node's federation identity exactly as `edge_node` derives it from its
/// `<state-dir>/fed` seeds (`FedKey::identity_signer`): Ed25519 from the seed,
/// ML-DSA-65 from the PQC seed, the key id derived from the label and pubkey.
async fn node_signer(label: &str) -> (LocalSigner, Vec<u8>, String) {
    let ed = Ed25519SoftwareSigner::from_bytes(&ED_SEED, label).expect("ed25519");
    let pqc =
        MlDsa65SoftwareSigner::from_seed_bytes(&PQC_SEED, format!("{label}-pqc")).expect("ml-dsa");
    let ed_pub = HardwareSigner::public_key(&ed).await.expect("ed pub");
    let pqc_pub = PqcSigner::public_key(&pqc).await.expect("pqc pub");
    let key_id = ciris_verify_core::fedcode::derive_key_id(label, &ed_pub);
    let signer = LocalSigner::new(
        key_id.clone(),
        Arc::new(ed) as Arc<dyn HardwareSigner>,
        Some(Arc::new(pqc) as Arc<dyn PqcSigner>),
    );
    let pqc_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, pqc_pub);
    (signer, ed_pub, pqc_b64 + "|" + &key_id)
}

/// The node's self-signed registration (as every fixture mints one).
async fn record(
    signer: &LocalSigner,
    ed_pub: &[u8],
    pqc_b64: &str,
) -> ciris_persist::federation::KeyRecord {
    let ed_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, ed_pub);
    let mut envelope = serde_json::json!({});
    ciris_persist::federation::admission::bind_subject_into_envelope(
        &mut envelope,
        &signer.key_id,
        "node",
        &ed_b64,
        Some(pqc_b64),
        None,
    )
    .expect("bind subject");
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (c, q) = sign_bound_hybrid(signer, &canonical, "self registration")
        .await
        .expect("hybrid self-scrub");
    let now = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
        chrono::Utc::now(),
    );
    ciris_persist::federation::KeyRecord {
        key_id: signer.key_id.clone(),
        pubkey_ed25519_base64: ed_b64,
        pubkey_ml_dsa_65_base64: Some(pqc_b64.to_owned()),
        algorithm: "hybrid".to_string(),
        identity_type: "node".to_string(),
        identity_ref: signer.key_id.clone(),
        valid_from: now,
        valid_until: None,
        registration_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: c,
        scrub_signature_pqc: q,
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: Some(now),
        persist_row_hash: String::new(),
        capability_roles: Vec::new(),
        attestation_evidence: Some(
            ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
        ),
        consent_role: None,
        additional_scrubs: Vec::new(),
    }
}

/// A running node under `state_dir` (custody laid out as `edge_node` lays it
/// out), its directory, and the row it self-emitted at construction.
struct Running {
    signer: LocalSigner,
    dir: Arc<SqliteBackend>,
    row: SignedTransportDestination,
    _transport: Arc<ReticulumTransport>,
}

async fn running_node(label: &str, state_dir: &Path) -> Running {
    let (signer, ed_pub, pqc_and_id) = node_signer(label).await;
    let pqc_b64 = pqc_and_id.split('|').next().expect("pqc").to_owned();
    std::fs::create_dir_all(state_dir.join("fed")).expect("fed dir");
    std::fs::write(state_dir.join("fed/ed25519.seed"), ED_SEED).expect("ed seed");
    std::fs::write(state_dir.join("fed/mldsa65.seed"), PQC_SEED).expect("pqc seed");
    let dir = directory_with(vec![record(&signer, &ed_pub, &pqc_b64).await]).await;
    // `LocalSigner` is not `Clone`; the derivation is deterministic, so the
    // transport gets its own copy of the same keys.
    let signer_arc = Arc::new(node_signer(label).await.0);
    let (transport, _) = common::build_reticulum_with_retry(|| {
        let signer = Arc::clone(&signer_arc);
        let dir = Arc::clone(&dir);
        let id_path = state_dir.join("transport.id");
        async move {
            let mut c = ReticulumTransportConfig::new(id_path, &signer.key_id);
            let port = std::net::TcpListener::bind("127.0.0.1:0")
                .expect("bind")
                .local_addr()
                .expect("addr")
                .port();
            c.listen_addr = format!("127.0.0.1:{port}").parse().expect("addr");
            (
                c,
                ReticulumAuth {
                    signer: Some(signer),
                    rooting: Some(Arc::clone(&dir) as Arc<dyn RootingDirectory>),
                    resolver: None,
                    hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
                    ..ReticulumAuth::default()
                },
            )
        }
    })
    .await;
    let mut rows = Vec::new();
    for _ in 0..40 {
        rows = dir
            .list_signed_transport_destinations_for(&signer.key_id)
            .await
            .expect("list");
        if !rows.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    let row = rows
        .into_iter()
        .next()
        .expect("the running node self-emitted its route");
    Running {
        signer,
        dir,
        row,
        _transport: transport,
    }
}

/// The row with the two fields the CC lets differ blanked, envelope and typed
/// projection alike.
fn without_clock_fields(row: &SignedTransportDestination) -> serde_json::Value {
    let mut env = row.signed_envelope.clone();
    let mut td = serde_json::to_value(&row.transport_destination).expect("td json");
    for v in [&mut env, &mut td] {
        if let Some(o) = v.as_object_mut() {
            o.remove("asserted_at");
            o.remove("last_seen_at");
        }
    }
    serde_json::json!({
        "attesting_key_id": row.attesting_key_id,
        "envelope": env,
        "transport_destination": td,
    })
}

/// Run `edge_node emit-transport-destination`; `(exit code, stderr)`.
#[cfg(all(feature = "mesh-harness", feature = "test-anchor"))]
fn run_emit(state_dir: &Path, label: &str, out: &Path, asserted_at: Option<&str>) -> (i32, String) {
    let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_edge_node"));
    cmd.arg("emit-transport-destination")
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--node-name")
        .arg(label)
        .arg("--out")
        .arg(out);
    if let Some(t) = asserted_at {
        cmd.arg("--asserted-at").arg(t);
    }
    let o = cmd.output().expect("run edge_node");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// **CC 5.3.4** — the offline emit and the live self-emit are one producer:
/// the same custody and signer give the same #1106 row, hybrid-signed by the
/// node's own key, differing ONLY in `asserted_at` / `last_seen_at`; pinned to
/// the live row's `asserted_at`, the signed envelope is byte-equal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_offline_emitted_row_equals_the_runtime_self_emitted_row_e1() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let label = "offline-emit-eq";
    let live = running_node(label, tmp.path()).await;
    let material = offline_route_material(&tmp.path().join("transport.id")).expect("custody");
    assert!(
        material.transit.is_some(),
        "the running node holds a transit pair"
    );

    // Unpinned: equal except the two clock fields.
    let offline = sign_route_offline(
        &live.signer,
        material.named_dest_hash,
        &material.transport_pubkey,
        material.transit.as_ref(),
        live.row.transport_destination.epoch,
        chrono::Utc::now() + chrono::Duration::hours(1),
    )
    .await
    .expect("offline row");
    assert_eq!(
        without_clock_fields(&offline),
        without_clock_fields(&live.row)
    );
    assert!(
        offline.signature.mldsa65_signature_base64.is_some(),
        "hybrid-signed"
    );

    // Pinned to the live asserted_at: the signed envelope is byte-equal, and
    // so is the (deterministic) Ed25519 signature over it.
    let pinned = sign_route_offline(
        &live.signer,
        material.named_dest_hash,
        &material.transport_pubkey,
        material.transit.as_ref(),
        live.row.transport_destination.epoch,
        live.row.transport_destination.asserted_at,
    )
    .await
    .expect("pinned row");
    assert_eq!(
        ciris_persist::prelude::ceg_produce_canonicalize(&pinned.signed_envelope).expect("jcs"),
        ciris_persist::prelude::ceg_produce_canonicalize(&live.row.signed_envelope).expect("jcs"),
    );
    assert_eq!(
        pinned.signature.ed25519_signature_base64,
        live.row.signature.ed25519_signature_base64
    );

    // The command's own output, through the binary.
    #[cfg(all(feature = "mesh-harness", feature = "test-anchor"))]
    {
        let out = tmp.path().join("row.json");
        let at = live.row.transport_destination.asserted_at.to_rfc3339();
        let (code, err) = run_emit(tmp.path(), label, &out, Some(&at));
        assert_eq!(code, 0, "emit failed: {err}");
        let cli: SignedTransportDestination =
            serde_json::from_slice(&std::fs::read(&out).expect("row file")).expect("row json");
        assert_eq!(without_clock_fields(&cli), without_clock_fields(&live.row));
        assert_eq!(
            ciris_persist::prelude::ceg_produce_canonicalize(&cli.signed_envelope).expect("jcs"),
            ciris_persist::prelude::ceg_produce_canonicalize(&live.row.signed_envelope)
                .expect("jcs"),
        );
    }
}

/// **CC 5.3.4** — a node with no transit pair gets NO row: the producer refuses
/// by name (`OfflineEmitError::NoTransitPair`), and the command exits non-zero
/// with `offline_emit_no_transit_pair` and writes nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_offline_emit_refuses_a_row_without_a_transit_pair_e1() {
    let label = "offline-emit-nopair";
    let (signer, _, _) = node_signer(label).await;
    let refused = sign_route_offline(&signer, [7; 16], &[9; 64], None, 0, chrono::Utc::now()).await;
    assert!(
        matches!(refused, Err(OfflineEmitError::NoTransitPair)),
        "{refused:?}"
    );
    assert_eq!(
        OfflineEmitError::NoTransitPair.label(),
        "offline_emit_no_transit_pair"
    );

    #[cfg(all(feature = "mesh-harness", feature = "test-anchor"))]
    {
        // A node whose custody holds federation seeds and a transport
        // identity, and no transit seed.
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(tmp.path().join("fed")).expect("fed dir");
        std::fs::write(tmp.path().join("fed/ed25519.seed"), ED_SEED).expect("ed seed");
        std::fs::write(tmp.path().join("fed/mldsa65.seed"), PQC_SEED).expect("pqc seed");
        let identity = leviculum_std::generate_identity();
        std::fs::write(
            tmp.path().join("transport.id"),
            identity.private_key_bytes().expect("identity bytes"),
        )
        .expect("identity file");
        let out = tmp.path().join("row.json");
        let (code, err) = run_emit(tmp.path(), label, &out, None);
        assert_ne!(code, 0, "a pair-less node must not emit");
        assert!(err.contains("offline_emit_no_transit_pair"), "{err}");
        assert!(!out.exists(), "nothing written");
        assert!(
            !tmp.path().join("transport.id.transit-kex").exists(),
            "the emit never mints a transit seed"
        );
    }
}
