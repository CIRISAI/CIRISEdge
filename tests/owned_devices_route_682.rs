//! CIRISEdge#722 / #682 — two devices of ONE owner, at the admission seam.
//!
//! The field (CIRISServer's `selffiles` fixture: one person, two devices, D2
//! dials D1) refused every Resource-carried Deliver at #393 item 2 while both
//! inbound arms are provably the same code path (`reverse_link_resource_binding_722`).
//! So the operand was wrong: D2 did not hold a hybrid-verified
//! `SignedTransportDestination` for D1 naming D1's announced destination. The
//! serve-side rule that decides whether that row is ever HANDED to D2 is
//! CIRISEdge#682 (CC 5.4.6): an owned node's identity rows go to every peer
//! only while the node is announced (owner-binding at `cohort_scope:
//! federation`); an unannounced node's rows go only to `nodes_owned_by(owner)`
//! — as the SERVING node resolves that set from its own directory.
//!
//! This witness starts where a claimed device starts: each device holds the
//! owner's key record and ITS OWN owner-binding (a claim writes the binding at
//! a `self` audience, never at `federation` — CIRISServer `claim_remote`'s
//! scope vocabulary), both dial each other, and nothing else is pre-shared.
//! Two shapes:
//!
//! - **announced** (`cohort_scope: federation`, the fixture's `announced: true`):
//!   each device serves its route to everyone; both routes cross (2 sweeps);
//!   D2 admits a Resource-carried row from D1. The control — GREEN.
//! - **unannounced** (`cohort_scope: self`) — RED on main, a bootstrap
//!   deadlock of the #393 shape that #402 closed for keys: D1 may hand its
//!   route only to `nodes_owned_by(owner)` as D1 resolves it, i.e. only once
//!   `owner → D2` sits in D1's directory. That binding is an Attestation row
//!   D2 could carry, but (a) D2's send-set gate withholds a `self`-audience row
//!   from a peer outside that audience (CIRISPersist#884), and (b) D1 would
//!   admit the Attestation plane only from an ATTRIBUTED peer, which needs
//!   D2's route at D1 — which D2 withholds for the mirror-image reason.
//!   Observed: `identity_row_node_not_announced` ≈ 320 on each side, 0 routes
//!   held, no convergence in 120 s. The test is `#[ignore]`d with that reason
//!   until the class is fixed (the fix is a policy decision — how two devices
//!   of one owner learn each other's ownership before either is announced —
//!   not a transport arm).
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test owned_devices_route_682`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::first_contact::{
    DirectoryOwnerBinding, OwnerBindingCarveOut, OwnerBindingOutcome, OwnerBindingRefusal,
    OWNER_BINDING_ADMITTED, OWNER_BINDING_ANSWERED, OWNER_BINDING_PUSHED,
};
use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::WithholdReason;
use ciris_edge::replication::attestation_bind::{
    bind_attestation_envelope, replication_consent_attestation, AttestationColumns,
    DEFAULT_CONSENT_PREFIXES,
};
use ciris_edge::replication::protocol::{DeliverMessage, ReplicationMessage};
use ciris_edge::replication::{
    self_publish_set, wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::store::sqlite::SqliteBackend;
use common::{build_reticulum_with_retry_metrics, directory_with};
use sha2::Digest as _;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

/// A production-shaped identity (as in `first_contact_ladder_659.rs`).
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
    records:
        tokio::sync::Mutex<std::collections::HashMap<String, ciris_persist::federation::KeyRecord>>,
}

impl Ident {
    async fn new(alias: &str, seed: u8) -> Self {
        let mut ed = Ed25519SoftwareSigner::new(alias);
        ed.import_key(&[seed; 32]).expect("import ed key");
        let pqc =
            MlDsa65SoftwareSigner::from_seed_bytes(&[seed ^ 0x55; 32], format!("{alias}-pqc"))
                .expect("ml-dsa from seed");
        let ed_pub = ed.public_key().await.expect("ed pubkey");
        let pqc_pub_b64 = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            pqc.public_key().await.expect("pqc pubkey"),
        );
        let key_id = ciris_verify_core::fedcode::derive_key_id(ed.current_alias(), &ed_pub);
        Self {
            key_id,
            ed: Arc::new(ed),
            pqc: Arc::new(pqc),
            ed_pub,
            pqc_pub_b64,
            records: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
    fn ed_pub_b64(&self) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.ed_pub)
    }
    fn signer(&self) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> = Arc::clone(&self.ed) as Arc<dyn HardwareSigner>;
        let pqc: Arc<dyn PqcSigner> = Arc::clone(&self.pqc) as Arc<dyn PqcSigner>;
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
    async fn record(&self, identity_type: &str) -> ciris_persist::federation::KeyRecord {
        if let Some(r) = self.records.lock().await.get(identity_type) {
            return r.clone();
        }
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            identity_type,
            &self.ed_pub_b64(),
            Some(&self.pqc_pub_b64),
            None,
        )
        .expect("bind subject");
        let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
        let digest = sha2::Sha256::digest(&canonical);
        let (sig_classical, sig_pqc) =
            sign_bound_hybrid(&self.signer(), &canonical, "self registration")
                .await
                .expect("hybrid self-scrub");
        let now = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
            chrono::Utc::now(),
        );
        let r = ciris_persist::federation::KeyRecord {
            key_id: self.key_id.clone(),
            pubkey_ed25519_base64: self.ed_pub_b64(),
            pubkey_ml_dsa_65_base64: Some(self.pqc_pub_b64.clone()),
            algorithm: "hybrid".to_string(),
            identity_type: identity_type.to_string(),
            identity_ref: self.key_id.clone(),
            valid_from: now,
            valid_until: None,
            registration_envelope: envelope,
            original_content_hash: hex::encode(digest),
            scrub_signature_classical: sig_classical,
            scrub_signature_pqc: sig_pqc,
            scrub_key_id: self.key_id.clone(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: Some(
                ciris_persist::federation::hardware_attestation::test_support::fresh_accord_holder_evidence(),
            ),
            consent_role: None,
            additional_scrubs: Vec::new(),
        };
        self.records
            .lock()
            .await
            .insert(identity_type.to_owned(), r.clone());
        r
    }
}

/// The owner-binding `delegates_to(owner → node)` exactly as
/// `attestation_bind::owner_binding_attestation` mints it, at a chosen
/// `cohort_scope`: `self` is what a claim writes; `federation` is the announce.
async fn owner_binding_at(owner: &Ident, node: &str, cohort_scope: &str) -> Attestation {
    owner_binding_signed_by(owner, owner, node, cohort_scope).await
}

/// CIRISEdge#727 — the same row with the attester FIELD naming `owner` but the
/// signature made by `signer`. With `signer == owner` it is the genuine
/// binding; with a stranger's key it is the forged-signature negative.
async fn owner_binding_signed_by(
    owner: &Ident,
    signer: &Ident,
    node: &str,
    cohort_scope: &str,
) -> Attestation {
    let asserted_at = ciris_edge::replication::attestation_bind::truncate_to_substrate_resolution(
        chrono::Utc::now(),
    );
    let attestation_id = format!("owner-binding-{node}");
    let subjects = vec![node.to_owned()];
    let mut envelope =
        ciris_persist::federation::self_at_login::owner_binding_delegates_to_envelope(
            node,
            &["infra:network_presence".to_string()],
        );
    bind_attestation_envelope(
        &mut envelope,
        asserted_at,
        &AttestationColumns {
            attestation_id: &attestation_id,
            attesting_key_id: &owner.key_id,
            attestation_type: "delegates_to",
            attested_key_id: node,
            subject_key_ids: &subjects,
            cohort_scope,
            weight: None,
        },
    );
    let canonical = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let digest = sha2::Sha256::digest(&canonical);
    let (sig_classical, sig_pqc) = sign_bound_hybrid(&signer.signer(), &canonical, "owner binding")
        .await
        .expect("hybrid sign");
    Attestation {
        attestation_id,
        attesting_key_id: owner.key_id.clone(),
        attested_key_id: node.to_owned(),
        attestation_type: "delegates_to".to_owned(),
        weight: None,
        asserted_at,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash: hex::encode(digest),
        scrub_signature_classical: sig_classical,
        scrub_signature_pqc: sig_pqc,
        scrub_key_id: owner.key_id.clone(),
        scrub_timestamp: asserted_at,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: subjects,
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope.to_owned(),
        // `tier` is where the row LIVES (persist's federation listings read
        // `tier = 'federation'` only — a `local` row is invisible to
        // `owner_of`); `cohort_scope` is the AUDIENCE. A claim's binding is a
        // federation-tier row at a `self` audience; the announce widens the
        // audience, never the tier.
        tier: "federation".to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    }
}

struct Device {
    key: Arc<Ident>,
    dir: Arc<SqliteBackend>,
    metrics: EdgeMetrics,
    transport: Arc<ReticulumTransport>,
    runtime: Arc<ReplicationRuntime>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Device {
    async fn holds_route_for(&self, peer: &Ident) -> bool {
        self.dir
            .list_signed_transport_destinations_for(&peer.key_id)
            .await
            .unwrap_or_default()
            .iter()
            .any(|r| r.signature.mldsa65_signature_base64.is_some())
    }
    async fn holds_attestation(&self, id: &str) -> bool {
        self.dir
            .list_attestations_since(None, 1024)
            .await
            .expect("list")
            .iter()
            .any(|r| r.attestation.attestation_id == id)
    }
    fn withholds(&self) -> (u64, u64) {
        (
            self.metrics
                .withholds(WithholdReason::IdentityRowNodeNotAnnounced),
            self.metrics
                .withholds(WithholdReason::IdentityRowAnnounceUnresolved),
        )
    }
    /// CIRISEdge#727 — one `first_contact_outcomes` label (`owner_binding_*`).
    fn ledger(&self, label: &str) -> u64 {
        ledger(&self.metrics, label)
    }
    /// CIRISEdge#727 — every `owner_binding_*` label this node booked.
    fn owner_binding_ledger(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .metrics
            .snapshot()
            .first_contact_outcomes
            .into_iter()
            .filter(|(k, _)| k.starts_with("owner_binding_"))
            .collect();
        v.sort();
        v
    }
}

fn ledger(metrics: &EdgeMetrics, label: &str) -> u64 {
    metrics
        .snapshot()
        .first_contact_outcomes
        .get(label)
        .copied()
        .unwrap_or(0)
}

/// What D2 starts with (D1 always starts claimed: the three key records and
/// its own binding at `scope`).
#[derive(Clone, Copy)]
enum D2Starts {
    /// Claimed like D1: the three records and its own binding at `scope`.
    Claimed,
    /// CIRISEdge#727 recovery: wiped to its seed (its own record) and the
    /// owner's key record — no sibling record, no binding.
    Wiped,
}

struct Pair {
    d1: Device,
    d2: Device,
    owner: Ident,
    /// D1's TCP listen port — a third node bootstraps to it (test (c)).
    d1_port: u16,
    tmp: tempfile::TempDir,
}

/// One owner, two claimed devices. Each device's directory: the three key
/// records and ITS OWN owner-binding at `scope`. D2 bootstraps to D1; the
/// runtimes then dial each other over RNS links from the announces.
// One linear fixture (as `first_contact_ladder_659.rs`).
async fn pair(tag: &str, scope: &str) -> Pair {
    pair_with(tag, scope, D2Starts::Claimed).await
}

#[allow(clippy::too_many_lines)]
async fn pair_with(tag: &str, scope: &str, d2: D2Starts) -> Pair {
    let tmp = tempfile::tempdir().expect("tempdir");
    let owner = Ident::new(&format!("owner-682-{tag}"), 0x41).await;
    let k1 = Arc::new(Ident::new(&format!("d1-682-{tag}"), 0x11).await);
    let k2 = Arc::new(Ident::new(&format!("d2-682-{tag}"), 0x12).await);
    let records = vec![
        k1.record("node").await,
        k2.record("node").await,
        owner.record("user").await,
    ];
    let dir1 = directory_with(records.clone()).await;
    let dir2 = match d2 {
        D2Starts::Claimed => directory_with(records).await,
        D2Starts::Wiped => {
            directory_with(vec![k2.record("node").await, owner.record("user").await]).await
        }
    };
    // D1 holds ITS OWN binding; under `Wiped` it also still holds D2's (the
    // sibling remembers the wiped device — that is what recovery rides).
    let d1_bindings: Vec<&str> = match d2 {
        D2Starts::Claimed => vec![&k1.key_id],
        D2Starts::Wiped => vec![&k1.key_id, &k2.key_id],
    };
    for node in d1_bindings {
        let row = owner_binding_at(&owner, node, scope).await;
        dir1.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("owner-binding for {node} at {scope} (D1): {e:?}"));
    }
    if matches!(d2, D2Starts::Claimed) {
        let row = owner_binding_at(&owner, &k2.key_id, scope).await;
        dir2.put_attestation(SignedAttestation { attestation: row })
            .await
            .unwrap_or_else(|e| panic!("owner-binding for D2 at {scope}: {e:?}"));
    }

    let auth = |key: &Arc<Ident>, dir: &Arc<SqliteBackend>| ReticulumAuth {
        signer: Some(key.signer()),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        // CIRISEdge#727 — the production wiring: a node pushes its own
        // owner-binding on every link it dials.
        own_owner_binding: Some(Arc::new(DirectoryOwnerBinding::new(
            Arc::clone(dir) as Arc<dyn FederationDirectory>,
            key.key_id.clone(),
        ))),
        ..ReticulumAuth::default()
    };
    // One `EdgeMetrics` per device, shared by its transport (the #727 push
    // ledger is a transport fact) and its runtime.
    let m1 = EdgeMetrics::new();
    let m2 = EdgeMetrics::new();
    let (t1, addr1) = build_reticulum_with_retry_metrics(
        || {
            let base = tmp.path().to_path_buf();
            let auth = auth(&k1, &dir1);
            let key_id = k1.key_id.clone();
            async move {
                let mut c = ReticulumTransportConfig::new(base.join("d1/transport.id"), &key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.announce_interval = Duration::from_secs(5);
                (c, auth)
            }
        },
        m1.clone(),
    )
    .await;
    let port1 = addr1.port();
    let (t2, _) = build_reticulum_with_retry_metrics(
        || {
            let base = tmp.path().to_path_buf();
            let auth = auth(&k2, &dir2);
            let key_id = k2.key_id.clone();
            async move {
                let mut c = ReticulumTransportConfig::new(base.join("d2/transport.id"), &key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.bootstrap_peers = vec![format!("127.0.0.1:{port1}").parse().unwrap()];
                c.announce_interval = Duration::from_secs(5);
                (c, auth)
            }
        },
        m2.clone(),
    )
    .await;

    let d1 = device(Arc::clone(&k1), dir1, t1, m1, &owner, &k2).await;
    let d2 = device(Arc::clone(&k2), dir2, t2, m2, &owner, &k1).await;
    Pair {
        d1,
        d2,
        owner,
        d1_port: port1,
        tmp,
    }
}

/// The production wiring in miniature (as `first_contact_ladder_659.rs`): a
/// runtime over the transport, the peer registered on the three bootstrap
/// planes plus Attestation, the self-publish set `{node, owner}`, and an
/// inbound loop feeding the router.
async fn device(
    key: Arc<Ident>,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    owner: &Ident,
    peer: &Ident,
) -> Device {
    let peers = [
        EnvelopeKind::Key,
        EnvelopeKind::IdentityOccurrence,
        EnvelopeKind::TransportDestination,
        EnvelopeKind::Attestation,
    ]
    .into_iter()
    .map(|kind| ReplicationPeer {
        peer_key_id: peer.key_id.clone(),
        kind,
    })
    .collect();
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&transport) as Arc<dyn Transport>,
            peers,
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    // Rounds are driven by the test (`drive_until`), so a
                    // hand-built Deliver can be sent into a QUIET responder
                    // (a mid-round responder treats extra envelopes as unasked
                    // and refuses them — the #426 hole closure, not a drop
                    // under test here).
                    cadence: Duration::from_secs(3600),
                    round_timeout: Duration::from_secs(15),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(key.key_id.clone()),
                metrics: Some(metrics.clone()),
                ..Default::default()
            },
            Some(self_publish_set([
                key.key_id.as_str(),
                owner.key_id.as_str(),
            ])),
        )
        .await,
    );
    let (tx, mut rx) = tokio::sync::mpsc::channel::<InboundFrame>(1024);
    let t = Arc::clone(&transport);
    let router = InboundRouter::new(runtime.registry());
    let tasks = vec![
        tokio::spawn(async move {
            let _ = t.listen(tx).await;
        }),
        tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let _ = router.try_route(&frame).await;
            }
        }),
    ];
    Device {
        key,
        dir,
        metrics,
        transport,
        runtime,
        _tasks: tasks,
    }
}

/// Drive both runtimes' rounds until `done` or the budget runs out. Returns the
/// number of round sweeps it took (`None` = never).
async fn drive_until<F, Fut>(p: &Pair, budget: Duration, mut done: F) -> Option<usize>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + budget;
    let mut sweeps = 0usize;
    loop {
        let _ = p.d1.runtime.round_now_all().await;
        let _ = p.d2.runtime.round_now_all().await;
        sweeps += 1;
        tokio::time::sleep(Duration::from_millis(1500)).await;
        if done().await {
            return Some(sweeps);
        }
        if tokio::time::Instant::now() > deadline {
            return None;
        }
    }
}

async fn dump(p: &Pair, label: &str) {
    for (who, dev, other) in [("D1", &p.d1, &p.d2), ("D2", &p.d2, &p.d1)] {
        let want = hex::encode(other.transport.local_named_dest_hash());
        let rows = dev
            .dir
            .list_signed_transport_destinations_for(&other.key.key_id)
            .await
            .unwrap_or_default();
        let (not_announced, unresolved) = dev.withholds();
        eprintln!(
            "[{label}] {who} holds {} signed route(s) for its peer (item 2 wants dest={want}); \
             withheld identity_row_node_not_announced={not_announced} \
             identity_row_announce_unresolved={unresolved}",
            rows.len()
        );
        for r in &rows {
            eprintln!(
                "    dest={} mldsa={} epoch={}",
                r.transport_destination.destination,
                r.signature.mldsa65_signature_base64.is_some(),
                r.transport_destination.epoch
            );
        }
    }
}

/// A Deliver of eight consent rows D1 → peer_i: above the Channel-first cap at
/// the loopback link's 16 KB MDU, so it rides a Resource (see
/// `reverse_link_resource_binding_722`).
async fn resource_deliver(from: &Ident, peers: &[Ident]) -> (Vec<u8>, Vec<String>) {
    let signer = from.signer();
    let mut envelopes = Vec::new();
    let mut ids = Vec::new();
    for peer in peers {
        let att = replication_consent_attestation(
            &from.key_id,
            &peer.key_id,
            &DEFAULT_CONSENT_PREFIXES,
            chrono::Utc::now(),
            &signer,
        )
        .await
        .expect("consent");
        ids.push(att.attestation_id.clone());
        envelopes.push(serde_json::to_vec(&att).expect("json"));
    }
    let frame = wire_frame::wrap_for_kind(&ReplicationMessage::Deliver(DeliverMessage {
        kind: EnvelopeKind::Attestation,
        envelopes,
    }));
    assert!(
        frame.len() > 8 * (16_297 - 16),
        "must exceed the Channel-first cap"
    );
    (frame, ids)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "warn,ciris_edge=info".into()),
        )
        .with_test_writer()
        .try_init();
}

/// Returns the number of round sweeps until both routes crossed.
async fn routes_cross_and_a_resource_row_admits(p: &Pair, label: &str) -> usize {
    let crossed = drive_until(p, Duration::from_secs(120), || async {
        p.d2.holds_route_for(&p.d1.key).await && p.d1.holds_route_for(&p.d2.key).await
    })
    .await;
    dump(p, label).await;
    for (who, dev) in [("D1", &p.d1), ("D2", &p.d2)] {
        eprintln!(
            "[{label}] {who} owner-binding ledger: {:?}",
            dev.owner_binding_ledger()
        );
    }
    assert!(
        crossed.is_some(),
        "[{label}] each device must come to hold the other's hybrid-signed route (the \
         #393 item-2 operand) — see the withhold ledger above for which leg held it back"
    );
    let sweeps = crossed.unwrap_or(0);
    eprintln!("[{label}] both routes crossed after {sweeps} sweep(s)");

    // D1 → D2 as a Resource, over whichever live link D1 holds to D2.
    let extra: Vec<Ident> = {
        let mut v = Vec::new();
        for i in 0u8..8 {
            v.push(Ident::new(&format!("peer-{i}-682-{label}"), 0x90 | i).await);
        }
        v
    };
    for e in &extra {
        p.d2.dir
            .put_public_key(ciris_persist::federation::SignedKeyRecord {
                record: e.record("node").await,
            })
            .await
            .expect("register consent subject at D2");
    }
    let (frame, ids) = resource_deliver(&p.d1.key, &extra).await;
    // Let every driven round settle (round_timeout is 15 s) so D2's responder
    // for D1 is quiet and the Deliver is judged as the unsolicited push it is.
    tokio::time::sleep(Duration::from_secs(16)).await;
    p.d1.transport
        .send(&p.d2.key.key_id, &frame)
        .await
        .expect("D1 -> D2 Resource");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    let landed = loop {
        let mut all = true;
        for id in &ids {
            all &= p.d2.holds_attestation(id).await;
        }
        if all {
            break Some(());
        }
        if tokio::time::Instant::now() > deadline {
            break None;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    };
    assert!(
        landed.is_some(),
        "[{label}] the Resource-carried rows from D1 must be ADMITTED at D2 once D2 holds \
         D1's route"
    );
    let _ = &p.owner;
    sweeps
}

/// Control: both devices announced (owner-binding at `federation`) — the
/// fixture's `announced: true`. Routes cross; the Resource row admits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn announced_devices_of_one_owner_exchange_routes_and_admit_682() {
    init_tracing();
    let p = pair("announced", "federation").await;
    routes_cross_and_a_resource_row_admits(&p, "announced").await;
    let (n1, _) = p.d1.withholds();
    let (n2, _) = p.d2.withholds();
    assert_eq!(
        (n1, n2),
        (0, 0),
        "an announced node's identity rows are never withheld for announce state"
    );
}

/// CIRISEdge#727 — the round bound for the unannounced pair. The announced
/// control crosses in 2 sweeps; the dark pair needs each device's own binding
/// to cross first (pushed on the dial each device makes in its first round),
/// then the route in the next. Measured: see the PR. This is a BOUND, asserted
/// so a regression to "converges eventually" (a TTL-paced memo, #568) fails
/// loudly instead of passing slowly.
const UNANNOUNCED_ROUND_BOUND: usize = 6;

/// CIRISEdge#727 — the round bound for RECOVERY. The wiped device is unowned
/// in its own directory, so the rung admits nothing at it; it re-learns its
/// binding on the ordinary attributed path (§2.1.1 "Recovery"). Measured 12
/// sweeps, and the shape is known: both routes cross within 2 sweeps, then
/// the sibling's Attestation-plane round toward the wiped device — opened
/// before the device was Attributed at the sibling, so its reply could not
/// route back — waits out the fixture's 15 s `round_timeout` (≈10 sweeps at
/// 1.5 s) before the NEXT round delivers both bindings. That is the #634
/// stuck-round class, bounded by `round_timeout`, not a memo TTL (#568): no
/// gate here waits on time. Pinned with the one-timeout margin.
const RECOVERY_ROUND_BOUND: usize = 16;

/// The claimed-but-unannounced pair: each device knows only its own binding.
/// FAILED on the pre-#727 code (see the module docs): neither route ever
/// crossed, each side booked ≈320 `identity_row_node_not_announced` withholds
/// in 120 s. With the owner-binding rung (`FSD/FIRST_CONTACT.md` §2.1.1) each
/// device pushes `owner → self` on the link it dials; the sibling admits it
/// (its own owner signed it), the #682 memo invalidates, and its route
/// follows on the next round. Bounded in rounds; no TTL waited on.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unannounced_devices_of_one_owner_exchange_routes_and_admit_682() {
    init_tracing();
    let p = pair("dark", "self").await;
    let sweeps = routes_cross_and_a_resource_row_admits(&p, "unannounced").await;
    assert!(
        sweeps <= UNANNOUNCED_ROUND_BOUND,
        "the unannounced pair must converge within {UNANNOUNCED_ROUND_BOUND} sweeps, took \
         {sweeps} (a memo left to its TTL would still pass the 120 s budget — #568)"
    );
    // I-a / I-d: each side ADMITTED the other's binding on the rung (the row
    // is in the directory, and the ledger names the rung, not a TTL).
    for (who, dev, other) in [("D1", &p.d1, &p.d2), ("D2", &p.d2, &p.d1)] {
        assert!(
            dev.holds_attestation(&format!("owner-binding-{}", other.key.key_id))
                .await,
            "{who} must hold its sibling's owner-binding"
        );
        assert!(
            dev.ledger(OWNER_BINDING_ADMITTED) >= 1,
            "{who} must have admitted a binding on the owner-binding rung, ledger={:?}",
            dev.owner_binding_ledger()
        );
        // I-b: each side SENT its own binding — on a link it dialed, or as
        // the answer to its sibling's newly admitted binding (which of the two
        // depends on who dialed first and whether the other's sends reused
        // that link, #531). Never neither.
        assert!(
            dev.ledger(OWNER_BINDING_PUSHED) + dev.ledger(OWNER_BINDING_ANSWERED) >= 1,
            "{who} must have pushed (dialed link) or answered (reply path) its own binding, \
             ledger={:?}",
            dev.owner_binding_ledger()
        );
        assert_eq!(
            dev.ledger(OwnerBindingRefusal::NotOwnOwner.as_str()),
            0,
            "{who} received nothing but its own owner's bindings"
        );
    }
}

// ── CIRISEdge#727 — the negatives and the recovery case (I20) ──────────────

/// The Deliver the rung judges: kind Attestation, the given rows.
fn owner_binding_deliver(rows: &[Attestation]) -> DeliverMessage {
    DeliverMessage {
        kind: EnvelopeKind::Attestation,
        envelopes: rows
            .iter()
            .map(|r| {
                serde_json::to_vec(&SignedAttestation {
                    attestation: r.clone(),
                })
                .expect("json")
            })
            .collect(),
    }
}

/// (a) `O → Y` signed by a key that is not R's owner is refused BY NAME, both
/// shapes: the attester field names a stranger (refused before any
/// cryptography), and the attester field names O but a stranger signed
/// (refused at the signature). Nothing is stored either way.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_binding_signed_by_a_key_that_is_not_the_receivers_owner_is_refused_by_name_727() {
    let owner = Ident::new("owner-727a", 0x51).await;
    let r = Ident::new("r-727a", 0x52).await;
    let y = Ident::new("y-727a", 0x53).await;
    let stranger = Ident::new("stranger-727a", 0x54).await;
    let dir = directory_with(vec![
        owner.record("user").await,
        r.record("node").await,
        y.record("node").await,
        stranger.record("user").await,
    ])
    .await;
    dir.put_attestation(SignedAttestation {
        attestation: owner_binding_at(&owner, &r.key_id, "self").await,
    })
    .await
    .expect("R's own binding");
    let metrics = EdgeMetrics::new();
    let gate = OwnerBindingCarveOut::new(
        r.key_id.clone(),
        Arc::clone(&dir) as Arc<dyn FederationDirectory>,
        None,
        Some(metrics.clone()),
    );

    // Shape 1: a stranger's own binding of Y — attester = stranger.
    let strangers_row = owner_binding_at(&stranger, &y.key_id, "self").await;
    let out = gate
        .admit_deliver(&owner_binding_deliver(std::slice::from_ref(&strangers_row)))
        .await;
    assert_eq!(
        out,
        OwnerBindingOutcome::Consumed {
            admitted: 0,
            held: 0,
            refused: vec![OwnerBindingRefusal::NotOwnOwner],
            subjects: vec![],
        },
        "a binding whose attester is not R's owner is refused by name"
    );
    assert_eq!(ledger(&metrics, "owner_binding_not_own_owner"), 1);
    assert_eq!(
        ledger(&metrics, "owner_binding_signature_invalid"),
        0,
        "refused BEFORE any cryptography: the signature was never checked"
    );

    // Shape 2: the attester FIELD says O, the signature is the stranger's.
    let forged = owner_binding_signed_by(&owner, &stranger, &y.key_id, "self").await;
    let out = gate.admit_deliver(&owner_binding_deliver(&[forged])).await;
    assert_eq!(
        out,
        OwnerBindingOutcome::Consumed {
            admitted: 0,
            held: 0,
            refused: vec![OwnerBindingRefusal::SignatureInvalid],
            subjects: vec![],
        },
        "a row naming O but not signed by O fails against the held owner key"
    );
    assert_eq!(ledger(&metrics, "owner_binding_signature_invalid"), 1);

    // Nothing landed: Y is not one of O's nodes at R.
    let rows = dir.list_attestations_since(None, 1024).await.expect("list");
    assert!(
        !rows
            .iter()
            .any(|s| s.attestation.attestation_id == format!("owner-binding-{}", y.key_id)),
        "no refused row is stored"
    );
    let owned_nodes = ciris_persist::federation::admission::nodes_owned_by(&*dir, &owner.key_id)
        .await
        .expect("nodes_owned_by");
    assert_eq!(
        owned_nodes,
        vec![r.key_id.clone()],
        "O's node set at R is still just R"
    );
    assert_eq!(ledger(&metrics, OWNER_BINDING_ADMITTED), 0);
}

/// (b) A stranger S receiving `O → X` refuses it — unowned S by
/// `owner_binding_receiver_unowned`, S owned by P by
/// `owner_binding_not_own_owner` — stores nothing, and O's device set is not
/// enumerable at S: `nodes_owned_by(O)` stays empty, which is exactly the set
/// the #682 serve gate would hand X's rows to. S never serves X the self plane.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stranger_refuses_another_owners_binding_and_holds_nothing_727() {
    let owner = Ident::new("owner-727b", 0x61).await;
    let x = Ident::new("x-727b", 0x62).await;
    let s = Ident::new("s-727b", 0x63).await;
    let p = Ident::new("p-727b", 0x64).await;
    let genuine = owner_binding_at(&owner, &x.key_id, "self").await;

    // S unowned.
    let dir_s = directory_with(vec![
        owner.record("user").await,
        x.record("node").await,
        s.record("node").await,
    ])
    .await;
    let metrics = EdgeMetrics::new();
    let gate = OwnerBindingCarveOut::new(
        s.key_id.clone(),
        Arc::clone(&dir_s) as Arc<dyn FederationDirectory>,
        None,
        Some(metrics.clone()),
    );
    let out = gate
        .admit_deliver(&owner_binding_deliver(std::slice::from_ref(&genuine)))
        .await;
    assert_eq!(
        out,
        OwnerBindingOutcome::Consumed {
            admitted: 0,
            held: 0,
            refused: vec![OwnerBindingRefusal::ReceiverUnowned],
            subjects: vec![],
        }
    );
    assert_eq!(ledger(&metrics, "owner_binding_receiver_unowned"), 1);

    // S owned by P: still not O.
    let dir_s2 = directory_with(vec![
        owner.record("user").await,
        x.record("node").await,
        s.record("node").await,
        p.record("user").await,
    ])
    .await;
    dir_s2
        .put_attestation(SignedAttestation {
            attestation: owner_binding_at(&p, &s.key_id, "self").await,
        })
        .await
        .expect("P → S");
    let metrics2 = EdgeMetrics::new();
    let gate2 = OwnerBindingCarveOut::new(
        s.key_id.clone(),
        Arc::clone(&dir_s2) as Arc<dyn FederationDirectory>,
        None,
        Some(metrics2.clone()),
    );
    let out = gate2
        .admit_deliver(&owner_binding_deliver(std::slice::from_ref(&genuine)))
        .await;
    assert_eq!(
        out,
        OwnerBindingOutcome::Consumed {
            admitted: 0,
            held: 0,
            refused: vec![OwnerBindingRefusal::NotOwnOwner],
            subjects: vec![],
        }
    );
    assert_eq!(ledger(&metrics2, "owner_binding_not_own_owner"), 1);
    assert_eq!(
        ledger(&metrics2, "owner_binding_signature_invalid"),
        0,
        "no cryptography was spent on a stranger's row"
    );

    for (label, dir) in [("unowned S", &dir_s), ("P-owned S", &dir_s2)] {
        let rows = dir.list_attestations_since(None, 1024).await.expect("list");
        assert!(
            !rows
                .iter()
                .any(|r| r.attestation.attestation_id == genuine.attestation_id),
            "[{label}] the genuine `O → X` is NOT stored at a stranger"
        );
        let owned_nodes =
            ciris_persist::federation::admission::nodes_owned_by(&**dir, &owner.key_id)
                .await
                .expect("nodes_owned_by");
        assert!(
            owned_nodes.is_empty(),
            "[{label}] O's device set is not enumerable at S (got {owned_nodes:?}) — the #682 \
             serve gate hands X's rows to exactly this set, so S never serves X the self \
             plane"
        );
    }
}

/// (c) X pushes its binding only on a link X DIALED. A stranger S that dials
/// D1 (D1 never dials S — S is not in D1's peer set) is sent nothing on the
/// rung: S's ledger has no `owner_binding_*` entry at all, S holds no binding
/// of O's, and D1's push count equals what it pushed toward its sibling.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_pushes_its_binding_only_on_a_link_it_dialed_727() {
    init_tracing();
    let p = pair("dialed", "self").await;
    // The stranger: unowned, its own record + D1's + the owner's (so it can
    // verify anything it is handed), D1 as its only peer, dialing D1.
    let s = Arc::new(Ident::new("stranger-727c", 0x71).await);
    let dir_s = directory_with(vec![
        s.record("node").await,
        p.d1.key.record("node").await,
        p.owner.record("user").await,
    ])
    .await;
    let port1 = p.d1_port;
    let ms = EdgeMetrics::new();
    let (ts, _) = build_reticulum_with_retry_metrics(
        || {
            let base = p.tmp.path().to_path_buf();
            let auth = ReticulumAuth {
                signer: Some(s.signer()),
                rooting: Some(Arc::clone(&dir_s) as Arc<dyn RootingDirectory>),
                resolver: None,
                hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
                own_owner_binding: Some(Arc::new(DirectoryOwnerBinding::new(
                    Arc::clone(&dir_s) as Arc<dyn FederationDirectory>,
                    s.key_id.clone(),
                ))),
                ..ReticulumAuth::default()
            };
            let key_id = s.key_id.clone();
            async move {
                let mut c = ReticulumTransportConfig::new(base.join("s/transport.id"), &key_id);
                c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                c.bootstrap_peers = vec![format!("127.0.0.1:{port1}").parse().unwrap()];
                c.announce_interval = Duration::from_secs(5);
                (c, auth)
            }
        },
        ms.clone(),
    )
    .await;
    let stranger = device(Arc::clone(&s), dir_s, ts, ms, &s, &p.d1.key).await;

    // Drive all three; the pair converges, the stranger keeps dialing D1.
    let crossed = drive_until(&p, Duration::from_secs(120), || async {
        let _ = stranger.runtime.round_now_all().await;
        p.d2.holds_route_for(&p.d1.key).await && p.d1.holds_route_for(&p.d2.key).await
    })
    .await;
    assert!(
        crossed.is_some(),
        "the pair still converges with a stranger attached"
    );
    for _ in 0..3 {
        let _ = stranger.runtime.round_now_all().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    eprintln!(
        "[dialed] D1 ledger {:?}; S ledger {:?}",
        p.d1.owner_binding_ledger(),
        stranger.owner_binding_ledger()
    );

    // I-b: the stranger is unowned, so it pushed nothing on the links IT dialed.
    assert_eq!(
        stranger.ledger(OWNER_BINDING_PUSHED),
        0,
        "an unowned node pushes nothing"
    );
    // I-b: D1 pushed only toward its sibling; nothing rode the stranger's
    // inbound link, so the stranger's rung never fired — not even a refusal.
    assert!(
        stranger.owner_binding_ledger().is_empty(),
        "the stranger's inbound link carried no binding push at all: {:?}",
        stranger.owner_binding_ledger()
    );
    assert!(
        !stranger
            .holds_attestation(&format!("owner-binding-{}", p.d1.key.key_id))
            .await,
        "the stranger holds no binding of O's"
    );
    let owned_nodes =
        ciris_persist::federation::admission::nodes_owned_by(&*stranger.dir, &p.owner.key_id)
            .await
            .expect("nodes_owned_by");
    assert!(
        owned_nodes.is_empty(),
        "O's device set is not enumerable at the stranger"
    );
    assert!(
        p.d1.ledger(OWNER_BINDING_PUSHED) + p.d1.ledger(OWNER_BINDING_ANSWERED) >= 1,
        "D1 sent its binding toward its sibling (and, per the stranger's empty ledger, \
         nowhere else)"
    );
}

/// Recovery: D2 wiped to its seed + O's key record dials D1, which still
/// holds `O → D2`. D2 re-converges: it holds `O → D2` and `O → D1` again and
/// both routes cross, within the same round bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wiped_device_reconverges_by_dialling_its_sibling_727() {
    init_tracing();
    let p = pair_with("wiped", "self", D2Starts::Wiped).await;
    assert!(
        !p.d2
            .holds_attestation(&format!("owner-binding-{}", p.d2.key.key_id))
            .await,
        "precondition: the wiped device holds no binding about itself"
    );
    let crossed = drive_until(&p, Duration::from_secs(120), || async {
        p.d2.holds_route_for(&p.d1.key).await
            && p.d1.holds_route_for(&p.d2.key).await
            && p.d2
                .holds_attestation(&format!("owner-binding-{}", p.d2.key.key_id))
                .await
            && p.d2
                .holds_attestation(&format!("owner-binding-{}", p.d1.key.key_id))
                .await
    })
    .await;
    dump(&p, "wiped").await;
    for (who, dev) in [("D1", &p.d1), ("D2", &p.d2)] {
        eprintln!(
            "[wiped] {who} owner-binding ledger: {:?}",
            dev.owner_binding_ledger()
        );
    }
    let sweeps = crossed.expect(
        "the wiped device must recover its binding, its sibling's binding and both routes \
         by dialling its sibling",
    );
    eprintln!("[wiped] recovered after {sweeps} sweep(s)");
    assert!(
        sweeps <= RECOVERY_ROUND_BOUND,
        "recovery must be bounded in rounds (one stuck-round timeout + the exchange), took \
         {sweeps} > {RECOVERY_ROUND_BOUND}"
    );
    let owned_nodes =
        ciris_persist::federation::admission::nodes_owned_by(&*p.d2.dir, &p.owner.key_id)
            .await
            .expect("nodes_owned_by");
    let mut want = vec![p.d1.key.key_id.clone(), p.d2.key.key_id.clone()];
    want.sort();
    assert_eq!(owned_nodes, want, "D2 knows O's device set again");
}
