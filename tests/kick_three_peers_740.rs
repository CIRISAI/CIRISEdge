//! CIRISEdge#740 — a node with THREE peers must survive a kicked round.
//!
//! The field (CIRISServer `selffiles`: one person on two devices plus a
//! contact's node, all three peered with the canonical): D1's self-room tick
//! placed the Welcome, the kick fanned out, and the process stopped — no
//! further round, no HTTP. The gdb dump: 42 threads parked in
//! `DirectoryStateAdapter::local_refs`'s `block_in_place` + `Handle::block_on`,
//! zero blocking-pool threads executing. `block_in_place` hands the worker's
//! core to a replacement drawn from the blocking pool, and `block_on` parks on
//! a persist read that needs ANOTHER pool slot; a kick runs every
//! `(peer, kind)` at once, so 3 peers × 14 kinds = 42 bridged reads against a
//! 32-slot pool (`max_blocking_threads(32)`, edge's and the server's budget)
//! hold every slot before any read starts. Two peers (28) fit — which is why
//! every two-node witness was green.
//!
//! This witness is that shape on real parts: four production-shaped nodes
//! (self-signed hybrid keys whose ids bind their pubkeys, a real persist
//! directory per node holding every node's key row and each hub↔peer
//! hybrid-signed route, Reticulum over loopback TCP, `ReplicationRuntime`s
//! routing inbound frames through the #393 gate), D1 replicating with three
//! rooted peers over 14 kinds, the self room installed on D1 and its sibling
//! device. It runs on a runtime built exactly as the node's —
//! `max_blocking_threads(32)` — in its own thread, and the test thread holds a
//! hard wall-clock timeout on it (a wedged runtime cannot fire its own timers,
//! so the timeout must live outside it).
//!
//! - **Pre-fix (v34.3.0 @ 852f43d, observed):** the start-up fan-out (every
//!   coordinator's first tick fires at spawn — a start IS a kick) wedges D1:
//!   the 240 s hard timeout fired with 3 of 42 rounds terminated and the
//!   counter frozen. The same file with `PEERS = 2` (28 rounds) passes on
//!   v34.3.0 in 3.5 s — the threshold is the pool, exactly as the arithmetic
//!   says.
//! - **Post-fix (observed):** the start-up rounds and a `round_now_all` kick
//!   both finish (42 + 42 rounds in ~4.5 s), and every one of the 42
//!   `(peer, kind)` rounds of the kick reaches its peer on the wire.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test kick_three_peers_740`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::collections::HashSet;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::RoundOutcome;
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationPeer, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{CohortScope, EdgeMetrics};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;
use tokio::sync::mpsc;

/// The blocking-pool ceiling edge_node and CIRISServer build their runtimes
/// with (`runtime_budget::DEFAULT_MAX_BLOCKING_THREADS`), spelled out so the
/// witness pins the field's number even if the default moves.
const MAX_BLOCKING_THREADS: usize = 32;
/// edge_node's worker count.
const WORKER_THREADS: usize = 4;
/// The field's per-peer plane count: 3 × 14 = 42 > 32.
const KINDS: usize = 14;
const PEERS: usize = 3;
/// The hard wall-clock bound the test thread holds on the whole scenario.
const HARD_TIMEOUT: Duration = Duration::from_secs(240);

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .with_test_writer()
        .try_init();
}

/// A production-shaped identity: a hybrid keypair and a key id that BINDS the
/// pubkey fingerprint, so the announce yields `owns_key` (item 1).
struct Ident {
    key_id: String,
    ed: Arc<Ed25519SoftwareSigner>,
    pqc: Arc<MlDsa65SoftwareSigner>,
    ed_pub: Vec<u8>,
    pqc_pub_b64: String,
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
        ciris_persist::federation::KeyRecord {
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
        }
    }
}

fn auth(signer: Arc<LocalSigner>, dir: &Arc<SqliteBackend>) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

async fn build_transport(
    metrics: &EdgeMetrics,
    base: &std::path::Path,
    who: &Ident,
    dir: &Arc<SqliteBackend>,
    bootstrap: Option<u16>,
) -> (Arc<ReticulumTransport>, u16) {
    for _ in 0..16 {
        let signer = who.signer();
        let mut c = ReticulumTransportConfig::new(
            base.join(format!("{}/transport.id", who.key_id)),
            &signer.key_id,
        );
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        if let Some(port) = bootstrap {
            c.bootstrap_peers = vec![format!("127.0.0.1:{port}").parse().unwrap()];
        }
        c.announce_interval = Duration::from_secs(5);
        let port = c.listen_addr.port();
        match ReticulumTransport::new(c, auth(signer, dir)).await {
            Ok(t) => return (Arc::new(t.with_metrics(Some(metrics.clone()))), port),
            Err(e)
                if e.to_string().contains("Address already in use")
                    || e.to_string().contains("os error 98") => {}
            Err(e) => panic!("build reticulum transport: {e:?}"),
        }
    }
    panic!("build reticulum transport: exhausted bind retries");
}

/// The self room on `transport` (D1 and its sibling device).
fn install_self_room(transport: &ReticulumTransport, me: &str, members: &[&str]) {
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    table
        .install_group(
            &CohortScope::SelfOnly,
            "self:owner-740",
            1,
            &[0x74; 32],
            members,
        )
        .expect("install the self room");
    let own = table
        .send_address(&CohortScope::SelfOnly, "self:owner-740", me)
        .expect("own derived address");
    transport
        .register_scoped_destination(&own, &CohortScope::SelfOnly)
        .expect("listen on the derived address");
    transport
        .install_scope_address_table(table)
        .expect("install the table");
}

/// Every `(peer, kind)` a node's listener saw a replication frame for.
type SeenKinds = Arc<std::sync::Mutex<HashSet<EnvelopeKind>>>;

/// A runtime + router over `transport`, as production wires it. The listener
/// records the kind of every replication frame it sees, then routes it.
async fn node(
    key: &Ident,
    dir: &Arc<SqliteBackend>,
    transport: &Arc<ReticulumTransport>,
    metrics: &EdgeMetrics,
    peers: Vec<ReplicationPeer>,
    seen: SeenKinds,
) -> Arc<ReplicationRuntime> {
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(dir) as Arc<dyn FederationDirectory>,
            Arc::clone(transport) as Arc<dyn Transport>,
            peers,
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    // Rounds after the start-up tick are driven by the test.
                    cadence: Duration::from_secs(3600),
                    round_timeout: Duration::from_secs(5),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(key.key_id.clone()),
                metrics: Some(metrics.clone()),
                ..Default::default()
            },
            None,
        )
        .await,
    );
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(1024);
    let listener = Arc::clone(transport);
    let router = InboundRouter::new(runtime.registry());
    tokio::spawn(async move {
        let _ = listener.listen(tx).await;
    });
    tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if let Ok(Some(msg)) = wire_frame::try_unwrap(&frame.envelope_bytes) {
                seen.lock().unwrap().insert(msg.kind());
            }
            let _ = router.try_route(&frame).await;
        }
    });
    runtime
}

fn rounds_terminated(m: &EdgeMetrics) -> u64 {
    let snap = m.snapshot();
    [
        RoundOutcome::Completed,
        RoundOutcome::Refused,
        RoundOutcome::TimedOut,
        RoundOutcome::Error,
    ]
    .iter()
    .map(|o| {
        snap.replication_round_outcomes_total
            .get(o)
            .copied()
            .unwrap_or(0)
    })
    .sum()
}

/// Where the scenario is — read by the test thread when the hard timeout fires.
const STAGE_SETUP: u8 = 0;
const STAGE_STARTUP_FANOUT: u8 = 1;
const STAGE_LEARN: u8 = 2;
const STAGE_KICK: u8 = 3;
const STAGE_DONE: u8 = 4;

fn stage_name(s: u8) -> &'static str {
    match s {
        STAGE_SETUP => "setup",
        STAGE_STARTUP_FANOUT => "start-up fan-out (every coordinator's first tick)",
        STAGE_LEARN => "D1 and the peers learning each other",
        STAGE_KICK => "round_now_all kick",
        _ => "done",
    }
}

struct Outcome {
    startup_rounds: u64,
    kick_rounds: u64,
    kinds_seen_per_peer: Vec<usize>,
    kinds_seen_per_peer_after_kick: Vec<usize>,
}

#[allow(clippy::too_many_lines)] // one field scenario, top to bottom
async fn scenario(stage: Arc<AtomicU8>, d1_metrics: EdgeMetrics) -> Outcome {
    let tmp = tempfile::tempdir().expect("tempdir");
    let d1 = Ident::new("d1-740", 0xd1).await;
    let mut peers = Vec::with_capacity(PEERS);
    for i in 0..PEERS {
        peers.push(
            Ident::new(
                &format!("peer-{i}-740"),
                0x40 | u8::try_from(i).expect("a handful of peers"),
            )
            .await,
        );
    }
    let mut records = vec![d1.record("node").await];
    for p in &peers {
        records.push(p.record("node").await);
    }
    let d1_dir = directory_with(records.clone()).await;
    let (d1_transport, d1_port) =
        build_transport(&d1_metrics, tmp.path(), &d1, &d1_dir, None).await;

    let mut peer_dirs = Vec::with_capacity(PEERS);
    let mut peer_transports = Vec::with_capacity(PEERS);
    let mut peer_metrics = Vec::with_capacity(PEERS);
    for p in &peers {
        let dir = directory_with(records.clone()).await;
        let metrics = EdgeMetrics::new();
        let (t, _) = build_transport(&metrics, tmp.path(), p, &dir, Some(d1_port)).await;
        peer_dirs.push(dir);
        peer_transports.push(t);
        peer_metrics.push(metrics);
    }

    // Hub ↔ peer: each side holds the other's hybrid-signed route (#393 item
    // 2 in both directions) — the peering act's end state.
    for (i, p) in peers.iter().enumerate() {
        for (from, from_key, to) in [(&d1_dir, &d1, &peer_dirs[i]), (&peer_dirs[i], p, &d1_dir)] {
            let routes = from
                .list_signed_transport_destinations_for(&from_key.key_id)
                .await
                .expect("list routes");
            assert!(
                routes
                    .iter()
                    .any(|r| r.signature.mldsa65_signature_base64.is_some()),
                "the route must be hybrid-signed"
            );
            for r in &routes {
                FederationDirectory::put_signed_transport_destination(&**to, r)
                    .await
                    .expect("seed the route");
            }
        }
    }

    // The self room: D1 and its sibling device (peer 0), as in the field.
    let members = [d1.key_id.as_str(), peers[0].key_id.as_str()];
    install_self_room(&d1_transport, &d1.key_id, &members);
    install_self_room(&peer_transports[0], &peers[0].key_id, &members);

    // The peers answer through the responder factory; D1 initiates toward all
    // three over the 14 planes.
    let mut peer_seen: Vec<SeenKinds> = Vec::with_capacity(PEERS);
    let mut peer_runtimes = Vec::with_capacity(PEERS);
    for i in 0..PEERS {
        let seen: SeenKinds = Arc::default();
        peer_runtimes.push(
            node(
                &peers[i],
                &peer_dirs[i],
                &peer_transports[i],
                &peer_metrics[i],
                Vec::new(),
                Arc::clone(&seen),
            )
            .await,
        );
        peer_seen.push(seen);
    }
    let kinds = &EnvelopeKind::ALL[..KINDS];
    let d1_peers: Vec<ReplicationPeer> = peers
        .iter()
        .flat_map(|p| {
            kinds.iter().map(move |k| ReplicationPeer {
                peer_key_id: p.key_id.clone(),
                kind: *k,
            })
        })
        .collect();
    assert_eq!(d1_peers.len(), PEERS * KINDS);
    let expected = (PEERS * KINDS) as u64;

    // ── The start-up fan-out: every coordinator's first tick fires at spawn.
    stage.store(STAGE_STARTUP_FANOUT, Ordering::SeqCst);
    let d1_runtime = node(
        &d1,
        &d1_dir,
        &d1_transport,
        &d1_metrics,
        d1_peers,
        Arc::new(std::sync::Mutex::new(HashSet::new())),
    )
    .await;
    while rounds_terminated(&d1_metrics) < expected {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let startup_rounds = rounds_terminated(&d1_metrics);
    let kinds_seen_per_peer: Vec<usize> =
        peer_seen.iter().map(|s| s.lock().unwrap().len()).collect();

    // Both ends learn each other from their announces (the listeners are up
    // now), so the kick's rounds reach their peers on the wire.
    stage.store(STAGE_LEARN, Ordering::SeqCst);
    for (i, t) in peer_transports.iter().enumerate() {
        let known = tokio::time::timeout(Duration::from_secs(90), async {
            while !(t.knows_peer(&d1.key_id).await
                && d1_transport.knows_peer(&peers[i].key_id).await)
            {
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        })
        .await;
        assert!(known.is_ok(), "D1 and peer {i} must learn each other");
    }

    // ── The kick: `round_now_all` fans out to all 42 coordinators at once.
    stage.store(STAGE_KICK, Ordering::SeqCst);
    for s in &peer_seen {
        s.lock().unwrap().clear();
    }
    d1_runtime.round_now_all().await.expect("kick");
    while rounds_terminated(&d1_metrics) < startup_rounds + expected
        || peer_seen.iter().any(|s| s.lock().unwrap().len() < KINDS)
    {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let kick_rounds = rounds_terminated(&d1_metrics) - startup_rounds;
    let kinds_seen_per_peer_after_kick: Vec<usize> =
        peer_seen.iter().map(|s| s.lock().unwrap().len()).collect();
    stage.store(STAGE_DONE, Ordering::SeqCst);
    drop(peer_runtimes);
    Outcome {
        startup_rounds,
        kick_rounds,
        kinds_seen_per_peer,
        kinds_seen_per_peer_after_kick,
    }
}

/// **The witness.** Three rooted peers × 14 planes = 42 `(peer, kind)` rounds
/// on a `max_blocking_threads(32)` runtime: the start-up fan-out and a kick
/// both finish, every round reaching its peer. Pre-fix (v34.3.0) the runtime
/// wedges and the hard timeout fires.
#[test]
fn three_peers_survive_a_kick_on_a_32_slot_blocking_pool_740() {
    init_tracing();
    let stage = Arc::new(AtomicU8::new(STAGE_SETUP));
    let d1_metrics = EdgeMetrics::new();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    {
        let stage = Arc::clone(&stage);
        let d1_metrics = d1_metrics.clone();
        // Detached on purpose: a wedged runtime can neither finish nor be
        // dropped (its drop joins the parked threads), so on failure the test
        // thread reports and the process exit reaps it.
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(WORKER_THREADS)
                .max_blocking_threads(MAX_BLOCKING_THREADS)
                .enable_all()
                .build()
                .expect("runtime");
            let out = rt.block_on(scenario(stage, d1_metrics));
            let _ = done_tx.send(out);
            rt.shutdown_timeout(Duration::from_secs(5));
        });
    }
    let started = std::time::Instant::now();
    let out = match done_rx.recv_timeout(HARD_TIMEOUT) {
        Ok(out) => out,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!(
            "D1 did not finish within {HARD_TIMEOUT:?} — stage `{}`, {} of {} D1 rounds \
             terminated ({PEERS} peers × {KINDS} kinds on a \
             max_blocking_threads({MAX_BLOCKING_THREADS}) runtime). A frozen round counter \
             in a fan-out stage is the CIRISEdge#740 blocking-pool deadlock.",
            stage_name(stage.load(Ordering::SeqCst)),
            rounds_terminated(&d1_metrics),
            PEERS * KINDS,
        ),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!(
            "the scenario panicked in stage `{}` (see above)",
            stage_name(stage.load(Ordering::SeqCst)),
        ),
    };
    eprintln!(
        "740 witness: start-up rounds={} kick rounds={} kinds/peer start-up={:?} kick={:?} in {:?}",
        out.startup_rounds,
        out.kick_rounds,
        out.kinds_seen_per_peer,
        out.kinds_seen_per_peer_after_kick,
        started.elapsed()
    );
    assert!(out.startup_rounds >= (PEERS * KINDS) as u64);
    assert!(out.kick_rounds >= (PEERS * KINDS) as u64);
    assert!(
        out.kinds_seen_per_peer_after_kick
            .iter()
            .all(|&n| n == KINDS),
        "every (peer, kind) round of the kick reached its peer: {:?}",
        out.kinds_seen_per_peer_after_kick
    );
}
