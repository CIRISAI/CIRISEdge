//! CIRISEdge#805 E4 — **a room call between two members behind NAT**, through
//! the host call API (`Call::join`), on real Reticulum with leviculum direct
//! links (item 8).
//!
//! The topology is `direct_links_805`'s, the field's shape: a transport node
//! `T` (a bare leviculum node, the canonical's role: transport on, a
//! facilitator on a UDP port) and two edge nodes `A` and `B`, TCP clients of
//! `T` and of nothing else. A call leg dials a DERIVED address, which is
//! announce-suppressed (CC 5.4) and answers only a one-hop neighbour; across
//! `T` it cannot establish. So a call between `A` and `B` stands only when its
//! legs ride a punched interface.
//!
//! - **E4** (`a_room_call_behind_t_runs_over_a_punched_interface`): `A` is
//!   configured with `T`'s facilitator, `B` is on the DEFAULT accept (room
//!   peers, asked per request). Both join the room's call. `A`'s leg to `B`
//!   proposes on the identity link, both ends move onto the punched
//!   interface, and every leg comes up over it, sealed (CC 5.3.3.5 E1). Each
//!   member's frames reach the other byte-identical and in order, and still
//!   do after `T` is stopped.
//! - **E4 fail-before** (`a_room_call_behind_t_without_a_facilitator_has_no_leg`):
//!   the same call with no facilitator anywhere never brings a leg up, and
//!   publishing has no budget.
//!
//! **The gap, stated:** this is loopback. `T`, `A` and `B` share 127.0.0.1, so
//! the "punch" crosses no NAT mapping, filtering or port rewrite; it witnesses
//! the protocol (proposal on the identity link, the facilitator exchange,
//! the move, the call's legs born on the punched interface, survival without
//! `T`), not traversal of a real NAT. A real-NAT witness needs two hosts
//! behind distinct NATs (or network namespaces with NAT rules), which a
//! loopback test cannot give.
//!
//! Requires `transport-reticulum`:
//! `cargo test --features "transport-http transport-reticulum" --test av_call_nat_805`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::transport::av_call::{
    Call, CallDeps, CallError, CallOptions, Frame, ReceivedFrame, RoomRoster,
};
use ciris_edge::transport::av_chunk_auth::StreamKeyVerifier;
use ciris_edge::transport::av_keep::{StreamDekRegistrar, UnwiredRegistrar};
use ciris_edge::transport::direct_path::{DirectLinksConfig, DirectPathEvent};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport as _};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use leviculum_std::driver::{ReticulumNode, ReticulumNodeBuilder};
use sha2::Digest as _;
use tokio::sync::{broadcast, mpsc};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("addr")
        .port()
}

fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .expect("bind ephemeral udp")
        .local_addr()
        .expect("addr")
        .port()
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

async fn wait_until<F, Fut>(budget: Duration, mut done: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        if done().await {
            return true;
        }
        if tokio::time::Instant::now() > deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// A production-shaped identity (as `av_spine_live_node_805`): a hybrid
/// keypair and a key id that BINDS the pubkey fingerprint.
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
    async fn record(&self) -> ciris_persist::federation::KeyRecord {
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            "node",
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
            identity_type: "node".to_string(),
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

/// `T`: a bare leviculum transport node with a TCP server and a facilitator.
async fn transport_node(tcp_port: u16, facilitator_port: u16) -> ReticulumNode {
    let storage = tempfile::tempdir().expect("tempdir");
    let mut node = ReticulumNodeBuilder::new()
        .enable_transport(true)
        .add_interface_config(leviculum_std::config::InterfaceConfig {
            name: "T TCP server".to_string(),
            interface_type: "TCPServerInterface".to_string(),
            listen_ip: Some("127.0.0.1".to_string()),
            listen_port: Some(tcp_port),
            ingress_control: Some(false),
            ..Default::default()
        })
        .direct_link(leviculum_std::direct_link::DirectLinkSettings {
            facilitator_port: Some(facilitator_port),
            ..Default::default()
        })
        .storage_path(storage.path().to_path_buf())
        .build()
        .await
        .expect("build T");
    std::mem::forget(storage);
    node.start().await.expect("start T");
    let mut rx = node.take_event_receiver().expect("T's events");
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    node
}

/// One edge node: a TCP client of `T` only.
struct Side {
    key: Ident,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    lifecycle: Arc<ScopeLifecycle>,
    events: broadcast::Receiver<DirectPathEvent>,
    _edge: ciris_edge::Edge,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn side(
    key: Ident,
    dir: &Arc<SqliteBackend>,
    base: &std::path::Path,
    t_port: u16,
    direct: DirectLinksConfig,
) -> Side {
    let mut transport = None;
    for _ in 0..16 {
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = Duration::from_secs(5);
        c.bootstrap_peers = vec![format!("127.0.0.1:{t_port}").parse().unwrap()];
        let c = c.with_direct_links(direct.clone());
        let auth = ReticulumAuth {
            signer: Some(key.signer()),
            rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            blackhole_rules: Some(
                Arc::clone(dir) as Arc<dyn ciris_persist::federation::BlackholeRules>
            ),
            ..ReticulumAuth::default()
        };
        match ReticulumTransport::new(c, auth).await {
            Ok(t) => {
                transport = Some(Arc::new(t));
                break;
            }
            Err(e)
                if e.to_string().contains("Address already in use")
                    || e.to_string().contains("os error 98") => {}
            Err(e) => panic!("build reticulum transport: {e:?}"),
        }
    }
    let transport = transport.expect("bind retries exhausted");
    let edge = ciris_edge::Edge::builder()
        .directory(Arc::clone(dir) as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(Arc::clone(dir) as Arc<dyn FederationDirectory>)
        .queue(Arc::clone(dir) as Arc<dyn ciris_edge::outbound::OutboundHandle>)
        .signer(key.signer())
        .transport(Arc::clone(&transport) as Arc<dyn ciris_edge::transport::Transport>)
        .config(ciris_edge::EdgeConfig {
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            ..ciris_edge::EdgeConfig::default()
        })
        .build()
        .expect("build the edge");
    let metrics = edge.metrics();
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    transport
        .install_scope_address_table(Arc::clone(&table))
        .expect("install the table");
    let lifecycle = Arc::new(ScopeLifecycle::new(
        Arc::clone(&table),
        Arc::clone(&transport) as Arc<dyn ScopedDestinationSink>,
        key.key_id.clone(),
        Duration::from_secs(300),
    ));
    let events = transport.subscribe_direct_path_events();
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(256);
    let listener = Arc::clone(&transport);
    let tasks = vec![
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }),
        tokio::spawn(async move { while rx.recv().await.is_some() {} }),
    ];
    Side {
        key,
        dir: Arc::clone(dir),
        transport,
        metrics,
        lifecycle,
        events,
        _edge: edge,
        _tasks: tasks,
    }
}

/// A roster that answers yes (persist's active roster, stubbed: the
/// community rows are `av_call_record_805`'s subject, not this one's).
struct Roster;

#[async_trait::async_trait]
impl RoomRoster for Roster {
    async fn is_active_member(&self, _room: &str, _key_id: &str) -> Result<bool, String> {
        Ok(true)
    }
}

fn store(tag: &str) -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(tag.as_bytes()).expect("in-memory scope state"),
    ))
}

struct Pair {
    t: ReticulumNode,
    a: Side,
    b: Side,
    room: String,
    groups: [CohortGroup; 2],
    _tmp: tempfile::TempDir,
}

/// `T`, then `A` and `B` as its clients, each holding the other's signed
/// route and knowing the other through `T`; plus the room's MLS group over
/// both. `facilitated` gives `A` `T`'s facilitator; `B` is on the default.
async fn pair(tag: &str, facilitated: bool) -> Pair {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let t_port = free_port();
    let f_port = free_udp_port();
    let t = transport_node(t_port, f_port).await;
    let a_direct = DirectLinksConfig {
        facilitator: facilitated.then(|| format!("127.0.0.1:{f_port}")),
        ..DirectLinksConfig::default()
    };

    let key_a = Ident::new(&format!("node-a-nat-{tag}"), 0x3a).await;
    let key_b = Ident::new(&format!("node-b-nat-{tag}"), 0x3b).await;
    let records = vec![key_a.record().await, key_b.record().await];
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;
    let a = side(key_a, &a_dir, &tmp.path().join("a"), t_port, a_direct).await;
    let b = side(
        key_b,
        &b_dir,
        &tmp.path().join("b"),
        t_port,
        DirectLinksConfig::default(),
    )
    .await;
    for (from, from_key, to) in [(&a_dir, &a.key, &b_dir), (&b_dir, &b.key, &a_dir)] {
        let routes = from
            .list_signed_transport_destinations_for(&from_key.key_id)
            .await
            .expect("list routes");
        for r in &routes {
            FederationDirectory::put_signed_transport_destination(&**to, r)
                .await
                .expect("seed the route");
        }
    }
    let known = wait_until(Duration::from_secs(60), || async {
        a.transport.knows_peer(&b.key.key_id).await && b.transport.knows_peer(&a.key.key_id).await
    })
    .await;
    assert!(known, "A and B learn each other's announces through T");

    let room = format!("room-call-nat-{tag}");
    let ga = CohortGroup::create(store(&format!("{tag}-a")), &room, &a.key.key_id, 16)
        .await
        .expect("A founds the room");
    let (material, kp) = mint_cohort_key_material(&b.key.key_id).expect("key material");
    let add = ga.add_member(&b.key.key_id, kp).await.expect("add B");
    let gb = CohortGroup::join(
        store(&format!("{tag}-b")),
        &room,
        material,
        add.welcome().expect("a Welcome"),
        16,
    )
    .await
    .expect("B joins from the Welcome");
    Pair {
        t,
        a,
        b,
        room,
        groups: [ga, gb],
        _tmp: tmp,
    }
}

async fn join(side: &Side, group: &CohortGroup, room: &str) -> Result<Call, CallError> {
    Call::join(
        room,
        &side.key.key_id,
        CallDeps {
            room_group: group.clone(),
            roster: Arc::new(Roster),
            transport: Arc::clone(&side.transport),
            lifecycle: Arc::clone(&side.lifecycle),
            registrar: Arc::new(UnwiredRegistrar) as Arc<dyn StreamDekRegistrar>,
            events: None,
            metrics: Some(side.metrics.clone()),
            record: None,
            signer: side.key.signer(),
            verifier: Arc::clone(&side.dir) as Arc<dyn StreamKeyVerifier>,
        },
        CallOptions::default(),
    )
    .await
}

fn dl(m: &EdgeMetrics, label: &str) -> u64 {
    m.direct_link().get(label).copied().unwrap_or(0)
}

fn body(who: &str, seq: u64) -> Vec<u8> {
    let mut b = format!("{who}-nat-{seq:04}-").into_bytes();
    b.resize(96, b'.');
    b
}

/// Publish `seqs` from `from` (retrying a congested leg), then read them back
/// at `rx`, byte-identical and in order.
async fn cross(
    from: &mut Call,
    who: &str,
    publisher: &str,
    seqs: std::ops::Range<u64>,
    rx: &mut mpsc::Receiver<ReceivedFrame>,
) {
    for seq in seqs.clone() {
        let mut delivered = false;
        for _ in 0..50 {
            let r = from
                .publish(Frame::opaque(body(who, seq)))
                .await
                .expect("publish");
            if r.delivered() == 1 {
                delivered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(delivered, "{who}'s frame {seq} reached its one leg");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut last = None;
    let mut got = Vec::new();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while got.len() < usize::try_from(seqs.end - seqs.start).unwrap() {
        let f = tokio::time::timeout_at(deadline, rx.recv())
            .await
            .unwrap_or_else(|_| panic!("{who}'s frames in time: got {}", got.len()))
            .expect("frames open");
        assert_eq!(f.publisher, publisher);
        if let Some(prev) = last {
            assert!(f.chunk_seq.0 > prev, "in order");
        }
        last = Some(f.chunk_seq.0);
        got.push(f.bytes);
    }
    let want: Vec<Vec<u8>> = seqs.map(|s| body(who, s)).collect();
    assert_eq!(got, want, "{who}'s frames arrive byte-identical");
}

/// **E4** — a room call between two members behind `T` runs over a punched
/// interface, through the host call API, and outlives `T`.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_room_call_behind_t_runs_over_a_punched_interface() {
    let mut p = pair("e4", true).await;
    let mut call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    let mut call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    let mut a_frames = call_a.frames().expect("A's frames");
    let mut b_frames = call_b.frames().expect("B's frames");

    // A's leg to B proposed on the identity link; both ends moved.
    let a_up = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match p.a.events.recv().await {
                Ok(e @ DirectPathEvent::Established { .. }) => return e,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("A's events closed"),
            }
        }
    })
    .await
    .expect("A's identity link moves onto a punched interface");
    assert!(
        matches!(&a_up, DirectPathEvent::Established { proposed: true, peer, .. }
            if peer.as_deref() == Some(p.b.key.key_id.as_str())),
        "A proposed, to B: {a_up:?}"
    );
    let b_up = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match p.b.events.recv().await {
                Ok(e @ DirectPathEvent::Established { .. }) => return e,
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("B's events closed"),
            }
        }
    })
    .await
    .expect("B moved too");
    assert!(
        matches!(&b_up, DirectPathEvent::Established { proposed: false, peer, .. }
            if peer.as_deref() == Some(p.a.key.key_id.as_str())),
        "B accepted, attributed to A: {b_up:?}"
    );
    assert_eq!(
        dl(&p.b.metrics, "direct_link_request_accepted"),
        1,
        "B's host was asked and said yes: A is in B's call"
    );

    // Every leg of the call comes up over it, both ways.
    for (call, who) in [(&call_a, "A"), (&call_b, "B")] {
        assert!(
            wait_until(Duration::from_secs(60), || async { call.legs().len() == 1 }).await,
            "{who}'s leg to the other member comes up"
        );
    }
    // CC 5.3.3.5 E1 — the legs ride sealed links: each end keyed what it
    // dialled and answered what it was dialled.
    for (side, who) in [(&p.a, "A"), (&p.b, "B")] {
        let seal = side.metrics.link_seal();
        assert!(
            seal.get("link_seal_initiated").copied().unwrap_or(0) >= 1
                && seal.get("link_seal_accepted").copied().unwrap_or(0) >= 1,
            "{who} keyed its leg and answered the other's: {seal:?}"
        );
    }
    // The A/V leg is born on the punched interface at the base MTU (Channel
    // 425 less the 25-byte seal), so the call's budget is that leg's.
    let budget = call_a.chunk_plaintext_budget().expect("A's budget");
    assert!(budget > 0 && budget <= 400, "base-MTU budget: {budget}");

    cross(&mut call_a, "A", &p.a.key.key_id, 0..10, &mut b_frames).await;
    cross(&mut call_b, "B", &p.b.key.key_id, 0..10, &mut a_frames).await;

    // T gone: the call never needed it.
    p.t.stop().await.expect("stop T");
    tokio::time::sleep(Duration::from_millis(500)).await;
    cross(&mut call_a, "A", &p.a.key.key_id, 10..15, &mut b_frames).await;
    cross(&mut call_b, "B", &p.b.key.key_id, 10..15, &mut a_frames).await;

    call_a.leave().await.expect("A leaves");
    call_b.leave().await.expect("B leaves");
}

/// **E4 fail-before** — the same call with no facilitator anywhere: no
/// proposal, so a derived address behind `T` answers no dial, no leg comes
/// up, and publishing has no budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_room_call_behind_t_without_a_facilitator_has_no_leg() {
    let p = pair("e4-none", false).await;
    let mut call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    let call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    assert!(
        !wait_until(Duration::from_secs(20), || async {
            !call_a.legs().is_empty() || !call_b.legs().is_empty()
        })
        .await,
        "no leg stands across T: A {:?}, B {:?}",
        call_a.legs(),
        call_b.legs()
    );
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 0);
    assert!(matches!(
        call_a.publish(Frame::opaque(body("A", 0))).await,
        Err(CallError::NoBudget)
    ));
}
