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
    transport_node_ingress(tcp_port, facilitator_port, false).await
}

async fn transport_node_ingress(
    tcp_port: u16,
    facilitator_port: u16,
    ingress: bool,
) -> ReticulumNode {
    transport_node_limited(tcp_port, facilitator_port, ingress, None).await
}

async fn transport_node_limited(
    tcp_port: u16,
    facilitator_port: u16,
    ingress: bool,
    announce_rate_target: Option<u32>,
) -> ReticulumNode {
    let storage = tempfile::tempdir().expect("tempdir");
    // Node-wide: the one setting that reaches the connections a listener spawns.
    let mut builder = ReticulumNodeBuilder::new();
    if announce_rate_target.is_some() {
        let mut config = leviculum_std::config::Config::default();
        config.reticulum.default_ar_target = announce_rate_target;
        builder = builder.config(config);
    }
    let mut node = builder
        .enable_transport(true)
        .add_interface_config(leviculum_std::config::InterfaceConfig {
            name: "T TCP server".to_string(),
            interface_type: "TCPServerInterface".to_string(),
            listen_ip: Some("127.0.0.1".to_string()),
            listen_port: Some(tcp_port),
            ingress_control: Some(ingress),
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
    side_every(key, dir, base, t_port, direct, Duration::from_secs(5)).await
}

async fn side_every(
    key: Ident,
    dir: &Arc<SqliteBackend>,
    base: &std::path::Path,
    t_port: u16,
    direct: DirectLinksConfig,
    announce_interval: Duration,
) -> Side {
    let mut transport = None;
    for _ in 0..16 {
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.announce_interval = announce_interval;
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
    // A loaded box can start B a minute after A: this holds it there on demand.
    tokio::time::sleep(Duration::from_secs(env_secs("NAT_B_DELAY", 0))).await;
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
    // Each asks for the other. This waited for the announces alone, which is
    // not a thing a node can wait for: A's start and B's can be 60 s apart on
    // a loaded box, and by then T's rate limit (grace 5, A announcing every
    // 5 s) has stopped relaying A for an hour. The node that joined late never
    // heard it. A path request is what T still answers.
    let known = wait_until(Duration::from_secs(60), || async {
        a.transport.seek_peer(&b.key.key_id).await && b.transport.seek_peer(&a.key.key_id).await
    })
    .await;
    assert!(known, "A and B reach each other through T");

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
            owners: Arc::clone(&side.dir) as Arc<dyn ciris_edge::transport::av_call::CallOwners>,
            transport: Arc::clone(&side.transport),
            lifecycle: Arc::clone(&side.lifecycle),
            registrar: Arc::new(UnwiredRegistrar) as Arc<dyn StreamDekRegistrar>,
            events: None,
            metrics: Some(side.metrics.clone()),
            record: None,
            signer: side.key.signer(),
            verifier: Arc::clone(&side.dir) as Arc<dyn StreamKeyVerifier>,
            load: None,
        },
        CallOptions::default(),
    )
    .await
}

fn dl(m: &EdgeMetrics, label: &str) -> u64 {
    m.direct_link().get(label).copied().unwrap_or(0)
}

fn av(m: &EdgeMetrics, label: &str) -> u64 {
    m.av_plane().get(label).copied().unwrap_or(0)
}

/// The link MDU leviculum gives a link at `mtu` (`compute_link_mdu`, after
/// Python's `Link.update_mdu`).
fn link_mdu_at(mtu: usize) -> usize {
    use leviculum_core::constants::{
        AES_BLOCK_SIZE, HEADER_MINSIZE, IFAC_MIN_SIZE, TOKEN_OVERHEAD,
    };
    ((mtu - IFAC_MIN_SIZE - HEADER_MINSIZE - TOKEN_OVERHEAD) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE - 1
}

/// leviculum#104 — `from`'s leg to `to` runs at the probed path MTU of the
/// punched loopback path (its 1400 step), and the call's budget is that leg's
/// media limit NOW: the datagram limit when the leg rides datagrams, else the
/// Channel's, less the chunk's wire overhead and source signature. Returns
/// the budget.
fn assert_budget_follows_the_leg(call: &Call, from: &Side, to: &Side, datagrams: bool) -> usize {
    use ciris_edge::transport::av_chunk_auth::CHUNK_TRAILER_LEN;
    use ciris_edge::transport::link_seal::SEAL_OVERHEAD;
    use ciris_edge::transport::realtime_av::AV_CHUNK_WIRE_OVERHEAD;
    let leg = call
        .leg_link_for_test(&to.key.key_id)
        .expect("the leg is up");
    let (channel, datagram) = from
        .transport
        .av_link_limits(&leg)
        .expect("leviculum holds the leg");
    let mdu = link_mdu_at(1400);
    assert_eq!(
        datagram + SEAL_OVERHEAD + 4,
        mdu,
        "the leg runs at the probed 1400-byte MTU (leviculum#104), not the base 500"
    );
    assert_eq!(
        channel + SEAL_OVERHEAD + leviculum_core::constants::CHANNEL_ENVELOPE_HEADER_SIZE,
        mdu
    );
    let budget = call.chunk_plaintext_budget().expect("a budget");
    let limit = if datagrams { datagram } else { channel };
    assert_eq!(
        budget,
        limit - AV_CHUNK_WIRE_OVERHEAD - CHUNK_TRAILER_LEN,
        "the budget follows the leg's {} limit",
        if datagrams { "datagram" } else { "Channel" }
    );
    budget
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
    // leviculum#102 — both ends run this build, so once each has heard the
    // other's CAPS its media to it rides unordered datagrams.
    for (call, other, who) in [(&call_a, &p.b, "A"), (&call_b, &p.a, "B")] {
        assert!(
            wait_until(Duration::from_secs(20), || async {
                call.leg_uses_datagrams(&other.key.key_id) == Some(true)
            })
            .await,
            "{who}'s leg rides datagrams once the other's CAPS arrive"
        );
    }
    // CC 5.3.3.5 E1 — the legs ride sealed links: each end keyed what it
    // dialled and answered what it was dialled. Read after the CAPS: a leg is
    // up once its DIALLER has keyed it, while the responder keys off the event
    // path (CIRISEdge#947) and only then speaks, so the other's CAPS on a leg
    // is what proves the responder answered it. (Read right after the legs
    // came up, the responder's count raced its keying: 1 run in 6 once the
    // handshake fit one 1400-MTU message, leviculum#104.)
    for (side, who) in [(&p.a, "A"), (&p.b, "B")] {
        let seal = side.metrics.link_seal();
        assert!(
            seal.get("link_seal_initiated").copied().unwrap_or(0) >= 1
                && seal.get("link_seal_accepted").copied().unwrap_or(0) >= 1,
            "{who} keyed its leg and answered the other's: {seal:?}"
        );
    }
    // leviculum#104 — the leg is born on the punched interface, which probed
    // the path's MTU (loopback carries the 1400 step), not the base 500, and
    // the call's budget follows that leg's datagram limit.
    let budget = assert_budget_follows_the_leg(&call_a, &p.a, &p.b, true);
    assert!(budget > 400, "past the base-MTU 400: {budget}");

    let sent = av(&p.a.metrics, "av_sent_datagram");
    cross(&mut call_a, "A", &p.a.key.key_id, 0..10, &mut b_frames).await;
    cross(&mut call_b, "B", &p.b.key.key_id, 0..10, &mut a_frames).await;
    assert_eq!(
        av(&p.a.metrics, "av_sent_datagram") - sent,
        10,
        "each of A's frames left as one datagram: {:?}",
        p.a.metrics.av_plane()
    );
    // A full-budget frame rides one datagram too.
    let at = call_a
        .publish(Frame::opaque(vec![0x5a; budget]))
        .await
        .expect("the budget fits");
    assert_eq!(at.delivered(), 1, "a full-budget frame: {:?}", at.legs);
    let f = tokio::time::timeout(Duration::from_secs(20), b_frames.recv())
        .await
        .expect("the full frame in time")
        .expect("frames open");
    assert_eq!(f.bytes.len(), budget, "a {budget}-byte frame arrives whole");

    // The host's lever off: legs that come up from now on stay on the
    // Channel, but this leg keeps its datagrams (one-way per leg).
    p.a.transport.set_av_datagrams_enabled(false);
    assert_eq!(
        p.a.metrics.snapshot().av_datagrams_enabled,
        0,
        "the gauge reads it"
    );
    assert_eq!(
        call_a.leg_uses_datagrams(&p.b.key.key_id),
        Some(true),
        "an existing leg keeps datagrams"
    );

    // T gone: the call never needed it.
    p.t.stop().await.expect("stop T");
    tokio::time::sleep(Duration::from_millis(500)).await;
    let sent = av(&p.a.metrics, "av_sent_datagram");
    cross(&mut call_a, "A", &p.a.key.key_id, 10..15, &mut b_frames).await;
    assert_eq!(
        av(&p.a.metrics, "av_sent_datagram") - sent,
        5,
        "the existing leg still sends datagrams with the lever off"
    );
    cross(&mut call_b, "B", &p.b.key.key_id, 10..15, &mut a_frames).await;

    call_a.leave().await.expect("A leaves");
    call_b.leave().await.expect("B leaves");
}

/// Both members' legs are up and keyed, and each has heard the other's
/// C3 `CAPS` (so each leg's carrier is settled).
async fn legs_settled(p: &Pair, call_a: &Call, call_b: &Call) {
    for (call, who) in [(call_a, "A"), (call_b, "B")] {
        assert!(
            wait_until(Duration::from_secs(60), || async { call.legs().len() == 1 }).await,
            "{who}'s leg to the other member comes up"
        );
    }
    for (call, other, who) in [(call_a, &p.b, "A"), (call_b, &p.a, "B")] {
        assert!(
            wait_until(Duration::from_secs(20), || async {
                call.alm_c3_peers().contains(&other.key.key_id)
            })
            .await,
            "{who} heard the other's CAPS"
        );
    }
}

/// leviculum#102 **fallback** — B runs a build that predates datagrams (its
/// CAPS leave out `CAP_LINK_DATAGRAMS`). A's media to B stays on the Channel,
/// every frame counted as a fallback and none sent as a datagram, and the
/// budget follows the Channel; B's media to A, whose CAPS carry the bit, rides
/// datagrams. Frames cross both ways.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_member_on_an_older_build_gets_its_media_on_the_channel() {
    use ciris_edge::transport::realtime_av_alm::controller::wire::CAP_LINK_DATAGRAMS;
    let p = pair("e4-old", true).await;
    p.b.transport
        .set_av_caps_withheld_for_test(CAP_LINK_DATAGRAMS);
    let mut call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    let mut call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    let mut a_frames = call_a.frames().expect("A's frames");
    let mut b_frames = call_b.frames().expect("B's frames");
    legs_settled(&p, &call_a, &call_b).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            call_b.leg_uses_datagrams(&p.a.key.key_id) == Some(true)
        })
        .await,
        "B's leg to A, whose CAPS carry the bit, rides datagrams"
    );
    assert_eq!(
        call_a.leg_uses_datagrams(&p.b.key.key_id),
        Some(false),
        "A's leg to B, whose CAPS leave the bit out, does not"
    );
    assert_budget_follows_the_leg(&call_a, &p.a, &p.b, false);
    assert_budget_follows_the_leg(&call_b, &p.b, &p.a, true);

    let (a_dg, a_fb) = (
        av(&p.a.metrics, "av_sent_datagram"),
        av(&p.a.metrics, "av_sent_datagram_fallback"),
    );
    let (b_dg, b_fb) = (
        av(&p.b.metrics, "av_sent_datagram"),
        av(&p.b.metrics, "av_sent_datagram_fallback"),
    );
    let a_timed = av(&p.a.metrics, "av_sent_timed");
    cross(&mut call_a, "A", &p.a.key.key_id, 0..10, &mut b_frames).await;
    cross(&mut call_b, "B", &p.b.key.key_id, 0..10, &mut a_frames).await;
    assert_eq!(
        (
            av(&p.a.metrics, "av_sent_datagram") - a_dg,
            av(&p.a.metrics, "av_sent_datagram_fallback") - a_fb
        ),
        (0, 10),
        "A sent B no datagram and counted each Channel frame as a fallback: {:?}",
        p.a.metrics.av_plane()
    );
    assert_eq!(
        av(&p.a.metrics, "av_sent_timed") - a_timed,
        10,
        "the fallback is the timed Channel frame (B's CAPS still say it takes them)"
    );
    assert_eq!(
        (
            av(&p.b.metrics, "av_sent_datagram") - b_dg,
            av(&p.b.metrics, "av_sent_datagram_fallback") - b_fb
        ),
        (10, 0),
        "B's frames to A rode datagrams: {:?}",
        p.b.metrics.av_plane()
    );
    call_a.leave().await.expect("A leaves");
    call_b.leave().await.expect("B leaves");
}

/// leviculum#102 **the host's lever** — B's host turned datagrams off before
/// its call: B's CAPS leave the bit out (so A's media to B stays on the
/// Channel) and B sends none on its own new leg either, although A's CAPS
/// carry the bit. The gauge reads 0 on B and 1 on A.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn the_datagram_lever_off_keeps_new_legs_on_the_channel() {
    let p = pair("e4-lever", true).await;
    assert_eq!(p.b.metrics.snapshot().av_datagrams_enabled, 1, "default on");
    p.b.transport.set_av_datagrams_enabled(false);
    assert_eq!(p.b.metrics.snapshot().av_datagrams_enabled, 0);
    assert_eq!(p.a.metrics.snapshot().av_datagrams_enabled, 1);
    let mut call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    let mut call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    let mut a_frames = call_a.frames().expect("A's frames");
    let mut b_frames = call_b.frames().expect("B's frames");
    legs_settled(&p, &call_a, &call_b).await;
    assert_eq!(call_a.leg_uses_datagrams(&p.b.key.key_id), Some(false));
    assert_eq!(call_b.leg_uses_datagrams(&p.a.key.key_id), Some(false));
    let before = [&p.a, &p.b].map(|s| {
        (
            av(&s.metrics, "av_sent_datagram"),
            av(&s.metrics, "av_sent_datagram_fallback"),
        )
    });
    cross(&mut call_a, "A", &p.a.key.key_id, 0..10, &mut b_frames).await;
    cross(&mut call_b, "B", &p.b.key.key_id, 0..10, &mut a_frames).await;
    for (side, (dg, fb), who) in [(&p.a, before[0], "A"), (&p.b, before[1], "B")] {
        assert_eq!(
            (
                av(&side.metrics, "av_sent_datagram") - dg,
                av(&side.metrics, "av_sent_datagram_fallback") - fb
            ),
            (0, 10),
            "{who}'s media rode the Channel: {:?}",
            side.metrics.av_plane()
        );
    }
    call_a.leave().await.expect("A leaves");
    call_b.leave().await.expect("B leaves");
}

/// leviculum#102 — a datagram the sender numbered and this node never saw (a
/// shed, or a lossy path) is never sent again, and the hop resyncs past it.
/// B loses more of A's datagrams than the hop counter's resync slack covers,
/// so only the sequence gap reported to the hop lets B open the next frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_lost_datagram_is_never_resent_and_the_hop_resyncs_past_it() {
    use ciris_edge::transport::realtime_av_dispatcher::HOP_COUNTER_RESYNC_SLACK;
    let lost = HOP_COUNTER_RESYNC_SLACK + 4;
    let p = pair("e4-loss", true).await;
    let mut call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    let mut call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    let mut b_frames = call_b.frames().expect("B's frames");
    legs_settled(&p, &call_a, &call_b).await;
    assert!(
        wait_until(Duration::from_secs(20), || async {
            call_a.leg_uses_datagrams(&p.b.key.key_id) == Some(true)
        })
        .await,
        "A's leg to B rides datagrams"
    );
    // The hop has a newest datagram to measure the gap from.
    cross(&mut call_a, "A", &p.a.key.key_id, 0..5, &mut b_frames).await;

    let sent = av(&p.a.metrics, "av_sent_datagram");
    p.b.transport.lose_next_datagrams_for_test(lost);
    let total = lost + 10;
    for seq in 5..5 + total {
        let mut delivered = false;
        for _ in 0..50 {
            let r = call_a
                .publish(Frame::opaque(body("A", seq)))
                .await
                .expect("publish");
            if r.delivered() == 1 {
                delivered = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(delivered, "A's frame {seq} left on its one leg");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let mut got = Vec::new();
    while got.len() < 10 {
        let f = tokio::time::timeout_at(deadline, b_frames.recv())
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "the frames past the gap open at B: got {}; B {:?}",
                    got.len(),
                    p.b.metrics.av_plane()
                )
            })
            .expect("frames open");
        got.push(f.bytes);
    }
    let want: Vec<Vec<u8>> = (5 + lost..5 + total).map(|s| body("A", s)).collect();
    assert_eq!(
        got, want,
        "the frames past the gap, byte-identical and in order"
    );
    assert_eq!(
        av(&p.a.metrics, "av_sent_datagram") - sent,
        total,
        "A sent each frame once and never again"
    );
    assert_eq!(
        av(&p.b.metrics, "av_inbound_datagram_gap"),
        lost,
        "B reported the gap to the hop: {:?}",
        p.b.metrics.av_plane()
    );
    let leg = call_a.leg_link_for_test(&p.b.key.key_id).expect("A's leg");
    let at_b =
        p.b.transport
            .av_link_datagram_stats(&leg)
            .expect("B holds A's leg");
    assert_eq!(at_b.replayed, 0, "nothing was sent twice: {at_b:?}");
    // The lost frames never come back.
    assert!(
        tokio::time::timeout(Duration::from_secs(2), b_frames.recv())
            .await
            .is_err(),
        "no lost frame arrives later"
    );
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

/// **E4, the other order** — A's dial proposes to B before B's call is
/// installed, so B is asked while it shares nothing with A. B's host holds the
/// request for that standing instead of refusing it; B joins, and the link
/// moves. Refused at once, the pair rode the relay through a retry backoff of
/// 45 s or more: E4 on CI darwin, the v44.0.0 and v44.1.0 tag runs, where A's
/// proposal reached B 20 ms before B's call was installed.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_proposal_that_reaches_a_member_before_its_call_is_held_for_it() {
    let mut p = pair("e4-order", true).await;
    let call_a = join(&p.a, &p.groups[0], &p.room).await.expect("A joins");
    assert!(
        wait_until(Duration::from_secs(20), || async {
            dl(&p.b.metrics, "direct_link_request_held") == 1
        })
        .await,
        "A's proposal reaches B before B's call, and is held: {:?}",
        p.b.metrics.direct_link()
    );
    let call_b = join(&p.b, &p.groups[1], &p.room).await.expect("B joins");
    let a_up = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            match p.a.events.recv().await {
                Ok(e @ (DirectPathEvent::Established { .. } | DirectPathEvent::Failed { .. })) => {
                    return e
                }
                Ok(_) | Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(broadcast::error::RecvError::Closed) => panic!("A's events closed"),
            }
        }
    })
    .await
    .expect("A's proposal has an outcome");
    assert!(
        matches!(&a_up, DirectPathEvent::Established { proposed: true, peer, .. }
            if peer.as_deref() == Some(p.b.key.key_id.as_str())),
        "the held request was accepted once B joined: {a_up:?}"
    );
    assert_eq!(dl(&p.b.metrics, "direct_link_request_accepted"), 1);
    assert_eq!(dl(&p.b.metrics, "direct_link_request_refused"), 0);
    assert_eq!(dl(&p.a.metrics, "direct_link_failed_rejected"), 0);
    drop((call_a, call_b));
}

/// `T` with `A` on it long enough that the relay's rate limit blocks A's
/// re-announces, then `B` joining: A's announce is not coming. A's 1 s interval
/// reaches the limiter's grace (5) within seconds; on the 300 s default it
/// takes half an hour and then lasts about an hour.
struct LateJoin {
    t: ReticulumNode,
    a: Side,
    b: Side,
    a_dir: Arc<SqliteBackend>,
    b_dir: Arc<SqliteBackend>,
    _tmp: tempfile::TempDir,
}

const LIMITER_ARMED: Duration = Duration::from_secs(12);

async fn late_join(tag: &str) -> LateJoin {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (t_port, f_port) = (free_port(), free_udp_port());
    let t = transport_node(t_port, f_port).await;
    let key_a = Ident::new(&format!("node-a-{tag}"), 0x3a).await;
    let key_b = Ident::new(&format!("node-b-{tag}"), 0x3b).await;
    let records = vec![key_a.record().await, key_b.record().await];
    let (a_dir, b_dir) = (
        directory_with(records.clone()).await,
        directory_with(records).await,
    );
    let every = Duration::from_secs(1);
    let direct = DirectLinksConfig::default;
    let a = side_every(
        key_a,
        &a_dir,
        &tmp.path().join("a"),
        t_port,
        direct(),
        every,
    )
    .await;
    tokio::time::sleep(LIMITER_ARMED).await;
    assert!(
        t.transport_stats().drops_announce_rate_limited() > 0,
        "the premise: the relay is blocking A's re-announces: {:?}",
        t.transport_stats()
    );
    let b = side_every(
        key_b,
        &b_dir,
        &tmp.path().join("b"),
        t_port,
        direct(),
        every,
    )
    .await;
    LateJoin {
        t,
        a,
        b,
        a_dir,
        b_dir,
        _tmp: tmp,
    }
}

/// Copy `from`'s signed route rows into `to`, as replication does.
async fn share_routes(from: &Side, from_dir: &Arc<SqliteBackend>, to: &Arc<SqliteBackend>) {
    let routes = from_dir
        .list_signed_transport_destinations_for(&from.key.key_id)
        .await
        .expect("list routes");
    assert!(!routes.is_empty(), "the peer published its route");
    for r in &routes {
        FederationDirectory::put_signed_transport_destination(&**to, r)
            .await
            .expect("seed the route");
    }
}

/// **The product bug behind the NAT flake.** A transport node relays a
/// destination's announce until the rate limit's grace runs out, then not for
/// up to an hour, so a node that joins later cannot wait for A's announce. It
/// holds A's signed route, it wants A, and the relay still holds A's path: the
/// send asks for it. Before the fix the send had no way to address A at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_late_joiner_reaches_its_peer_on_its_first_send() {
    let j = late_join("late-send").await;
    share_routes(&j.a, &j.a_dir, &j.b_dir).await;
    let id_a = j.a.key.key_id.clone();
    assert!(!j.b.transport.knows_peer(&id_a).await, "the premise");
    let start = std::time::Instant::now();
    let sent = j.b.transport.send(&id_a, b"{\"late\":true}").await;
    eprintln!(
        "[LATE] first send: {sent:?} in {:?}; T {:?}",
        start.elapsed(),
        j.t.transport_stats()
    );
    assert!(sent.is_ok(), "{sent:?}");
    assert!(
        j.b.transport.knows_peer(&id_a).await,
        "A's announce came back"
    );
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// The same for a peer this node can already name but has no path to (a
/// primed peer, or a directory-resolved one): the dial asks before it
/// broadcasts a link request only a neighbour could answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_known_peer_with_no_path_is_asked_for_before_the_dial() {
    let j = late_join("late-known").await;
    share_routes(&j.a, &j.a_dir, &j.b_dir).await;
    let id_a = j.a.key.key_id.clone();
    j.b.transport
        .prime_peer(
            &id_a,
            j.a.transport.local_named_dest_hash(),
            j.a.transport.local_transport_pubkey(),
        )
        .await
        .expect("prime");
    let start = std::time::Instant::now();
    let sent = j.b.transport.send(&id_a, b"{\"known\":true}").await;
    eprintln!("[LATE] known peer: {sent:?} in {:?}", start.elapsed());
    assert!(sent.is_ok(), "{sent:?}");
    assert!(
        start.elapsed() < Duration::from_secs(10),
        "{:?}",
        start.elapsed()
    );
}

/// The bound on the ask: a peer that is gone costs one wait, and the sends
/// behind it fail as fast as they always did, so nothing here turns a retry
/// loop into a broadcast loop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_peer_costs_one_bounded_ask() {
    let j = late_join("late-dead").await;
    share_routes(&j.a, &j.a_dir, &j.b_dir).await;
    let id_a = j.a.key.key_id.clone();
    j.t.stop_shared().await.expect("T stops");
    let send = |n: u8| {
        let (t, id) = (std::sync::Arc::clone(&j.b.transport), id_a.clone());
        async move {
            let at = std::time::Instant::now();
            let r = t.send(&id, &[b'{', n, b'}']).await;
            (r.is_ok(), at.elapsed())
        }
    };
    let (ok, first) = send(b'1').await;
    let (_, second) = send(b'2').await;
    eprintln!("[LATE] dead peer: first {first:?} ok={ok}, second {second:?}");
    assert!(!ok, "the relay is gone: nothing can answer");
    assert!(first < Duration::from_secs(5), "bounded: {first:?}");
    assert!(
        second < Duration::from_secs(1),
        "no second wait: {second:?}"
    );
}

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// Measurement, run by hand: how long a node that joins after its peer's
/// announce takes to learn that peer through `T`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: LATE_GAP, LATE_BUDGET, LATE_INGRESS, LATE_INTERVAL"]
async fn late_joiner_measure() {
    let (gap, budget, interval) = (
        env_secs("LATE_GAP", 8),
        env_secs("LATE_BUDGET", 60),
        env_secs("LATE_INTERVAL", 5),
    );
    let ingress = env_secs("LATE_INGRESS", 0) == 1;
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (t_port, f_port) = (free_port(), free_udp_port());
    let target = u32::try_from(env_secs("LATE_TARGET", 0))
        .ok()
        .filter(|t| *t > 0);
    let t = transport_node_limited(t_port, f_port, ingress, target).await;
    let key_a = Ident::new("node-a-late", 0x3a).await;
    let key_b = Ident::new("node-b-late", 0x3b).await;
    let (id_a, id_b) = (key_a.key_id.clone(), key_b.key_id.clone());
    let records = vec![key_a.record().await, key_b.record().await];
    let (a_dir, b_dir) = (
        directory_with(records.clone()).await,
        directory_with(records).await,
    );
    let every = Duration::from_secs(interval);
    let direct = DirectLinksConfig::default;
    let a = side_every(
        key_a,
        &a_dir,
        &tmp.path().join("a"),
        t_port,
        direct(),
        every,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(gap)).await;
    let before = t.transport_stats();
    let b = side_every(
        key_b,
        &b_dir,
        &tmp.path().join("b"),
        t_port,
        direct(),
        every,
    )
    .await;
    let start = std::time::Instant::now();
    let (mut a_knows, mut b_knows) = (None, None);
    while start.elapsed() < Duration::from_secs(budget) {
        if a_knows.is_none() && a.transport.knows_peer(&id_b).await {
            a_knows = Some(start.elapsed());
        }
        if b_knows.is_none() && b.transport.knows_peer(&id_a).await {
            b_knows = Some(start.elapsed());
        }
        if a_knows.is_some() && b_knows.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    eprintln!(
        "[LATE] gap={gap}s interval={interval}s ingress={ingress} budget={budget}s \
         a_knows_b={a_knows:?} b_knows_a={b_knows:?}"
    );
    eprintln!("[LATE] T before B: {before:?}");
    eprintln!("[LATE] T after:    {:?}", t.transport_stats());
}

/// Measurement, run by hand: a real announce burst on a fresh `T` interface.
/// `X` connects and announces `BURST_N` destinations at once; `Y`, already on
/// `T`, reports when each reaches it. Held, dropped, and does it come back?
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "a measurement: BURST_N, BURST_BUDGET, BURST_INGRESS, BURST_ASK"]
#[allow(clippy::many_single_char_names)] // t, x, y: the nodes as the test names them
async fn fresh_interface_burst_measure() {
    use leviculum_core::Identity;
    use leviculum_core::{Destination, DestinationType, Direction};
    let (n, budget) = (env_secs("BURST_N", 12), env_secs("BURST_BUDGET", 150));
    let ingress = env_secs("BURST_INGRESS", 1) == 1;
    init_tracing();
    let (t_port, f_port) = (free_port(), free_udp_port());
    let t = transport_node_ingress(t_port, f_port, ingress).await;
    let addr: std::net::SocketAddr = format!("127.0.0.1:{t_port}").parse().unwrap();
    let client = || async {
        let storage = tempfile::tempdir().expect("tempdir");
        let mut node = ReticulumNodeBuilder::new()
            .add_tcp_client(addr)
            .storage_path(storage.path().to_path_buf())
            .build()
            .await
            .expect("build a client");
        std::mem::forget(storage);
        node.start().await.expect("start a client");
        let mut rx = node.take_event_receiver().expect("events");
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        node
    };
    let y = client().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let x = client().await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut dests = Vec::new();
    for i in 0..n {
        let identity = Identity::generate(&mut rand::rngs::OsRng);
        let aspect = format!("burst{i}");
        let mut d = Destination::new(
            Some(identity),
            Direction::In,
            DestinationType::Single,
            "late",
            &[aspect.as_str()],
        )
        .expect("destination");
        d.set_accepts_links(true);
        dests.push(*d.hash());
        x.register_destination(d);
    }
    let start = std::time::Instant::now();
    for d in &dests {
        x.announce_destination(d, Some(b"burst"))
            .await
            .expect("announce");
    }
    // `Y` asks for the burst's last destination while T is holding it.
    let asked = *dests.last().expect("a burst");
    let ask = env_secs("BURST_ASK", 0) == 1;
    let mut asked_yet = false;
    let mut answered = None;
    let mut last = usize::MAX;
    while start.elapsed() < Duration::from_secs(budget) {
        if ask && !asked_yet && start.elapsed() > Duration::from_secs(1) {
            asked_yet = true;
            y.request_path(&asked).await.expect("ask");
            eprintln!(
                "[BURST] asked at {:?}, T holds it: {}",
                start.elapsed(),
                !t.has_path(&asked)
            );
        }
        if answered.is_none() && y.has_path(&asked) {
            answered = Some(start.elapsed());
            eprintln!("[BURST] the asked destination reached Y at {answered:?}");
        }
        let (at_t, at_y) = (
            dests.iter().filter(|d| t.has_path(d)).count(),
            dests.iter().filter(|d| y.has_path(d)).count(),
        );
        if at_t + at_y * 1_000 != last {
            last = at_t + at_y * 1_000;
            eprintln!(
                "[BURST] t={:?} n={n} ingress={ingress} at_T={at_t} at_Y={at_y} ingress_drops={}",
                start.elapsed(),
                t.transport_stats().drops_ingress_burst_announce()
            );
        }
        if at_y as u64 == n {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    eprintln!(
        "[BURST] end {:?}: {:?}",
        start.elapsed(),
        t.transport_stats()
    );
}
