//! CIRISEdge#805 item 8 — two call members behind NAT reach each other over a
//! punched interface (leviculum v0.30 direct links, leviculum#70).
//!
//! The topology is the field's: a transport node `T` (a bare leviculum node,
//! the canonical's role: transport on, a facilitator on a UDP port) and two
//! edge nodes `A` and `B` that are TCP clients of `T` and of nothing else. Each
//! holds the other's hybrid-signed route and learns the other's announce
//! through `T`, so their IDENTITY-plane link is pathed through `T`. A call's
//! A/V leg dials a DERIVED address, which is announce-suppressed (CC 5.4) and
//! answers only a one-hop neighbour; across `T` it cannot establish at all.
//!
//! - **W4** (`the_default_never_proposes_and_a_member_behind_t_is_unreachable`):
//!   the inert default proposes nothing, and A's A/V dial to B fails with
//!   `NoRouteToPeer`. This is what item 8 fixes, and the fail-before of W1.
//! - **W1 + W5** (`a_member_behind_nat_is_reached_over_a_punched_interface`):
//!   A configured with `T`'s facilitator, B on the DEFAULT accept (room peers,
//!   asked per request): B shares the call with A, so B accepts. A's A/V
//!   dial proposes on the identity link first. Both ends see the upgrade, the
//!   dial establishes over the punched interface, frames cross, and they still
//!   cross with `T` stopped. The identity link's Channel limit drops to
//!   1400-MTU size on the move (leviculum lowers the MTU and never raises it);
//!   the event carries both limits, which item 5's `BudgetChanged` reads. The
//!   A/V leg itself is born on the punched interface at the base MTU 500
//!   (Channel 425).
//! - **W3** (`a_refused_upgrade_leaves_the_dial_as_it_was`): B with accepting
//!   turned `Off` (the operator override). The proposal fails `Rejected`, the
//!   dial behaves exactly as with no proposal, and a second dial does NOT
//!   propose again on the refused link.
//! - **W6** (`a_peer_outside_our_rooms_is_refused_and_learns_nothing`): B on the
//!   default accept, but B never joined the call, so A shares no room with B.
//!   B's host refuses; A's proposal ends `Rejected`; B probed nothing, so A
//!   learned nothing about B's address.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test direct_links_805`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::Arc;
use std::time::Duration;

use ciris_crypto::{ml_kem, x25519, MlDsa65Signer};
use ciris_edge::av_addressing;
use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::welcome_wrap::FederationDirectoryEntry;
use ciris_edge::scope_addressing::{MemberAddress, ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::transport::av_leg_choice::{Leg, LegAction};
use ciris_edge::transport::av_sink::AvArrival;
use ciris_edge::transport::av_spine::AvSpine;
use ciris_edge::transport::direct_path::{
    DirectAccept, DirectLinksConfig, DirectPathEvent, DirectPathState,
};
use ciris_edge::transport::federation_session::{OwnKexKeys, PeerKexPubkeys};
use ciris_edge::transport::realtime_av::{
    seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, InnerSealed, StreamId, CODEC_OPAQUE,
};
use ciris_edge::transport::realtime_av_dispatcher::{
    AvDispatcher, AvDispatcherConfig, AvInboundLink, AvLinkReceiver as _, AvLinkSender as _,
    AvRole, AvSubscriberLink,
};
use ciris_edge::transport::realtime_av_mls::{mint_joiner_key_material, Member};
use ciris_edge::transport::realtime_av_runtime::{AvPublisher, AvRelay, AvSubscriber, LegStreams};
use ciris_edge::transport::realtime_av_session::AvSession;
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport as _, TransportError};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::{CohortScope, EdgeMetrics};
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
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

fn auth(signer: Arc<LocalSigner>, dir: &Arc<SqliteBackend>) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer),
        rooting: Some(Arc::clone(dir) as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        blackhole_rules: Some(Arc::clone(dir) as Arc<dyn ciris_persist::federation::BlackholeRules>),
        ..ReticulumAuth::default()
    }
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

/// `T`: a bare leviculum transport node with a TCP server and a facilitator,
/// the role a canonical plays. Its events are drained so its queue never
/// backs up.
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

/// One edge node: a TCP client of `T` only, its scope table and lifecycle
/// installed, its listener running (it drives the event loop).
struct Side {
    key: Ident,
    /// The port this node's TCP server listens on.
    port: u16,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    table: Arc<ScopeAddressTable>,
    lifecycle: Arc<ScopeLifecycle>,
    events: broadcast::Receiver<DirectPathEvent>,
    /// This node's own directory.
    dir: Arc<SqliteBackend>,
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
    side_cfg(key, dir, base, move |c| {
        let mut c = c.with_direct_links(direct.clone());
        c.bootstrap_peers = vec![format!("127.0.0.1:{t_port}").parse().unwrap()];
        c
    })
    .await
}

/// [`side`], with the config shaped by `shape` (listen address, announce
/// cadence and identity path are set first).
async fn side_cfg(
    key: Ident,
    dir: &Arc<SqliteBackend>,
    base: &std::path::Path,
    shape: impl Fn(ReticulumTransportConfig) -> ReticulumTransportConfig,
) -> Side {
    side_cfg_auth(key, dir, base, shape, |a| a).await
}

/// [`side_cfg`], with the transport's auth shaped by `shape_auth` too.
async fn side_cfg_auth(
    key: Ident,
    dir: &Arc<SqliteBackend>,
    base: &std::path::Path,
    shape: impl Fn(ReticulumTransportConfig) -> ReticulumTransportConfig,
    shape_auth: impl Fn(ReticulumAuth) -> ReticulumAuth,
) -> Side {
    let mut transport = None;
    let mut port = 0;
    for _ in 0..16 {
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
        port = free_port();
        c.listen_addr = format!("127.0.0.1:{port}").parse().unwrap();
        c.announce_interval = Duration::from_secs(5);
        let c = shape(c);
        match ReticulumTransport::new(c, shape_auth(auth(key.signer(), dir))).await {
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
        port,
        transport,
        metrics,
        table,
        lifecycle,
        events,
        dir: Arc::clone(dir),
        _edge: edge,
        _tasks: tasks,
    }
}

struct Trio {
    t: ReticulumNode,
    a: Side,
    b: Side,
    facilitator: String,
    _tmp: tempfile::TempDir,
}

/// `T`, then `A` and `B` as its clients, each holding the other's
/// hybrid-signed route, each having learned the other's announce through `T`.
async fn trio(tag: &str, a_direct: DirectLinksConfig, b_direct: DirectLinksConfig) -> Trio {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let t_port = free_port();
    let f_port = free_udp_port();
    let t = transport_node(t_port, f_port).await;
    let facilitator = format!("127.0.0.1:{f_port}");
    let fill = |c: DirectLinksConfig| DirectLinksConfig {
        facilitator: c.facilitator.map(|_| facilitator.clone()),
        ..c
    };

    let key_a = Ident::new(&format!("node-a-dl-{tag}"), 0x2a).await;
    let key_b = Ident::new(&format!("node-b-dl-{tag}"), 0x2b).await;
    let records = vec![key_a.record().await, key_b.record().await];
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;
    let a = side(key_a, &a_dir, &tmp.path().join("a"), t_port, fill(a_direct)).await;
    let b = side(key_b, &b_dir, &tmp.path().join("b"), t_port, fill(b_direct)).await;

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
    Trio {
        t,
        a,
        b,
        facilitator,
        _tmp: tmp,
    }
}

const ROOM: &str = "room-805-direct";

fn scope() -> CohortScope {
    CohortScope::Cohort {
        cohort_id: ROOM.to_owned(),
    }
}

#[allow(clippy::similar_names)]
fn fresh_joiner_xwing() -> (PeerKexPubkeys, OwnKexKeys) {
    let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
    let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().expect("ml-kem keypair");
    (
        PeerKexPubkeys {
            x25519_pub: x_pk,
            mlkem768_pub: mlkem_pk.clone(),
        },
        OwnKexKeys {
            x25519_priv: x_sk,
            mlkem768_priv: Some(mlkem_sk),
            mlkem768_pub: Some(mlkem_pk),
        },
    )
}

/// A real MLS call between A and B (as `av_spine_live_node_805`), each side
/// installing the call's derived addresses through its own lifecycle. Returns
/// the spine (holding A's addresses) and B's address as A derives it.
async fn open_call(p: &Trio) -> (AvSpine, MemberAddress) {
    open_call_with(p, true).await
}

/// [`open_call`], with B installing the call (`b_joins`) or not: a B that
/// never installs it shares no room with A.
async fn open_call_with(p: &Trio, b_joins: bool) -> (AvSpine, MemberAddress) {
    let (spine, b_addr, b_snapshot) = open_call_deferring_b(p).await;
    if b_joins {
        let _ =
            p.b.lifecycle
                .install(&scope(), &b_snapshot)
                .expect("B installs the call");
    }
    (spine, b_addr)
}

/// [`open_call_with`], with B's install left to the caller: the room exists on
/// A, and B joins it whenever it installs the returned snapshot.
async fn open_call_deferring_b(
    p: &Trio,
) -> (
    AvSpine,
    MemberAddress,
    ciris_edge::scope_lifecycle::ScopeGroupSnapshot,
) {
    let stream = StreamId(sha2::Sha256::digest(b"av-stream-805-direct").into());
    let (mut session, _dek0) = AvSession::create(
        stream,
        &p.a.key.key_id,
        vec![Member {
            key_id: "seed-805-direct".to_owned(),
            kex_pubkeys: PeerKexPubkeys {
                x25519_pub: [1u8; 32],
                mlkem768_pub: vec![0xAB; 1184],
            },
        }],
    )
    .expect("create the call");
    let (joiner_material, joiner_kp) =
        mint_joiner_key_material(&p.b.key.key_id).expect("mint joiner key material");
    let inviter = MlDsa65Signer::new().expect("inviter signer");
    let inviter_pk = ciris_crypto::PqcSigner::public_key(&inviter).expect("inviter pk");
    let (joiner_kex_pub, joiner_kex_secret) = fresh_joiner_xwing();
    let artifacts = session
        .admit_published_joiner(
            &p.b.key.key_id,
            joiner_kp,
            &joiner_kex_pub,
            &inviter,
            "inviter-805",
        )
        .expect("admit B");
    let pub_dek = EpochDek::from_bytes(*artifacts.new_dek.as_bytes());
    let mut sub_session = AvSession::new_joiner(stream, joiner_material);
    sub_session
        .process_welcome(
            &artifacts.welcome_bytes[0],
            &joiner_kex_secret,
            move |id: &str| {
                (id == "inviter-805").then(|| FederationDirectoryEntry {
                    pk_id: id.to_owned(),
                    ml_dsa_pk: inviter_pk.clone(),
                    x_wing_pk: None,
                })
            },
        )
        .expect("B processes the Welcome");
    let publisher = AvPublisher::from_session(stream, session, pub_dek, vec![]).expect("publisher");
    let spine =
        AvSpine::open(scope(), Arc::clone(&p.a.lifecycle), publisher, None).expect("open the call");
    let b_snapshot = av_addressing::snapshot(&sub_session).expect("B's snapshot");
    let group = av_addressing::stream_group_id(stream);
    let b_addr =
        p.a.table
            .send_address(&scope(), &group, &p.b.key.key_id)
            .expect("A derives B's call address");
    (spine, b_addr, b_snapshot)
}

fn dl(m: &EdgeMetrics, label: &str) -> u64 {
    m.direct_link().get(label).copied().unwrap_or(0)
}

/// The next direct-path event on `rx` matching `pick`, within `budget`.
async fn next_event(
    rx: &mut broadcast::Receiver<DirectPathEvent>,
    budget: Duration,
    mut pick: impl FnMut(&DirectPathEvent) -> bool,
) -> Option<DirectPathEvent> {
    let deadline = tokio::time::Instant::now() + budget;
    loop {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Ok(ev)) if pick(&ev) => return Some(ev),
            Ok(Ok(_) | Err(broadcast::error::RecvError::Lagged(_))) => {}
            Ok(Err(broadcast::error::RecvError::Closed)) | Err(_) => return None,
        }
    }
}

fn proposer() -> DirectLinksConfig {
    DirectLinksConfig {
        // Replaced by T's facilitator in `trio`.
        facilitator: Some(String::new()),
        ..DirectLinksConfig::default()
    }
}

/// **W4** — the inert default: no proposal anywhere, and a call member behind
/// `T` cannot be reached on its derived address. This is the gap item 8
/// closes; W1 is the same dial with a facilitator configured.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_default_never_proposes_and_a_member_behind_t_is_unreachable() {
    let p = trio(
        "w4",
        DirectLinksConfig::default(),
        DirectLinksConfig::default(),
    )
    .await;
    let (_spine, b_addr) = open_call(&p).await;
    match p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await {
        Err(TransportError::NoRouteToPeer { .. }) => {}
        other => panic!("a derived address behind T answers no dial: {other:?}"),
    }
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 0);
    assert!(
        p.a.metrics.direct_link().is_empty(),
        "the default touches nothing: {:?}",
        p.a.metrics.direct_link()
    );
    assert_eq!(p.a.transport.direct_path_state(&p.b.key.key_id), None);
}

/// **W1 + W5** — A's A/V dial to a member behind `T` proposes on the identity
/// link first; both ends move onto a punched interface; the A/V leg then
/// establishes over it, carries frames, and keeps carrying them with `T`
/// gone. The moved identity link's Channel limit drops to 1400-MTU size.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_member_behind_nat_is_reached_over_a_punched_interface() {
    // B on the default: accept room peers, asked per request.
    let mut p = trio("w1", proposer(), DirectLinksConfig::default()).await;
    assert!(!p.facilitator.is_empty());
    let (_spine, b_addr) = open_call(&p).await;
    let mut arrivals = p.b.transport.take_av_arrivals().expect("B's arrivals");

    let link =
        p.a.transport
            .open_av_link(&p.b.key.key_id, &b_addr)
            .await
            .expect("A reaches B's A/V address over the punched interface");

    // Both ends saw the upgrade; A proposed, B accepted.
    let a_up = next_event(&mut p.a.events, Duration::from_secs(5), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("A's Established");
    let DirectPathEvent::Established {
        peer,
        link_id: identity_link,
        proposed,
        channel_limit_before,
        channel_limit_after,
        ..
    } = a_up
    else {
        unreachable!()
    };
    assert!(proposed, "A proposed");
    assert_eq!(peer.as_deref(), Some(p.b.key.key_id.as_str()));
    let b_up = next_event(&mut p.b.events, Duration::from_secs(10), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("B's Established");
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
    assert!(p.b.transport.should_accept_direct(&p.a.key.key_id));
    assert!(matches!(
        p.a.transport.direct_path_state(&p.b.key.key_id),
        Some(DirectPathState::Direct { .. })
    ));
    assert!(
        p.a.transport.direct_link_interface(identity_link).is_some(),
        "the identity link runs over the punched interface"
    );
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 1);
    assert_eq!(dl(&p.a.metrics, "direct_link_established"), 1);
    assert_eq!(p.a.metrics.direct_links_active(), 1);
    assert!(
        link.sender.is_direct(),
        "the leg holds the punched interface"
    );

    // W5 — the identity link came up over TCP at a large MTU; the move lowers
    // it to 1400 (Channel 1321) and never raises it.
    let before = channel_limit_before.expect("recorded at the proposal");
    let after = channel_limit_after.expect("the link is held");
    // 1400-MTU Channel limit: 1321, less the 25-byte CC 5.3.3.5 E1 seal.
    assert_eq!(after, 1296, "1400-MTU Channel limit, sealed");
    assert!(
        before > after,
        "the move lowered the limit: {before} -> {after}"
    );
    let av_limit = link.sender.channel_limit().expect("the A/V link is held");
    // The A/V leg is BORN on the punched interface, which signals no hardware
    // MTU, so it negotiates the base 500: Channel 425 (link MDU 431 less the
    // 6-byte envelope), 400 of it plaintext under the CC 5.3.3.5 E1 seal.
    assert_eq!(av_limit, 400, "the A/V leg runs at the base MTU");

    // CIRISEdge#805 / CC 5.3.3.5 E1 — the link's transit KEX handshake rode
    // this base-MTU leg as its first Channel messages (about 1.2 KB at 400 B
    // each), and B answered it: both ends hold the link's keys, by role.
    let arrival = tokio::time::timeout(Duration::from_secs(20), arrivals.recv())
        .await
        .expect("B's consumer gets the link")
        .expect("arrivals open");
    assert_eq!(arrival.peer.as_str(), p.a.key.key_id);
    assert!(
        p.a.metrics
            .link_seal()
            .get("link_seal_initiated")
            .copied()
            .unwrap_or(0)
            >= 1,
        "A keyed the A/V leg it dialled"
    );
    let accepted =
        p.b.transport
            .accept_av_arrival(arrival)
            .await
            .expect("B answers A's transit KEX over the punched leg");
    assert_eq!(link.transit.seal_key(), accepted.transit.open_key());
    assert_eq!(accepted.transit.seal_key(), link.transit.open_key());
    let arrival = accepted.arrival;

    // Frames cross the A/V leg, then still cross with T gone.
    link.sender.send(b"direct-805-1").await.expect("send 1");
    let got = tokio::time::timeout(Duration::from_secs(10), arrival.inbound.recv())
        .await
        .expect("frame 1 in time")
        .expect("frame 1");
    assert_eq!(got, b"direct-805-1");

    p.t.stop().await.expect("stop T");
    tokio::time::sleep(Duration::from_millis(500)).await;
    link.sender.send(b"direct-805-2").await.expect("send 2");
    let got = tokio::time::timeout(Duration::from_secs(10), arrival.inbound.recv())
        .await
        .expect("frame 2 in time, T gone")
        .expect("frame 2");
    assert_eq!(got, b"direct-805-2", "the leg never needed T");
}

/// **W3** — B refuses (accepting `Off`). The proposal fails `Rejected`, the dial
/// behaves exactly as with no proposal, and a second dial does not propose
/// again on the refused link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_upgrade_leaves_the_dial_as_it_was() {
    let refuser = DirectLinksConfig {
        accept: DirectAccept::Off,
        ..DirectLinksConfig::default()
    };
    let mut p = trio("w3", proposer(), refuser).await;
    let (_spine, b_addr) = open_call(&p).await;
    match p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await {
        Err(TransportError::NoRouteToPeer { .. }) => {}
        other => panic!("refused: the dial is the no-proposal dial: {other:?}"),
    }
    let failed = next_event(&mut p.a.events, Duration::from_secs(5), |e| {
        matches!(e, DirectPathEvent::Failed { .. })
    })
    .await
    .expect("A's Failed");
    assert!(
        matches!(&failed, DirectPathEvent::Failed { reason, proposed: true, .. }
            if *reason == "direct_link_failed_rejected"),
        "{failed:?}"
    );
    assert_eq!(
        p.a.transport.direct_path_state(&p.b.key.key_id),
        Some(DirectPathState::BackingOff)
    );
    assert_eq!(dl(&p.a.metrics, "direct_link_failed_rejected"), 1);

    // Again: no second proposal on the refused link.
    let _ = p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await;
    assert_eq!(
        dl(&p.a.metrics, "direct_link_proposed"),
        1,
        "{:?}",
        p.a.metrics.direct_link()
    );
    assert_eq!(dl(&p.a.metrics, "direct_link_skipped_backoff"), 1);
}

/// **W6** — a peer this node shares no room with is refused, and learns
/// nothing. A has B in its call; B never joined it, so to B, A is an
/// identified peer outside every room it holds. B's host refuses: A's
/// proposal ends `Rejected` (a REJECT B sent without probing, so no reflexive
/// address of B's was learned or sent), and B never moves anything direct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_outside_our_rooms_is_refused_and_learns_nothing() {
    let mut p = trio("w6", proposer(), DirectLinksConfig::default()).await;
    let (_spine, b_addr) = open_call_with(&p, false).await;
    assert!(!p.b.transport.should_accept_direct(&p.a.key.key_id));
    let _ = p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await;

    let asked = next_event(&mut p.b.events, Duration::from_secs(10), |e| {
        matches!(e, DirectPathEvent::Requested { .. })
    })
    .await
    .expect("B's host was asked");
    assert!(
        matches!(&asked, DirectPathEvent::Requested { accepted: false, peer, .. }
            if peer.as_deref() == Some(p.a.key.key_id.as_str())),
        "attributed to A, refused: {asked:?}"
    );
    let failed = next_event(&mut p.a.events, Duration::from_secs(10), |e| {
        matches!(e, DirectPathEvent::Failed { .. })
    })
    .await
    .expect("A's Failed");
    assert!(
        matches!(&failed, DirectPathEvent::Failed { reason, .. }
            if *reason == "direct_link_failed_rejected"),
        "{failed:?}"
    );
    assert_eq!(dl(&p.b.metrics, "direct_link_request_refused"), 1);
    assert_eq!(dl(&p.b.metrics, "direct_link_request_accepted"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_established"), 0);
    assert_eq!(p.b.transport.direct_path_state(&p.a.key.key_id), None);
    assert_eq!(p.b.metrics.direct_links_active(), 0);
}

// ─── W2: the subscriber's choice of leg (CIRISEdge#805 item 8, cut 2) ─

/// R is the field's reachable member: an EDGE node that is the transport
/// node, the facilitator, and a call member that relays. A, B and C are TCP
/// clients of R only. A publishes; B subscribes; C is not in the call.
struct Quad {
    r: Side,
    a: Side,
    b: Side,
    c: Side,
    _tmp: tempfile::TempDir,
}

#[allow(clippy::too_many_lines)]
async fn quad(tag: &str) -> Quad {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let f_port = free_udp_port();
    let keys = [
        Ident::new(&format!("node-r-dl-{tag}"), 0x3a).await,
        Ident::new(&format!("node-a-dl-{tag}"), 0x3b).await,
        Ident::new(&format!("node-b-dl-{tag}"), 0x3c).await,
        Ident::new(&format!("node-c-dl-{tag}"), 0x3d).await,
    ];
    let mut records = Vec::new();
    for k in &keys {
        records.push(k.record().await);
    }
    let mut dirs = Vec::new();
    for _ in 0..4 {
        dirs.push(directory_with(records.clone()).await);
    }
    let [key_r, key_a, key_b, key_c] = keys;
    let r = side_cfg(key_r, &dirs[0], &tmp.path().join("r"), move |c| {
        c.with_transport_node(true)
            .with_direct_links(DirectLinksConfig {
                serve_facilitator: Some(f_port),
                ..DirectLinksConfig::default()
            })
    })
    .await;
    let r_port = r.port;
    let client = |direct: DirectLinksConfig| {
        move |c: ReticulumTransportConfig| {
            let mut c = c.with_direct_links(direct.clone());
            c.bootstrap_peers = vec![format!("127.0.0.1:{r_port}").parse().unwrap()];
            c
        }
    };
    let a_direct = DirectLinksConfig {
        facilitator: Some(format!("127.0.0.1:{f_port}")),
        ..DirectLinksConfig::default()
    };
    let a = side_cfg(key_a, &dirs[1], &tmp.path().join("a"), client(a_direct)).await;
    let b = side_cfg(
        key_b,
        &dirs[2],
        &tmp.path().join("b"),
        client(DirectLinksConfig::default()),
    )
    .await;
    let c = side_cfg(
        key_c,
        &dirs[3],
        &tmp.path().join("c"),
        client(DirectLinksConfig::default()),
    )
    .await;
    let sides = [&r, &a, &b, &c];
    for (i, from) in sides.iter().enumerate() {
        let routes = dirs[i]
            .list_signed_transport_destinations_for(&from.key.key_id)
            .await
            .expect("list routes");
        for (j, to) in dirs.iter().enumerate() {
            if i == j {
                continue;
            }
            for route in &routes {
                FederationDirectory::put_signed_transport_destination(&**to, route)
                    .await
                    .expect("seed the route");
            }
        }
    }
    let known = wait_until(Duration::from_secs(90), || async {
        a.transport.knows_peer(&b.key.key_id).await
            && b.transport.knows_peer(&a.key.key_id).await
            && a.transport.knows_peer(&r.key.key_id).await
            && b.transport.knows_peer(&r.key.key_id).await
            && c.transport.knows_peer(&r.key.key_id).await
            && r.transport.knows_peer(&c.key.key_id).await
    })
    .await;
    assert!(known, "every node learns the others it needs through R");
    Quad {
        r,
        a,
        b,
        c,
        _tmp: tmp,
    }
}

const LEGS_DEK: [u8; 32] = [0x44; 32];

fn legs_stream() -> StreamId {
    StreamId(sha2::Sha256::digest(b"av-stream-805-legs").into())
}

/// The call's group on `side`, as `members` (A, B and R; C installs a copy
/// naming itself too, as a leaked or stale view would).
fn install_legs_group(side: &Side, members: &[&str]) {
    side.lifecycle
        .joined(
            &scope(),
            &av_addressing::stream_group_id(legs_stream()),
            1,
            &[0x77; 32],
            members,
        )
        .expect("install the call's group");
}

fn legs_address(side: &Side, member: &str) -> MemberAddress {
    side.table
        .send_address(
            &scope(),
            &av_addressing::stream_group_id(legs_stream()),
            member,
        )
        .expect("the member's call address")
}

fn legs_chunk(seq: u64) -> InnerSealed {
    let mut body = format!("legs-805-{seq:04}-").into_bytes();
    body.resize(64, 0x2e);
    seal_av_inner(
        &body,
        &EpochDek::from_bytes(LEGS_DEK),
        legs_stream(),
        Epoch(1),
        ChunkSeq(seq),
        CODEC_OPAQUE,
        ChunkLayer::BASE,
    )
    .expect("seal")
}

async fn next_arrival(arrivals: &mut mpsc::Receiver<AvArrival>, from: &str) -> AvArrival {
    let arrival = tokio::time::timeout(Duration::from_secs(20), arrivals.recv())
        .await
        .expect("an A/V link arrives in time")
        .expect("arrivals open");
    assert_eq!(arrival.peer.as_str(), from, "the arrival is {from}'s");
    arrival
}

/// Dial R's call address from `side` and subscribe: a subscription is the
/// dialled link, whose first message is the transit KEX handshake
/// (CIRISEdge#805). The subscriber dialled, so it is the INITIATOR and opens
/// R's frames with its open key (`responder_to_initiator`).
async fn dial_r(side: &Side, r_id: &str) -> ciris_edge::transport::av_sink::AvLink {
    side.transport
        .open_av_link(r_id, &legs_address(side, r_id))
        .await
        .expect("dial R")
}

/// R answers its upstream's handshake: the publisher dialled R, so R is the
/// RESPONDER and opens with its open key (`initiator_to_responder`).
async fn accept_upstream(r: &Side, arrival: AvArrival) -> (AvInboundLink, [u8; 32], Vec<u8>) {
    let accepted = r
        .transport
        .accept_av_arrival(arrival)
        .await
        .expect("R answers the publisher's transit KEX");
    let key = accepted.transit.open_key();
    let link_id = accepted.arrival.link_id.to_vec();
    (
        AvInboundLink {
            transit_key: key,
            link_id: link_id.clone(),
            inbound_recv: Box::new(accepted.arrival.inbound),
        },
        key,
        link_id,
    )
}

/// **W2** — B hears A's stream over the relay member R, then directly once a
/// punched path exists, then over R again when the direct path is judged
/// dead:
///
/// - every chunk B delivers is delivered once (the overlap's copies are
///   counted as duplicates, never delivered);
/// - the relay leg is dropped once the direct leg is confirmed, and from then
///   the relay carries nothing to B (one delivery path at steady state);
/// - `fall_back_from_direct` retires A's identity link off the punched
///   interface (leviculum#83) and closes the leg; B rejoins R and chunks
///   resume, the final run complete;
/// - C, which is not in R's view of the call, dials R and gets nothing.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_subscriber_moves_between_relay_and_direct_legs_and_back() {
    let q = quad("w2").await;
    let (a_id, b_id, r_id, c_id) = (
        q.a.key.key_id.clone(),
        q.b.key.key_id.clone(),
        q.r.key.key_id.clone(),
        q.c.key.key_id.clone(),
    );
    let members = [a_id.as_str(), b_id.as_str(), r_id.as_str()];
    for side in [&q.r, &q.a, &q.b] {
        install_legs_group(side, &members);
    }
    install_legs_group(
        &q.c,
        &[a_id.as_str(), b_id.as_str(), r_id.as_str(), c_id.as_str()],
    );
    let mut r_arrivals = q.r.transport.take_av_arrivals().expect("R's arrivals");
    let mut b_arrivals = q.b.transport.take_av_arrivals().expect("B's arrivals");

    // A → R, the relay leg's upstream. R starts its pump on A's first frame.
    let a_r =
        q.a.transport
            .open_av_link(&r_id, &legs_address(&q.a, &r_id))
            .await
            .expect("A dials R");
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: legs_stream(),
        local_role: AvRole::Publisher,
        epoch_dek: Some(LEGS_DEK),
        initial_subscribers: vec![AvSubscriberLink {
            subscriber: r_id.clone(),
            transit_key: a_r.transit.seal_key(),
            link_id: a_r.link_id.to_vec(),
            outbound_send: Box::new(a_r.sender),
        }],
        inbound_links: vec![],
    })
    .expect("A's publisher");
    let mut seq = 0u64;
    let _ = publisher.publish_inner(legs_chunk(seq)).await;
    seq += 1;
    let upstream = next_arrival(&mut r_arrivals, &a_id).await;
    let (upstream, up_key, up_link) = accept_upstream(&q.r, upstream).await;
    let (_pump, admissions) = AvRelay::new(legs_stream(), Vec::new())
        .expect("R's relay")
        .spawn_pump_admitting(upstream, up_key, up_link);

    // B subscribes by DIALLING R (its first frame is the subscription).
    let b_r = dial_r(&q.b, &r_id).await;
    let arrival = next_arrival(&mut r_arrivals, &b_id).await;
    assert!(
        q.r.transport
            .admit_dialled_subscriber(arrival, &admissions)
            .await,
        "B is in R's call: admitted"
    );
    let LegStreams {
        legs,
        chunks: mut b_chunks,
        actions: mut b_actions,
    } = AvSubscriber::subscribe_legs(
        legs_stream(),
        &EpochDek::from_bytes(LEGS_DEK),
        a_id.clone(),
        r_id.clone(),
        AvInboundLink {
            transit_key: b_r.transit.open_key(),
            link_id: b_r.link_id.to_vec(),
            inbound_recv: Box::new(b_r.inbound),
        },
        Some(q.b.metrics.clone()),
    )
    .expect("B's legs");
    let delivered: Arc<std::sync::Mutex<Vec<u64>>> = Arc::default();
    let sink = Arc::clone(&delivered);
    tokio::spawn(async move {
        while let Some(chunk) = b_chunks.recv().await {
            sink.lock().unwrap().push(chunk.chunk_seq.0);
        }
    });
    for _ in 0..20 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    assert!(
        wait_until(Duration::from_secs(10), || async {
            delivered.lock().unwrap().contains(&(seq - 1))
        })
        .await,
        "B hears A over R: {:?}",
        delivered.lock().unwrap()
    );

    // The direct leg: A's dial punches through R and reaches B directly.
    let a_b =
        q.a.transport
            .open_av_link(&b_id, &legs_address(&q.a, &b_id))
            .await
            .expect("A reaches B directly");
    let anchor = a_b.sender.direct_anchor();
    assert!(anchor.is_some(), "the leg holds a punched path");
    let a_b_link = a_b.link_id;
    publisher
        .add_subscriber(AvSubscriberLink {
            subscriber: b_id.clone(),
            transit_key: a_b.transit.seal_key(),
            link_id: a_b.link_id.to_vec(),
            outbound_send: Box::new(a_b.sender),
        })
        .expect("A adds B's direct leg");
    let _ = publisher.publish_inner(legs_chunk(seq)).await;
    seq += 1;
    // A dialled B, so B is the RESPONDER on the direct leg: it opens with
    // `initiator_to_responder`.
    let direct = next_arrival(&mut b_arrivals, &a_id).await;
    let direct =
        q.b.transport
            .accept_av_arrival(direct)
            .await
            .expect("B answers A's transit KEX on the direct leg");
    legs.add_leg(
        Leg::Direct,
        AvInboundLink {
            transit_key: direct.transit.open_key(),
            link_id: direct.arrival.link_id.to_vec(),
            inbound_recv: Box::new(direct.arrival.inbound),
        },
    )
    .await
    .expect("B adds the direct leg");

    // The overlap: both legs deliver until the direct one is confirmed.
    let mut dropped = None;
    for _ in 0..40 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
        if let Ok(action) = b_actions.try_recv() {
            dropped = Some(action);
            break;
        }
    }
    assert_eq!(dropped, Some(LegAction::DropRelay), "make-before-break");
    q.b.transport
        .link_teardown(&b_r.link_id)
        .await
        .expect("B closes its relay leg");
    let duplicates =
        q.b.metrics
            .av_plane()
            .get("av_inbound_duplicate_leg")
            .copied()
            .unwrap_or(0);
    assert!(duplicates > 0, "the overlap delivered copies, deduped");
    // One delivery path at steady state: the relay leg no longer exists at
    // either end, so R has nothing to carry to B (its fan-out prunes the
    // gone link).
    let relay_leg = b_r.link_id;
    let gone = wait_until(Duration::from_secs(10), || async {
        let held = |planes: Vec<([u8; 16], ciris_edge::transport::reticulum::LinkPlane, bool)>| {
            planes.iter().any(|(id, _, _)| *id == relay_leg)
        };
        !held(q.b.transport.link_planes_for_test().await)
            && !held(q.r.transport.link_planes_for_test().await)
    })
    .await;
    assert!(gone, "B's relay leg is closed at B and at R");
    for _ in 0..20 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }

    // The direct path is judged dead: A falls back on both planes.
    let mut a_events = q.a.transport.subscribe_direct_path_events();
    q.a.transport.fall_back_from_direct(a_b_link, anchor).await;
    assert!(
        next_event(&mut a_events, Duration::from_secs(5), |e| {
            matches!(e, DirectPathEvent::Lost { .. })
        })
        .await
        .is_some(),
        "#83: the identity link left the punched interface"
    );
    assert_eq!(
        q.a.transport.direct_link_interface(anchor.expect("anchor")),
        None
    );
    let rejoin = tokio::time::timeout(Duration::from_secs(10), b_actions.recv())
        .await
        .expect("B notices the direct leg closed")
        .expect("actions open");
    assert_eq!(rejoin, LegAction::RejoinRelay);
    let b_r2 = dial_r(&q.b, &r_id).await;
    let arrival = next_arrival(&mut r_arrivals, &b_id).await;
    assert!(
        q.r.transport
            .admit_dialled_subscriber(arrival, &admissions)
            .await
    );
    legs.add_leg(
        Leg::Relay,
        AvInboundLink {
            transit_key: b_r2.transit.open_key(),
            link_id: b_r2.link_id.to_vec(),
            inbound_recv: Box::new(b_r2.inbound),
        },
    )
    .await
    .expect("B rejoins R");
    let resumed_from = seq;
    for _ in 0..40 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let last = seq - 1;
    assert!(
        wait_until(Duration::from_secs(10), || async {
            delivered.lock().unwrap().contains(&last)
        })
        .await,
        "chunks resume over R"
    );
    let got = delivered.lock().unwrap().clone();
    let mut unique = got.clone();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(
        unique.len(),
        got.len(),
        "every chunk delivered ONCE: {got:?}"
    );
    // A FRESH relay link refuses with `Congested` for its opening window
    // (a few hundred ms idle, longer under load), and the fan-out drops,
    // never queues, a refused frame (CIRISEdge#591; pacing is #863 item 5).
    // How long that ramp lasts is the host's load, not a property to pin; what
    // is pinned is that nothing after the rejoin is lost SILENTLY: every chunk
    // is delivered or is one the relay booked as a congested drop. (A fixed
    // ~20-chunk budget here failed a gate on a loaded box with the ramp
    // running to chunk 64 and one more drop at 72.)
    let dropped = admissions.congested_drops();
    for s in resumed_from..=last {
        assert!(
            got.contains(&s) || dropped.contains(&s),
            "chunk {s} after the rejoin was neither delivered nor booked as a congested \
             drop: delivered {got:?}, dropped {dropped:?}"
        );
    }

    // C is not in R's view of the call: refused, and hears nothing.
    let c_r = dial_r(&q.c, &r_id).await;
    let arrival = next_arrival(&mut r_arrivals, &c_id).await;
    assert!(
        !q.r.transport
            .admit_dialled_subscriber(arrival, &admissions)
            .await,
        "C is refused"
    );
    assert_eq!(
        q.r.metrics
            .av_plane()
            .get("av_relay_dialler_refused")
            .copied(),
        Some(1)
    );
    for _ in 0..10 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let heard = tokio::time::timeout(Duration::from_secs(2), c_r.inbound.recv()).await;
    assert!(!matches!(heard, Ok(Ok(_))), "C received nothing: {heard:?}");
}

/// **W2b** (CIRISEdge#863 item 6) — a relay leg carrying media outlives the
/// inbound reaper, on BOTH ends.
///
/// B subscribes by dialling R, then sends nothing: at R the link is INBOUND
/// and R only ever SENDS on it, so R's sends must be its liveness, or R's
/// reaper closes the leg mid-call at its idle bound (120 s in the field; 2 s
/// here, with reap passes running throughout and media flowing well past
/// it). The symmetric end: at B the same link is OUTBOUND and B only
/// receives; it is never the inbound reaper's to close, and it is in no link
/// pool, so the pooled (outbound) reaper, run here at the same bound, never
/// judges it either (the exemption is asserted by name).
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_relay_leg_carrying_media_outlives_the_reaper_863() {
    let q = quad("w2b").await;
    let (a_id, b_id, r_id) = (
        q.a.key.key_id.clone(),
        q.b.key.key_id.clone(),
        q.r.key.key_id.clone(),
    );
    let members = [a_id.as_str(), b_id.as_str(), r_id.as_str()];
    for side in [&q.r, &q.a, &q.b] {
        install_legs_group(side, &members);
    }
    let mut r_arrivals = q.r.transport.take_av_arrivals().expect("R's arrivals");
    let a_r =
        q.a.transport
            .open_av_link(&r_id, &legs_address(&q.a, &r_id))
            .await
            .expect("A dials R");
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: legs_stream(),
        local_role: AvRole::Publisher,
        epoch_dek: Some(LEGS_DEK),
        initial_subscribers: vec![AvSubscriberLink {
            subscriber: r_id.clone(),
            transit_key: a_r.transit.seal_key(),
            link_id: a_r.link_id.to_vec(),
            outbound_send: Box::new(a_r.sender),
        }],
        inbound_links: vec![],
    })
    .expect("A's publisher");
    let mut seq = 0u64;
    let _ = publisher.publish_inner(legs_chunk(seq)).await;
    seq += 1;
    let upstream = next_arrival(&mut r_arrivals, &a_id).await;
    let (upstream, up_key, up_link) = accept_upstream(&q.r, upstream).await;
    let (_pump, admissions) = AvRelay::new(legs_stream(), Vec::new())
        .expect("R's relay")
        .spawn_pump_admitting(upstream, up_key, up_link);
    let b_r = dial_r(&q.b, &r_id).await;
    let arrival = next_arrival(&mut r_arrivals, &b_id).await;
    assert!(
        q.r.transport
            .admit_dialled_subscriber(arrival, &admissions)
            .await
    );
    let relay_leg = b_r.link_id;
    let mut chunks = AvSubscriber::subscribe(
        legs_stream(),
        &EpochDek::from_bytes(LEGS_DEK),
        &r_id,
        AvInboundLink {
            transit_key: b_r.transit.open_key(),
            link_id: relay_leg.to_vec(),
            inbound_recv: Box::new(b_r.inbound),
        },
    )
    .expect("B subscribes over R");

    // A 2 s idle bound on both ends; media every 100 ms for 6 s; a reap
    // pass on both ends every 500 ms.
    let bound = Duration::from_secs(2);
    q.r.transport.set_inbound_link_idle_bound(bound);
    q.b.transport.set_inbound_link_idle_bound(bound);
    // The OUTBOUND side's idle reaper too (#819/#821's pooled reap), at the
    // same bound: B's leg is outbound at B and only receives.
    let (_, cap) = q.b.transport.link_pool_policy();
    q.b.transport.set_link_pool_policy(bound, cap);
    q.r.transport.set_link_pool_policy(bound, cap);
    let mut reaped = (0usize, 0usize);
    for i in 0..60 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        seq += 1;
        tokio::time::sleep(Duration::from_millis(100)).await;
        if i % 5 == 4 {
            reaped.0 += q.r.transport.reap_idle_inbound_links().await;
            reaped.0 += q.r.transport.reap_idle_pooled_links().await;
            reaped.1 += q.b.transport.reap_idle_inbound_links().await;
            reaped.1 += q.b.transport.reap_idle_pooled_links().await;
        }
    }
    // The exemption, named: an A/V leg is in neither link pool at either end,
    // so the pooled reaper can never judge it.
    assert!(!q.b.transport.link_is_pooled_for_test(relay_leg).await);
    assert!(!q.r.transport.link_is_pooled_for_test(relay_leg).await);
    let held = |planes: Vec<([u8; 16], ciris_edge::transport::reticulum::LinkPlane, bool)>| {
        planes.iter().any(|(id, _, _)| *id == relay_leg)
    };
    assert!(
        held(q.r.transport.link_planes_for_test().await),
        "R kept the leg it only sends on (reaped at R: {})",
        reaped.0
    );
    assert!(
        held(q.b.transport.link_planes_for_test().await),
        "B kept the leg it only receives on (reaped at B: {})",
        reaped.1
    );
    // And it is still carrying media: the last chunk arrives.
    let last = seq - 1;
    let got_last = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(chunk) = chunks.recv().await {
            if chunk.chunk_seq.0 == last {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(
        got_last,
        Ok(true),
        "the relay leg still delivers past the bound"
    );
}

// ─── CIRISEdge#805 — the per-link transit KEX, refused by name ────────

/// Re-sign `owner`'s reticulum route in `dir` WITHOUT its transit KEX pair, at
/// a later `asserted_at`: the node, as `dir` now sees it, publishes no pair.
async fn strip_transit_pair(dir: &Arc<SqliteBackend>, owner: &Ident) {
    use base64::Engine as _;
    let b64 = base64::engine::general_purpose::STANDARD;
    let route = dir
        .list_signed_transport_destinations_for(&owner.key_id)
        .await
        .expect("list routes")
        .into_iter()
        .find(|r| r.transport_destination.transport_kind == "reticulum")
        .expect("the owner's route");
    let mut row = route.transport_destination.clone();
    row.asserted_at += chrono::Duration::seconds(1);
    let envelope = serde_json::to_value(&row).expect("row to value");
    let bytes = ciris_persist::prelude::ceg_produce_canonicalize(&envelope).expect("canon");
    let ed = HardwareSigner::sign(owner.ed.as_ref(), &bytes)
        .await
        .expect("ed25519 sign");
    let mut bound = bytes;
    bound.extend_from_slice(&ed);
    let mldsa = PqcSigner::sign(owner.pqc.as_ref(), &bound)
        .await
        .expect("ml-dsa sign");
    let stripped = ciris_persist::federation::self_at_login::SignedTransportDestination {
        attesting_key_id: owner.key_id.clone(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: b64.encode(&ed),
            mldsa65_signature_base64: Some(b64.encode(&mldsa)),
        },
    };
    FederationDirectory::put_signed_transport_destination(&**dir, &stripped)
        .await
        .expect("the pair-less route admits");
    assert_eq!(
        ciris_persist::federation::self_at_login::transit_kex_pair_for(&**dir, &owner.key_id)
            .await
            .expect("resolve"),
        None,
        "the owner now publishes no pair, as this directory sees it"
    );
}

/// **W7** (CIRISEdge#805, CC 5.3.3.5 E1) — an A/V hop is keyed by the per-link
/// transit KEX or not at all:
///
/// - a subscriber whose handshake CLAIMS another member is refused at the
///   relay by name (`link_seal_refused_claim_mismatch`), the link is closed
///   before it is ever handed to the relay, and it hears nothing while the
///   stream runs;
/// - a dial to a node that publishes no transit pair is refused by name
///   (`LinkSealRefused` / `link_seal_refused_no_pair`) before the link
///   carries a byte; nothing arrives at the dialled node.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_transit_kex_refuses_a_false_claim_and_a_missing_pair_by_name() {
    let q = quad("w7").await;
    let (a_id, b_id, r_id) = (
        q.a.key.key_id.clone(),
        q.b.key.key_id.clone(),
        q.r.key.key_id.clone(),
    );
    let members = [a_id.as_str(), b_id.as_str(), r_id.as_str()];
    for side in [&q.r, &q.a, &q.b] {
        install_legs_group(side, &members);
    }
    let mut r_arrivals = q.r.transport.take_av_arrivals().expect("R's arrivals");

    // A publishes through R, keyed by A's handshake.
    let a_r =
        q.a.transport
            .open_av_link(&r_id, &legs_address(&q.a, &r_id))
            .await
            .expect("A dials R");
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: legs_stream(),
        local_role: AvRole::Publisher,
        epoch_dek: Some(LEGS_DEK),
        initial_subscribers: vec![AvSubscriberLink {
            subscriber: r_id.clone(),
            transit_key: a_r.transit.seal_key(),
            link_id: a_r.link_id.to_vec(),
            outbound_send: Box::new(a_r.sender),
        }],
        inbound_links: vec![],
    })
    .expect("A's publisher");
    let upstream = next_arrival(&mut r_arrivals, &a_id).await;
    let (upstream, up_key, up_link) = accept_upstream(&q.r, upstream).await;
    let (_pump, admissions) = AvRelay::new(legs_stream(), Vec::new())
        .expect("R's relay")
        .spawn_pump_admitting(upstream, up_key, up_link);

    // B dials R but its handshake claims A. R's link proves B: refused at
    // the link layer, and the link never reaches R's A/V consumer.
    let liar =
        q.b.transport
            .open_av_link_claiming_for_test(&r_id, &legs_address(&q.b, &r_id), &a_id)
            .await
            .expect("B's dial and handshake go out");
    let refused = wait_until(Duration::from_secs(20), || async {
        q.r.metrics
            .link_seal()
            .get("link_seal_refused_claim_mismatch")
            .copied()
            == Some(1)
    })
    .await;
    assert!(
        refused,
        "a handshake claiming another member is refused: {:?}",
        q.r.metrics.link_seal()
    );
    let r_av = q.r.metrics.av_plane();
    assert_eq!(r_av.get("av_relay_dialler_admitted").copied(), None);
    let _ = &admissions;
    for seq in 0..15u64 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let heard = tokio::time::timeout(Duration::from_secs(2), liar.inbound.recv()).await;
    assert!(
        !matches!(heard, Ok(Ok(_))),
        "the refused dialler heard nothing: {heard:?}"
    );

    // R, as A's directory now sees it, publishes no pair: A's dial is refused
    // by name and never keyed another way.
    let keyed_before = q.a.metrics.link_seal().get("link_seal_initiated").copied();
    strip_transit_pair(&q.a.dir, &q.r.key).await;
    match q
        .a
        .transport
        .open_av_link(&r_id, &legs_address(&q.a, &r_id))
        .await
    {
        Err(TransportError::LinkSealRefused { peer, reason, .. }) => {
            assert_eq!(peer, r_id);
            assert_eq!(reason, "link_seal_refused_no_pair");
        }
        other => panic!("a dial to a pair-less node must be refused by name: {other:?}"),
    }
    let a_seal = q.a.metrics.link_seal();
    assert_eq!(
        a_seal.get("link_seal_refused_no_pair").copied(),
        Some(1),
        "{a_seal:?}"
    );
    assert_eq!(
        a_seal.get("link_seal_initiated").copied(),
        keyed_before,
        "the refused dial keyed nothing: {a_seal:?}"
    );
    let nothing = tokio::time::timeout(Duration::from_secs(2), r_arrivals.recv()).await;
    assert!(
        nothing.is_err(),
        "the refused dial sent nothing, so nothing arrived at R"
    );
}

// ─── CIRISEdge#541/#805 — one occurrence key id under use_node_identity ─

/// A software `TransportIdentityKeystore` in `dir`: the keystore-backed path
/// `use_node_identity` deployments run.
fn software_keystore(dir: &std::path::Path) -> Arc<dyn ciris_keyring::TransportIdentityKeystore> {
    let storage = ciris_keyring::storage::SoftwareSecureBlobStorage::new("split-805", dir)
        .expect("software blob storage");
    Arc::new(ciris_keyring::BlobTransportKeystore::new(Box::new(storage)))
}

/// One node as `use_node_identity` builds it (pyo3's #541 wiring): the
/// advertised id and the signer are the NODE's, a keystore holds the RNS
/// identity and the transit seed, and they are stored under the ACTOR's id
/// (`transport_identity_storage_key`), which differs.
async fn split_side(
    key: Ident,
    actor_id: &str,
    dir: &Arc<SqliteBackend>,
    base: &std::path::Path,
    shape: impl Fn(ReticulumTransportConfig) -> ReticulumTransportConfig,
) -> (Side, Arc<dyn ciris_keyring::TransportIdentityKeystore>) {
    let keystore = software_keystore(&base.join("keystore"));
    let ks = Arc::clone(&keystore);
    let actor = actor_id.to_owned();
    let side = side_cfg_auth(
        key,
        dir,
        base,
        move |c| {
            let mut c = shape(c);
            c.transport_identity_storage_key = Some(actor.clone());
            c
        },
        move |a| ReticulumAuth {
            transport_identity_keystore: Some(Arc::clone(&ks)),
            ..a
        },
    )
    .await;
    (side, keystore)
}

/// **W8** (CIRISEdge#541/#805) — under `use_node_identity` the advertised id
/// (the node's) and the actor's id differ. ONE occurrence key id is
/// advertised, published, looked up and named in both halves of the transit
/// KEX; the actor's id only names keystore entries. A dial between two such
/// nodes handshakes and carries media.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_occurrence_key_id_keys_a_hop_under_use_node_identity() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_r = Ident::new("node-r-dl-w8", 0x4a).await;
    let key_a = Ident::new("node-a-dl-w8", 0x4b).await;
    let records = vec![key_r.record().await, key_a.record().await];
    let r_dir = directory_with(records.clone()).await;
    let a_dir = directory_with(records).await;
    let (r_id, a_id) = (key_r.key_id.clone(), key_a.key_id.clone());
    let (r_actor, a_actor) = ("actor-r-w8".to_owned(), "actor-a-w8".to_owned());

    let (r, r_keystore) = split_side(key_r, &r_actor, &r_dir, &tmp.path().join("r"), |c| {
        c.with_transport_node(true)
    })
    .await;
    let r_port = r.port;
    let (a, _a_keystore) = split_side(key_a, &a_actor, &a_dir, &tmp.path().join("a"), move |c| {
        let mut c = c;
        c.bootstrap_peers = vec![format!("127.0.0.1:{r_port}").parse().unwrap()];
        c
    })
    .await;
    assert_eq!(r.transport.occurrence_key_id(), r_id);
    assert_eq!(a.transport.occurrence_key_id(), a_id);
    assert!(!r.transport.signer_id_mismatch() && !a.transport.signer_id_mismatch());
    assert_eq!(r.metrics.transport_signer_id_mismatch(), 0);
    // The actor's id names only the keystore entries, the transit seed's too.
    assert!(
        r_keystore
            .load(&format!("transit-kex:v1:{r_actor}"))
            .expect("keystore read")
            .is_some(),
        "R's transit seed is stored under the actor's id"
    );
    assert!(r_keystore
        .load(&format!("transit-kex:v1:{r_id}"))
        .expect("keystore read")
        .is_none());

    // Each holds the other's signed route: published under the node id.
    for (from, from_id, to) in [(&r_dir, &r_id, &a_dir), (&a_dir, &a_id, &r_dir)] {
        let routes = from
            .list_signed_transport_destinations_for(from_id)
            .await
            .expect("list routes");
        assert!(!routes.is_empty(), "{from_id} published its route");
        for route in &routes {
            FederationDirectory::put_signed_transport_destination(&**to, route)
                .await
                .expect("seed the route");
        }
    }
    assert!(
        ciris_persist::federation::self_at_login::transit_kex_pair_for(&*a_dir, &r_id)
            .await
            .expect("resolve")
            .is_some(),
        "R's pair resolves under its node id"
    );
    assert!(
        wait_until(Duration::from_secs(60), || async {
            a.transport.knows_peer(&r_id).await && r.transport.knows_peer(&a_id).await
        })
        .await,
        "A and R learn each other"
    );
    let members = [a_id.as_str(), r_id.as_str()];
    install_legs_group(&r, &members);
    install_legs_group(&a, &members);
    let mut r_arrivals = r.transport.take_av_arrivals().expect("R's arrivals");

    // A dials R: the handshake names A's node id as initiator and R's as
    // responder; R answers it as its node id; media flows.
    let a_r = a
        .transport
        .open_av_link(&r_id, &legs_address(&a, &r_id))
        .await
        .expect("A's dial handshakes under the node ids");
    let arrival = next_arrival(&mut r_arrivals, &a_id).await;
    let accepted = r
        .transport
        .accept_av_arrival(arrival)
        .await
        .expect("R answers as its node id; the claim is A's node id");
    let mut publisher = AvDispatcher::new(AvDispatcherConfig {
        stream_id: legs_stream(),
        local_role: AvRole::Publisher,
        epoch_dek: Some(LEGS_DEK),
        initial_subscribers: vec![AvSubscriberLink {
            subscriber: r_id.clone(),
            transit_key: a_r.transit.seal_key(),
            link_id: a_r.link_id.to_vec(),
            outbound_send: Box::new(a_r.sender),
        }],
        inbound_links: vec![],
    })
    .expect("A's publisher");
    let mut chunks = AvSubscriber::subscribe(
        legs_stream(),
        &EpochDek::from_bytes(LEGS_DEK),
        &a_id,
        AvInboundLink {
            transit_key: accepted.transit.open_key(),
            link_id: accepted.arrival.link_id.to_vec(),
            inbound_recv: Box::new(accepted.arrival.inbound),
        },
    )
    .expect("R subscribes on the keyed hop");
    for seq in 0..10u64 {
        let _ = publisher.publish_inner(legs_chunk(seq)).await;
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let got = tokio::time::timeout(Duration::from_secs(10), chunks.recv())
        .await
        .expect("media in time")
        .expect("a chunk");
    assert_eq!(got.stream_id, legs_stream(), "R opened A's media");
    assert!(
        a.metrics
            .link_seal()
            .get("link_seal_initiated")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        r.metrics
            .link_seal()
            .get("link_seal_accepted")
            .copied()
            .unwrap_or(0)
            >= 1
    );
}

/// **W9** (CIRISEdge#541/#805) — a host wired the way CIRISServer's
/// `build_edge` wires a split node today: it ADVERTISES the node id
/// (`local_key_id`) but passes the ACTOR's signer. Edge must not brick it:
///
/// - the transport still BUILDS, and says so on the
///   `transport_signer_id_mismatch` gauge (and one startup error log);
/// - its signed route (and transit pair) is published under the signer's
///   id, the only id persist lets that signer publish for, so none is
///   resolvable under the advertised id;
/// - a dial to it by the advertised id is refused BY NAME as
///   `link_seal_refused_no_pair` before any link is made, never a silent
///   drop.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_host_signing_as_another_id_builds_and_is_refused_by_name() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key_r = Ident::new("node-r-dl-w9", 0x5a).await;
    let actor_r = Ident::new("actor-r-dl-w9", 0x5b).await;
    let key_a = Ident::new("node-a-dl-w9", 0x5c).await;
    let records = vec![
        key_r.record().await,
        actor_r.record().await,
        key_a.record().await,
    ];
    let r_dir = directory_with(records.clone()).await;
    let a_dir = directory_with(records).await;
    let (r_id, a_id, actor_id) = (
        key_r.key_id.clone(),
        key_a.key_id.clone(),
        actor_r.key_id.clone(),
    );

    // Server-style: advertises the node id, signs as the actor. It builds.
    let actor_signer = actor_r.signer();
    let r = side_cfg_auth(
        key_r,
        &r_dir,
        &tmp.path().join("r"),
        |c| c,
        move |a| ReticulumAuth {
            signer: Some(Arc::clone(&actor_signer)),
            ..a
        },
    )
    .await;
    assert_eq!(
        r.transport.occurrence_key_id(),
        r_id,
        "it advertises the node id"
    );
    assert!(r.transport.signer_id_mismatch());
    assert_eq!(
        r.metrics.transport_signer_id_mismatch(),
        1,
        "the mismatch is on the operator's gauge"
    );
    assert_eq!(r.metrics.snapshot().transport_signer_id_mismatch, 1);

    // Its route went out under the signer's id, not the advertised one.
    let under_actor = r_dir
        .list_signed_transport_destinations_for(&actor_id)
        .await
        .expect("list");
    assert!(!under_actor.is_empty(), "published under the signer's id");
    assert!(r_dir
        .list_signed_transport_destinations_for(&r_id)
        .await
        .expect("list")
        .is_empty());
    for route in &under_actor {
        FederationDirectory::put_signed_transport_destination(&*a_dir, route)
            .await
            .expect("seed the route at A");
    }

    // A dials R by the id R advertises: refused by name, before any link.
    let a = side_cfg(key_a, &a_dir, &tmp.path().join("a"), |c| c).await;
    let members = [a_id.as_str(), r_id.as_str()];
    install_legs_group(&r, &members);
    install_legs_group(&a, &members);
    let mut r_arrivals = r.transport.take_av_arrivals().expect("R's arrivals");
    match a
        .transport
        .open_av_link(&r_id, &legs_address(&a, &r_id))
        .await
    {
        Err(TransportError::LinkSealRefused { peer, reason, .. }) => {
            assert_eq!(peer, r_id);
            assert_eq!(reason, "link_seal_refused_no_pair");
        }
        other => panic!("a dial to the mismatched host must be refused by name: {other:?}"),
    }
    assert!(
        a.metrics
            .link_seal()
            .get("link_seal_refused_no_pair")
            .copied()
            .unwrap_or(0)
            >= 1
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), r_arrivals.recv())
            .await
            .is_err(),
        "nothing was dialled, so nothing arrived"
    );
}

// ─── CIRISEdge#915: a room peer's identity link is brought direct ───────

/// **#915** — a send to a ROOM peer reached through `T` proposes on the link it
/// shipped over, without an A/V call: the link moves onto a punched interface
/// and the room's later traffic rides it, with `T` gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_to_a_room_peer_brings_the_link_direct_915() {
    let mut p = trio("r915", proposer(), DirectLinksConfig::default()).await;
    // The room is shared both ways; no A/V leg is dialled.
    let (_spine, _b_addr) = open_call(&p).await;
    assert!(p.b.transport.should_accept_direct(&p.a.key.key_id));

    p.a.transport
        .send(&p.b.key.key_id, b"room-915-1")
        .await
        .expect("A's send to B ships through T");
    let up = next_event(&mut p.a.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("the send's link comes up direct");
    let DirectPathEvent::Established {
        peer,
        link_id,
        proposed,
        ..
    } = up
    else {
        unreachable!()
    };
    assert!(proposed, "A proposed");
    assert_eq!(peer.as_deref(), Some(p.b.key.key_id.as_str()));
    assert!(p.a.transport.direct_link_interface(link_id).is_some());
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 1);

    // A second send proposes nothing more: the peer is already direct.
    p.a.transport
        .send(&p.b.key.key_id, b"room-915-2")
        .await
        .expect("the second send");
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 1);

    // With T gone, the room's traffic still crosses.
    p.t.stop().await.expect("stop T");
    tokio::time::sleep(Duration::from_millis(500)).await;
    p.a.transport
        .send(&p.b.key.key_id, b"room-915-3")
        .await
        .expect("a send with T gone rides the punched interface");
}

/// **#915** — a send to a peer this node shares NO room with proposes
/// nothing: a proposal reveals this node's public address.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_outside_every_room_proposes_nothing_915() {
    let p = trio("n915", proposer(), DirectLinksConfig::default()).await;
    p.a.transport
        .send(&p.b.key.key_id, b"no-room-915")
        .await
        .expect("A's send to B ships through T");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 0);
    assert_eq!(p.a.transport.direct_path_state(&p.b.key.key_id), None);
}

/// **#920** — the live mesh's sequence: A, the room's creator, sends to B
/// before B has joined, so B refuses A's proposal. B then joins and replies
/// over A's own link (the reverse path), past leviculum's per-link proposal
/// cooldown. That reply proposes, B now shares the room, and the link comes up
/// direct. Before #920 the refusal was pinned to
/// the link and B's reverse-path sends never proposed, so the pair room
/// stayed relayed for good.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_peer_that_refused_before_joining_the_room_comes_up_direct_once_it_joins_920() {
    let mut p = trio("j920", proposer(), proposer()).await;
    let (_spine, _b_addr, b_snapshot) = open_call_deferring_b(&p).await;
    assert!(!p.b.transport.should_accept_direct(&p.a.key.key_id));

    p.a.transport
        .send(&p.b.key.key_id, b"before-b-joins")
        .await
        .expect("A's send to B ships through T");
    let refused = next_event(&mut p.a.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Failed { .. })
    })
    .await
    .expect("B refuses: it does not share the room yet");
    assert!(
        matches!(&refused, DirectPathEvent::Failed { reason, .. }
            if *reason == "direct_link_failed_rejected"),
        "{refused:?}"
    );

    let _ =
        p.b.lifecycle
            .install(&scope(), &b_snapshot)
            .expect("B joins the room");
    assert!(p.b.transport.should_accept_direct(&p.a.key.key_id));

    // leviculum binds both ends of a link to a cooldown after any proposal on
    // it (A's refused one included): inside it, B's proposal is refused BUSY
    // by A's node. Edge's retry base is that cooldown, so the next send after
    // it proposes; here that send is B's reply.
    tokio::time::sleep(
        ciris_edge::transport::direct_path::DIRECT_RETRY_BASE + Duration::from_secs(1),
    )
    .await;
    p.b.transport
        .send(&p.a.key.key_id, b"b-replies")
        .await
        .expect("B's reply rides A's link");
    let up = next_event(&mut p.b.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("B's reply brings the link direct");
    assert!(
        matches!(&up, DirectPathEvent::Established { proposed: true, peer, .. }
            if peer.as_deref() == Some(p.a.key.key_id.as_str())),
        "B proposed, to A: {up:?}"
    );
}

/// **Eric 2026-10-30** — two nodes that share NO room, but whose hosts named
/// each other consented contacts (a contact request sent and accepted), go
/// direct on the first send: the consent exchange rides the direct link at
/// once. A node that named no contact still proposes nothing
/// (`a_send_outside_every_room_proposes_nothing_915`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn consented_contacts_go_direct_without_a_room() {
    let mut p = trio("c1030", proposer(), DirectLinksConfig::default()).await;
    assert!(!p.b.transport.should_accept_direct(&p.a.key.key_id));
    assert!(p.a.transport.allow_direct_contact(&p.b.key.key_id));
    assert!(p.b.transport.allow_direct_contact(&p.a.key.key_id));
    assert!(p.b.transport.should_accept_direct(&p.a.key.key_id));

    p.a.transport
        .send(&p.b.key.key_id, b"contact-request")
        .await
        .expect("A's send to B ships through T");
    let up = next_event(&mut p.a.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("the contacts' link comes up direct");
    assert!(
        matches!(&up, DirectPathEvent::Established { proposed: true, peer, .. }
            if peer.as_deref() == Some(p.b.key.key_id.as_str())),
        "{up:?}"
    );

    p.b.transport.forget_direct_contact(&p.a.key.key_id);
    assert!(
        !p.b.transport.should_accept_direct(&p.a.key.key_id),
        "a withdrawn contact is no longer accepted"
    );
}
