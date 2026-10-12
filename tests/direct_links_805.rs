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
//!   A configured with `T`'s facilitator, B accepting `IdentifiedOnly`. A's A/V
//!   dial proposes on the identity link first. Both ends see the upgrade, the
//!   dial establishes over the punched interface, frames cross, and they still
//!   cross with `T` stopped. The identity link's Channel limit drops to
//!   1400-MTU size on the move (leviculum lowers the MTU and never raises it);
//!   the event carries both limits, which item 5's `BudgetChanged` reads.
//! - **W3** (`a_refused_upgrade_leaves_the_dial_as_it_was`): B at the default
//!   `Reject`. The proposal fails `Rejected`, the dial behaves exactly as with
//!   no proposal, and a second dial does NOT propose again on the refused link.
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
use ciris_edge::transport::av_spine::AvSpine;
use ciris_edge::transport::direct_path::{
    DirectAccept, DirectLinksConfig, DirectPathEvent, DirectPathState,
};
use ciris_edge::transport::federation_session::{OwnKexKeys, PeerKexPubkeys};
use ciris_edge::transport::realtime_av::{EpochDek, StreamId};
use ciris_edge::transport::realtime_av_dispatcher::{AvLinkReceiver as _, AvLinkSender as _};
use ciris_edge::transport::realtime_av_mls::{mint_joiner_key_material, Member};
use ciris_edge::transport::realtime_av_runtime::AvPublisher;
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
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    table: Arc<ScopeAddressTable>,
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
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id)
            .with_direct_links(direct.clone());
        c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
        c.bootstrap_peers = vec![format!("127.0.0.1:{t_port}").parse().unwrap()];
        c.announce_interval = Duration::from_secs(5);
        match ReticulumTransport::new(c, auth(key.signer(), dir)).await {
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
        transport,
        metrics,
        table,
        lifecycle,
        events,
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
    let snap = av_addressing::snapshot(&sub_session).expect("B's snapshot");
    let _ =
        p.b.lifecycle
            .install(&scope(), &snap)
            .expect("B installs the call");
    let group = av_addressing::stream_group_id(stream);
    let b_addr =
        p.a.table
            .send_address(&scope(), &group, &p.b.key.key_id)
            .expect("A derives B's call address");
    (spine, b_addr)
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

fn accepter() -> DirectLinksConfig {
    DirectLinksConfig {
        accept: DirectAccept::IdentifiedOnly,
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
    let mut p = trio("w1", proposer(), accepter()).await;
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
    assert_eq!(after, 1321, "1400-MTU Channel limit");
    assert!(
        before > after,
        "the move lowered the limit: {before} -> {after}"
    );
    let av_limit = link.sender.channel_limit().expect("the A/V link is held");
    assert!(
        av_limit <= after,
        "an A/V leg born on the punched interface carries no more than it: {av_limit}"
    );

    // Frames cross the A/V leg, then still cross with T gone.
    link.sender.send(b"direct-805-1").await.expect("send 1");
    let arrival = tokio::time::timeout(Duration::from_secs(20), arrivals.recv())
        .await
        .expect("B's consumer gets the link")
        .expect("arrivals open");
    assert_eq!(arrival.peer.as_str(), p.a.key.key_id);
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

/// **W3** — B refuses (the default). The proposal fails `Rejected`, the dial
/// behaves exactly as with no proposal, and a second dial does not propose
/// again on the refused link.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_refused_upgrade_leaves_the_dial_as_it_was() {
    let mut p = trio("w3", proposer(), DirectLinksConfig::default()).await;
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
