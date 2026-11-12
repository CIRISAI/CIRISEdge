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
//!   A/V leg itself is born on the punched interface at the path MTU the
//!   interface probed (leviculum#104; 1400 on loopback, Channel 1321), where
//!   before #104 it was the base MTU 500 (Channel 425).
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
    DirectAccept, DirectLinksConfig, DirectPathEvent, DirectPathState, Proposing,
};
use ciris_edge::transport::federation_session::{OwnKexKeys, PeerKexPubkeys};
use ciris_edge::transport::realtime_av::{
    seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, InnerSealed, StreamId, CODEC_OPAQUE,
};
use ciris_edge::transport::realtime_av_dispatcher::{
    AvDispatcher, AvDispatcherConfig, AvDispatcherError, AvInboundLink, AvLinkReceiver as _,
    AvLinkSender, AvRole, AvSubscriberLink,
};
use ciris_edge::transport::realtime_av_mls::{mint_joiner_key_material, Member};
use ciris_edge::transport::realtime_av_runtime::{AvPublisher, AvRelay, AvSubscriber, LegStreams};
use ciris_edge::transport::realtime_av_session::AvSession;
use ciris_edge::transport::reticulum::{
    LinkDirection, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
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
        hybrid_policy: ciris_edge::HybridPolicy::Strict,
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

/// One frame on an A/V leg, waiting out backpressure. A fresh leg's Channel
/// is in its first round trip: the opener's transit handshake is its first
/// message, the window starts at 2 and sends are paced, so a frame right
/// behind it can be refused `Congested` (leviculum's `Busy` or `PacingDelay`)
/// until acks come back. On CI darwin (the v44.0.0 tag run) they came after
/// the test's next send. `Congested` is backpressure, not a failure
/// (`AvLinkSender::send`); the call path waits it out the same way
/// (`av_call::send_patiently`).
async fn send_patiently(sender: &impl AvLinkSender, bytes: &[u8]) -> Result<(), AvDispatcherError> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match sender.send(bytes).await {
            Err(AvDispatcherError::Congested) if tokio::time::Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            other => return other,
        }
    }
}

/// `T`: a bare leviculum transport node with a TCP server and a facilitator,
/// the role a canonical plays. Its events are drained so its queue never
/// backs up.
///
/// On ports of its own. A port [`free_port`] named can be taken before the
/// bind, by anything on the host, so an address in use is a redraw.
async fn transport_node_on_free_ports() -> (ReticulumNode, u16, u16) {
    let mut left = 8;
    loop {
        let (t_port, f_port) = (free_port(), free_udp_port());
        match try_transport_node(t_port, f_port).await {
            Ok(node) => return (node, t_port, f_port),
            Err(e) if left > 0 => {
                left -= 1;
                tracing::debug!("T's ports were taken, redrawing: {e}");
            }
            Err(e) => panic!("start T: {e}"),
        }
    }
}

async fn try_transport_node(tcp_port: u16, facilitator_port: u16) -> Result<ReticulumNode, String> {
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
    node.start().await.map_err(|e| format!("{e:?}"))?;
    let mut rx = node.take_event_receiver().expect("T's events");
    tokio::spawn(async move { while rx.recv().await.is_some() {} });
    Ok(node)
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
    shaping: Option<&ciris_edge::transport::link_shaping::ShapingPolicy>,
) -> Side {
    side_cfg(key, dir, base, move |c| {
        let mut c = c.with_direct_links(direct.clone());
        c.bootstrap_peers = vec![format!("127.0.0.1:{t_port}").parse().unwrap()];
        if let Some(policy) = shaping {
            c.shaping = policy.clone();
            // An off node's class is its device's: a home node here.
            if !policy.enabled() {
                c.device = ciris_edge::transport::link_shaping::DeviceState::of(
                    ciris_edge::transport::link_shaping::DeviceKind::Home,
                );
            }
        }
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
            hybrid_policy: ciris_edge::HybridPolicy::Strict,
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
        Duration::from_mins(5),
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

/// A TCP pipe to `T` on `t_port` that holds the client's bytes toward `T` for
/// `held_ms` (read per chunk, so a test turns it on after setup), in order;
/// `T`'s bytes back pass at once. It gives the field's asymmetry a shape on
/// loopback: what `B` says reaches `A` late, what `A` says reaches `B` at once.
/// Returns the port to dial.
async fn held_uplink(t_port: u16, held_ms: Arc<std::sync::atomic::AtomicU64>) -> u16 {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the uplink");
    let port = listener.local_addr().expect("addr").port();
    tokio::spawn(async move {
        loop {
            let Ok((client, _)) = listener.accept().await else {
                return;
            };
            let Ok(upstream) = tokio::net::TcpStream::connect(("127.0.0.1", t_port)).await else {
                continue;
            };
            let (mut client_rx, mut client_tx) = client.into_split();
            let (mut up_rx, mut up_tx) = upstream.into_split();
            tokio::spawn(async move {
                let _ = tokio::io::copy(&mut up_rx, &mut client_tx).await;
            });
            let (tx, mut rx) = mpsc::unbounded_channel::<(tokio::time::Instant, Vec<u8>)>();
            let held = Arc::clone(&held_ms);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                while let Ok(n) = client_rx.read(&mut buf).await {
                    if n == 0 {
                        return;
                    }
                    let ms = held.load(std::sync::atomic::Ordering::Relaxed);
                    let due = tokio::time::Instant::now() + Duration::from_millis(ms);
                    if tx.send((due, buf[..n].to_vec())).is_err() {
                        return;
                    }
                }
            });
            tokio::spawn(async move {
                while let Some((due, bytes)) = rx.recv().await {
                    tokio::time::sleep_until(due).await;
                    if up_tx.write_all(&bytes).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    port
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
    trio_uplink(tag, a_direct, b_direct, None, None).await
}

/// [`trio`], with a side reaching `T` through a [`held_uplink`] when its uplink
/// is named.
async fn trio_uplink(
    tag: &str,
    a_direct: DirectLinksConfig,
    b_direct: DirectLinksConfig,
    a_uplink: Option<Arc<std::sync::atomic::AtomicU64>>,
    b_uplink: Option<Arc<std::sync::atomic::AtomicU64>>,
) -> Trio {
    trio_shaped(tag, a_direct, b_direct, a_uplink, b_uplink, None).await
}

/// [`trio_uplink`], with both sides on a shaping policy when one is named.
async fn trio_shaped(
    tag: &str,
    a_direct: DirectLinksConfig,
    b_direct: DirectLinksConfig,
    a_uplink: Option<Arc<std::sync::atomic::AtomicU64>>,
    b_uplink: Option<Arc<std::sync::atomic::AtomicU64>>,
    shaping: Option<(
        ciris_edge::transport::link_shaping::ShapingPolicy,
        ciris_edge::transport::link_shaping::ShapingPolicy,
    )>,
) -> Trio {
    init_tracing();
    let (a_shaping, b_shaping) = shaping.unzip();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (t, t_port, f_port) = transport_node_on_free_ports().await;
    let a_t_port = match a_uplink {
        Some(held) => held_uplink(t_port, held).await,
        None => t_port,
    };
    let b_t_port = match b_uplink {
        Some(held) => held_uplink(t_port, held).await,
        None => t_port,
    };
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
    let a = side(
        key_a,
        &a_dir,
        &tmp.path().join("a"),
        a_t_port,
        fill(a_direct),
        a_shaping.as_ref(),
    )
    .await;
    let b = side(
        key_b,
        &b_dir,
        &tmp.path().join("b"),
        b_t_port,
        fill(b_direct),
        b_shaping.as_ref(),
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
    // Each asks for the other: T's announce rate limit stops relaying a node
    // after its grace (about 30 s at 5 s), so a node that starts later on a
    // loaded box would wait for an announce that is not coming.
    let known = wait_until(Duration::from_mins(1), || async {
        a.transport.seek_peer(&b.key.key_id).await && b.transport.seek_peer(&a.key.key_id).await
    })
    .await;
    assert!(known, "A and B reach each other through T");
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

/// **W4** — proposing `off`, and an unresolved default: no proposal
/// anywhere, leviculum's retry off, and a call member behind `T` cannot be
/// reached on its derived address. This is the gap item 8 closes; W1 is the
/// same dial with a facilitator (v44's resolved default).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proposing_off_never_proposes_and_a_member_behind_t_is_unreachable() {
    let p = trio(
        "w4",
        DirectLinksConfig {
            proposing: Proposing::Off,
            facilitator: Some("127.0.0.1:1".to_owned()),
            ..DirectLinksConfig::default()
        },
        DirectLinksConfig::default(),
    )
    .await;
    assert!(
        !p.a.transport.direct_link_retry_enabled(),
        "off: no retry either"
    );
    assert!(
        !p.b.transport.direct_link_retry_enabled(),
        "an unresolved default proposes nothing, so no retry"
    );
    let (_spine, b_addr) = open_call(&p).await;
    match p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await {
        Err(TransportError::NoRouteToPeer { .. }) => {}
        other => panic!("a derived address behind T answers no dial: {other:?}"),
    }
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 0);
    // v44 — silence here used to read like idle: it says why it is silent, and
    // nothing else moved.
    assert_eq!(dl(&p.a.metrics, "direct_link_off:proposing_off"), 1);
    assert_eq!(
        p.a.metrics.direct_link().len(),
        1,
        "the default touches nothing else: {:?}",
        p.a.metrics.direct_link()
    );
    assert_eq!(p.a.metrics.snapshot().direct_link_proposing, 0);
    assert_eq!(p.a.transport.direct_path_state(&p.b.key.key_id), None);
}

/// Both ends' row policy, at the server class's rate: everything offers.
fn shaping_all(strict: bool) -> ciris_edge::transport::link_shaping::ShapingPolicy {
    use ciris_edge::transport::link_shaping::{BudgetClass, ShapingPolicy, ShapingScope};
    let mut p = ShapingPolicy::fleet_default(BudgetClass::Server);
    p.scope = ShapingScope::AllIdentityLinks;
    p.require_shaped_links = strict;
    p
}

fn shaped(m: &EdgeMetrics, label: &str) -> u64 {
    m.link_shaping().get(label).copied().unwrap_or(0)
}

/// A row with a recognisable body, small enough to be a row.
fn a_row(marker: &[u8]) -> Vec<u8> {
    let mut row = marker.to_vec();
    row.resize(2_000, b'r');
    row
}

/// **CC 5.4.3 `CLM-shaped-link-one-hop`** — A and B both shape, and only `T`
/// joins them. A's row crosses sealed and unshaped: nothing is offered, and no
/// shaper ever runs at either end. Mutation: offer through the forwarder →
/// this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_link_is_never_shaped() {
    let p = trio_shaped(
        "fw",
        DirectLinksConfig::default(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((shaping_all(false), shaping_all(false))),
    )
    .await;
    p.a.transport
        .send(&p.b.key.key_id, &a_row(b"FW-ROW-"))
        .await
        .expect("a row crosses the forwarder, sealed and unshaped");
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(shaped(&p.a.metrics, "link_shaping_unshaped:forwarded"), 1);
    assert_eq!(shaped(&p.a.metrics, "link_shaping_offered"), 0);
    assert_eq!(shaped(&p.a.metrics, "link_shaping_agreed"), 0);
    assert_eq!(shaped(&p.b.metrics, "link_shaping_agreed"), 0);
    assert_eq!(shaped(&p.a.metrics, "link_shaping_frames_real"), 0);
}

/// The other end of that rule. A dialler older than the rule offers through the
/// forwarder, and B, which holds a two-hop path to it, answers `off`: the link
/// stays unshaped at both ends and the row still crosses. Mutation: the
/// responder answers as if direct → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_forwarded_offer_is_answered_off() {
    let p = trio_shaped(
        "fwa",
        DirectLinksConfig::default(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((shaping_all(false), shaping_all(false))),
    )
    .await;
    p.a.transport.set_offer_forwarded_for_test(true);
    p.a.transport
        .send(&p.b.key.key_id, &a_row(b"FWA-ROW-"))
        .await
        .expect("the row crosses unshaped");
    assert_eq!(shaped(&p.a.metrics, "link_shaping_offered:dialled"), 1);
    assert!(
        wait_until(Duration::from_secs(30), || async {
            shaped(&p.b.metrics, "link_shaping_unshaped:forwarded") == 1
        })
        .await,
        "B saw the forwarder: {:?}",
        p.b.metrics.link_shaping()
    );
    assert_eq!(shaped(&p.a.metrics, "link_shaping_agreed"), 0);
    assert_eq!(shaped(&p.b.metrics, "link_shaping_agreed"), 0);
}

/// CC 5.4.3 — the same pair with a punched path. The first `SHAP` goes out at
/// `DirectLinkEstablished`, the frame is the link's MDU, and the class's
/// bytes/s hold at that frame. When the link falls back onto the forwarder the
/// shaped link closes. Mutations: no offer on the move, or no close on the
/// fall back → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_link_that_goes_direct_shapes_at_the_mdu_and_closes_when_it_falls_back() {
    let policy = shaping_all(false);
    let budget = policy.bytes_per_s;
    let mut p = trio_shaped(
        "up",
        proposer(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((policy.clone(), policy)),
    )
    .await;
    let (_spine, _b_addr) = open_call(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, &a_row(b"UP-ROW-"))
        .await
        .expect("the row crosses the forwarder and the proposal follows it");
    let up = next_event(&mut p.a.events, Duration::from_secs(30), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("A's Established");
    let DirectPathEvent::Established { link_id, .. } = up else {
        unreachable!()
    };
    assert!(
        wait_until(Duration::from_secs(30), || async {
            p.a.transport.shaped_agreement_for_test(link_id).is_some()
                && p.b.transport.shaped_agreement_for_test(link_id).is_some()
        })
        .await,
        "shaped both ways: {:?}",
        p.a.metrics.link_shaping()
    );
    assert_eq!(shaped(&p.a.metrics, "link_shaping_offered:dialled"), 1);
    assert_eq!(shaped(&p.b.metrics, "link_shaping_offered:answered"), 1);
    let (frame, bytes_per_s) =
        p.a.transport
            .shaped_agreement_for_test(link_id)
            .expect("shaped");
    assert_eq!(
        usize::from(frame),
        p.a.transport.link_channel_mdu_for_test(link_id),
        "the frame is the punched link's MDU"
    );
    assert!(
        (1_000..=1_400).contains(&frame),
        "about 1.3 KB on a punched link: {frame}"
    );
    assert!(
        bytes_per_s.abs_diff(budget) * 100 <= budget,
        "the class's budget holds by frame rate: {bytes_per_s} against {budget}"
    );

    // The call's leg is not this link: only the move off the punched interface
    // can close it.
    p.a.transport
        .fall_back_from_direct([0xee; 16], Some(link_id))
        .await;
    assert!(
        wait_until(Duration::from_secs(15), || async {
            p.a.transport.shaped_agreement_for_test(link_id).is_none()
        })
        .await,
        "the shaped link closed with its direct path"
    );
    assert_eq!(shaped(&p.a.metrics, "link_shaping_direct_lost"), 1);
}

/// **`CLM-shaping-offered-never-refused`** — A is shaped-only and B has shaping
/// off. Through the forwarder there is no shaped link to give, so A's row
/// refuses; on the direct path B answers at its own device class, the link runs
/// at the lower of the two, and the row goes. Mutation: an off node refuses to
/// be asked → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_off_node_gives_a_shaped_only_peer_a_shaped_link_on_a_direct_path() {
    use ciris_edge::transport::link_shaping::{BudgetClass, ShapingPolicy};
    let mut p = trio_shaped(
        "asked",
        proposer(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((shaping_all(true), ShapingPolicy::default())),
    )
    .await;
    let (_spine, _b_addr) = open_call(&p).await;
    let row = a_row(b"ASKED-ROW-");
    let err =
        p.a.transport
            .send(&p.b.key.key_id, &row)
            .await
            .expect_err("forwarded: nothing to shape, so a shaped-only node refuses");
    assert!(
        err.to_string().contains("link_shaping_no_direct_path"),
        "{err}"
    );
    let up = next_event(&mut p.a.events, Duration::from_secs(30), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("A's Established");
    let DirectPathEvent::Established { link_id, .. } = up else {
        unreachable!()
    };
    assert!(
        wait_until(Duration::from_secs(30), || async {
            p.a.transport.send(&p.b.key.key_id, &row).await.is_ok()
        })
        .await,
        "the row goes: {:?}",
        p.a.metrics.link_shaping()
    );
    assert_eq!(
        shaped(&p.b.metrics, "link_shaping_offered"),
        1,
        "B answered"
    );
    assert_eq!(shaped(&p.b.metrics, "link_shaping_agreed:asked"), 1);
    let (_, bytes_per_s) =
        p.a.transport
            .shaped_agreement_for_test(link_id)
            .expect("shaped");
    let home = ShapingPolicy::for_class(BudgetClass::Home).bytes_per_s;
    assert!(
        bytes_per_s.abs_diff(home) * 100 <= home,
        "the lower of the two, B's class: {bytes_per_s} against {home}"
    );
}

/// Two nodes with shaping off stay unshaped on a direct path: nobody asked.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn off_with_off_stays_unshaped_on_a_direct_path() {
    use ciris_edge::transport::link_shaping::ShapingPolicy;
    let mut p = trio_shaped(
        "offoff",
        proposer(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((ShapingPolicy::default(), ShapingPolicy::default())),
    )
    .await;
    let (_spine, _b_addr) = open_call(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, &a_row(b"OFFOFF-ROW-"))
        .await
        .expect("an ordinary row");
    assert!(
        next_event(&mut p.a.events, Duration::from_secs(30), |e| {
            matches!(e, DirectPathEvent::Established { .. })
        })
        .await
        .is_some(),
        "the link went direct"
    );
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(shaped(&p.a.metrics, "link_shaping_offered"), 0);
    assert_eq!(shaped(&p.b.metrics, "link_shaping_offered"), 0);
    assert_eq!(shaped(&p.a.metrics, "link_shaping_agreed"), 0);
    assert_eq!(shaped(&p.b.metrics, "link_shaping_agreed"), 0);
}

/// CC 5.4.3 — under `require_shaped_links` a row to a peer with no direct path
/// refuses by name, and the link stays up with its proposal already out, so the
/// next try finds a shaped link. Refuse before proposing and this deadlocks:
/// mutation: drop the proposal → this fails.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_required_shaped_link_proposes_before_it_refuses_and_the_rung_opens() {
    let mut p = trio_shaped(
        "rung",
        proposer(),
        DirectLinksConfig::default(),
        None,
        None,
        Some((shaping_all(true), shaping_all(false))),
    )
    .await;
    let (_spine, _b_addr) = open_call(&p).await;
    let row = a_row(b"RUNG-ROW-");
    let err =
        p.a.transport
            .send(&p.b.key.key_id, &row)
            .await
            .expect_err("no direct path yet: the row is refused");
    assert!(
        err.to_string().contains("link_shaping_no_direct_path"),
        "by name: {err}"
    );
    assert!(
        next_event(&mut p.a.events, Duration::from_secs(30), |e| {
            matches!(e, DirectPathEvent::Established { .. })
        })
        .await
        .is_some(),
        "the refusal did not stop the proposal"
    );
    assert!(
        wait_until(Duration::from_secs(30), || async {
            p.a.transport.send(&p.b.key.key_id, &row).await.is_ok()
        })
        .await,
        "the row goes once the link is direct and shaped: {:?}",
        p.a.metrics.link_shaping()
    );
    assert_eq!(
        shaped(&p.a.metrics, "link_shaping_agreed"),
        1,
        "no row went ahead of the shaper"
    );
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
    assert!(
        p.a.transport.direct_link_retry_enabled(),
        "v44: a proposing node keeps leviculum's background re-proposal"
    );
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
    // leviculum#104 — the A/V leg is BORN on the punched interface, which now
    // probes the path (1400, then 1280) and signals the largest step acked;
    // loopback acks 1400. So the leg runs at the probed MTU, as the moved
    // identity link does: Channel 1321, 1296 of it plaintext under the CC
    // 5.3.3.5 E1 seal. Before #104 it negotiated the base 500 (400 sealed).
    assert_eq!(
        av_limit, 1296,
        "the A/V leg runs at the probed 1400-byte MTU"
    );
    // leviculum#102 — a datagram on it carries the link MDU less its 4-byte
    // sequence number, less the seal: two bytes more than a Channel message.
    assert_eq!(link.sender.datagram_limit(), Some(1298));

    // CIRISEdge#805 / CC 5.3.3.5 E1 — the link's transit KEX handshake rode
    // this leg as its first Channel messages, and B answered it: both ends
    // hold the link's keys, by role.
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
    send_patiently(&link.sender, b"direct-805-1")
        .await
        .expect("send 1");
    let got = tokio::time::timeout(Duration::from_secs(10), arrival.inbound.recv())
        .await
        .expect("frame 1 in time")
        .expect("frame 1");
    assert_eq!(got, b"direct-805-1");

    p.t.stop().await.expect("stop T");
    tokio::time::sleep(Duration::from_millis(500)).await;
    send_patiently(&link.sender, b"direct-805-2")
        .await
        .expect("send 2");
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
        a.transport.seek_peer(&b.key.key_id).await
            && b.transport.seek_peer(&a.key.key_id).await
            && a.transport.seek_peer(&r.key.key_id).await
            && b.transport.seek_peer(&r.key.key_id).await
            && c.transport.seek_peer(&r.key.key_id).await
            && r.transport.seek_peer(&c.key.key_id).await
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
    // leviculum v0.33 grew the node; box the fixture future (clippy::large_futures).
    let q = Box::pin(quad("w2")).await;
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
    // leviculum v0.33 grew the node; box the fixture future (clippy::large_futures).
    let q = Box::pin(quad("w2b")).await;
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

    // A row from A: an identity link, inbound at R and on no punched interface.
    // A's call must not hold it: only a punched link is held for a call.
    q.a.transport
        .send(&r_id, b"row-from-a")
        .await
        .expect("A's row to R");
    let a_dialled: Vec<[u8; 16]> =
        q.a.transport
            .link_directions_for_test()
            .into_iter()
            .filter(|(_, d)| *d == LinkDirection::Outbound)
            .map(|(id, _)| id)
            .collect();
    let identity_from_a =
        |planes: Vec<([u8; 16], ciris_edge::transport::reticulum::LinkPlane, bool)>| {
            planes
                .iter()
                .filter(|(id, plane, _)| {
                    *plane == ciris_edge::transport::reticulum::LinkPlane::Identity
                        && a_dialled.contains(id)
                })
                .count()
        };
    assert_eq!(
        identity_from_a(q.r.transport.link_planes_for_test().await),
        1,
        "the row's link"
    );

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
    assert_eq!(
        identity_from_a(q.r.transport.link_planes_for_test().await),
        0,
        "a relayed identity link ages through its peer's call"
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
    // leviculum v0.33 grew the node; box the fixture future (clippy::large_futures).
    let q = Box::pin(quad("w7")).await;
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
        wait_until(Duration::from_mins(1), || async {
            a.transport.seek_peer(&r_id).await && r.transport.seek_peer(&a_id).await
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
/// cooldown. B is that link's responder, so its reply yields to A (v44,
/// leviculum#96); A has nothing more to send, so B's timer proposes, B now
/// shares the room, and the link comes up direct. Before #920 the refusal was
/// pinned to the link and B's reverse-path sends never proposed, so the pair
/// room stayed relayed for good.
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
    let wait = ciris_edge::transport::direct_path::GLARE_WAIT.mul_f64(1.25);
    let up = next_event(&mut p.b.events, wait + Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("B's reply brings the link direct");
    assert_eq!(dl(&p.b.metrics, "direct_link_yielded"), 1);
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

/// **ALM stage 2 / #926 on a punched path** — leviculum v0.33's two-sided
/// punch brings A↔B direct (both ends `Established`, each having proven the
/// address both ways), and the #926 stall guard then watches that punched
/// identity link: when the peer stops acknowledging on it (the 2026-10-31
/// one-sided-punch symptom), three zero-landing Channel sends judge it dead
/// and the guard moves it OFF the punched interface back onto its relayed
/// path (leviculum#83 `retire_direct_link`) instead of retrying it for
/// minutes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_punched_link_that_stops_acking_is_retired_by_the_stall_guard() {
    let mut p = trio("w926", proposer(), DirectLinksConfig::default()).await;
    let (_spine, b_addr) = open_call(&p).await;
    let _arrivals = p.b.transport.take_av_arrivals().expect("B's arrivals");
    let _link =
        p.a.transport
            .open_av_link(&p.b.key.key_id, &b_addr)
            .await
            .expect("A reaches B over the punched interface");
    let DirectPathEvent::Established {
        link_id: identity_link,
        ..
    } = next_event(&mut p.a.events, Duration::from_secs(5), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("A's Established")
    else {
        unreachable!()
    };
    // Two-sided: B moved too (v0.33: an address proven both ways).
    next_event(&mut p.b.events, Duration::from_secs(10), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("B's Established");
    assert!(p.a.transport.direct_link_interface(identity_link).is_some());

    // The peer stops acknowledging on the punched link.
    assert!(
        wait_until(Duration::from_secs(10), || async {
            p.a.transport.link_channel_settled_for_test(identity_link)
        })
        .await
    );
    p.a.transport
        .stop_acks_on_link_for_test(identity_link, Some(0));
    let frame = vec![0x5a; 64];
    for _ in 0..3 {
        let (sent, total) =
            p.a.transport
                .send_channel_for_test(identity_link, &frame)
                .await;
        assert_eq!(sent, 0, "nothing lands ({sent}/{total})");
    }
    p.a.transport
        .stop_acks_on_link_for_test(identity_link, None);
    let retired = wait_until(Duration::from_secs(10), || async {
        p.a.transport.direct_link_interface(identity_link).is_none()
    })
    .await;
    assert!(
        retired,
        "the stall guard moved the dead punched link off its interface: stall={:?}",
        p.a.transport.link_stall_for_test(identity_link)
    );
    let (zero, dead) = p.a.transport.link_stall_for_test(identity_link);
    assert!(
        !dead && zero == 0,
        "a fresh run on the relayed path: ({zero}, {dead})"
    );
}

// ─── v44: proposal glare (leviculum#96) ─────────────────────────────────

/// The one identity link both `a` and `b` hold between them: `a` dialled
/// it (Outbound on `a`), `b` accepted it (Inbound on `b`).
fn shared_link(a: &Side, b: &Side) -> [u8; 16] {
    let outbound: Vec<[u8; 16]> = a
        .transport
        .link_directions_for_test()
        .into_iter()
        .filter(|(_, d)| *d == LinkDirection::Outbound)
        .map(|(id, _)| id)
        .collect();
    b.transport
        .link_directions_for_test()
        .into_iter()
        .filter(|(id, d)| *d == LinkDirection::Inbound && outbound.contains(id))
        .map(|(id, _)| id)
        .next()
        .expect("one link A dialled to B")
}

/// **Glare** — both ends want the same link direct at the same instant. The
/// link's initiator (A) proposes; the responder (B) yields instead of
/// proposing, so leviculum never refuses either `Rejected(2)`, and the link
/// goes direct on the first attempt. Mutation: a tie-break that never yields
/// has both propose, both refused `REJECT_BUSY`, nothing direct.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn simultaneous_proposals_resolve_to_the_initiator_with_no_rejected_pair() {
    let mut p = trio("glare", proposer(), proposer()).await;
    // The identity link first, with no room yet so the send proposes nothing.
    p.a.transport
        .send(&p.b.key.key_id, b"glare-0")
        .await
        .expect("A's send to B ships through T");
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 0);
    let link = shared_link(&p.a, &p.b);
    // Now the room, and both propose on that link at once.
    let (_spine, _b_addr) = open_call(&p).await;
    let (ra, rb) = tokio::join!(
        p.a.transport
            .propose_direct_on_link_for_test(&p.b.key.key_id, link),
        p.b.transport
            .propose_direct_on_link_for_test(&p.a.key.key_id, link),
    );
    let settled = |e: &DirectPathEvent| {
        matches!(
            e,
            DirectPathEvent::Established { .. } | DirectPathEvent::Failed { .. }
        )
    };
    let a_up = next_event(&mut p.a.events, Duration::from_secs(20), settled)
        .await
        .expect("A's outcome");
    let b_up = next_event(&mut p.b.events, Duration::from_secs(20), settled)
        .await
        .expect("B's outcome");
    let (a_rej, b_rej) = (
        dl(&p.a.metrics, "direct_link_failed_rejected"),
        dl(&p.b.metrics, "direct_link_failed_rejected"),
    );
    assert!(
        a_rej == 0 && b_rej == 0,
        "the Rejected(2) pair: A={ra} rejected={a_rej}, B={rb} rejected={b_rej}"
    );
    assert_eq!(ra, "proposed", "the initiator proposes");
    assert_eq!(rb, "yield_to_initiator", "the responder yields");
    assert!(matches!(
        a_up,
        DirectPathEvent::Established { proposed: true, .. }
    ));
    assert!(matches!(
        b_up,
        DirectPathEvent::Established {
            proposed: false,
            ..
        }
    ));
    assert_eq!(dl(&p.a.metrics, "direct_link_proposed"), 1);
    assert_eq!(dl(&p.b.metrics, "direct_link_proposed"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_yielded"), 1);
    assert_eq!(dl(&p.a.metrics, "direct_link_failed_rejected"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_failed_rejected"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_request_accepted"), 1);
}

/// **The yield is never before mutual.** A named B a contact; B did not name
/// A and shares no room with it. A's proposal is refused by B's host
/// (`shares_room=false` before anything else, as the baseline's first
/// attempt was), and B neither yields nor proposes: with no standing there
/// is nothing to yield to.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_yield_never_happens_before_mutual() {
    let mut p = trio("glare-m", proposer(), proposer()).await;
    assert!(p.a.transport.allow_direct_contact(&p.b.key.key_id));
    p.a.transport
        .send(&p.b.key.key_id, b"glare-m-0")
        .await
        .expect("A's send to B ships through T");
    // A's send proposed (A has standing); B refused: no room, no contact.
    let asked = next_event(&mut p.b.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Requested { .. })
    })
    .await
    .expect("B is asked");
    assert!(matches!(
        asked,
        DirectPathEvent::Requested {
            accepted: false,
            ..
        }
    ));
    let link = shared_link(&p.a, &p.b);
    let rb =
        p.b.transport
            .propose_direct_on_link_for_test(&p.a.key.key_id, link)
            .await;
    assert_eq!(rb, "no_standing", "B neither yields nor proposes");
    assert_eq!(dl(&p.b.metrics, "direct_link_yielded"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_proposed"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_request_refused"), 1);
    assert!(
        wait_until(Duration::from_secs(20), || async {
            dl(&p.a.metrics, "direct_link_failed_rejected") >= 1
        })
        .await,
        "A's proposal was refused by policy"
    );
    assert_eq!(
        p.a.transport.direct_path_state(&p.b.key.key_id),
        Some(DirectPathState::BackingOff)
    );
}

/// B's address for call member `member`, on the call `open_call` makes.
fn call_address(side: &Side, member: &str) -> MemberAddress {
    let stream = StreamId(sha2::Sha256::digest(b"av-stream-805-direct").into());
    side.table
        .send_address(&scope(), &av_addressing::stream_group_id(stream), member)
        .expect("the member's call address")
}

/// **The responder's call dial never yields** — B holds A's link only as its
/// responder, A never proposes, and B's call dial is the only thing that wants
/// the path direct. The derived address answers nothing behind `T`, so a dial
/// that yielded would fail. It does not yield: a call's identity lane comes
/// from the pool of links this node dialled (`dial_and_identify`), so B is the
/// initiator of the link it proposes on, and proposes at once.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_responders_call_dial_gets_a_direct_path_when_the_initiator_never_proposes() {
    let p = trio("glare-d", proposer(), proposer()).await;
    p.a.transport
        .send(&p.b.key.key_id, b"glare-d-0")
        .await
        .expect("A's send to B ships through T");
    let _link = shared_link(&p.a, &p.b);
    let (_spine, _b_addr) = open_call(&p).await;
    let a_addr = call_address(&p.b, &p.a.key.key_id);
    let t0 = std::time::Instant::now();
    let dial = p.b.transport.open_av_link(&p.a.key.key_id, &a_addr).await;
    let took = t0.elapsed();
    eprintln!(
        "RESPONDER-DIAL ok={} took={took:?} yielded={} proposed={}",
        dial.is_ok(),
        dl(&p.b.metrics, "direct_link_yielded"),
        dl(&p.b.metrics, "direct_link_proposed"),
    );
    assert!(dial.is_ok(), "the dial reaches A: {:?}", dial.err());
    assert_eq!(dl(&p.b.metrics, "direct_link_proposed"), 1);
    assert_eq!(
        dl(&p.b.metrics, "direct_link_yielded"),
        0,
        "a dial never yields"
    );
    assert!(took < ciris_edge::transport::direct_path::DIRECT_PATH_BUDGET);
}

/// **Both ends dial the call at once**, which is every call start: each member
/// dials each other member. Each proposes on the link it dialled, so the two
/// proposals never cross on one link: both dials reach their member, neither
/// yields, and neither end is refused `Rejected(2)`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn both_ends_dialling_a_call_propose_on_their_own_links() {
    let p = trio("glare-b", proposer(), proposer()).await;
    p.a.transport
        .send(&p.b.key.key_id, b"glare-b-0")
        .await
        .expect("A's send to B ships through T");
    let _link = shared_link(&p.a, &p.b);
    let (_spine, b_addr) = open_call(&p).await;
    let a_addr = call_address(&p.b, &p.a.key.key_id);
    let t0 = std::time::Instant::now();
    let (from_a, from_b) = tokio::join!(
        async {
            let r = p.a.transport.open_av_link(&p.b.key.key_id, &b_addr).await;
            (r, t0.elapsed())
        },
        async {
            let r = p.b.transport.open_av_link(&p.a.key.key_id, &a_addr).await;
            (r, t0.elapsed())
        },
    );
    eprintln!(
        "BOTH-DIAL a_ok={} a_took={:?} b_ok={} b_took={:?} a_prop={} b_prop={} a_rej={} b_rej={}",
        from_a.0.is_ok(),
        from_a.1,
        from_b.0.is_ok(),
        from_b.1,
        dl(&p.a.metrics, "direct_link_proposed"),
        dl(&p.b.metrics, "direct_link_proposed"),
        dl(&p.a.metrics, "direct_link_failed_rejected"),
        dl(&p.b.metrics, "direct_link_failed_rejected"),
    );
    assert!(from_a.0.is_ok(), "A's dial: {:?}", from_a.0.err());
    assert!(from_b.0.is_ok(), "B's dial: {:?}", from_b.0.err());
    assert_eq!(dl(&p.a.metrics, "direct_link_failed_rejected"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_failed_rejected"), 0);
    assert_eq!(dl(&p.a.metrics, "direct_link_yielded"), 0);
    assert_eq!(dl(&p.b.metrics, "direct_link_yielded"), 0);
}

/// **A yield's timer stands down under suspend**: B yields, the transport
/// suspends, and the timer's turn comes and goes without a proposal.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_yields_timer_does_not_propose_while_suspended() {
    let p = trio("glare-s", proposer(), proposer()).await;
    p.a.transport
        .send(&p.b.key.key_id, b"glare-s-0")
        .await
        .expect("A's send to B ships through T");
    let link = shared_link(&p.a, &p.b);
    let (_spine, _b_addr) = open_call(&p).await;
    assert_eq!(
        p.b.transport
            .propose_direct_on_link_for_test(&p.a.key.key_id, link)
            .await,
        "yield_to_initiator"
    );
    let _ = p.b.transport.suspend(Duration::from_secs(5)).await;
    assert!(p.b.transport.is_suspended());
    tokio::time::sleep(
        ciris_edge::transport::direct_path::GLARE_WAIT.mul_f64(1.25) + Duration::from_secs(1),
    )
    .await;
    assert_eq!(dl(&p.b.metrics, "direct_link_proposed"), 0);
}

/// **v44 — one side moves, the other holds.** The wedge of the first cross-NAT
/// run (agent run 42157633553), with the real path: `A` proposes on its
/// identity link, both punches land, and one side's COMPLETE arrives late, so
/// the other is on the punched interface at the direct MTU while this one is
/// still committing on the relay at the link's old one. A frame this side
/// ships now is advertised to a peer that has already lowered its MTU: the
/// peer sizes the parts from its own MTU, refuses every part this side cuts
/// (`InvalidPart`, `len=16348`), and leviculum holds this side's move on the
/// Resource that cannot finish. Returns the behind side's metrics.
///
/// `proposer_behind` picks the side that sends: `A`, or the accepting `B`.
/// `pinned` sends on the upgrading link itself, as an answer does.
async fn one_side_moves_the_other_sends(
    tag: &str,
    proposer_behind: bool,
    pinned: bool,
) -> EdgeMetrics {
    use ciris_edge::transport::{ReplyPath, TransportId};
    use std::sync::atomic::{AtomicU64, Ordering};
    // How long the behind side stays behind, and so the headroom a slow runner
    // has for the send below to start inside the window. On from before the
    // link is dialled: the Channel has to learn this RTT, or a hold that
    // appears on a millisecond link exhausts its retries and closes it.
    const HOLD: Duration = Duration::from_secs(2);

    let held = Arc::new(AtomicU64::new(0));
    // The ahead side's bytes are the late ones: it moves on the behind side's
    // COMPLETE at once, and the behind side hears its COMPLETE a HOLD later.
    let (a_uplink, b_uplink) = if proposer_behind {
        (None, Some(Arc::clone(&held)))
    } else {
        (Some(Arc::clone(&held)), None)
    };
    let mut p = trio_uplink(
        tag,
        proposer(),
        DirectLinksConfig::default(),
        a_uplink,
        b_uplink,
    )
    .await;
    held.store(u64::try_from(HOLD.as_millis()).unwrap(), Ordering::Relaxed);
    // A's first send, before any room: the link exists and nothing proposes.
    p.a.transport
        .send(&p.b.key.key_id, b"before-the-room")
        .await
        .expect("A's send to B ships through T");
    let (_spine, _b_addr) = open_call(&p).await;
    let link = shared_link(&p.a, &p.b);

    let proposed =
        p.a.transport
            .propose_direct_on_link_for_test(&p.b.key.key_id, link)
            .await;
    assert_eq!(proposed, "proposed");
    let (behind, ahead) = if proposer_behind {
        (&mut p.a, &mut p.b)
    } else {
        (&mut p.b, &mut p.a)
    };
    let moved = next_event(&mut ahead.events, Duration::from_secs(30), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("the side ahead moves: the other's COMPLETE reached it");
    assert!(
        matches!(&moved, DirectPathEvent::Established { proposed, .. }
            if *proposed != proposer_behind),
        "{moved:?}"
    );
    assert!(
        behind.transport.direct_link_interface(link).is_none(),
        "the side behind has not moved: the COMPLETE is still on the held uplink"
    );

    // Over the Channel-first cap, so this is a Resource by size; random so it
    // does not compress below it.
    let mut frame = vec![0u8; 400 * 1024];
    ciris_crypto::random::fill(&mut frame).expect("random frame");
    let sender = Arc::clone(&behind.transport);
    let to = ahead.key.key_id.clone();
    let in_flight = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let sent = if pinned {
            let path = ReplyPath::new(TransportId::RETICULUM_RS, link);
            sender.send_on_reply_path_only(&to, &path, &frame).await
        } else {
            sender.send(&to, &frame).await
        };
        (sent, started.elapsed())
    });

    let up = next_event(&mut behind.events, HOLD + Duration::from_secs(25), |e| {
        matches!(
            e,
            DirectPathEvent::Established { .. } | DirectPathEvent::Failed { .. }
        )
    })
    .await;
    assert!(
        matches!(&up, Some(DirectPathEvent::Established { .. })),
        "the side behind moves once the COMPLETE lands, a frame in flight or not: {up:?}"
    );
    assert!(behind.transport.direct_link_interface(link).is_some());
    let (sent, took) = tokio::time::timeout(Duration::from_mins(1), in_flight)
        .await
        .expect("the send ends")
        .expect("the send task");
    sent.unwrap_or_else(|e| panic!("the frame is delivered ({took:?}): {e:?}"));

    // The outcome ends the guard: the same size on the same link now ships
    // with nothing refused, at the MTU both ends hold.
    let total = |m: &EdgeMetrics| m.direct_link_upgrade_guarded().values().sum::<u64>();
    let refused = total(&behind.metrics);
    let mut again = vec![0u8; 400 * 1024];
    ciris_crypto::random::fill(&mut again).expect("random frame");
    let path = ReplyPath::new(TransportId::RETICULUM_RS, link);
    behind
        .transport
        .send_on_reply_path_only(&ahead.key.key_id, &path, &again)
        .await
        .expect("a frame on the moved link");
    assert_eq!(
        total(&behind.metrics),
        refused,
        "the guard ended at the move"
    );
    behind.metrics.clone()
}

fn guarded(m: &EdgeMetrics, label: &str) -> u64 {
    m.direct_link_upgrade_guarded()
        .get(label)
        .copied()
        .unwrap_or(0)
}

/// The proposer behind, sending by key: its dialled lane is upgrading, so the
/// pool passes over it and the frame takes another lane.
/// Mutation: the pool's filter gone, the send takes the upgrading link and the
/// ship refusal is what counts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_send_by_key_during_an_upgrade_takes_another_lane() {
    let m = Box::pin(one_side_moves_the_other_sends("upg-key", true, false)).await;
    assert!(guarded(&m, "upgrade_guarded_pool") > 0);
    assert_eq!(guarded(&m, "upgrade_guarded_ship"), 0);
}

/// The proposer behind, answering on the upgrading link: no other lane may
/// carry it. The send gets `Busy`, its Channel fragments (cut for the old MTU)
/// do not finish before the move shrinks the link under them, and the bounded
/// retry ships the Resource once this side has moved: the upgrade finished
/// first, and the frame is cut for the MTU both ends hold.
/// Mutation: the ship refusal gone, the wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_answer_pinned_to_an_upgrading_link_waits_for_the_move() {
    let m = Box::pin(one_side_moves_the_other_sends("upg-pin", true, true)).await;
    assert!(guarded(&m, "upgrade_guarded_ship") > 0);
}

/// The ACCEPTOR behind: it knows of the upgrade only by the peer's request.
/// Mutation: no acceptance record, the wedge.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_acceptor_sending_during_an_upgrade_starts_no_resource() {
    let m = Box::pin(one_side_moves_the_other_sends("upg-acc", false, false)).await;
    assert!(guarded(&m, "upgrade_guarded_ship") > 0);
}

/// A/V up to a punched interface, with `B`'s inbound idle bound short. Returns
/// the trio, the leg's two ends, and the identity link the interface belongs
/// to: on `B` it is an inbound link that media never touches.
async fn call_on_a_punched_interface(
    tag: &str,
    bound: Duration,
) -> (
    Trio,
    AvSpine,
    ciris_edge::transport::av_sink::AvLink,
    ciris_edge::transport::av_sink::AcceptedAvArrival,
    [u8; 16],
) {
    let mut p = trio(tag, proposer(), DirectLinksConfig::default()).await;
    let mut arrivals = p.b.transport.take_av_arrivals().expect("B's arrivals");
    let (spine, b_addr) = open_call(&p).await;
    let leg =
        p.a.transport
            .open_av_link(&p.b.key.key_id, &b_addr)
            .await
            .expect("A's dial over the punched interface");
    assert!(leg.sender.is_direct());
    let up = next_event(&mut p.a.events, Duration::from_secs(5), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("the identity link came up direct");
    let DirectPathEvent::Established { link_id, .. } = up else {
        unreachable!()
    };
    let arrival = tokio::time::timeout(Duration::from_secs(20), arrivals.recv())
        .await
        .expect("the leg arrives at B")
        .expect("arrivals open");
    let accepted =
        p.b.transport
            .accept_av_arrival(arrival)
            .await
            .expect("B answers the leg's KEX");
    p.b.transport.set_inbound_link_idle_bound(bound);
    (p, spine, leg, accepted, link_id)
}

/// **v44** — the punched interface lives as long as the identity link it was
/// punched for, and that link is inbound on the side that did not dial it,
/// where media never touches it. So the inbound reaper closed it at its idle
/// bound and took a live call's interface with it (A kept sending, nothing
/// arrived). A peer's live A/V link makes the punched link busy; when the call
/// ends the link ages as any other.
/// Mutation: without the busy mark, the frames stop at the bound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_call_on_a_punched_interface_outlives_the_inbound_idle_bound() {
    const BOUND: Duration = Duration::from_secs(2);
    let (p, _spine, leg, accepted, identity) =
        Box::pin(call_on_a_punched_interface("reap-call", BOUND)).await;

    let started = tokio::time::Instant::now();
    let mut frames = 0u32;
    while started.elapsed() < BOUND * 3 {
        // Patiently: the leg is fresh, and its first frames can be refused
        // `Congested` until the Channel's first acks come back (on CI darwin
        // frame 1 was, 120 ms after the leg opened). What is pinned here is
        // that frames keep crossing past the bound, which the receive below
        // asserts for every frame.
        send_patiently(&leg.sender, format!("media-{frames}").as_bytes())
            .await
            .unwrap_or_else(|e| panic!("frame {frames} sends: {e:?}"));
        tokio::time::timeout(Duration::from_secs(10), accepted.arrival.inbound.recv())
            .await
            .unwrap_or_else(|_| panic!("frame {frames} crosses, {:?} in", started.elapsed()))
            .expect("the leg is open");
        frames += 1;
        p.b.transport.reap_idle_inbound_links().await;
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        p.b.transport.direct_link_interface(identity).is_some(),
        "the interface outlived the bound, {frames} frames in"
    );

    // The call ended: nothing holds the link, and it ages.
    p.a.transport
        .link_teardown(&leg.link_id)
        .await
        .expect("A hangs up");
    let aged = wait_until(BOUND * 3 + Duration::from_secs(30), || async {
        p.b.transport.reap_idle_inbound_links().await;
        p.b.transport.direct_link_interface(identity).is_none()
    })
    .await;
    assert!(aged, "with the call gone the link is reaped at its bound");
}

/// **v44** — the reaper stays what ends a wedge. A punched link with no call
/// whose inbound transfer stopped arriving is the wedge as the moved side sees
/// it: busy for the transfer's stall window, then reaped. The state is marked
/// here, not produced, the guard having removed the way to it. An idle punched
/// link with no call ages too.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wedged_punched_link_with_no_call_is_still_reaped() {
    let mut p = trio("reap-wedge", proposer(), DirectLinksConfig::default()).await;
    let (_spine, _b_addr) = open_call(&p).await;
    p.a.transport
        .send(&p.b.key.key_id, b"go-direct")
        .await
        .expect("the send that proposes");
    let up = next_event(&mut p.a.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("the link comes up direct");
    let DirectPathEvent::Established { link_id, .. } = up else {
        unreachable!()
    };
    // B moves on its own Established, not on A's: since leviculum#104 each
    // end probes the punched path's MTU before its interface attaches, so B
    // can attach a few ms after A has. Reading B's interface on A's event
    // raced that (2 runs in 8).
    next_event(&mut p.b.events, Duration::from_secs(20), |e| {
        matches!(e, DirectPathEvent::Established { .. })
    })
    .await
    .expect("B moves too");
    assert!(p.b.transport.direct_link_interface(link_id).is_some());

    p.b.transport.note_inbound_transfer_for_test(link_id, true);
    p.b.transport
        .set_inbound_link_idle_bound(Duration::from_secs(1));
    // Past the idle bound, inside the stall window: the transfer holds it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    p.b.transport.reap_idle_inbound_links().await;
    p.b.transport.reap_idle_inbound_links().await;
    assert!(
        p.b.transport.direct_link_interface(link_id).is_some(),
        "a transfer inside its stall window holds the link"
    );
    let reaped = wait_until(Duration::from_mins(1), || async {
        p.b.transport.reap_idle_inbound_links().await;
        p.b.transport.direct_link_interface(link_id).is_none()
    })
    .await;
    assert!(reaped, "the wedge ends: no call holds this link");
}
