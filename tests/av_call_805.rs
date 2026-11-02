//! CIRISEdge#805 items 5–6 — the host call API over REAL loopback Reticulum
//! (`FSD/AV_CALL_API.md` §9).
//!
//! Three edge nodes in a TCP full mesh (every pair one hop, so every call
//! address is dialable), each holding the others' hybrid-signed routes (and
//! so their transit KEX pairs). A room's MLS group spans the three; each node
//! joins the room's call. Every leg is a per-link transit KEX: a node DIALS
//! every other member's call address (initiator) and ACCEPTS the others'
//! dials (responder, after the claim check).
//!
//! - **A8** (`a_three_member_room_call_over_keyed_links`): every frame of every
//!   other publisher arrives byte-identical and in chunk order; C relays with
//!   a capped layer policy for B, A's direct leg to B loses every third chunk
//!   and C's relay leg is delayed, and B's `frames()` is still strictly
//!   increasing with nothing skipped; only base-layer chunks are relayed.
//! - **A3** (`a_removed_member_hears_nothing_after_the_roll`): the room
//!   removes C; A's stream rolls; B hears the post-roll chunks, C hears none.
//! - **A4 / A7 / A12** (`budget_keep_refused_and_no_key_door`): a Kept stream
//!   is refused by name and the call lives on unkept; the budget refuses one
//!   byte over BEFORE the seal; across a room roll the keep door is never
//!   touched.
//! - **A2** (`joining_is_membership_by_name`): a key outside the room's group
//!   is `NotARoomMember`; one in the group with no active roster membership
//!   is `ConsentMissing`.
//!
//! Requires `transport-reticulum`:
//! `cargo test --features "transport-http transport-reticulum" --test av_call_805`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::mls::cohort_group::mint_cohort_key_material;
use ciris_edge::mls::{CohortGroup, ScopeStateProvider};
use ciris_edge::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use ciris_edge::scope_lifecycle::{ScopeLifecycle, ScopedDestinationSink};
use ciris_edge::transport::av_call::{
    Call, CallAttendance, CallDeps, CallError, CallEvent, CallOptions, CallRecord, CallState,
    Frame, LegOutcome, ReceivedFrame, RoomRoster,
};
use ciris_edge::transport::av_call_key::CallId;
use ciris_edge::transport::av_chunk_auth::StreamKeyVerifier;
use ciris_edge::transport::av_keep::{AvKeep, AvKeepTarget, StreamDekRegistrar};
use ciris_edge::transport::realtime_av::{ChunkLayer, ChunkSeq, ReceiverLayerPolicy, CODEC_OPAQUE};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport as _};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::encrypted_kv::XChaChaKvStore;
use ciris_persist::federation::{BlobError, FederationDirectory};
use ciris_persist::store::sqlite::SqliteBackend;
use common::directory_with;
use sha2::Digest as _;
use tokio::sync::mpsc;

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
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// A production-shaped identity (as `direct_links_805`).
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
    fn signer(&self) -> Arc<LocalSigner> {
        let classical: Arc<dyn HardwareSigner> = Arc::clone(&self.ed) as Arc<dyn HardwareSigner>;
        let pqc: Arc<dyn PqcSigner> = Arc::clone(&self.pqc) as Arc<dyn PqcSigner>;
        Arc::new(LocalSigner::new(self.key_id.clone(), classical, Some(pqc)))
    }
    async fn record(&self) -> ciris_persist::federation::KeyRecord {
        let ed_b64 =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &self.ed_pub);
        let mut envelope = serde_json::json!({});
        ciris_persist::federation::admission::bind_subject_into_envelope(
            &mut envelope,
            &self.key_id,
            "node",
            &ed_b64,
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
            pubkey_ed25519_base64: ed_b64,
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

/// One edge node: its transport (listener running), metrics, table and
/// lifecycle.
struct Node {
    key: Ident,
    port: u16,
    dir: Arc<SqliteBackend>,
    transport: Arc<ReticulumTransport>,
    metrics: EdgeMetrics,
    lifecycle: Arc<ScopeLifecycle>,
    _edge: ciris_edge::Edge,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
}

async fn node(key: Ident, dir: Arc<SqliteBackend>, base: &std::path::Path, peers: &[u16]) -> Node {
    let mut transport = None;
    let mut port = 0;
    for _ in 0..16 {
        let mut c = ReticulumTransportConfig::new(base.join("transport.id"), &key.key_id);
        port = free_port();
        c.listen_addr = format!("127.0.0.1:{port}").parse().unwrap();
        c.announce_interval = Duration::from_secs(3);
        c.bootstrap_peers = peers
            .iter()
            .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
            .collect();
        let auth = ReticulumAuth {
            signer: Some(key.signer()),
            rooting: Some(Arc::clone(&dir) as Arc<dyn RootingDirectory>),
            resolver: None,
            hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
            blackhole_rules: Some(
                Arc::clone(&dir) as Arc<dyn ciris_persist::federation::BlackholeRules>
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
        .directory(Arc::clone(&dir) as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .federation_directory(Arc::clone(&dir) as Arc<dyn FederationDirectory>)
        .queue(Arc::clone(&dir) as Arc<dyn ciris_edge::outbound::OutboundHandle>)
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
    let (tx, mut rx) = mpsc::channel::<InboundFrame>(256);
    let listener = Arc::clone(&transport);
    let tasks = vec![
        tokio::spawn(async move {
            let _ = listener.listen(tx).await;
        }),
        tokio::spawn(async move { while rx.recv().await.is_some() {} }),
    ];
    Node {
        key,
        port,
        dir,
        transport,
        metrics,
        lifecycle,
        _edge: edge,
        _tasks: tasks,
    }
}

/// A roster that answers as told (persist's active roster, stubbed: the
/// community rows are not what these witnesses are about).
struct Roster(bool);

#[async_trait::async_trait]
impl RoomRoster for Roster {
    async fn is_active_member(&self, _room: &str, _key_id: &str) -> Result<bool, String> {
        Ok(self.0)
    }
}

/// A keep door that counts every call (A4).
#[derive(Default)]
struct CountingRegistrar(AtomicU64);

#[async_trait::async_trait]
impl StreamDekRegistrar for CountingRegistrar {
    async fn register_stream_epoch_dek(
        &self,
        _target: &AvKeepTarget,
        _stream_id: &str,
        _epoch: u64,
        _dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn store(tag: &str) -> ScopeStateProvider {
    ScopeStateProvider::new(Arc::new(
        XChaChaKvStore::open_in_memory(tag.as_bytes()).expect("in-memory scope state"),
    ))
}

/// `n` nodes in a TCP full mesh, each holding every other's signed route,
/// each knowing every other; plus the room's MLS group over all of them.
async fn mesh(tag: &str, n: usize) -> (Vec<Node>, Vec<CohortGroup>, tempfile::TempDir) {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let mut keys = Vec::new();
    for i in 0..n {
        keys.push(
            Ident::new(
                &format!("node-{i}-call-{tag}"),
                sha2::Sha256::digest(tag.as_bytes())[0].wrapping_add(u8::try_from(i).unwrap()),
            )
            .await,
        );
    }
    let mut records = Vec::new();
    for k in &keys {
        records.push(k.record().await);
    }
    let mut nodes: Vec<Node> = Vec::new();
    for (i, key) in keys.into_iter().enumerate() {
        let dir = directory_with(records.clone()).await;
        let peers: Vec<u16> = nodes.iter().map(|n| n.port).collect();
        nodes.push(node(key, dir, &tmp.path().join(format!("n{i}")), &peers).await);
    }
    for (i, from) in nodes.iter().enumerate() {
        let routes = from
            .dir
            .list_signed_transport_destinations_for(&from.key.key_id)
            .await
            .expect("list routes");
        for (j, to) in nodes.iter().enumerate() {
            if i != j {
                for r in &routes {
                    FederationDirectory::put_signed_transport_destination(&*to.dir, r)
                        .await
                        .expect("seed the route");
                }
            }
        }
    }
    let known = wait_until(Duration::from_secs(90), || async {
        for a in &nodes {
            for b in &nodes {
                if a.key.key_id != b.key.key_id && !a.transport.knows_peer(&b.key.key_id).await {
                    return false;
                }
            }
        }
        true
    })
    .await;
    assert!(known, "every node learns every other");

    // The room: node 0 founds it and adds the others, each applying the
    // commits that came before its own Add.
    let room = format!("room-call-{tag}");
    let first = CohortGroup::create(store(&format!("{tag}-0")), &room, &nodes[0].key.key_id, 16)
        .await
        .expect("found the room");
    let mut groups = vec![first];
    for (i, nd) in nodes.iter().enumerate().skip(1) {
        let (material, kp) = mint_cohort_key_material(&nd.key.key_id).expect("key material");
        let add = groups[0]
            .add_member(&nd.key.key_id, kp)
            .await
            .expect("add the member");
        for g in groups.iter().skip(1) {
            let _ = g
                .apply_remote_commit(add.commit())
                .await
                .expect("apply the Add");
        }
        let joined = CohortGroup::join(
            store(&format!("{tag}-{i}")),
            &room,
            material,
            add.welcome().expect("a Welcome"),
            16,
        )
        .await
        .expect("join from the Welcome");
        groups.push(joined);
    }
    (nodes, groups, tmp)
}

fn room_of(tag: &str) -> String {
    format!("room-call-{tag}")
}

async fn join(
    node: &Node,
    group: &CohortGroup,
    tag: &str,
    opts: CallOptions,
    registrar: Arc<dyn StreamDekRegistrar>,
) -> Result<Call, CallError> {
    join_recorded(node, group, tag, opts, registrar, None).await
}

async fn join_recorded(
    node: &Node,
    group: &CohortGroup,
    tag: &str,
    opts: CallOptions,
    registrar: Arc<dyn StreamDekRegistrar>,
    record: Option<Arc<dyn CallRecord>>,
) -> Result<Call, CallError> {
    Call::join(
        &room_of(tag),
        &node.key.key_id,
        CallDeps {
            room_group: group.clone(),
            roster: Arc::new(Roster(true)),
            transport: Arc::clone(&node.transport),
            lifecycle: Arc::clone(&node.lifecycle),
            registrar,
            events: None,
            metrics: Some(node.metrics.clone()),
            record,
            signer: node.key.signer(),
            verifier: Arc::clone(&node.dir) as Arc<dyn StreamKeyVerifier>,
        },
        opts,
    )
    .await
}

fn av(m: &EdgeMetrics, label: &str) -> u64 {
    m.av_plane().get(label).copied().unwrap_or(0)
}

fn seal(m: &EdgeMetrics, label: &str) -> u64 {
    m.link_seal().get(label).copied().unwrap_or(0)
}

fn body(who: &str, seq: u64) -> Vec<u8> {
    let mut b = format!("{who}-frame-{seq:04}-").into_bytes();
    b.resize(96, b'.');
    b
}

/// Collect frames from `rx` until `want` frames of `publisher` arrived.
async fn collect_from(
    rx: &mut mpsc::Receiver<ReceivedFrame>,
    seen: &mut Vec<ReceivedFrame>,
    publisher: &str,
    want: usize,
) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while seen.iter().filter(|f| f.publisher == publisher).count() < want {
        match tokio::time::timeout_at(deadline, rx.recv()).await {
            Ok(Some(f)) => seen.push(f),
            _ => return false,
        }
    }
    true
}

async fn wait_legs(call: &Call, n: usize) {
    assert!(
        wait_until(Duration::from_secs(30), || async { call.legs().len() >= n }).await,
        "the call's legs come up: {:?}",
        call.legs()
    );
}

/// Wait until `call` has verified `n` other publishers' stream key bindings:
/// the setup step after the legs (a hybrid verification each, once), before
/// which a receiver holds its first chunks in the link's queue.
async fn wait_bound(call: &Call, n: u64) {
    assert!(
        wait_until(Duration::from_secs(30), || async {
            call.chunk_auth_counts().bindings_installed >= n
        })
        .await,
        "the call verifies its peers' bindings: {:?}",
        call.chunk_auth_counts()
    );
}

/// **A8** — a three-member room call over keyed loopback links.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_three_member_room_call_over_keyed_links() {
    let tag = "a8";
    let (nodes, groups, _tmp) = mesh(tag, 3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let none = || Arc::new(CountingRegistrar::default()) as Arc<dyn StreamDekRegistrar>;
    let mut call_a = join(a, &groups[0], tag, CallOptions::default(), none())
        .await
        .expect("A joins");
    let mut call_b = join(b, &groups[1], tag, CallOptions::default(), none())
        .await
        .expect("B joins");
    let mut call_c = join(
        c,
        &groups[2],
        tag,
        CallOptions {
            relay: true,
            ..CallOptions::default()
        },
        none(),
    )
    .await
    .expect("C joins as a relay");
    for call in [&call_a, &call_b, &call_c] {
        wait_legs(call, 2).await;
    }
    for call in [&call_a, &call_b, &call_c] {
        wait_bound(call, 2).await;
    }
    for nd in [a, b, c] {
        // CC 5.3.3.5 E1 — every link is keyed by the link layer (identity
        // links too), so the two call legs it dialled are at least two.
        assert!(
            seal(&nd.metrics, "link_seal_initiated") >= 2,
            "every leg it dialled is keyed"
        );
    }
    assert!(
        wait_until(Duration::from_secs(10), || async {
            [a, b, c]
                .iter()
                .all(|nd| seal(&nd.metrics, "link_seal_accepted") >= 2)
        })
        .await,
        "every leg dialled to a node was answered after the claim check"
    );

    // C relays to B at the base layer only; A's direct leg to B loses every
    // third chunk, and C's relay leg lags by 60 ms.
    call_c
        .set_layer_policy(&b.key.key_id, ReceiverLayerPolicy::BLINKING_DOT)
        .await
        .expect("C caps B");
    call_c.delay_relay_for_test(Duration::from_millis(60));
    call_a.withhold_from_for_test(&b.key.key_id, 3);

    let mut frames_a = call_a.frames().expect("A's frames");
    let mut frames_b = call_b.frames().expect("B's frames");
    let mut frames_c = call_c.frames().expect("C's frames");
    let enhanced = ChunkLayer {
        spatial: 1,
        temporal: 0,
        quality: 0,
    };
    let layer_of = |s: u64| {
        if s % 3 == 2 {
            enhanced
        } else {
            ChunkLayer::BASE
        }
    };
    for s in 0..30u64 {
        let report = call_a
            .publish(Frame {
                codec_id: CODEC_OPAQUE,
                layer: layer_of(s),
                bytes: body("a", s),
            })
            .await
            .expect("A publishes");
        assert_eq!(report.chunk_seq, ChunkSeq(s));
        assert!(report
            .legs
            .iter()
            .all(|(_, o)| matches!(o, LegOutcome::Delivered | LegOutcome::Congested)));
        if s < 10 {
            call_b
                .publish(Frame::opaque(body("b", s)))
                .await
                .expect("B publishes");
        }
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let (mut seen_a, mut seen_b, mut seen_c) = (Vec::new(), Vec::new(), Vec::new());
    assert!(
        collect_from(&mut frames_b, &mut seen_b, &a.key.key_id, 30).await,
        "B: {} of A's: {:?}, reorder {:?}",
        seen_b.len(),
        seen_b.iter().map(|f| f.chunk_seq.0).collect::<Vec<_>>(),
        call_b.reorder_counts()
    );
    assert!(
        collect_from(&mut frames_c, &mut seen_c, &a.key.key_id, 30).await,
        "C: {}",
        seen_c.len()
    );
    assert!(
        collect_from(&mut frames_a, &mut seen_a, &b.key.key_id, 10).await,
        "A: {}",
        seen_a.len()
    );
    assert!(collect_from(&mut frames_c, &mut seen_c, &b.key.key_id, 10).await);

    // Byte-identical and strictly in chunk order, per publisher.
    for (seen, from, n, who) in [
        (&seen_b, &a.key.key_id, 30u64, "a"),
        (&seen_c, &a.key.key_id, 30, "a"),
        (&seen_a, &b.key.key_id, 10, "b"),
        (&seen_c, &b.key.key_id, 10, "b"),
    ] {
        let got: Vec<&ReceivedFrame> = seen.iter().filter(|f| f.publisher == *from).collect();
        let seqs: Vec<u64> = got.iter().map(|f| f.chunk_seq.0).collect();
        assert_eq!(
            seqs,
            (0..n).collect::<Vec<_>>(),
            "in order, every chunk once"
        );
        for f in &got {
            assert_eq!(f.bytes, body(who, f.chunk_seq.0), "byte-identical");
        }
    }
    // B heard A's withheld chunks only through C's lagging relay leg: the
    // window held the direct copies until they came, skipping nothing.
    let rb = call_b.reorder_counts();
    assert_eq!(rb.skipped, 0, "{rb:?}");
    assert!(rb.duplicates > 0, "the two legs overlapped: {rb:?}");
    // C relayed only what each member's policy admits: A's base chunks to B
    // (20 of 30) and B's 10 base chunks to A — never the enhanced layer to B.
    let relayed = av(&c.metrics, "av_call_relayed");
    assert!(
        (20..=30).contains(&relayed),
        "C relays base-layer chunks only (at most 20 + 10; a congested relay send is \
         dropped, never queued): {:?}",
        c.metrics.av_plane()
    );
    // Every chunk heard was its publisher's: each binding (direct, and
    // forwarded by C) arrived before the chunks it keys.
    for call in [&call_a, &call_b, &call_c] {
        let auth = call.chunk_auth_counts();
        assert_eq!((auth.forged, auth.unbound), (0, 0), "{auth:?}");
        assert!(
            auth.verified > 0 && auth.bindings_installed >= 2,
            "{auth:?}"
        );
    }
    assert_eq!(call_a.state(), CallState::Live);
    let summary = call_a.leave().await.expect("A leaves");
    assert_eq!(summary.frames_published, 30);
}

/// **A3** — the room removes C: A's stream rolls; B hears the post-roll
/// chunks and C hears none of them.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_removed_member_hears_nothing_after_the_roll() {
    let tag = "a3";
    let (nodes, groups, _tmp) = mesh(tag, 3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let none = || Arc::new(CountingRegistrar::default()) as Arc<dyn StreamDekRegistrar>;
    let mut call_a = join(a, &groups[0], tag, CallOptions::default(), none())
        .await
        .expect("A");
    let mut call_b = join(b, &groups[1], tag, CallOptions::default(), none())
        .await
        .expect("B");
    let mut call_c = join(c, &groups[2], tag, CallOptions::default(), none())
        .await
        .expect("C");
    wait_legs(&call_a, 2).await;
    for call in [&call_a, &call_b, &call_c] {
        wait_bound(call, 2).await;
    }
    let mut events_a = call_a.events().expect("A's events");
    let mut frames_b = call_b.frames().expect("B");
    let mut frames_c = call_c.frames().expect("C");
    for s in 0..5u64 {
        call_a
            .publish(Frame::opaque(body("a", s)))
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let (mut seen_b, mut seen_c) = (Vec::new(), Vec::new());
    assert!(
        collect_from(&mut frames_c, &mut seen_c, &a.key.key_id, 5).await,
        "C hears the pre-roll stream"
    );
    let pre_epoch = call_a.epoch().await;

    // The room removes C (A commits, B applies; C's state is left behind).
    let rm = groups[0]
        .remove_member(&c.key.key_id)
        .await
        .expect("remove C");
    let _ = groups[1]
        .apply_remote_commit(rm.commit())
        .await
        .expect("B applies");
    for s in 0..10u64 {
        let r = call_a
            .publish(Frame::opaque(body("a-post", s)))
            .await
            .expect("publish");
        assert!(
            r.epoch > pre_epoch,
            "every post-commit chunk is in the new epoch"
        );
        if s == 0 {
            assert_eq!(r.chunk_seq, ChunkSeq(0), "the roll restarted chunk_seq");
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    let rolled = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(e) = events_a.recv().await {
            if matches!(e, CallEvent::EpochRolled { .. }) {
                return true;
            }
        }
        false
    })
    .await;
    assert_eq!(rolled, Ok(true), "A's call rolled with the room");
    assert!(
        collect_from(&mut frames_b, &mut seen_b, &a.key.key_id, 15).await,
        "B hears all 15: {}",
        seen_b.len()
    );
    let post: Vec<&ReceivedFrame> = seen_b.iter().filter(|f| f.epoch > pre_epoch).collect();
    assert_eq!(post.len(), 10);
    // C: nothing from the new epoch, ever.
    let heard = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(f) = frames_c.recv().await {
            if f.epoch > pre_epoch {
                return Some(f);
            }
        }
        None
    })
    .await;
    assert!(
        !matches!(heard, Ok(Some(_))),
        "the removed member opened a post-roll chunk: {heard:?}"
    );
    assert!(
        !call_a.legs().contains(&c.key.key_id),
        "A closed its leg to C"
    );
}

/// **Source authentication** — B, a room member, can derive A's stream DEK.
/// It opens its own link to C (a relay), names A's stream in the hello as if
/// it were A, and sends chunks for A's stream that are validly encrypted under
/// that DEK and signed with a chunk key of its own. C drops every one as not
/// A's and counts it; C delivers none, relays none, and A's own chunks still
/// reach B and C, directly and through C's relay.
#[allow(clippy::too_many_lines)]
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_member_cannot_forge_another_members_stream_through_a_relay() {
    use ciris_edge::cohort_scope::CohortScope;
    use ciris_edge::transport::av_call::{call_group_id, call_id_for_room};
    use ciris_edge::transport::av_call_key::stream_epoch_dek;
    use ciris_edge::transport::av_chunk_auth::ChunkSigner;
    use ciris_edge::transport::realtime_av::{seal_av_inner, seal_av_outer};
    use ciris_edge::transport::realtime_av_dispatcher::{AvDispatcherError, AvLinkSender as _};

    const FORGED: &[u8] = b"FORGED-BY-B";
    let tag = "forge";
    let (nodes, groups, _tmp) = mesh(tag, 3).await;
    let (a, b, c) = (&nodes[0], &nodes[1], &nodes[2]);
    let none = || Arc::new(CountingRegistrar::default()) as Arc<dyn StreamDekRegistrar>;
    let mut call_a = join(a, &groups[0], tag, CallOptions::default(), none())
        .await
        .expect("A joins");
    let mut call_b = join(b, &groups[1], tag, CallOptions::default(), none())
        .await
        .expect("B joins");
    let mut call_c = join(
        c,
        &groups[2],
        tag,
        CallOptions {
            relay: true,
            ..CallOptions::default()
        },
        none(),
    )
    .await
    .expect("C joins as a relay");
    for call in [&call_a, &call_b, &call_c] {
        wait_legs(call, 2).await;
    }
    for call in [&call_a, &call_b, &call_c] {
        wait_bound(call, 2).await;
    }
    let mut frames_a = call_a.frames().expect("A's frames");
    let mut frames_b = call_b.frames().expect("B's frames");
    let mut frames_c = call_c.frames().expect("C's frames");

    // A's real stream reaches B and C: C now holds A's verified binding.
    for s in 0..5u64 {
        call_a
            .publish(Frame::opaque(body("a", s)))
            .await
            .expect("A publishes");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    let (mut seen_b, mut seen_c) = (Vec::new(), Vec::new());
    assert!(collect_from(&mut frames_b, &mut seen_b, &a.key.key_id, 5).await);
    assert!(collect_from(&mut frames_c, &mut seen_c, &a.key.key_id, 5).await);
    let relayed_before = av(&c.metrics, "av_call_relayed");

    // B forges: A's stream, A's epoch, A's DEK (derived from B's own room
    // state), B's own chunk key, on a link B dials to C naming A's stream.
    let stream_a = call_a.stream();
    let epoch = call_a.epoch().await;
    let dek = stream_epoch_dek(&groups[1], stream_a, epoch)
        .await
        .expect("a member derives every stream's DEK");
    let room = room_of(tag);
    let address = b
        .lifecycle
        .table()
        .send_address(
            &CohortScope::Cohort {
                cohort_id: room.clone(),
            },
            &call_group_id(call_id_for_room(&room)),
            &c.key.key_id,
        )
        .expect("C's call address");
    let link = b
        .transport
        .open_av_link(&c.key.key_id, &address)
        .await
        .expect("B dials C");
    let send = |bytes: Vec<u8>| {
        let sender = &link.sender;
        async move {
            for _ in 0..200 {
                match sender.send(&bytes).await {
                    Ok(()) => return,
                    Err(AvDispatcherError::Congested) => {
                        tokio::time::sleep(Duration::from_millis(25)).await;
                    }
                    Err(e) => panic!("forger send: {e}"),
                }
            }
            panic!("forger send stayed congested");
        }
    };
    let mut hello = b"CHLO".to_vec();
    hello.push(1);
    hello.extend_from_slice(&stream_a.0);
    send(hello).await;
    let forger = ChunkSigner::generate(stream_a, epoch).expect("B's chunk key");
    let forgeries = 10u64;
    for i in 0..forgeries {
        let inner = seal_av_inner(
            FORGED,
            &dek,
            stream_a,
            epoch,
            ChunkSeq(1000 + i),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("validly encrypted");
        let signed = forger.sign(&inner).expect("signed by B");
        let wire = seal_av_outer(&signed, &link.transit.seal_key(), &link.link_id, i)
            .expect("hop seal")
            .to_bytes();
        send(wire).await;
    }
    assert!(
        wait_until(Duration::from_secs(10), || async {
            av(&c.metrics, "av_call_frame_forged") >= forgeries
        })
        .await,
        "C drops and counts every forgery: {:?}",
        c.metrics.av_plane()
    );
    assert!(call_c.chunk_auth_counts().forged >= forgeries);
    assert_eq!(
        av(&c.metrics, "av_call_relayed"),
        relayed_before,
        "C relays no forgery"
    );
    // Nothing forged is ever delivered, at C or (through C) at A.
    for (rx, who) in [(&mut frames_c, "C"), (&mut frames_a, "A")] {
        let got = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(f) = rx.recv().await {
                if f.bytes == FORGED {
                    return Some(f);
                }
            }
            None
        })
        .await;
        assert!(
            !matches!(got, Ok(Some(_))),
            "{who} delivered a forged chunk: {got:?}"
        );
    }

    // A's real chunks still flow, direct and through C's relay.
    for s in 5..10u64 {
        call_a
            .publish(Frame::opaque(body("a", s)))
            .await
            .expect("A publishes");
        tokio::time::sleep(Duration::from_millis(33)).await;
    }
    assert!(collect_from(&mut frames_b, &mut seen_b, &a.key.key_id, 10).await);
    assert!(collect_from(&mut frames_c, &mut seen_c, &a.key.key_id, 10).await);
    for seen in [&seen_b, &seen_c] {
        let got: Vec<u64> = seen
            .iter()
            .filter(|f| f.publisher == a.key.key_id)
            .map(|f| f.chunk_seq.0)
            .collect();
        assert_eq!(got, (0..10).collect::<Vec<_>>());
    }
    assert!(
        av(&c.metrics, "av_call_relayed") > relayed_before,
        "C relays A's real chunks"
    );
    assert!(call_b.chunk_auth_counts().verified >= 10);
}

/// **A4 / A7 / A12** — a Kept stream is refused by name and the call lives
/// on; the budget refuses one byte over BEFORE the seal; across a room roll
/// the keep door is never touched.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn budget_keep_refused_and_no_key_door() {
    let tag = "a7";
    let (nodes, groups, _tmp) = mesh(tag, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let registrar = Arc::new(CountingRegistrar::default());
    let mut call_a = join(
        a,
        &groups[0],
        tag,
        CallOptions {
            keep: AvKeep::Kept,
            ..CallOptions::default()
        },
        Arc::clone(&registrar) as Arc<dyn StreamDekRegistrar>,
    )
    .await
    .expect("A joins, kept asked");
    let mut call_b = join(
        b,
        &groups[1],
        tag,
        CallOptions::default(),
        Arc::clone(&registrar) as Arc<dyn StreamDekRegistrar>,
    )
    .await
    .expect("B joins");
    let mut events_a = call_a.events().expect("events");
    match tokio::time::timeout(Duration::from_secs(2), events_a.recv()).await {
        Ok(Some(CallEvent::KeepRefused { reason, .. })) => {
            assert_eq!(reason, "keep_deferred_cirispersist_1067");
        }
        other => panic!("a Kept stream is refused by name at once: {other:?}"),
    }
    assert_eq!(call_a.state(), CallState::Live, "the call goes on, unkept");

    // A7: nothing to cut to before a leg is up …
    // (legs come up asynchronously; wait, then cut to the budget)
    wait_legs(&call_a, 1).await;
    let budget = call_a
        .chunk_plaintext_budget()
        .expect("a budget once a leg is up");
    let mut frames_b = call_b.frames().expect("B");
    let at = call_a
        .publish(Frame::opaque(vec![0x5a; budget]))
        .await
        .expect("exactly the budget is delivered");
    assert_eq!(at.delivered(), 1);
    let before = call_a.next_chunk_seq_for_test().await;
    match call_a.publish(Frame::opaque(vec![0x5a; budget + 1])).await {
        Err(CallError::FrameTooLarge { bytes, budget: b }) => {
            assert_eq!((bytes, b), (budget + 1, budget));
        }
        other => panic!("one byte over is refused by name: {other:?}"),
    }
    assert_eq!(
        call_a.next_chunk_seq_for_test().await,
        before,
        "the refused frame consumed no chunk_seq, so no nonce"
    );
    let mut seen = Vec::new();
    assert!(collect_from(&mut frames_b, &mut seen, &a.key.key_id, 1).await);
    assert_eq!(seen[0].bytes.len(), budget);

    // A4: a room roll (an Update) and more frames; the door stays shut.
    let up = groups[0].rotate().await.expect("rotate");
    let _ = groups[1]
        .apply_remote_commit(up.commit())
        .await
        .expect("B applies");
    // Paced as a call is (a burst into a fresh Channel window is refused
    // as Congested and dropped for that leg, #591).
    for s in 0..3u64 {
        let r = call_a
            .publish(Frame::opaque(body("a", s)))
            .await
            .expect("publish");
        assert_eq!(r.chunk_seq, ChunkSeq(s), "the roll restarted chunk_seq");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        collect_from(&mut frames_b, &mut seen, &a.key.key_id, 4).await,
        "B after the roll: {} frames, reorder {:?}, B av_plane {:?}, A av_plane {:?}",
        seen.len(),
        call_b.reorder_counts(),
        b.metrics.av_plane(),
        a.metrics.av_plane()
    );
    assert_eq!(
        registrar.0.load(Ordering::SeqCst),
        0,
        "no register_stream_epoch_dek, ever"
    );
}

/// **A2** — joining is membership, refused by name.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn joining_is_membership_by_name() {
    init_tracing();
    let tmp = tempfile::tempdir().expect("tempdir");
    let key = Ident::new("node-x-call-a2", 0x71).await;
    let dir = directory_with(vec![key.record().await]).await;
    let x = node(key, dir, tmp.path(), &[]).await;
    let deps = |group: &CohortGroup, active: bool| CallDeps {
        room_group: group.clone(),
        roster: Arc::new(Roster(active)),
        transport: Arc::clone(&x.transport),
        lifecycle: Arc::clone(&x.lifecycle),
        registrar: Arc::new(CountingRegistrar::default()),
        events: None,
        metrics: None,
        record: None,
        signer: x.key.signer(),
        verifier: Arc::clone(&x.dir) as Arc<dyn StreamKeyVerifier>,
    };
    // A room X is not in.
    let other = CohortGroup::create(store("a2-other"), "room-a2", "someone-else", 16)
        .await
        .unwrap();
    match Call::join(
        "room-a2",
        &x.key.key_id,
        deps(&other, true),
        CallOptions::default(),
    )
    .await
    {
        Err(CallError::NotARoomMember { key_id, room }) => {
            assert_eq!(
                (key_id.as_str(), room.as_str()),
                (x.key.key_id.as_str(), "room-a2")
            );
        }
        other => panic!("a non-member is refused by name: {other:?}"),
    }
    // X in the room's group, but persist holds no active membership for it.
    let own = CohortGroup::create(store("a2-own"), "room-a2b", &x.key.key_id, 16)
        .await
        .unwrap();
    match Call::join(
        "room-a2b",
        &x.key.key_id,
        deps(&own, false),
        CallOptions::default(),
    )
    .await
    {
        Err(CallError::ConsentMissing { .. }) => {}
        other => panic!("a member without consent is refused by name: {other:?}"),
    }
    assert!(
        x.lifecycle.groups().is_empty(),
        "no address was installed for a refused join"
    );
}

/// A call-row door that refuses every write (persist refusing the put).
struct RefusingRecord(String);

#[async_trait::async_trait]
impl CallRecord for RefusingRecord {
    fn attendee(&self) -> &str {
        &self.0
    }
    async fn record_join(
        &self,
        _room: &str,
        _call: CallId,
        _at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), String> {
        Err("put call row: refused by the directory double".to_owned())
    }
    async fn attendance(&self, _room: &str, _call: CallId) -> Result<CallAttendance, String> {
        Ok(CallAttendance::default())
    }
}

/// **(d)** The call row is refused: `RecordRefused` fires ONCE, the call
/// stays live, and frames still flow.
#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn a_refused_call_row_is_one_event_and_the_call_lives() {
    let tag = "rr";
    let (nodes, groups, _tmp) = mesh(tag, 2).await;
    let (a, b) = (&nodes[0], &nodes[1]);
    let none = || Arc::new(CountingRegistrar::default()) as Arc<dyn StreamDekRegistrar>;
    let mut call_a = join_recorded(
        a,
        &groups[0],
        tag,
        CallOptions::default(),
        none(),
        Some(Arc::new(RefusingRecord(a.key.key_id.clone())) as Arc<dyn CallRecord>),
    )
    .await
    .expect("A joins though its row is refused");
    let mut call_b = join(b, &groups[1], tag, CallOptions::default(), none())
        .await
        .expect("B joins");
    let mut events = call_a.events().expect("events");
    match tokio::time::timeout(Duration::from_secs(2), events.recv()).await {
        Ok(Some(CallEvent::RecordRefused { reason })) => {
            assert!(reason.contains("refused"), "{reason}");
        }
        other => panic!("RecordRefused at once: {other:?}"),
    }
    assert_eq!(call_a.state(), CallState::Live, "the call lives");
    wait_legs(&call_a, 1).await;
    let mut frames_b = call_b.frames().expect("B");
    for s in 0..5u64 {
        call_a
            .publish(Frame::opaque(body("a", s)))
            .await
            .expect("frames still go out");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let mut seen = Vec::new();
    assert!(collect_from(&mut frames_b, &mut seen, &a.key.key_id, 5).await);
    assert_eq!(av(&a.metrics, "av_call_record_refused"), 1);
    // Once: nothing more about the row on the event stream.
    while let Ok(e) = events.try_recv() {
        assert!(!matches!(e, CallEvent::RecordRefused { .. }), "fired twice");
    }
    assert_eq!(call_a.attendees().await, vec![a.key.key_id.clone()]);
}
