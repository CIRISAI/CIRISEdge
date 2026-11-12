//! CIRISEdge#943 — the delay on the real path, and its end.
//!
//! Two Reticulum nodes on loopback. B dials A and opens rounds; A answers
//! through the real `ReplicationRuntime` responder. The reverse path is dead
//! the way the field's was: the #926 seam stops B acknowledging on the links
//! it opened to A, so each frame's pacing wait runs out and the Resource slot
//! stays `Busy`, and A's dial out is refused (a NAT'd peer has no other way
//! back). B's frames still reach A.
//!
//! B's round-open is what a real session produces with #927 proactive
//! publish: a `Summary`, then a `Deliver` straight behind it. The Summary's
//! reply parks in A's send; the question is what happens to the Deliver.
//!
//! - **Pre-fix (observed):** the Deliver stepped 9.5 s after the round-open,
//!   behind one failed send.
//! - **Post-fix (observed):** it stepped at 33 ms; the reply failed at 9.5 s,
//!   and a round on the healed path was answered.
//!
//! Order, not a stopwatch: the assertion is which of two counters moved first.
//!
//! Requires the `transport-reticulum` feature:
//! `cargo test --features transport-reticulum --test responder_drain_943`

#![cfg(feature = "transport-reticulum")]

mod common;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ciris_edge::identity::{sign_bound_hybrid, LocalSigner};
use ciris_edge::observability::{
    RESPONDER_ROUND_COMPLETED_RESPONDER_FINAL, RESPONDER_ROUND_REPLY_SEND_FAILED,
};
use ciris_edge::replication::coordinator::{DriveStep, ReplicationCoordinator};
use ciris_edge::replication::directory::{
    DirectoryStateAdapter, MockReplicationDirectory, MutableDirectoryStateAdapter,
    ReplicationDirectory,
};
use ciris_edge::replication::session::SessionRole;
use ciris_edge::replication::{
    wire_frame, EnvelopeKind, InboundRouter, ReplicationMessage, ReplicationRuntime,
    ReplicationRuntimeConfig, SchedulerConfig,
};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{
    InboundFrame, Transport, TransportError, TransportId, TransportSendOutcome,
};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::EdgeMetrics;
use ciris_keyring::{Ed25519SoftwareSigner, HardwareSigner, MlDsa65SoftwareSigner, PqcSigner};
use ciris_persist::federation::FederationDirectory;
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
        hybrid_policy: ciris_edge::HybridPolicy::Strict,
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
        common::apply_env_shaping(&mut c);
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

/// B's side of one round: a real initiator session, proactive, on a plane
/// holding `row`. Fresh per round, so its push ledger always carries the row.
/// Frames leave through this seam and are then handed to the real transport.
#[derive(Default)]
struct Wire(Mutex<Vec<Vec<u8>>>);

#[async_trait]
impl Transport for Wire {
    fn id(&self) -> TransportId {
        TransportId::RETICULUM_RS
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        envelope_bytes: &[u8],
    ) -> Result<TransportSendOutcome, TransportError> {
        self.0.lock().unwrap().push(envelope_bytes.to_vec());
        Ok(TransportSendOutcome::Delivered)
    }
    async fn listen(&self, _sink: mpsc::Sender<InboundFrame>) -> Result<(), TransportError> {
        Ok(())
    }
}

/// The frames of one round-open, and the round they carry.
async fn round_open(a_key: &str, row: &[u8]) -> (Vec<Vec<u8>>, u64) {
    let dir = Arc::new(MockReplicationDirectory::new());
    dir.seed(
        EnvelopeKind::Key,
        sha2::Sha256::digest(row).into(),
        row.to_vec(),
        1,
    )
    .await;
    let directory: Arc<dyn ReplicationDirectory> = dir;
    let wire = Arc::new(Wire::default());
    let coord = ReplicationCoordinator::new(
        Arc::clone(&wire) as Arc<dyn Transport>,
        a_key,
        EnvelopeKind::Key,
        SessionRole::Initiator,
        Arc::new(DirectoryStateAdapter::new(Arc::clone(&directory))),
        Arc::new(MutableDirectoryStateAdapter::new(directory)),
    )
    .with_proactive_publish(true);
    let DriveStep::SendThenWait(msgs) = coord.drive_round_step(None).await.expect("a round opens")
    else {
        panic!("an initiator's round opens with SendThenWait");
    };
    for m in &msgs {
        coord
            .send_message(m)
            .await
            .expect("the wire seam never fails");
    }
    let round = coord.current_round();
    let frames = std::mem::take(&mut *wire.0.lock().unwrap());
    (frames, round)
}

fn count(m: &EdgeMetrics, outcome: &str) -> u64 {
    m.responder_rounds_total()
        .get(&format!("{}:{outcome}", EnvelopeKind::Key.as_wire_str()))
        .copied()
        .unwrap_or(0)
}

/// Replies B has received: `(round, message)`.
type Replies = Arc<Mutex<Vec<(u64, &'static str)>>>;

fn replied(replies: &Replies, round: u64, what: &str) -> bool {
    replies
        .lock()
        .unwrap()
        .iter()
        .any(|(r, w)| *r == round && *w == what)
}

fn name_of(msg: &ReplicationMessage) -> &'static str {
    match msg {
        ReplicationMessage::Summary(_) => "summary",
        ReplicationMessage::Diff(_) => "diff",
        ReplicationMessage::Deliver(_) => "deliver",
        _ => "other",
    }
}

async fn wait_for(what: &str, within: Duration, mut cond: impl FnMut() -> bool) {
    let deadline = Instant::now() + within;
    while !cond() {
        assert!(Instant::now() < deadline, "{what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

struct Nodes {
    a_key: String,
    b_key: String,
    a: Arc<ReticulumTransport>,
    b: Arc<ReticulumTransport>,
    a_metrics: EdgeMetrics,
    replies: Replies,
    _runtime: Arc<ReplicationRuntime>,
    _tmp: tempfile::TempDir,
}

async fn nodes() -> Nodes {
    let tmp = tempfile::tempdir().expect("tempdir");
    let a_id = Ident::new("a-943", 0xa9).await;
    let b_id = Ident::new("b-943", 0xb9).await;
    let records = vec![a_id.record("node").await, b_id.record("node").await];
    let a_dir = directory_with(records.clone()).await;
    let b_dir = directory_with(records).await;
    let a_metrics = EdgeMetrics::new();
    let (a, a_port) = build_transport(&a_metrics, tmp.path(), &a_id, &a_dir, None).await;
    let (b, _) =
        build_transport(&EdgeMetrics::new(), tmp.path(), &b_id, &b_dir, Some(a_port)).await;
    for (from, who, to) in [(&a_dir, &a_id, &b_dir), (&b_dir, &b_id, &a_dir)] {
        for r in &from
            .list_signed_transport_destinations_for(&who.key_id)
            .await
            .expect("list routes")
        {
            FederationDirectory::put_signed_transport_destination(&**to, r)
                .await
                .expect("seed the route");
        }
    }
    let runtime = Arc::new(
        ReplicationRuntime::start(
            Arc::clone(&a_dir) as Arc<dyn FederationDirectory>,
            Arc::clone(&a) as Arc<dyn Transport>,
            Vec::new(),
            ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: Duration::from_hours(1),
                    ..SchedulerConfig::default()
                },
                local_key_id: Some(a_id.key_id.clone()),
                metrics: Some(a_metrics.clone()),
                ..Default::default()
            },
            None,
        )
        .await,
    );
    let (a_tx, mut a_rx) = mpsc::channel::<InboundFrame>(1024);
    let (b_tx, mut b_rx) = mpsc::channel::<InboundFrame>(1024);
    let (la, lb) = (Arc::clone(&a), Arc::clone(&b));
    tokio::spawn(async move {
        let _ = la.listen(a_tx).await;
    });
    tokio::spawn(async move {
        let _ = lb.listen(b_tx).await;
    });
    let router = InboundRouter::new(runtime.registry());
    tokio::spawn(async move {
        while let Some(frame) = a_rx.recv().await {
            let _ = router.try_route(&frame).await;
        }
    });
    let replies: Replies = Arc::default();
    let seen = Arc::clone(&replies);
    tokio::spawn(async move {
        while let Some(frame) = b_rx.recv().await {
            if let Ok(Some(f)) = wire_frame::try_unwrap_framed(&frame.envelope_bytes) {
                seen.lock()
                    .unwrap()
                    .push((f.meta.map_or(0, |m| m.round), name_of(&f.msg)));
            }
        }
    });
    Nodes {
        a_key: a_id.key_id.clone(),
        b_key: b_id.key_id.clone(),
        a,
        b,
        a_metrics,
        replies,
        _runtime: runtime,
        _tmp: tmp,
    }
}

impl Nodes {
    /// B sends the round-open over the real transport, frame by frame.
    async fn open(&self, row: &[u8]) -> u64 {
        let (frames, round) = round_open(&self.a_key, row).await;
        assert_eq!(frames.len(), 2, "Summary, then the proactive Deliver");
        // A's announce may still be on its way: the route is what the wait is
        // for, and a frame that could not leave has not opened anything.
        let deadline = Instant::now() + Duration::from_mins(1);
        for f in &frames {
            while let Err(e) = self.b.send(&self.a_key, f).await {
                assert!(Instant::now() < deadline, "B -> A: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        }
        round
    }

    /// The links B opened to A, once A's Channel on each has settled.
    async fn settled_reverse_links(&self) -> Vec<[u8; 16]> {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let links = self.a.reverse_links_for_test(&self.b_key).await;
            if !links.is_empty()
                && links
                    .iter()
                    .all(|l| self.a.link_channel_settled_for_test(*l))
            {
                return links;
            }
            assert!(Instant::now() < deadline, "A holds a settled link from B");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

/// **The witness on the wire.**
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dead_reverse_path_does_not_hold_the_deliver_behind_the_reply_943() {
    let n = tokio::time::timeout(Duration::from_mins(2), nodes())
        .await
        .expect("the pair comes up");

    // A healthy round first: B reaches A's responder and hears back.
    let deadline = Instant::now() + Duration::from_mins(1);
    let round = loop {
        let round = n.open(b"row-healthy").await;
        let hit = tokio::time::timeout(Duration::from_secs(5), async {
            while !replied(&n.replies, round, "diff") {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if hit.is_ok() {
            break round;
        }
        assert!(
            Instant::now() < deadline,
            "A's responder never answered on a healthy path: {:?}",
            n.a_metrics.responder_rounds_total()
        );
    };
    assert!(round != 0);

    // The reverse path dies, and A has no way round it.
    for link in n.settled_reverse_links().await {
        n.a.stop_acks_on_link_for_test(link, Some(0));
    }
    n.a.refuse_outbound_dials_for_test(true);
    let done = count(&n.a_metrics, RESPONDER_ROUND_COMPLETED_RESPONDER_FINAL);
    let failed = count(&n.a_metrics, RESPONDER_ROUND_REPLY_SEND_FAILED);

    let t0 = Instant::now();
    n.open(b"row-behind-the-held-reply").await;
    wait_for("A stepped the Deliver", Duration::from_secs(90), || {
        count(&n.a_metrics, RESPONDER_ROUND_COMPLETED_RESPONDER_FINAL) > done
    })
    .await;
    let stepped_after = t0.elapsed();
    let failed_by_then = count(&n.a_metrics, RESPONDER_ROUND_REPLY_SEND_FAILED) - failed;
    eprintln!(
        "CIRISEdge#943 real path: Deliver stepped {stepped_after:?} after the round-open, \
         {failed_by_then} reply send(s) had failed by then"
    );
    assert_eq!(
        failed_by_then, 0,
        "the Deliver waited out the reply's failure: stepped {stepped_after:?} after the \
         round-open, behind {failed_by_then} failed send(s)"
    );
    wait_for(
        "the reply fails, and is counted",
        Duration::from_secs(90),
        || count(&n.a_metrics, RESPONDER_ROUND_REPLY_SEND_FAILED) > failed,
    )
    .await;
    eprintln!(
        "CIRISEdge#943 real path: the reply failed {:?} after the round-open",
        t0.elapsed()
    );

    // The path heals: the next round, a new id, runs. Nothing of the dead one
    // holds it.
    for link in n.a.reverse_links_for_test(&n.b_key).await {
        n.a.stop_acks_on_link_for_test(link, None);
    }
    n.a.refuse_outbound_dials_for_test(false);
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        let round = n.open(b"row-after-the-heal").await;
        let hit = tokio::time::timeout(Duration::from_secs(10), async {
            while !replied(&n.replies, round, "diff") {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        if hit.is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no round completed after the heal: {:?}",
            n.a_metrics.responder_rounds_total()
        );
    }
}
