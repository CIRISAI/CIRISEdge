//! `transport_reticulum_inbound_contention` — the bench that TESTS whether the
//! leviculum#29 node-lock win is visible at edge's transport seam. It is not: the
//! A/B below is a rigorous negative (checked two ways), and that is the finding.
//!
//! # Why this exists (and why the loopback bench can't show it)
//!
//! `transport_reticulum_loopback` is a single-link ping-pong: send, wait,
//! receive, reply. leviculum#29 fixed *inbound crypto blocking outbound sends
//! under CONTENTION* — a `Mutex<StdNodeCore>` that serialized every inbound
//! decrypt against every outbound send. A single serial link has no contention
//! to relieve, so moving crypto off the lock changes its latency by ~0. The
//! improvement is invisible to any bench that doesn't drive a node's inbound and
//! outbound paths AT THE SAME TIME.
//!
//! # Shape (leviculum's OWN metric: the inbound dip)
//!
//! One **victim** node V, one **sink** S, and `N_FLOODERS` flooder peers that
//! continuously send small packets to V. The flood is ALWAYS on — V is always
//! receiving. We time V draining `DRAIN_K` frames from its own inbound sink (the
//! inverse of its inbound DECRYPT rate) under two conditions:
//!   - `inbound_drain/quiescent`     — V is NOT sending.
//!   - `inbound_drain/while_sending` — V is ALSO sending resources to S, so it is
//!     contending for its own node lock.
//!
//! The signal is the RATIO `while_sending / quiescent` — leviculum's "inbound dip
//! while sending resources" (1.3% on v0.15.0, 32% before #29 stage 1). Pre-#29 V's
//! outbound send holds the node lock and stalls inbound decrypt → the drain slows;
//! post-#29 the two converge. (An earlier variant measured OUTBOUND latency under
//! flood instead; same negative result — see below.)
//!
//! # The A/B result — a NEGATIVE result, and that IS the finding
//!
//! Run locally on both leviculum pins (N=8 flooders, 64 KiB victim send, this host):
//!
//! | metric \ leviculum          | v0.15.0 (post-#29) | v0.14.0 (pre-#29) |
//! |-----------------------------|--------------------|-------------------|
//! | inbound_drain quiescent     | 6.90 s             | 6.48 s            |
//! | inbound_drain while_sending | 10.30 s            | 10.48 s           |
//! | → dip ratio                 | 1.49×              | 1.62×             |
//! | (earlier) outbound quiescent| 97.1 ms            | 93.8 ms           |
//! | (earlier) outbound + flood  | 143.7 ms           | 133.4 ms          |
//! | → inflation                 | 1.48×              | 1.42×             |
//!
//! Both metrics, both versions: STATISTICALLY INDISTINGUISHABLE. The `while_sending`
//! drains are identical (10.30 vs 10.48 s, CIs fully overlapping); the dip is ~1.5×
//! on BOTH, and the 1.49-vs-1.62 gap is inside the ±11% run-to-run noise. So the dip
//! is CPU + loopback-TCP contention (V's send task competing for CPU/TCP with its
//! own inbound), NOT the node lock #29 removed.
//!
//! WHY edge cannot see #29: the win is a µs-scale PER-PACKET lock-hold (35µs→1.2µs)
//! measured by instrumenting leviculum's OWN `Mutex<StdNodeCore>`. At edge's seam,
//! V's whole-stack inbound rate here is ~72 frames/s — dominated by edge's per-frame
//! attribution/decode, not raw packet decrypt — and on localhost the `while_sending`
//! penalty is CPU/TCP, identical across versions. A ~34µs/packet lock-hold reduction
//! is invisible against that. **leviculum's per-packet lock-hold measurement is the
//! authoritative one; it lives one layer below edge's transport seam, and edge is
//! the wrong altitude to observe #29.**
//!
//! # On the .io trend page (CIRISEdge#369)
//!
//! It is version-blind for the µs-scale #29 class — but it still runs on the
//! bench.yml TREND lane (alert-SUPPRESSED like the other transport families, #461,
//! so it never gates), because a COARSE end-to-end concurrency change — a new
//! fan-out strategy, a scheduling regression, an algorithmic throughput shift —
//! WOULD move these numbers and show up on cirisai.github.io/CIRISEdge. That is the
//! "so future enhancements show up" goal: this is the standardized concurrency trend
//! edge did not have. It is a real-multi-node bench whose transport timing can flake
//! on a loaded runner, so bench.yml runs it TOLERANTLY (a failed run is a WARNING,
//! not a red job — a missed trend point, never a gate). It also stands as the PROOF
//! of the A/B above and a reusable real-transport concurrency harness.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::field_reassign_with_default,
    clippy::needless_raw_string_hashes
)]
#![cfg(feature = "transport-reticulum")]

#[path = "common/mod.rs"]
mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ciris_edge::identity::LocalSigner;
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
use ciris_edge::transport::reticulum::{
    ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_edge::HybridPolicy;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use serde_json::value::RawValue;
use tokio::sync::{mpsc, Mutex};

use common::{build_in_memory_backend, signed_record, BenchFedKey};

/// How many independent flooder peers hammer V's inbound path. Each is a distinct
/// link → a distinct concurrent inbound-decrypt task contending for V's node lock,
/// which is what leviculum#29's 20–40-link fan-out reproduced. Kept modest so the
/// N+2-node mutual discovery at fixture build stays under the timeout.
const N_FLOODERS: usize = 8;
/// The measured outbound payload. leviculum#29 used 1 MiB; edge's loopback bench
/// tops out at a PROVEN-deliverable 64 KiB, so this rides the resource path
/// (segmented, > the ~470 B MDU) at a size this harness reassembles reliably.
/// Bigger sizes hold V's node lock longer (a stronger contention signal) but were
/// not reliably delivered by the multi-node fixture; 64 KiB is the honest floor.
const RESOURCE_BYTES: usize = 64 * 1024;
/// Small flood packets — sized to ride the packet path, so the flood is a HIGH
/// RATE of lock acquisitions on V (many small inbound decrypts/sec), not a few
/// big transfers.
const FLOOD_BYTES: usize = 256;

async fn signer_for(key: &BenchFedKey, base: &std::path::Path) -> Arc<LocalSigner> {
    let seed_dir = key.write_seed_dir(base);
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: key.key_id.clone(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(key.ml_dsa_signer());
    Arc::new(LocalSigner::new(key.key_id.clone(), classical, Some(pqc)))
}

async fn auth_for(
    key: &BenchFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

async fn wait_for<F, Fut>(timeout: Duration, mut cond: F) -> bool
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if cond().await {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn envelope_to(dst: &str, src: &str, body_size: usize) -> Vec<u8> {
    let payload = "x".repeat(body_size.saturating_sub(48));
    let body = RawValue::from_string(format!(r#"{{"text":"{payload}"}}"#)).expect("raw value");
    let env = EdgeEnvelope {
        edge_schema_version: SchemaVersion::V2_0_0,
        signing_key_id: src.into(),
        destination_key_id: dst.into(),
        message_type: MessageType::OpaqueEvent,
        sent_at: Utc::now(),
        nonce: [0x5a; 16],
        body,
        signature: "ZmFrZS1lZDI1NTE5LXNpZ25hdHVyZS1ieXRlcw==".to_string(),
        signature_pqc: None,
        in_reply_to: None,
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
    };
    serde_json::to_vec(&env).expect("serialize")
}

/// A built node kept alive for the bench's lifetime.
struct Node {
    key_id: String,
    transport: Arc<ReticulumTransport>,
    _listen: tokio::task::JoinHandle<()>,
}

struct ContentionFixture {
    victim: Node,
    /// V's OWN inbound sink — the flood lands here. Draining a fixed count from it
    /// measures V's inbound DECRYPT rate (the leviculum#29 metric), which dips when
    /// V is also holding the node lock to send (pre-#29).
    victim_rx: Arc<Mutex<mpsc::Receiver<InboundFrame>>>,
    /// S's sink — where V's outbound resource lands. Kept alive so V's sends have a
    /// live receiver during the `while_sending` case.
    _sink_rx: Arc<Mutex<mpsc::Receiver<InboundFrame>>>,
    flooders: Vec<Node>,
    _tmp: tempfile::TempDir,
}

async fn build_node(
    key: &BenchFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
    listen_port: u16,
    bootstrap: &[u16],
    sink_cap: usize,
) -> (Node, Arc<Mutex<mpsc::Receiver<InboundFrame>>>) {
    let mut cfg = ReticulumTransportConfig::new(
        base.join(format!("{}/transport.id", key.key_id)),
        &key.key_id,
    );
    cfg.listen_addr = format!("127.0.0.1:{listen_port}").parse().unwrap();
    cfg.bootstrap_peers = bootstrap
        .iter()
        .map(|p| format!("127.0.0.1:{p}").parse().unwrap())
        .collect();
    cfg.announce_interval = Duration::from_secs(1);
    let auth = auth_for(key, directory, base).await;
    let transport = Arc::new(
        ReticulumTransport::new(cfg, auth)
            .await
            .expect("build transport"),
    );
    let (tx, rx) = mpsc::channel::<InboundFrame>(sink_cap);
    let l = transport.clone();
    let listen = tokio::spawn(async move {
        let _ = l.listen(tx).await;
    });
    (
        Node {
            key_id: key.key_id.clone(),
            transport,
            _listen: listen,
        },
        Arc::new(Mutex::new(rx)),
    )
}

async fn build_fixture() -> ContentionFixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let base = tmp.path();

    let steward = BenchFedKey::new("steward-contention", 0x01);
    let victim_key = BenchFedKey::new("edge-victim", 0x0a);
    let sink_key = BenchFedKey::new("edge-sink", 0x0b);
    let flooder_keys: Vec<BenchFedKey> = (0..N_FLOODERS)
        .map(|i| BenchFedKey::new(&format!("edge-flooder-{i}"), 0x20 + i as u8))
        .collect();

    // Everyone is an admitted agent under the one steward → all mutually rootable.
    let mut records = vec![
        signed_record(&steward, &steward, "steward"),
        signed_record(&victim_key, &steward, "agent"),
        signed_record(&sink_key, &steward, "agent"),
    ];
    for f in &flooder_keys {
        records.push(signed_record(f, &steward, "agent"));
    }
    let directory = build_in_memory_backend(records).await;

    // Build order matters: a node DIALS its bootstrap peers, so the dialee must be
    // up first, and the SENDER must dial the RECEIVER (the working loopback bench's
    // rule — an established outbound link is what a `send` rides). So: S (sink)
    // listens with no dial; V dials S (for the measured V → S resource); the
    // flooders dial V (for the inbound flood F → V). V is thus dialed BY the
    // flooders (its inbound) and dials OUT to S (its outbound) — the two paths that
    // contend on V's node lock, which is the whole point.
    let sink_port = free_port();
    let victim_port = free_port();
    let (_sink, sink_rx) =
        build_node(&sink_key, directory.clone(), base, sink_port, &[], 256).await;
    let (victim, victim_rx) = build_node(
        &victim_key,
        directory.clone(),
        base,
        victim_port,
        &[sink_port],
        // Small inbound buffer: the drain must be limited by V's DECRYPT rate, not
        // by pulling a large pre-filled backlog — a big buffer would hide the dip.
        256,
    )
    .await;

    let mut flooders = Vec::with_capacity(N_FLOODERS);
    for f in &flooder_keys {
        // Flooder sinks are tiny + drained-by-drop: we never read them, the
        // flooders only SEND. A small bounded channel keeps memory flat.
        let (node, _rx) =
            build_node(f, directory.clone(), base, free_port(), &[victim_port], 16).await;
        flooders.push(node);
    }

    // Discovery, paid ONCE (outside the measured loop): V must root S (to send the
    // measured resource), and every flooder must root V (to flood it).
    let ok = wait_for(Duration::from_secs(180), || {
        let vt = victim.transport.clone();
        async move { vt.knows_peer("edge-sink").await }
    })
    .await;
    assert!(ok, "victim did not root the sink within 180s");
    for f in &flooders {
        let fid = f.key_id.clone();
        let ft = f.transport.clone();
        let rooted = wait_for(Duration::from_secs(180), || {
            let ft = ft.clone();
            async move { ft.knows_peer("edge-victim").await }
        })
        .await;
        assert!(rooted, "flooder {fid} did not root the victim within 180s");
    }

    // Let every rooted link settle into a resource-capable state (LINKIDENTIFY +
    // first reverse-path exchange) before the measured sends — a just-rooted peer
    // has an announce but not necessarily a resource-ready link.
    tokio::time::sleep(Duration::from_secs(3)).await;

    ContentionFixture {
        victim,
        victim_rx,
        _sink_rx: sink_rx,
        flooders,
        _tmp: tmp,
    }
}

/// How many inbound frames the measured drain pulls per iteration. Large enough
/// that the time is dominated by V's steady-state DECRYPT rate, not the initial
/// buffer flush.
const DRAIN_K: usize = 200;

/// The measured metric (leviculum#29's own): drain [`DRAIN_K`] frames from V's OWN
/// inbound sink and time it — `time / DRAIN_K` is the inverse of V's inbound
/// DECRYPT rate. The leading `try_recv` flush drops any pre-filled backlog so the
/// timed frames are FRESH decrypts (V's small buffer + this flush keep the drain
/// limited by decrypt throughput, not by pulling a queue). Pre-#29, V holding the
/// node lock to send stalls inbound decrypt → this drain SLOWS (the "inbound dip").
async fn drain_k(rx: &Arc<Mutex<mpsc::Receiver<InboundFrame>>>, k: usize) {
    let mut g = rx.lock().await;
    while g.try_recv().is_ok() {} // flush backlog → measure fresh decrypts only
    for _ in 0..k {
        let frame = tokio::time::timeout(Duration::from_secs(60), g.recv())
            .await
            .expect("inbound drain timed out — the flood stalled")
            .expect("victim inbound channel closed");
        black_box(frame.envelope_bytes);
    }
}

/// Background loop: V sends [`RESOURCE_BYTES`] resources to S until `stop`. This is
/// the OUTBOUND work whose node-lock hold dips V's inbound decrypt rate pre-#29 —
/// run concurrently with the `while_sending` drain, silent on the quiescent one.
fn start_victim_sending(
    victim: Arc<ReticulumTransport>,
    rt: &tokio::runtime::Runtime,
    stop: Arc<AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    rt.spawn(async move {
        let bytes = envelope_to("edge-sink", "edge-victim", RESOURCE_BYTES);
        while !stop.load(Ordering::Relaxed) {
            // Best-effort — a backpressured send is fine; the point is that V is
            // CONTENDING for its own node lock while the drain measures inbound.
            let _ = victim.send("edge-sink", &bytes).await;
        }
    })
}

/// Spawn the sustained inbound flood: every flooder loops small sends → V until
/// `stop` is set. Returns the handles (aborted when dropped at group end).
fn start_flood(
    flooders: &[Node],
    rt: &tokio::runtime::Runtime,
    stop: Arc<AtomicBool>,
) -> Vec<tokio::task::JoinHandle<()>> {
    flooders
        .iter()
        .map(|f| {
            let t = f.transport.clone();
            let src = f.key_id.clone();
            let stop = stop.clone();
            rt.spawn(async move {
                let bytes = envelope_to("edge-victim", &src, FLOOD_BYTES);
                while !stop.load(Ordering::Relaxed) {
                    // Best-effort: a backpressured/dropped flood packet is fine —
                    // we want sustained lock PRESSURE on V, not delivery.
                    let _ = t.send("edge-victim", &bytes).await;
                }
            })
        })
        .collect()
}

fn bench_inbound_contention(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(6)
        .enable_all()
        .build()
        .expect("tokio multi-thread runtime");
    let fixture = rt.block_on(build_fixture());

    let mut group = c.benchmark_group("transport_reticulum_inbound_contention");
    group
        .sample_size(10)
        .measurement_time(Duration::from_secs(20));

    // The inbound flood is ALWAYS on for BOTH cases — V is always receiving. The
    // only thing that changes is whether V is ALSO sending, i.e. whether it is
    // contending for its own node lock. That is the leviculum#29 axis.
    let flood_stop = Arc::new(AtomicBool::new(false));
    let flood_handles = start_flood(&fixture.flooders, &rt, flood_stop.clone());
    // Ramp so the flood is saturating V's inbound decrypt before we measure.
    rt.block_on(async { tokio::time::sleep(Duration::from_secs(5)).await });

    // Case 1: V's inbound drain rate with V NOT sending — the baseline decrypt rate.
    {
        let rx = fixture.victim_rx.clone();
        group.bench_function("inbound_drain/quiescent", |b| {
            let rx = rx.clone();
            b.to_async(&rt).iter(|| {
                let rx = rx.clone();
                async move { drain_k(&rx, DRAIN_K).await }
            });
        });
    }

    // Case 2: V's inbound drain rate while V is ALSO sending resources to S.
    // Pre-#29, V's outbound send holds the node lock and stalls inbound decrypt →
    // the drain SLOWS (the "inbound dip"). Post-#29 the two cases converge.
    {
        let send_stop = Arc::new(AtomicBool::new(false));
        let send_handle =
            start_victim_sending(fixture.victim.transport.clone(), &rt, send_stop.clone());
        // Let V's sending ramp so it is genuinely contending during the drain.
        rt.block_on(async { tokio::time::sleep(Duration::from_secs(1)).await });

        let rx = fixture.victim_rx.clone();
        group.bench_function("inbound_drain/while_sending", |b| {
            let rx = rx.clone();
            b.to_async(&rt).iter(|| {
                let rx = rx.clone();
                async move { drain_k(&rx, DRAIN_K).await }
            });
        });

        send_stop.store(true, Ordering::Relaxed);
        send_handle.abort();
    }

    flood_stop.store(true, Ordering::Relaxed);
    for h in flood_handles {
        h.abort();
    }
    group.finish();
}

criterion_group!(benches, bench_inbound_contention);
criterion_main!(benches);
