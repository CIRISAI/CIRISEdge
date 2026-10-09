//! **CIRISEdge#856 — a configurable misbehaving peer, against a real responder.**
//!
//! Reusable: a later floor or bound is tested by giving a peer the knobs that
//! misbehave in the new way. Everything rides real Reticulum on loopback.
//!
//! - [`Responder`] is the node under test: a `ReticulumTransport` on
//!   `127.0.0.1`, a `ReplicationRuntime` that only responds, and the inbound
//!   router.
//! - [`Peer`] is one identity: its own `ReticulumTransport`, rooted on the
//!   responder (and the responder on it), speaking SCRIPTED anti-entropy rounds
//!   on the `Key` plane so each knob is exact rather than emergent. A peer's
//!   inbound frames come to the fixture, not to a runtime, so the knobs on what
//!   it accepts are the fixture's.
//!
//! The knobs ([`Knobs`]), each independent:
//! - `dial_interval` — `Some(d)`: every round rides a FRESH link and the old
//!   one is left up (leaked from the pool, not closed), `d` apart: the
//!   link-up rate. `None`: one pooled link, reused.
//! - `complete_rounds` — `false`: the peer opens a round, takes the reply and
//!   goes silent, so no round it opens ever completes.
//! - `max_segments` — `Some(n)`: a reply needing more than `n` Resource
//!   segments is dropped on arrival, as a build that cannot reassemble it does.
//! - `dial_at_all` — `false`: the peer roots and never dials.
//! - `identities_per_source` — how many identities share this peer's source
//!   address.
//! - `wire` — the framing the peer opens rounds with (v3, or legacy v1/v2).
//! - `source` — the loopback address it dials from, which is its source
//!   address at the responder.
#![allow(dead_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use ciris_edge::identity::LocalSigner;
use ciris_edge::replication::protocol::{
    DeliverMessage, DiffMessage, EnvelopeRef, ReplicationMessage, SummaryMessage,
};
use ciris_edge::replication::responder_bounds::NoProgressPolicy;
use ciris_edge::replication::wire_frame::{self, RoundSide, SINGLE_SEGMENT_MAX_BYTES};
use ciris_edge::replication::{
    self_publish_set, EnvelopeKind, InboundRouter, ReplicationRuntime, ReplicationRuntimeConfig,
};
use ciris_edge::transport::link_up_bounds::LinkUpRatePolicy;
use ciris_edge::transport::reticulum::{
    LinkDirection, ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::RootingDirectory;
use ciris_persist::federation::FederationDirectory;
use tokio::sync::{mpsc, Mutex};

use crate::common::{
    build_reticulum_with_retry_metrics, directory_with, prime_v7_peer_pair, signed_record,
    TestFedKey,
};

/// The plane every scripted round runs on.
pub const KIND: EnvelopeKind = EnvelopeKind::Key;

/// How long a peer waits for a reply frame before calling a round unserved.
pub const REPLY_WAIT: Duration = Duration::from_millis(2_500);

/// The framing a peer opens rounds with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wire {
    /// v3: round-correlated (edge v26.0.0+).
    V3,
    /// v1/v2: legacy, no round id (pre-v26).
    Legacy,
}

/// The address a peer dials from — its source address at the responder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `127.0.0.1`, straight to the responder.
    Direct,
    /// `127.0.0.<n>` (`n` ≥ 2), through a fixture proxy whose outbound socket
    /// is bound to that address (the whole of `127/8` is local on Linux). A
    /// peer cannot pick its own source otherwise: the kernel answers
    /// `127.0.0.1` for any loopback destination, and leviculum's TCP server
    /// cannot listen on IPv6 at the pin (it formats `listen_ip:port` without
    /// brackets).
    Loopback(u8),
}

/// See the module docs.
#[derive(Debug, Clone, Copy)]
pub struct Knobs {
    pub dial_interval: Option<Duration>,
    pub complete_rounds: bool,
    pub max_segments: Option<usize>,
    pub dial_at_all: bool,
    pub identities_per_source: usize,
    pub wire: Wire,
    pub source: Source,
}

impl Knobs {
    /// A healthy peer: one pooled link, rounds completed, multi-segment
    /// replies taken, v3, from `127.0.0.2`.
    #[must_use]
    pub fn healthy() -> Self {
        Self {
            dial_interval: None,
            complete_rounds: true,
            max_segments: None,
            dial_at_all: true,
            identities_per_source: 1,
            wire: Wire::V3,
            source: Source::Loopback(2),
        }
    }

    /// The misbehaving baseline: as [`Self::healthy`] but from `127.0.0.1`;
    /// each test turns the knobs it needs.
    #[must_use]
    pub fn misbehaving() -> Self {
        Self {
            source: Source::Direct,
            ..Self::healthy()
        }
    }
}

/// The responder's bounds for one run; `Default` is production's.
#[derive(Debug, Clone, Default)]
pub struct ResponderConfig {
    pub link_up: LinkUpRatePolicy,
    pub no_progress: NoProgressPolicy,
    pub silence_bounds: Vec<Duration>,
    /// Extra `Key` rows the responder holds and publishes, so a peer that
    /// wants them all gets a reply past one Resource segment.
    pub bulk_keys: usize,
}

/// The node under test.
pub struct Responder {
    pub key: TestFedKey,
    pub transport: Arc<ReticulumTransport>,
    pub metrics: ciris_edge::EdgeMetrics,
    pub runtime: Arc<ReplicationRuntime>,
    port: u16,
}

impl Responder {
    /// Live inbound links in the responder's link-direction ledger.
    #[must_use]
    pub fn inbound_links(&self) -> usize {
        self.transport
            .link_directions_for_test()
            .iter()
            .filter(|(_, d)| *d == LinkDirection::Inbound)
            .count()
    }

    /// A one-line account of the responder's link-ups, for assertion messages.
    #[must_use]
    pub fn link_report(&self) -> String {
        format!(
            "inbound={} refused={:?} link_up_total={:?} closed={:?} dirs={:?}",
            self.inbound_links(),
            self.metrics.link_ups_refused_total(),
            self.metrics.responder_link_up_total(),
            self.metrics.inbound_link_closed_by_reason(),
            self.transport
                .link_directions_for_test()
                .iter()
                .map(|(id, d)| format!("{}:{d:?}", hex::encode(&id[..4])))
                .collect::<Vec<_>>()
        )
    }

    #[must_use]
    pub fn refused(&self, reason: &str) -> u64 {
        self.metrics.link_ups_refused_total()[reason]
    }

    /// `responder_rounds_total{kind=KIND, outcome}`.
    #[must_use]
    pub fn rounds(&self, outcome: &str) -> u64 {
        self.metrics
            .responder_rounds_total()
            .get(&format!("{}:{outcome}", KIND.as_wire_str()))
            .copied()
            .unwrap_or(0)
    }
}

/// What a scripted round came to, seen from the peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundResult {
    /// No reply within [`REPLY_WAIT`].
    NotServed,
    /// Replied to; the peer then went silent (`complete_rounds: false`).
    Abandoned,
    /// The peer drove it to the end (Diff, the responder's Deliver, Deliver).
    Completed,
    /// Served up to the Diff; the responder's Deliver never arrived.
    NoDeliver,
}

/// One peer identity.
pub struct Peer {
    pub key: TestFedKey,
    pub knobs: Knobs,
    pub transport: Arc<ReticulumTransport>,
    pub metrics: ciris_edge::EdgeMetrics,
    rx: Mutex<mpsc::Receiver<InboundFrame>>,
    next_round: AtomicU64,
    /// `complete_rounds`, switchable mid-run (a peer that recovers).
    complete: AtomicBool,
    /// The largest frame that arrived from the responder.
    pub max_frame_seen: AtomicUsize,
    /// Frames dropped by `max_segments`.
    pub oversized_dropped: AtomicU64,
    responder_key: String,
}

/// A responder and its peers, groups in the order their knobs were given.
pub struct Harness {
    pub responder: Responder,
    pub groups: Vec<Vec<Arc<Peer>>>,
    _tasks: Vec<tokio::task::JoinHandle<()>>,
    _tmp: tempfile::TempDir,
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral")
        .local_addr()
        .expect("local addr")
        .port()
}

/// A TCP proxy to `127.0.0.1:target` whose outbound connections come from
/// `127.0.0.<n>`. Returns the port to dial.
async fn source_proxy(target: u16, n: u8, tasks: &mut Vec<tokio::task::JoinHandle<()>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let port = listener.local_addr().expect("proxy addr").port();
    let from = std::net::SocketAddr::from(([127, 0, 0, n], 0));
    let to = std::net::SocketAddr::from(([127, 0, 0, 1], target));
    tasks.push(tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            tokio::spawn(async move {
                let sock = tokio::net::TcpSocket::new_v4().expect("socket");
                sock.bind(from).expect("bind the proxy's source address");
                let Ok(mut outbound) = sock.connect(to).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    }));
    port
}

async fn signer_for(key: &TestFedKey, base: &std::path::Path) -> Arc<LocalSigner> {
    let seed_dir = key.write_seed_dir(base);
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: key.key_id.clone(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");
    let pqc: Arc<dyn ciris_keyring::PqcSigner> = Arc::new(key.pqc_signer());
    Arc::new(LocalSigner::new(key.key_id.clone(), classical, Some(pqc)))
}

async fn auth_for(
    key: &TestFedKey,
    directory: Arc<ciris_persist::store::sqlite::SqliteBackend>,
    base: &std::path::Path,
) -> ReticulumAuth {
    ReticulumAuth {
        signer: Some(signer_for(key, base).await),
        rooting: Some(directory as Arc<dyn RootingDirectory>),
        resolver: None,
        hybrid_policy: ciris_edge::HybridPolicy::Ed25519Fallback,
        ..ReticulumAuth::default()
    }
}

/// Poll `cond` every 100 ms until it holds or `timeout` passes.
pub async fn wait_for<F, Fut>(timeout: Duration, mut cond: F) -> bool
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

impl Harness {
    /// Start a responder with `config` and one group of
    /// `identities_per_source` peers per entry of `groups`, every peer rooted
    /// on the responder and the responder on it.
    #[allow(clippy::too_many_lines)]
    pub async fn start(tag: &str, config: ResponderConfig, groups: &[Knobs]) -> Self {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("warn,ciris_edge=info")
            .try_init();
        let tmp = tempfile::tempdir().expect("tempdir");
        let steward = TestFedKey::new(&format!("steward-856-{tag}"), 0x01);
        let r_key = TestFedKey::new(&format!("responder-856-{tag}"), 0x02);
        let mut seed = 0x10u8;
        let peer_keys: Vec<Vec<TestFedKey>> = groups
            .iter()
            .enumerate()
            .map(|(g, k)| {
                (0..k.identities_per_source)
                    .map(|i| {
                        seed = seed.wrapping_add(1);
                        TestFedKey::new(&format!("peer-856-{tag}-g{g}-i{i}"), seed)
                    })
                    .collect()
            })
            .collect();
        let bulk: Vec<TestFedKey> = (0..config.bulk_keys)
            .map(|i| {
                let mut k = TestFedKey::new(&format!("bulk-856-{tag}-{i:04}"), 0x80);
                let [lo, hi, ..] = i.to_le_bytes();
                k.seed[1] = lo;
                k.seed[2] = hi;
                k
            })
            .collect();
        let mut records = vec![
            signed_record(&steward, &steward, "steward"),
            signed_record(&r_key, &steward, "agent"),
        ];
        for k in peer_keys.iter().flatten() {
            records.push(signed_record(k, &steward, "agent"));
        }
        for k in &bulk {
            records.push(signed_record(k, &steward, "agent"));
        }
        let directory = directory_with(records).await;

        let metrics = ciris_edge::EdgeMetrics::new();
        let (transport, addr) = build_reticulum_with_retry_metrics(
            || {
                let key = &r_key;
                let dir = directory.clone();
                let base = tmp.path().to_path_buf();
                async move {
                    let mut c =
                        ReticulumTransportConfig::new(base.join("r/transport.id"), &key.key_id);
                    c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                    c.announce_interval = Duration::from_secs(2);
                    let auth = auth_for(key, dir, &base).await;
                    (c, auth)
                }
            },
            metrics.clone(),
        )
        .await;
        let port = addr.port();
        // A fast reaper tick, so the rooted set reaches the metrics quickly;
        // the inbound idle bound stays long (links leak on purpose here).
        transport.set_link_pool_policy(Duration::from_secs(2), 4);
        transport.set_inbound_link_idle_bound(Duration::from_secs(600));
        transport.set_link_up_rate_policy(config.link_up);
        metrics.set_rooted_silence_bounds(config.silence_bounds.clone());

        let mut publish: Vec<String> = vec![r_key.key_id.clone()];
        publish.extend(bulk.iter().map(|k| k.key_id.clone()));
        let runtime = Arc::new(
            ReplicationRuntime::start(
                Arc::clone(&directory) as Arc<dyn FederationDirectory>,
                Arc::clone(&transport) as Arc<dyn Transport>,
                Vec::new(),
                ReplicationRuntimeConfig {
                    local_key_id: Some(r_key.key_id.clone()),
                    metrics: Some(metrics.clone()),
                    responder_no_progress: config.no_progress,
                    ..Default::default()
                },
                Some(self_publish_set(publish)),
            )
            .await,
        );
        let mut tasks = Vec::new();
        let (tx, mut rx) = mpsc::channel::<InboundFrame>(1024);
        let t = Arc::clone(&transport);
        tasks.push(tokio::spawn(async move {
            let _ = t.listen(tx).await;
        }));
        let router = InboundRouter::new(runtime.registry());
        tasks.push(tokio::spawn(async move {
            while let Some(frame) = rx.recv().await {
                let _ = router.try_route(&frame).await;
            }
        }));

        let mut out_groups = Vec::new();
        for (g, (knobs, keys)) in groups.iter().zip(peer_keys).enumerate() {
            let mut group = Vec::new();
            for (i, key) in keys.into_iter().enumerate() {
                let pm = ciris_edge::EdgeMetrics::new();
                let dial = match knobs.source {
                    Source::Direct => port,
                    Source::Loopback(n) => source_proxy(port, n, &mut tasks).await,
                };
                let bootstrap = format!("127.0.0.1:{dial}");
                let (pt, _) = build_reticulum_with_retry_metrics(
                    || {
                        let key = &key;
                        let dir = directory.clone();
                        let base = tmp.path().to_path_buf();
                        let bootstrap = bootstrap.clone();
                        async move {
                            let mut c = ReticulumTransportConfig::new(
                                base.join(format!("p{g}-{i}/transport.id")),
                                &key.key_id,
                            );
                            c.listen_addr = format!("127.0.0.1:{}", free_port()).parse().unwrap();
                            c.bootstrap_peers = vec![bootstrap.parse().unwrap()];
                            c.announce_interval = Duration::from_secs(2);
                            let auth = auth_for(key, dir, &base).await;
                            (c, auth)
                        }
                    },
                    pm.clone(),
                )
                .await;
                pt.set_link_pool_policy(Duration::from_secs(600), 4);
                prime_v7_peer_pair(&transport, &r_key.key_id, &pt, &key.key_id).await;
                let (ptx, prx) = mpsc::channel::<InboundFrame>(256);
                let lt = Arc::clone(&pt);
                tasks.push(tokio::spawn(async move {
                    let _ = lt.listen(ptx).await;
                }));
                group.push(Arc::new(Peer {
                    key,
                    knobs: *knobs,
                    transport: pt,
                    metrics: pm,
                    rx: Mutex::new(prx),
                    next_round: AtomicU64::new(1),
                    complete: AtomicBool::new(knobs.complete_rounds),
                    max_frame_seen: AtomicUsize::new(0),
                    oversized_dropped: AtomicU64::new(0),
                    responder_key: r_key.key_id.clone(),
                }));
            }
            out_groups.push(group);
        }
        Self {
            responder: Responder {
                key: r_key,
                transport,
                metrics,
                runtime,
                port,
            },
            groups: out_groups,
            _tasks: tasks,
            _tmp: tmp,
        }
    }
}

impl Peer {
    fn frame(&self, msg: &ReplicationMessage, round: u64) -> Vec<u8> {
        match self.knobs.wire {
            Wire::V3 => wire_frame::wrap_v3(msg, RoundSide::Initiator, round),
            Wire::Legacy => wire_frame::wrap_for_kind(msg),
        }
    }

    async fn send(&self, msg: &ReplicationMessage, round: u64) -> bool {
        self.transport
            .send(&self.responder_key, &self.frame(msg, round))
            .await
            .is_ok()
    }

    /// The next reply frame of `round` from the responder within `wait`,
    /// after the `max_segments` filter. Frames of other rounds are discarded.
    async fn reply(&self, round: u64, wait: Duration) -> Option<ReplicationMessage> {
        let mut rx = self.rx.lock().await;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let frame = tokio::time::timeout_at(deadline, rx.recv()).await.ok()??;
            let len = frame.envelope_bytes.len();
            self.max_frame_seen.fetch_max(len, Ordering::Relaxed);
            if let Some(n) = self.knobs.max_segments {
                if len > n.saturating_mul(SINGLE_SEGMENT_MAX_BYTES) {
                    self.oversized_dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            }
            let Ok(Some(framed)) = wire_frame::try_unwrap_framed(&frame.envelope_bytes) else {
                continue;
            };
            let ours = match (self.knobs.wire, framed.meta) {
                (Wire::V3, Some(meta)) => meta.round == round && meta.from == RoundSide::Responder,
                (Wire::Legacy, None) => true,
                _ => false,
            };
            if ours && framed.msg.kind() == KIND {
                return Some(framed.msg);
            }
        }
    }

    /// Switch `complete_rounds` mid-run.
    pub fn set_complete_rounds(&self, on: bool) {
        self.complete.store(on, Ordering::Relaxed);
    }

    /// Drain anything queued from earlier rounds.
    pub async fn drain(&self) {
        let mut rx = self.rx.lock().await;
        while rx.try_recv().is_ok() {}
    }

    /// Open one round and play it out per the knobs. The peer's Diff asks
    /// for every ref the responder's Summary offered when `want_all`, else
    /// for nothing.
    pub async fn round(&self, want_all: bool) -> RoundResult {
        if self.knobs.dial_interval.is_some() {
            self.transport.leak_pooled_links_for_test().await;
        }
        let round = self.next_round.fetch_add(1, Ordering::Relaxed);
        let open = ReplicationMessage::Summary(SummaryMessage {
            kind: KIND,
            refs: Vec::new(),
        });
        if !self.send(&open, round).await {
            return RoundResult::NotServed;
        }
        // The responder answers a Summary with its own Summary and a Diff.
        let mut offered: Option<Vec<EnvelopeRef>> = None;
        let mut diffed = false;
        let deadline = tokio::time::Instant::now() + REPLY_WAIT;
        while offered.is_none() || !diffed {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.reply(round, left).await {
                Some(ReplicationMessage::Summary(s)) => offered = Some(s.refs),
                Some(ReplicationMessage::Diff(_)) => diffed = true,
                Some(_) => {}
                None => break,
            }
        }
        if offered.is_none() && !diffed {
            return RoundResult::NotServed;
        }
        if !self.complete.load(Ordering::Relaxed) {
            return RoundResult::Abandoned;
        }
        let want = if want_all {
            offered
                .unwrap_or_default()
                .iter()
                .map(|r| r.envelope_hash)
                .collect()
        } else {
            Vec::new()
        };
        let diff = ReplicationMessage::Diff(DiffMessage { kind: KIND, want });
        if !self.send(&diff, round).await {
            return RoundResult::NoDeliver;
        }
        let mut delivered = false;
        let deadline = tokio::time::Instant::now() + REPLY_WAIT * 4;
        while !delivered {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now());
            match self.reply(round, left).await {
                Some(ReplicationMessage::Deliver(_)) => delivered = true,
                Some(_) => {}
                None => break,
            }
        }
        if !delivered {
            return RoundResult::NoDeliver;
        }
        let deliver = ReplicationMessage::Deliver(DeliverMessage {
            kind: KIND,
            envelopes: Vec::new(),
        });
        if self.send(&deliver, round).await {
            RoundResult::Completed
        } else {
            RoundResult::NoDeliver
        }
    }

    /// `n` round opens on fresh links, `dial_interval` apart, without waiting
    /// for replies: the dial storm.
    pub async fn storm(&self, n: usize) -> usize {
        let pause = self.knobs.dial_interval.unwrap_or(Duration::ZERO);
        let mut sent = 0;
        for _ in 0..n {
            self.transport.leak_pooled_links_for_test().await;
            let round = self.next_round.fetch_add(1, Ordering::Relaxed);
            let open = ReplicationMessage::Summary(SummaryMessage {
                kind: KIND,
                refs: Vec::new(),
            });
            if self.send(&open, round).await {
                sent += 1;
            }
            tokio::time::sleep(pause).await;
        }
        sent
    }
}
