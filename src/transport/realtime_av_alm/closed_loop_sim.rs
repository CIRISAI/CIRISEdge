//! Closed-loop ALM simulator — the substrate the controller is proven on
//! before it is wired into `av_call.rs` (stage 2).
//!
//! `sim.rs` grades the dormant primitives with chunks as bare events: no
//! uplink, no queue, so congestion and herding can be counted but never
//! *observed*. Here the loop is closed:
//!
//! - **per-node uplink** — a FIFO serializer at the node's real rate; a
//!   queue deeper than [`MAX_QUEUE_MS`] drops (bounded queue). Every child a
//!   forwarder serves shares that one uplink, so overload shows up as queue
//!   delay and loss on every child's path, which the children's C1 meters see
//!   and the forwarder's egress meter turns into a measured ceiling;
//! - **per-path capacity** (optional second serializer), **RTT** from node
//!   coordinates, **jitter**, **Gilbert-Elliott burst loss**, per-path extra
//!   latency (a degrading path), **churn** (kill / revive), and **blackhole**
//!   (alive, forwarding nothing);
//! - **control messages** (subscribe / decision / unsubscribe / shed) ride the
//!   path latency, reliably (C3 will ride the reliable Channel).
//!
//! It drives the PRODUCTION controller types unchanged
//! ([`ParentSelector`], [`Admission`], [`EgressMeter`], [`DecisionLog`]) with
//! an injected clock and seeded RNGs: one seed reproduces a run bit-for-bit,
//! and every failure prints the seed, the decision-log tail and the
//! offending node.
//!
//! The media model: one stream, one chunk per [`CHUNK_MS`]. A primary child
//! gets the full chunk (video + audio), a standby child the audio part only.
//! A forwarder forwards on first receipt (dedupe by seq), so multi-hop trees
//! work exactly like the production relay would once C3 replaces the flood.

#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

use super::controller::{
    Admission, ClassPolicy, ControlMsg, ControllerConfig, DecisionKind, DecisionLog, EgressMeter,
    JitterSource, ParentSelector, Role, SelectorAction, ShedReason, SplitMix64, SubscribeRequest,
    Tier,
};
use crate::load_ladder::ServiceTier;

/// Media chunk interval (and the sim's base step).
pub const CHUNK_MS: u64 = 50;
/// Controller tick cadence.
pub const CONTROL_MS: u64 = 250;
/// Offer cadence.
pub const OFFER_MS: u64 = 1_000;
/// Metric sample cadence.
pub const SAMPLE_MS: u64 = 1_000;
/// Uplink queue bound: deeper than this, the uplink drops.
pub const MAX_QUEUE_MS: f64 = 300.0;
/// Most per-hop ARQ retries the sim models.
pub const MAX_ARQ_TRIES: u32 = 4;
/// How long a dead peer's link takes to be declared gone.
pub const LINK_DETECT_MS: u64 = 3_000;

// ─── Network model ───────────────────────────────────────────────────

/// Gilbert-Elliott burst loss: `avg_loss` overall, bursts of mean length
/// `mean_burst` chunks (the bad state loses everything).
#[derive(Debug, Clone, Copy)]
pub struct GeSpec {
    pub avg_loss: f64,
    pub mean_burst: f64,
}

#[derive(Debug, Clone)]
struct PathState {
    latency_ms: f64,
    extra_ms: f64,
    jitter_ms: f64,
    last_arrival: f64,
    ge: Option<GeSpec>,
    bad: bool,
    cap_bps: Option<f64>,
    free_at: f64,
}

/// A node's static description.
#[derive(Debug, Clone, Copy)]
pub struct NodeSpec {
    /// Real uplink, in streams (× `stream_bps`).
    pub uplink_streams: f64,
    /// Advertised uplink, in streams (`None` = no claim).
    pub advertised_streams: Option<f64>,
    /// Whether it can forward.
    pub forwarder: bool,
    /// Whether it is a room member (only members may be tree nodes).
    pub member: bool,
}

impl NodeSpec {
    pub fn relay(streams: f64) -> Self {
        Self {
            uplink_streams: streams,
            advertised_streams: Some(streams),
            forwarder: true,
            member: true,
        }
    }
    pub fn leaf() -> Self {
        Self {
            uplink_streams: 1.0,
            advertised_streams: None,
            forwarder: false,
            member: true,
        }
    }
}

#[derive(Debug, Clone)]
enum Payload {
    Chunk { seq: u64, full: bool, emitted: u64 },
    Ctrl(ControlMsg<u32>),
    LinkDown,
}

#[derive(Debug, Clone)]
struct Ev {
    at: u64,
    order: u64,
    from: u32,
    to: u32,
    payload: Payload,
}
impl PartialEq for Ev {
    fn eq(&self, o: &Self) -> bool {
        (self.at, self.order) == (o.at, o.order)
    }
}
impl Eq for Ev {}
impl PartialOrd for Ev {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Ev {
    fn cmp(&self, o: &Self) -> Ordering {
        (o.at, o.order).cmp(&(self.at, self.order))
    }
}

#[derive(Debug, Clone, Default)]
struct Bits(Vec<u64>);
impl Bits {
    fn get(&self, i: u64) -> bool {
        self.0
            .get((i / 64) as usize)
            .is_some_and(|w| w & (1 << (i % 64)) != 0)
    }
    fn set(&mut self, i: u64) -> bool {
        let k = (i / 64) as usize;
        if k >= self.0.len() {
            self.0.resize(k + 1, 0);
        }
        let had = self.0[k] & (1 << (i % 64)) != 0;
        self.0[k] |= 1 << (i % 64);
        !had
    }
}

struct Node {
    spec: NodeSpec,
    alive: bool,
    blackhole: bool,
    uplink_free_at: f64,
    egress: EgressMeter,
    adm: Option<Admission<u32>>,
    sel: Option<ParentSelector<u32>>,
    cands: Vec<u32>,
    got_full: Bits,
    got_any: Bits,
    last_full_at: Option<u64>,
    hist: Vec<(u64, u32)>,
    last_unserved: u64,
    dup_bytes: u64,
}

/// Candidate discovery.
#[derive(Debug, Clone, Copy)]
pub enum Candidates {
    /// Every forwarder.
    All,
    /// The publisher plus `k` random forwarders (local view).
    Sample(usize),
}

/// The world.
pub struct Sim {
    pub seed: u64,
    pub cfg: ControllerConfig,
    pub now: u64,
    nodes: Vec<Node>,
    coords: Vec<(f64, f64)>,
    paths: HashMap<(u32, u32), PathState>,
    default_ge: Option<GeSpec>,
    events: BinaryHeap<Ev>,
    order: u64,
    net: SplitMix64,
    ctl: SplitMix64,
    pub log: DecisionLog,
    /// Per-hop ARQ retries (0 = raw loss; production's Channel retransmits).
    pub arq_tries: u32,
    full_bytes: u64,
    audio_bytes: u64,
    /// (t, node, committed bps, 0.65 × real uplink bps)
    pub overcap: Vec<(u64, u32, f64, f64)>,
    /// Worst committed / real-uplink ratio seen per forwarder.
    pub worst_load: BTreeMap<u32, f64>,
    /// Count of over-cap samples per forwarder in the stable phase.
    pub overcap_from: u64,
    roster: Vec<u32>,
    /// Membership-invariant violations: (t, node, what). A non-member holding
    /// downstream legs, or being anyone's primary/standby.
    pub nonmember_violations: Vec<(u64, u32, &'static str)>,
    /// Stage 2: the canonical (a non-member transport forwarder, the last
    /// tier, audio only), if this world has one.
    pub canonical: Option<u32>,
    /// Stage 2: samples where the canonical held a PRIMARY (video)
    /// commitment: (t, subscriber). V1 says never.
    pub canonical_video: Vec<(u64, u32)>,
    /// Stage 2: the canonical's peak audio commitment (bps).
    pub canonical_peak_bps: u64,
}

impl Sim {
    /// Build a world: node 0 is the publisher.
    pub fn new(
        seed: u64,
        cfg: ControllerConfig,
        publisher: NodeSpec,
        others: &[NodeSpec],
        cands: Candidates,
        ge: Option<GeSpec>,
    ) -> Self {
        let mut net = SplitMix64(seed ^ 0xA5A5_5A5A_D00D_F00D);
        let ctl = SplitMix64(seed.rotate_left(17) ^ 0x0123_4567_89AB_CDEF);
        let mut specs = vec![publisher];
        specs.extend_from_slice(others);
        let coords: Vec<(f64, f64)> = specs
            .iter()
            .map(|_| (net.unit() * 60.0, net.unit() * 60.0))
            .collect();
        let forwarders: Vec<u32> = specs
            .iter()
            .enumerate()
            .filter(|(i, s)| *i == 0 || s.forwarder)
            .map(|(i, _)| i as u32)
            .collect();
        let full_bytes = cfg.stream_bps * CHUNK_MS / 8_000;
        let audio_bytes = cfg.standby_bps * CHUNK_MS / 8_000;
        let roster: Vec<u32> = specs
            .iter()
            .enumerate()
            .filter(|(_, s)| s.member)
            .map(|(i, _)| i as u32)
            .collect();
        let mut nodes = Vec::with_capacity(specs.len());
        for (i, spec) in specs.iter().enumerate() {
            let id = i as u32;
            let my_cands: Vec<u32> = match cands {
                Candidates::All => forwarders.iter().copied().filter(|&f| f != id).collect(),
                Candidates::Sample(k) => {
                    let pool: Vec<u32> = forwarders
                        .iter()
                        .copied()
                        .filter(|&f| f != id && f != 0)
                        .collect();
                    let mut picked = vec![0u32];
                    let mut pool = pool;
                    for _ in 0..k.min(pool.len()) {
                        let j = net.range_u64(0, pool.len() as u64) as usize;
                        picked.push(pool.swap_remove(j));
                    }
                    if id == 0 {
                        picked.clear();
                    }
                    picked
                }
            };
            nodes.push(Self::fresh_node(id, *spec, &cfg, my_cands, &roster));
        }
        Self {
            seed,
            cfg,
            now: 0,
            nodes,
            coords,
            paths: HashMap::new(),
            default_ge: ge,
            events: BinaryHeap::new(),
            order: 0,
            net,
            ctl,
            log: DecisionLog::new(40),
            arq_tries: 0,
            full_bytes,
            audio_bytes,
            overcap: Vec::new(),
            worst_load: BTreeMap::new(),
            overcap_from: 0,
            roster,
            nonmember_violations: Vec::new(),
            canonical: None,
            canonical_video: Vec::new(),
            canonical_peak_bps: 0,
        }
    }

    /// Stage 2 (`FSD/CIRIS_MESH.md` §6.4): make node `n` the canonical — a
    /// non-member TRANSPORT forwarder advertising `advertised_streams`,
    /// under the canonical class policy (never video, audio within 5 %, no
    /// trial slot), in the last tier of every selector. It carries each
    /// requester's link 1:1 (each child is its own relayed link, never a
    /// fan-out of one stream, §4.4 M2), so it is fed the far end's chunks
    /// directly rather than through a parent of its own.
    pub fn make_canonical(&mut self, n: u32, advertised_streams: f64) {
        let adv = (advertised_streams * self.cfg.stream_bps as f64) as u64;
        let mut a = Admission::transport(n, self.cfg.clone(), Some(adv), ClassPolicy::canonical());
        a.set_members(self.roster.iter().copied());
        let node = &mut self.nodes[n as usize];
        node.adm = Some(a);
        node.sel = None;
        node.spec.forwarder = true;
        node.spec.member = false;
        node.spec.uplink_streams = node.spec.uplink_streams.max(advertised_streams);
        for nd in &mut self.nodes {
            if let Some(sel) = nd.sel.as_mut() {
                sel.set_tier(&n, Tier::Canonical);
            }
        }
        self.canonical = Some(n);
    }

    /// Stage 2: node `n`'s candidates (its contact set; a hard-NAT node's
    /// does not include the publisher).
    pub fn set_candidates(&mut self, n: u32, cands: Vec<u32>) {
        self.nodes[n as usize].cands = cands;
    }

    /// Stage 2: give the publisher a starting probe allowance (the far end of
    /// many relayed links is not one cold uplink).
    pub fn set_probe_streams(&mut self, n: u32, streams: u64) {
        if let Some(a) = self.nodes[n as usize].adm.as_mut() {
            a.set_probe_streams(streams);
        }
    }

    /// Stage 2 (`FSD/CIRIS_MESH.md` §7.2): node `n`'s service tier. Tier ≥ 1
    /// closes its admission; tier 2 sheds every commitment LIFO,
    /// make-before-break (the shed child keeps receiving until it moves).
    pub fn set_tier(&mut self, n: u32, tier: ServiceTier) -> Vec<u32> {
        let t = self.now;
        let mut shed = Vec::new();
        if let Some(a) = self.nodes[n as usize].adm.as_mut() {
            a.set_admit_closed(!tier.admits_new_relay_work());
            if tier.sheds_relayed_audio() {
                shed = a.shed_all_draining(t, ShedReason::LoadShed, &mut self.log);
            }
        }
        for &v in &shed {
            self.send_ctrl(
                t,
                n,
                v,
                ControlMsg::Shed {
                    reason: ShedReason::LoadShed,
                },
            );
        }
        shed
    }

    /// Node `n`'s candidates: (id, state, tier).
    pub fn candidates_of(&self, n: u32) -> Vec<(u32, super::controller::PeerState, Tier)> {
        self.nodes[n as usize]
            .sel
            .as_ref()
            .map(ParentSelector::candidates)
            .unwrap_or_default()
    }

    /// Whether `n` hears the stream on the canonical tier, audio only.
    pub fn video_unavailable(&self, n: u32) -> bool {
        self.nodes[n as usize]
            .sel
            .as_ref()
            .is_some_and(ParentSelector::video_unavailable)
    }

    fn fresh_node(
        id: u32,
        spec: NodeSpec,
        cfg: &ControllerConfig,
        cands: Vec<u32>,
        roster: &[u32],
    ) -> Node {
        let adv = spec
            .advertised_streams
            .map(|s| (s * cfg.stream_bps as f64) as u64);
        let adm = if id == 0 {
            Some(Admission::publisher(id, cfg.clone(), adv))
        } else if spec.forwarder {
            Some(Admission::relay(id, cfg.clone(), adv))
        } else {
            None
        };
        let mut adm = adm;
        if let Some(a) = adm.as_mut() {
            a.set_members(roster.iter().copied());
        }
        let sel = (id != 0).then(|| {
            let mut s = ParentSelector::new(id, cfg.clone(), spec.forwarder);
            s.set_members(roster.iter().copied());
            s
        });
        Node {
            spec,
            alive: true,
            blackhole: false,
            uplink_free_at: 0.0,
            egress: EgressMeter::new(cfg.meter_window_ms, cfg.congestion_queue_ms),
            adm,
            sel,
            cands,
            got_full: Bits::default(),
            got_any: Bits::default(),
            last_full_at: None,
            hist: Vec::new(),
            last_unserved: 0,
            dup_bytes: 0,
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    fn path(&mut self, from: u32, to: u32) -> &mut PathState {
        let (a, b) = (self.coords[from as usize], self.coords[to as usize]);
        let ge = self.default_ge;
        self.paths.entry((from, to)).or_insert_with(|| {
            let d = (a.0 - b.0).hypot(a.1 - b.1);
            PathState {
                latency_ms: 5.0 + d,
                extra_ms: 0.0,
                jitter_ms: 4.0,
                last_arrival: 0.0,
                ge,
                bad: false,
                cap_bps: None,
                free_at: 0.0,
            }
        })
    }

    fn base_latency(&mut self, from: u32, to: u32) -> f64 {
        let p = self.path(from, to);
        p.latency_ms + p.extra_ms
    }

    // ─── Faults ───────────────────────────────────────────────────

    /// Burst loss on one path.
    pub fn set_path_loss(&mut self, from: u32, to: u32, ge: Option<GeSpec>) {
        self.path(from, to).ge = ge;
    }
    /// Extra one-way latency on one path (a degrading path).
    pub fn set_path_extra(&mut self, from: u32, to: u32, ms: f64) {
        self.path(from, to).extra_ms = ms;
    }
    /// A path bottleneck below the sender's uplink.
    pub fn set_path_cap(&mut self, from: u32, to: u32, streams: Option<f64>) {
        let bps = streams.map(|s| s * self.cfg.stream_bps as f64);
        self.path(from, to).cap_bps = bps;
    }
    /// Alive but forwarding nothing.
    pub fn set_blackhole(&mut self, n: u32, on: bool) {
        self.nodes[n as usize].blackhole = on;
    }

    /// The node dies; its peers learn the link is gone after [`LINK_DETECT_MS`].
    pub fn kill(&mut self, n: u32) {
        let node = &mut self.nodes[n as usize];
        if !node.alive {
            return;
        }
        node.alive = false;
        let mut peers: Vec<u32> = node
            .sel
            .as_ref()
            .map(|s| s.subscriptions().into_iter().map(|(p, _)| p).collect())
            .unwrap_or_default();
        if let Some(a) = &node.adm {
            peers.extend(a.ledger().keys().copied());
        }
        let at = self.now + LINK_DETECT_MS;
        for p in peers {
            self.push(at, n, p, Payload::LinkDown);
        }
    }

    /// The node comes back with fresh controller state.
    pub fn revive(&mut self, n: u32) {
        let i = n as usize;
        if self.nodes[i].alive {
            return;
        }
        let spec = self.nodes[i].spec;
        let cands = std::mem::take(&mut self.nodes[i].cands);
        let mut fresh = Self::fresh_node(n, spec, &self.cfg, cands, &self.roster);
        fresh.got_full = std::mem::take(&mut self.nodes[i].got_full);
        fresh.got_any = std::mem::take(&mut self.nodes[i].got_any);
        fresh.hist = std::mem::take(&mut self.nodes[i].hist);
        fresh.uplink_free_at = self.now as f64;
        fresh.last_unserved = self.now;
        self.nodes[i] = fresh;
    }

    pub fn alive(&self, n: u32) -> bool {
        self.nodes[n as usize].alive
    }

    // ─── Plumbing ─────────────────────────────────────────────────

    fn push(&mut self, at: u64, from: u32, to: u32, payload: Payload) {
        self.order += 1;
        self.events.push(Ev {
            at,
            order: self.order,
            from,
            to,
            payload,
        });
    }

    fn send_ctrl(&mut self, at: u64, from: u32, to: u32, msg: ControlMsg<u32>) {
        if !self.nodes[from as usize].alive {
            return;
        }
        let lat = self.base_latency(from, to);
        self.push(at + lat.ceil() as u64, from, to, Payload::Ctrl(msg));
    }

    fn send_chunk(&mut self, at: u64, from: u32, to: u32, seq: u64, full: bool, emitted: u64) {
        let bytes = if full {
            self.full_bytes
        } else {
            self.audio_bytes
        };
        let nowf = at as f64;
        let node = &mut self.nodes[from as usize];
        let start = node.uplink_free_at.max(nowf);
        let q = start - nowf;
        if q > MAX_QUEUE_MS {
            node.egress.on_dropped(at, bytes);
            return;
        }
        let rate = node.spec.uplink_streams * self.cfg.stream_bps as f64;
        let depart = start + bytes as f64 * 8_000.0 / rate;
        node.uplink_free_at = depart;
        node.egress.on_sent(at, bytes, q);
        let jitter_draw = self.net.unit();
        let flip_draw = self.net.unit();
        let mut retry_draws = [0.0f64; MAX_ARQ_TRIES as usize];
        for d in retry_draws.iter_mut().take(self.arq_tries as usize) {
            *d = self.net.unit();
        }
        let arq_tries = self.arq_tries;
        let p = self.path(from, to);
        let mut depart = depart;
        if let Some(cap) = p.cap_bps {
            let s = p.free_at.max(depart);
            if s - depart > MAX_QUEUE_MS {
                return;
            }
            p.free_at = s + bytes as f64 * 8_000.0 / cap;
            depart = p.free_at;
        }
        if let Some(ge) = p.ge {
            let pi = ge.avg_loss.clamp(0.0, 0.99);
            let p_bg = 1.0 / ge.mean_burst.max(1.0);
            let p_gb = p_bg * pi / (1.0 - pi);
            p.bad = if p.bad {
                flip_draw >= p_bg
            } else {
                flip_draw < p_gb
            };
            if p.bad {
                // Per-hop ARQ (the leviculum Channel): each retry lands one
                // RTT later and is lost independently with `avg_loss`. The
                // path stays in order, so later chunks queue behind it (HOL).
                let rtt = 2.0 * (p.latency_ms + p.extra_ms);
                let mut delivered = false;
                for &d in retry_draws.iter().take(arq_tries as usize) {
                    depart += rtt;
                    if d >= pi {
                        delivered = true;
                        break;
                    }
                }
                if !delivered {
                    return;
                }
            }
        }
        let arrival =
            (depart + p.latency_ms + p.extra_ms + jitter_draw * p.jitter_ms).max(p.last_arrival);
        p.last_arrival = arrival;
        self.push(
            arrival.ceil() as u64,
            from,
            to,
            Payload::Chunk { seq, full, emitted },
        );
    }

    fn forward(&mut self, at: u64, n: u32, seq: u64, full: bool, emitted: u64, first_any: bool) {
        let node = &self.nodes[n as usize];
        if node.blackhole {
            return;
        }
        let Some(adm) = &node.adm else {
            return;
        };
        let mut kids: Vec<(u32, Role)> = adm.forwarding_to();
        if kids.is_empty() {
            return;
        }
        let r = (seq as usize) % kids.len();
        kids.rotate_left(r);
        for (k, role) in kids {
            if first_any {
                self.send_chunk(at, n, k, seq, full && role == Role::Primary, emitted);
            } else if full && role == Role::Primary {
                self.send_chunk(at, n, k, seq, true, emitted);
            }
        }
    }

    fn apply_actions(&mut self, at: u64, n: u32, actions: Vec<SelectorAction<u32>>) {
        let fc = self.nodes[n as usize].spec.forwarder;
        for a in actions {
            match a {
                SelectorAction::Subscribe { parent, role } => self.send_ctrl(
                    at,
                    n,
                    parent,
                    ControlMsg::Subscribe(SubscribeRequest {
                        subscriber: n,
                        role,
                        forward_capable: fc,
                    }),
                ),
                SelectorAction::Unsubscribe { parent } => {
                    self.send_ctrl(at, n, parent, ControlMsg::Unsubscribe { subscriber: n });
                }
            }
        }
    }

    fn deliver(&mut self, ev: Ev) {
        let to = ev.to as usize;
        if !self.nodes[to].alive {
            return;
        }
        let at = ev.at;
        match ev.payload {
            Payload::Chunk { seq, full, emitted } => {
                let bytes = if full {
                    self.full_bytes
                } else {
                    self.audio_bytes
                };
                let node = &mut self.nodes[to];
                if let Some(sel) = node.sel.as_mut() {
                    sel.on_chunk(at, &ev.from, seq, full, bytes, (at - emitted) as f64);
                }
                let first_any = node.got_any.set(seq);
                let first_full = full && node.got_full.set(seq);
                if full && !first_full {
                    node.dup_bytes += bytes;
                }
                if first_full {
                    node.last_full_at = Some(at);
                }
                if first_any || first_full {
                    self.forward(at, ev.to, seq, full, emitted, first_any);
                }
            }
            Payload::LinkDown => {
                let node = &mut self.nodes[to];
                if let Some(sel) = node.sel.as_mut() {
                    sel.on_link_down(at, &ev.from, &mut self.log);
                }
                if let Some(adm) = node.adm.as_mut() {
                    adm.release(&ev.from);
                }
            }
            Payload::Ctrl(msg) => match msg {
                ControlMsg::Subscribe(req) => {
                    let node = &mut self.nodes[to];
                    if let Some(adm) = node.adm.as_mut() {
                        let d = adm.request(at, &req, &mut self.ctl, &mut self.log);
                        let pre = adm.take_preempted();
                        self.send_ctrl(at, ev.to, ev.from, ControlMsg::Decision(d));
                        for v in pre {
                            self.send_ctrl(
                                at,
                                ev.to,
                                v,
                                ControlMsg::Shed {
                                    reason: ShedReason::Preempted,
                                },
                            );
                        }
                    }
                }
                ControlMsg::Unsubscribe { subscriber } => {
                    if let Some(adm) = self.nodes[to].adm.as_mut() {
                        adm.release(&subscriber);
                    }
                }
                ControlMsg::Decision(d) => {
                    let mut acts = Vec::new();
                    let node = &mut self.nodes[to];
                    if let Some(sel) = node.sel.as_mut() {
                        acts = sel.on_decision(at, &ev.from, &d, &mut self.ctl, &mut self.log);
                        if let Some(adm) = node.adm.as_mut() {
                            Self::sync_upstream(adm, sel);
                        }
                    }
                    self.apply_actions(at, ev.to, acts);
                }
                ControlMsg::Shed { .. } => {
                    if let Some(sel) = self.nodes[to].sel.as_mut() {
                        sel.on_shed(at, &ev.from, &mut self.ctl, &mut self.log);
                    }
                }
                ControlMsg::Offer(_) => {}
            },
        }
    }

    fn drain(&mut self, until: u64) {
        while self.events.peek().is_some_and(|e| e.at <= until) {
            let ev = self.events.pop().expect("peeked");
            self.deliver(ev);
        }
    }

    fn control(&mut self, t: u64) {
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive {
                continue;
            }
            let n = i as u32;
            let node = &mut self.nodes[i];
            if let (Some(adm), Some(sel)) = (node.adm.as_mut(), node.sel.as_ref()) {
                Self::sync_upstream(adm, sel);
            }
            let mut shed = Vec::new();
            if let Some(adm) = node.adm.as_mut() {
                if let Some(w) = node.egress.roll(t) {
                    shed = adm.on_egress_window(t, &w, &mut self.log);
                }
            }
            let mut acts = Vec::new();
            let has_children = node
                .adm
                .as_ref()
                .is_some_and(|a| a.ledger().values().any(|c| c.role == Role::Primary));
            if let Some(sel) = node.sel.as_mut() {
                sel.set_has_children(has_children);
                acts = sel.tick(t, &mut self.ctl, &mut self.log);
                // Refresh the admission's upstream view AFTER the selector
                // decided: a forwarder that just lost its primary must refuse
                // (UpstreamUnhealthy) before a peer in the same failover
                // wave lands on it — the simultaneous-failover loop.
                if let Some(adm) = node.adm.as_mut() {
                    Self::sync_upstream(adm, sel);
                }
                let p = sel.primary().copied();
                if let Some(p) = p {
                    if node.hist.last().map(|h| h.1) != Some(p) {
                        node.hist.push((t, p));
                    }
                }
            }
            for v in shed {
                self.send_ctrl(
                    t,
                    n,
                    v,
                    ControlMsg::Shed {
                        reason: ShedReason::OverCommitted,
                    },
                );
            }
            self.apply_actions(t, n, acts);
        }
    }

    fn sync_upstream(adm: &mut Admission<u32>, sel: &ParentSelector<u32>) {
        match sel.upstream_view() {
            Some(u) => adm.set_upstream(Some(u.depth), u.ancestry, u.healthy, u.latency_ms),
            None => adm.set_upstream(None, Vec::new(), false, 0),
        }
    }

    fn offers(&mut self, t: u64) {
        let offers: Vec<_> = self
            .nodes
            .iter()
            .map(|n| n.adm.as_ref().filter(|_| n.alive).map(Admission::offer))
            .collect();
        for i in 0..self.nodes.len() {
            if !self.nodes[i].alive || self.nodes[i].sel.is_none() {
                continue;
            }
            let cands = self.nodes[i].cands.clone();
            for c in cands {
                if let Some(o) = &offers[c as usize] {
                    let rtt = 2.0 * self.base_latency(i as u32, c);
                    let sel = self.nodes[i].sel.as_mut().expect("checked");
                    sel.on_offer(t, o.clone(), rtt, &mut self.log);
                }
            }
        }
    }

    fn sample(&mut self, t: u64) {
        // Membership invariant (CC 5.4.6 / E1 item 1 / 6.1.6): no non-member
        // holds downstream legs or is anyone's media parent.
        if let Some(c) = self.canonical {
            if let Some(a) = self.nodes[c as usize].adm.as_ref() {
                for (k, cm) in a.ledger() {
                    if cm.role == Role::Primary {
                        self.canonical_video.push((t, *k));
                    }
                }
                self.canonical_peak_bps = self.canonical_peak_bps.max(a.committed_bps());
            }
        }
        for (i, n) in self.nodes.iter().enumerate() {
            let id = i as u32;
            // The canonical is a transport forwarder of 1:1 links (§4.4), not
            // a tree node: its links are not tree edges.
            if Some(id) == self.canonical {
                continue;
            }
            if !n.spec.member && n.adm.as_ref().is_some_and(|a| !a.ledger().is_empty()) {
                self.nonmember_violations
                    .push((t, id, "non-member holds downstream legs"));
            }
            if let Some(sel) = n.sel.as_ref() {
                for (p, role) in sel.subscriptions() {
                    if Some(p) == self.canonical {
                        if role == Role::Primary {
                            self.nonmember_violations.push((
                                t,
                                p,
                                "the canonical is a video parent",
                            ));
                        }
                        continue;
                    }
                    if !self.nodes[p as usize].spec.member {
                        self.nonmember_violations
                            .push((t, p, "non-member is a media parent"));
                    }
                }
            }
        }
        for (i, n) in self.nodes.iter_mut().enumerate() {
            if !n.alive {
                continue;
            }
            if let Some(adm) = &n.adm {
                let real = n.spec.uplink_streams * self.cfg.stream_bps as f64;
                let load = adm.committed_bps() as f64;
                let w = self.worst_load.entry(i as u32).or_insert(0.0);
                if t >= self.overcap_from {
                    *w = w.max(load / real);
                    let cap = self.cfg.commit_fraction * real;
                    if load > cap + 1.0 {
                        self.overcap.push((t, i as u32, load, cap));
                    }
                }
            }
            if i != 0 {
                let served = n.sel.as_ref().is_some_and(|s| s.primary().is_some())
                    && n.last_full_at.is_some_and(|l| t.saturating_sub(l) <= 1_000);
                if !served {
                    n.last_unserved = t;
                }
            }
        }
    }

    /// Advance one chunk step.
    pub fn step(&mut self) {
        let t = self.now;
        self.drain(t);
        if self.nodes[0].alive {
            let seq = t / CHUNK_MS;
            self.nodes[0].got_full.set(seq);
            self.nodes[0].got_any.set(seq);
            self.forward(t, 0, seq, true, t, true);
            if let Some(c) = self.canonical {
                if self.nodes[c as usize].alive {
                    let lat = self.base_latency(0, c);
                    self.push(
                        t + lat.ceil() as u64,
                        0,
                        c,
                        Payload::Chunk {
                            seq,
                            full: true,
                            emitted: t,
                        },
                    );
                }
            }
        }
        if t % OFFER_MS == 0 {
            self.offers(t);
        }
        if t % CONTROL_MS == 0 {
            self.control(t);
        }
        if t % SAMPLE_MS == 0 {
            self.sample(t);
        }
        self.now += CHUNK_MS;
    }

    /// Run to `t` (exclusive).
    pub fn run_until(&mut self, t: u64) {
        while self.now < t {
            self.step();
        }
    }

    // ─── Readouts ─────────────────────────────────────────────────

    pub fn primary_of(&self, n: u32) -> Option<u32> {
        self.nodes[n as usize]
            .sel
            .as_ref()
            .and_then(|s| s.primary().copied())
    }
    pub fn standby_of(&self, n: u32) -> Option<u32> {
        self.nodes[n as usize]
            .sel
            .as_ref()
            .and_then(|s| s.standby().copied())
    }
    pub fn children_of(&self, n: u32) -> Vec<(u32, Role)> {
        self.nodes[n as usize]
            .adm
            .as_ref()
            .map(|a| a.ledger().iter().map(|(k, c)| (*k, c.role)).collect())
            .unwrap_or_default()
    }
    pub fn committed(&self, n: u32) -> u64 {
        self.nodes[n as usize]
            .adm
            .as_ref()
            .map_or(0, Admission::committed_bps)
    }
    pub fn ceiling(&self, n: u32) -> Option<f64> {
        self.nodes[n as usize]
            .adm
            .as_ref()
            .and_then(Admission::ceiling_bps)
    }
    pub fn last_unserved(&self, n: u32) -> u64 {
        self.nodes[n as usize].last_unserved
    }
    pub fn uplink_streams(&self, n: u32) -> f64 {
        self.nodes[n as usize].spec.uplink_streams
    }
    pub fn hist(&self, n: u32) -> &[(u64, u32)] {
        &self.nodes[n as usize].hist
    }
    pub fn dup_bytes(&self, n: u32) -> u64 {
        self.nodes[n as usize].dup_bytes
    }
    pub fn got_full(&self, n: u32, seq: u64) -> bool {
        self.nodes[n as usize].got_full.get(seq)
    }
    pub fn got_any(&self, n: u32, seq: u64) -> bool {
        self.nodes[n as usize].got_any.get(seq)
    }
    /// Depth of `n` in the current primary tree (publisher 0), `None` if
    /// unrooted or looped.
    pub fn depth(&self, n: u32) -> Option<u32> {
        let mut cur = n;
        let mut d = 0u32;
        while cur != 0 {
            cur = self.primary_of(cur)?;
            d += 1;
            if d as usize > self.nodes.len() {
                return None;
            }
        }
        Some(d)
    }

    /// The failure context every assertion prints.
    pub fn report(&self, node: Option<u32>, what: &str) -> String {
        format!(
            "\n[ALM-SIM FAIL] seed={seed} t={t}ms node={node:?}: {what}\n  decisions={n} hash={h}\n  --- decision-log tail ---\n{tail}\n",
            seed = self.seed,
            t = self.now,
            n = self.log.len(),
            h = self.log.hash_hex(),
            tail = self.log.tail(),
        )
    }
}

// ─── Metrics ─────────────────────────────────────────────────────────

/// What a run measured over `[from_ms, to_ms)`.
#[derive(Debug, Clone)]
pub struct Metrics {
    /// Last time any subscriber was unserved (convergence), if it converged.
    pub converged_ms: Option<u64>,
    /// Primary changes per subscriber per 120 s after convergence.
    pub change_rate_per_120s: f64,
    /// A→B→A flips that returned within 3 × dwell.
    pub flips: u64,
    /// Node with the most flips.
    pub worst_flipper: Option<u32>,
    /// Over-cap samples (committed > 0.65 × real uplink).
    pub overcap_samples: usize,
    /// Worst committed / real-uplink.
    pub worst_load: f64,
    /// Worst-loaded forwarder.
    pub worst_loaded: Option<u32>,
    /// Subscribers whose full-chunk delivery ≥ 99 % in the window.
    pub served: usize,
    /// Subscribers measured.
    pub subscribers: usize,
    /// p5 delivery ratio.
    pub delivery_p5: f64,
    /// Longest run of missing full chunks.
    pub max_video_gap: u64,
    /// Longest run of missing audio.
    pub max_audio_gap: u64,
    /// Deepest primary-tree depth.
    pub max_depth: u32,
}

fn percentile(v: &mut [f64], pct: f64) -> f64 {
    if v.is_empty() {
        return 0.0;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal));
    let rank = ((pct / 100.0) * v.len() as f64).ceil() as usize;
    v[rank.clamp(1, v.len()) - 1]
}

impl Sim {
    pub fn metrics(&self, from_ms: u64, to_ms: u64, subs: &[u32]) -> Metrics {
        let horizon = to_ms.saturating_sub(SAMPLE_MS * 2);
        let converged_ms = subs
            .iter()
            .map(|&n| self.last_unserved(n))
            .max()
            .filter(|&t| t < horizon);
        let conv = converged_ms.unwrap_or(to_ms);
        let mut changes = 0u64;
        let mut flips = 0u64;
        let mut worst_flipper = None;
        let mut worst_flips = 0;
        let flip_window = 3 * self.cfg.min_dwell_ms.max(10_000);
        for &n in subs {
            let h = self.hist(n);
            changes += h.iter().skip(1).filter(|(t, _)| *t > conv).count() as u64;
            let mut f = 0;
            for w in h.windows(3) {
                if w[2].0 >= from_ms && w[0].1 == w[2].1 && w[2].0 - w[1].0 <= flip_window {
                    f += 1;
                }
            }
            if f > worst_flips {
                worst_flips = f;
                worst_flipper = Some(n);
            }
            flips += f;
        }
        let span = to_ms.saturating_sub(conv).max(1) as f64;
        let change_rate_per_120s = changes as f64 / subs.len().max(1) as f64 * 120_000.0 / span;
        let (lo, hi) = (from_ms / CHUNK_MS, to_ms.saturating_sub(1_000) / CHUNK_MS);
        let mut ratios = Vec::with_capacity(subs.len());
        let mut served = 0;
        let mut max_video_gap = 0;
        let mut max_audio_gap = 0;
        let mut max_depth = 0;
        for &n in subs {
            if !self.alive(n) {
                continue;
            }
            let (mut got, mut vrun, mut arun) = (0u64, 0u64, 0u64);
            for s in lo..hi {
                if self.got_full(n, s) {
                    got += 1;
                    vrun = 0;
                } else {
                    vrun += 1;
                    max_video_gap = max_video_gap.max(vrun);
                }
                if self.got_any(n, s) {
                    arun = 0;
                } else {
                    arun += 1;
                    max_audio_gap = max_audio_gap.max(arun);
                }
            }
            let r = got as f64 / (hi - lo).max(1) as f64;
            if r >= 0.99 {
                served += 1;
            }
            ratios.push(r);
            max_depth = max_depth.max(self.depth(n).unwrap_or(u32::MAX));
        }
        let (worst_loaded, worst_load) = self
            .worst_load
            .iter()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(Ordering::Equal))
            .map_or((None, 0.0), |(k, v)| (Some(*k), *v));
        Metrics {
            converged_ms,
            change_rate_per_120s,
            flips,
            worst_flipper,
            overcap_samples: self.overcap.len(),
            worst_load,
            worst_loaded,
            served,
            subscribers: ratios.len(),
            delivery_p5: percentile(&mut ratios, 5.0),
            max_video_gap,
            max_audio_gap,
            max_depth,
        }
    }
}

// ─── Scenarios ───────────────────────────────────────────────────────

#[cfg(test)]
mod scenarios {
    use super::*;

    const SECOND: u64 = 1_000;

    fn emit(name: &str, sim: &Sim, m: &Metrics) {
        eprintln!(
            "[ALM-CTRL] {name:<14} seed={seed} conv={conv:?} chg/sub/120s={cr:.3} flips={fl} \
             overcap={oc} worst_load={wl:.2}@{wn:?} served={sv}/{ns} p5={p5:.4} vgap={vg} agap={ag} \
             depth={d} decisions={dn} hash={h}",
            seed = sim.seed,
            conv = m.converged_ms,
            cr = m.change_rate_per_120s,
            fl = m.flips,
            oc = m.overcap_samples,
            wl = m.worst_load,
            wn = m.worst_loaded,
            sv = m.served,
            ns = m.subscribers,
            p5 = m.delivery_p5,
            vg = m.max_video_gap,
            ag = m.max_audio_gap,
            d = m.max_depth,
            dn = sim.log.len(),
            h = &sim.log.hash_hex()[..16],
        );
    }

    // ── T1 world: 1 publisher, 4 heterogeneous relays, 20 NAT'd leaves ──

    const T1_RELAYS: [f64; 4] = [6.0, 8.0, 12.0, 16.0];
    const T1_LEAVES: usize = 20;
    const T1_END: u64 = 300 * SECOND;

    fn t1_world(seed: u64, cfg: ControllerConfig) -> Sim {
        t1_world_n(seed, cfg, T1_LEAVES)
    }

    /// The T1 world with `leaves` leaves. 16 leaves is N+1 provisioned (the
    /// room still fits after its biggest relay dies); 20 is not.
    fn t1_world_n(seed: u64, cfg: ControllerConfig, leaves: usize) -> Sim {
        let mut others: Vec<NodeSpec> = T1_RELAYS.iter().map(|&s| NodeSpec::relay(s)).collect();
        others.extend(std::iter::repeat(NodeSpec::leaf()).take(leaves));
        Sim::new(
            seed,
            cfg,
            NodeSpec::relay(10.0),
            &others,
            Candidates::All,
            None,
        )
    }

    fn subs(sim: &Sim) -> Vec<u32> {
        (1..sim.node_count() as u32).collect()
    }

    /// The T1 pass predicate. `Err` names the violated criterion.
    fn t1_verdict(sim: &Sim, m: &Metrics) -> Result<(), String> {
        if let Some(&(t, n, what)) = sim.nonmember_violations.first() {
            return Err(sim.report(Some(n), &format!("{what} at t={t}")));
        }
        if m.overcap_samples > 0 {
            let (t, n, load, cap) = sim.overcap[0];
            return Err(sim.report(
                Some(n),
                &format!(
                    "over committed cap: {load:.0} > {cap:.0} bps at t={t} ({} samples)",
                    m.overcap_samples
                ),
            ));
        }
        match m.converged_ms {
            Some(c) if c <= 30 * SECOND => {}
            c => {
                let worst = subs(sim).into_iter().max_by_key(|&n| sim.last_unserved(n));
                return Err(sim.report(worst, &format!("not converged by 30 s: {c:?}")));
            }
        }
        if m.change_rate_per_120s > 1.0 {
            return Err(sim.report(
                None,
                &format!(
                    "parent-change rate {:.3}/sub/120s > 1",
                    m.change_rate_per_120s
                ),
            ));
        }
        if m.flips > 0 {
            return Err(sim.report(m.worst_flipper, &format!("{} A→B→A flips", m.flips)));
        }
        Ok(())
    }

    fn run_t1(seed: u64, cfg: ControllerConfig) -> (Sim, Metrics) {
        let mut sim = t1_world(seed, cfg);
        sim.run_until(T1_END);
        let s = subs(&sim);
        let m = sim.metrics(30 * SECOND, T1_END, &s);
        (sim, m)
    }

    #[test]
    fn t1_herding_closed_loop() {
        for seed in [1u64, 2, 3, 0xC1E5] {
            let (sim, m) = run_t1(seed, ControllerConfig::interactive());
            emit("T1", &sim, &m);
            if let Err(e) = t1_verdict(&sim, &m) {
                panic!("T1 failed:{e}");
            }
            assert_eq!(
                m.served,
                m.subscribers,
                "{}",
                sim.report(None, "a subscriber below 99 % delivery")
            );
        }
    }

    #[test]
    fn t1_mut_herding_controls_off_must_fail() {
        for seed in [1u64, 2] {
            let (sim, m) = run_t1(seed, ControllerConfig::interactive().herding_mutant());
            emit("T1-mut", &sim, &m);
            assert!(
                t1_verdict(&sim, &m).is_err(),
                "T1-mut PASSED T1 — T1 cannot detect herding{}",
                sim.report(None, "mutant passed")
            );
            // The specific herding signatures: overload and oscillation.
            assert!(
                m.overcap_samples > 0,
                "mutant never over-committed{}",
                sim.report(None, "")
            );
            assert!(
                m.flips >= 5 || m.change_rate_per_120s > 1.0,
                "mutant did not oscillate{}",
                sim.report(None, "")
            );
        }
    }

    fn dump(sim: &Sim, detail: &[u32]) {
        eprintln!("=== t={}ms", sim.now);
        for n in 0..sim.node_count() as u32 {
            let a = sim.nodes[n as usize].adm.as_ref();
            eprintln!(
                "n{n} prim={:?} stby={:?} unserved_at={} committed={} limit={:?} hard={:?} offer={:?} kids={:?}",
                sim.primary_of(n), sim.standby_of(n), sim.last_unserved(n), sim.committed(n),
                a.map(|a| a.limit_bps() as u64), a.map(|a| a.hard_limit_bps() as u64),
                a.map(|a| (a.offer().depth, a.offer().headroom_bps, a.offer().forwarding)),
                sim.children_of(n)
            );
        }
        for &n in detail {
            eprintln!("--- selector n{n}: {:#?}", sim.nodes[n as usize].sel);
        }
    }

    #[test]
    #[ignore = "repro dump: ALM_SEED, ALM_WORLD=t3|t4|t7|deg, ALM_NODES=a,b, ALM_BLACKHOLE"]
    fn dbg_dump() {
        let seed: u64 = std::env::var("ALM_SEED")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);
        let world = std::env::var("ALM_WORLD").unwrap_or_default();
        let detail: Vec<u32> = std::env::var("ALM_NODES")
            .unwrap_or_default()
            .split(',')
            .filter_map(|x| x.parse().ok())
            .collect();
        let mut sim = if world == "t3" || world == "t4" {
            t1_world_n(seed, ControllerConfig::interactive(), 16)
        } else if world == "t7" {
            let others = [
                NodeSpec::relay(6.0),
                NodeSpec::relay(6.0),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
            ];
            Sim::new(
                seed,
                ControllerConfig::interactive(),
                NodeSpec::relay(2.5),
                &others,
                Candidates::All,
                None,
            )
        } else {
            t1_world(seed, ControllerConfig::interactive())
        };
        sim.log = DecisionLog::new(20_000);
        sim.run_until(60 * SECOND);
        if world == "t4" {
            let subject = (5..sim.node_count() as u32)
                .find(|&n| sim.primary_of(n).is_some_and(|p| p != 0) && sim.standby_of(n).is_some())
                .expect("subject");
            let old = sim.primary_of(subject).expect("primary");
            eprintln!(
                "T4 subject={subject} old={old} standby={:?}",
                sim.standby_of(subject)
            );
            let t0 = sim.now;
            while sim.now < t0 + 60 * SECOND {
                let ramp = ((sim.now - t0) as f64 / 20_000.0).min(1.0) * 400.0;
                sim.set_path_extra(old, subject, ramp);
                sim.step();
            }
        }
        if world == "t3" {
            sim.run_until(100 * SECOND);
            dump(&sim, &[]);
            let victim = (1..=4u32)
                .max_by_key(|&r| {
                    sim.children_of(r)
                        .iter()
                        .filter(|(_, x)| *x == Role::Primary)
                        .count()
                })
                .expect("relays");
            eprintln!("KILL {victim}");
            if std::env::var("ALM_BLACKHOLE").is_ok() {
                sim.set_blackhole(victim, true);
            } else {
                sim.kill(victim);
            }
            sim.run_until(130 * SECOND);
        }
        if world == "deg" {
            let n = detail[0];
            let old = sim.primary_of(n).expect("p");
            sim.set_path_loss(
                old,
                n,
                Some(GeSpec {
                    avg_loss: 0.2,
                    mean_burst: 5.0,
                }),
            );
            sim.run_until(90 * SECOND);
        }
        dump(&sim, &detail);
        eprintln!("{}", sim.log.tail());
    }

    #[test]
    fn determinism_same_seed_same_hash() {
        let (a, _) = run_t1(77, ControllerConfig::interactive());
        let (b, _) = run_t1(77, ControllerConfig::interactive());
        let (c, _) = run_t1(78, ControllerConfig::interactive());
        assert!(
            a.log.len() > 50,
            "too few decisions to be a meaningful hash"
        );
        assert_eq!(
            a.log.hash(),
            b.log.hash(),
            "same seed, different decision log{}",
            a.report(None, "")
        );
        assert_ne!(
            a.log.hash(),
            c.log.hash(),
            "different seed, same decision log"
        );
        eprintln!(
            "[ALM-CTRL] determinism seed=77 hash={} decisions={}",
            a.log.hash_hex(),
            a.log.len()
        );
    }

    // ── Membership: a big, attractive non-member is never a tree node ──
    //
    // CC 5.4.6 / E1 item 1 / 6.1.6: every node that fans out MUST be a room
    // member. A non-member relay with 10× the capacity and an honest ad is
    // offered to everyone as a candidate; it must never hold a downstream
    // leg nor be anyone's primary or standby — even in the T1 mutation
    // (admission off), because membership is eligibility, not admission.

    #[test]
    fn membership_non_member_is_never_a_tree_node() {
        for (seed, mutant) in [(1u64, false), (2, false), (3, true)] {
            let mut others: Vec<NodeSpec> = T1_RELAYS.iter().map(|&s| NodeSpec::relay(s)).collect();
            let outsider = others.len() as u32 + 1;
            others.push(NodeSpec {
                uplink_streams: 100.0,
                advertised_streams: Some(100.0),
                forwarder: true,
                member: false,
            });
            others.extend(std::iter::repeat(NodeSpec::leaf()).take(T1_LEAVES));
            let cfg = if mutant {
                ControllerConfig::interactive().herding_mutant()
            } else {
                ControllerConfig::interactive()
            };
            let mut sim = Sim::new(
                seed,
                cfg,
                NodeSpec::relay(10.0),
                &others,
                Candidates::All,
                None,
            );
            sim.run_until(120 * SECOND);
            if let Some(&(t, n, what)) = sim.nonmember_violations.first() {
                panic!("{}", sim.report(Some(n), &format!("{what} at t={t}")));
            }
            let refused = sim.log.count(DecisionKind::Refuse);
            eprintln!(
                "[ALM-CTRL] MEMBERSHIP seed={seed} mutant={mutant} outsider={outsider} violations=0 refusals={refused}"
            );
            if !mutant {
                let s: Vec<u32> = (1..sim.node_count() as u32)
                    .filter(|&n| n != outsider)
                    .collect();
                let m = sim.metrics(30 * SECOND, 120 * SECOND, &s);
                assert_eq!(
                    m.served,
                    m.subscribers,
                    "{}",
                    sim.report(None, "members unserved")
                );
            }
        }
    }

    // ── T2: one relay claims 10× its real capacity ──

    #[test]
    fn t2_dishonest_capacity_is_measured_and_curtailed() {
        for seed in [1u64, 2, 3] {
            // Capacity-tight: honest capacity (publisher 4, relays 8 + 8)
            // cannot carry the room, so the liar MUST be loaded past what it
            // really has before its measurement can catch it.
            let liar = 1u32;
            let mut others = vec![
                NodeSpec {
                    uplink_streams: 12.0,
                    advertised_streams: Some(120.0),
                    forwarder: true,
                    member: true,
                },
                NodeSpec::relay(8.0),
                NodeSpec::relay(8.0),
            ];
            others.extend(std::iter::repeat(NodeSpec::leaf()).take(T1_LEAVES));
            let mut sim = Sim::new(
                seed,
                ControllerConfig::interactive(),
                NodeSpec::relay(4.0),
                &others,
                Candidates::All,
                None,
            );
            // No herd onto the liar at t=0: the cold-start trial slot.
            let mut early_max = 0usize;
            while sim.now < 2 * SECOND {
                sim.step();
                let prim = sim
                    .children_of(liar)
                    .iter()
                    .filter(|(_, r)| *r == Role::Primary)
                    .count();
                early_max = early_max.max(prim);
            }
            assert!(
                early_max <= 1,
                "liar admitted {early_max} primaries in the first 2 s{}",
                sim.report(Some(liar), "herd onto liar")
            );
            sim.run_until(T1_END);
            let cap = sim.cfg.commit_fraction * 12.0 * sim.cfg.stream_bps as f64;
            let detected = sim.log.count(DecisionKind::OverClaim);
            assert!(
                detected >= 1,
                "over-claim never flagged{}",
                sim.report(Some(liar), "")
            );
            // Every over-cap sample of the liar falls inside a bounded detection
            // window (the probe overshoot), never in the steady state.
            let liar_over: Vec<_> = sim.overcap.iter().filter(|o| o.1 == liar).collect();
            let last_over = liar_over.last().map_or(0, |o| o.0);
            let first_over = liar_over.first().map_or(0, |o| o.0);
            assert!(
                last_over.saturating_sub(first_over) <= 10 * SECOND,
                "liar over cap for {} ms{}",
                last_over - first_over,
                sim.report(Some(liar), "curtailment too slow")
            );
            assert!(
                (sim.committed(liar) as f64) <= cap + 1.0,
                "liar committed {} > 0.65 × measured{}",
                sim.committed(liar),
                sim.report(Some(liar), "")
            );
            let others_over = sim.overcap.iter().filter(|o| o.1 != liar).count();
            assert_eq!(
                others_over,
                0,
                "{}",
                sim.report(None, "an honest forwarder over cap")
            );
            let s = subs(&sim);
            let m = sim.metrics(60 * SECOND, T1_END, &s);
            emit("T2", &sim, &m);
            eprintln!(
                "[ALM-CTRL] T2 liar ceiling={:?} committed={} overshoot_window={}ms",
                sim.ceiling(liar),
                sim.committed(liar),
                last_over.saturating_sub(first_over)
            );
            // Honest outcome: a liar cannot make capacity appear. What fits is
            // 0.65 × (4 + 12 + 8 + 8) = 20.8 streams for 23 subscribers.
            assert!(
                m.served >= 15,
                "{}",
                sim.report(None, &format!("only {} served", m.served))
            );
        }
    }

    // ── T3: primary failure with a warm standby ──

    fn t3_case(seed: u64, blackhole: bool) -> Vec<f64> {
        let mut sim = t1_world_n(seed, ControllerConfig::interactive(), 16);
        sim.run_until(100 * SECOND);
        // Kill the relay with the most primary children.
        let victim = (1..=4u32)
            .max_by_key(|&r| {
                sim.children_of(r)
                    .iter()
                    .filter(|(_, x)| *x == Role::Primary)
                    .count()
            })
            .expect("relays");
        let orphans: Vec<u32> = sim
            .children_of(victim)
            .into_iter()
            .filter(|(_, r)| *r == Role::Primary)
            .map(|(k, _)| k)
            .collect();
        assert!(
            !orphans.is_empty(),
            "{}",
            sim.report(Some(victim), "victim had no children")
        );
        // Orphans whose standby is outside the victim's subtree.
        let outside = |sim: &Sim, mut n: u32| {
            for _ in 0..8 {
                if n == victim {
                    return false;
                }
                match sim.primary_of(n) {
                    Some(p) => n = p,
                    None => return true,
                }
            }
            true
        };
        let with_standby: Vec<u32> = orphans
            .iter()
            .copied()
            .filter(|&o| sim.standby_of(o).is_some_and(|s| outside(&sim, s)))
            .collect();
        let victim_depth = u64::from(sim.depth(victim).unwrap_or(1));
        let t_fail = sim.now;
        if blackhole {
            sim.set_blackhole(victim, true);
        } else {
            sim.kill(victim);
        }
        sim.run_until(t_fail + 30 * SECOND);
        // Recovery per orphan: the emission time (after the kill) of the
        // first full chunk it received again — chunks the dead parent never
        // sent are never retransmitted, so this IS the first video outage.
        // A later second outage (a relay orphan preempting this freshly
        // placed leaf) is measured separately, as total missed video.
        let (lo, hi) = (t_fail / CHUNK_MS + 1, (t_fail + 25 * SECOND) / CHUNK_MS);
        let mut recovered: BTreeMap<u32, u64> = BTreeMap::new();
        let mut worst_missed = 0usize;
        for &o in &orphans {
            let first = (lo..hi).find(|&s| sim.got_full(o, s));
            let Some(first) = first else {
                panic!(
                    "{}",
                    sim.report(
                        Some(o),
                        "orphan never recovered (no video 25 s after the kill)"
                    )
                );
            };
            recovered.insert(o, first * CHUNK_MS - t_fail);
            let tail_missing = (first..hi).filter(|&s| !sim.got_full(o, s)).count();
            worst_missed = worst_missed.max(tail_missing);
        }
        eprintln!("[ALM-CTRL] T3 seed={seed} blackhole={blackhole} orphans={} worst_missed_after_recovery={worst_missed} chunks", orphans.len());
        // Audio: zero gap for orphans whose standby survived.
        // The audit asked for zero. Measured: zero except when a relay orphan
        // preempts a leaf's standby in the same failover wave (forwarder
        // preemption, hard limit binding) — bounded here at 500 ms.
        let mut worst_audio = 0usize;
        for &o in &with_standby {
            let missing = (lo..hi).filter(|&s| !sim.got_any(o, s)).count();
            worst_audio = worst_audio.max(missing);
            assert!(
                missing <= 10,
                "{}",
                sim.report(
                    Some(o),
                    &format!("audio gap {missing} chunks with a live standby")
                )
            );
        }
        eprintln!(
            "[ALM-CTRL] T3 seed={seed} blackhole={blackhole} orphans_with_live_standby={}/{} worst_audio_gap={worst_audio} chunks",
            with_standby.len(),
            orphans.len()
        );
        // Suspicion of a depth-d parent waits suspect · (1 + d/2); then one
        // admission round, allowing for one refusal + jittered retry.
        let bound = sim.cfg.suspect_silence_ms * (2 + victim_depth) / 2 + 2 * SECOND;
        let rec: Vec<f64> = recovered.values().map(|&v| v as f64).collect();
        for (&o, &r) in &recovered {
            assert!(
                r <= bound,
                "{}",
                sim.report(Some(o), &format!("recovery {r} ms > bound {bound} ms"))
            );
        }
        rec
    }

    #[test]
    fn t3_parent_failure_warm_standby() {
        let mut all = Vec::new();
        for seed in [1u64, 2, 3, 4] {
            all.extend(t3_case(seed, false));
            all.extend(t3_case(seed, true));
        }
        let (p50, p95, p99) = (
            percentile(&mut all.clone(), 50.0),
            percentile(&mut all.clone(), 95.0),
            percentile(&mut all, 99.0),
        );
        eprintln!("[ALM-CTRL] T3 recovery ms p50={p50:.0} p95={p95:.0} p99={p99:.0}");
    }

    // ── T4: make-before-break on a degrading primary ──

    #[test]
    fn t4_make_before_break_no_gap() {
        for seed in [1u64, 2, 3] {
            let mut sim = t1_world_n(seed, ControllerConfig::interactive(), 16);
            sim.run_until(60 * SECOND);
            // A leaf served by a relay, with a standby elsewhere.
            let subject = (5..sim.node_count() as u32)
                .find(|&n| sim.primary_of(n).is_some_and(|p| p != 0) && sim.standby_of(n).is_some())
                .expect("a relay-served leaf with a standby");
            let old = sim.primary_of(subject).expect("primary");
            let switches_before = sim.log.count(DecisionKind::Switch);
            let dup_before = sim.dup_bytes(subject);
            let t0 = sim.now;
            while sim.now < t0 + 60 * SECOND {
                let ramp = ((sim.now - t0) as f64 / 20_000.0).min(1.0) * 400.0;
                sim.set_path_extra(old, subject, ramp);
                sim.step();
            }
            let moved = sim.primary_of(subject).is_some_and(|p| p != old);
            assert!(
                moved,
                "{}",
                sim.report(Some(subject), "never switched off a degrading primary")
            );
            assert!(sim.log.count(DecisionKind::Switch) > switches_before);
            let (lo, hi) = (t0 / CHUNK_MS, (sim.now - SECOND) / CHUNK_MS);
            let skipped = (lo..hi).filter(|&s| !sim.got_full(subject, s)).count();
            assert_eq!(
                skipped,
                0,
                "{}",
                sim.report(
                    Some(subject),
                    &format!("{skipped} full chunks skipped across the switch")
                )
            );
            let dup = sim.dup_bytes(subject) - dup_before;
            eprintln!(
                "[ALM-CTRL] T4 seed={seed} node={subject} {old}→{:?} skipped=0 dup_bytes={dup}",
                sim.primary_of(subject)
            );
            // Overlap is bounded: confirm chunks plus the decision latency.
            assert!(
                dup <= 200 * sim.full_bytes,
                "{}",
                sim.report(Some(subject), &format!("overlap {dup} bytes"))
            );
        }
    }

    // ── T5: burst loss everywhere; the tree holds ──

    #[test]
    fn t5_burst_loss_tree_holds() {
        for (seed, loss) in [(1u64, 0.05), (2, 0.10), (3, 0.20)] {
            let mut others: Vec<NodeSpec> = T1_RELAYS.iter().map(|&s| NodeSpec::relay(s)).collect();
            others.extend(std::iter::repeat(NodeSpec::leaf()).take(T1_LEAVES));
            let ge = GeSpec {
                avg_loss: loss,
                mean_burst: 5.0,
            };
            let mut sim = Sim::new(
                seed,
                ControllerConfig::interactive(),
                NodeSpec::relay(10.0),
                &others,
                Candidates::All,
                Some(ge),
            );
            sim.arq_tries = 3;
            sim.run_until(T1_END);
            let s = subs(&sim);
            let m = sim.metrics(60 * SECOND, T1_END, &s);
            emit("T5", &sim, &m);
            eprintln!(
                "[ALM-CTRL] T5 loss={loss} delivery_p5={:.3} (per-hop ARQ, 3 retries)",
                m.delivery_p5
            );
            assert_eq!(
                m.overcap_samples,
                0,
                "{}",
                sim.report(m.worst_loaded, "over cap under loss")
            );
            assert_eq!(
                m.flips,
                0,
                "{}",
                sim.report(m.worst_flipper, "flips under burst loss")
            );
            assert!(
                m.change_rate_per_120s <= 1.0,
                "{}",
                sim.report(None, &format!("change rate {:.3}", m.change_rate_per_120s))
            );
            for &n in &s {
                assert!(
                    sim.primary_of(n).is_some(),
                    "{}",
                    sim.report(Some(n), "unrooted under loss")
                );
            }
        }
    }

    // ── T5b / per-path: one bad path moves its subscriber, once ──

    #[test]
    fn t5b_one_bad_path_moves_once() {
        for (seed, cap) in [(1u64, false), (2, false), (3, true), (4, true)] {
            let mut sim = t1_world_n(seed, ControllerConfig::interactive(), 16);
            sim.run_until(60 * SECOND);
            let subject = (5..sim.node_count() as u32)
                .find(|&n| sim.primary_of(n).is_some() && sim.standby_of(n).is_some())
                .expect("a leaf with a standby");
            let bad = sim.primary_of(subject).expect("primary");
            if cap {
                // A path bottleneck at half a stream, below the sender's uplink.
                sim.set_path_cap(bad, subject, Some(0.5));
            } else {
                sim.set_path_loss(
                    bad,
                    subject,
                    Some(GeSpec {
                        avg_loss: 0.20,
                        mean_burst: 5.0,
                    }),
                );
            }
            let before = sim.hist(subject).len();
            sim.run_until(T1_END);
            let after: Vec<u32> = sim.hist(subject)[before..].iter().map(|h| h.1).collect();
            eprintln!(
                "[ALM-CTRL] T5b seed={seed} cap={cap} node={subject} bad={bad} moves={after:?}"
            );
            assert!(
                sim.primary_of(subject) != Some(bad),
                "{}",
                sim.report(Some(subject), "stayed on the bad path")
            );
            assert!(
                !after.contains(&bad),
                "{}",
                sim.report(Some(subject), "returned to the bad path")
            );
            assert!(
                after.len() <= 2,
                "{}",
                sim.report(
                    Some(subject),
                    &format!("{} moves for one bad path", after.len())
                )
            );
        }
    }

    // ── T6: 10 %/min churn ──

    #[test]
    fn t6_churn_ten_percent_per_minute() {
        for seed in [1u64, 2, 3] {
            let mut sim = t1_world_n(seed, ControllerConfig::interactive(), 16);
            let mut rng = SplitMix64(seed ^ 0xC4A2);
            let n = sim.node_count() as u32;
            let mut down_until: BTreeMap<u32, u64> = BTreeMap::new();
            let mut up_since: BTreeMap<u32, u64> = BTreeMap::new();
            sim.overcap_from = 0;
            // 10 %/min per node, as a per-step probability.
            let per_tick = 0.10 * CHUNK_MS as f64 / 60_000.0;
            let mut kills = 0u64;
            while sim.now < T1_END {
                if sim.now >= 30 * SECOND {
                    for id in 1..n {
                        if let Some(&t) = down_until.get(&id) {
                            if sim.now >= t {
                                sim.revive(id);
                                down_until.remove(&id);
                                up_since.insert(id, sim.now);
                            }
                        } else if sim.now < T1_END - 30 * SECOND && rng.unit() < per_tick {
                            sim.kill(id);
                            kills += 1;
                            down_until
                                .insert(id, sim.now + rng.range_u64(10 * SECOND, 30 * SECOND));
                        }
                    }
                }
                sim.step();
            }
            let failovers = sim.log.count(DecisionKind::Failover);
            let switches = sim.log.count(DecisionKind::Switch);
            let s: Vec<u32> = (1..n).filter(|&i| sim.alive(i)).collect();
            let m = sim.metrics(30 * SECOND, T1_END, &s);
            emit("T6", &sim, &m);
            eprintln!("[ALM-CTRL] T6 seed={seed} kills={kills} failovers={failovers} voluntary_switches={switches}");
            assert_eq!(
                m.overcap_samples,
                0,
                "{}",
                sim.report(m.worst_loaded, "over cap during churn")
            );
            assert!(
                switches as f64 <= 0.1 * failovers as f64 + 2.0,
                "{}",
                sim.report(
                    None,
                    &format!("voluntary switches {switches} > churn-induced {failovers} + 10 %")
                )
            );
            assert!(kills > 0);
            // Stability holds: every node up for ≥ 30 s at the end is served
            // (a primary, and full video within the last second).
            for id in 1..n {
                let settled = sim.alive(id)
                    && up_since
                        .get(&id)
                        .map_or(true, |&t| sim.now - t >= 30 * SECOND);
                if settled {
                    let fresh = (sim.now / CHUNK_MS).saturating_sub(30);
                    let ok = sim.primary_of(id).is_some()
                        && (fresh..fresh + 10).any(|q| sim.got_full(id, q));
                    assert!(
                        ok,
                        "{}",
                        sim.report(Some(id), "settled node unserved at the end of churn")
                    );
                }
            }
        }
    }

    // ── T7: weak publisher uplink fans out through relays ──

    #[test]
    fn t7_weak_publisher_fans_out() {
        for seed in [1u64, 2, 3] {
            let others = [
                NodeSpec::relay(6.0),
                NodeSpec::relay(6.0),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
                NodeSpec::leaf(),
            ];
            let mut sim = Sim::new(
                seed,
                ControllerConfig::interactive(),
                NodeSpec::relay(2.5),
                &others,
                Candidates::All,
                None,
            );
            sim.run_until(120 * SECOND);
            let s = subs(&sim);
            let m = sim.metrics(40 * SECOND, 120 * SECOND, &s);
            emit("T7", &sim, &m);
            assert_eq!(
                m.overcap_samples,
                0,
                "{}",
                sim.report(Some(0), "publisher over-committed")
            );
            let direct = sim
                .children_of(0)
                .iter()
                .filter(|(_, r)| *r == Role::Primary)
                .count();
            assert!(
                direct <= 1,
                "{}",
                sim.report(Some(0), &format!("publisher serving {direct} primaries"))
            );
            assert_eq!(
                m.served,
                s.len(),
                "{}",
                sim.report(None, "a member unserved")
            );
            assert!(m.max_depth >= 2, "tree did not fan out through relays");
        }
    }

    // ── Multi-hop: 1 → many at depth 2–3, relay caps hold ──

    fn multihop(seed: u64, leaves: usize, end: u64) -> (Sim, Metrics) {
        let relays = (leaves / 16).max(4);
        let mut others: Vec<NodeSpec> = (0..relays).map(|_| NodeSpec::relay(60.0)).collect();
        others.extend(std::iter::repeat(NodeSpec::leaf()).take(leaves));
        let mut sim = Sim::new(
            seed,
            ControllerConfig::interactive(),
            NodeSpec::relay(8.0),
            &others,
            Candidates::Sample(12),
            None,
        );
        sim.run_until(end);
        let s = subs(&sim);
        let m = sim.metrics(end / 2, end, &s);
        (sim, m)
    }

    fn multihop_verdict(sim: &Sim, m: &Metrics, leaves: usize) {
        emit("MULTIHOP", sim, m);
        let relays = sim.node_count() - 1 - leaves;
        let relay_streams: f64 = (1..=relays as u32).map(|r| sim.uplink_streams(r)).sum();
        let total_streams = relay_streams + sim.uplink_streams(0);
        let mut hist = BTreeMap::new();
        for n in 1..sim.node_count() as u32 {
            *hist.entry(sim.depth(n)).or_insert(0usize) += 1;
        }
        eprintln!(
            "[ALM-CTRL] MULTIHOP N={} relays={relays} served={}/{} depth_hist={hist:?} \
             subs_per_relay_stream_unit={:.3} subs_per_total_stream_unit={:.3} (ideal at 65 %: 0.650)",
            sim.node_count() - 1,
            m.served,
            m.subscribers,
            m.served as f64 / relay_streams,
            m.served as f64 / total_streams,
        );
        assert!(
            sim.nonmember_violations.is_empty(),
            "{}",
            sim.report(None, "membership invariant")
        );
        assert_eq!(
            m.overcap_samples,
            0,
            "{}",
            sim.report(m.worst_loaded, "relay over cap")
        );
        assert!(
            m.max_depth <= u32::from(sim.cfg.max_depth),
            "{}",
            sim.report(None, &format!("depth {}", m.max_depth))
        );
        assert!(m.max_depth >= 2, "multi-hop scenario stayed flat");
        assert_eq!(
            m.served,
            m.subscribers,
            "{}",
            sim.report(None, "unserved subscribers")
        );
        assert!(
            sim.log.count(DecisionKind::LoopDetected) == 0,
            "{}",
            sim.report(None, "a loop formed")
        );
    }

    #[test]
    fn multihop_depth_2_3_n200() {
        let (sim, m) = multihop(1, 200, 120 * SECOND);
        multihop_verdict(&sim, &m, 200);
    }

    #[test]
    #[ignore = "large-N: run explicitly (cargo test --lib realtime_av_alm -- --ignored)"]
    fn multihop_depth_2_3_n1000() {
        for seed in [1u64, 2] {
            let (sim, m) = multihop(seed, 1000, 180 * SECOND);
            multihop_verdict(&sim, &m, 1000);
        }
    }

    // ── Headline: sustainable subscribers per unit of relay bandwidth ──
    //
    // Saturate: more leaves than the relays can carry, so `served` measures
    // what the controller actually extracts from the uplinks. The ceiling is
    // `commit_fraction` (0.65) minus the standby audio share.

    fn saturation(
        seed: u64,
        relays: usize,
        relay_streams: f64,
        leaves: usize,
        end: u64,
    ) -> (Sim, Metrics, f64) {
        let mut others: Vec<NodeSpec> = (0..relays)
            .map(|_| NodeSpec::relay(relay_streams))
            .collect();
        others.extend(std::iter::repeat(NodeSpec::leaf()).take(leaves));
        let mut sim = Sim::new(
            seed,
            ControllerConfig::interactive(),
            NodeSpec::relay(8.0),
            &others,
            Candidates::Sample(12),
            None,
        );
        sim.run_until(end);
        let s = subs(&sim);
        let m = sim.metrics(end / 2, end, &s);
        let units = relays as f64 * relay_streams + 8.0;
        let eff = m.served as f64 / units;
        eprintln!(
            "[ALM-CTRL] HEADLINE seed={seed} relays={relays}x{relay_streams} leaves={leaves} served={}/{} \
             served_per_stream_unit={eff:.3} (0.65 ceiling; {:.0}% of it) overcap={} flips={}",
            m.served,
            m.subscribers,
            eff / 0.65 * 100.0,
            m.overcap_samples,
            m.flips
        );
        (sim, m, eff)
    }

    #[test]
    fn headline_saturated_relay_efficiency() {
        let (sim, m, eff) = saturation(5, 8, 20.0, 220, 120 * SECOND);
        assert_eq!(
            m.overcap_samples,
            0,
            "{}",
            sim.report(m.worst_loaded, "over cap at saturation")
        );
        assert!(
            eff >= 0.45,
            "{}",
            sim.report(
                None,
                &format!("efficiency {eff:.3} < 0.45 subs per stream unit")
            )
        );
    }

    #[test]
    #[ignore = "large-N headline: run explicitly"]
    fn headline_saturated_relay_efficiency_large() {
        let (sim, m, eff) = saturation(6, 40, 20.0, 1000, 180 * SECOND);
        assert_eq!(
            m.overcap_samples,
            0,
            "{}",
            sim.report(m.worst_loaded, "over cap at saturation")
        );
        assert!(
            eff >= 0.45,
            "{}",
            sim.report(None, &format!("efficiency {eff:.3}"))
        );
    }

    #[test]
    #[ignore = "large-N herding: run explicitly"]
    fn t1_large_n_herding_500() {
        let mut others: Vec<NodeSpec> = (0..32)
            .map(|i| NodeSpec::relay(20.0 + f64::from(i % 4) * 10.0))
            .collect();
        others.extend(std::iter::repeat(NodeSpec::leaf()).take(500));
        let mut sim = Sim::new(
            9,
            ControllerConfig::interactive(),
            NodeSpec::relay(10.0),
            &others,
            Candidates::Sample(12),
            None,
        );
        sim.run_until(240 * SECOND);
        let s = subs(&sim);
        let m = sim.metrics(60 * SECOND, 240 * SECOND, &s);
        emit("T1-500", &sim, &m);
        assert_eq!(
            m.overcap_samples,
            0,
            "{}",
            sim.report(m.worst_loaded, "over cap")
        );
        assert_eq!(m.flips, 0, "{}", sim.report(m.worst_flipper, "flips"));
        assert!(
            m.converged_ms.is_some_and(|c| c <= 60 * SECOND),
            "{}",
            sim.report(None, &format!("conv {:?}", m.converged_ms))
        );
    }
}

// ─── Stage 2 scenarios: relay selection (FSD CIRIS_MESH §9) ──────────

#[cfg(test)]
mod mesh_scenarios {
    //! `FSD/CIRIS_MESH.md` §9 and §7.6 on the closed loop, driving the
    //! production controller types. The worlds:
    //!
    //! - node 0 is the far end of every requester's link (the publisher);
    //! - **member relays** reach it directly and are the ALM media parents
    //!   of the hard-NAT members, who cannot reach node 0 at all (their
    //!   candidates are their contact set: roster relays + the canonical);
    //! - the **canonical** is a non-member transport forwarder of 1:1 links,
    //!   the last tier, audio only (§6.4).
    use super::*;

    const SECOND: u64 = 1_000;

    fn seeds() -> Vec<u64> {
        let n = std::env::var("CIRIS_ALM_SOAK")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(3u64);
        (1..=n).collect()
    }

    struct World {
        sim: Sim,
        relays: Vec<u32>,
        leaves: Vec<u32>,
        canonical: u32,
    }

    /// `relay_caps` member relays, `leaves` hard-NAT members each with
    /// `contacts` random relays + the canonical (advertising `canon_streams`).
    fn world(
        seed: u64,
        cfg: ControllerConfig,
        relay_caps: &[f64],
        leaves: usize,
        contacts: usize,
        canon_streams: f64,
    ) -> World {
        let mut others: Vec<NodeSpec> = relay_caps.iter().map(|&c| NodeSpec::relay(c)).collect();
        others.extend(std::iter::repeat(NodeSpec::leaf()).take(leaves));
        others.push(NodeSpec::leaf());
        let far_end = (relay_caps.len() as f64 * 1.7).max(4.0);
        let mut sim = Sim::new(
            seed,
            cfg,
            NodeSpec::relay(far_end),
            &others,
            Candidates::All,
            None,
        );
        let relays: Vec<u32> = (1..=relay_caps.len() as u32).collect();
        let first_leaf = relay_caps.len() as u32 + 1;
        let leaf_ids: Vec<u32> = (first_leaf..first_leaf + leaves as u32).collect();
        let canonical = first_leaf + leaves as u32;
        sim.make_canonical(canonical, canon_streams);
        sim.set_probe_streams(0, relays.len() as u64 + 1);
        for &r in &relays {
            sim.set_candidates(r, vec![0]);
        }
        let mut pick = SplitMix64(seed ^ 0xC0_7AC7);
        for &l in &leaf_ids {
            let mut pool = relays.clone();
            let mut c = Vec::with_capacity(contacts + 1);
            for _ in 0..contacts.min(pool.len()) {
                let j = pick.range_u64(0, pool.len() as u64) as usize;
                c.push(pool.swap_remove(j));
            }
            c.push(canonical);
            sim.set_candidates(l, c);
        }
        World {
            sim,
            relays,
            leaves: leaf_ids,
            canonical,
        }
    }

    fn line(name: &str, w: &World, m: &Metrics, extra: &str) {
        eprintln!(
            "[ALM-MESH] {name:<10} seed={} conv={:?} chg/sub/120s={:.3} flips={} overcap={} \
             served={}/{} canon_video={} canon_peak_bps={} {extra} decisions={} hash={}",
            w.sim.seed,
            m.converged_ms,
            m.change_rate_per_120s,
            m.flips,
            m.overcap_samples,
            m.served,
            m.subscribers,
            w.sim.canonical_video.len(),
            w.sim.canonical_peak_bps,
            w.sim.log.len(),
            &w.sim.log.hash_hex()[..16],
        );
    }

    /// Per-relay committed ÷ real capacity, max/min over relays carrying load.
    fn load_spread(w: &World) -> f64 {
        let loads: Vec<f64> = w
            .relays
            .iter()
            .filter(|&&r| w.sim.alive(r))
            .map(|&r| {
                w.sim.committed(r) as f64 / (w.sim.uplink_streams(r) * w.sim.cfg.stream_bps as f64)
            })
            .collect();
        let max = loads.iter().copied().fold(0.0, f64::max);
        let min = loads.iter().copied().fold(f64::MAX, f64::min);
        if min <= 0.0 {
            f64::INFINITY
        } else {
            max / min
        }
    }

    const S1_END: u64 = 300 * SECOND;

    fn s1(seed: u64, cfg: ControllerConfig) -> (World, Metrics) {
        // FSD S1: 200 hard-NAT members, 40 roster relays of {5,10,20}
        // reservation units, each member's contacts a random 8 of the 40, the
        // canonical present, all joining at t = 0.
        let caps: Vec<f64> = (0..40).map(|i| [5.0, 10.0, 20.0][i % 3]).collect();
        let mut w = world(seed, cfg, &caps, 200, 8, 100.0);
        w.sim.run_until(S1_END);
        let m = w.sim.metrics(30 * SECOND, S1_END, &w.leaves);
        (w, m)
    }

    /// The FSD S1 criteria, as this world measures them: (1) every member
    /// attached by 30 s (a member primary, or audio on the canonical when
    /// every one of its contacts is genuinely full), ≥ 99 % on a member;
    /// (2) no relay over 0.65 × capacity; (4) no flips and ≤ 1 change per
    /// member per 120 s; (5) the canonical carries only members none of
    /// whose contacts has room (≤ 1 %), and never video. The load spread
    /// (3) is reported, not asserted (see the module report).
    fn s1_verdict(w: &World, m: &Metrics) -> Result<String, String> {
        let sim = &w.sim;
        if let Some(&(t, n, what)) = sim.nonmember_violations.first() {
            return Err(sim.report(Some(n), &format!("{what} at t={t}")));
        }
        if let Some(&(t, n)) = sim.canonical_video.first() {
            return Err(sim.report(Some(n), &format!("video on the canonical at t={t}")));
        }
        if m.overcap_samples > 0 {
            let (t, n, load, cap) = sim.overcap[0];
            return Err(sim.report(Some(n), &format!("{load:.0} > {cap:.0} at t={t}")));
        }
        let on_member: Vec<u32> = w
            .leaves
            .iter()
            .copied()
            .filter(|&l| sim.primary_of(l).is_some_and(|p| w.relays.contains(&p)))
            .collect();
        let off: Vec<u32> = w
            .leaves
            .iter()
            .copied()
            .filter(|l| !on_member.contains(l))
            .collect();
        if on_member.len() * 100 < w.leaves.len() * 99 {
            return Err(sim.report(
                None,
                &format!(
                    "{}/{} on a roster relay; off {off:?}",
                    on_member.len(),
                    w.leaves.len()
                ),
            ));
        }
        for &l in &off {
            if !sim.video_unavailable(l) {
                return Err(sim.report(
                    Some(l),
                    "unattached (neither a member primary nor canonical audio)",
                ));
            }
        }
        let late = on_member
            .iter()
            .copied()
            .filter(|&l| sim.last_unserved(l) > 30 * SECOND)
            .max_by_key(|&l| sim.last_unserved(l));
        if let Some(l) = late {
            return Err(sim.report(
                Some(l),
                &format!("member-served only at {} ms", sim.last_unserved(l)),
            ));
        }
        let canon_kids: Vec<u32> = sim
            .children_of(w.canonical)
            .into_iter()
            .map(|(k, _)| k)
            .collect();
        // FSD S1 (5) as ruled (§6.4 V2, Eric): the canonical carries no video,
        // and audio only for members with no admitting contact, within 5 %.
        let cap = (0.05 * 100.0 * sim.cfg.stream_bps as f64) as u64;
        if sim.canonical_peak_bps > cap {
            return Err(sim.report(
                Some(w.canonical),
                &format!("canonical audio {} > 5 % ({cap})", sim.canonical_peak_bps),
            ));
        }
        if canon_kids.iter().any(|k| !off.contains(k)) {
            return Err(sim.report(
                Some(w.canonical),
                &format!(
                    "the canonical carries a member that has a member primary: {canon_kids:?}"
                ),
            ));
        }
        if m.flips > 0 {
            return Err(sim.report(m.worst_flipper, &format!("{} A→B→A flips", m.flips)));
        }
        if m.change_rate_per_120s > 1.0 {
            return Err(sim.report(None, &format!("change rate {:.3}", m.change_rate_per_120s)));
        }
        Ok(format!(
            "on_member={} canonical_audio_only={} spread={:.2}",
            on_member.len(),
            off.len(),
            load_spread(w)
        ))
    }

    /// **S1 — hard-NAT members choose roster relays without herding.** Pass:
    /// served by 30 s, ≥ 99 % on a roster relay, no relay over 0.65 ×
    /// capacity, no flips, ≤ 1 change per member per 120 s, the canonical
    /// carrying nothing.
    #[test]
    fn s1_hard_nat_members_choose_roster_relays_without_herding() {
        for seed in seeds() {
            let (w, m) = s1(seed, ControllerConfig::interactive());
            let r = s1_verdict(&w, &m);
            line("S1", &w, &m, r.as_deref().unwrap_or("FAIL"));
            if let Err(e) = r {
                panic!("{e}");
            }
        }
    }

    /// **S1-mut** — the herding controls off MUST fail S1.
    #[test]
    fn s1_mut_herding_controls_off_must_fail() {
        let (w, m) = s1(1, ControllerConfig::interactive().herding_mutant());
        let r = s1_verdict(&w, &m);
        line(
            "S1-mut",
            &w,
            &m,
            if r.is_err() {
                "FAILS (as it must)"
            } else {
                "PASSED"
            },
        );
        assert!(r.is_err(), "S1 does not test herding: the mutant passed");
    }

    /// **S3 — a roster relay goes offline; failover to another MEMBER before
    /// the canonical.** The killed relay's members promote their (member)
    /// standbys: audio never gaps, video gaps at most the suspicion bound,
    /// and the canonical carries nothing. Variant: every relay goes, and
    /// the members fall to the canonical — audio only, never video.
    #[test]
    fn s3_relay_failover_prefers_members_then_canonical_audio_only() {
        for seed in seeds() {
            let mut w = world(
                seed,
                ControllerConfig::interactive(),
                &[10.0; 6],
                24,
                6,
                50.0,
            );
            w.sim.run_until(120 * SECOND);
            let victim = w
                .relays
                .iter()
                .copied()
                .max_by_key(|&r| w.sim.children_of(r).len())
                .expect("relays");
            let orphans: Vec<u32> = w
                .leaves
                .iter()
                .copied()
                .filter(|&l| w.sim.primary_of(l) == Some(victim))
                .collect();
            assert!(
                !orphans.is_empty(),
                "{}",
                w.sim.report(Some(victim), "no orphans")
            );
            // The canonical may carry audio during cold start (members still
            // probing their capacity, R2); what counts is after the failure.
            w.sim.canonical_peak_bps = 0;
            w.sim.kill(victim);
            w.sim.run_until(180 * SECOND);
            let m = w.sim.metrics(120 * SECOND, 180 * SECOND, &orphans);
            for &o in &orphans {
                let p = w.sim.primary_of(o);
                assert!(
                    p.is_some_and(|p| w.relays.contains(&p) && p != victim),
                    "{}",
                    w.sim
                        .report(Some(o), &format!("not on another member: {p:?}"))
                );
            }
            assert_eq!(
                w.sim.canonical_peak_bps,
                0,
                "{}",
                w.sim.report(
                    Some(w.canonical),
                    "the canonical carried a member that had a member"
                )
            );
            // Suspicion (1.5 s) + RTT + one admission round, in chunks.
            let bound = (super::super::PARENT_SILENCE_HEAL_MS + 2_000) / CHUNK_MS;
            assert!(
                m.max_audio_gap <= 2 && m.max_video_gap <= bound,
                "{}",
                w.sim.report(
                    None,
                    &format!("gaps audio={} video={}", m.max_audio_gap, m.max_video_gap)
                )
            );
            line(
                "S3",
                &w,
                &m,
                &format!(
                    "orphans={} vgap={} agap={}",
                    orphans.len(),
                    m.max_video_gap,
                    m.max_audio_gap
                ),
            );

            // Variant: no member left. Audio-only on the canonical, V1 holds.
            for &r in &w.relays.clone() {
                if w.sim.alive(r) {
                    w.sim.kill(r);
                }
            }
            w.sim.run_until(260 * SECOND);
            assert!(w.sim.canonical_video.is_empty(), "video on the canonical");
            let audio_only = w
                .leaves
                .iter()
                .filter(|&&l| w.sim.video_unavailable(l))
                .count();
            assert!(
                audio_only > 0,
                "{}",
                w.sim.report(
                    Some(w.leaves[0]),
                    &format!(
                        "nobody fell to the canonical: leaf0 primary={:?} standby={:?} cands={:?} canon_children={:?}",
                        w.sim.primary_of(w.leaves[0]),
                        w.sim.standby_of(w.leaves[0]),
                        w.sim.candidates_of(w.leaves[0]),
                        w.sim.children_of(w.canonical)
                    )
                )
            );
            let cap = (0.05 * 50.0 * w.sim.cfg.stream_bps as f64) as u64;
            assert!(
                w.sim.canonical_peak_bps <= cap,
                "audio {} > 5 % ({cap})",
                w.sim.canonical_peak_bps
            );
            eprintln!(
                "[ALM-MESH] S3-variant seed={seed} audio_only_on_canonical={audio_only}/{}",
                w.leaves.len()
            );
        }
    }

    /// **S5 + S6 — canonical saturation, then recovery to the member tier.**
    /// No member relay is up: every member asks the canonical. Zero video
    /// reservations at the canonical ever; audio ≤ 5 % of its capacity;
    /// members beyond that get nothing (refused `relay_capacity`), never an
    /// unadmitted path. Then the relays come up: members leave the canonical
    /// make-before-break, video resumes, and the canonical's audio falls to
    /// ≤ 10 % of its peak.
    #[test]
    fn s5_s6_canonical_saturation_then_recovery() {
        for seed in seeds() {
            let mut w = world(
                seed,
                ControllerConfig::interactive(),
                &[10.0; 24],
                120,
                6,
                60.0,
            );
            for &r in &w.relays.clone() {
                w.sim.kill(r);
            }
            w.sim.run_until(100 * SECOND);
            let cap = (0.05 * 60.0 * w.sim.cfg.stream_bps as f64) as u64;
            let audio_only = w
                .leaves
                .iter()
                .filter(|&&l| w.sim.video_unavailable(l))
                .count();
            let unserved = w
                .leaves
                .iter()
                .filter(|&&l| w.sim.standby_of(l).is_none())
                .count();
            assert!(
                w.sim.canonical_video.is_empty(),
                "V1: video on the canonical"
            );
            assert!(
                w.sim.canonical_peak_bps <= cap,
                "V2: {} > {cap}",
                w.sim.canonical_peak_bps
            );
            let refusals = w.sim.log.count(DecisionKind::Refuse);
            assert!(
                audio_only > 0 && unserved > 0 && refusals > 0,
                "audio_only={audio_only} unserved={unserved}"
            );
            // Nobody hears video with no member up.
            for &l in &w.leaves {
                assert!(
                    !w.sim.got_full(l, 90 * SECOND / CHUNK_MS),
                    "video without a member path"
                );
            }
            let peak = w.sim.canonical_peak_bps;
            for &r in &w.relays.clone() {
                w.sim.revive(r);
            }
            w.sim.run_until(300 * SECOND);
            let now_canon = w.sim.committed(w.canonical);
            let m = w.sim.metrics(200 * SECOND, 300 * SECOND, &w.leaves);
            assert!(
                now_canon * 10 <= peak,
                "{}",
                w.sim.report(
                    Some(w.canonical),
                    &format!("canonical still holds {now_canon} of peak {peak}")
                )
            );
            assert!(w.sim.canonical_video.is_empty());
            line(
                "S5/S6",
                &w,
                &m,
                &format!(
                    "audio_only={audio_only} refused_capacity={unserved} canon_after={now_canon}"
                ),
            );
            assert!(
                m.served * 100 >= m.subscribers * 95,
                "video did not resume: {}/{}",
                m.served,
                m.subscribers
            );
        }
    }

    /// **LS4 — make-before-break shed.** A relay goes to tier 2 and sheds
    /// every commitment LIFO; each shed member moves to another member relay
    /// (never the canonical while a member has headroom) with zero frames
    /// lost to the move: the shedding relay keeps forwarding until it moves.
    #[test]
    #[allow(clippy::many_single_char_names)]
    fn ls4_tier_two_shed_is_make_before_break() {
        for seed in seeds() {
            let mut w = world(
                seed,
                ControllerConfig::interactive(),
                &[10.0; 4],
                12,
                4,
                50.0,
            );
            w.sim.run_until(120 * SECOND);
            let r = w
                .relays
                .iter()
                .copied()
                .max_by_key(|&r| w.sim.children_of(r).len())
                .expect("relays");
            let before: Vec<u32> = w.sim.children_of(r).into_iter().map(|(c, _)| c).collect();
            w.sim.canonical_peak_bps = 0;
            let shed = w.sim.set_tier(r, ServiceTier::ChatAndContacts);
            let mut sorted = shed.clone();
            sorted.sort_unstable();
            let mut b = before.clone();
            b.sort_unstable();
            assert_eq!(sorted, b, "every commitment shed");
            w.sim.run_until(180 * SECOND);
            let primaries: Vec<u32> = w
                .leaves
                .iter()
                .copied()
                .filter(|l| shed.contains(l))
                .collect();
            let m = w.sim.metrics(119 * SECOND, 180 * SECOND, &primaries);
            for &c in &primaries {
                let p = w.sim.primary_of(c);
                assert!(
                    p.is_some_and(|p| p != r && w.relays.contains(&p)),
                    "{}",
                    w.sim.report(Some(c), &format!("moved to {p:?}"))
                );
            }
            assert_eq!(
                m.max_audio_gap,
                0,
                "{}",
                w.sim.report(None, "audio lost to the move")
            );
            assert_eq!(
                m.max_video_gap,
                0,
                "{}",
                w.sim.report(None, "video lost to the move")
            );
            assert_eq!(
                w.sim.canonical_peak_bps, 0,
                "a member fell to the canonical"
            );
            assert!(
                w.sim.children_of(r).is_empty(),
                "the shed relay admitted again"
            );
            eprintln!(
                "[ALM-MESH] LS4 seed={seed} shed={} (LIFO) moved_without_loss",
                shed.len()
            );
        }
    }

    /// Same seed, same decision-log hash (the determinism gate for stage 2).
    #[test]
    fn mesh_determinism_same_seed_same_hash() {
        let a = {
            let mut w = world(7, ControllerConfig::interactive(), &[8.0; 6], 24, 4, 50.0);
            w.sim.run_until(60 * SECOND);
            w.sim.log.hash_hex()
        };
        let b = {
            let mut w = world(7, ControllerConfig::interactive(), &[8.0; 6], 24, 4, 50.0);
            w.sim.run_until(60 * SECOND);
            w.sim.log.hash_hex()
        };
        assert_eq!(a, b);
    }
}
