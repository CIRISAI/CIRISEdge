//! CC 5.4.3 measurement — the shaped frame at the link's channel payload MDU
//! (16,272 B over TCP, today) against a capped frame (the 1,400 B proposal,
//! with 1,200 / 2,048 / 4,096 beside it). Not a gate: every test here is
//! `#[ignore]`; run with `--ignored --nocapture`.
//!
//! Everything runs edge's PRODUCTION primitives: the agreement comes from
//! `ShapingOffer::from_policy` + `agree` at each frame; frames are cut by
//! `frame_fragment::fragment` at `body_capacity`; `wrap`/`wrap_multi`/`unwrap`
//! frame them; the `PoissonScheduler` and `BudgetMeter` drive the stream; the
//! contact story runs real `LinkShaper`s (coalescing on, as between v44
//! peers) on tokio's paused clock.
//!
//! * `fm1_real_share_grid` — fixed real BYTE demand (rows Poisson, sizes from
//!   a mix), 2 h virtual per cell: real-frame share, the worst meter-window
//!   and sliding-window share against ρ, fires the budget blocked, the queue,
//!   and the row delay.
//! * `fm1b_catch_up_burst` — a first-contact catch-up dumped at t = 0.
//! * `fm2_wrap_seal_cpu` — wrap + AES-256-GCM seal and open + unwrap per
//!   frame, and what that costs per link at the class λ.
//! * `fm3_contact_latency` — K request/response exchanges over a shaped pair
//!   (direct) and over two shaped hops (relayed through a canonical).
#![cfg(feature = "transport-reticulum")]

use std::collections::VecDeque;
use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_edge::emission::{BudgetMeter, BudgetState, PoissonScheduler, ScopeKey};
use ciris_edge::transport::frame_fragment::{fragment, Reassembler};
use ciris_edge::transport::link_shaping::{
    agree, body_capacity, unwrap, wrap, wrap_multi, Agreement, BudgetClass, Emission, LinkShaper,
    ShapedFrame, ShapingOffer, ShapingPolicy, DEFAULT_QUEUE_CAP,
};

/// The TCP channel payload MDU the 0.5.245 rig agreed (`REFERENCE_FRAME_BYTES`).
const MDU: usize = 16_272;

fn env_list<T: std::str::FromStr>(name: &str, default: &[T]) -> Vec<T>
where
    T: Clone,
    T::Err: std::fmt::Debug,
{
    std::env::var(name).ok().map_or_else(
        || default.to_vec(),
        |v| {
            v.split(',')
                .map(|x| x.trim().parse().expect(name))
                .collect()
        },
    )
}

fn frames() -> Vec<usize> {
    env_list("FM_FRAMES", &[MDU, 4096, 2048, 1400, 1200])
}

/// The proposal: min(cap, MDU), the agreement both ends compute.
fn agreement(class: BudgetClass, frame: usize) -> Agreement {
    let p = ShapingPolicy::for_class(class);
    let o = ShapingOffer::from_policy(&p, frame.min(MDU));
    agree(&o, &o).expect("both shape")
}

fn class_of(name: &str) -> BudgetClass {
    match name {
        "server" => BudgetClass::Server,
        "home" => BudgetClass::Home,
        "phone-wifi" => BudgetClass::PhoneWifi,
        "phone-cellular" => BudgetClass::PhoneCellular,
        other => panic!("class {other}"),
    }
}

/// xorshift64* — the arrivals' own stream, independent of the scheduler.
struct Rng(u64);
impl Rng {
    fn next_f64(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        (self.0 >> 11) as f64 / (1u64 << 53) as f64
    }
    fn exp(&mut self, rate: f64) -> f64 {
        -(1.0 - self.next_f64()).ln() / rate
    }
    fn pick(&mut self, mix: &[(usize, f64)]) -> usize {
        let total: f64 = mix.iter().map(|(_, w)| w).sum();
        let mut x = self.next_f64() * total;
        for (n, w) in mix {
            if x < *w {
                return *n;
            }
            x -= w;
        }
        mix.last().unwrap().0
    }
}

/// Row size mixes (envelope bytes). `t2`: the T2 mesh sample's shape, mean
/// ≈ 8.3 KB (the 2026-10-22 harness's 50 rows averaged 8.5 KB): consent/control
/// rows, chat-sized rows, hybrid-signed key/attestation rows (an ML-DSA-65
/// signature alone is 3,309 B), summaries. `control`: the steady maintenance
/// planes between rounds — Pulls, cursors, acks, small rows; mean ≈ 430 B.
fn mix(name: &str) -> Vec<(usize, f64)> {
    match name {
        "t2" => vec![
            (300, 1.0),
            (971, 1.0),
            (2_000, 1.0),
            (8_000, 1.0),
            (30_000, 1.0),
        ],
        "control" => vec![(200, 7.0), (971, 3.0)],
        other => panic!("mix {other}"),
    }
}

fn mean_of(mix: &[(usize, f64)]) -> f64 {
    let w: f64 = mix.iter().map(|(_, w)| w).sum();
    mix.iter().map(|(n, x)| *n as f64 * x).sum::<f64>() / w
}

#[derive(Default, Debug)]
struct ShareStats {
    real: u64,
    cover: u64,
    blocked: u64,
    max_window_share: f64,
    max_sliding_share: f64,
    max_queue: usize,
    backlog: usize,
    delays: Vec<f64>,
    body_bytes: u64,
    row_bytes: u64,
}

fn pct(v: &[f64], p: f64) -> f64 {
    if v.is_empty() {
        return f64::NAN;
    }
    v[((v.len() - 1) as f64 * p).round() as usize]
}

/// The production emission decision (`LinkShaper::next_emission`) on a
/// virtual clock: one Poisson fire → the meter's verdict → the head body, or
/// as many heads as fit (coalescing), else cover. `rows` are `(arrival_s,
/// envelope_len)` in arrival order.
fn run_stream(
    a: &Agreement,
    coalesce: bool,
    rows: &[(f64, usize)],
    horizon_s: f64,
    seed: u8,
) -> ShareStats {
    let scope = ScopeKey::community("measure".to_owned());
    let p = PoissonScheduler::from_seed([seed; 32]);
    p.set_rate(scope.clone(), a.lambda);
    let budget = BudgetMeter::new();
    let target = (a.rho * a.lambda * a.window.as_secs_f64()).ceil().max(1.0) as u32;
    budget.configure(scope.clone(), target, a.window);
    let cap = body_capacity(a.frame_bytes);
    let w_s = a.window.as_secs_f64();
    let base = Instant::now();
    let mut st = ShareStats::default();
    // (arrival_s, body_len, last_of_row)
    let mut q: VecDeque<(f64, usize, bool)> = VecDeque::new();
    let mut ri = 0usize;
    let mut now = 0.0f64;
    // The meter's own windows (it rolls on the first touch past W).
    let (mut w_start, mut w_real, mut w_all) = (0.0f64, 0u64, 0u64);
    // Sliding window: (t, real?) of every fire in the last W.
    let mut slide: VecDeque<(f64, bool)> = VecDeque::new();
    let mut slide_real = 0u64;
    let mut pad = vec![0u8; usize::from(a.frame_bytes)];
    while now < horizon_s {
        now += p.next_interval(&scope).expect("rate").as_secs_f64();
        while ri < rows.len() && rows[ri].0 <= now {
            let (at, n) = rows[ri];
            st.row_bytes += n as u64;
            let frags = fragment(&vec![0u8; n], cap).expect("fragments");
            let k = frags.len();
            for (i, f) in frags.into_iter().enumerate() {
                q.push_back((at, f.len(), i + 1 == k));
            }
            ri += 1;
        }
        st.max_queue = st.max_queue.max(q.len());
        if now - w_start >= w_s {
            if w_all > 0 && now - w_start < 2.0 * w_s {
                st.max_window_share = st.max_window_share.max(w_real as f64 / w_all as f64);
            }
            w_start = now;
            w_real = 0;
            w_all = 0;
        }
        let virt = base + Duration::from_secs_f64(now);
        let under = matches!(
            budget.query_at(&scope, virt),
            BudgetState::UnderBudget { .. }
        );
        let mut bodies: Vec<(f64, usize, bool)> = Vec::new();
        if under {
            let mut used = 0usize;
            while let Some(&(_, len, _)) = q.front() {
                let need = if coalesce { 2 + len } else { len };
                if !bodies.is_empty() && (!coalesce || used + need > cap) {
                    break;
                }
                used += need;
                bodies.push(q.pop_front().expect("front"));
            }
        } else if !q.is_empty() {
            st.blocked += 1;
        }
        let real = !bodies.is_empty();
        // The production framing, so its cost and its limits are the real ones.
        let mut fill = |b: &mut [u8]| p.fill_bytes(b);
        let framed = if bodies.len() > 1 {
            let bs: Vec<Vec<u8>> = bodies.iter().map(|(_, l, _)| vec![0u8; *l]).collect();
            wrap_multi(a.frame_bytes, &bs, &mut fill)
        } else if let Some((_, l, _)) = bodies.first() {
            pad.truncate(*l);
            pad.resize(*l, 0);
            wrap(a.frame_bytes, Some(&pad), &mut fill)
        } else {
            wrap(a.frame_bytes, None, &mut fill)
        };
        assert_eq!(framed.expect("fits").len(), usize::from(a.frame_bytes));
        if real {
            budget.record_real_at(&scope, virt);
            st.real += 1;
            for (at, len, last) in &bodies {
                st.body_bytes += *len as u64;
                if *last {
                    st.delays.push(now - at);
                }
            }
        } else {
            budget.record_cover_at(&scope, virt);
            st.cover += 1;
        }
        w_all += 1;
        w_real += u64::from(real);
        slide.push_back((now, real));
        slide_real += u64::from(real);
        while slide.front().is_some_and(|(t, _)| now - t > w_s) {
            let (_, r) = slide.pop_front().unwrap();
            slide_real -= u64::from(r);
        }
        if now > w_s {
            st.max_sliding_share = st
                .max_sliding_share
                .max(slide_real as f64 / slide.len() as f64);
        }
    }
    st.backlog = q.len();
    st.delays.sort_by(|a, b| a.partial_cmp(b).unwrap());
    st
}

fn poisson_rows(
    rate_bytes: f64,
    mix: &[(usize, f64)],
    horizon_s: f64,
    seed: u64,
) -> Vec<(f64, usize)> {
    let row_rate = rate_bytes / mean_of(mix);
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
    let mut t = 0.0;
    let mut v = Vec::new();
    loop {
        t += rng.exp(row_rate);
        if t >= horizon_s {
            break;
        }
        v.push((t, rng.pick(mix)));
    }
    v
}

/// **M1** — fixed real byte demand, frame varied. Env: `FM_FRAMES`,
/// `FM_CLASSES`, `FM_MIXES`, `FM_LOADS` (real bytes ÷ class bytes/s),
/// `FM_HOURS`, `FM_COALESCE` (1/0 list).
#[test]
#[ignore = "measurement, not a gate"]
fn fm1_real_share_grid() {
    let classes: Vec<String> = env_list("FM_CLASSES", &["server".to_owned(), "home".to_owned()]);
    let mixes: Vec<String> = env_list("FM_MIXES", &["t2".to_owned(), "control".to_owned()]);
    let loads: Vec<f64> = env_list("FM_LOADS", &[0.025, 0.05, 0.1, 0.2, 0.3, 0.4, 0.45]);
    let hours: f64 = env_list("FM_HOURS", &[2.0])[0];
    let coalesce: Vec<u8> = env_list("FM_COALESCE", &[1u8]);
    println!(
        "FM1 class mix coalesce frame lambda rho target load_Bps real_share max_win_share \
         max_slide_share blocked_fires max_queue backlog body_eff mean_s p50_s p95_s p99_s"
    );
    for c in &classes {
        let class = class_of(c);
        let rate = f64::from(ShapingPolicy::for_class(class).bytes_per_s);
        for m in &mixes {
            let mx = mix(m);
            for &load in &loads {
                let horizon = hours * 3600.0;
                let rows = poisson_rows(load * rate, &mx, horizon, (load * 1e4) as u64);
                for &co in &coalesce {
                    for &f in &frames() {
                        let a = agreement(class, f);
                        let s = run_stream(&a, co == 1, &rows, horizon, 11);
                        let all = (s.real + s.cover).max(1) as f64;
                        let target = (a.rho * a.lambda * a.window.as_secs_f64()).ceil();
                        // Real bytes carried ÷ the wire bytes the real frames cost.
                        let eff =
                            s.row_bytes as f64 / (s.real.max(1) as f64 * f64::from(a.frame_bytes));
                        let mean = s.delays.iter().sum::<f64>() / s.delays.len().max(1) as f64;
                        println!(
                            "FM1 {c} {m} {co} {} {:.3} {} {target} {:.0} {:.3} {:.3} {:.3} {} {} {} {:.2} {mean:.2} {:.2} {:.2} {:.2}",
                            a.frame_bytes,
                            a.lambda,
                            a.rho,
                            load * rate,
                            s.real as f64 / all,
                            s.max_window_share,
                            s.max_sliding_share,
                            s.blocked,
                            s.max_queue,
                            s.backlog,
                            eff,
                            pct(&s.delays, 0.5),
                            pct(&s.delays, 0.95),
                            pct(&s.delays, 0.99),
                        );
                    }
                }
            }
        }
    }
}

/// **M1b** — a catch-up burst (first contact: `FM_BURST_ROWS` T2 rows queued at
/// t = 0, over a background of 5 % control load): time to drain, real share
/// over the first window, fires the budget blocked.
#[test]
#[ignore = "measurement, not a gate"]
fn fm1b_catch_up_burst() {
    let classes: Vec<String> = env_list("FM_CLASSES", &["server".to_owned(), "home".to_owned()]);
    let bursts: Vec<usize> = env_list("FM_BURST_ROWS", &[50usize, 200, 400]);
    println!("FM1B class burst_rows burst_bytes frame lambda target drain_p50_s drain_max_s blocked first_win_share max_queue queue_cap");
    for c in &classes {
        let class = class_of(c);
        let rate = f64::from(ShapingPolicy::for_class(class).bytes_per_s);
        for &n in &bursts {
            let mut rng = Rng(77);
            let t2 = mix("t2");
            let mut rows: Vec<(f64, usize)> = (0..n).map(|_| (0.0, rng.pick(&t2))).collect();
            let bytes: usize = rows.iter().map(|r| r.1).sum();
            let horizon = 3.0 * 3600.0;
            rows.extend(poisson_rows(0.05 * rate, &mix("control"), horizon, 5));
            rows.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap());
            for &f in &frames() {
                let a = agreement(class, f);
                let s = run_stream(&a, true, &rows, horizon, 13);
                // The burst rows are the n zero-arrival delays: the drain is
                // the largest delay among rows that arrived at t = 0.
                let target = (a.rho * a.lambda * a.window.as_secs_f64()).ceil();
                let drain_max = s.delays.iter().cloned().fold(0.0f64, f64::max);
                println!(
                    "FM1B {c} {n} {bytes} {} {:.3} {target} {:.1} {:.1} {} {:.3} {} {}",
                    a.frame_bytes,
                    a.lambda,
                    pct(&s.delays, 0.5),
                    drain_max,
                    s.blocked,
                    s.max_window_share,
                    s.max_queue,
                    DEFAULT_QUEUE_CAP,
                );
            }
        }
    }
}

/// **M2** — per-frame CPU: wrap (random pad from the scheduler's CSPRNG) +
/// AES-256-GCM seal (the E1 seal's own call, fresh key schedule per call as
/// in `SealedLink::seal`), and open + unwrap. Per link: λ frames out and λ in,
/// each way, all the time (cover costs the same as real).
#[test]
#[ignore = "measurement, not a gate"]
fn fm2_wrap_seal_cpu() {
    let key = [7u8; 32];
    let aad = [0x5au8; 17];
    let p = PoissonScheduler::from_seed([3; 32]);
    println!("FM2 frame tx_us(wrap+seal) rx_us(open+unwrap) | class lambda seals_per_s_each_way cpu_pct_per_link cpu_pct_8_links");
    for &f in &frames() {
        let frame = u16::try_from(f).unwrap();
        let body = vec![0xabu8; 300];
        let n: u32 = if f > 8_000 { 4_000 } else { 30_000 };
        let mut fill = |b: &mut [u8]| p.fill_bytes(b);
        let t = Instant::now();
        let mut last = Vec::new();
        for i in 0..n {
            let w = wrap(frame, Some(&body), &mut fill).unwrap();
            let mut nonce = [0u8; 12];
            nonce[..4].copy_from_slice(&i.to_be_bytes());
            last = ciris_crypto::aes_gcm::encrypt_aad(&key, &nonce, &aad, &w).unwrap();
        }
        let tx_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(n);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&(n - 1).to_be_bytes());
        let t = Instant::now();
        for _ in 0..n {
            let pt = ciris_crypto::aes_gcm::decrypt_aad(&key, &nonce, &aad, &last).unwrap();
            assert!(matches!(unwrap(&pt).unwrap(), ShapedFrame::Real(_)));
        }
        let rx_us = t.elapsed().as_secs_f64() * 1e6 / f64::from(n);
        for c in ["server", "home"] {
            let a = agreement(class_of(c), f);
            let cpu = a.lambda * (tx_us + rx_us) / 1e6 * 100.0;
            println!(
                "FM2 {} {tx_us:.2} {rx_us:.2} | {c} {:.3} {:.3} {:.4} {:.4}",
                a.frame_bytes,
                a.lambda,
                a.lambda,
                cpu,
                cpu * 8.0
            );
        }
    }
}

// ---------------------------------------------------------------------------
// M3 — contact latency on tokio's paused clock, real `LinkShaper`s.
// ---------------------------------------------------------------------------

/// One direction of a shaped link: the production shaper's emission loop,
/// delivering each frame to the far end's receive task at once (loopback).
fn run_direction(
    s: Arc<LinkShaper>,
    deliver: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match s.next_emission().await {
                Emission::Frame {
                    bytes,
                    real,
                    ticket,
                } => {
                    if real {
                        s.note_sent(ticket);
                    }
                    if deliver.send(bytes).is_err() {
                        return;
                    }
                }
                Emission::Stopped => return,
            }
        }
    })
}

/// The receive side: unwrap, reassemble (the production `Reassembler`), and
/// hand each whole frame up.
fn run_receiver(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    up: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut reasm = Reassembler::new();
        while let Some(f) = rx.recv().await {
            let bodies = match unwrap(&f).expect("a shaped frame") {
                ShapedFrame::Cover => continue,
                ShapedFrame::Real(b) => vec![b],
                ShapedFrame::Many(bs) => bs,
            };
            for b in bodies {
                if let Some(whole) = reasm.accept(&b) {
                    if up.send(whole).is_err() {
                        return;
                    }
                }
            }
        }
    })
}

/// A shaped pair `x ⇄ y`: `(to_y, from_y_at_x)`… returned as the two shapers
/// and the two upward channels.
struct Pair {
    xy: Arc<LinkShaper>,
    yx: Arc<LinkShaper>,
    at_y: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    at_x: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl Pair {
    fn new(a: Agreement, seed: u8) -> Self {
        let mk = |s: u8| {
            let sh = Arc::new(LinkShaper::new_seeded(
                [s; 16],
                a,
                DEFAULT_QUEUE_CAP,
                [s; 32],
            ));
            sh.enable_coalescing();
            sh
        };
        let xy = mk(seed);
        let yx = mk(seed.wrapping_add(101));
        let (wxy, rxy) = tokio::sync::mpsc::unbounded_channel();
        let (wyx, ryx) = tokio::sync::mpsc::unbounded_channel();
        let (uy, at_y) = tokio::sync::mpsc::unbounded_channel();
        let (ux, at_x) = tokio::sync::mpsc::unbounded_channel();
        let tasks = vec![
            run_direction(Arc::clone(&xy), wxy),
            run_direction(Arc::clone(&yx), wyx),
            run_receiver(rxy, uy),
            run_receiver(ryx, ux),
        ];
        Self {
            xy,
            yx,
            at_y,
            at_x,
            tasks,
        }
    }
    fn stop(self) {
        self.xy.stop();
        self.yx.stop();
        for t in self.tasks {
            t.abort();
        }
    }
}

fn send(s: &LinkShaper, msg: &[u8]) {
    let cap = body_capacity(s.agreement().frame_bytes);
    s.enqueue(fragment(msg, cap).expect("fragments"))
        .expect("queued");
}

fn msg(tag: u32, i: u32, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len.max(8)];
    v[..4].copy_from_slice(&tag.to_be_bytes());
    v[4..8].copy_from_slice(&i.to_be_bytes());
    v
}

/// K request/response exchanges, `hops` shaped hops each way (1 = direct,
/// 2 = relayed through a canonical that reassembles and re-queues).
async fn contact(a: Agreement, k: u32, req: usize, resp: usize, hops: usize, seed: u8) -> f64 {
    let start = tokio::time::Instant::now();
    if hops == 1 {
        let mut p = Pair::new(a, seed);
        for i in 0..k {
            send(&p.xy, &msg(1, i, req));
            let r = p.at_y.recv().await.expect("request");
            assert_eq!(&r[4..8], &i.to_be_bytes());
            send(&p.yx, &msg(2, i, resp));
            let r = p.at_x.recv().await.expect("response");
            assert_eq!(&r[4..8], &i.to_be_bytes());
        }
        p.stop();
    } else {
        // client ⇄ canonical ⇄ peer
        let mut l1 = Pair::new(a, seed);
        let mut l2 = Pair::new(a, seed.wrapping_add(53));
        for i in 0..k {
            send(&l1.xy, &msg(1, i, req));
            let r = l1.at_y.recv().await.expect("at canonical");
            send(&l2.xy, &r);
            let r = l2.at_y.recv().await.expect("at peer");
            assert_eq!(&r[4..8], &i.to_be_bytes());
            send(&l2.yx, &msg(2, i, resp));
            let r = l2.at_x.recv().await.expect("back at canonical");
            send(&l1.yx, &r);
            let r = l1.at_x.recv().await.expect("at client");
            assert_eq!(&r[4..8], &i.to_be_bytes());
        }
        l1.stop();
        l2.stop();
    }
    start.elapsed().as_secs_f64()
}

/// **M3** — contact-like latency: K exchanges (`FM_K`, default 7), request
/// `FM_REQ` B, response sizes `FM_RESPS` (a few hundred bytes; and a
/// hybrid-signed key row), direct and relayed, `FM_SAMPLES` per cell.
#[tokio::test(flavor = "current_thread", start_paused = true)]
#[ignore = "measurement, not a gate"]
async fn fm3_contact_latency() {
    let k: u32 = env_list("FM_K", &[7u32])[0];
    let req: usize = env_list("FM_REQ", &[400usize])[0];
    let resps: Vec<usize> = env_list("FM_RESPS", &[400usize, 6_000]);
    let samples: usize = env_list("FM_SAMPLES", &[400usize])[0];
    let classes: Vec<String> = env_list("FM_CLASSES", &["server".to_owned(), "home".to_owned()]);
    println!("FM3 class hops k req resp frame lambda gap_s p50_s p90_s p99_s mean_s");
    for c in &classes {
        for &resp in &resps {
            for hops in [1usize, 2] {
                for &f in &frames() {
                    let a = agreement(class_of(c), f);
                    let mut v = Vec::with_capacity(samples);
                    for s in 0..samples {
                        v.push(contact(a, k, req, resp, hops, (s % 251) as u8 + 1).await);
                    }
                    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
                    let mean = v.iter().sum::<f64>() / v.len() as f64;
                    println!(
                        "FM3 {c} {hops} {k} {req} {resp} {} {:.3} {:.3} {:.1} {:.1} {:.1} {mean:.1}",
                        a.frame_bytes,
                        a.lambda,
                        1.0 / a.lambda,
                        pct(&v, 0.5),
                        pct(&v, 0.9),
                        pct(&v, 0.99),
                    );
                }
            }
        }
    }
}
