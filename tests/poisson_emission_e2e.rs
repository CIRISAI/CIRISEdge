//! v6.1.0 (CIRISEdge#175, FSD §3.1) — Poisson emission discipline
//! end-to-end test.
//!
//! Asserts the two acceptance criteria the FSD §9 row pins:
//!
//! - **Cover envelopes flow when queue empty.** The scheduler emits
//!   synthetic cover envelopes (AEAD-protected `EnvelopeType::Cover`)
//!   on every Poisson timer fire while the real-publication queue is
//!   empty.
//! - **Per-scope KS-style inter-emission interval check.** Over a
//!   bounded sample window, the empirical mean inter-emission
//!   interval matches `1/λ` within tolerance. The FSD § 9 row
//!   specifies a KS-test at p > 0.01 over a 24h window — the v6.1.0
//!   unit test is the bounded-window analogue (the full 24h test
//!   lives in CIRISConformance per FSD §6.1).
//!
//! Both assertions exercise the wire-shape invariant: every emitted
//! envelope is exactly `ENVELOPE_BYTES = 1400` bytes (one MTU,
//! matching §2.4 RaptorQ symbol).

use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

use ciris_edge::emission::scheduler::{EmitFn, ScopeConfig};
use ciris_edge::{
    unseal_envelope, EmissionScheduler, EmissionSchedulerConfig, EmissionScopeKey, EnvelopeType,
    PoissonScheduler, ENVELOPE_BYTES,
};

fn make_recorder() -> (EmitFn, Arc<Mutex<Vec<ciris_edge::EmissionEnvelope>>>) {
    let envelopes: Arc<Mutex<Vec<ciris_edge::EmissionEnvelope>>> = Arc::new(Mutex::new(Vec::new()));
    let env_inner = envelopes.clone();
    let f: EmitFn = Arc::new(move |env| {
        let env_inner = env_inner.clone();
        Box::pin(async move {
            env_inner.lock().push(env);
        })
    });
    (f, envelopes)
}

fn one_scope(lambda: f64, scope_key: [u8; 32]) -> EmissionSchedulerConfig {
    let mut cfg = EmissionSchedulerConfig::default();
    cfg.scopes.insert(
        EmissionScopeKey::community("alpha".into()),
        ScopeConfig {
            lambda,
            target_real_per_window: 1000,
            window: Duration::from_secs(60),
            scope_key,
        },
    );
    cfg
}

#[tokio::test(flavor = "current_thread")]
async fn cover_envelopes_flow_when_queue_empty() {
    let (emit, envelopes) = make_recorder();
    let key = [0xAA; 32];
    let poisson = Arc::new(PoissonScheduler::from_seed([0x11; 32]));
    let sched = EmissionScheduler::new_with_poisson(one_scope(1000.0, key), emit, poisson);
    let _handle = sched.start();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let snap = envelopes.lock().clone();
    assert!(
        !snap.is_empty(),
        "scheduler must emit even with empty queue"
    );
    for (i, env) in snap.iter().enumerate() {
        assert_eq!(
            env.bytes.len(),
            ENVELOPE_BYTES,
            "envelope #{i} must be exactly ENVELOPE_BYTES bytes"
        );
        let (header, _) = unseal_envelope(&key, &env.bytes).expect("AEAD opens");
        assert_eq!(
            header.envelope_type,
            EnvelopeType::Cover,
            "envelope #{i} must be cover (queue is empty)"
        );
    }
}

#[tokio::test(flavor = "current_thread")]
async fn real_envelope_flows_then_covers_resume() {
    let (emit, envelopes) = make_recorder();
    let key = [0xBB; 32];
    let poisson = Arc::new(PoissonScheduler::from_seed([0x22; 32]));
    let sched = EmissionScheduler::new_with_poisson(one_scope(1000.0, key), emit, poisson);

    // Submit one real publication BEFORE starting — the scheduler's
    // first fire should drain it.
    sched
        .submit(
            &EmissionScopeKey::community("alpha".into()),
            [0xCD; 32],
            7,
            b"hello scope-native privacy",
        )
        .expect("submit accepted");
    let _handle = sched.start();

    tokio::time::sleep(Duration::from_millis(200)).await;
    let snap = envelopes.lock().clone();
    assert!(snap.len() >= 2, "expected real + at least one cover");

    let (hdr0, payload0) = unseal_envelope(&key, &snap[0].bytes).unwrap();
    assert_eq!(hdr0.envelope_type, EnvelopeType::Real);
    assert_eq!(hdr0.fragment_id, 7);
    assert_eq!(hdr0.fragment_count, 1);
    assert_eq!(
        &payload0[..b"hello scope-native privacy".len()],
        b"hello scope-native privacy"
    );

    // Subsequent envelopes (queue empty) are cover.
    let (hdr1, _) = unseal_envelope(&key, &snap[1].bytes).unwrap();
    assert_eq!(hdr1.envelope_type, EnvelopeType::Cover);
}

#[test]
fn inter_emission_intervals_match_exponential_mean() {
    // FSD §9 — per-scope KS-style discipline. The unit test is the
    // bounded-window analogue: empirical mean over N draws must be
    // within 5% of 1/λ. The full 24h KS test lives in
    // CIRISConformance per FSD §6.1.
    let p = PoissonScheduler::from_seed([0x33; 32]);
    let scope = EmissionScopeKey::community("alpha".into());
    let lambda = 50.0_f64;
    p.set_rate(scope.clone(), lambda);

    let n = 10_000;
    let mut total = 0.0;
    for _ in 0..n {
        total += p.next_interval(&scope).unwrap().as_secs_f64();
    }
    let mean = total / f64::from(n);
    let expected = 1.0 / lambda;
    let rel_err = (mean - expected).abs() / expected;
    assert!(
        rel_err < 0.05,
        "empirical mean {mean} too far from 1/λ = {expected} (rel_err {rel_err})"
    );
}
