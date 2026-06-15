//! `accord_threshold_verify` — CIRISEdge#19 wire-layer 2-of-3
//! multi-sig check. Exercises the `dispatch_inbound` `AccordCarrier`
//! gate (the only edge-public path that reaches `verify_accord_carrier`).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Flat across signature-count permutations — every holder's signature
//! is verified once. Early-reject (≥ M valid sigs short-circuits) ⇒
//! the wire-layer 2-of-3 gate is exiting before checking all holders.
//! That is a fail-loud violation per the docs: every holder's sig must
//! be checked so a tampered-holder is named in the reject.
//!
//! # Scenarios
//!
//! - `3of3_valid` — three valid sigs.
//! - `2of3_valid_1of3_invalid` — two valid + one bad-bytes sig.
//! - `1of3_valid` — one valid sig only (below threshold).
//! - `no_holders_configured` — persist directory holds zero
//!   `accord_holder` rows; refusal short-circuits to
//!   `NoAccordHoldersConfigured`.

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

#[path = "common/mod.rs"]
mod common;

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use chrono::Utc;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{
    AccordSignature, AnnouncementKind, AnnouncementPriority, AuthorityClass,
    FederationAnnouncement, MessageType,
};
use ciris_edge::transport::{InboundFrame, Transport};
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OutboundHandle, TransportId};
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use common::{
    bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
};

struct Fixture {
    edge: Arc<Edge>,
    sender_signer: Arc<LocalSigner>,
    holders: Vec<BenchFedKey>,
    _tmp: tempfile::TempDir,
}

/// Build fixture. If `seed_holders` is true, persist directory is
/// seeded with 3 `accord_holder` rows. Otherwise the directory has
/// only the steward + agent rows (`NoAccordHoldersConfigured` path).
async fn build_fixture(seed_holders: bool) -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("edge-self", 0xAA);
    let sender = BenchFedKey::new("steward-sender", 0xBB);

    let h1 = BenchFedKey::new("accord-holder-1", 0x11);
    let h2 = BenchFedKey::new("accord-holder-2", 0x22);
    let h3 = BenchFedKey::new("accord-holder-3", 0x33);

    let mut rows = vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&sender, &bootstrap, "steward"),
    ];
    if seed_holders {
        rows.push(signed_record(&h1, &bootstrap, "accord_holder"));
        rows.push(signed_record(&h2, &bootstrap, "accord_holder"));
        rows.push(signed_record(&h3, &bootstrap, "accord_holder"));
    }
    let directory = build_in_memory_backend(rows).await;
    let edge_signer = bench_local_signer(&me, &tmp).await;
    let sender_signer = bench_local_signer(&sender, &tmp).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    };
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(directory as Arc<dyn OutboundHandle>)
        .signer(edge_signer)
        .transport(Arc::new(NullTransport) as Arc<dyn Transport>)
        .config(config)
        .build()
        .expect("build edge");
    Fixture {
        edge: Arc::new(edge),
        sender_signer,
        holders: vec![h1, h2, h3],
        _tmp: tmp,
    }
}

fn announcement_with_sigs(
    holders: &[(&BenchFedKey, bool)], // (holder, valid?)
) -> FederationAnnouncement {
    let mut ann = FederationAnnouncement {
        priority: AnnouncementPriority::AccordCarrier,
        kind: AnnouncementKind::AccordCarrier,
        title: "bench accord".into(),
        body: "bench body".into(),
        authority_class: AuthorityClass::HumanityAccord,
        accord_payload: None,
        supersedes: None,
        expires_at: chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc),
        evidence_refs: vec![],
        accord_signatures: vec![],
    };
    let canonical = ann
        .canonical_bytes_for_accord_signatures()
        .expect("canonical bytes");
    for (h, valid) in holders {
        let sig = if *valid {
            h.sign(&canonical)
        } else {
            // Sign a different message — the sig will be 64 bytes but
            // won't verify.
            h.sign(b"bench-invalid")
        };
        ann.accord_signatures.push(AccordSignature {
            key_id: h.key_id.clone(),
            signature_ed25519_base64: B64.encode(sig),
        });
    }
    ann
}

async fn make_envelope_bytes(
    sender: &Arc<LocalSigner>,
    dest_key_id: &str,
    ann: &FederationAnnouncement,
) -> Vec<u8> {
    let mut env = build_envelope(
        MessageType::FederationAnnouncement,
        &sender.key_id,
        dest_key_id,
        ann,
        None,
    )
    .expect("build envelope");
    sign_envelope(sender, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("envelope to bytes")
}

fn bench_accord_threshold(c: &mut Criterion) {
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let bench_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let fx_with = setup_rt.block_on(build_fixture(true));
    let fx_without = setup_rt.block_on(build_fixture(false));

    let mut group = c.benchmark_group("accord_threshold_verify");
    group
        .sample_size(30)
        .measurement_time(Duration::from_secs(8));

    // Pre-build a pool of envelopes per scenario — the verify pipeline's
    // replay window admits each `(signing_key_id, nonce)` once, so the
    // bench replays from a pre-signed pool (within one criterion sample
    // set the replay-reject path IS the dominant cost; the multi-sig
    // gate runs BEFORE the replay window in dispatch_inbound, so the
    // shape question is answered regardless).
    //
    // ALSO: re-derived per iteration is the per-scenario distinct cost
    // (different signature mask), so we keep the bench's slope answer
    // about the gate, not about envelope-build.
    const POOL: usize = 64;
    let scenarios: &[(&str, &[bool])] = &[
        ("3of3_valid", &[true, true, true]),
        ("2of3_valid_1of3_invalid", &[true, true, false]),
        ("1of3_valid", &[true, false, false]),
    ];
    let scenario_pools: Vec<(&str, Vec<Vec<u8>>)> = setup_rt.block_on(async {
        let mut out = Vec::with_capacity(scenarios.len());
        let dest = fx_with.edge.signer_key_id().to_string();
        for (label, valid_mask) in scenarios {
            let holders: Vec<(&BenchFedKey, bool)> = fx_with
                .holders
                .iter()
                .zip(valid_mask.iter().copied())
                .collect();
            let mut envs = Vec::with_capacity(POOL);
            for _ in 0..POOL {
                let ann = announcement_with_sigs(&holders);
                envs.push(make_envelope_bytes(&fx_with.sender_signer, &dest, &ann).await);
            }
            out.push((*label, envs));
        }
        out
    });

    for (label, pool) in &scenario_pools {
        let mut idx = 0usize;
        let edge = fx_with.edge.clone();
        group.bench_function(*label, |b| {
            let edge = edge.clone();
            b.to_async(&bench_rt).iter(|| {
                let envelope_bytes = pool[idx % pool.len()].clone();
                idx = idx.wrapping_add(1);
                let edge = edge.clone();
                async move {
                    let frame = InboundFrame {
                        envelope_bytes,
                        transport: TransportId::HTTP,
                        received_at: Utc::now(),
                        source_key_id: None,
                    };
                    edge.dispatch_inbound_for_test(black_box(frame)).await;
                }
            });
        });
    }

    // ── no_holders_configured: directory has zero accord_holder rows
    //    → refusal short-circuits to NoAccordHoldersConfigured. ──
    let pool_no_holders: Vec<Vec<u8>> = setup_rt.block_on(async {
        let dest = fx_without.edge.signer_key_id().to_string();
        let mut envs = Vec::with_capacity(POOL);
        for _ in 0..POOL {
            let ann = announcement_with_sigs(&[]);
            envs.push(make_envelope_bytes(&fx_without.sender_signer, &dest, &ann).await);
        }
        envs
    });
    let mut idx = 0usize;
    let edge_without = fx_without.edge.clone();
    group.bench_function("no_holders_configured", |b| {
        let edge = edge_without.clone();
        b.to_async(&bench_rt).iter(|| {
            let envelope_bytes = pool_no_holders[idx % pool_no_holders.len()].clone();
            idx = idx.wrapping_add(1);
            let edge = edge.clone();
            async move {
                let frame = InboundFrame {
                    envelope_bytes,
                    transport: TransportId::HTTP,
                    received_at: Utc::now(),
                    source_key_id: None,
                };
                edge.dispatch_inbound_for_test(black_box(frame)).await;
            }
        });
    });

    group.finish();
}

criterion_group!(benches, bench_accord_threshold);
criterion_main!(benches);
