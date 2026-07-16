//! `accord_threshold_verify` — CIRISEdge#19 / #359 wire-layer 2-of-3
//! HYBRID (Ed25519 + ML-DSA-65) multi-sig check. Exercises the
//! `dispatch_inbound` `AccordCarrier` gate (the only edge-public path that
//! reaches `verify_accord_carrier`).
//!
//! # Post-quantum accuracy (CIRISEdge#359)
//!
//! The accord carrier is constitutional kill-switch-class traffic, so
//! `verify_accord_carrier` verifies every signature as a HYBRID pair under
//! `HybridPolicy::Strict` (finding 2) and counts it only if the holder occupies
//! a pinned SEAT in verify's `accord_holder_bootstrap_anchor()` (finding 3).
//! This bench therefore measures the REAL post-quantum cost: ML-DSA-65 verify
//! dominates each holder's per-signature work.
//!
//! ## Why this bench requires `--features test-anchor`
//!
//! The seat set is pinned to verify's baked humanity-accord roster — the
//! synthetic bench holders are only "seated" via the test-anchor
//! `CIRIS_TEST_TRUST_ROOT` override, which is compile-fenced behind
//! `test-anchor`. Without the feature the file compiles to an inert `main` and
//! the default `cargo bench --benches` run skips it. Run the real measurement:
//!
//! ```text
//! cargo bench --features test-anchor --bench accord_threshold_verify
//! ```
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! The gate checks EVERY seated holder's signature (no early-exit after the
//! threshold is met — that's the fail-loud "name the tampered holder" contract).
//! Cost scales with the number of VALID signatures: a valid signature pays the
//! full Ed25519 + ML-DSA-65 verify (~150 µs, ML-DSA-dominated), while an invalid
//! one fails on the cheap Ed25519 half before the ML-DSA verify. So `3of3 >
//! 2of3 > 1of3` is EXPECTED (more valid sigs = more ML-DSA work). A DROP once
//! ≥ M valid sigs are present (e.g. `2of3` ≈ `3of3`) would signal an illegal
//! short-circuit after the threshold — the fail-loud violation to watch for.
//!
//! # Scenarios
//!
//! - `3of3_valid` — three valid hybrid sigs (accept; 3 full ML-DSA verifies).
//! - `2of3_valid_1of3_invalid` — two valid + one bad-bytes hybrid sig (accept).
//! - `1of3_valid` — one valid hybrid sig + two invalid (below threshold → refuse).
//! - `no_holders_configured` — zero `accord_holder` rows →
//!   `NoAccordHoldersConfigured` (the cheap pre-verify reject).

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

// CIRISEdge#359 — the real bench lives behind `test-anchor` (seated-roster
// injection). Everything is module-scoped under the feature so the default
// (no-test-anchor) build has no unused imports and just an inert `main`.
#[cfg(feature = "test-anchor")]
#[path = "common/mod.rs"]
mod common;

#[cfg(feature = "test-anchor")]
mod imp {
    use std::sync::{Arc, Once};
    use std::time::Duration;

    use chrono::Utc;
    use ciris_edge::messages::{
        AccordSignature, AnnouncementKind, AnnouncementPriority, AuthorityClass,
        FederationAnnouncement,
    };
    use ciris_edge::transport::Transport;
    use ciris_edge::verify::HybridPolicy;
    use ciris_edge::{Edge, EdgeConfig, OutboundHandle};
    use criterion::{black_box, Criterion};

    use super::common::{
        bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
    };

    /// Arm the test-anchor ONCE (env is process-global; each `[[bench]]` is its
    /// own process). Makes the synthetic accord holders "seated" by publishing
    /// their Ed25519 pubkeys as `CIRIS_TEST_TRUST_ROOT` — the exact override
    /// verify's `accord_holder_bootstrap_anchor()` reads under
    /// `CIRIS_TESTING_MODE` + the `test-anchor` feature.
    fn arm_test_anchor(seated: &[BenchFedKey]) {
        static ARM: Once = Once::new();
        ARM.call_once(|| {
            std::env::set_var("CIRIS_TESTING_MODE", "true");
            for prod in ["ENVIRONMENT", "CIRIS_ENV", "CIRIS_ENVIRONMENT"] {
                std::env::remove_var(prod);
            }
            let roots: Vec<String> = seated.iter().map(BenchFedKey::pubkey_b64).collect();
            std::env::set_var("CIRIS_TEST_TRUST_ROOT", roots.join(","));
        });
    }

    struct Fixture {
        edge: Arc<Edge>,
        holders: Vec<BenchFedKey>,
        _tmp: tempfile::TempDir,
    }

    /// Build fixture. If `seed_holders`, the directory gets 3 `accord_holder`
    /// rows (registered HYBRID — ed + ml-dsa pubkeys); otherwise only steward +
    /// agent rows (`NoAccordHoldersConfigured` path).
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
            // CIRISEdge#359 finding 2 — HYBRID signature. A valid sig is the
            // hybrid pair over the real canonical bytes; an "invalid" sig is a
            // well-formed hybrid pair over DIFFERENT bytes, so both halves fail
            // to verify against the announcement (the realistic tampered-holder
            // cost — the ML-DSA verify still runs).
            let (ed_b64, ml_dsa_b64) = if *valid {
                h.hybrid_sign(&canonical)
            } else {
                h.hybrid_sign(b"bench-invalid-canonical-bytes")
            };
            ann.accord_signatures.push(AccordSignature {
                key_id: h.key_id.clone(),
                signature_ed25519_base64: ed_b64,
                signature_ml_dsa_65_base64: Some(ml_dsa_b64),
            });
        }
        ann
    }

    pub fn bench_accord_threshold(c: &mut Criterion) {
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
        // Seat the bench holders (finding 3) BEFORE any verify runs.
        arm_test_anchor(&fx_with.holders);

        let mut group = c.benchmark_group("accord_threshold_verify");
        group
            .sample_size(30)
            .measurement_time(Duration::from_secs(8));

        // CIRISEdge#359 — measure the accord gate DIRECTLY (not through
        // dispatch_inbound, whose replay window would reject a pooled envelope
        // before the accord verify and hide the ML-DSA-65 cost). Each scenario
        // is a fixed pre-built hybrid-signed announcement; every iteration runs
        // the full per-signature hybrid verify, so the curve reflects the real
        // post-quantum cost.
        let scenarios: &[(&str, &[bool])] = &[
            ("3of3_valid", &[true, true, true]),
            ("2of3_valid_1of3_invalid", &[true, true, false]),
            ("1of3_valid", &[true, false, false]),
        ];
        for (label, valid_mask) in scenarios {
            let holders: Vec<(&BenchFedKey, bool)> = fx_with
                .holders
                .iter()
                .zip(valid_mask.iter().copied())
                .collect();
            let ann = announcement_with_sigs(&holders);
            let edge = fx_with.edge.clone();
            group.bench_function(*label, |b| {
                let edge = edge.clone();
                let ann = &ann;
                b.to_async(&bench_rt).iter(|| {
                    let edge = edge.clone();
                    async move {
                        black_box(edge.verify_accord_carrier_for_bench(ann).await).ok();
                    }
                });
            });
        }

        // ── no_holders_configured: directory has zero accord_holder rows →
        //    refusal short-circuits to NoAccordHoldersConfigured (the cheap
        //    pre-verify reject). ──
        let ann_no_holders = announcement_with_sigs(&[]);
        let edge_without = fx_without.edge.clone();
        group.bench_function("no_holders_configured", |b| {
            let edge = edge_without.clone();
            let ann = &ann_no_holders;
            b.to_async(&bench_rt).iter(|| {
                let edge = edge.clone();
                async move {
                    black_box(edge.verify_accord_carrier_for_bench(ann).await).ok();
                }
            });
        });

        group.finish();
    }
}

#[cfg(feature = "test-anchor")]
criterion::criterion_group!(benches, imp::bench_accord_threshold);
#[cfg(feature = "test-anchor")]
criterion::criterion_main!(benches);

// Inert entry point when the `test-anchor` feature is off — the seated-roster
// injection this bench needs is compile-fenced behind it. Keeps the default
// `cargo bench --benches` run (and the `--no-run` compile gate without the
// feature) green while measuring nothing.
#[cfg(not(feature = "test-anchor"))]
fn main() {
    eprintln!(
        "accord_threshold_verify requires `--features test-anchor` (seated-roster \
         injection). Run: cargo bench --features test-anchor --bench accord_threshold_verify"
    );
}
