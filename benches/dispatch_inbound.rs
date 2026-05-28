//! `dispatch_inbound` — end-to-end receive: verify + ACK-match +
//! attestation-emit + handler-dispatch. Per `MessageType` (docs/BENCHMARKS.md).
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! `dispatch_inbound` (per `MessageType`): constant per-type +
//! linear-in-body (verify dominates). A step-function on `MessageType`
//! ⇒ per-type special-casing crept in (AV-22).
//!
//! # Per-MessageType slices
//!
//! - `InlineText` — verify → InlineText fan-out (no subscribers
//!   registered → no callback cost; the per-event GIL-acquire is
//!   benched separately in `subscription_throughput`).
//! - `FederationAnnouncement` (non-AccordCarrier) — verify →
//!   `is_federation_attestation_emitting_type` → enqueue a
//!   `DeliveryAttestation` outbound row.
//! - `ContentFetch` — verify → no handler registered (benches the
//!   warn-log + return path).
//! - `StewardDirective` — verify → attestation emission (same hook
//!   as FederationAnnouncement, per CIRISEdge#20 ask #3).

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

use chrono::Utc;
use ciris_edge::identity::{build_envelope, sign_envelope, LocalSigner};
use ciris_edge::messages::{
    AnnouncementKind, AnnouncementPriority, AuthorityClass, ContentFetch, FederationAnnouncement,
    InlineText, MessageType, StewardDirective,
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
    /// Holds both seed-tmpdirs alive for the duration of the bench so
    /// the keyring loader's seed file outlives any lazy use.
    _seed_dir: tempfile::TempDir,
}

async fn build_fixture() -> Fixture {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let directory = build_in_memory_backend(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
    ])
    .await;
    let edge_signer = bench_local_signer(&me, &tmp).await;
    // Separate handle to the same seed bytes — used to sign inbound
    // envelopes addressed at `me.key_id`. Same seed, same pubkey,
    // verify passes against the federation_keys row.
    let sender_signer = bench_local_signer(&me, &tmp).await;
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
        _seed_dir: tmp,
    }
}

/// Build a signed envelope of `message_type` with a small fixed body.
/// The nonce is set per-call (build_envelope uses uuid v4) so the
/// replay window doesn't reject repeats.
async fn make_signed_envelope_bytes(
    signer: &Arc<LocalSigner>,
    destination_key_id: &str,
    message_type: MessageType,
) -> Vec<u8> {
    let mut env = match message_type {
        MessageType::InlineText => build_envelope(
            MessageType::InlineText,
            &signer.key_id,
            destination_key_id,
            &InlineText {
                text: "x".repeat(256),
            },
            None,
        ),
        MessageType::FederationAnnouncement => build_envelope(
            MessageType::FederationAnnouncement,
            &signer.key_id,
            destination_key_id,
            &FederationAnnouncement {
                priority: AnnouncementPriority::Advisory,
                kind: AnnouncementKind::PolicyUpdate,
                title: "bench announcement".into(),
                body: "x".repeat(256),
                authority_class: AuthorityClass::RootWa,
                accord_payload: None,
                supersedes: None,
                expires_at: chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                    .unwrap()
                    .with_timezone(&Utc),
                evidence_refs: vec![],
                accord_signatures: vec![],
            },
            None,
        ),
        MessageType::ContentFetch => build_envelope(
            MessageType::ContentFetch,
            &signer.key_id,
            destination_key_id,
            &ContentFetch {
                sha256: [0u8; 32],
                response_hint: None,
            },
            None,
        ),
        MessageType::StewardDirective => build_envelope(
            MessageType::StewardDirective,
            &signer.key_id,
            destination_key_id,
            &StewardDirective {
                title: "bench directive".into(),
                body: "x".repeat(256),
            },
            None,
        ),
        other => panic!("unsupported MessageType for dispatch_inbound bench: {other:?}"),
    }
    .expect("build envelope");

    sign_envelope(signer, &mut env)
        .await
        .expect("sign envelope");
    serde_json::to_vec(&env).expect("envelope to bytes")
}

fn bench_dispatch(c: &mut Criterion) {
    // Two runtimes: setup_rt builds envelopes outside the bench iter
    // (no nested-runtime panic); bench_rt drives `to_async`.
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let bench_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let fixture = setup_rt.block_on(build_fixture());
    let dest = fixture.edge.signer_key_id().to_string();

    // Pre-sign a pool of envelopes per message type. The replay window
    // (default 100 K) accepts re-plays once their entries age out; the
    // bench's per-iter pool draw is round-robin, so within a single
    // criterion sample-set the same nonce will recur as a replay-
    // reject. The cheap-reject path (step 5 — replay window LRU hit)
    // IS still the receive cost we want measured for the slope-shape
    // question; the FRESH-envelope cost is at the envelope_verify
    // bench's iter_batched cousin. See BENCHMARKS.md "Reading the
    // curves" — per-MessageType slope shape is what `dispatch_inbound`
    // owns.
    const POOL: usize = 64;
    let pool_per_type: Vec<(&str, MessageType, Vec<Vec<u8>>)> = setup_rt.block_on(async {
        let types = [
            ("InlineText", MessageType::InlineText),
            (
                "FederationAnnouncement",
                MessageType::FederationAnnouncement,
            ),
            ("ContentFetch", MessageType::ContentFetch),
            ("StewardDirective", MessageType::StewardDirective),
        ];
        let mut out = Vec::with_capacity(types.len());
        for (label, mt) in types {
            let mut envs = Vec::with_capacity(POOL);
            for _ in 0..POOL {
                envs.push(
                    make_signed_envelope_bytes(&fixture.sender_signer, &dest, mt.clone()).await,
                );
            }
            out.push((label, mt, envs));
        }
        out
    });

    let mut group = c.benchmark_group("dispatch_inbound");
    group
        .sample_size(30)
        .measurement_time(Duration::from_secs(8));

    for (label, _mt, pool) in &pool_per_type {
        let mut idx = 0usize;
        let edge = fixture.edge.clone();
        group.bench_function(*label, |b| {
            let edge = edge.clone();
            b.to_async(&bench_rt).iter(|| {
                let envelope = pool[idx % pool.len()].clone();
                idx = idx.wrapping_add(1);
                let edge = edge.clone();
                async move {
                    let frame = InboundFrame {
                        envelope_bytes: envelope,
                        transport: TransportId::HTTP,
                        received_at: Utc::now(),
                    };
                    edge.dispatch_inbound_for_test(black_box(frame)).await;
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_dispatch);
criterion_main!(benches);
