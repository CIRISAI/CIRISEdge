//! `outbound_enqueue` — build envelope + sign +
//! [`OutboundHandle::enqueue_outbound`]. Per delivery class.
//!
//! # Expected curve (per BENCHMARKS.md "Reading the curves")
//!
//! Constant per-class — `Ephemeral` shortest (no persist write);
//! `Durable`/`Federation`/`Mandatory` add the persist roundtrip
//! through the same `edge_outbound_queue` row write. `Federation`
//! and `Mandatory` should be linear in the fan-out set, not in the
//! per-envelope path — super-linearity ⇒ enumeration happening
//! per-envelope instead of once-per-call.
//!
//! # Per-class slices
//!
//! - `Ephemeral` — `Edge::send` over `AccordEventsBatch` (the bench
//!   uses an empty `BatchEnvelope` body to keep sign cost dominant;
//!   `send` returns `EdgeError::Config` because Phase 1 ephemeral
//!   response-correlation isn't wired — the cost being measured is
//!   build + sign, which IS what spec point "build envelope + sign"
//!   covers).
//! - `Durable` — `Edge::send_durable` over `OpaqueEvent` (the
//!   canonical durable Tier 2 path; produces one outbound row).
//! - `Federation` — `Edge::send_federation` with a 3-steward set
//!   (representative middle of the fan-out sweep; `steward_fanout`
//!   bench owns the size sweep).
//! - `Mandatory` — `Edge::send_mandatory` with a 3-peer directory
//!   (broadcast fan-out).

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

use async_trait::async_trait;
use ciris_edge::messages::{
    AnnouncementKind, AnnouncementPriority, AuthorityClass, FederationAnnouncement, OpaqueEvent,
    StewardDirective,
};
use ciris_edge::outbound::{PeerDirectory, StewardDirectory, StewardKey};
use ciris_edge::transport::Transport;
use ciris_edge::verify::HybridPolicy;
use ciris_edge::{Edge, EdgeConfig, OutboundHandle};
use ciris_persist::outbound::Error as PersistOutboundError;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use common::{
    bench_local_signer, build_in_memory_backend, signed_record, BenchFedKey, NullTransport,
};

/// Static peer directory — 3 peers for the Mandatory fan-out bench.
struct StaticPeerDirectory(Vec<String>);

#[async_trait]
impl PeerDirectory for StaticPeerDirectory {
    async fn list_recipients(&self) -> Result<Vec<String>, PersistOutboundError> {
        Ok(self.0.clone())
    }
}

/// Static steward directory — 3 stewards for the Federation fan-out.
struct StaticStewardDirectory(Vec<StewardKey>);

#[async_trait]
impl StewardDirectory for StaticStewardDirectory {
    async fn current_stewards(&self) -> Result<Vec<StewardKey>, PersistOutboundError> {
        Ok(self.0.clone())
    }
}

async fn build_edge() -> (Arc<Edge>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bootstrap = BenchFedKey::new("bootstrap", 0x01);
    let me = BenchFedKey::new("bench-self", 0xAA);
    let s1 = BenchFedKey::new("steward-1", 0xB1);
    let s2 = BenchFedKey::new("steward-2", 0xB2);
    let s3 = BenchFedKey::new("steward-3", 0xB3);
    let directory = build_in_memory_backend(vec![
        signed_record(&bootstrap, &bootstrap, "steward"),
        signed_record(&me, &bootstrap, "agent"),
        signed_record(&s1, &bootstrap, "steward"),
        signed_record(&s2, &bootstrap, "steward"),
        signed_record(&s3, &bootstrap, "steward"),
    ])
    .await;
    let signer = bench_local_signer(&me, &tmp).await;
    let config = EdgeConfig {
        hybrid_policy: HybridPolicy::Ed25519Fallback,
        ..EdgeConfig::default()
    };
    let stewards = vec![
        StewardKey {
            key_id: s1.key_id.clone(),
            identity_ref: s1.key_id.clone(),
        },
        StewardKey {
            key_id: s2.key_id.clone(),
            identity_ref: s2.key_id.clone(),
        },
        StewardKey {
            key_id: s3.key_id.clone(),
            identity_ref: s3.key_id.clone(),
        },
    ];
    let peers = vec![s1.key_id, s2.key_id, s3.key_id];
    let edge = Edge::builder()
        .directory(directory.clone() as Arc<dyn ciris_edge::verify::VerifyDirectory>)
        .queue(directory as Arc<dyn OutboundHandle>)
        .signer(signer)
        .transport(Arc::new(NullTransport) as Arc<dyn Transport>)
        .steward_directory(Arc::new(StaticStewardDirectory(stewards)))
        .peer_directory(Arc::new(StaticPeerDirectory(peers)))
        .config(config)
        .build()
        .expect("build edge");
    (Arc::new(edge), tmp)
}

fn bench_enqueue(c: &mut Criterion) {
    let setup_rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("setup tokio runtime");
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("bench tokio runtime");
    let (edge, _tmp) = setup_rt.block_on(build_edge());

    let mut group = c.benchmark_group("outbound_enqueue");
    group
        .sample_size(30)
        .measurement_time(Duration::from_secs(8));

    // ── Ephemeral: send returns EdgeError::Config (Phase 1
    //    request-response not wired); we measure build + sign +
    //    transport.send dispatch. Ignore the Err return (the bench
    //    measures the path, not the response). ──
    {
        let edge = edge.clone();
        group.bench_function("Ephemeral", |b| {
            let edge = edge.clone();
            b.to_async(&rt).iter(|| {
                let edge = edge.clone();
                async move {
                    let msg = ciris_edge::messages::ContentFetch {
                        sha256: [0u8; 32],
                        response_hint: None,
                    };
                    let r = edge.send(edge.signer_key_id(), msg).await;
                    black_box(r).ok();
                }
            });
        });
    }

    // ── Durable: enqueues one row. ──
    {
        let edge = edge.clone();
        group.bench_function("Durable", |b| {
            let edge = edge.clone();
            b.to_async(&rt).iter(|| {
                let edge = edge.clone();
                async move {
                    let msg = OpaqueEvent {
                        kind: 0x0000_0001,
                        payload: b"bench durable text".to_vec(),
                    };
                    let r = edge.send_durable(edge.signer_key_id(), msg).await;
                    black_box(r).ok();
                }
            });
        });
    }

    // ── Federation: 3 stewards × per-row enqueue. ──
    {
        let edge = edge.clone();
        group.bench_function("Federation_3stewards", |b| {
            let edge = edge.clone();
            b.to_async(&rt).iter(|| {
                let edge = edge.clone();
                async move {
                    let msg = StewardDirective {
                        title: "bench directive".into(),
                        body: "bench body".into(),
                    };
                    let r = edge.send_federation(msg, None).await;
                    black_box(r).ok();
                }
            });
        });
    }

    // ── Mandatory: 3 peers × per-row enqueue. ──
    {
        let edge = edge.clone();
        group.bench_function("Mandatory_3peers", |b| {
            let edge = edge.clone();
            b.to_async(&rt).iter(|| {
                let edge = edge.clone();
                async move {
                    let msg = FederationAnnouncement {
                        priority: AnnouncementPriority::Advisory,
                        kind: AnnouncementKind::PolicyUpdate,
                        title: "bench announcement".into(),
                        body: "bench body".into(),
                        authority_class: AuthorityClass::RootWa,
                        accord_payload: None,
                        supersedes: None,
                        expires_at: chrono::DateTime::parse_from_rfc3339("2027-01-01T00:00:00Z")
                            .unwrap()
                            .with_timezone(&chrono::Utc),
                        evidence_refs: vec![],
                        accord_signatures: vec![],
                    };
                    let r = edge.send_mandatory(msg).await;
                    black_box(r).ok();
                }
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_enqueue);
criterion_main!(benches);
