//! **A destination claimed by thousands of keys costs a standing check little.**
//!
//! Production held 3,281 live routes on one reticulum destination, all from
//! keys it held no record of. `binding_stands` read the destination folded, and
//! the fold asks for an owner per pair of claimants: one check never finished,
//! and the sweep repeated it for as long as the node ran. Anyone can mint that
//! shape.
//!
//! Its own binary: the read counter is process-wide.
//!
//! `cargo test --test standing_fold_cost_v44 --features transport-reticulum`

#![cfg(feature = "transport-reticulum")]

use base64::Engine as _;
use ciris_edge::verify::{LiveTransportBinding, RootingDirectory};
use ciris_persist::federation::self_at_login::{BindingProvenance, TransportDestination};
use ciris_persist::federation::FederationDirectory;
use ciris_persist::prelude::Backend;
use ciris_persist::store::sqlite::SqliteBackend;

const CLAIMANTS: i64 = 200;

fn door_reads() -> u64 {
    ciris_persist::observe::snapshot()
        .reads
        .iter()
        .filter(|d| d.door == "attestation_query")
        .map(|d| d.reads)
        .sum()
}

fn claim(key: String, destination: &str, age: i64) -> TransportDestination {
    let b64 = base64::engine::general_purpose::STANDARD;
    let at = chrono::Utc::now().timestamp_millis() - age;
    TransportDestination {
        occurrence_key_id: key,
        transport_kind: "reticulum".to_owned(),
        destination: destination.to_owned(),
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(at).expect("millis"),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(b64.encode([0xbb; 32])),
        transport_x25519_pubkey_base64: Some(b64.encode([0xcc; 32])),
        binding_provenance: BindingProvenance::Advisory,
        epoch: 1,
        retired_at: None,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_crowded_destination_costs_one_key_reads_per_claimant_at_most() {
    let dir = SqliteBackend::open(":memory:").await.expect("open");
    dir.run_migrations().await.expect("migrate");
    let dest_hash = [0xa1; 16];
    let destination = hex::encode(dest_hash);
    for i in 0..CLAIMANTS {
        let route = claim(format!("bench-{i}"), &destination, 1_000 * (CLAIMANTS - i));
        FederationDirectory::put_transport_destination(&dir, &route)
            .await
            .expect("the route lands");
    }
    let row = LiveTransportBinding {
        key_id: "bench-0".to_owned(),
        dest_hash,
        transport_pubkey64: [0x33; 64],
        provenance: BindingProvenance::Advisory,
    };

    let before = door_reads();
    let stands = RootingDirectory::binding_stands(&dir, &row).await;
    let reads = door_reads() - before;

    assert!(stands, "no claimant shares an owner with it");
    let bound = 3 * u64::try_from(CLAIMANTS).expect("positive");
    assert!(
        reads <= bound,
        "one standing check read {reads} times, past {bound}: it is folding the destination"
    );
}
