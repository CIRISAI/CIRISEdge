//! **CIRISEdge#971 — a route older than the one held is fetched once, not
//! every round.**
//!
//! Over a real sqlite directory and the real bridge, B holds N's route at
//! epoch 2 and is offered N's route at epoch 1:
//!
//! - **r1** — the old hash is wanted (B does not hold those bytes), is
//!   delivered, and the apply reports `Duplicate` (the stale arm) and marks it;
//! - **r2** — the old hash is NOT wanted: the mark survives the `Duplicate`
//!   that `remember_outcome` clears the refusal memory on, and a second
//!   delivery of the same bytes keeps it;
//! - **r3** — N's route at epoch 3 is a different hash, is wanted, and is
//!   admitted: the mark is per hash, never per record.
//!
//! `cargo test --lib stale_route_971`

use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;

use super::park_fresh_858_tests::{hold, substrate, Ident};
use super::summary::ApplyOutcome;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

async fn route_at(
    node: &Ident,
    epoch: u64,
) -> ciris_persist::federation::self_at_login::SignedTransportDestination {
    use base64::Engine as _;
    use ciris_persist::federation::self_at_login::{
        BindingProvenance, SignedTransportDestination, TransportDestination,
    };
    let b64 = base64::engine::general_purpose::STANDARD;
    let row = TransportDestination {
        occurrence_key_id: node.key_id().to_owned(),
        transport_kind: "reticulum".to_owned(),
        destination: format!("{:02x}", 0xa0 + epoch).repeat(16),
        asserted_at: chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
            chrono::Utc::now().timestamp_millis(),
        )
        .expect("millis"),
        last_seen_at: None,
        transport_ed25519_pubkey_base64: Some(b64.encode([0xbb; 32])),
        transport_x25519_pubkey_base64: Some(b64.encode([0xcc; 32])),
        binding_provenance: BindingProvenance::Rooted,
        epoch,
        retired_at: None,
    };
    let envelope = serde_json::to_value(&row).expect("route");
    let canonical = ciris_verify_core::jcs::canonicalize(&envelope).expect("jcs");
    let (ed, pqc) = crate::identity::sign_bound_hybrid(&node.signer(), &canonical, "route")
        .await
        .expect("sign");
    SignedTransportDestination {
        attesting_key_id: node.key_id().to_owned(),
        transport_destination: row,
        signed_envelope: envelope,
        signature: ciris_verify_core::transport_binding::TransportBindingSignature {
            ed25519_signature_base64: ed,
            mldsa65_signature_base64: pqc,
        },
    }
}

fn wire(
    route: &ciris_persist::federation::self_at_login::SignedTransportDestination,
) -> (Vec<u8>, EnvelopeRef) {
    use sha2::{Digest as _, Sha256};
    let bytes = serde_json::to_vec(route).expect("wire");
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    (
        bytes,
        EnvelopeRef {
            envelope_hash: hash,
            seq: 0,
        },
    )
}

/// The `want` a round computes: the diff, minus what the refusal memories
/// suppress (exactly `Session::on_summary`'s two steps).
async fn want(
    bridge: &FederationDirectoryReplicationBridge,
    offered: &[EnvelopeRef],
) -> Vec<[u8; 32]> {
    let mut want = bridge
        .holdings_want(EnvelopeKind::TransportDestination, offered)
        .await;
    want.retain(|h| !bridge.retry_suppressed(EnvelopeKind::TransportDestination, h));
    want
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stale_route_is_fetched_once_not_every_round_971() {
    let n = Ident::mint("node-n-stale971", "node", 0xd1).await;
    let dir = substrate().await;
    hold(&dir, &n).await;
    let e1 = route_at(&n, 1).await;
    let e2 = route_at(&n, 2).await;
    dir.put_signed_transport_destination(&e2)
        .await
        .expect("B holds N's route at epoch 2");
    let bridge = Arc::new(FederationDirectoryReplicationBridge::with_config(
        Arc::clone(&dir) as Arc<dyn FederationDirectory>,
        Arc::new(Vec::new),
        BridgeConfig::default(),
    ));
    let (old_bytes, old_ref) = wire(&e1);

    // r1 — wanted, delivered, stale.
    assert_eq!(
        want(&bridge, std::slice::from_ref(&old_ref)).await,
        vec![old_ref.envelope_hash],
        "r1: B does not hold the old bytes"
    );
    let r1 = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &old_bytes, None)
        .await;
    assert_eq!(r1, ApplyOutcome::Duplicate, "r1: the stale arm");

    // r2 — not wanted, and a second delivery keeps the mark.
    assert!(
        want(&bridge, std::slice::from_ref(&old_ref))
            .await
            .is_empty(),
        "r2: the mark survived the Duplicate's remember_outcome"
    );
    let again = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &old_bytes, None)
        .await;
    assert_eq!(again, ApplyOutcome::Duplicate);
    assert!(
        want(&bridge, std::slice::from_ref(&old_ref))
            .await
            .is_empty(),
        "r2: still marked after the bytes were pushed again"
    );

    // r3 — a newer route is a new hash: wanted and admitted.
    let e3 = route_at(&n, 3).await;
    let (new_bytes, new_ref) = wire(&e3);
    assert_eq!(
        want(&bridge, &[old_ref.clone(), new_ref.clone()]).await,
        vec![new_ref.envelope_hash],
        "r3: only the newer route is wanted"
    );
    let r3 = bridge
        .apply_envelope_bytes(EnvelopeKind::TransportDestination, &new_bytes, None)
        .await;
    assert!(r3.is_admitted(), "r3: admitted, got {r3:?}");
    assert!(
        want(&bridge, &[old_ref, new_ref]).await.is_empty(),
        "r3: the new route is held (write-through) and the old one stays marked"
    );
}
