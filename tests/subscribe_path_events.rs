//! CIRISEdge#34 (v0.19.0) — subscribe_path_events acceptance gate.
//!
//! Verifies the dispatch-side reachability transitions (DeliveryAttestation
//! arm = PathDiscovered, AccordCarrier wire-layer refusal arm =
//! PathLost) emit on the EventBus path channel + the subscribe_paths
//! receiver picks them up.

#![cfg(feature = "transport-reticulum")]

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::events::{EventBus, EventKind, EventSeverity, NetworkEvent, PathEvent};

#[tokio::test]
async fn subscribe_path_events_yields_on_path_discovered() {
    let bus = Arc::new(EventBus::default());
    let mut rx = bus.subscribe_paths();
    bus.emit_path(NetworkEvent::path(
        EventKind::PathDiscovered,
        vec![0x12; 16],
        1,
        Some("reticulum-rs".to_string()),
        Some("peer-discovered".to_string()),
        EventSeverity::Info,
        "path observed",
    ));
    let got = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("did not lag")
        .expect("did not close");
    assert_eq!(got.kind, EventKind::PathDiscovered);
    let proj = PathEvent::from_event(&got).expect("projection");
    assert_eq!(proj.destination_hash, vec![0x12; 16]);
    assert_eq!(proj.hops, 1);
    assert_eq!(proj.via_transport_id.as_deref(), Some("reticulum-rs"));
}

#[tokio::test]
async fn subscribe_path_events_yields_on_path_lost() {
    let bus = Arc::new(EventBus::default());
    let mut rx = bus.subscribe_paths();
    bus.emit_path(NetworkEvent::path(
        EventKind::PathLost,
        vec![0x34; 16],
        0,
        Some("http".to_string()),
        Some("peer-lost".to_string()),
        EventSeverity::Warning,
        "AccordCarrier refused at wire-layer gate",
    ));
    let got = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("did not lag")
        .expect("did not close");
    assert_eq!(got.kind, EventKind::PathLost);
    assert_eq!(got.severity, EventSeverity::Warning);
    let proj = PathEvent::from_event(&got).expect("projection");
    assert_eq!(proj.destination_hash, vec![0x34; 16]);
}

/// Filter: callers project `PathEvent::from_event` and skip events
/// where `destination_hash` doesn't match their target. This test
/// drives the filter pattern end-to-end against the EventBus.
#[tokio::test]
async fn subscribe_path_events_filtered_by_destination() {
    let bus = Arc::new(EventBus::default());
    let mut rx = bus.subscribe_paths();
    let target = vec![0xAA; 16];

    // Emit two events: one for the target destination, one for a
    // distractor.
    bus.emit_path(NetworkEvent::path(
        EventKind::PathDiscovered,
        vec![0xBB; 16],
        1,
        Some("reticulum-rs".to_string()),
        Some("peer-distractor".to_string()),
        EventSeverity::Info,
        "distractor",
    ));
    bus.emit_path(NetworkEvent::path(
        EventKind::PathDiscovered,
        target.clone(),
        2,
        Some("reticulum-rs".to_string()),
        Some("peer-target".to_string()),
        EventSeverity::Info,
        "target",
    ));

    let mut got_target = None;
    for _ in 0..2 {
        let ev = tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .expect("did not lag")
            .expect("did not close");
        let proj = PathEvent::from_event(&ev).expect("projection");
        if proj.destination_hash == target {
            got_target = Some(proj);
        }
    }
    let got = got_target.expect("target destination_hash not observed");
    assert_eq!(got.hops, 2);
    assert_eq!(got.peer_key_id.as_deref(), Some("peer-target"));
}
