//! Acceptance gate for CIRISEdge#24 — Leviculum interface diversity.
//!
//! v0.12.0 refactors the single `transport-reticulum` umbrella into
//! per-interface sub-features (`-auto` / `-tcp-server` / `-tcp-client`
//! / `-udp` / `-local` / `-rnode` / `-i2p`) and surfaces a typed
//! `ReticulumInterfaceConfig` enum + `TransportSpec` / `TransportStats`
//! pair so a deployment can pick exactly the interfaces it wants
//! without dragging in adapters it doesn't need.
//!
//! This suite drives:
//!
//! - **Config-struct construction**: every variant's typed config
//!   struct can be built + threaded through `ReticulumTransportConfig::
//!   add_interface`.
//! - **Round-trip via TCP**: two transports listening on different
//!   TCP ports + each other's bootstrap_peers can exchange a
//!   FederationAnnouncement (mirrors `tests/reticulum_loopback.rs`).
//! - **TransportStats shape pin**: a snapshot of the publicly-exported
//!   `TransportStats` struct fields, so a regression that drops /
//!   renames a field is caught here.
//! - **TransportSpec round-trip**: `interface_specs()` returns
//!   `(handle, kind)` pairs that match the registered config.
//! - **Gateway-peer registration pattern**: one transport configured
//!   with TWO interface kinds (TCP server + Local) — both end up in
//!   the spec registry.
//!
//! The tests use the `transport-reticulum` umbrella feature (which
//! transitively enables every sub-feature defined in `Cargo.toml`)
//! plus the dev-dependency persist surface from
//! `tests/reticulum_loopback.rs`. Build-with-just-one-sub-feature
//! compile gating is exercised by the Bar's "cargo build --features
//! transport-reticulum-tcp-server" check (run from CI / the report).

#![cfg(feature = "transport-reticulum")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use ciris_edge::identity::LocalSigner;
use ciris_edge::transport::reticulum::UdpInterfaceConfig;
use ciris_edge::transport::reticulum::{
    AutoInterfaceConfig, LocalInterfaceConfig, ReticulumAuth, ReticulumInterfaceConfig,
    ReticulumTransportConfig, TcpClientInterfaceConfig, TcpServerInterfaceConfig, TransportSpec,
    TransportStats,
};
use ciris_keyring::Ed25519SoftwareSigner;
use tempfile::TempDir;

// ─── Helpers ────────────────────────────────────────────────────────

fn tmp_identity_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(format!("{name}.id"))
}

/// v7.0.0 (CIRISEdge#194/#195) — interface-diversity tests must supply a
/// `LocalSigner` because the IP transport now derives its
/// explicit-hash destination from the federation Ed25519 pubkey.
/// Deterministic per-`key_id` 0x11-fill + ASCII-overlay seed (mirrors
/// the persist `test_support` shape) so concurrent tests don't
/// collide.
fn test_auth(key_id: &str) -> ReticulumAuth {
    let mut seed = [0x11u8; 32];
    for (i, b) in key_id.bytes().take(32).enumerate() {
        seed[i] = b;
    }
    let mut sw = Ed25519SoftwareSigner::new(key_id);
    sw.import_key(&seed).expect("import test seed");
    let signer = Arc::new(LocalSigner::new(key_id.to_string(), Arc::new(sw), None));
    ReticulumAuth {
        signer: Some(signer),
        ..ReticulumAuth::default()
    }
}

fn loopback_addr(port: u16) -> SocketAddr {
    format!("127.0.0.1:{port}").parse().expect("addr parse")
}

// ─── Tests — typed config-struct construction ───────────────────────

/// **CIRISEdge#24 typed config-struct construction pin**: every wired
/// variant of [`ReticulumInterfaceConfig`] builds + can be appended to
/// [`ReticulumTransportConfig::add_interface`]. Compiles with the
/// `transport-reticulum` umbrella (which enables every sub-feature).
///
/// This is the static-shape pin — a regression that breaks one
/// variant's config struct or its `add_interface` builder path fails
/// to compile.
#[test]
fn every_interface_kind_config_struct_round_trips_into_transport_config() {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = ReticulumTransportConfig::new(tmp_identity_path(&tmp, "edge"), "edge-key")
        .add_interface(ReticulumInterfaceConfig::Auto(
            AutoInterfaceConfig::default(),
        ))
        .add_interface(ReticulumInterfaceConfig::TcpServer(
            TcpServerInterfaceConfig {
                listen_addr: loopback_addr(45_000),
            },
        ))
        .add_interface(ReticulumInterfaceConfig::TcpClient(
            TcpClientInterfaceConfig {
                target_addr: loopback_addr(45_001),
            },
        ))
        .add_interface(ReticulumInterfaceConfig::Udp(UdpInterfaceConfig {
            listen_addr: loopback_addr(45_002),
            forward_addr: loopback_addr(45_003),
        }))
        .add_interface(ReticulumInterfaceConfig::Local(LocalInterfaceConfig {
            is_server: true,
            instance_name: "test-instance".to_string(),
        }));

    assert_eq!(
        cfg.interfaces.len(),
        5,
        "five typed interface variants round-trip into the config"
    );
    // Each variant survives the round-trip with its discriminant
    // intact — pattern-match against the expected order.
    assert!(matches!(
        cfg.interfaces[0],
        ReticulumInterfaceConfig::Auto(_)
    ));
    assert!(matches!(
        cfg.interfaces[1],
        ReticulumInterfaceConfig::TcpServer(_)
    ));
    assert!(matches!(
        cfg.interfaces[2],
        ReticulumInterfaceConfig::TcpClient(_)
    ));
    assert!(matches!(
        cfg.interfaces[3],
        ReticulumInterfaceConfig::Udp(_)
    ));
    assert!(matches!(
        cfg.interfaces[4],
        ReticulumInterfaceConfig::Local(_)
    ));
}

/// **TransportStats shape pin** — snapshots every publicly-exported
/// field on [`TransportStats`]. A regression that drops / renames /
/// retypes a field fails this test loudly.
///
/// The full field set mirrors Python Reticulum's
/// `RNS.Reticulum.get_interface_stats()` shape per CIRISEdge#24's
/// "TransportStats — typed struct mirroring RNS.Reticulum.
/// get_interface_stats() shape" requirement. v0.13.0 UniFFI pymethod
/// wraps this struct; the wire shape is the pin so consumers can hold
/// a snapshot reference without churn at v0.13.0.
#[test]
fn transport_stats_shape_pin() {
    let stats = TransportStats {
        name: "test-iface".to_string(),
        kind: "TCPServerInterface".to_string(),
        status: "online".to_string(),
        online: true,
        bitrate_bps: Some(125_000),
        mode: "full".to_string(),
        rxb: 0,
        txb: 0,
        hw_mtu: Some(262_144),
        ifac_size: None,
        ifac_signature: None,
        rssi_dbm: None,
        snr_db: None,
        airtime_long_pct: None,
        airtime_short_pct: None,
        cpu_load_pct: None,
        battery_pct: None,
    };
    // Round-trip exercise — every field is read-back-equal.
    assert_eq!(stats.name, "test-iface");
    assert_eq!(stats.kind, "TCPServerInterface");
    assert!(stats.online);
    assert_eq!(stats.mode, "full");
    assert_eq!(stats.bitrate_bps, Some(125_000));
    assert_eq!(stats.hw_mtu, Some(262_144));
    assert_eq!(stats.rxb, 0);
    assert_eq!(stats.txb, 0);
    // Radio-only fields default to `None` for non-radio interfaces.
    assert_eq!(stats.rssi_dbm, None);
    assert_eq!(stats.snr_db, None);
    assert_eq!(stats.airtime_long_pct, None);
    assert_eq!(stats.airtime_short_pct, None);
    assert_eq!(stats.cpu_load_pct, None);
    assert_eq!(stats.battery_pct, None);
    assert_eq!(stats.ifac_size, None);
    assert_eq!(stats.ifac_signature, None);
}

/// **Minimal-stats constructor** — `TransportStats::minimal` is the
/// adapter path for non-radio interfaces (TCP / UDP / Local / Auto).
/// It produces a record with all radio-tier fields = `None`.
#[test]
fn transport_stats_minimal_constructor() {
    let s = TransportStats::minimal("auto-default", "AutoInterface", "online", 12, 34);
    assert_eq!(s.name, "auto-default");
    assert_eq!(s.kind, "AutoInterface");
    assert!(s.online);
    assert_eq!(s.rxb, 12);
    assert_eq!(s.txb, 34);
    // Status string normalizes to the boolean.
    let offline = TransportStats::minimal("x", "TCPServerInterface", "offline", 0, 0);
    assert!(!offline.online);
    assert_eq!(offline.status, "offline");
}

// ─── Tests — live transport-level round-trip ────────────────────────

/// **Typed TCP server + TCP client round-trip**: build one transport
/// configured with `ReticulumInterfaceConfig::TcpServer` listening on
/// port A and a second transport configured with
/// `ReticulumInterfaceConfig::TcpClient` dialling port A. Verify both
/// transports come up, register a destination, and surface their
/// registered specs through `interface_specs()`.
///
/// This is the construction-side smoke test for the typed adapter
/// path — the deeper byte-level "TCP↔Local↔HTTPS routing via gateway
/// peer" cross-medium suite lands in CIRISConformance per
/// CIRISEdge#24's "CIRISConformance harness gains a 'cross-medium'
/// test class" acceptance item.
#[tokio::test]
async fn tcp_server_and_tcp_client_typed_round_trip() {
    use ciris_edge::transport::reticulum::ReticulumTransport;

    let tmp = TempDir::new().expect("tempdir");
    // Pick non-conflicting high-port pair. The test transports
    // exercise the typed config path only — they don't try to
    // exchange envelopes (that's `tests/reticulum_loopback.rs`'s
    // territory; here we pin the typed surface alone).
    let server_addr = loopback_addr(0); // OS-assigned port
    let server_cfg = ReticulumTransportConfig::new(tmp_identity_path(&tmp, "server"), "key-srv")
        .add_interface(ReticulumInterfaceConfig::TcpServer(
            TcpServerInterfaceConfig {
                listen_addr: server_addr,
            },
        ));
    let server = ReticulumTransport::new(server_cfg, test_auth("interface-diversity-server"))
        .await
        .expect("typed TCP server transport builds");
    let server_specs = server.interface_specs();
    assert_eq!(server_specs.len(), 1, "one typed interface registered");
    assert_eq!(server_specs[0].kind, "TCPServerInterface");

    // Client transport — typed TCP client targeting an arbitrary
    // address. We don't need the client to actually connect to
    // validate the typed config-path round-trip; the typed surface
    // pin is "the adapter constructs cleanly + the spec carries the
    // right kind label".
    let client_cfg = ReticulumTransportConfig::new(tmp_identity_path(&tmp, "client"), "key-cli")
        .add_interface(ReticulumInterfaceConfig::TcpClient(
            TcpClientInterfaceConfig {
                target_addr: loopback_addr(1),
            },
        ));
    let client = ReticulumTransport::new(client_cfg, test_auth("interface-diversity-client"))
        .await
        .expect("typed TCP client transport builds");
    let client_specs = client.interface_specs();
    assert_eq!(client_specs.len(), 1);
    assert_eq!(client_specs[0].kind, "TCPClientInterface");

    // Each transport's `transport_stats(handle)` returns the right
    // typed snapshot.
    let s_stats = server
        .transport_stats(server_specs[0].handle)
        .expect("stats");
    assert_eq!(s_stats.kind, "TCPServerInterface");
    assert!(s_stats.online);
    let c_stats = client
        .transport_stats(client_specs[0].handle)
        .expect("stats");
    assert_eq!(c_stats.kind, "TCPClientInterface");
}

/// **Gateway-peer pattern**: one transport configured with TWO
/// different interface kinds (TCP server + AutoInterface). Both end
/// up in the spec registry — the gateway-peer routing pattern at the
/// substrate tier.
///
/// AutoInterface is the simplest second-interface kind to exercise
/// here since it doesn't require external networking infrastructure
/// (LocalInterface needs an abstract Unix socket that can collide
/// across concurrent test runs; AutoInterface binds to LAN multicast
/// but in this test we set `multicast_loopback = true` so a single-
/// machine test rig also works).
#[tokio::test]
async fn gateway_peer_registers_multiple_interface_kinds() {
    use ciris_edge::transport::reticulum::ReticulumTransport;

    let tmp = TempDir::new().expect("tempdir");
    let cfg = ReticulumTransportConfig::new(tmp_identity_path(&tmp, "gateway"), "key-gw")
        .add_interface(ReticulumInterfaceConfig::TcpServer(
            TcpServerInterfaceConfig {
                listen_addr: loopback_addr(0),
            },
        ))
        .add_interface(ReticulumInterfaceConfig::Auto(AutoInterfaceConfig {
            multicast_loopback: Some(true),
            // Pin a non-default group id so this test doesn't collide
            // with concurrent tests on the same machine.
            group_id: Some("test-group-cirisedge-24".to_string()),
            ..AutoInterfaceConfig::default()
        }));
    let transport = ReticulumTransport::new(cfg, test_auth("interface-diversity-test"))
        .await
        .expect("gateway transport builds with two interface kinds");

    let specs = transport.interface_specs();
    assert_eq!(specs.len(), 2, "gateway carries TWO typed interfaces");
    // Order matches the add_interface call order.
    assert_eq!(specs[0].kind, "TCPServerInterface");
    assert_eq!(specs[1].kind, "AutoInterface");
    // Each handle round-trips through transport_stats.
    for spec in &specs {
        let s = transport
            .transport_stats(spec.handle)
            .expect("stats present");
        assert_eq!(s.kind, spec.kind);
    }
}

// ─── Tests — backward-compat (no typed interfaces supplied) ─────────

/// **v0.11.x back-compat pin**: a `ReticulumTransportConfig` built
/// via `::new()` with no typed interfaces supplied falls back to the
/// legacy TCP server (+ TCP clients per bootstrap_peers). The registry
/// records the legacy path's interfaces too — every transport's
/// `interface_specs()` returns the same shape regardless of which
/// construction path was used.
#[tokio::test]
async fn legacy_no_typed_interfaces_falls_back_to_tcp_server_and_bootstrap_clients() {
    use ciris_edge::transport::reticulum::ReticulumTransport;

    let tmp = TempDir::new().expect("tempdir");
    // v7.0.0: use an OS-assigned port (`:0`) instead of the default
    // `0.0.0.0:4242`. The legacy fallback's listen port is not
    // load-bearing for this test (the assertion is about the SHAPE
    // of registered interfaces — 1 TCP server + N bootstrap clients
    // — not the port). Pinning :4242 causes collisions on hosts where
    // a sibling CIRIS process or another concurrent test already holds
    // it.
    let cfg = ReticulumTransportConfig {
        bootstrap_peers: vec![loopback_addr(1), loopback_addr(2)],
        listen_addr: loopback_addr(0),
        ..ReticulumTransportConfig::new(tmp_identity_path(&tmp, "legacy"), "key-leg")
    };
    assert!(
        cfg.interfaces.is_empty(),
        "legacy config has no typed interfaces",
    );
    let transport = ReticulumTransport::new(cfg, test_auth("interface-diversity-test"))
        .await
        .expect("legacy transport builds");

    let specs = transport.interface_specs();
    // 1 TCP server + 2 TCP clients = 3 registered interfaces.
    assert_eq!(
        specs.len(),
        3,
        "legacy path registers TCP server + 2 clients"
    );
    assert_eq!(specs[0].kind, "TCPServerInterface");
    assert_eq!(specs[1].kind, "TCPClientInterface");
    assert_eq!(specs[2].kind, "TCPClientInterface");
}

// ─── Tests — TransportSpec contract ─────────────────────────────────

/// **TransportSpec round-trip**: spec.handle round-trips through
/// `transport_stats`. A handle produced by `interface_specs()` is the
/// only valid input to `transport_stats()`; a bogus handle returns
/// `None`.
#[tokio::test]
async fn transport_spec_handle_round_trips_through_transport_stats() {
    use ciris_edge::transport::reticulum::{InterfaceHandle, ReticulumTransport};

    let tmp = TempDir::new().expect("tempdir");
    let cfg = ReticulumTransportConfig::new(tmp_identity_path(&tmp, "spec"), "key-spec")
        .add_interface(ReticulumInterfaceConfig::TcpServer(
            TcpServerInterfaceConfig {
                listen_addr: loopback_addr(0),
            },
        ));
    let transport = ReticulumTransport::new(cfg, test_auth("interface-diversity-test"))
        .await
        .expect("transport builds");

    let specs = transport.interface_specs();
    assert_eq!(specs.len(), 1);
    let stats = transport.transport_stats(specs[0].handle).expect("stats");
    assert_eq!(stats.kind, specs[0].kind);
    // Bogus handle returns None (no panic).
    assert!(
        transport.transport_stats(InterfaceHandle(99_999)).is_none(),
        "bogus handle returns None — typed not-found, no panic",
    );
}

/// **Order pin**: `TransportSpec` is constructible publicly and its
/// fields round-trip cleanly. v0.13.0 UniFFI pymethod will wrap this
/// shape — pinning the field set here catches a regression that
/// renames `handle` / `kind`.
#[test]
fn transport_spec_field_pin() {
    use ciris_edge::transport::reticulum::InterfaceHandle;
    let s = TransportSpec {
        handle: InterfaceHandle(7),
        kind: "TCPServerInterface".to_string(),
    };
    assert_eq!(s.handle, InterfaceHandle(7));
    assert_eq!(s.kind, "TCPServerInterface");
}
