//! v0.18.0 (CIRISEdge#45) — `AgentMode` init-param acceptance gate.
//!
//! Pure Rust unit cover: the mode → knob mapping
//! ([`AgentMode::apply_defaults`]) is the only source of truth for the
//! translation, so this suite exercises the matrix directly without
//! standing up a Reticulum transport or a persist engine. The
//! cross-binding integration test (`PyEdge.init_edge_runtime(..., agent_mode="server")`)
//! lives downstream in the CIRISConformance v0.18.0 cohabitation gate.

use ciris_edge::{AgentMode, EdgeConfig};

#[test]
fn default_mode_is_proxy() {
    // Both the bare default and `EdgeConfig::default()`'s embedded
    // mode resolve to `AgentMode::Proxy` — preserves v0.17.x behavior
    // when callers omit the `agent_mode` kwarg.
    assert_eq!(AgentMode::default(), AgentMode::Proxy);
    let config = EdgeConfig::default();
    assert_eq!(config.agent_mode, AgentMode::Proxy);
}

#[test]
fn unknown_mode_string_returns_value_error() {
    // FFI surface decodes via `AgentMode::from_wire`; this is the
    // shared decoder both the PyO3 path (`init_edge_runtime`) and any
    // future UniFFI exposure consume. Unknown tokens yield `None` so
    // the FFI surface can translate to a typed ValueError /
    // InvalidArgument at the boundary.
    assert!(AgentMode::from_wire("Client").is_none());
    assert!(AgentMode::from_wire("PROXY").is_none());
    assert!(AgentMode::from_wire("bootstrap").is_none());
    assert!(AgentMode::from_wire("").is_none());
}

#[test]
fn wire_round_trip_canonical_tokens() {
    // The wire codec is total over the enum. `as_wire` produces a
    // snake_case token that `from_wire` decodes back to the same
    // variant. Locks the contract Agent-side `AgentMode` consumers
    // depend on.
    for mode in [AgentMode::Client, AgentMode::Proxy, AgentMode::Server] {
        let s = mode.as_wire();
        let decoded = AgentMode::from_wire(s).expect("round-trip decode");
        assert_eq!(decoded, mode, "{s:?} round-trip");
    }
}

#[test]
fn client_mode_does_not_bind_listener() {
    // Client posture is egress-only — the v0.18.0 contract.
    // Application of the mode flips `listener_bound` to false; the
    // outbound queue contracts to the minimal 256-row cap.
    let mut config = EdgeConfig::default();
    AgentMode::Client.apply_defaults(&mut config);
    assert_eq!(config.agent_mode, AgentMode::Client);
    assert!(
        !config.listener_bound,
        "client mode must NOT bind the listener",
    );
    assert_eq!(
        config.outbound_queue_max, 256,
        "client mode caps the outbound queue at 256",
    );
}

#[test]
fn proxy_mode_binds_listener_with_default_queue() {
    // Proxy is the v0.17.x default — listener bound, 4096-row queue.
    let mut config = EdgeConfig::default();
    AgentMode::Proxy.apply_defaults(&mut config);
    assert_eq!(config.agent_mode, AgentMode::Proxy);
    assert!(config.listener_bound, "proxy mode binds the listener");
    assert_eq!(
        config.outbound_queue_max, 4096,
        "proxy mode keeps the v0.17.x 4096-row default",
    );
}

#[test]
fn server_mode_binds_listener_with_large_queue() {
    // Server posture — bootstrap-node, large queue.
    let mut config = EdgeConfig::default();
    AgentMode::Server.apply_defaults(&mut config);
    assert_eq!(config.agent_mode, AgentMode::Server);
    assert!(config.listener_bound, "server mode binds the listener");
    assert_eq!(
        config.outbound_queue_max, 65536,
        "server mode widens the outbound queue to 65536",
    );
}

#[test]
fn apply_defaults_is_idempotent_per_mode() {
    // Operator may reconfigure a mode at runtime (future surface);
    // applying the same mode twice yields the same config — no
    // accumulating side-effects.
    let mut config = EdgeConfig::default();
    AgentMode::Server.apply_defaults(&mut config);
    let queue_after_first = config.outbound_queue_max;
    let bound_after_first = config.listener_bound;
    AgentMode::Server.apply_defaults(&mut config);
    assert_eq!(config.outbound_queue_max, queue_after_first);
    assert_eq!(config.listener_bound, bound_after_first);
}
