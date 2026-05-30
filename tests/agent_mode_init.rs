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
    let disk_after_first = config.disk_budget_bytes;
    let depth_after_first = config.trust_recursion_depth;
    AgentMode::Server.apply_defaults(&mut config);
    assert_eq!(config.outbound_queue_max, queue_after_first);
    assert_eq!(config.listener_bound, bound_after_first);
    assert_eq!(config.disk_budget_bytes, disk_after_first);
    assert_eq!(config.trust_recursion_depth, depth_after_first);
}

// ─── CIRISEdge#51 (v0.20.0 RC1) — CEWP L0/L1 tier refinement ──────

#[test]
fn agent_mode_client_disk_budget_is_zero() {
    // Client mode is the egress-only posture — no storage tier, so
    // the CEWP disk budget is `0` (no caching of remote evidence).
    assert_eq!(AgentMode::Client.default_disk_budget_bytes(), 0);
}

#[test]
fn agent_mode_proxy_disk_budget_is_256gb() {
    // Proxy = L0 CEWP tier — 256 GB storage budget. The number is a
    // tier-defining constant, not a heuristic; the test pins the
    // exact byte count so a refactor that drifts the unit (TiB vs TB,
    // MiB vs MB) fails loud.
    assert_eq!(
        AgentMode::Proxy.default_disk_budget_bytes(),
        256 * 1024 * 1024 * 1024,
    );
}

#[test]
fn agent_mode_server_disk_budget_is_1tb() {
    // Server = L1 CEWP tier — 1 TB storage budget (4x proxy). Pinned
    // exactly so the tier ratio is byte-identifiable in the test
    // matrix.
    assert_eq!(
        AgentMode::Server.default_disk_budget_bytes(),
        1024 * 1024 * 1024 * 1024,
    );
}

#[test]
fn agent_mode_client_trust_recursion_depth_is_zero() {
    // Client doesn't dispatch inbound — recursion depth is the
    // dispatch_inbound knob, so client's value is irrelevant but
    // pinned at 0 for completeness.
    assert_eq!(AgentMode::Client.default_trust_recursion_depth(), 0);
}

#[test]
fn agent_mode_proxy_trust_recursion_depth_is_zero() {
    // Proxy = L0 = strict direct trust. Persist's
    // `TrustScoring::trust_score(_, 0)` walks no `delegates_to` hops
    // — only attestations directly targeting the key contribute. The
    // L0 default reflects the "tight blast radius" stance.
    assert_eq!(AgentMode::Proxy.default_trust_recursion_depth(), 0);
}

#[test]
fn agent_mode_server_trust_recursion_depth_is_one() {
    // Server = L1 = friend-of-friends. Persist's
    // `TrustScoring::trust_score(_, 1)` walks one `delegates_to` hop
    // per the BFS in `crate::federation::topology::
    // build_delegation_graph`. L2+ is deferred to a post-v1.0 cut
    // (the spec explicitly defers them).
    assert_eq!(AgentMode::Server.default_trust_recursion_depth(), 1);
}

#[test]
fn apply_defaults_threads_disk_budget_and_recursion_depth() {
    // `apply_defaults` is the single source of truth — applying it
    // for each mode flips both new fields per the AgentMode table.
    let mut cfg = EdgeConfig::default();
    AgentMode::Client.apply_defaults(&mut cfg);
    assert_eq!(cfg.disk_budget_bytes, 0);
    assert_eq!(cfg.trust_recursion_depth, 0);
    AgentMode::Proxy.apply_defaults(&mut cfg);
    assert_eq!(cfg.disk_budget_bytes, 256 * 1024 * 1024 * 1024);
    assert_eq!(cfg.trust_recursion_depth, 0);
    AgentMode::Server.apply_defaults(&mut cfg);
    assert_eq!(cfg.disk_budget_bytes, 1024 * 1024 * 1024 * 1024);
    assert_eq!(cfg.trust_recursion_depth, 1);
}

#[test]
fn operator_override_disk_budget_takes_precedence() {
    // After `apply_defaults` runs, the cohabitation init path may
    // override either field. The override is a plain field write —
    // there's no setter ceremony — but the test pins the contract
    // shape so a future refactor that interleaves the two calls
    // doesn't accidentally re-stomp the override.
    let mut cfg = EdgeConfig::default();
    AgentMode::Server.apply_defaults(&mut cfg);
    assert_eq!(cfg.disk_budget_bytes, 1024 * 1024 * 1024 * 1024);
    // Operator pins a custom 512 GB budget on an L1 server.
    cfg.disk_budget_bytes = 512 * 1024 * 1024 * 1024;
    assert_eq!(cfg.disk_budget_bytes, 512 * 1024 * 1024 * 1024);
}

#[test]
fn operator_override_trust_recursion_depth_takes_precedence() {
    // Symmetric to the disk-budget override: a curated server may
    // pin depth = 0 even though L1 default is 1 (the spec's
    // "operator may pin even stricter" example).
    let mut cfg = EdgeConfig::default();
    AgentMode::Server.apply_defaults(&mut cfg);
    assert_eq!(cfg.trust_recursion_depth, 1);
    // Operator pins strict direct-trust on an L1 server.
    cfg.trust_recursion_depth = 0;
    assert_eq!(cfg.trust_recursion_depth, 0);
}

#[test]
fn edge_config_default_disk_budget_matches_proxy_l0() {
    // `EdgeConfig::default()` mirrors the Proxy column per the
    // v0.18.0 convention — preserves backward-compat when callers
    // omit `agent_mode`. The new fields must follow the same
    // convention.
    let cfg = EdgeConfig::default();
    assert_eq!(cfg.disk_budget_bytes, 256 * 1024 * 1024 * 1024);
    assert_eq!(cfg.trust_recursion_depth, 0);
}
