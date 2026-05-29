//! UniFFI-side type definitions — the Rust structs / enums the
//! UDL declares.
//!
//! # v0.13.0 (CIRISEdge#36 GO)
//!
//! UniFFI's UDL-mode discipline: the `#[udl_derive(Enum|Record|Error)]`
//! attribute macros emit ONLY the `FfiConverter` impls; the underlying
//! type definitions must be hand-written in Rust to match the UDL
//! shape. The Askama-generated `ciris_edge.uniffi.rs` references each
//! type by bare name at the crate root, so this module's `pub use`
//! re-exports at `lib.rs` complete the surface.
//!
//! Names match the UDL one-to-one. Field types match the UDL `type_rs`
//! mapping (string → String, sequence<T> → Vec<T>, record<K,V> →
//! HashMap<K,V>, T? → Option<T>, bytes → Vec<u8>).

use std::collections::HashMap;

// ─── Error ──────────────────────────────────────────────────────────
//
// `[Error] enum EdgeBindingsError { "NotInitialized", ... }` flat-error
// shape. UniFFI's `flat_error` mode requires the rust enum implement
// `Display`; `thiserror::Error` covers that AND the `Error` blanket.

#[derive(Debug, thiserror::Error)]
pub enum EdgeBindingsError {
    #[error("edge runtime not initialized (call init_edge_runtime first)")]
    NotInitialized,
    #[error("not implemented")]
    NotImplemented,
    #[error("not found")]
    NotFound,
    #[error("invalid argument")]
    InvalidArgument,
    #[error("internal error")]
    Internal,
    #[error("unsupported")]
    Unsupported,
    #[error("persist error")]
    Persist,
    #[error("transport error")]
    Transport,
}

// ─── Peer mgmt types (#26) ──────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum EdgePeerTrust {
    Trusted,
    Untrusted,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct EdgePeerHandle {
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct EdgePeerPolicy {
    pub subscription_filter: Vec<String>,
    pub max_queue_depth: u32,
    pub ack_timeout_seconds_override: Option<u32>,
    pub priority_class: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdgePeerFilter {
    pub trust: Option<EdgePeerTrust>,
    pub identity_type: Option<String>,
    pub rooted: Option<bool>,
}

#[derive(Debug, Clone)]
pub struct EdgePeerInfo {
    pub handle: EdgePeerHandle,
    pub pubkey_ed25519_base64: String,
    pub identity_type: String,
    pub rooted: bool,
    pub reachable_via: Vec<String>,
    pub last_seen_at: Option<String>,
    pub last_attestation_id: Option<String>,
    pub policy: EdgePeerPolicy,
    pub trust: EdgePeerTrust,
    pub alias: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdgeProbeResult {
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub failure_class: Option<String>,
}

// ─── Transport mgmt types (#25) ─────────────────────────────────────

#[derive(Debug, Clone)]
pub struct EdgeTransportHandle {
    pub id: u64,
    pub kind: String,
}

#[derive(Debug, Clone)]
pub struct EdgeTransportSpec {
    pub kind: String,
    pub config_json: String,
}

#[derive(Debug, Clone)]
pub struct EdgeTransportInfo {
    pub handle: EdgeTransportHandle,
    pub config_summary_json: String,
    pub peer_count: u32,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub started_at: String,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdgeTransportStats {
    pub name: String,
    pub kind: String,
    pub status: String,
    pub online: bool,
    pub bitrate_bps: Option<u64>,
    pub mode: String,
    pub rxb: u64,
    pub txb: u64,
    pub hw_mtu: Option<u32>,
    pub ifac_size: Option<u32>,
    pub ifac_signature: Option<String>,
    pub rssi_dbm: Option<f64>,
    pub snr_db: Option<f64>,
    pub airtime_long_pct: Option<f64>,
    pub airtime_short_pct: Option<f64>,
    pub cpu_load_pct: Option<f64>,
    pub battery_pct: Option<f64>,
}

#[derive(Debug, Clone)]
pub struct EdgeTransportHealth {
    pub link_state: String,
    pub last_success_at: Option<String>,
    pub last_error_at: Option<String>,
    pub last_error: Option<String>,
    pub peer_count: u32,
}

// ─── Observability snapshot types (#28) ─────────────────────────────

#[derive(Debug, Clone)]
pub struct EdgeMetricsSnapshot {
    pub counters: HashMap<String, u64>,
    pub gauges: HashMap<String, f64>,
    pub snapshot_at: String,
    pub window_seconds: u64,
}

#[derive(Debug, Clone)]
pub struct EdgeNetworkEvent {
    pub at: String,
    pub kind: String,
    pub severity: String,
    pub body_json: String,
}

#[derive(Debug, Clone)]
pub struct EdgeErrorEvent {
    pub at: String,
    pub class_name: String,
    pub message: String,
    pub body_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EdgePeerHealth {
    pub peer_key_id: String,
    pub reachability_ratio: f64,
    pub last_success_at: Option<String>,
    pub last_error_class: Option<String>,
    pub attempts: u64,
    pub successes: u64,
}

#[derive(Debug, Clone)]
pub struct EdgePathEntry {
    pub peer_key_id: String,
    pub transport_kind: String,
    pub hops: u32,
    pub next_hop: Option<String>,
    pub last_seen_at: Option<String>,
}
