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

// ─── #33 Routing-table FFI types (v0.15.0) ──────────────────────────
//
// Per the issue body, the routing-table surface exposes Reticulum's
// path/announce/rate/tunnels/reverse tables and a typed blackhole
// (operator deny-list). The `EdgeRouting*` prefix keeps these
// separate from the existing `EdgePathEntry` (#28 observability
// snapshot) — the v0.15.0 surface is the richer routing-tier view.
//
// **Reticulum-prior-art limitations** (v0.15.0):
//
// Leviculum's driver public API exposes `has_path` / `hops_to` /
// `request_path` / `path_count` and aggregate `transport_stats`, but
// the per-row enumeration accessors — `path_table_entries`,
// `rate_table_entries`, `remove_path`, `drop_all_paths_via` — are only
// `pub(crate)` on `NodeCore` from `reticulum-std`'s driver wrapper.
// The `announce_table` (in-flight retry queue) and `reverse_table`
// (debug routing memory) are NEVER publicly exposed at any level. The
// v0.15.0 routing-table FFI therefore lands the **wire shape** but
// stubs the body of the enumeration / mutation methods with empty
// `Vec` returns and `Ok(())` no-ops respectively, pending the upstream
// Leviculum gap closure. The blackhole table is fully functional
// (in-memory; durable persistence stubbed pending the
// `cirislens.blackhole_rules` persist table — CIRISPersist#120). See
// the docstrings on each `ReticulumTransport::routing_*` method for
// the per-method gap note.
//
// Note: the CIRISAI/leviculum repository has issues disabled (forked
// from teranos/leviculum). The upstream gap is therefore tracked only
// in this crate's docstrings + the v0.15.0 CHANGELOG; the eventual
// widening lands as a fork-side patch in the CIRISAI/leviculum tree
// (the same fork that strips upstream's broken submodules).

/// Single path-table entry (read view). `destination_hash` is the
/// 16-byte Reticulum destination hash; `peer_key_id` is filled from
/// edge's rooted-peer map when the destination matches a known peer
/// (the cold-start authenticated path, AV-42); `via_transport_id` and
/// `via_transport_kind` identify the transport carrying the path;
/// `next_hop` is the 16-byte identity hash of the next-hop peer (empty
/// when the path is direct / one-hop); timestamps are RFC-3339 UTC.
///
/// v0.15.0 limitation: the upstream driver does not expose
/// `path_table_entries` publicly — see module-level note. The Rust
/// `path_table()` accessor returns `Vec::new()` until Leviculum lifts
/// the visibility cap; the wire shape is pinned so a v0.15.x patch
/// can flip on real values without binding-side churn.
#[derive(Debug, Clone)]
pub struct EdgeRoutingPathEntry {
    pub destination_hash: Vec<u8>,
    pub peer_key_id: Option<String>,
    pub hops: u32,
    pub via_transport_id: String,
    pub via_transport_kind: String,
    pub next_hop: Vec<u8>,
    pub last_seen_at: String,
    pub expires_at: String,
}

/// Operator-configured deny-list entry. `identity_hash` is the 16-byte
/// Reticulum identity hash of the blocked peer; `until` is the optional
/// RFC-3339 expiry (`None` → permanent until `blackhole_remove`);
/// `reason` is the operator-supplied note; `hits` is the count of
/// envelopes the transport dropped because this rule matched.
///
/// v0.15.0: in-memory only. The rules survive the `ReticulumTransport`
/// instance but NOT a process restart. Durability lands in v0.15.x
/// patch once persist exposes a `cirislens.blackhole_rules` table
/// (CIRISPersist follow-up filed during v0.15.0 implementation).
#[derive(Debug, Clone)]
pub struct EdgeBlackholeEntry {
    pub identity_hash: Vec<u8>,
    pub until: Option<String>,
    pub reason: Option<String>,
    pub added_at: String,
    pub hits: u64,
}

/// Single rate-limit table entry — Reticulum's per-source announce-
/// frequency tracker exposed for operator inspection. `identity_hash`
/// is the 16-byte source identity; `announce_freq_per_min` is the
/// measured frequency; `violations` is the count of rate-cap breaches;
/// `blocked_until` (RFC-3339 UTC) is the ban expiry when the source
/// crossed the violation threshold.
///
/// v0.15.0 limitation: `rate_table_entries` is not exposed on the
/// driver public API (only via `pub(crate)` NodeCore::rate_table_entries).
/// Returns empty until Leviculum widens the visibility.
#[derive(Debug, Clone)]
pub struct EdgeRateEntry {
    pub identity_hash: Vec<u8>,
    pub announce_freq_per_min: f64,
    pub violations: u32,
    pub blocked_until: Option<String>,
}

/// Reticulum tunnel — long-lived path synthesizing destination
/// reachability across multi-hop relays. Mirrors the Reticulum Python
/// `Transport.tunnels` dict shape: a `hash` (the tunnel hash, derived
/// from the well-known `rnstransport.tunnel.synthesize` destination),
/// the tunnel's own `tunnel_id` (16 bytes), the current `hops` count,
/// and the RFC-3339 expiry.
///
/// v0.15.0 limitation: `transport.tunnels` is NOT publicly exposed in
/// reticulum-core / reticulum-std at all — even at `pub(crate)`. The
/// only references are internal (`tunnel_synthesize_hash` for control-
/// destination routing). Returns empty pending an upstream Leviculum
/// gap-closure issue.
#[derive(Debug, Clone)]
pub struct EdgeTunnelInfo {
    pub hash: Vec<u8>,
    pub tunnel_id: Vec<u8>,
    pub hops: u32,
    pub expires_at: String,
}

/// Single in-flight outbound announce — the retry queue Reticulum
/// owns for announces it has emitted but not yet seen rebroadcast /
/// settled. `destination_hash` is the announce target; `attempts` is
/// the retry counter; `next_retry_at` is the RFC-3339 scheduled
/// retransmit time.
///
/// v0.15.0 limitation: the outbound announce retry queue is
/// `pub(crate)` from `reticulum-core::transport`. Returns empty
/// pending Leviculum widening.
#[derive(Debug, Clone)]
pub struct EdgeInFlightAnnounce {
    pub destination_hash: Vec<u8>,
    pub attempts: u32,
    pub next_retry_at: String,
}

/// Single reverse-routing table entry — debugging surface only.
/// Reticulum's reverse table records which interface a destination
/// was learned over, so the proof / response path can route back
/// without re-running PATH_REQUEST.
///
/// v0.15.0 limitation: the reverse table is `pub(crate)` from
/// `reticulum-core::transport` and only consulted internally for
/// proof routing. Returns empty pending Leviculum widening.
#[derive(Debug, Clone)]
pub struct EdgeReverseEntry {
    pub source_hash: Vec<u8>,
    pub destination_hash: Vec<u8>,
    pub last_seen_at: String,
}

// ─── #32 Links FFI types (v0.14.0) ──────────────────────────────────
//
// Mirrors Reticulum's `LinkState` enum projection (Pending / Active /
// Closing / Closed / Stale). Leviculum's `LinkState::Handshake` rolls
// into `Pending` from the consumer's POV — the link is not yet usable.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EdgeLinkState {
    Pending,
    Active,
    Closing,
    Closed,
    Stale,
}

#[derive(Debug, Clone)]
pub struct EdgeLinkHandle {
    pub link_id: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EdgeLinkInfo {
    pub link_id: Vec<u8>,
    pub peer_identity_hash: Vec<u8>,
    pub state: EdgeLinkState,
    pub age_seconds: u64,
    pub rssi_dbm: Option<f64>,
    pub snr_db: Option<f64>,
    pub establishment_rate_kbps: Option<f64>,
    pub mtu: u32,
    pub mdu: u32,
    pub transport_id: String,
    pub transport_kind: String,
}
