// `needless_pass_by_value` — every UDL-exported function MUST match
// the generated signature (which always passes records by value).
// `cast_possible_truncation` — `handle.id` is a u64 by UDL contract
// but indexes a Rust-side `usize` (interface handle index); the cast
// is sound because indices are <2^32 in practice but lint can't know.
// `items_after_statements` — the cfg-gated `let target = ...` line in
// `transport_stats` must precede a `for` loop because the binding's
// type comes from a cfg-gated module; the lint mis-flags the `let`.
#![allow(
    clippy::needless_pass_by_value,
    clippy::cast_possible_truncation,
    clippy::items_after_statements
)]

//! UniFFI bindings — Python / Kotlin / Swift surface for the
//! operator-facing reads + the typed transport / peer mgmt CRUD.
//!
//! # v0.13.0 (CIRISEdge#36 GO + #25 + #26 + #31 reads + #28 snapshot reads)
//!
//! Per the spike's GO carve-out:
//!
//! - PyO3 stays for: `init_edge_runtime` (PyCapsule + Bound<PyAny>),
//!   Tier 2 GIL-drainer callbacks (`register_inline_text_handler`,
//!   `DurableHandle`, `SubscriptionHandle`), AsyncIterator event stream
//!   (`subscribe_*`), `set_local_display_name` + QR import/export.
//!
//! - UniFFI takes: #25 Transport mgmt, #26 Peer mgmt, #31 Identity
//!   READS, #28 SNAPSHOT READS.
//!
//! Both bindings live in the SAME `.so` (the wheel feature set has
//! `pyo3 + ffi-uniffi` together by default). `nm -D` will show
//! `PyInit_ciris_edge` AND `uniffi_ciris_edge_fn_func_*` symbols.
//!
//! # Edge handle plumbing
//!
//! UniFFI free functions don't take a `self` — they operate on a
//! process-global Edge. We use a `OnceLock<RwLock<Weak<Edge>>>`
//! that `init_edge_runtime` (PyO3-side) populates via
//! [`install_edge_handle`]. Calls before init return
//! `EdgeError::NotInitialized`.
//!
//! `Weak<Edge>` not `Arc<Edge>` so the static doesn't prevent edge
//! teardown; the consumer upgrades to a strong `Arc` per call.
//!
//! # Module layout
//!
//! The Rust impl lives here; the UDL-side type definitions
//! (`EdgeError`, `EdgePeerInfo`, `EdgePeerHandle`, etc.) are generated
//! by `build.rs` via `uniffi::generate_scaffolding` and pulled in at
//! the crate root via `uniffi::include_scaffolding!("ciris_edge")` in
//! `lib.rs`. The functions exported here MUST match the UDL
//! signatures exactly — the generated scaffolding contains
//! `#[export_for_udl] pub fn $NAME(...)` stubs whose macro expansion
//! replaces them with marshalling shells that delegate to a same-named
//! function visible at the crate root.

use std::sync::{Arc, OnceLock, RwLock, Weak};

use crate::edge::Edge;

// ─── Edge handle registry ───────────────────────────────────────────

fn edge_slot() -> &'static RwLock<Weak<Edge>> {
    static SLOT: OnceLock<RwLock<Weak<Edge>>> = OnceLock::new();
    SLOT.get_or_init(|| RwLock::new(Weak::new()))
}

/// Install the process-global `Weak<Edge>` handle. Called from
/// `crate::ffi::pyo3::init_edge_runtime` at the same point the
/// `PyEdge` is constructed.
pub fn install_edge_handle(edge: &Arc<Edge>) {
    let mut slot = edge_slot().write().expect("edge_slot poisoned");
    *slot = Arc::downgrade(edge);
}

/// Resolve the registered Edge to a strong `Arc`. `Err(NotInitialized)`
/// if `install_edge_handle` was never called OR the underlying Edge
/// has been dropped.
pub(crate) fn current_edge() -> Result<Arc<Edge>, crate::EdgeBindingsError> {
    let slot = edge_slot().read().expect("edge_slot poisoned");
    slot.upgrade()
        .ok_or(crate::EdgeBindingsError::NotInitialized)
}

// ─── Crate version ──────────────────────────────────────────────────
//
// NOTE: UniFFI's `flat_error` mode auto-derives `Display` + `Error`
// on the generated enum via `thiserror`. The crate root's
// `include_scaffolding!` expansion is the source of truth for that
// derive; this module does NOT add a manual impl (it would conflict).

pub fn crate_version() -> Result<String, crate::EdgeBindingsError> {
    Ok(env!("CARGO_PKG_VERSION").to_string())
}

// ─── #26 Peer mgmt — READS ──────────────────────────────────────────
//
// **v0.13.0 limitation**: `VerifyDirectory` exposes `lookup_public_key`
// + `list_accord_holders` but NOT a generic `list_keys_by_identity_type`
// or `list_all_keys`. So `peer_list` can enumerate ACCORD_HOLDER rows
// (the only directory-listable identity type at this trait surface);
// other identity types yield empty results. A persist-side trait
// widening lifts this — tracked under the CIRISPersist follow-up
// referenced in CIRISEdge#36 closure.

/// `peer_list(filter)` — enumerate every peer reachable via
/// `VerifyDirectory::list_accord_holders` (the only directory
/// enumeration surface available at this trait level in v0.13.0).
pub fn peer_list(
    filter: Option<crate::EdgePeerFilter>,
) -> Result<Vec<crate::EdgePeerInfo>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = edge.verify_directory();

    let directory_clone = directory.clone();
    let rows = block_on_runtime(&edge, async move {
        directory_clone.list_accord_holders().await.map_err(|e| {
            tracing::warn!(error = %e, "list_accord_holders for peer_list");
            crate::EdgeBindingsError::Persist
        })
    })?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        if let Some(f) = filter.as_ref() {
            if let Some(ref t) = f.trust {
                if !matches!(t, crate::EdgePeerTrust::Trusted) {
                    continue;
                }
            }
            if let Some(want_rooted) = f.rooted {
                if !want_rooted {
                    continue;
                }
            }
            if let Some(it) = f.identity_type.as_deref() {
                if it != "accord_holder" {
                    continue;
                }
            }
        }

        use base64::Engine as _;
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(row.pubkey_ed25519);

        let canonical = edge.is_canonical_peer(&row.key_id);
        out.push(crate::EdgePeerInfo {
            handle: crate::EdgePeerHandle {
                key_id: row.key_id.clone(),
            },
            pubkey_ed25519_base64: pubkey_b64,
            identity_type: "accord_holder".to_string(),
            rooted: true,
            reachable_via: Vec::new(),
            last_seen_at: None,
            last_attestation_id: None,
            policy: default_open_policy(),
            trust: crate::EdgePeerTrust::Trusted,
            alias: None,
            notes: None,
            canonical,
        });
    }
    Ok(out)
}

fn default_open_policy() -> crate::EdgePeerPolicy {
    crate::EdgePeerPolicy {
        subscription_filter: Vec::new(),
        max_queue_depth: 1000,
        ack_timeout_seconds_override: None,
        priority_class: None,
    }
}

/// `peer_get(key_id)` — single-row lookup via persist's
/// `lookup_public_key`. Returns `None` if absent.
pub fn peer_get(key_id: String) -> Result<Option<crate::EdgePeerInfo>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = edge.verify_directory();

    let key_id_owned = key_id.clone();
    let directory_clone = directory.clone();
    let row = block_on_runtime(&edge, async move {
        directory_clone
            .lookup_public_key(&key_id_owned)
            .await
            .map_err(|e| {
                tracing::warn!(error = %e, key_id = %key_id_owned, "lookup_public_key for peer_get");
                crate::EdgeBindingsError::Persist
            })
    })?;

    Ok(row.map(|pubkey| {
        use base64::Engine as _;
        let pubkey_b64 = base64::engine::general_purpose::STANDARD.encode(pubkey);
        let canonical = edge.is_canonical_peer(&key_id);
        crate::EdgePeerInfo {
            handle: crate::EdgePeerHandle {
                key_id: key_id.clone(),
            },
            pubkey_ed25519_base64: pubkey_b64,
            identity_type: "unknown".to_string(),
            rooted: true,
            reachable_via: Vec::new(),
            last_seen_at: None,
            last_attestation_id: None,
            policy: default_open_policy(),
            trust: crate::EdgePeerTrust::Trusted,
            alias: None,
            notes: None,
            canonical,
        }
    }))
}

// ─── #26 Peer mgmt — MUTATIONS (v0.15.1 LIVE, CIRISPersist#117) ─────
//
// v0.13.0 stubbed these as `PEER_MUTATION_FOLLOWUP` returning
// `EdgeBindingsError::NotImplemented`: persist's `FederationDirectory`
// trait did not yet expose the per-peer write surface they need (only
// the keypair-row admission path `put_public_key`, which is the
// federation-shared identity layer, not the operator-local
// per-instance metadata these mutations target).
//
// CIRISPersist v3.1.0 (CIRISPersist#117) closes that gap by adding 6
// new `async fn`s on `FederationDirectory` — `add_peer_record`,
// `remove_peer_record`, `update_peer_alias`, `update_peer_trust`,
// `update_peer_notes`, `update_peer_policy` — backed by the V051
// `federation_peer_metadata` sibling table. Each method is
// `#[async_trait]` object-safe (matched 1:1 by the
// `Arc<dyn FederationDirectory>` we now retain on Edge via
// `EdgeBuilder::federation_directory` and the pyo3 cohabitation init
// path's `federation_directory_capsule` extraction).
//
// `peer_probe` STAYS `NotImplemented` — it's a network primitive
// (Reticulum-backed live reachability), NOT persist-backed. Separate
// follow-up (CIRISEdge#22 / v0.16.0 reachability surface).

/// Look up the concrete `Arc<dyn FederationDirectory>` Edge retains
/// for peer-mutation FFI calls. Returns `Unsupported` when the host
/// wired only a `VerifyDirectory` (e.g., tests that don't exercise the
/// mutation surface) — distinct from `NotInitialized` (no Edge
/// installed at all).
fn current_federation_directory(
) -> Result<Arc<dyn ciris_persist::federation::FederationDirectory>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    edge.federation_directory()
        .ok_or(crate::EdgeBindingsError::Unsupported)
}

/// EdgePeerTrust → persist TrustClass — total mapping per v0.15.1
/// alignment (variants match 1:1).
fn edge_trust_to_persist(t: crate::EdgePeerTrust) -> ciris_persist::federation::TrustClass {
    use ciris_persist::federation::TrustClass;
    match t {
        crate::EdgePeerTrust::Untrusted => TrustClass::Untrusted,
        crate::EdgePeerTrust::Trusted => TrustClass::Trusted,
        crate::EdgePeerTrust::Restricted => TrustClass::Restricted,
        crate::EdgePeerTrust::Blocked => TrustClass::Blocked,
    }
}

/// EdgePeerPolicy → persist PeerPolicyBlob. The blob is opaque to
/// persist (`#[serde(transparent)]` newtype over `serde_json::Value`),
/// so we serialize the entire edge-side dictionary and let persist
/// round-trip the JSON verbatim. Infallible — `serde_json::json!`
/// can't fail over `Vec<String>` / `u32` / `Option<u32>` /
/// `Option<String>` primitives.
fn edge_policy_to_blob(p: &crate::EdgePeerPolicy) -> ciris_persist::federation::PeerPolicyBlob {
    // Build the JSON value via a serde-friendly intermediate so the
    // wire shape is predictable (named fields, snake_case keys
    // matching the UDL field names).
    let value = serde_json::json!({
        "subscription_filter": p.subscription_filter,
        "max_queue_depth": p.max_queue_depth,
        "ack_timeout_seconds_override": p.ack_timeout_seconds_override,
        "priority_class": p.priority_class,
    });
    ciris_persist::federation::PeerPolicyBlob(value)
}

/// Persist `federation::Error` → `EdgeBindingsError`. Maps the two
/// typed variants introduced by CIRISPersist#117 specifically:
/// - `PeerNotFound { .. }` → `NotFound`
/// - `HardRemoveWithActiveAttestations { .. }` → `InvalidArgument`
///   (the caller asked for an action the data model rejects; the
///   fix is operator-driven — soft-remove or revoke first)
///
/// All other persist errors (Backend / Conflict / InvalidArgument /
/// SignatureInvalid / RateLimited / admission variants) fold into
/// `Persist` — the binding consumer reads the stable
/// `Error::kind()` token off the debug-display when they need
/// finer-grained discrimination.
fn map_federation_err(e: ciris_persist::federation::Error) -> crate::EdgeBindingsError {
    use ciris_persist::federation::Error as FE;
    match e {
        FE::PeerNotFound { ref key_id } => {
            tracing::debug!(key_id = %key_id, kind = e.kind(), "federation peer not found");
            crate::EdgeBindingsError::NotFound
        }
        FE::HardRemoveWithActiveAttestations {
            ref key_id,
            attestation_count,
        } => {
            tracing::warn!(
                key_id = %key_id,
                attestation_count,
                kind = e.kind(),
                "hard-remove rejected due to active attestations",
            );
            crate::EdgeBindingsError::InvalidArgument
        }
        FE::InvalidArgument(_) => {
            tracing::warn!(error = %e, kind = e.kind(), "peer mutation invalid argument");
            crate::EdgeBindingsError::InvalidArgument
        }
        FE::Conflict(_) => {
            tracing::warn!(error = %e, kind = e.kind(), "peer mutation conflict");
            crate::EdgeBindingsError::InvalidArgument
        }
        other => {
            tracing::warn!(error = %other, kind = other.kind(), "peer mutation persist error");
            crate::EdgeBindingsError::Persist
        }
    }
}

/// `peer_add(key_id, pubkey_ed25519_base64, transport_identity, policy)`
/// — admits a new peer row via persist's
/// [`FederationDirectory::add_peer_record`]. Idempotent on a matching
/// pubkey; rejects with `InvalidArgument` (mapped from persist's
/// `Conflict`) on a differing pubkey for the same `key_id`.
///
/// The default `identity_type` for a newly-added operator-bound peer
/// is the persist-defined `"agent"` token
/// ([`ciris_persist::federation::types::identity_type::AGENT`]) — the
/// general-purpose federation identity bucket. Stewards / accord
/// holders / substrate keys land via the registry's admission path,
/// not this FFI.
///
/// If `policy` is supplied, follows the `add_peer_record` call with an
/// immediate `update_peer_policy` so the operator-set policy lands
/// atomically from the caller's POV. The trust class defaults to
/// `Untrusted` (persist's default); operators promote via
/// `peer_set_trust`.
pub fn peer_add(
    key_id: String,
    pubkey_ed25519_base64: String,
    transport_identity: Option<String>,
    policy: Option<crate::EdgePeerPolicy>,
) -> Result<crate::EdgePeerHandle, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = current_federation_directory()?;
    let key_id_owned = key_id.clone();
    let policy_blob = policy.as_ref().map(edge_policy_to_blob);
    block_on_runtime(&edge, async move {
        directory
            .add_peer_record(
                &key_id_owned,
                &pubkey_ed25519_base64,
                ciris_persist::federation::types::identity_type::AGENT,
                transport_identity,
            )
            .await
            .map_err(map_federation_err)?;
        if let Some(blob) = policy_blob {
            directory
                .update_peer_policy(&key_id_owned, blob)
                .await
                .map_err(map_federation_err)?;
        }
        Ok(crate::EdgePeerHandle {
            key_id: key_id_owned,
        })
    })
}

/// `peer_remove(handle, hard)` — soft-remove (default) marks the
/// `federation_peer_metadata.removed_at = NOW()`; hard-remove DELETEs
/// the `federation_keys` row AND (cascade) the metadata row.
/// Hard-remove is rejected with `InvalidArgument` (mapped from
/// `HardRemoveWithActiveAttestations`) when active attestations would
/// be orphaned — the operator either soft-removes (preserves audit
/// trail) or revokes the key first.
///
/// v0.18.0 (CIRISEdge#46) — hard-remove of a CANONICAL bootstrap peer
/// (one whose `key_id` lives in the init-supplied `bootstrap_peers`
/// set) is rejected with [`EdgeBindingsError::CannotRemoveCanonicalPeer`]
/// BEFORE the persist call runs. Soft-remove on a canonical peer is
/// permitted; the row is hidden from reads, the canonical knowledge
/// stays in memory, and the init reseed does NOT un-hide it (persist
/// preserves `removed_at` across the idempotent `add_peer_record`).
pub fn peer_remove(
    handle: crate::EdgePeerHandle,
    hard: bool,
) -> Result<(), crate::EdgeBindingsError> {
    let edge = current_edge()?;
    if hard && edge.is_canonical_peer(&handle.key_id) {
        tracing::warn!(
            key_id = %handle.key_id,
            "peer_remove(hard=true) rejected on canonical bootstrap peer",
        );
        return Err(crate::EdgeBindingsError::CannotRemoveCanonicalPeer);
    }
    let directory = current_federation_directory()?;
    let key_id = handle.key_id;
    block_on_runtime(&edge, async move {
        directory
            .remove_peer_record(&key_id, hard)
            .await
            .map_err(map_federation_err)
    })
}

/// `peer_set_alias(key_id, alias)` — operator-local display name.
/// `None` clears the field. Returns `NotFound` when the key has no
/// peer metadata row.
pub fn peer_set_alias(
    key_id: String,
    alias: Option<String>,
) -> Result<(), crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = current_federation_directory()?;
    block_on_runtime(&edge, async move {
        directory
            .update_peer_alias(&key_id, alias)
            .await
            .map_err(map_federation_err)
    })
}

/// `peer_set_trust(key_id, trust)` — promote / demote a peer's
/// operator-trust class. Variants map 1:1 to persist v3.1.0's
/// [`TrustClass`](ciris_persist::federation::TrustClass)
/// (`Untrusted` / `Trusted` / `Restricted` / `Blocked`).
pub fn peer_set_trust(
    key_id: String,
    trust: crate::EdgePeerTrust,
) -> Result<(), crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = current_federation_directory()?;
    let persist_trust = edge_trust_to_persist(trust);
    block_on_runtime(&edge, async move {
        directory
            .update_peer_trust(&key_id, persist_trust)
            .await
            .map_err(map_federation_err)
    })
}

/// `peer_set_notes(key_id, notes)` — operator-local free-form notes.
/// `None` clears the field.
pub fn peer_set_notes(
    key_id: String,
    notes: Option<String>,
) -> Result<(), crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = current_federation_directory()?;
    block_on_runtime(&edge, async move {
        directory
            .update_peer_notes(&key_id, notes)
            .await
            .map_err(map_federation_err)
    })
}

/// `peer_set_policy(handle, policy)` — replaces the per-peer policy
/// blob. Persist round-trips the JSON verbatim
/// (`PeerPolicyBlob(serde_json::Value)`); the shape is owned by this
/// FFI (matches the `EdgePeerPolicy` UDL dictionary).
pub fn peer_set_policy(
    handle: crate::EdgePeerHandle,
    policy: crate::EdgePeerPolicy,
) -> Result<(), crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let directory = current_federation_directory()?;
    let blob = edge_policy_to_blob(&policy);
    let key_id = handle.key_id;
    block_on_runtime(&edge, async move {
        directory
            .update_peer_policy(&key_id, blob)
            .await
            .map_err(map_federation_err)
    })
}

/// `peer_probe(key_id, timeout_ms)` — STAYS `NotImplemented` at
/// v0.15.1. The probe is a network primitive (Reticulum-backed live
/// reachability), distinct from the persist-backed peer-metadata
/// mutations the rest of this section landed. Tracked under a
/// separate v0.16.x follow-up.
pub fn peer_probe(
    _key_id: String,
    _timeout_ms: u64,
) -> Result<crate::EdgeProbeResult, crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

// ─── #25 Transport mgmt ─────────────────────────────────────────────

/// `transport_list()` — enumerate the registered transports.
pub fn transport_list() -> Result<Vec<crate::EdgeTransportInfo>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let mut out = Vec::new();
    for (idx, transport) in edge.transports().iter().enumerate() {
        let kind = transport.id().0.to_string();
        out.push(crate::EdgeTransportInfo {
            handle: crate::EdgeTransportHandle {
                id: idx as u64,
                kind: kind.clone(),
            },
            config_summary_json: format!(r#"{{"kind":"{kind}"}}"#),
            peer_count: 0,
            bytes_in: 0,
            bytes_out: 0,
            started_at: chrono::Utc::now().to_rfc3339(),
            last_error: None,
        });
    }
    Ok(out)
}

pub fn transport_add(
    _spec: crate::EdgeTransportSpec,
) -> Result<crate::EdgeTransportHandle, crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

pub fn transport_remove(
    _handle: crate::EdgeTransportHandle,
    _drain: bool,
) -> Result<(), crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

pub fn transport_enable(
    _handle: crate::EdgeTransportHandle,
) -> Result<(), crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

pub fn transport_disable(
    _handle: crate::EdgeTransportHandle,
) -> Result<(), crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

pub fn transport_set_mode(
    _handle: crate::EdgeTransportHandle,
    _mode: String,
) -> Result<(), crate::EdgeBindingsError> {
    Err(crate::EdgeBindingsError::NotImplemented)
}

/// `transport_stats(handle)` — typed snapshot for one Reticulum
/// interface. Reuses v0.12.0's `TransportStats` shape.
pub fn transport_stats(
    handle: crate::EdgeTransportHandle,
) -> Result<crate::EdgeTransportStats, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    #[cfg(feature = "_reticulum-module")]
    {
        if let Some(s) = edge.reticulum_stats_for_handle(handle.id as usize) {
            return Ok(crate::EdgeTransportStats {
                name: s.name,
                kind: s.kind,
                status: s.status,
                online: s.online,
                bitrate_bps: s.bitrate_bps,
                mode: s.mode,
                rxb: s.rxb,
                txb: s.txb,
                hw_mtu: s.hw_mtu,
                ifac_size: s.ifac_size.and_then(|v| u32::try_from(v).ok()),
                ifac_signature: s.ifac_signature,
                rssi_dbm: s.rssi_dbm,
                snr_db: s.snr_db,
                airtime_long_pct: s.airtime_long_pct,
                airtime_short_pct: s.airtime_short_pct,
                cpu_load_pct: s.cpu_load_pct,
                battery_pct: s.battery_pct,
            });
        }
    }
    let _ = edge;
    Ok(crate::EdgeTransportStats {
        name: handle.kind.clone(),
        kind: handle.kind.clone(),
        status: "unknown".to_string(),
        online: false,
        bitrate_bps: None,
        mode: "full".to_string(),
        rxb: 0,
        txb: 0,
        hw_mtu: None,
        ifac_size: None,
        ifac_signature: None,
        rssi_dbm: None,
        snr_db: None,
        airtime_long_pct: None,
        airtime_short_pct: None,
        cpu_load_pct: None,
        battery_pct: None,
    })
}

/// `transport_health(handle)` — link state + per-transport peer count
/// from the reachability tracker.
pub fn transport_health(
    handle: crate::EdgeTransportHandle,
) -> Result<crate::EdgeTransportHealth, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let snap = edge.reachability_tracker().snapshot_all();
    let mut peer_count: u32 = 0;
    let mut last_success_at: Option<String> = None;
    let mut last_error_at: Option<String> = None;
    let mut last_error: Option<String> = None;
    for entry in &snap {
        if entry.transport_id.0 == handle.kind {
            peer_count = peer_count.saturating_add(1);
            if let Some(t) = entry.last_success_at {
                last_success_at = Some(t.to_rfc3339());
            }
            if entry.last_error_class.is_some() {
                if let Some(t) = entry.last_attempt_at {
                    last_error_at = Some(t.to_rfc3339());
                }
            }
            if let Some(ec) = entry.last_error_class.clone() {
                last_error = Some(ec);
            }
        }
    }
    Ok(crate::EdgeTransportHealth {
        link_state: if peer_count > 0 { "up" } else { "unknown" }.to_string(),
        last_success_at,
        last_error_at,
        last_error,
        peer_count,
    })
}

/// `transport_config_blob(handle)` — the configured-side JSON for the
/// transport.
pub fn transport_config_blob(
    handle: crate::EdgeTransportHandle,
) -> Result<String, crate::EdgeBindingsError> {
    let _edge = current_edge()?;
    Ok(format!(
        r#"{{"kind":"{}", "id":{}}}"#,
        handle.kind, handle.id
    ))
}

// ─── #31 Identity READS ─────────────────────────────────────────────

/// `identity_hash()` — 16-byte federation identity fingerprint.
pub fn identity_hash() -> Result<Vec<u8>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let signer = edge.signer();
    let hash = block_on_runtime(&edge, async move {
        signer.identity_hash().await.map_err(|e| {
            tracing::warn!(error = %e, "identity_hash");
            crate::EdgeBindingsError::Internal
        })
    })?;
    Ok(hash.to_vec())
}

/// `identity_pubkeys()` — `{"ed25519": bytes, "ml_dsa_65": bytes?}`.
pub fn identity_pubkeys(
) -> Result<std::collections::HashMap<String, Vec<u8>>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let signer = edge.signer();
    let (ed25519, pqc) = block_on_runtime(&edge, async move {
        signer.federation_pubkeys().await.map_err(|e| {
            tracing::warn!(error = %e, "federation_pubkeys");
            crate::EdgeBindingsError::Internal
        })
    })?;
    let mut out = std::collections::HashMap::new();
    out.insert("ed25519".to_string(), ed25519);
    if let Some(pqc) = pqc {
        out.insert("ml_dsa_65".to_string(), pqc);
    }
    Ok(out)
}

pub fn current_ratchet_id() -> Result<String, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    Ok(edge.signer().ratchet_id.clone())
}

pub fn last_rotation_at() -> Result<String, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    Ok(edge.signer().last_rotation_at.to_rfc3339())
}

// ─── #28 Observability snapshot reads ───────────────────────────────

pub fn metrics_snapshot() -> Result<crate::EdgeMetricsSnapshot, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let tracker = edge.reachability_tracker();
    let snap = tracker.snapshot_all();

    let mut counters: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut gauges: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    let mut total_attempts: u64 = 0;
    let mut total_successes: u64 = 0;
    for entry in &snap {
        total_attempts = total_attempts.saturating_add(entry.attempts);
        total_successes = total_successes.saturating_add(entry.successes);
    }
    counters.insert("reachability.attempts_total".to_string(), total_attempts);
    counters.insert("reachability.successes_total".to_string(), total_successes);
    #[allow(clippy::cast_precision_loss)]
    gauges.insert(
        "reachability.peer_medium_count".to_string(),
        snap.len() as f64,
    );
    #[allow(clippy::cast_precision_loss)]
    gauges.insert(
        "reachability.window_seconds".to_string(),
        tracker.window_seconds() as f64,
    );

    Ok(crate::EdgeMetricsSnapshot {
        counters,
        gauges,
        snapshot_at: chrono::Utc::now().to_rfc3339(),
        window_seconds: tracker.window_seconds(),
    })
}

pub fn recent_events(
    _limit: u32,
) -> Result<Vec<crate::EdgeNetworkEvent>, crate::EdgeBindingsError> {
    let _edge = current_edge()?;
    Ok(Vec::new())
}

pub fn recent_errors(_limit: u32) -> Result<Vec<crate::EdgeErrorEvent>, crate::EdgeBindingsError> {
    let _edge = current_edge()?;
    Ok(Vec::new())
}

pub fn queue_depth(
    delivery_class: Option<String>,
) -> Result<std::collections::HashMap<String, u64>, crate::EdgeBindingsError> {
    let _edge = current_edge()?;
    let mut out = std::collections::HashMap::new();
    let class = delivery_class.unwrap_or_else(|| "all".to_string());
    out.insert(class, 0_u64);
    Ok(out)
}

pub fn peer_health_summary() -> Result<Vec<crate::EdgePeerHealth>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let snap = edge.reachability_tracker().snapshot_all();

    let mut by_peer: std::collections::HashMap<String, crate::EdgePeerHealth> =
        std::collections::HashMap::new();
    for entry in snap {
        let row = crate::EdgePeerHealth {
            peer_key_id: entry.peer_key_id.clone(),
            reachability_ratio: entry.ratio(),
            last_success_at: entry.last_success_at.map(|t| t.to_rfc3339()),
            last_error_class: entry.last_error_class.clone(),
            attempts: entry.attempts,
            successes: entry.successes,
        };
        by_peer
            .entry(entry.peer_key_id.clone())
            .and_modify(|prev| {
                if row.attempts > prev.attempts {
                    *prev = row.clone();
                }
            })
            .or_insert(row);
    }
    Ok(by_peer.into_values().collect())
}

pub fn path_table() -> Result<Vec<crate::EdgePathEntry>, crate::EdgeBindingsError> {
    let edge = current_edge()?;
    let snap = edge.reachability_tracker().snapshot_all();
    Ok(snap
        .into_iter()
        .map(|entry| crate::EdgePathEntry {
            peer_key_id: entry.peer_key_id,
            transport_kind: entry.transport_id.0.to_string(),
            hops: 1,
            next_hop: None,
            last_seen_at: entry.last_attempt_at.map(|t| t.to_rfc3339()),
        })
        .collect())
}

// ─── Async block_on helper ──────────────────────────────────────────
fn block_on_runtime<F, T>(_edge: &Edge, fut: F) -> Result<T, crate::EdgeBindingsError>
where
    F: std::future::Future<Output = Result<T, crate::EdgeBindingsError>> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(fut))
    } else {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| {
                tracing::warn!(error = %e, "transient runtime build");
                crate::EdgeBindingsError::Internal
            })?;
        rt.block_on(fut)
    }
}

#[cfg(test)]
mod tests {
    //! v0.13.0 (CIRISEdge#36 GO) UniFFI surface smoke gates.
    //!
    //! Coexistence: confirms the UniFFI free functions surface a
    //! typed `NotInitialized` error when no Edge handle has been
    //! installed (the pre-`init_edge_runtime` posture). The full
    //! cross-binding integration test (Python `from ciris_edge import PyEdge` +
    //! `from ciris_edge.uniffi_bindings import peer_list`) lives
    //! downstream in the CIRISConformance v0.13.0 cohabitation gate
    //! — drives a real `init_edge_runtime` via the persist cohabitation
    //! capsule, then exercises both bindings in the same interpreter.

    use super::*;

    #[test]
    fn crate_version_returns_pkg_version() {
        let v = crate_version().expect("crate_version always Ok");
        assert_eq!(v, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn peer_list_before_init_returns_not_initialized() {
        // Each test runs in its own thread but the OnceLock is
        // process-global; if a sibling test has populated it, this
        // assertion changes shape. Tests that populate the slot live
        // ONLY in this module and explicitly tear down after — see
        // `install_uninstall_round_trip` below.
        let err = peer_list(None).expect_err("no edge installed yet");
        assert!(matches!(err, crate::EdgeBindingsError::NotInitialized));
    }

    #[test]
    fn metrics_snapshot_before_init_returns_not_initialized() {
        let err = metrics_snapshot().expect_err("no edge installed yet");
        assert!(matches!(err, crate::EdgeBindingsError::NotInitialized));
    }

    #[test]
    fn peer_add_before_init_returns_not_initialized() {
        // v0.15.1: the 6 peer-mutation entry points are LIVE
        // (persist#117). Pre-init posture surfaces `NotInitialized`,
        // mirroring `peer_list_before_init_returns_not_initialized`.
        // Full round-trip + per-variant + typed-error mapping coverage
        // lives in the integration test `tests/peer_mutation_ffi.rs`
        // (which uses a real `FederationDirectorySqlite` + an
        // installed `Edge` to exercise the persist v3.1.0 surface).
        let err = peer_add(
            "key-1".to_string(),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            None,
            None,
        )
        .expect_err("no edge installed yet");
        assert!(matches!(err, crate::EdgeBindingsError::NotInitialized));
    }

    #[test]
    fn peer_probe_remains_not_implemented() {
        // v0.15.1 carve-out: `peer_probe` is a network primitive
        // (Reticulum-backed live reachability), NOT persist-backed —
        // it stays `NotImplemented` while the 6 sibling persist-backed
        // mutations flip to LIVE. The follow-up cut for the probe
        // surface tracks under CIRISEdge#22 / v0.16.x reachability.
        let err = peer_probe("key-1".to_string(), 1000).expect_err("probe stays stubbed");
        assert!(matches!(err, crate::EdgeBindingsError::NotImplemented));
    }
}
