// `needless_pass_by_value` — every UDL-exported function MUST match
// the generated signature (which always passes records by value).
#![allow(clippy::needless_pass_by_value)]

//! UniFFI Links bindings — v0.14.0 (CIRISEdge#32).
//!
//! Exposes Reticulum's Link layer to the operator surface. The
//! lifecycle (open / teardown), inspection (list / count), and
//! request/response (`link_request`) sit between Transports (#25,
//! v0.13.0) and Federation Peers (#26, v0.13.0).
//!
//! # Async posture
//!
//! Per the UniFFI 0.31 spike's NO-GO on AsyncIterator, async functions
//! are CASE-BY-CASE. `link_open` and `link_request` are exposed as
//! sync functions that internally block on the host's tokio runtime
//! handle (the v0.13.0 `block_on_runtime` pattern reused). The async
//! polish — `link_request` returning a UniFFI `Future` — is deferred
//! to v0.14.x once UniFFI 0.32+ ships its async surface.
//!
//! # Edge transport plumbing
//!
//! The Links surface needs the concrete `Arc<ReticulumTransport>`
//! (the Links lifecycle is Reticulum-specific). v0.14.0 added a
//! `EdgeBuilder::reticulum_transport` typed-handle path and an
//! `Edge::reticulum_transport() -> Option<Arc<ReticulumTransport>>`
//! accessor; this module consults that. `None` → `Unsupported`.
//!
//! # link_open contract
//!
//! `destination_hash` is the 16-byte Reticulum destination hash for the
//! peer's `ciris.edge` endpoint — the same hash that arrives on the
//! announce stream. The transport-tier signing key is sourced from the
//! rooted-peer map (AV-42), so `link_open` will fail with `NotFound`
//! when the destination has not yet been rooted via the authenticated
//! cold-start path. Pattern: consumer subscribes to announces, waits
//! for the peer, then calls `link_open` with the announced
//! `destination_hash`.
//!
//! # link_teardown contract
//!
//! Idempotent. Calls against an unknown / already-closed link return
//! `Ok(())` (the v0.14.0 implementation removes the link from the
//! established set eagerly so concurrent teardowns converge).
//!
//! # link_request contract
//!
//! Blocking. The internal `tokio::time::sleep`-based poll runs on the
//! host runtime via `block_on_runtime` so non-tokio call sites still
//! get a working `block_in_place` path.

#[cfg(feature = "_reticulum-module")]
use std::time::Duration;

#[cfg(feature = "_reticulum-module")]
use crate::transport::TransportError;

#[allow(unused_imports)]
use crate::ffi::uniffi_impl::install_edge_handle;

// ─── Edge / transport resolution helpers ────────────────────────────

/// Look up the registered Reticulum transport (typed). Returns
/// `Unsupported` when the Edge was built without
/// `EdgeBuilder::reticulum_transport` (an HTTP-only deployment) OR
/// when the `_reticulum-module` feature is off (in which case the
/// Links surface is just `Unsupported` everywhere — no Links without
/// Reticulum).
#[cfg(feature = "_reticulum-module")]
fn current_reticulum(
) -> Result<std::sync::Arc<crate::transport::reticulum::ReticulumTransport>, crate::EdgeBindingsError>
{
    let edge = current_edge_arc()?;
    edge.reticulum_transport()
        .ok_or(crate::EdgeBindingsError::Unsupported)
}

#[allow(dead_code)]
fn current_edge_arc() -> Result<std::sync::Arc<crate::edge::Edge>, crate::EdgeBindingsError> {
    // The `ffi::uniffi_impl` module owns the registry; we go through
    // the same private helper by re-implementing the upgrade locally
    // (the helper is `fn current_edge() -> Result<Arc<Edge>, _>` but
    // not `pub`). The simplest path is to call `install_edge_handle`'s
    // sibling indirectly — but since it's not pub, copy the upgrade
    // logic. The slot itself IS pub-accessible via the existing
    // function shape; we reuse it by invoking `peer_list`-style
    // bootstrap. Cleaner: add a `pub(crate) fn current_edge()` to
    // uniffi_impl. Done below.
    crate::ffi::uniffi_impl::current_edge()
}

// ─── #32 Links — lifecycle reads ────────────────────────────────────

pub fn link_list() -> Result<Vec<crate::EdgeLinkInfo>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.link_list().await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn link_count() -> Result<u32, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move {
            let n = transport.link_count().await;
            Ok(u32::try_from(n).unwrap_or(u32::MAX))
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── #32 Links — mutations ──────────────────────────────────────────

pub fn link_open(
    destination_hash: Vec<u8>,
    timeout_ms: u64,
) -> Result<crate::EdgeLinkHandle, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        let timeout = Duration::from_millis(timeout_ms);
        let bytes = block_on(async move {
            transport
                .link_open(&destination_hash, timeout)
                .await
                .map_err(map_transport_err)
        })?;
        Ok(crate::EdgeLinkHandle {
            link_id: bytes.to_vec(),
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = (destination_hash, timeout_ms);
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn link_teardown(link_id: Vec<u8>) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move {
            transport
                .link_teardown(&link_id)
                .await
                .map_err(map_transport_err)
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = link_id;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn link_request(
    link_handle: crate::EdgeLinkHandle,
    path: String,
    data: Vec<u8>,
    timeout_ms: u64,
) -> Result<Vec<u8>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        let timeout = Duration::from_millis(timeout_ms);
        block_on(async move {
            transport
                .link_request(&link_handle.link_id, &path, &data, timeout)
                .await
                .map_err(map_transport_err)
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = (link_handle, path, data, timeout_ms);
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

#[cfg(feature = "_reticulum-module")]
fn map_transport_err(e: TransportError) -> crate::EdgeBindingsError {
    match e {
        TransportError::Unreachable(_) => crate::EdgeBindingsError::NotFound,
        TransportError::Config(_) => crate::EdgeBindingsError::InvalidArgument,
        // Timeout / Io / BodyTooLarge collapse to the typed Transport
        // error class — the bindings caller distinguishes via the
        // typed exception class on the language side.
        _ => crate::EdgeBindingsError::Transport,
    }
}

/// Block on a future from a sync UniFFI shell. Mirrors the
/// `block_on_runtime` helper in `uniffi_impl.rs` — uses the host's
/// current tokio runtime via `block_in_place` when available, else
/// builds a transient single-thread runtime.
#[allow(dead_code)]
fn block_on<F, T>(fut: F) -> Result<T, crate::EdgeBindingsError>
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
            .map_err(|_| crate::EdgeBindingsError::Internal)?;
        rt.block_on(fut)
    }
}
