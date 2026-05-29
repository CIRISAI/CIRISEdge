// `needless_pass_by_value` — every UDL-exported function MUST match
// the generated signature (which always passes records by value).
#![allow(clippy::needless_pass_by_value)]

//! UniFFI Routing-table bindings — v0.15.0 (CIRISEdge#33).
//!
//! Exposes Reticulum's routing-tier internals — paths, blackhole
//! (operator deny-list), rate limits, tunnels, in-flight announces,
//! and the reverse routing table — to the Network screen + the
//! federation-maintainer diagnostics surface.
//!
//! # Async posture
//!
//! Sync free functions on the UniFFI side. Reads that need to consult
//! the underlying `ReticulumTransport` (whose state machine is
//! tokio-async) block on the host's tokio runtime via the
//! v0.13.0 `block_on_runtime` pattern (mirrored from
//! `uniffi_impl_links.rs`). Mutations (`routing_blackhole_add` /
//! `routing_blackhole_remove`) operate on the in-memory
//! `Arc<RwLock<...>>` without touching async — they're sync inside.
//!
//! # Edge transport plumbing
//!
//! The routing surface needs the concrete
//! `Arc<ReticulumTransport>` (routing-table state is Reticulum-
//! specific). Reuses the `EdgeBuilder::reticulum_transport` typed-
//! handle path the v0.14.0 Links FFI already wired in; `None` →
//! `Unsupported`.
//!
//! # Upstream Leviculum gaps
//!
//! Per the v0.15.0 brief, several read methods return empty Vecs in
//! v0.15.0 because the underlying `NodeCore::*_table_entries`
//! accessors are `pub(crate)` from `reticulum-std` (or never exposed,
//! in the case of `tunnels` and `reverse_table`). The wire shape is
//! pinned so a v0.15.x patch can flip on real values without
//! binding-side churn. See per-method docs on
//! `ReticulumTransport::routing_*` for the gap notes.

#[cfg(feature = "_reticulum-module")]
use crate::transport::TransportError;

#[allow(unused_imports)]
use crate::ffi::uniffi_impl::install_edge_handle;

// ─── Edge / transport resolution helpers ────────────────────────────

#[cfg(feature = "_reticulum-module")]
fn current_reticulum(
) -> Result<std::sync::Arc<crate::transport::reticulum::ReticulumTransport>, crate::EdgeBindingsError>
{
    let edge = crate::ffi::uniffi_impl::current_edge()?;
    edge.reticulum_transport()
        .ok_or(crate::EdgeBindingsError::Unsupported)
}

// ─── #33 Paths ──────────────────────────────────────────────────────

pub fn routing_path_table(
    max_hops: Option<u32>,
) -> Result<Vec<crate::EdgeRoutingPathEntry>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_path_table(max_hops).await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = max_hops;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_path_to(
    destination_hash: Vec<u8>,
) -> Result<Option<crate::EdgeRoutingPathEntry>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_path_to(&destination_hash).await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = destination_hash;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_path_request(
    destination_hash: Vec<u8>,
    on_interface: Option<String>,
) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move {
            transport
                .routing_path_request(&destination_hash, on_interface.as_deref())
                .await
                .map_err(map_transport_err)
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = (destination_hash, on_interface);
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_path_drop(destination_hash: Vec<u8>) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move {
            transport
                .routing_path_drop(&destination_hash)
                .await
                .map_err(map_transport_err)
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = destination_hash;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_path_drop_via(
    transport_identity_hash: Vec<u8>,
) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move {
            transport
                .routing_path_drop_via(&transport_identity_hash)
                .await
                .map_err(map_transport_err)
        })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = transport_identity_hash;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── #33 Blackhole ──────────────────────────────────────────────────

pub fn routing_blackhole_list() -> Result<Vec<crate::EdgeBlackholeEntry>, crate::EdgeBindingsError>
{
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        Ok(transport.routing_blackhole_list())
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_blackhole_add(
    identity_hash: Vec<u8>,
    until: Option<String>,
    reason: Option<String>,
) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        transport
            .routing_blackhole_add(&identity_hash, until.as_deref(), reason.as_deref())
            .map_err(map_transport_err)
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = (identity_hash, until, reason);
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_blackhole_remove(identity_hash: Vec<u8>) -> Result<(), crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        transport
            .routing_blackhole_remove(&identity_hash)
            .map_err(map_transport_err)
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        let _ = identity_hash;
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── #33 Rate-limit observation ─────────────────────────────────────

pub fn routing_rate_table() -> Result<Vec<crate::EdgeRateEntry>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_rate_table().await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── #33 Transport state ────────────────────────────────────────────

pub fn routing_transport_uptime() -> Result<u64, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        Ok(transport.routing_transport_uptime())
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_transport_id() -> Result<Vec<u8>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        Ok(transport.routing_transport_id())
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_tunnels() -> Result<Vec<crate::EdgeTunnelInfo>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_tunnels().await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_announce_table() -> Result<Vec<crate::EdgeInFlightAnnounce>, crate::EdgeBindingsError>
{
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_announce_table().await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

pub fn routing_reverse_table() -> Result<Vec<crate::EdgeReverseEntry>, crate::EdgeBindingsError> {
    #[cfg(feature = "_reticulum-module")]
    {
        let transport = current_reticulum()?;
        block_on(async move { Ok(transport.routing_reverse_table().await) })
    }
    #[cfg(not(feature = "_reticulum-module"))]
    {
        Err(crate::EdgeBindingsError::Unsupported)
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

#[cfg(feature = "_reticulum-module")]
fn map_transport_err(e: TransportError) -> crate::EdgeBindingsError {
    match e {
        TransportError::Unreachable(_) => crate::EdgeBindingsError::NotFound,
        TransportError::Config(_) => crate::EdgeBindingsError::InvalidArgument,
        // PeerBlackholed collapses into the typed Transport class on
        // the FFI side; the calling language differentiates via the
        // structured error message body (the operator already knows
        // the rule's identity_hash + reason from blackhole_list).
        _ => crate::EdgeBindingsError::Transport,
    }
}

#[cfg(feature = "_reticulum-module")]
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
