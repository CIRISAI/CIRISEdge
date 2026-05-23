//! PyO3 bindings — Python-facing Edge surface.
//!
//! # CIRIS 3.0 cohabitation shape (CIRISEdge#16)
//!
//! Edge's PyO3 surface is the runtime entry point for the in-process
//! cohabitation pattern (CIRISPersist#85 EPIC). The agent (Python)
//! plus CIRISNodeCore + CIRISLensCore + edge + persist run in one
//! process, sharing **one** persist `Engine` and **one** edge
//! `Edge`. The agent constructs the `Edge` via [`init_edge_runtime`]
//! and hands it to the co-resident consumers' bootstrap entries
//! (`ciris_node_core.install_from_dispatch(node_core_dispatch, edge)`,
//! lens equivalent).
//!
//! The constructor reuses the agent's already-bootstrapped persist
//! engine — it does NOT re-open the DB or re-load the keyring.
//! Path 2 (the locked design on issue #16): pull the
//! federation_directory / outbound_queue / keyring_signer Rust-level
//! accessors persist#95 ships in v2.0.2's [`PyEngine`], match the
//! [`BackendDispatch`] variant, and compose them into an `Edge` via
//! the existing [`EdgeBuilder`].
//!
//! # PyEdge wrapper rationale
//!
//! [`Edge`] holds `Arc<dyn Transport>` + `Arc<Mutex<HashMap<...>>>`
//! and is not `Clone`. Rather than place `#[pyclass]` on `Edge`
//! itself (which would leak `pyo3` into `edge.rs` and force a
//! conditional-compilation tangle on a load-bearing core type), the
//! Python-reachable handle is a thin `PyEdge` wrapper holding
//! `Arc<Edge>`. Sibling cdylibs reach the underlying runtime via
//! [`PyEdge::edge_handle`] — the same Option-B pattern persist's
//! `PyEngine::node_core_service` uses, see
//! `ciris_persist::ffi::pyo3::PyEngine::node_core_service` for the
//! ratified shape.
//!
//! # AV-17 invariant
//!
//! The keyring signer arrives via [`PyEngine::keyring_signer`] as
//! `Arc<dyn HardwareSigner>` — the federation seed has already been
//! loaded by the host's keyring bootstrap and never enters edge's
//! process memory in raw form (`docs/THREAT_MODEL.md` §10).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::wrap_pyfunction;

use ciris_persist::ffi::pyo3::PyEngine;
use ciris_persist::BackendDispatch;

use crate::edge::Edge;
use crate::identity::LocalSigner;
use crate::outbound::OutboundHandle;
#[cfg(feature = "transport-reticulum")]
use crate::transport::reticulum::{ReticulumAuth, ReticulumTransport, ReticulumTransportConfig};
use crate::transport::Transport;
use crate::verify::{HybridPolicy, RootingDirectory, VerifyDirectory};

/// Wire-format schema versions edge supports. Strict allowlist (AV-7);
/// out-of-set values reject at the verify pipeline. Mirrors persist's
/// `SUPPORTED_SCHEMA_VERSIONS` export.
const SUPPORTED_SCHEMA_VERSIONS: [&str; 1] = ["1.0.0"];

/// Crate version (compile-time). Surfaces as `ciris_edge.__version__`.
const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Python-reachable handle wrapping `Arc<Edge>`. Constructed by
/// [`init_edge_runtime`]; sibling cdylibs (CIRISNodeCore /
/// CIRISLensCore) accept a `PyRef<PyEdge>` and call
/// [`PyEdge::edge_handle`] Rust-side to extract the shared runtime
/// without re-marshalling through Python.
///
/// See module-level doc for the cohabitation pattern rationale.
#[pyclass(name = "Edge", module = "ciris_edge")]
pub struct PyEdge {
    /// The shared edge runtime. `Arc` so sibling cdylibs can clone
    /// and own a reference for the duration of their dispatch loops.
    inner: Arc<Edge>,
}

impl PyEdge {
    /// Rust-level accessor — the Option-B sibling-cdylib hand-off.
    /// CIRISNodeCore's / CIRISLensCore's `#[pyfunction]` bootstrap
    /// wrappers call this via `PyRef<PyEdge>` to extract the shared
    /// runtime without crossing the Python boundary.
    ///
    /// Mirrors `ciris_persist::ffi::pyo3::PyEngine::node_core_service`
    /// exactly — plain `pub fn`, not a `#[pymethod]`, because the
    /// return type is a Rust-only `Arc<Edge>`. Cheap: one `Arc` clone.
    #[must_use]
    pub fn edge_handle(&self) -> Arc<Edge> {
        self.inner.clone()
    }
}

#[pymethods]
impl PyEdge {
    /// Crate version of the edge runtime backing this handle. Surface
    /// for diagnostics + cross-version compatibility assertions on
    /// the Python side (`ciris_edge.Edge.crate_version()`).
    #[staticmethod]
    fn crate_version() -> &'static str {
        VERSION
    }
}

/// Consumer-side hybrid PQC acceptance policy choice, exposed as a
/// string kwarg on [`init_edge_runtime`]. Mirrors persist's
/// `HybridPolicy` discriminants; kept as `&str` rather than a
/// `#[pyclass]` to keep the surface minimal — the policy choice is
/// a single switch the host configures once.
///
/// The `soft` variant takes a window in seconds via the
/// `soft_freshness_window_seconds` kwarg on the constructor.
fn parse_hybrid_policy(s: &str, soft_freshness_window_seconds: u64) -> PyResult<HybridPolicy> {
    match s {
        "strict" | "Strict" => Ok(HybridPolicy::Strict),
        "soft" | "SoftFreshness" | "soft_freshness" => Ok(HybridPolicy::SoftFreshness {
            window: Duration::from_secs(soft_freshness_window_seconds),
        }),
        "ed25519_fallback" | "Ed25519Fallback" | "fallback" => Ok(HybridPolicy::Ed25519Fallback),
        other => Err(PyValueError::new_err(format!(
            "unknown hybrid_policy {other:?}; expected one of \
             \"strict\" / \"soft\" / \"ed25519_fallback\""
        ))),
    }
}

/// Construct an [`Edge`] from the host's shared persist [`PyEngine`].
///
/// This is the CIRIS 3.0 cohabitation entry point (CIRISEdge#16,
/// merge blocker for CIRISPersist#85). The Python agent calls this
/// **once** during process bootstrap, after constructing its
/// `ciris_persist.Engine`, and hands the returned [`PyEdge`] to
/// CIRISNodeCore + CIRISLensCore bootstrap functions.
///
/// # Rust-side dispatch (Path 2 of issue #16)
///
/// - Calls [`PyEngine::federation_directory`] → matches
///   [`BackendDispatch`] → wraps the concrete backend `Arc` as both
///   `Arc<dyn VerifyDirectory>` and `Arc<dyn RootingDirectory>` via
///   the blanket impls in `crate::verify`. (Same `Arc` — both traits
///   are implemented on the same concrete type.)
/// - Calls [`PyEngine::outbound_queue`] → matches
///   [`BackendDispatch`] → wraps as `Arc<dyn OutboundHandle>` via
///   the blanket impl in `crate::outbound`.
/// - Calls [`PyEngine::keyring_signer`] → extracts the
///   `Arc<dyn HardwareSigner>` + `Option<Arc<dyn PqcSigner>>` +
///   `key_id` and wraps them in edge's own [`LocalSigner`]. The
///   keyring identity is NOT re-bootstrapped — the cohabitation
///   invariant is "one keyring identity per host"
///   (`docs/COHABITATION.md` rule 1).
/// - Builds a [`ReticulumTransport`] with [`ReticulumAuth`] wiring
///   the signer + rooting directory + the configured hybrid policy.
///   The transport's authenticated cold-start path (CIRISEdge#15,
///   AV-42 closure) is then live.
/// - Assembles `Edge::builder().directory(..).queue(..).signer(..)
///   .transport(..).build()` and returns the [`PyEdge`] wrapper.
///
/// # Python signature
///
/// ```python
/// edge = ciris_edge.init_edge_runtime(
///     engine,                       # ciris_persist.Engine
///     identity_path="/var/lib/ciris/transport.id",
///     listen_addr="0.0.0.0:4242",
///     bootstrap_peers=["1.2.3.4:4242"],
///     announce_interval_seconds=300,
///     local_epoch=0,
///     hybrid_policy="strict",
/// )
/// ```
///
/// # AV-17 invariant
///
/// The federation seed never crosses the FFI boundary — only the
/// `Arc<dyn HardwareSigner>` handle does, and only between sibling
/// cdylibs at the Rust level. The transport-tier Reticulum identity
/// at `identity_path` is a separate dual-key identity generated by
/// the transport itself (`src/transport/reticulum.rs` §"Identity
/// model").
#[cfg(feature = "transport-reticulum")]
#[pyfunction]
#[pyo3(signature = (
    engine,
    identity_path,
    listen_addr = "0.0.0.0:4242",
    bootstrap_peers = vec![],
    announce_interval_seconds = 300,
    local_epoch = 0,
    hybrid_policy = "strict",
    soft_freshness_window_seconds = 60,
))]
#[allow(clippy::too_many_arguments, clippy::needless_pass_by_value)]
fn init_edge_runtime(
    py: Python<'_>,
    engine: PyRef<'_, PyEngine>,
    identity_path: &str,
    listen_addr: &str,
    bootstrap_peers: Vec<String>,
    announce_interval_seconds: u64,
    local_epoch: u64,
    hybrid_policy: &str,
    soft_freshness_window_seconds: u64,
) -> PyResult<PyEdge> {
    let hybrid_policy = parse_hybrid_policy(hybrid_policy, soft_freshness_window_seconds)?;

    // ── Step 1: extract the substrate handles from the shared PyEngine.
    //
    // persist#95's Option-B `pub fn` accessors return Rust-only types —
    // call them through the `PyRef<PyEngine>` deref without crossing
    // the Python boundary.
    let directory_dispatch = engine.federation_directory();
    let queue_dispatch = engine.outbound_queue();
    let signer_handle = engine.keyring_signer();

    // ── Step 2: BackendDispatch → edge adapter Arcs.
    //
    // Both traits (`FederationDirectory`, `OutboundQueue`) are
    // implemented on the same concrete backend type. The blanket
    // impls in `crate::verify` + `crate::outbound` lift any
    // `FederationDirectory`/`OutboundQueue` into the dyn-compatible
    // adapters edge holds. We extract the inner `Arc<...Backend>`
    // from the dispatch enum and unsize-coerce to the trait objects.
    // Edge's `pyo3` feature pins `ciris-persist/pyo3`, which in turn
    // pins `ciris-persist/postgres`; combined with the always-on
    // `ciris-persist/sqlite` from the default dep features, both
    // `BackendDispatch` variants are always reachable here. The match
    // is exhaustive over the enum's two `#[cfg]`-gated variants under
    // this feature combination.
    let (verify_dir, rooting_dir): (Arc<dyn VerifyDirectory>, Arc<dyn RootingDirectory>) =
        match directory_dispatch {
            BackendDispatch::Postgres(b) => (b.clone(), b),
            BackendDispatch::Sqlite(b) => (b.clone(), b),
        };
    let queue: Arc<dyn OutboundHandle> = match queue_dispatch {
        BackendDispatch::Postgres(b) => b,
        BackendDispatch::Sqlite(b) => b,
    };

    // ── Step 3: keyring signer parts → edge's LocalSigner.
    //
    // persist's `KeyringSignerHandle` already contains the cloned
    // `Arc<dyn HardwareSigner>` + optional `Arc<dyn PqcSigner>` the
    // host loaded; wrap them in edge's local-signer struct without
    // re-bootstrapping the keyring (AV-17 / COHABITATION rule 1).
    let signer = Arc::new(LocalSigner {
        key_id: signer_handle.key_id.clone(),
        classical: signer_handle.signer.clone(),
        pqc: signer_handle.pqc_signer.clone(),
    });

    // ── Step 4: parse the Reticulum transport config.
    let listen_addr = listen_addr
        .parse()
        .map_err(|e| PyValueError::new_err(format!("listen_addr parse: {e}")))?;
    let bootstrap_peers = bootstrap_peers
        .iter()
        .map(|s| {
            s.parse().map_err(|e| {
                PyValueError::new_err(format!("bootstrap_peers entry {s:?} parse: {e}"))
            })
        })
        .collect::<PyResult<Vec<_>>>()?;
    let mut transport_config =
        ReticulumTransportConfig::new(PathBuf::from(identity_path), signer.key_id.clone());
    transport_config.listen_addr = listen_addr;
    transport_config.bootstrap_peers = bootstrap_peers;
    transport_config.announce_interval = Duration::from_secs(announce_interval_seconds);
    transport_config.local_epoch = local_epoch;

    let auth = ReticulumAuth {
        signer: Some(signer.clone()),
        rooting: Some(rooting_dir.clone()),
        resolver: None,
        hybrid_policy,
    };

    // ── Step 5: build the transport + Edge under the host runtime.
    //
    // Construction is async (Reticulum node start + identity load).
    // `Python::detach` (pyo3 0.28 rename of the older `allow_threads`)
    // releases the GIL while the persist runtime (held by the shared
    // `PyEngine`) drives the future to completion — the host's tokio
    // runtime owns the worker threads edge's transport schedules on.
    let runtime = ciris_persist::current_runtime_handle()
        .ok_or_else(|| PyRuntimeError::new_err("persist tokio runtime unavailable"))?;
    let transport: Arc<dyn Transport> = py.detach(|| {
        runtime
            .block_on(async {
                ReticulumTransport::new(transport_config, auth)
                    .await
                    .map(|t| Arc::new(t) as Arc<dyn Transport>)
            })
            .map_err(|e| PyRuntimeError::new_err(format!("ReticulumTransport::new: {e}")))
    })?;

    // ── Step 6: assemble the Edge.
    let edge = Edge::builder()
        .directory(verify_dir)
        .queue(queue)
        .signer(signer)
        .transport(transport)
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Edge::build: {e}")))?;

    Ok(PyEdge {
        inner: Arc::new(edge),
    })
}

/// Top-level Python module entry point. `import ciris_edge` triggers
/// this; per-symbol bindings register here as they land.
#[pymodule]
fn ciris_edge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", VERSION)?;
    m.add(
        "SUPPORTED_SCHEMA_VERSIONS",
        SUPPORTED_SCHEMA_VERSIONS.to_vec(),
    )?;

    // PyEdge — the cohabitation handle wrapping Arc<Edge>.
    m.add_class::<PyEdge>()?;

    // init_edge_runtime — the CIRISEdge#16 / CIRIS-3.0 cohabitation
    // constructor. Only registered when the Reticulum transport is
    // compiled in — that is the canonical wire for the cohabitation
    // pattern; an HTTP-only build would expose a different entry
    // point in a future revision.
    #[cfg(feature = "transport-reticulum")]
    m.add_function(wrap_pyfunction!(init_edge_runtime, m)?)?;

    Ok(())
}

#[cfg(test)]
#[cfg(feature = "transport-reticulum")]
mod tests {
    //! Rust-side smoke gates (CIRISEdge#16 Bar): pin the
    //! Option-B sibling-cdylib hand-off shape that the cohabiting
    //! NodeCore / LensCore PyO3 bindings consume, and exercise the
    //! `BackendDispatch` extraction + adapter-trait dispatch on a
    //! Sqlite-backed test fixture so the persist#95 → edge surface
    //! is at minimum compiled + invoked once in CI.
    //!
    //! A full Python-driven `init_edge_runtime` call requires a
    //! linked-against-libpython test binary AND a host-process
    //! `Engine(...)` constructed under the `extension-module` build,
    //! which is environment-specific (the cross-cdylib integration
    //! lives in the downstream agent test suite, not here). The
    //! lighter Rust-only checks below give the same coverage of
    //! edge's contribution.
    use super::*;
    use crate::transport::{InboundFrame, TransportId, TransportSendOutcome};

    /// Stub transport — exercises the [`EdgeBuilder`] build path
    /// without binding a real socket. Used by
    /// [`edge_assembles_from_persist_2x_handles`] below.
    struct NoopTransport;

    #[async_trait::async_trait]
    impl Transport for NoopTransport {
        fn id(&self) -> TransportId {
            TransportId("noop")
        }
        async fn send(
            &self,
            _destination_key_id: &str,
            _envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, crate::TransportError> {
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _tx: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), crate::TransportError> {
            std::future::pending::<()>().await;
            Ok(())
        }
    }

    /// Compile-time gate: the Rust-side accessor signature must be
    /// `pub fn edge_handle(&self) -> Arc<Edge>` — the shape
    /// CIRISNodeCore's / CIRISLensCore's PyO3 bootstrap wrappers
    /// expect (Option-B sibling-cdylib pattern, mirroring
    /// `ciris_persist::ffi::pyo3::PyEngine::node_core_service`). If
    /// this stops type-checking, the cross-crate cohabitation
    /// contract has drifted.
    #[test]
    fn edge_handle_signature_is_stable() {
        fn _assert_signature(p: &PyEdge) -> Arc<Edge> {
            p.edge_handle()
        }
        let _ = _assert_signature as fn(&PyEdge) -> Arc<Edge>;
    }

    /// `BackendDispatch::Sqlite` Arc casts cleanly to all three of
    /// edge's adapter trait objects (`Arc<dyn VerifyDirectory>`,
    /// `Arc<dyn RootingDirectory>`, `Arc<dyn OutboundHandle>`) via
    /// the blanket impls in `crate::verify` / `crate::outbound`.
    /// This is the same coercion `init_edge_runtime` runs after
    /// `PyEngine::federation_directory()` / `outbound_queue()`.
    #[tokio::test]
    async fn backend_dispatch_sqlite_casts_to_edge_adapter_traits() {
        use ciris_persist::prelude::{EdgeOutboundQueueSqlite, FederationDirectorySqlite};

        let dir_arc = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open federation directory sqlite in-memory");
        let _: Arc<dyn VerifyDirectory> = dir_arc.clone();
        let _: Arc<dyn RootingDirectory> = dir_arc.clone();

        let q_arc = EdgeOutboundQueueSqlite::open(":memory:")
            .await
            .expect("open outbound queue sqlite in-memory");
        let _: Arc<dyn OutboundHandle> = q_arc;
    }

    /// End-to-end Rust-side: build an `Edge` from the same handle
    /// shapes persist#95's accessors return, without spinning up a
    /// `PyEngine`. This is the inner half of `init_edge_runtime` —
    /// once `PyEngine::federation_directory()` /
    /// `outbound_queue()` / `keyring_signer()` are unpacked, the
    /// remaining work is the [`EdgeBuilder`] composition pinned
    /// here.
    ///
    /// Uses the HTTP transport rather than Reticulum so the test
    /// stays hermetic — Reticulum binds a TCP listen socket on
    /// construction. The `Transport` trait surface edge consumes
    /// is identical between the two; this exercises the
    /// composition shape `init_edge_runtime` follows.
    #[tokio::test]
    async fn edge_assembles_from_persist_2x_handles() {
        use ciris_keyring::{Ed25519SoftwareSigner, MlDsa65SoftwareSigner};
        use ciris_persist::prelude::{EdgeOutboundQueueSqlite, FederationDirectorySqlite};

        let directory = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open federation directory");
        let queue = EdgeOutboundQueueSqlite::open(":memory:")
            .await
            .expect("open outbound queue");

        // Synthesize a signer Arc pair shaped exactly like the
        // `KeyringSignerHandle` persist#95 returns. The real
        // cohabitation path consumes the host's already-loaded
        // identity; for the smoke test, software signers are a
        // surface-equivalent stand-in (`AV-17` heap-scan property is
        // unchanged — software signers are the development-tier
        // descriptor).
        let classical = Arc::new(Ed25519SoftwareSigner::new("test-edge-cohabitation"));
        let pqc = Arc::new(MlDsa65SoftwareSigner::new("test-edge-cohabitation-pqc"));
        let signer = Arc::new(LocalSigner {
            key_id: "test-edge-cohabitation".into(),
            classical,
            pqc: Some(pqc),
        });

        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);

        let edge = Edge::builder()
            .directory(directory)
            .queue(queue)
            .signer(signer)
            .transport(transport)
            .build()
            .expect("Edge::build from persist 2.x handles");

        // The PyEdge Rust-side hand-off shape — `Arc<Edge>` flows
        // out of `edge_handle()` for the sibling-cdylib consumers.
        let py_edge = PyEdge {
            inner: Arc::new(edge),
        };
        let handle: Arc<Edge> = py_edge.edge_handle();
        assert!(Arc::strong_count(&handle) >= 2);
    }
}
