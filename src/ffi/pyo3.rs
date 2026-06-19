//! PyO3 bindings — Python-facing Edge surface.
//!
//! # CIRIS 3.0 cohabitation shape (CIRISEdge#16, CIRISEdge#22)
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
//!
//! # v0.9.2 — PyCapsule cohabitation (CIRISPersist#109)
//!
//! v0.9.1's `init_edge_runtime` accepted `engine: PyRef<'_, PyEngine>`
//! and called persist's Rust-level Option-B `pub fn` accessors via the
//! `PyEngine` deref. That works for the in-process tests (both
//! pyclasses linked into one binary) but FAILS in real cross-wheel
//! cohabitation: PyO3 `#[pyclass]` registration is per-extension-module,
//! so `ciris_persist.abi3.so` and `ciris_edge.abi3.so` each see their
//! own `PyTypeInfo` for `PyEngine` and the cross-module isinstance
//! check rejects the argument with
//! `'Engine' object is not an instance of 'Engine'`.
//!
//! v0.9.2 takes `engine: Bound<'_, PyAny>` and pulls the substrate
//! handles via `PyCapsule`-typed `#[pymethod]`s persist 2.7.0 added
//! (`federation_directory_capsule`, `outbound_queue_capsule`,
//! `keyring_signer_capsule`). The capsule is an opaque pointer with a
//! producer-set name tag — Python's type-identity machinery isn't
//! involved at all on the cross-module path. See [`extract_capsule`]
//! for the safety justification.
//!
//! # v0.10.1 — runtime_handle_capsule (CIRISPersist#111, CIRISEdge#22)
//!
//! v0.10.0 shipped with the v0.9.2 capsule pattern for the three
//! substrate handles, but still called `ciris_persist::current_runtime_handle()`
//! (a pure-Rust `pub fn` over persist's `ENGINE_SINGLETON` static) to
//! acquire the tokio runtime. That static is duplicated per-cdylib at
//! link time — when persist ships as `ciris_persist.abi3.so` AND is
//! linked into `ciris_edge.abi3.so` as a Cargo rlib, edge's copy of
//! the static is NEVER populated even after the persist `.so`'s copy
//! is. The cross-cdylib production failure: CIRISConformance v0.10.0's
//! cohabitation gate caught this with `'persist tokio runtime
//! unavailable'` at `init_handshake` across all 6 (3 OS × 2 backend)
//! cells.
//!
//! v0.10.1 consumes persist v2.8.0's `runtime_handle_capsule` — the
//! same `PyCapsule`-opaque-pointer pattern that closes the cross-module
//! PyClass-identity issue (#109), now applied to the **statics** layer.
//! The capsule sources the handle from `self.runtime.handle().clone()`
//! inside `PyEngine::runtime_handle_capsule_py`, so edge's view of
//! `ENGINE_SINGLETON` is irrelevant — the handle hops the FFI via
//! opaque pointer with a producer-set name tag, identical to the
//! v0.9.2 contract for the three substrate handles. End-to-end
//! cohabitation cohabitation contract closure: persist#109 + #111 +
//! edge v0.10.1 = capsule-only handoff for every load-bearing
//! cross-cdylib handle.
//!
//! Required floor: `ciris-persist >= 2.8.0` (Cargo `tag = "v2.8.0"`,
//! pyproject `ciris-persist>=2.8.0,<3`). Older persist versions do not
//! expose `runtime_handle_capsule`; init_edge_runtime emits a typed
//! `PyRuntimeError` pointing at the upgrade path.
//!
//! # v0.16.1 cherry-pick — local_signer_capsule (CIRISPersist#119, CIRISEdge#43)
//!
//! v0.13.0 / v0.14.0 / v0.15.0 / v0.16.0 read the Reticulum-transport
//! federation Ed25519 pubkey from the `keyring_signer_capsule` (the
//! hardware-rooted hybrid signer). Under
//! `keyring_storage_kind = hardware_hsm_only` the hardware path emits
//! a 65-byte hybrid pubkey (e.g. TPM P-256), and
//! `ReticulumTransport::new` correctly rejected with `"federation
//! Ed25519 pubkey must be 32 bytes, got 65"` — blocking
//! CIRISAgent 2.9.4's cohabitation-init handshake on every hardware
//! deployment. The fix landed on the `v0.13.x-line` branch as v0.13.1
//! but never reached main (v0.14.0–v0.16.0 still carried the broken
//! init path); v0.16.1 cherry-picks the fix onto the v0.16-line so
//! downstream consumers `pip install ciris-edge>=0.14.0` get a working
//! cohab.
//!
//! v0.16.1 consumes persist v3.1.1's `local_signer_capsule` — a sixth
//! `PyCapsule` accessor wrapping `Arc<ciris_persist::signing::LocalSigner>`
//! (a software Ed25519 identity loaded from the agent's
//! `local_key_path`). The capsule is wrapped in persist's
//! `LocalSignerHardwareAdapter` (which implements
//! `ciris_keyring::HardwareSigner` honestly with a 32-byte raw Ed25519
//! `public_key()`) and threaded into the [`ReticulumAuth.signer`]
//! field. The hot-path scrub-signing surface
//! (`Edge::builder().signer(...)` → `Edge::send_durable` envelope
//! signing) stays on the hardware-rooted `keyring_signer_capsule` —
//! that is the correct primitive for forensic envelope signing.
//!
//! Two capsules, two roles, one engine: keyring_signer drives
//! hot-path scrub envelopes; local_signer drives transport-link
//! identity. AV-17 unchanged — neither seed crosses the FFI; both
//! signers arrive as `Arc<dyn Trait>` opaque pointers.
//!
//! When `local_signer_capsule` raises the typed
//! `ValueError("local_signer_unavailable")` (older cohab-init paths
//! predating persist v2.12.0 / #112), init_edge_runtime falls back to
//! the existing v0.13.0 behavior — keyring_signer drives BOTH the
//! envelope and transport-identity surfaces. A warning log names the
//! upgrade path. Production hardware-keyring deployments MUST be on
//! persist v3.1.1+ with `from_shared_with_local` for cohab init to
//! succeed; the fallback preserves binary compatibility for
//! still-on-3.0.x consumers using the software-only keyring path
//! (where the 32-byte Ed25519 invariant happens to hold from the
//! keyring signer side).
//!
//! # v0.16.1 — blackhole_rules durable flip (CIRISPersist#120, CIRISEdge#33)
//!
//! v0.15.0 shipped the routing-table FFI with an in-memory
//! `Arc<RwLock<HashMap<Vec<u8>, BlackholeRecord>>>` backing the
//! operator-configured deny-list. The wire shape was the v0.15.0 lock;
//! the storage was process-restart-lossy. v0.15.0's acceptance
//! criterion required durability — landing depended on persist
//! shipping a `BlackholeRules` trait + table.
//!
//! Persist v3.2.0 (CIRISPersist#120) ships the sibling `BlackholeRules`
//! trait (`blackhole_list` / `_upsert` / `_remove` / `_record_hit` /
//! `_prune_expired`) + V052 `cirislens.blackhole_rules` table; v0.16.1
//! consumes it. The `Arc<dyn BlackholeRules>` is derived from the same
//! `BackendDispatch` arm `outbound_queue_capsule` already produces —
//! no new capsule needed. Operator-set rules survive process restarts;
//! the hot-path send check + `record_hit` increment route through the
//! same backend pool the rest of edge already uses.
//!
//! # Unsafe carve-out
//!
//! WHY: `PyCapsule` extraction is inherently unsafe — `cap.reference::<T>()`
//! reinterprets the capsule's opaque pointer as `&T` with no
//! compile-time check that the producer's wrapped type matches.
//!
//! WHERE: ONLY the [`extract_capsule`] helper below. The crate-level
//! `#![deny(unsafe_code)]` (relaxed from `forbid` in v0.9.2) rejects
//! `unsafe` everywhere else; the helper opts in via
//! `#[allow(unsafe_code)]` on the function item.
//!
//! INVARIANT: persist 2.7.0+ guarantees the capsule name tags + wrapped
//! types per `ciris_persist::ffi::pyo3` docblocks. Edge's `Cargo.toml`
//! pins `ciris-persist = "2"` with `tag = "v2.7.0"`, and pyproject.toml
//! pins `ciris-persist>=2.7.0,<3` so any pip install pulls a persist
//! that carries the contract. Persist's semver-2 commitment is what
//! makes the unsafe `reference()` call sound across the wire.
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

use pyo3::exceptions::{PyRuntimeError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAnyMethods, PyCapsule, PyCapsuleMethods};
use pyo3::wrap_pyfunction;
#[cfg(test)]
use tokio::runtime::Handle as RuntimeHandle;
use tokio::sync::Mutex;

use ciris_persist::BackendDispatch;

use crate::edge::Edge;
use crate::handler::{DurableOutcome, DurableStatus};
use crate::identity::LocalSigner;
use crate::messages::{InlineText, InlineTextDurable};
use crate::outbound::OutboundHandle;
#[cfg(feature = "transport-reticulum")]
use crate::transport::reticulum::{ReticulumAuth, ReticulumTransport, ReticulumTransportConfig};
#[cfg(test)]
use crate::transport::Transport;
use crate::verify::{HybridPolicy, RootingDirectory, VerifyDirectory};

// CIRISEdge#35 — stub-info gatherer entry point. Called by
// `src/bin/stub_gen.rs` to gather every `#[gen_stub_pyclass]` /
// `#[gen_stub_pymethods]` / `#[gen_stub_pyfunction]` item registered
// via `inventory::submit!` and emit the merged `.pyi` to
// `python/ciris_edge/__init__.pyi`. The macro expansion produces
// `pub fn stub_info() -> pyo3_stub_gen::Result<pyo3_stub_gen::StubInfo>`.
//
// v3.0.0 (CIRISEdge#89) — pyo3-stub-gen has no pyo3 0.29-compatible
// release as of v3.0.0; the dep is dropped from Cargo.toml's `pyo3`
// feature list. Edge has zero active `#[gen_stub_*]` attributes
// anywhere in `src/` (every match is in a doc comment), so this
// gatherer registered an empty set; the existing `__init__.pyi`
// stays as the hand-maintained consumer-facing surface. A no-op
// `stub_info()` keeps `src/bin/stub_gen.rs` compiling — restore the
// macro invocation here when pyo3-stub-gen ships a 0.29 cut.
//
// pyo3_stub_gen::define_stub_info_gatherer!(stub_info);
pub fn stub_info() -> Result<NoopStubInfo, Box<dyn std::error::Error>> {
    Ok(NoopStubInfo)
}

/// v3.0.0 (CIRISEdge#89) — placeholder for the
/// `pyo3_stub_gen::StubInfo` shape `stub_gen` calls `.generate()` on.
/// While pyo3-stub-gen catches up to pyo3 0.29, this no-op preserves
/// the `stub_gen` binary's compile shape: it does nothing on
/// `generate()` and prints a notice. The existing
/// `python/ciris_edge/__init__.pyi` is the source of truth for the
/// Python type surface; CI's stub-drift gate is satisfied as long as
/// it is not regenerated.
pub struct NoopStubInfo;

impl NoopStubInfo {
    /// Stand-in for `pyo3_stub_gen::StubInfo::generate`. No-op; the
    /// hand-maintained `__init__.pyi` is the source of truth until
    /// pyo3-stub-gen ships 0.29 support.
    pub fn generate(&self) -> Result<(), Box<dyn std::error::Error>> {
        eprintln!(
            "stub_gen: no-op (pyo3-stub-gen has no pyo3 0.29 release yet; \
             see CIRISEdge#89 + Cargo.toml comment near pyo3-stub-gen)"
        );
        Ok(())
    }
}

/// Wire-format schema versions edge supports. Strict allowlist (AV-7);
/// out-of-set values reject at the verify pipeline. Mirrors persist's
/// `SUPPORTED_SCHEMA_VERSIONS` export.
const SUPPORTED_SCHEMA_VERSIONS: [&str; 1] = ["1.0.0"];

/// Crate version (compile-time). Surfaces as `ciris_edge.__version__`.
/// Re-exported from [`crate::version::VERSION`] so the C FFI accessor
/// (`ciris_edge_version`), the Rust constant, and `__version__` all
/// share one source of truth (see CIRISPersist#189 — version exposure
/// for the agent Trust-page binary-refresh integrity check).
use crate::version::VERSION;

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
    /// ABI-stable async executor (CIRISPersist v3.13.0
    /// `executor_capsule_v1`). The vtable's `spawn` fn-ptr lives in
    /// `ciris_persist.abi3.so`, so dispatching through it runs the
    /// spawned future on persist's tokio runtime — closing the
    /// cross-cdylib tokio-aliasing class (CIRISEdge#58 / #59).
    /// `Arc` because [`PyDurableHandle`] /
    /// [`PyVerifiedFeedSubscription`] / etc. clone it for their own
    /// lifecycle. Replaces the pre-v1.1.8 `runtime: RuntimeHandle`
    /// field that exposed a `tokio::Handle` to consumer-side
    /// dispatch (the cross-tokio aliasing trap).
    executor: Arc<ciris_persist::ffi::executor_capsule::AsyncExecutor>,
    /// v2.1.0 (CIRISEdge#85 / CIRISLensCore#43) — the host persist
    /// `Engine` PyObject the agent passed to [`init_edge_runtime`].
    /// Re-exposed via the [`PyEdge::engine`] pymethod so cohabiting
    /// cdylibs (CIRISLensCore relay + client modes, future
    /// CIRISNodeCore extensions) can reach the **same** engine
    /// instance the host wired into edge.
    ///
    /// Each cohabiting cdylib carries its own per-wheel
    /// `ciris_persist::ffi::pyo3::current_rust_engine()` `OnceLock`
    /// static, so a non-host cdylib calling it gets `None` or a
    /// different instance — that's lens-core's #43 P0 bug. Re-exposing
    /// the engine via PyEdge gives every cohabiting cdylib a stable
    /// path to the host engine: extract capsules from it
    /// (`federation_directory_capsule`, etc.) for Rust-side handle
    /// handoff, or call its Python methods (`receive_and_persist`,
    /// `local_sign`) which dispatch cross-wheel correctly via Python's
    /// name-based method resolution.
    ///
    /// `None` only for the test-only `for_test` constructor (no engine
    /// in pure-Rust test contexts). Production `init_edge_runtime`
    /// always populates this with the caller-supplied engine.
    engine: Option<Py<PyAny>>,
    /// v0.19.3 (CIRISEdge#49) — when `init_edge_runtime` was invoked
    /// with `https_dev_self_signed=True`, this holds the
    /// `Arc<tempfile::TempDir>` whose path carries the minted
    /// `dev-self-signed-{key_id}-{cert,key}.pem` files. The HTTPS
    /// listener reads those files at bind time (which happens AFTER
    /// init_edge_runtime returns); if the TempDir Drops before then
    /// the files vanish and rustls fails to start the server.
    /// Lifetime is now tied to PyEdge, which lives for the duration
    /// of the Python-owned Edge handle. `None` for non-dev paths
    /// (operator-supplied cert paths persist independently).
    #[cfg(feature = "transport-http")]
    _dev_cert_tmpdir: Option<Arc<tempfile::TempDir>>,
    /// v2.4.0 (CIRISEdge#103) — shared-instance lease cleanup state.
    /// When `init_edge_runtime` won the SharedInstanceDirectory
    /// election (auto role) and spawned the heartbeat task, this
    /// carries the parts [`Self::close`] needs to release the lease
    /// cleanly: a shutdown signal for the heartbeat loop + the
    /// `(name, owner_pid, lease)` triple for
    /// `release_shared_instance_lease`.
    ///
    /// `Mutex` because `close()` takes `&self` (PyO3 / pyclass — no
    /// `&mut self` from Python without `pyclass(unsendable)`) and we
    /// need interior mutability to `take()` the contents on the
    /// first close. Idempotent across multiple close calls.
    ///
    /// `None` when:
    /// - shared-instance was not configured (`local_instance_name=None`)
    /// - the operator pinned `local_instance_role="client"` (no lease
    ///   held)
    /// - `local_instance_role="auto"` lost the election (sibling is
    ///   server; no lease held)
    /// - this is a `for_test` constructor
    #[cfg(feature = "transport-reticulum-local")]
    shared_instance_cleanup: std::sync::Mutex<Option<SharedInstanceCleanup>>,
}

/// v2.4.0 (CIRISEdge#103) — best-effort cleanup if the Python caller
/// let `PyEdge` get GC'd without calling [`PyEdge::close`]
/// explicitly. Mirrors the close() path: signal the heartbeat to
/// stop + release the lease, this time WITHOUT `py.detach` (Drop
/// runs without the GIL anyway). On any error path, the lease ages
/// out via the staleness window — Drop never panics.
#[cfg(feature = "transport-reticulum-local")]
impl Drop for PyEdge {
    fn drop(&mut self) {
        // Lock the cleanup state. If poisoned (a prior call panicked
        // inside the lock), or empty (already closed), skip.
        let Ok(mut guard) = self.shared_instance_cleanup.lock() else {
            return;
        };
        let Some(mut cleanup) = guard.take() else {
            return;
        };
        // Signal heartbeat task to stop. `send(()) -> Err(_)` only
        // when the receiver already dropped (task exited early); fine
        // to ignore.
        if let Some(tx) = cleanup.shutdown_tx.take() {
            let _ = tx.send(());
        }
        // Best-effort release. Errors logged (no propagation possible
        // from Drop). The persist Engine's tokio runtime is reached
        // via the executor capsule we still hold an Arc to — it lives
        // for as long as the host engine's PyObject does, which the
        // `self.engine` field still references.
        let directory = cleanup.directory;
        let lease = cleanup.lease;
        let instance_name_for_log = lease.instance_name.clone();
        let release_result = run_async(&self.executor, async move {
            directory.release_shared_instance_lease(&lease).await
        });
        match release_result {
            Ok(()) => {
                tracing::info!(
                    instance_name = %instance_name_for_log,
                    "PyEdge::drop: shared-instance lease released (no explicit close() called)"
                );
            }
            Err(e) => {
                tracing::warn!(
                    instance_name = %instance_name_for_log,
                    error = %e,
                    "PyEdge::drop: shared-instance lease release failed; \
                     lease will age out via staleness window"
                );
            }
        }
    }
}

/// v2.4.0 (CIRISEdge#103) — auto-elected server's lease state, held
/// by [`PyEdge::shared_instance_cleanup`] from `init_edge_runtime`
/// until [`PyEdge::close`] runs the release path. See the field doc
/// for when this is populated vs `None`.
#[cfg(feature = "transport-reticulum-local")]
struct SharedInstanceCleanup {
    /// Shutdown signal for the heartbeat task; the loop `tokio::select!`s
    /// on the matching `Receiver`. Sending `()` (via
    /// [`tokio::sync::oneshot::Sender::send`]) breaks the loop on its
    /// next iteration. `Option` so [`PyEdge::close`] can `take()` it
    /// and `send` once; subsequent calls observe `None` and skip.
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    /// The lease as last seen by `init_edge_runtime`. Stored so the
    /// close path's `release_shared_instance_lease` ownership check
    /// can match the row.
    lease: ciris_persist::federation::SharedInstanceLease,
    /// The federation directory handle the close path uses to call
    /// `release_shared_instance_lease`. Clone of the same Arc the
    /// heartbeat task holds.
    directory: Arc<dyn ciris_persist::federation::FederationDirectory>,
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

    /// Test-only constructor. Builds a fresh multi-thread runtime,
    /// wraps it in an `AsyncExecutor` via persist's
    /// `build_persist_executor`, and exposes it on the resulting
    /// `PyEdge`. The `runtime: RuntimeHandle` parameter is unused
    /// post-CIRISEdge#59 (kept for signature compatibility with
    /// existing test call sites; will be removed in a follow-up).
    ///
    /// Production builds get the executor from persist's
    /// `executor_capsule` via the cross-cdylib ABI-stable vtable;
    /// tests are in-process so the PyCapsule round-trip is
    /// unnecessary — same vtable, direct construction.
    #[cfg(test)]
    pub(crate) fn for_test(inner: Arc<Edge>, _runtime: RuntimeHandle) -> Self {
        let rt_arc = std::sync::Arc::new(
            tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .worker_threads(1)
                .build()
                .expect("for_test runtime"),
        );
        let executor =
            Arc::new(ciris_persist::ffi::executor_capsule::build_persist_executor(rt_arc));
        Self {
            inner,
            executor,
            // v2.1.0 — pure-Rust tests don't carry an Engine; the
            // `engine()` pymethod raises a typed RuntimeError when
            // called on a `for_test`-constructed PyEdge. Tests that
            // need the engine field set use full `init_edge_runtime`
            // with a synthesized Python engine instead.
            engine: None,
            #[cfg(feature = "transport-http")]
            _dev_cert_tmpdir: None,
            #[cfg(feature = "transport-reticulum-local")]
            shared_instance_cleanup: std::sync::Mutex::new(None),
        }
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

    /// v2.4.0 (CIRISEdge#103) — graceful close. Idempotent; safe to
    /// call from `__del__`, `atexit` hooks, FastAPI shutdown handlers,
    /// `try/finally` blocks, etc.
    ///
    /// When this Edge owns a Reticulum shared-instance lease (auto-
    /// elected server), close():
    ///
    /// 1. Signals the heartbeat task to stop (oneshot — the loop's
    ///    `tokio::select!` preempts the 10s sleep on the next
    ///    iteration).
    /// 2. Calls `FederationDirectory::release_shared_instance_lease`
    ///    to free the lease row immediately (ownership-checked; safe
    ///    if the lease was already stolen by a sibling, in which case
    ///    persist returns `false` and we treat it as a no-op).
    ///
    /// Without close(), a worker exit leaves the lease row populated
    /// until the 30s staleness window elapses — sibling re-election
    /// then takes that full window. With close() the handoff is
    /// hundreds of milliseconds (one persist roundtrip), matching the
    /// orchestrator's expectations on `kubectl rollout restart` /
    /// `systemd reload`.
    ///
    /// For Edges with no shared-instance lease (no `local_instance_name`
    /// supplied, `local_instance_role="client"`, or election lost),
    /// close() is a no-op — the surface is present on every Edge so
    /// callers don't need to introspect.
    ///
    /// Errors from the persist release call are LOGGED but NOT
    /// raised: at process-shutdown time, a backend error doesn't
    /// help the caller (they're already exiting), and the lease will
    /// age out via the staleness window as a fallback.
    #[cfg(feature = "transport-reticulum-local")]
    #[allow(clippy::unnecessary_wraps)] // Keep PyResult for future-proofing the pymethod shape
    fn close(&self, py: Python<'_>) -> PyResult<()> {
        let Ok(mut guard) = self.shared_instance_cleanup.lock() else {
            // PoisonError: a prior caller panicked inside the lock.
            // Treat as already-closed and return Ok — re-panicking from
            // close() is worse than tolerating the poison.
            tracing::warn!(
                "PyEdge::close: shared_instance_cleanup mutex poisoned; \
                 skipping release path"
            );
            return Ok(());
        };
        let Some(mut cleanup) = guard.take() else {
            // Already closed, or never had a lease in the first place.
            return Ok(());
        };
        // Signal the heartbeat task FIRST so it stops touching the
        // lease before our release call lands. The receiver-side
        // `tokio::select!` is `biased` to preempt the 10s sleep.
        if let Some(tx) = cleanup.shutdown_tx.take() {
            let _ = tx.send(()); // err only if the receiver already dropped (task exited).
        }
        // Release the lease via run_async. Errors logged + swallowed.
        let directory = cleanup.directory;
        let lease = cleanup.lease;
        let instance_name_for_log = lease.instance_name.clone();
        py.detach(|| {
            let release_result = run_async(&self.executor, async move {
                directory.release_shared_instance_lease(&lease).await
            });
            match release_result {
                Ok(()) => {
                    tracing::info!(
                        instance_name = %instance_name_for_log,
                        "Reticulum shared-instance lease released on close"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        instance_name = %instance_name_for_log,
                        error = %e,
                        "Reticulum shared-instance lease release failed; \
                         lease will age out via staleness window \
                         (ownership-checked release is a no-op when a \
                         sibling already stole the lease)"
                    );
                }
            }
        });
        Ok(())
    }

    /// v2.4.0 (CIRISEdge#103) — `close()` shim for wheels built
    /// without `transport-reticulum-local`. Always Ok; provided so the
    /// Python API surface is feature-invariant (callers don't need to
    /// `hasattr(edge, "close")` based on the wheel's feature set).
    #[cfg(not(feature = "transport-reticulum-local"))]
    fn close(&self, _py: Python<'_>) -> PyResult<()> {
        Ok(())
    }

    /// v2.4.0 (CIRISEdge#103) — context-manager support so callers
    /// can write `with init_edge_runtime(...) as edge: ...` and have
    /// close() fire automatically on the with-block exit. Mirrors the
    /// `contextlib.contextmanager` shape (`__enter__` returns self,
    /// `__exit__` calls close()).
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// v2.4.0 (CIRISEdge#103) — context-manager exit. Always calls
    /// close(); never suppresses the exception (returns `None`
    /// implicitly — Python's `with` semantics).
    #[pyo3(signature = (_exc_type=None, _exc_value=None, _traceback=None))]
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Option<Bound<'_, PyAny>>,
        _exc_value: Option<Bound<'_, PyAny>>,
        _traceback: Option<Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.close(py)
    }

    /// v2.1.0 (CIRISEdge#85 / CIRISLensCore#43) — return the host
    /// persist `Engine` PyObject that was passed to
    /// [`init_edge_runtime`].
    ///
    /// Cohabiting cdylibs (CIRISLensCore relay + client modes,
    /// CIRISNodeCore extensions, etc.) call this to reach the same
    /// engine the host wired into edge — closing the cross-wheel
    /// `current_rust_engine()` `OnceLock` gap (each cdylib carries its
    /// own per-wheel `OnceLock` static, so a non-host cdylib calling
    /// it sees `None` or a different instance — that's the lens-core
    /// #43 P0).
    ///
    /// The returned object is the byte-identical Python handle the
    /// agent constructed and passed in. Cohabiting code can:
    /// - Call its Python methods (`receive_and_persist`, `local_sign`,
    ///   etc.) — dispatch is name-based + cross-wheel-safe; the
    ///   `process_trace_batch` pattern lens-core relies on works
    ///   without any per-wheel state.
    /// - Extract its capsules (`federation_directory_capsule`,
    ///   `outbound_queue_capsule`, `keyring_signer_capsule`,
    ///   `executor_capsule`, etc.) for Rust-side handle handoff —
    ///   same pattern edge itself uses inside `init_edge_runtime`.
    ///
    /// For Rust async contexts that need to call back into the
    /// engine, store the returned `PyObject` and use
    /// `Python::attach(|py| engine.bind(py).call_method1(...))` —
    /// works across wheels because Python method dispatch is
    /// name-based, not cdylib-bound.
    ///
    /// Raises `RuntimeError` if PyEdge was constructed via the
    /// test-only `for_test` constructor (no engine in pure-Rust test
    /// contexts).
    fn engine(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        match &self.engine {
            Some(engine) => Ok(engine.clone_ref(py)),
            None => Err(PyRuntimeError::new_err(
                "PyEdge::engine() — no engine bound on this handle (the \
                 for_test() test-only constructor was used)",
            )),
        }
    }

    /// v2.1.0 (CIRISPersist `LocalIdentityAggregate` RET-transport role
    /// — needed for CIRISAgent 2.9.6) — return edge's Reticulum
    /// transport-identity public keys as a `dict` with two
    /// base64-encoded fields:
    ///
    /// ```python
    /// edge.transport_identity_pubkeys() == {
    ///     "x25519_pub_base64":  "...",  # 32 raw bytes, base64 standard
    ///     "ed25519_pub_base64": "...",  # 32 raw bytes, base64 standard
    /// }
    /// ```
    ///
    /// Persist's `LocalIdentityAggregate` builder reads these to
    /// populate the RET-transport role (the third role in the
    /// `{signing, content-KEM, RET-transport}` triple — the other two
    /// are persist-self-sourced). The Reticulum destination hash
    /// `sha256(x25519 ‖ ed25519)[..16]` is left to the caller —
    /// persist's aggregate hashes the role contents itself.
    ///
    /// Edge owns this keypair end-to-end per the
    /// `crate::identity::federation_identity_hash` doc note:
    /// "the Reticulum destination hash lives on the *transport
    /// identity*, a different key pair generated by
    /// `src/transport/reticulum.rs`."
    ///
    /// Returns `None` for an HTTPS-only or transport-less Edge build
    /// (`disable_reticulum=True` at `init_edge_runtime`, or a wheel
    /// built without the `_reticulum-module` feature). Returns the
    /// dict otherwise.
    fn transport_identity_pubkeys<'py>(
        &self,
        py: Python<'py>,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyDict>>> {
        #[cfg(feature = "_reticulum-module")]
        {
            use base64::Engine as _;
            let Some(buf) = self.inner.local_transport_pubkey() else {
                return Ok(None);
            };
            let dict = pyo3::types::PyDict::new(py);
            let x25519_b64 = base64::engine::general_purpose::STANDARD.encode(&buf[..32]);
            let ed25519_b64 = base64::engine::general_purpose::STANDARD.encode(&buf[32..64]);
            dict.set_item("x25519_pub_base64", x25519_b64)?;
            dict.set_item("ed25519_pub_base64", ed25519_b64)?;
            Ok(Some(dict))
        }
        #[cfg(not(feature = "_reticulum-module"))]
        {
            let _ = py;
            Ok(None)
        }
    }

    /// v2.2.2 (CIRISEdge#97) — return edge's announced RNS destination
    /// hash as a lowercase hex string: the 16-byte `*dest.hash()` value
    /// Reticulum computes at `Destination` construction time over the
    /// identity + app aspects (NOT `sha256(pubkey)[..16]` — consumers
    /// can't safely re-derive it from
    /// [`Self::transport_identity_pubkeys`] alone).
    ///
    /// This is the destination peers resolve to dial this node. RNS
    /// shows destinations conventionally as hex strings; CIRISLensCore
    /// v1.4.0+'s `install_ret_relay` (CIRISLensCore#43) calls this to
    /// surface the dialable RNS address alongside the transport
    /// pubkeys.
    ///
    /// Returns `None` for HTTPS-only or transport-less Edge builds
    /// (`disable_reticulum=True`, or a wheel built without the
    /// `_reticulum-module` feature). Returns the 32-character lowercase
    /// hex string otherwise.
    fn reticulum_dest_hash_hex(&self) -> Option<String> {
        #[cfg(feature = "_reticulum-module")]
        {
            self.inner.local_dest_hash().map(hex::encode)
        }
        #[cfg(not(feature = "_reticulum-module"))]
        {
            None
        }
    }

    /// Local agent's federation `key_id` — the identity peers seed
    /// into their `federation_keys` directory to root inbound traffic
    /// from this agent. CIRISAgent 2.9.4 displays this on the
    /// Epistemic Commons operator surface as "your federation
    /// address is X" so the operator knows what to share with peers
    /// (CIRISEdge#22 Tier-2.5).
    ///
    /// One-line wrapper over [`Edge::signer_key_id`]; no new state.
    fn signer_key_id(&self) -> String {
        self.inner.signer_key_id().to_string()
    }

    /// v2.4.0 (CIRISEdge#95) — fetch a remote peer's hybrid KEM
    /// pubkeys (x25519 + ML-KEM-768) from persist's federation
    /// directory for `FederationSession::initiate` consumers
    /// (CIRISLensCore#34 RET-native relay).
    ///
    /// `occurrence_key_id` is the per-device occurrence key; content-
    /// KEM keys live at the occurrence level per CEG §5.6.8.4.
    ///
    /// ```python
    /// edge.resolve_peer_kex_pubkeys(peer_occurrence_key_id) == {
    ///     "x25519_pub_base64":     "...",  # 32 raw bytes, base64 standard
    ///     "ml_kem_768_pub_base64": "...",  # 1184 raw bytes, base64 standard
    /// }
    /// # OR None if the occurrence is unknown / has no registered
    /// # encryption_pubkeys block / has expired (valid_until in past).
    /// ```
    ///
    /// Returns `None` for: occurrence not in directory, occurrence
    /// expired, occurrence has no `encryption_pubkeys` block, or an
    /// Edge built without a federation directory wired (test
    /// constructors). Raises `RuntimeError` only on persist-backend
    /// failure or malformed base64 / wrong byte length in the
    /// stored row (operator-visible substrate corruption).
    fn resolve_peer_kex_pubkeys<'py>(
        &self,
        py: Python<'py>,
        occurrence_key_id: &str,
    ) -> PyResult<Option<Bound<'py, pyo3::types::PyDict>>> {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        let inner = self.inner.clone();
        let occurrence_key_id_owned = occurrence_key_id.to_string();
        let kex = py.detach(|| {
            run_async(&self.executor, async move {
                inner
                    .resolve_peer_kex_pubkeys(&occurrence_key_id_owned)
                    .await
            })
            .map_err(|e| PyRuntimeError::new_err(format!("resolve_peer_kex_pubkeys: {e}")))
        })?;
        let Some(kex) = kex else {
            let _ = b64; // suppress unused-binding lint in the None path
            return Ok(None);
        };
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("x25519_pub_base64", b64.encode(kex.x25519_pub))?;
        if let Some(mlkem) = kex.mlkem768_pub {
            dict.set_item("ml_kem_768_pub_base64", b64.encode(mlkem))?;
        }
        Ok(Some(dict))
    }

    /// v3.1.0 (CIRISEdge#108 / CIRISPersist#183, CEG §5.6.8.8.1) —
    /// list every reachable address registered for `occurrence_key_id`
    /// via persist's V078 `transport_destinations` table.
    ///
    /// ```python
    /// edge.list_transport_destinations_for(peer_occurrence_key_id) == [
    ///     {
    ///         "occurrence_key_id": "...",
    ///         "transport_kind": "reticulum",      # or "websocket" / "https" / op-defined
    ///         "destination": "<RNS hash hex>",    # transport-kind-specific
    ///         "asserted_at": "2026-06-13T23:59:00Z",
    ///         "last_seen_at": "2026-06-13T23:59:30Z",   # or None
    ///     },
    ///     ...
    /// ]
    /// ```
    ///
    /// Empty list when the occurrence has no registered addresses
    /// (not an error). Empty list for Edges built without a federation
    /// directory (test constructors). Raises `RuntimeError` on
    /// persist-backend failure.
    ///
    /// Liveness filtering on `last_seen_at` age is the caller's
    /// responsibility per persist's contract — reachability is
    /// mutable + disposable.
    fn list_transport_destinations_for<'py>(
        &self,
        py: Python<'py>,
        occurrence_key_id: &str,
    ) -> PyResult<Vec<Bound<'py, pyo3::types::PyDict>>> {
        let inner = self.inner.clone();
        let occurrence_owned = occurrence_key_id.to_string();
        let rows = py.detach(|| {
            run_async(&self.executor, async move {
                inner
                    .list_transport_destinations_for(&occurrence_owned)
                    .await
            })
            .map_err(|e| PyRuntimeError::new_err(format!("list_transport_destinations_for: {e}")))
        })?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let dict = pyo3::types::PyDict::new(py);
            dict.set_item("occurrence_key_id", row.occurrence_key_id)?;
            dict.set_item("transport_kind", row.transport_kind)?;
            dict.set_item("destination", row.destination)?;
            dict.set_item("asserted_at", row.asserted_at.to_rfc3339())?;
            dict.set_item("last_seen_at", row.last_seen_at.map(|ts| ts.to_rfc3339()))?;
            out.push(dict);
        }
        Ok(out)
    }

    // ─── CIRISEdge#22 Tier 2 (v0.9.0) — CommunicationBus replacement ──
    //
    // The pymethods below back CIRISAgent 2.9.5's
    // `EdgeCommunicationAdapter` (implementing the existing
    // `CommunicationServiceProtocol`). Wire-level message type is
    // [`MessageType::InlineText`] (one wire discriminator covers both
    // ephemeral and durable senders — the receiver sees the same body
    // shape regardless). The outbound `speak_pipeline`
    // (Classify + Scrub + EncryptAndStore per FSD §1.4) runs on the
    // caller-supplied text BEFORE signing — the load-bearing
    // forensic-completeness invariant; the pyo3 wrappers call
    // [`Edge::send_inline`] / [`Edge::send_durable_inline`] (not the
    // lower-level [`Edge::send`] / [`Edge::send_durable`]) so the
    // pipeline cannot be bypassed.
    //
    // GIL discipline: the methods release the GIL via `py.detach`
    // around the tokio `block_on` call. Callback invocations from the
    // `register_inline_text_handler` drainer thread reacquire the GIL
    // per call via `Python::with_gil`; see the [`SubscriptionHandle`]
    // doc for the queue + drainer-thread pattern.

    /// Send an ephemeral inline-text message — fire-and-forget; no ACK,
    /// no retry. Returns the `body_sha256` hex digest (the forensic
    /// join key into persist's structured logs and the ACK match key
    /// if the receiver later sends back a typed response).
    ///
    /// **Pipeline invariant**: the configured `speak_pipeline`
    /// (Classify + Scrub + EncryptAndStore per FSD §1.4) runs on `text`
    /// before signing. PII spans are scrubbed; `{SECRET:uuid:desc}`
    /// placeholders substitute for cleartext secrets. The wire payload
    /// never carries unredacted sensitive bytes. CIRISAgent#756 Q1.
    ///
    /// `recipient_key_id` is the federation `key_id`; the transport
    /// (Reticulum) resolves it to a destination address via the
    /// existing `PeerResolver` (AV-42 authenticated cold-start path).
    ///
    /// # Python signature
    /// ```python
    /// edge.send_inline_text("agent-bob", "hello") -> str  # 64-char hex
    /// ```
    fn send_inline_text(
        &self,
        py: Python<'_>,
        recipient_key_id: &str,
        text: &str,
    ) -> PyResult<String> {
        let edge = self.inner.clone();
        let recipient = recipient_key_id.to_string();
        let text_owned = text.to_string();
        let executor = self.executor.clone();
        py.detach(|| {
            run_async(&executor, async move {
                // Build the typed body, run `send_inline` so the
                // speak_pipeline runs + the envelope is signed + the
                // transport ships it (or the no-op test transport
                // accepts it). Compute body_sha256 from the
                // post-pipeline text (the bytes that actually shipped).
                let msg = InlineText { text: text_owned };
                // `send_inline` consumes a Phase 2 TODO (ephemeral
                // request-response correlation isn't wired). For
                // fire-and-forget we expect `EdgeError::Config`
                // "ephemeral request-response correlation not wired"
                // as the success-of-transport path — the bytes have
                // already shipped at that point. Map that one specific
                // config error back to Ok, surface anything else.
                let body_sha = compute_inline_text_body_sha(&edge, &recipient, &msg.text).await?;
                match edge.send_inline(&recipient, msg).await {
                    Ok(()) => Ok(body_sha),
                    Err(crate::EdgeError::Config(s))
                        if s.contains("ephemeral request-response correlation not wired") =>
                    {
                        // The transport accepted the bytes; the
                        // unwired correlation channel is the Phase 2
                        // TODO in `Edge::send`, not a failure of the
                        // wire-level send. CIRISAgent's adapter
                        // doesn't need the response struct for an
                        // inline-text fire-and-forget.
                        Ok(body_sha)
                    }
                    Err(e) => Err(PyRuntimeError::new_err(format!("send_inline_text: {e}"))),
                }
            })
        })
    }

    /// Durable variant — enqueues the inline-text envelope to the
    /// `edge_outbound_queue` with `requires_ack=true`. Returns a
    /// [`PyDurableHandle`] the caller polls (or awaits) to observe the
    /// eventual outcome.
    ///
    /// Defaults: 24h TTL, 20 attempts, 60s ACK timeout (mirrors
    /// [`crate::DSARRequest`]; chat-tier messages don't need the
    /// week-long `BuildManifestPublication` window). Same speak-pipeline
    /// invariant as [`Self::send_inline_text`].
    ///
    /// # Python signature
    /// ```python
    /// handle = edge.send_durable_inline_text("agent-bob", "hello")
    /// handle.body_sha256()           # str — 64-char hex
    /// handle.is_acknowledged()       # bool
    /// handle.await_ack(timeout_ms=5000)  # bool
    /// ```
    fn send_durable_inline_text(
        &self,
        py: Python<'_>,
        recipient_key_id: &str,
        text: &str,
    ) -> PyResult<PyDurableHandle> {
        let edge = self.inner.clone();
        let recipient = recipient_key_id.to_string();
        let text_owned = text.to_string();
        let executor = self.executor.clone();
        let queue_arc: Arc<dyn OutboundHandle> = edge.outbound_queue_handle();
        let executor_for_handle = executor.clone();
        let queue_for_handle = queue_arc.clone();
        py.detach(|| {
            run_async(&executor, async move {
                let msg = InlineTextDurable { text: text_owned };
                let body_sha = compute_inline_text_body_sha(&edge, &recipient, &msg.text).await?;
                let handle = edge
                    .send_durable_inline(&recipient, msg)
                    .await
                    .map_err(|e| {
                        PyRuntimeError::new_err(format!("send_durable_inline_text: {e}"))
                    })?;
                Ok(PyDurableHandle {
                    queue_id: handle.queue_id,
                    body_sha256_hex: body_sha,
                    executor: executor_for_handle,
                    queue: queue_for_handle,
                })
            })
        })
    }

    /// Register an inbound inline-text handler. `callback` is invoked
    /// as `callback(sender_key_id: str, body_text: str)` for every
    /// verified inbound `MessageType::InlineText` envelope. Returns a
    /// [`PySubscriptionHandle`] usable as a context manager:
    ///
    /// ```python
    /// with edge.register_inline_text_handler(on_msg) as sub:
    ///     ...  # subscription active for the duration of the block
    /// # subscription torn down on block exit
    /// ```
    ///
    /// # GIL + callback pattern
    ///
    /// The Rust-side inbound dispatcher (`dispatch_inbound`, running on
    /// a tokio task) MUST NOT block on the GIL — that would stall the
    /// transport listen loop. So each registration spawns a dedicated
    /// **Python-owned drainer thread** (`std::thread::spawn`) that
    /// receives `(sender_key_id, body_text)` tuples from an unbounded
    /// `tokio::mpsc::UnboundedReceiver`, acquires the GIL via
    /// `Python::with_gil` per tuple, and invokes the user callback. A
    /// callback that raises is caught + logged; the drainer keeps
    /// running. The Rust dispatcher's `send` is non-blocking — when
    /// the drainer thread exits (subscription unregistered), the
    /// channel closes and the dispatcher's `send` returns `Err`, at
    /// which point the next dispatch lazily prunes the dead entry.
    ///
    /// # Lifecycle
    ///
    /// The returned `SubscriptionHandle` MUST be retained or used as a
    /// context manager. Dropping the handle without calling
    /// `unsubscribe()` or letting `__exit__` fire will eventually
    /// tear down the subscription via the Python finalizer, but the
    /// timing is not deterministic — production code should
    /// `with ...:` it or explicitly `unsubscribe()`.
    fn register_inline_text_handler(&self, callback: Py<PyAny>) -> PyResult<PySubscriptionHandle> {
        // Validate the callback is actually callable. PyO3 doesn't
        // enforce this at the type level — match persist's
        // `PyEngine::subscribe` ergonomics (TypeError-equivalent).
        // Consume `callback` into the drainer thread; the bind for
        // validation borrows it under a GIL lease, so the move into
        // the spawned thread below is legal.
        Python::attach(|py| -> PyResult<()> {
            if !callback.bind(py).is_callable() {
                return Err(PyValueError::new_err("callback must be callable"));
            }
            Ok(())
        })?;

        let (id, rx) = self.inner.register_inline_text_subscriber();
        let edge_weak = Arc::downgrade(&self.inner);

        // Spawn the Python-owned drainer thread. `std::thread::spawn`
        // (not `tokio::spawn`) because the drainer's only job is the
        // blocking `recv()` → GIL-acquire → callback loop; a standalone
        // OS thread acquires + releases the GIL cleanly without
        // holding a tokio worker hostage on `Python::attach`.
        //
        // `Py<PyAny>` is `Send + Sync` (pyo3 0.28); refcounting on
        // drop is handled via pyo3's pending-decref queue + GIL reacquire,
        // so moving `callback` across the thread boundary is sound.
        let drainer = std::thread::Builder::new()
            .name(format!("ciris-edge-inline-text-drainer-{id}"))
            .spawn(move || {
                drain_inline_text(rx, callback);
            })
            .map_err(|e| {
                PyRuntimeError::new_err(format!("spawn inline-text drainer thread: {e}"))
            })?;

        Ok(PySubscriptionHandle {
            id,
            edge: edge_weak,
            drainer_thread: std::sync::Mutex::new(Some(drainer)),
        })
    }

    /// Snapshot count of live inline-text subscribers. Diagnostics
    /// helper — exposes [`Edge::inline_text_subscriber_count`] to
    /// Python so the lifecycle tests can verify a
    /// `SubscriptionHandle::unsubscribe` / context-manager exit
    /// actually removed the entry.
    fn inline_text_subscriber_count(&self) -> usize {
        self.inner.inline_text_subscriber_count()
    }

    // ─── CIRISEdge#22 Tier 3 (v0.17.0) — Epistemic Commons UI ──────────
    //
    // Three load-bearing pymethods backing CIRISAgent 2.10.0's
    // "Coming Soon" UI gating:
    //
    //   - `peer_reachability` — per-medium delivery counters surfaced
    //      to the Trust Topology drilldown (CIRISEdge#29 substrate;
    //      v0.11.0 shipped the tracker, this is the FFI surface).
    //   - `fetch_content`     — content-addressable byte transport
    //      (CIRISEdge#21 substrate; v0.8.0 shipped the ContentFetch /
    //      ContentBody / ContentMiss wire types, this is the FFI
    //      surface).
    //   - `subscribe_feed`    — verified-envelope AsyncIterator for
    //      the inbound UI panes.
    //
    // All three are thin shims over Rust-side primitives — the
    // pymethods own GIL discipline and JSON-shape projection, not
    // the substrate logic.

    /// Per-medium reachability snapshot for `key_id`. Returns a dict
    /// keyed by transport medium (`"reticulum-rs"`, `"http"`, etc.)
    /// → `{ratio: float, last_ok_ts: int}` where:
    ///
    /// - `ratio` is the rolling-window `successes / attempts` ratio
    ///   in `[0.0, 1.0]`. An empty dict means "no measurement yet"
    ///   (consumer SHOULD render "unknown", not "0.0%").
    /// - `last_ok_ts` is the wall-clock millisecond timestamp of the
    ///   most recent successful attempt in the window (or 0 if no
    ///   successes have been recorded).
    ///
    /// Cheap: one `parking_lot::RwLock` read of the in-process
    /// reachability tracker; no I/O.
    fn peer_reachability(&self, py: Python<'_>, key_id: &str) -> PyResult<Py<pyo3::types::PyDict>> {
        let tracker = self.inner.reachability_tracker();
        let snap = tracker.snapshot(key_id);
        let dict = pyo3::types::PyDict::new(py);
        for (transport_id, entry) in snap {
            let medium = transport_id.0;
            let inner = pyo3::types::PyDict::new(py);
            inner.set_item("ratio", entry.ratio())?;
            let last_ok_ts = entry.last_success_at.map_or(0, |t| t.timestamp_millis());
            inner.set_item("last_ok_ts", last_ok_ts)?;
            dict.set_item(medium, inner)?;
        }
        Ok(dict.unbind())
    }

    /// Fetch content addressed by `sha256` (hex string) from
    /// `peer_key_id`. Returns a dict that is either:
    ///
    /// - `{"kind": "bytes", "bytes": <bytes>}` — the peer returned
    ///   a `ContentBody` whose `sha256(bytes) == requested_sha256`
    ///   invariant was enforced by the dispatch gate.
    /// - `{"kind": "content_miss", "reason": "<MissReason>"}` —
    ///   the peer returned a `ContentMiss` (try another holder).
    ///
    /// Raises `ValueError` if `sha256` isn't a 64-char hex string.
    /// Raises `RuntimeError` on timeout or transport failure.
    #[pyo3(signature = (peer_key_id, sha256, timeout_ms = 30_000))]
    fn fetch_content(
        &self,
        py: Python<'_>,
        peer_key_id: &str,
        sha256: &str,
        timeout_ms: u64,
    ) -> PyResult<Py<pyo3::types::PyDict>> {
        // Parse the hex sha256 into a [u8; 32].
        if sha256.len() != 64 {
            return Err(PyValueError::new_err(format!(
                "sha256 must be a 64-char hex string, got {} chars",
                sha256.len()
            )));
        }
        let mut sha = [0u8; 32];
        for (i, byte) in sha.iter_mut().enumerate() {
            let s = &sha256[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(s, 16)
                .map_err(|e| PyValueError::new_err(format!("sha256 hex parse: {e}")))?;
        }

        let edge = self.inner.clone();
        let peer = peer_key_id.to_string();
        let executor = self.executor.clone();
        let result = py.detach(|| {
            run_async(&executor, async move {
                edge.fetch_content(&peer, sha, Duration::from_millis(timeout_ms))
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("fetch_content: {e}")))
            })
        })?;

        let dict = pyo3::types::PyDict::new(py);
        match result {
            crate::edge::ContentResult::Bytes(bytes) => {
                dict.set_item("kind", "bytes")?;
                dict.set_item("bytes", pyo3::types::PyBytes::new(py, &bytes))?;
            }
            crate::edge::ContentResult::ContentMiss { reason } => {
                dict.set_item("kind", "content_miss")?;
                dict.set_item("reason", reason)?;
            }
            // CIRISEdge#52 (v0.20.1) — multimedia tier: peer returned
            // a `BlobBody::External` pointer. Python surface returns
            // {"kind": "external", "external_uri": ..., "external_sha256_hex": ...};
            // the consumer's client fetches bytes directly from
            // `external_uri` (edge does NOT dereference the pointer
            // per MEDIA_SHARING.md §2.6 + THREAT_MODEL AV-49).
            crate::edge::ContentResult::External {
                external_uri,
                external_sha256_hex,
            } => {
                dict.set_item("kind", "external")?;
                dict.set_item("external_uri", external_uri)?;
                dict.set_item("external_sha256_hex", external_sha256_hex)?;
            }
        }
        Ok(dict.unbind())
    }

    /// CIRISEdge#55 v3.4.0-pre1 — adaptive multi-peer swarm fetch.
    ///
    /// Fetches a chunked blob from a set of holders concurrently with
    /// per-peer EWMA RTT tracking, in-flight caps, dishonest-peer
    /// demotion, and endgame mode (duplicate requests for the last
    /// chunks). Returns the assembled blob bytes.
    ///
    /// # Inputs
    ///
    /// - `blob_sha256_hex` — 64-char hex of the overall blob SHA-256.
    /// - `manifest_chunks` — ordered list of `(chunk_sha_hex,
    ///   chunk_size)` tuples (the persist `ChunkManifest.chunks`
    ///   projection).
    /// - `total_size` — Σ chunk sizes; validated against `manifest_chunks`.
    /// - `holders` — list of `key_id` strings, typically the result of
    ///   `engine.list_holders(blob_sha256)`. Edge does NOT query
    ///   persist directly — the caller owns the holder enumeration.
    /// - `timeout_ms` — per-chunk request timeout (default 30000).
    ///
    /// # Errors
    ///
    /// - `ValueError` — hex parse failure, manifest mismatch, etc.
    /// - `RuntimeError` — typed `SwarmError` variants (NoHolders,
    ///   ChunkUnreachable, Substrate, GoneFederationWide).
    ///
    /// # Manifest discovery
    ///
    /// v3.4.0-pre1 leaves manifest discovery to the caller — given a
    /// blob SHA, where do I get the manifest? lens-core / agent
    /// orchestration owns that question. The straightforward pattern
    /// is: `fetch_content(blob_sha256)` → if the response is a
    /// `chunk_dag` manifest, parse it into `manifest_chunks` + pass
    /// here.
    #[pyo3(signature = (blob_sha256_hex, manifest_chunks, total_size, holders, timeout_ms = 30_000))]
    #[allow(clippy::needless_pass_by_value)] // pyo3 surface takes owned Vecs
    fn fetch_blob_swarm(
        &self,
        py: Python<'_>,
        blob_sha256_hex: &str,
        manifest_chunks: Vec<(String, usize)>,
        total_size: u64,
        holders: Vec<String>,
        timeout_ms: u64,
    ) -> PyResult<Py<pyo3::types::PyBytes>> {
        // Parse the blob SHA.
        if blob_sha256_hex.len() != 64 {
            return Err(PyValueError::new_err(format!(
                "blob_sha256_hex must be a 64-char hex string, got {} chars",
                blob_sha256_hex.len()
            )));
        }
        let mut blob_sha = [0u8; 32];
        for (i, byte) in blob_sha.iter_mut().enumerate() {
            let s = &blob_sha256_hex[i * 2..i * 2 + 2];
            *byte = u8::from_str_radix(s, 16)
                .map_err(|e| PyValueError::new_err(format!("blob_sha256 hex parse: {e}")))?;
        }

        // Parse the chunk list.
        let mut chunks = Vec::with_capacity(manifest_chunks.len());
        for (idx, (sha_hex, size)) in manifest_chunks.iter().enumerate() {
            if sha_hex.len() != 64 {
                return Err(PyValueError::new_err(format!(
                    "manifest_chunks[{idx}].sha_hex must be 64 chars, got {}",
                    sha_hex.len()
                )));
            }
            let mut sha = [0u8; 32];
            for (i, byte) in sha.iter_mut().enumerate() {
                let s = &sha_hex[i * 2..i * 2 + 2];
                *byte = u8::from_str_radix(s, 16)
                    .map_err(|e| PyValueError::new_err(format!("chunk_sha hex parse: {e}")))?;
            }
            chunks.push((sha, *size));
        }
        let manifest = crate::blob_swarm::ChunkManifestLite { chunks, total_size };

        // v3.4.0-pre1 swarm wrapper takes the verifier from the
        // engine if one is wired; for the bare PyEdge surface we
        // construct a default "hash-check-only" verifier that uses
        // `sha2` directly (no persist write). The full
        // `put_blob_chunks` path lands in a follow-up cut once the
        // engine wrapper is in scope.
        let verifier = std::sync::Arc::new(DefaultPyChunkVerifier)
            as std::sync::Arc<dyn crate::blob_swarm::BlobChunkVerifier>;
        let config = crate::blob_swarm::SwarmConfig {
            per_request_timeout: Duration::from_millis(timeout_ms),
            ..crate::blob_swarm::SwarmConfig::default()
        };
        let scheduler =
            crate::blob_swarm::SwarmScheduler::new(self.inner.clone(), verifier, config);

        let result = py.detach(|| {
            run_async(&self.executor, async move {
                scheduler
                    .fetch_blob(blob_sha, manifest, holders)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("fetch_blob_swarm: {e}")))
            })
        })?;

        Ok(pyo3::types::PyBytes::new(py, &result).unbind())
    }

    /// Subscribe to verified inbound envelopes. Returns a
    /// [`PyVerifiedFeedSubscription`] — a Python AsyncIterator that
    /// yields one verified-envelope projection per inbound message.
    ///
    /// Iteration shape (one `__anext__` await yields):
    ///
    /// ```python
    /// {
    ///     "message_type": "InlineText",
    ///     "signing_key_id": "agent-bob",
    ///     "destination_key_id": "agent-self",
    ///     "body_sha256_prefix": "abc12345",  # first 8 hex chars
    ///     "transport_id": "reticulum-rs",
    ///     "received_at_ms": 1748392832000,
    /// }
    /// ```
    ///
    /// The full body is not surfaced through this AsyncIterator —
    /// consumers route by `message_type` + `body_sha256_prefix` and
    /// fetch the body via the typed handler dispatch path.
    fn subscribe_feed(&self) -> PyVerifiedFeedSubscription {
        let rx = self.inner.subscribe_verified_feed();
        PyVerifiedFeedSubscription {
            rx: Arc::new(Mutex::new(Some(rx))),
            executor: self.executor.clone(),
        }
    }

    // ─── CIRISEdge#47 (v0.17.0) — Short Authentication String ─────────

    /// Derive a Short Authentication String for verifying the local
    /// edge's identity against `peer_key_id`. Returns `words`
    /// (default 5) BIP39-English words deterministically derived from
    /// the `(local_pub, peer_pub, protocol-constant)` tuple — sorted
    /// so the words don't depend on which side calls "local".
    ///
    /// Two operators displaying the same word list have confirmed
    /// out-of-band that they share the same peer-key tuple (MITM-
    /// resistant verification of the federation-key bootstrap).
    ///
    /// Raises `ValueError` if `peer_key_id` isn't in the federation
    /// directory, or if the local signer's public key isn't 32 bytes
    /// (e.g. hybrid hardware signer without a software-Ed25519
    /// fallback — see persist `local_signer_capsule` v3.1.1).
    #[pyo3(signature = (peer_key_id, words = crate::sas::DEFAULT_SAS_WORDS))]
    fn peer_sas(&self, py: Python<'_>, peer_key_id: &str, words: usize) -> PyResult<Vec<String>> {
        let (local_pub, peer_pub) =
            resolve_sas_pubkeys(py, &self.inner, &self.executor, peer_key_id)?;
        crate::sas::peer_sas_words(&local_pub, &peer_pub, words).map_err(|e| match e {
            crate::sas::SasError::WordsOutOfRange(_) => PyValueError::new_err(format!("{e}")),
            other => PyRuntimeError::new_err(format!("peer_sas: {other}")),
        })
    }

    /// Numeric-only variant of [`Self::peer_sas`]. Returns a zero-
    /// padded decimal string of `digits` characters (default 6 ≈
    /// 19.93 bits, same as TOTP / Signal SAS).
    #[pyo3(signature = (peer_key_id, digits = crate::sas::DEFAULT_SAS_DIGITS))]
    fn peer_sas_digits(
        &self,
        py: Python<'_>,
        peer_key_id: &str,
        digits: usize,
    ) -> PyResult<String> {
        let (local_pub, peer_pub) =
            resolve_sas_pubkeys(py, &self.inner, &self.executor, peer_key_id)?;
        crate::sas::peer_sas_digits(&local_pub, &peer_pub, digits).map_err(|e| match e {
            crate::sas::SasError::DigitsOutOfRange(_) => PyValueError::new_err(format!("{e}")),
            other => PyRuntimeError::new_err(format!("peer_sas_digits: {other}")),
        })
    }

    // ─── CIRISEdge#34 (v0.19.0) — Network-event AsyncIterator surface ───
    //
    // Six pymethods backing the per-category broadcast bus. Each
    // returns a `PyNetworkEventSubscription` implementing
    // `__aiter__` / `__anext__` so consumers write
    // `async for ev in edge.subscribe_announces(): ...`. The dict
    // shape yielded by `__anext__` is documented on the pyclass impl.
    //
    // Channel cardinality (per [`crate::events::EventBus`]):
    //
    //   - subscribe_announces        → AnnounceReceived emissions
    //   - subscribe_link_events      → LinkEstablished / LinkDropped
    //   - subscribe_interface_events → TransportUp / TransportDown
    //   - subscribe_path_events      → PathDiscovered / PathLost
    //   - subscribe_resource_events  → ResourcePressure (queue depth,
    //                                   transport buffer pressure)
    //   - subscribe_all              → fan-in of all the above

    /// Subscribe to announce events (PeerResolver cold-start path).
    /// Yields one dict per arriving announce; raises `StopAsyncIteration`
    /// when the channel closes.
    fn subscribe_announces(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_announces())
    }

    /// Subscribe to link events (Reticulum link establish/drop). v0.14.2
    /// wired the Rust-side EventBus channel; v0.19.0 ships the pymethod
    /// surface.
    fn subscribe_link_events(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_links())
    }

    /// Subscribe to interface events (transport_up / transport_down).
    fn subscribe_interface_events(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_interfaces())
    }

    /// Subscribe to path events (CIRISEdge#34 v0.19.0). Yields
    /// PathDiscovered / PathLost dicts. Emission sites:
    /// `dispatch_inbound` `DeliveryAttestation` arm (PathDiscovered),
    /// `dispatch_inbound` AccordCarrier wire-layer refusal arm
    /// (PathLost), plus the Reticulum transport's path-table hooks.
    fn subscribe_path_events(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_paths())
    }

    /// Subscribe to resource events (CIRISEdge#34 v0.19.0). Yields
    /// ResourcePressure dicts carrying (`resource_kind`, `measurement`,
    /// `unit`). v0.19.0 emission sites: `send_durable` /
    /// `send_mandatory` / `send_federation` (durable_queue_depth
    /// gauges).
    fn subscribe_resource_events(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_resources())
    }

    /// Subscribe to the union of every per-category stream — every
    /// emission is fanned-in here in arrival order.
    fn subscribe_all(&self) -> PyNetworkEventSubscription {
        PyNetworkEventSubscription::new(self.inner.events().subscribe_all())
    }

    // ─── CIRISEdge#28 (v0.19.0) — metrics snapshot ─────────────────

    /// Snapshot the live edge metrics as a Python `dict` of `dict`s.
    /// Each call is point-in-time; consumers poll repeatedly for
    /// change-detection.
    ///
    /// Shape:
    ///
    /// ```python
    /// {
    ///   "envelopes_sent_total":     {"InlineText": 42, ...},
    ///   "envelopes_received_total": {"FederationAnnouncement": 7, ...},
    ///   "send_failures_total":      {"reticulum-rs:unreachable": 1, ...},
    ///   "verify_failures_total":    {"replay_detected": 3, ...},
    ///   "durable_queue_depth":      {"durable": 5, "mandatory": 0, ...},
    ///   "transport_bytes_in_total": {"reticulum-rs": 24576, ...},
    ///   "transport_bytes_out_total":{"http": 1024, ...},
    ///   "peer_reachability_ratio":  {"peer-x:reticulum-rs": 0.75, ...},
    /// }
    /// ```
    fn metrics_snapshot(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        // Mirror the live reachability tracker into the gauge before
        // snapshotting — consumers expect the gauge to be current.
        let reach_snap = self.inner.reachability_tracker().snapshot_all();
        let m = self.inner.metrics();
        for entry in &reach_snap {
            m.set_peer_reachability(&entry.peer_key_id, entry.transport_id.0, entry.ratio());
        }
        let bundle = m.snapshot();
        let root = pyo3::types::PyDict::new(py);

        let envelopes_sent = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.envelopes_sent_total {
            envelopes_sent.set_item(format!("{k:?}"), *v)?;
        }
        root.set_item("envelopes_sent_total", envelopes_sent)?;

        let envelopes_received = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.envelopes_received_total {
            envelopes_received.set_item(format!("{k:?}"), *v)?;
        }
        root.set_item("envelopes_received_total", envelopes_received)?;

        let send_failures = pyo3::types::PyDict::new(py);
        for ((t, c), v) in &bundle.send_failures_total {
            send_failures.set_item(format!("{}:{c}", t.0), *v)?;
        }
        root.set_item("send_failures_total", send_failures)?;

        let verify_failures = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.verify_failures_total {
            verify_failures.set_item(k.as_str(), *v)?;
        }
        root.set_item("verify_failures_total", verify_failures)?;

        let durable_depth = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.durable_queue_depth {
            durable_depth.set_item(k.as_str(), *v)?;
        }
        root.set_item("durable_queue_depth", durable_depth)?;

        let bytes_in = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.transport_bytes_in_total {
            bytes_in.set_item(k.0, *v)?;
        }
        root.set_item("transport_bytes_in_total", bytes_in)?;

        let bytes_out = pyo3::types::PyDict::new(py);
        for (k, v) in &bundle.transport_bytes_out_total {
            bytes_out.set_item(k.0, *v)?;
        }
        root.set_item("transport_bytes_out_total", bytes_out)?;

        let reachability = pyo3::types::PyDict::new(py);
        for ((peer, medium), v) in &bundle.peer_reachability_ratio {
            reachability.set_item(format!("{peer}:{medium}"), *v)?;
        }
        root.set_item("peer_reachability_ratio", reachability)?;

        Ok(root.unbind().into_any())
    }

    // ── CIRISEdge#65 v1.6.3 — PyO3 init wiring for replication ──────
    //
    // Closes the 8th and final rung of #65's v1 ladder per
    // FSD/REPLICATION_WIRE_FORMAT_V1.md §3.7. Spawns a
    // `ReplicationRuntime` (bridge + registry + scheduler) bound to
    // this PyEdge's federation directory and first transport;
    // returns a `PyReplicationHandle` the operator holds for the
    // lifetime of their replication peer set.

    /// Start the replication runtime over this edge's federation
    /// directory + transport.
    ///
    /// `peers` is a list of `(peer_key_id, kind_str)` tuples where
    /// `kind_str` is one of the 10 wire-stable kinds per FSD §3.3:
    /// "key" / "attestation" / "revocation" / "identity_occurrence"
    /// / "family" / "community" / "identity_occurrence_revocation"
    /// / "family_membership_revocation" /
    /// "community_membership_revocation" / "location_proof".
    ///
    /// `cadence_seconds` overrides the scheduler's default 30 s
    /// per-round cadence; `None` keeps the default. The round
    /// timeout stays at the scheduler default (10 s).
    ///
    /// Errors:
    /// - `ValueError("edge has no federation_directory wired")` if
    ///   the cohabitation init path didn't supply one (the typical
    ///   test-fixture trap).
    /// - `ValueError("edge has no transport wired")` if no
    ///   transport was registered at init.
    /// - `ValueError("unknown EnvelopeKind: {token}")` if a kind
    ///   string in `peers` doesn't match the 10 wire tokens.
    #[pyo3(signature = (peers, cadence_seconds = None))]
    fn start_replication(
        &self,
        py: Python<'_>,
        peers: Vec<(String, String)>,
        cadence_seconds: Option<u64>,
    ) -> PyResult<PyReplicationHandle> {
        let directory = self
            .inner
            .federation_directory()
            .ok_or_else(|| PyValueError::new_err("edge has no federation_directory wired"))?;
        let transports = self.inner.transports();
        let transport = transports
            .into_iter()
            .next()
            .ok_or_else(|| PyValueError::new_err("edge has no transport wired"))?;

        let mut typed_peers = Vec::with_capacity(peers.len());
        for (peer_key_id, kind_str) in peers {
            let kind = parse_envelope_kind(&kind_str)?;
            typed_peers.push(crate::replication::ReplicationPeer { peer_key_id, kind });
        }

        let mut config = crate::replication::ReplicationRuntimeConfig::default();
        if let Some(secs) = cadence_seconds {
            config.scheduler.cadence = std::time::Duration::from_secs(secs);
        }

        let executor = self.executor.clone();
        let runtime = py.detach(|| {
            run_async(&executor, async move {
                crate::replication::ReplicationRuntime::start(
                    directory,
                    transport,
                    typed_peers,
                    config,
                )
                .await
            })
        });

        Ok(PyReplicationHandle {
            inner: Arc::new(tokio::sync::Mutex::new(Some(runtime))),
            executor: self.executor.clone(),
        })
    }
}

/// Parse a wire-stable kind string into [`crate::replication::EnvelopeKind`].
/// The token set is the 10 `#[serde(rename_all = "snake_case")]`
/// variants per FSD §3.3.
fn parse_envelope_kind(s: &str) -> PyResult<crate::replication::EnvelopeKind> {
    use crate::replication::EnvelopeKind;
    match s {
        "key" => Ok(EnvelopeKind::Key),
        "attestation" => Ok(EnvelopeKind::Attestation),
        "revocation" => Ok(EnvelopeKind::Revocation),
        "identity_occurrence" => Ok(EnvelopeKind::IdentityOccurrence),
        "family" => Ok(EnvelopeKind::Family),
        "community" => Ok(EnvelopeKind::Community),
        "identity_occurrence_revocation" => Ok(EnvelopeKind::IdentityOccurrenceRevocation),
        "family_membership_revocation" => Ok(EnvelopeKind::FamilyMembershipRevocation),
        "community_membership_revocation" => Ok(EnvelopeKind::CommunityMembershipRevocation),
        "location_proof" => Ok(EnvelopeKind::LocationProof),
        other => Err(PyValueError::new_err(format!(
            "unknown EnvelopeKind: {other:?} (valid: key, attestation, revocation, \
             identity_occurrence, family, community, \
             identity_occurrence_revocation, family_membership_revocation, \
             community_membership_revocation, location_proof)"
        ))),
    }
}

/// Python-facing handle for the `ReplicationRuntime`.
///
/// Construct via [`PyEdge::start_replication`]; hold for the
/// lifetime of the application's replication peer set; call
/// `register_peer` for hot-add; call `stop` for graceful shutdown.
///
/// Clones of this handle (Python references) share the same inner
/// runtime — first `stop` shuts down; subsequent `stop` calls are
/// no-ops.
#[pyclass(name = "ReplicationHandle", module = "ciris_edge", unsendable)]
pub struct PyReplicationHandle {
    inner: Arc<tokio::sync::Mutex<Option<crate::replication::ReplicationRuntime>>>,
    executor: Arc<ciris_persist::ffi::executor_capsule::AsyncExecutor>,
}

#[pymethods]
impl PyReplicationHandle {
    /// Number of currently registered `(peer_key_id, kind)` pairs.
    /// Returns 0 after `stop()`.
    fn registered_count(&self, py: Python<'_>) -> usize {
        let inner = self.inner.clone();
        let executor = self.executor.clone();
        py.detach(|| {
            run_async(&executor, async move {
                let guard = inner.lock().await;
                if let Some(rt) = guard.as_ref() {
                    rt.registry().len().await
                } else {
                    0
                }
            })
        })
    }

    /// Hot-add a `(peer_key_id, kind)` after start. See
    /// `ReplicationRuntime::register_peer` for the v1 limitation
    /// (hot-adds default to Responder role; the scheduler's
    /// Initiator set is fixed at start in v1).
    fn register_peer(&self, py: Python<'_>, peer_key_id: &str, kind: &str) -> PyResult<()> {
        let kind = parse_envelope_kind(kind)?;
        let peer = peer_key_id.to_string();
        let inner = self.inner.clone();
        let executor = self.executor.clone();
        py.detach(|| {
            run_async(&executor, async move {
                let guard = inner.lock().await;
                if let Some(rt) = guard.as_ref() {
                    rt.register_peer(peer, kind).await;
                }
            });
        });
        Ok(())
    }

    /// Stop the replication runtime — signals the scheduler to
    /// exit and awaits its run loop. Idempotent.
    fn stop(&self, py: Python<'_>) {
        let inner = self.inner.clone();
        let executor = self.executor.clone();
        py.detach(|| {
            run_async(&executor, async move {
                let mut guard = inner.lock().await;
                if let Some(mut rt) = guard.take() {
                    rt.shutdown().await;
                }
            });
        });
    }
}

/// CIRISEdge#55 v3.4.0-pre1 — default chunk verifier for the
/// `fetch_blob_swarm` pymethod. Hash-checks the chunk bytes locally
/// (returns `Mismatch` on hash failure so the scheduler demotes the
/// peer) but does NOT persist via `put_blob_chunks`. The persist-
/// integrated verifier lands in a follow-up cut once the engine
/// adapter is in scope for the PyEdge path.
///
/// Visible-to-tests: the scheduler treats `Mismatch` as a dishonest-
/// peer strike; the unverified bytes are returned to the Python
/// caller as the assembled blob. Callers writing persist-backed
/// applications should wire a real verifier through the Rust API
/// surface (`SwarmScheduler::new`).
struct DefaultPyChunkVerifier;

impl crate::blob_swarm::BlobChunkVerifier for DefaultPyChunkVerifier {
    fn verify_and_store(
        &self,
        _blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        bytes: &[u8],
    ) -> Result<(), crate::blob_swarm::ChunkVerifyError> {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let out = h.finalize();
        let mut actual = [0u8; 32];
        actual.copy_from_slice(&out);
        if actual != chunk_sha256 {
            return Err(crate::blob_swarm::ChunkVerifyError::Mismatch {
                chunk_sha: hex::encode(chunk_sha256),
            });
        }
        Ok(())
    }
}

/// CIRISEdge#22 Tier 3 (v0.17.0) — Python-side projection of the
/// verified-envelope feed. Backs `PyEdge::subscribe_feed`. Implements
/// `__aiter__` / `__anext__` so `async for snap in feed: ...` drains
/// the broadcast receiver.
#[pyclass(name = "VerifiedFeedSubscription", module = "ciris_edge")]
pub struct PyVerifiedFeedSubscription {
    /// `Option<broadcast::Receiver<_>>` so `__anext__` can take the
    /// receiver via `Mutex::lock()` + `Option::take`, await its
    /// `recv()`, then restore it on success. `tokio::sync::Mutex`
    /// (not std) because the lock is held across an .await inside
    /// the future returned to Python.
    rx: Arc<Mutex<Option<tokio::sync::broadcast::Receiver<crate::edge::VerifiedEnvelopeSnapshot>>>>,
    /// CIRISEdge#59 — the executor capsule (cross-cdylib ABI-stable
    /// spawn primitive). Used by `__anext__`'s `run_async` to drive
    /// `broadcast::Receiver::recv()` from sync Python.
    executor: Arc<ciris_persist::ffi::executor_capsule::AsyncExecutor>,
}

#[pymethods]
impl PyVerifiedFeedSubscription {
    /// `async for` entry — Python AsyncIterator protocol.
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// `async for` step — returns the next verified-envelope snapshot
    /// as a Python dict, or raises `StopAsyncIteration` when the
    /// broadcast channel is closed.
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx_holder = self.rx.clone();
        // CIRISEdge#59 — pyo3_async_runtimes drives the future on its
        // own configured tokio runtime; we don't need to thread the
        // executor here.
        let _ = &self.executor;
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            // pyo3-async-runtimes drives the future on its own
            // configured tokio runtime; the receiver is bound to the
            // broadcast channel directly, no explicit `enter()` needed.
            let snap_opt = {
                let mut guard = rx_holder.lock().await;
                let Some(rx) = guard.as_mut() else {
                    return Err(PyRuntimeError::new_err("feed subscription closed"));
                };
                rx.recv().await
            };
            match snap_opt {
                Ok(snap) => Python::attach(|py| {
                    let dict = pyo3::types::PyDict::new(py);
                    dict.set_item("message_type", format!("{:?}", snap.envelope.message_type))?;
                    dict.set_item("signing_key_id", &snap.envelope.signing_key_id)?;
                    dict.set_item("destination_key_id", &snap.envelope.destination_key_id)?;
                    let mut prefix = String::with_capacity(16);
                    for b in &snap.body_sha256[..8] {
                        use std::fmt::Write as _;
                        let _ = write!(prefix, "{b:02x}");
                    }
                    dict.set_item("body_sha256_prefix", prefix)?;
                    dict.set_item("transport_id", snap.transport_id.0)?;
                    dict.set_item("received_at_ms", snap.received_at.timestamp_millis())?;
                    Ok(dict.unbind().into_any())
                }),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => Err(
                    PyRuntimeError::new_err(format!("feed subscription lagged by {n} events")),
                ),
            }
        })
    }
}

/// CIRISEdge#34 (v0.19.0) — Python-side projection of the per-category
/// network event broadcast. Backs every `PyEdge::subscribe_*`
/// pymethod (announces, link, interface, path, resource, all). Wire
/// shape is a Python dict — see `__anext__` for the keys.
#[pyclass(name = "NetworkEventSubscription", module = "ciris_edge")]
pub struct PyNetworkEventSubscription {
    rx: Arc<Mutex<Option<tokio::sync::broadcast::Receiver<crate::events::NetworkEvent>>>>,
}

impl PyNetworkEventSubscription {
    fn new(rx: tokio::sync::broadcast::Receiver<crate::events::NetworkEvent>) -> Self {
        Self {
            rx: Arc::new(Mutex::new(Some(rx))),
        }
    }
}

#[pymethods]
impl PyNetworkEventSubscription {
    fn __aiter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Yields the next [`crate::events::NetworkEvent`] as a Python dict.
    /// Keys:
    ///
    /// ```python
    /// {
    ///   "at": "2026-05-29T12:34:56Z",      # RFC-3339 UTC
    ///   "kind": "PathDiscovered",           # EventKind debug repr
    ///   "severity": "info" | "warning" | "error",
    ///   "message": "<free-form>",
    ///   "peer_key_id": str | None,
    ///   "transport_id": str | None,
    ///   # category-specific optional fields:
    ///   "identity_hash": bytes | None,
    ///   "app_data": bytes | None,
    ///   "aspect": str | None,
    ///   "link_id": bytes | None,
    ///   "destination_hash": bytes | None,
    ///   "hops": int | None,
    ///   "resource_kind": str | None,
    ///   "measurement": float | None,
    ///   "unit": str | None,
    ///   "lagged_count": int | None,
    /// }
    /// ```
    fn __anext__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let rx_holder = self.rx.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let recv_outcome = {
                let mut guard = rx_holder.lock().await;
                let Some(rx) = guard.as_mut() else {
                    return Err(PyRuntimeError::new_err("network event subscription closed"));
                };
                rx.recv().await
            };
            match recv_outcome {
                Ok(ev) => Python::attach(|py| {
                    let dict = network_event_to_pydict(py, &ev)?;
                    Ok(dict.unbind().into_any())
                }),
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    Err(pyo3::exceptions::PyStopAsyncIteration::new_err(()))
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    Err(PyRuntimeError::new_err(format!(
                        "network event subscription lagged by {n} events"
                    )))
                }
            }
        })
    }
}

/// CIRISEdge#34 (v0.19.0) — project a [`crate::events::NetworkEvent`]
/// into a Python dict matching the documented `__anext__` shape.
fn network_event_to_pydict<'py>(
    py: Python<'py>,
    ev: &crate::events::NetworkEvent,
) -> PyResult<Bound<'py, pyo3::types::PyDict>> {
    let dict = pyo3::types::PyDict::new(py);
    dict.set_item("at", ev.at.to_rfc3339())?;
    dict.set_item("kind", format!("{:?}", ev.kind))?;
    let sev = match ev.severity {
        crate::events::EventSeverity::Info => "info",
        crate::events::EventSeverity::Warning => "warning",
        crate::events::EventSeverity::Error => "error",
    };
    dict.set_item("severity", sev)?;
    dict.set_item("message", &ev.message)?;
    dict.set_item("peer_key_id", ev.peer_key_id.clone())?;
    dict.set_item("transport_id", ev.transport_id.clone())?;
    dict.set_item("aspect", ev.aspect.clone())?;
    dict.set_item("identity_hash", ev.identity_hash.clone())?;
    dict.set_item("app_data", ev.app_data.clone())?;
    dict.set_item("rssi_dbm", ev.rssi_dbm)?;
    dict.set_item("snr_db", ev.snr_db)?;
    dict.set_item("link_id", ev.link_id.clone())?;
    dict.set_item("destination_hash", ev.destination_hash.clone())?;
    dict.set_item("hops", ev.hops)?;
    dict.set_item("resource_kind", ev.resource_kind.clone())?;
    dict.set_item("measurement", ev.measurement)?;
    dict.set_item("unit", ev.unit.clone())?;
    dict.set_item("lagged_count", ev.lagged_count)?;
    Ok(dict)
}

/// CIRISEdge#47 (v0.17.0) — extract the 32-byte local Ed25519 pubkey
/// plus look up the peer's 32-byte pubkey from the federation
/// directory. Used by [`PyEdge::peer_sas`] / [`PyEdge::peer_sas_digits`].
fn resolve_sas_pubkeys(
    py: Python<'_>,
    edge: &Arc<crate::Edge>,
    executor: &ciris_persist::ffi::executor_capsule::AsyncExecutor,
    peer_key_id: &str,
) -> PyResult<([u8; 32], [u8; 32])> {
    let local_signer = edge.signer();
    let dir = edge.verify_directory();
    let peer_id = peer_key_id.to_string();
    let (local_pub_bytes, peer_pub) = py.detach(|| {
        run_async(executor, async move {
            let local =
                local_signer.classical.public_key().await.map_err(|e| {
                    PyRuntimeError::new_err(format!("local signer public_key: {e}"))
                })?;
            let peer = dir
                .lookup_public_key(&peer_id)
                .await
                .map_err(|e| PyRuntimeError::new_err(format!("directory lookup: {e}")))?
                .ok_or_else(|| PyValueError::new_err(format!("peer not found: {peer_id:?}")))?;
            Ok::<_, PyErr>((local, peer))
        })
    })?;
    if local_pub_bytes.len() != 32 {
        return Err(PyValueError::new_err(format!(
            "local pubkey must be 32 bytes for SAS derivation, got {}",
            local_pub_bytes.len()
        )));
    }
    let mut local_pub = [0u8; 32];
    local_pub.copy_from_slice(&local_pub_bytes);
    Ok((local_pub, peer_pub))
}

/// Compute `body_sha256` (hex) for the inline-text payload that
/// `send_inline_text` / `send_durable_inline_text` will actually ship —
/// post-pipeline, so PII-scrubbed / secret-substituted bytes are what
/// the receiver matches an ACK against.
///
/// Runs the `speak_pipeline` against a clone of the text (the real
/// `send_inline` runs it against the message struct in place; we need
/// the post-pipeline bytes for the hex return value of
/// `send_inline_text` BEFORE the `send_inline` call consumes the
/// struct). Yes, the pipeline runs twice — once here for the SHA,
/// once inside `send_inline` for the wire. The pipeline is idempotent
/// and cheap; the double-run is the cost of the Python surface
/// returning the SHA synchronously rather than as a side-channel.
///
/// The hex form is what CIRISAgent's adapter joins on (persist's
/// `body_sha256_prefix` index is built on hex, and the existing
/// `EdgeCommunicationAdapter` plumbing is hex-shaped).
async fn compute_inline_text_body_sha(
    edge: &Edge,
    recipient: &str,
    raw_text: &str,
) -> PyResult<String> {
    use crate::handler::InlineTextMessage as _;
    let mut msg = InlineText {
        text: raw_text.to_string(),
    };
    // Run the same pipeline `send_inline` will run. If no pipeline is
    // configured this is a no-op. The pipeline's `run` is idempotent —
    // double-running it (here, then inside `send_inline`) produces the
    // same final bytes.
    edge.run_speak_pipeline_for_external(&mut msg)
        .await
        .map_err(|e| PyRuntimeError::new_err(format!("speak_pipeline: {e}")))?;

    // Build the envelope shape that `send_inline` will ship — same
    // canonical-body bytes feed `envelope_body_sha256`.
    let envelope = crate::identity::build_envelope(
        crate::messages::MessageType::InlineText,
        edge.signer_key_id(),
        recipient,
        &InlineText {
            text: msg.text().to_string(),
        },
        None,
    )
    .map_err(|e| PyRuntimeError::new_err(format!("build_envelope: {e}")))?;
    let sha = crate::identity::envelope_body_sha256(&envelope);
    Ok(hex_encode_32(&sha))
}

/// Hex-encode a 32-byte SHA-256 — same shape persist's
/// `body_sha256_prefix` index uses. 64 characters lowercase, no
/// prefix. Free function rather than via `hex` crate at the FFI
/// layer to keep the surface minimal (the `hex` crate is a
/// dev-dependency only).
fn hex_encode_32(bytes: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(64);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// Drainer thread body — receives `(sender_key_id, body_text)` tuples
/// from the Rust dispatcher's unbounded sender, acquires the GIL per
/// tuple, and invokes the Python callback. Exits when the channel
/// closes (the `Edge`'s subscriber entry was removed via
/// `unregister_inline_text_subscriber`).
///
/// Per `register_inline_text_handler`'s lifecycle contract: the
/// dispatcher's `send` returns `Err(SendError)` when this thread has
/// already exited (the `rx` is dropped), and the next dispatch's
/// `fan_out_inline_text` lazy-prunes the dead entry. So the
/// shutdown path is: caller invokes
/// `SubscriptionHandle::unsubscribe()` → `Edge::unregister_inline_text_subscriber`
/// drops the registry entry's sender → this `recv()` returns `None` →
/// drainer thread exits cleanly.
#[allow(clippy::needless_pass_by_value)] // callback is consumed by drop at function exit
fn drain_inline_text(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<(String, String)>,
    callback: Py<PyAny>,
) {
    while let Some((sender_key_id, body_text)) = rx.blocking_recv() {
        Python::attach(|py| {
            // Argument order MUST match the consumer-comment spec:
            // `callback(sender_key_id, body_text)`.
            if let Err(e) = callback.call1(py, (sender_key_id.clone(), body_text.clone())) {
                tracing::warn!(
                    sender_key_id = %sender_key_id,
                    error = %e,
                    "inline-text callback raised; continuing",
                );
            }
        });
    }
    // `recv` returned `None` — channel closed. The Python callback
    // refcount decrements when this function returns and `callback`
    // drops; that drop reacquires the GIL internally (pyo3 0.28
    // `Py::drop` is GIL-safe via the runtime's pending-decref queue).
}

/// Python-reachable durable-send handle (CIRISEdge#22 Tier 2 v0.9.0).
///
/// Returned by [`PyEdge::send_durable_inline_text`]. The agent's
/// `EdgeCommunicationAdapter` polls or awaits this to observe the
/// eventual ACK from the recipient. Per the consumer-comment Tier 2
/// surface:
///
/// - [`Self::is_acknowledged`] — `True` iff persist's
///   `outbound_status(queue_id)` reports `DurableOutcome::Delivered`
///   with a non-empty ACK envelope.
/// - [`Self::body_sha256`] — the 64-char hex `body_sha256` (the ACK
///   match key against persist's `body_sha256_prefix` index).
/// - [`Self::await_ack`] — synchronous wait up to `timeout_ms`; polls
///   `outbound_status` every 50ms (the [`AWAIT_ACK_POLL_INTERVAL_MS`]
///   constant); `True` if the row reaches ACK'd-delivered terminal
///   state within the timeout, `False` on timeout. Holds NO GIL
///   during the poll loop (the method's `py.detach` releases it).
#[pyclass(name = "DurableHandle", module = "ciris_edge")]
pub struct PyDurableHandle {
    /// `edge_outbound_queue.queue_id` — persist's primary key.
    queue_id: String,
    /// Pre-computed body_sha256 hex (the ACK match key). Captured at
    /// `send_durable_inline_text` time so the Python caller can match
    /// inbound ACKs by SHA without re-deriving from the envelope.
    body_sha256_hex: String,
    /// ABI-stable async executor — same one PyEdge holds; cloned at
    /// `send_durable_inline_text` time so the handle's own
    /// `is_acknowledged` / `await_ack` polls go through persist's
    /// runtime via the vtable (CIRISEdge#59).
    executor: Arc<ciris_persist::ffi::executor_capsule::AsyncExecutor>,
    /// Shared outbound-queue handle — same `Arc<dyn OutboundHandle>`
    /// the `Edge` holds. Cloning the Arc lets the handle outlive the
    /// `PyEdge` that produced it (Python ownership semantics differ
    /// from Rust borrow lifetimes).
    queue: Arc<dyn OutboundHandle>,
}

/// Drive an async future to completion from a synchronous PyMethod
/// context, via persist's ABI-stable async-executor capsule.
///
/// # Why this shape (CIRISEdge#58 / CIRISEdge#59 / CIRISPersist#157)
///
/// The pre-v1.1.8 implementation captured a `tokio::runtime::Handle`
/// from persist via `runtime_handle_capsule` and called
/// `runtime.spawn(fut)` from edge's code. With two `tokio` crates
/// statically linked into one process (one inside `ciris_edge.abi3.so`,
/// one inside `ciris_persist.abi3.so` — different patch versions in
/// practice), the `spawn` method was dispatched through **edge's**
/// tokio while the handle's underlying runtime data belonged to
/// **persist's** tokio. The cross-crate vtable mismatch silently
/// queued tasks into a runtime view whose workers nobody parked into
/// → ~27% deadlock rate on `send_durable_inline_text` against
/// cohabitating persist (CIRISEdge#58 thread dump; CIRISPersist#156
/// false-cause issue closed).
///
/// CIRISPersist v3.13.0 ships an ABI-stable `executor_capsule` whose
/// `vtable.spawn` function-pointer lives inside
/// `ciris_persist.abi3.so`. Invoking it from edge transfers control
/// into persist's `.so`, where persist's own tokio code calls
/// `runtime.spawn(...)` against the runtime it owns. The future ends
/// up on persist's worker pool; persist's workers poll it. No cross-
/// cdylib dispatch — same structural pattern that closed the
/// libsqlite3 cross-cdylib SIGSEGV class at CIRISPersist#141.
///
/// # The consumer contract
///
/// Per persist's executor_capsule docs: the spawned future runs on a
/// tokio worker owned by persist's tokio. Tokio thread-locals on that
/// worker belong to **persist's** tokio. **The spawned future MUST
/// NOT use edge's tokio primitives** — `tokio::time::*`,
/// `tokio::sync::Notify`, `tokio::spawn` (the free function), etc.
/// — because those resolve through edge's tokio, whose thread-locals
/// are unset on a persist-owned worker → `"there is no reactor
/// running"` panic.
///
/// What IS safe inside the spawned future:
/// - Calls to persist's public async API (`Engine::*`, trait methods
///   on `Arc<dyn FederationDirectory>` / `BackendDispatch`) — those
///   dispatch into persist's `.so` and use persist's tokio.
/// - `std::sync::mpsc` / std primitives (no tokio involvement).
/// - Pure-CPU work + `.await` points on persist-side futures.
///
/// Edge's own async surfaces (`Edge::send_durable_inline`,
/// `Edge::send_inline`, etc.) need a per-call-site audit (CIRISEdge#59
/// T5) to ensure they meet this contract.
///
/// # Diagnostics — env-controlled stall watchdog
///
/// Set `CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS` (default `5000`) to log
/// a `tracing::warn!` line every N ms the spawned task remains
/// outstanding. The line carries `elapsed_ms` so a tail of warnings
/// pinpoints the hang point in real time. Set to `0` to disable
/// the watchdog (plain `rx.recv()`, no timer overhead).
type BoxedFut = std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'static>>;

fn run_async<F, T>(executor: &ciris_persist::ffi::executor_capsule::AsyncExecutor, fut: F) -> T
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    // CIRISEdge#58 / #59: spawn via persist's executor_capsule
    // vtable — control transfers into persist's .so so the spawn
    // dispatches onto persist's tokio runtime, closing the cross-
    // cdylib tokio-aliasing class.
    let (tx, rx) = std::sync::mpsc::sync_channel::<T>(1);

    // Wrap the typed future into the executor's `Output = ()` shape
    // via the mpsc sender. The wrapping closure is *also* edge-side
    // code, but it only does `let _ = tx.send(fut.await)` — no tokio
    // primitives are referenced here, so polling on a persist worker
    // is safe.
    let inner_fut: BoxedFut = Box::pin(async move {
        let _ = tx.send(fut.await);
    });
    // The vtable contract: `task: *mut TaskOpaque` is a
    // `Box::into_raw`'d `Box<Pin<Box<dyn Future<Output = ()> + Send +
    // 'static>>>`. Construct that outer Box, lower to *mut TaskOpaque,
    // hand to the vtable.
    let outer_box: Box<BoxedFut> = Box::new(inner_fut);
    let task_ptr: *mut ciris_persist::ffi::executor_capsule::TaskOpaque =
        Box::into_raw(outer_box).cast();
    // SAFETY: `executor.data` and `task_ptr` satisfy the safety
    // contract documented on `AsyncExecutorVTable::spawn`:
    //   - `executor.data` is the opaque pointer produced by persist's
    //     `executor_capsule` for `executor.vtable` (we extracted both
    //     from the same `executor_capsule_v1` PyCapsule in init).
    //   - `task_ptr` is the `Box::into_raw`'d outer box for the inner
    //     pinned future, with the exact shape the vtable expects.
    //   - The Arc<Runtime> backing `executor.data` is alive because
    //     the PyCapsule is rooted in `PyEdge::executor` (Arc) and the
    //     PyCapsule itself is kept alive by the Python `engine` /
    //     `edge` references, which the caller holds for the duration
    //     of this call.
    #[allow(unsafe_code)]
    unsafe {
        (executor.vtable.spawn)(executor.data, task_ptr);
    }

    let stall_ms = std::env::var("CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(5_000);

    if stall_ms == 0 {
        return rx.recv().expect(
            "ciris_edge::run_async spawned task ended without sending \
             (panic inside the task or runtime shutdown — check tracing logs)",
        );
    }

    let timeout = std::time::Duration::from_millis(stall_ms);
    let start = std::time::Instant::now();
    loop {
        match rx.recv_timeout(timeout) {
            Ok(t) => return t,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                tracing::warn!(
                    elapsed_ms = u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
                    threshold_ms = stall_ms,
                    "ciris_edge::run_async stalled \u{2014} spawned task hasn't \
                     completed; the future or its substrate dep is wedged. \
                     Set CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS=0 to silence."
                );
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!(
                    "ciris_edge::run_async spawned task ended without sending \
                     (panic inside the task or runtime shutdown \u{2014} check \
                     tracing logs for the underlying error)"
                );
            }
        }
    }
}

/// Default poll interval for [`PyDurableHandle::await_ack`]. 50ms is
/// the value pinned in the issue body — a balance between caller-
/// observed latency (50ms median additional wait beyond the actual
/// ACK time) and persist DB churn (a busy chat session might see
/// dozens of pending durable sends; polling each at 50ms is well
/// inside SQLite's read budget).
const AWAIT_ACK_POLL_INTERVAL_MS: u64 = 50;

#[pymethods]
impl PyDurableHandle {
    /// `True` iff the outbound row has reached
    /// `DurableOutcome::Delivered` with an ACK envelope attached.
    /// Polls persist's `outbound_status(queue_id)` once; non-blocking
    /// in the sense that it does NOT wait. For "wait until ACK'd"
    /// semantics, use [`Self::await_ack`].
    fn is_acknowledged(&self, py: Python<'_>) -> PyResult<bool> {
        let queue_id = self.queue_id.clone();
        let queue = self.queue.clone();
        let executor = self.executor.clone();
        py.detach(|| {
            run_async(&executor, async move {
                let row = queue
                    .outbound_status(&queue_id)
                    .await
                    .map_err(|e| PyRuntimeError::new_err(format!("outbound_status: {e}")))?;
                Ok(matches!(
                    row.map(|r| crate::edge::map_outbound_row_to_status(&r)),
                    Some(DurableStatus::Terminal(DurableOutcome::Delivered {
                        ack: _,
                        ..
                    })),
                ))
            })
        })
    }

    /// The 64-char hex `body_sha256` — the ACK match key into persist's
    /// `body_sha256_prefix` index.
    fn body_sha256(&self) -> &str {
        &self.body_sha256_hex
    }

    /// Synchronous wait up to `timeout_ms` for the durable row to
    /// reach ACK'd-delivered terminal state. Polls every 50ms
    /// ([`AWAIT_ACK_POLL_INTERVAL_MS`]). Returns `True` if ACK'd
    /// within the window, `False` on timeout.
    ///
    /// GIL is released for the entire poll loop via `py.detach`.
    fn await_ack(&self, py: Python<'_>, timeout_ms: u64) -> PyResult<bool> {
        let executor = self.executor.clone();
        py.detach(|| {
            // CIRISEdge#59 — the previous version did the poll loop
            // *inside* the spawned future via `tokio::time::sleep` +
            // `tokio::time::Instant`. Both resolve through edge's
            // tokio crate; when the future runs on persist's worker
            // (via the executor capsule's vtable dispatch), those
            // tokio thread-locals are unset → "no reactor running"
            // panic. The fix moves the loop OUTSIDE the spawned
            // future: each iteration spawns a single
            // `outbound_status` call (which uses persist's tokio
            // entirely, via the OutboundHandle trait dispatch), the
            // loop and sleep run on the GIL-released py.detach
            // thread using std primitives. Cost: one spawn per
            // 50ms poll instead of one spawn for the whole loop.
            let deadline = std::time::Instant::now() + Duration::from_millis(timeout_ms);
            loop {
                let queue_id = self.queue_id.clone();
                let queue = self.queue.clone();
                let executor_ref = &executor;
                let row = run_async(executor_ref, async move {
                    queue
                        .outbound_status(&queue_id)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("outbound_status: {e}")))
                })?;
                if let Some(r) = row {
                    if matches!(
                        crate::edge::map_outbound_row_to_status(&r),
                        DurableStatus::Terminal(DurableOutcome::Delivered { .. }),
                    ) {
                        return Ok::<bool, pyo3::PyErr>(true);
                    }
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                std::thread::sleep(Duration::from_millis(AWAIT_ACK_POLL_INTERVAL_MS));
            }
        })
    }

    /// `edge_outbound_queue.queue_id` — diagnostic surface. Persist's
    /// primary key into the outbound row.
    #[getter]
    fn queue_id(&self) -> &str {
        &self.queue_id
    }
}

/// Python-reachable subscription handle (CIRISEdge#22 Tier 2 v0.9.0).
///
/// Returned by [`PyEdge::register_inline_text_handler`]. Three ways to
/// tear down the subscription, all equivalent at the registry level:
///
/// 1. **Explicit**: `sub.unsubscribe()` — synchronous removal.
/// 2. **Context manager**: `with edge.register_inline_text_handler(cb) as sub:` —
///    `__exit__` calls `unsubscribe()`.
/// 3. **GC**: when the last Python reference drops, Rust's
///    [`Drop`] impl on `PySubscriptionHandle` removes the registry
///    entry. The drainer thread observes the closed channel and exits.
///
/// All three paths invoke [`Edge::unregister_inline_text_subscriber`]
/// + join the drainer thread; the operation is idempotent (a
/// double-unsubscribe is `Ok` with the count going from 1 → 0 → 0).
#[pyclass(name = "SubscriptionHandle", module = "ciris_edge")]
pub struct PySubscriptionHandle {
    /// Subscription id allocated by `Edge::register_inline_text_subscriber`.
    id: u64,
    /// `Weak<Edge>` — the registry is owned by `Edge`; we hold a weak
    /// ref so the handle's `Drop` doesn't transitively keep `Edge`
    /// alive (the Python `Edge` object's lifecycle is the source of
    /// truth, not the subscription handle's).
    edge: std::sync::Weak<Edge>,
    /// The drainer thread spawned at registration. `Mutex<Option<_>>`
    /// so a `JoinHandle::join` (which takes ownership) can run from
    /// `unsubscribe()` exactly once; subsequent calls observe `None`
    /// and no-op (idempotent unsubscribe).
    drainer_thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

#[pymethods]
impl PySubscriptionHandle {
    /// Tear down the subscription. Removes the entry from the `Edge`'s
    /// inline-text subscriber registry (so subsequent inbounds don't
    /// fan out to it), drops the unbounded-channel sender (so the
    /// drainer thread observes a closed channel on its next `recv()`),
    /// and joins the drainer thread before returning (so a unit test
    /// that calls `unsubscribe()` and then asserts the callback was
    /// NOT invoked has a strict happens-before guarantee — the
    /// drainer is GONE before `unsubscribe` returns). Idempotent.
    #[allow(clippy::unnecessary_wraps)] // PyResult kept for symmetry with __exit__ + future-proofing
    fn unsubscribe(&self, py: Python<'_>) -> PyResult<()> {
        // Step 1: remove from the registry. After this, no further
        // inbound dispatches will push tuples onto our channel.
        if let Some(edge) = self.edge.upgrade() {
            edge.unregister_inline_text_subscriber(self.id);
        }
        // Step 2: take the drainer thread handle. After
        // `unregister_inline_text_subscriber`, the sender is dropped
        // and the drainer's next `recv()` returns `None` and exits.
        // Join it under released GIL (the drainer thread may itself
        // try to acquire the GIL on its final callback drop — hold
        // ours during the join and we deadlock).
        let handle_opt = {
            let mut guard = self
                .drainer_thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        };
        if let Some(handle) = handle_opt {
            py.detach(|| {
                let _ = handle.join();
            });
        }
        Ok(())
    }

    /// Context-manager entry — returns `self` for the `with` binding.
    fn __enter__(slf: PyRef<'_, Self>) -> PyRef<'_, Self> {
        slf
    }

    /// Context-manager exit — calls [`Self::unsubscribe`] regardless
    /// of whether the block exited normally or via exception. The
    /// `*_args` are the (exc_type, exc_value, traceback) tuple
    /// Python's protocol passes; we don't suppress exceptions
    /// (return `None`/`False`-equivalent).
    fn __exit__(
        &self,
        py: Python<'_>,
        _exc_type: Py<PyAny>,
        _exc_value: Py<PyAny>,
        _traceback: Py<PyAny>,
    ) -> PyResult<bool> {
        self.unsubscribe(py)?;
        Ok(false)
    }

    /// Subscription id — diagnostic surface.
    #[getter]
    fn id(&self) -> u64 {
        self.id
    }
}

impl Drop for PySubscriptionHandle {
    /// GC-time cleanup. If the Python user dropped the handle without
    /// calling `unsubscribe()` or using it as a context manager, this
    /// fires (during Python finalization or eager refcount-zero). The
    /// effect is identical to [`PySubscriptionHandle::unsubscribe`]
    /// minus the GIL release on the join — `Drop` runs under whatever
    /// GIL state Python's destruction is using; pyo3 0.28 does not
    /// expose a portable "drop without GIL" idiom here so we accept a
    /// short blocking join (the drainer exits within one poll tick
    /// of its `recv()` once the sender drops).
    fn drop(&mut self) {
        if let Some(edge) = self.edge.upgrade() {
            edge.unregister_inline_text_subscriber(self.id);
        }
        let handle_opt = {
            let mut guard = self
                .drainer_thread
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.take()
        };
        if let Some(handle) = handle_opt {
            let _ = handle.join();
        }
    }
}

/// Consumer-side hybrid PQC acceptance policy choice, exposed as a
/// string kwarg on [`init_edge_runtime`]. Mirrors persist's
/// v0.18.0 (CIRISEdge#46) — extract a [`crate::CanonicalBootstrapPeer`]
/// from a Python item (dict literal OR object exposing matching attrs).
///
/// Accepted shapes (Python-side):
/// ```python
/// {"key_id": "...", "alias": "...", "pubkey_ed25519_base64": "...",
///  "transport_hint": "tcp://...", "description": "..."}
/// ```
/// or any object exposing the same attributes (a dataclass, NamedTuple,
/// or persist-emitted type). The two-mode fallback is the same shape
/// `extract_capsule` uses elsewhere: `getattr` first, then mapping
/// access. `transport_hint` and `description` are optional; the others
/// are required and a missing field surfaces a typed `ValueError`.
fn extract_canonical_bootstrap_peer(
    item: &Bound<'_, PyAny>,
) -> PyResult<crate::CanonicalBootstrapPeer> {
    /// Helper: read a string field by name, trying attribute access
    /// first then dict-like `__getitem__`. Returns the field's bound
    /// PyAny (a `String` extraction happens at the caller).
    fn read_field<'py>(item: &Bound<'py, PyAny>, name: &str) -> Option<Bound<'py, PyAny>> {
        if let Ok(attr) = item.getattr(name) {
            if !attr.is_none() {
                return Some(attr);
            }
        }
        match item.get_item(name) {
            Ok(value) => {
                if value.is_none() {
                    None
                } else {
                    Some(value)
                }
            }
            Err(_) => None,
        }
    }

    let key_id: String = read_field(item, "key_id")
        .ok_or_else(|| PyValueError::new_err("canonical_bootstrap_peers: missing key_id"))?
        .extract()
        .map_err(|e| PyValueError::new_err(format!("canonical_bootstrap_peers.key_id: {e}")))?;
    let alias: String = read_field(item, "alias")
        .map(|v| v.extract::<String>())
        .transpose()
        .map_err(|e| PyValueError::new_err(format!("canonical_bootstrap_peers.alias: {e}")))?
        .unwrap_or_default();
    let pubkey_ed25519_base64: String = read_field(item, "pubkey_ed25519_base64")
        .ok_or_else(|| {
            PyValueError::new_err(format!(
                "canonical_bootstrap_peers[{key_id:?}]: missing pubkey_ed25519_base64",
            ))
        })?
        .extract()
        .map_err(|e| {
            PyValueError::new_err(format!(
                "canonical_bootstrap_peers[{key_id:?}].pubkey_ed25519_base64: {e}",
            ))
        })?;
    let transport_hint: Option<String> = read_field(item, "transport_hint")
        .map(|v| v.extract::<String>())
        .transpose()
        .map_err(|e| {
            PyValueError::new_err(format!(
                "canonical_bootstrap_peers[{key_id:?}].transport_hint: {e}",
            ))
        })?;
    let description: Option<String> = read_field(item, "description")
        .map(|v| v.extract::<String>())
        .transpose()
        .map_err(|e| {
            PyValueError::new_err(format!(
                "canonical_bootstrap_peers[{key_id:?}].description: {e}",
            ))
        })?;

    Ok(crate::CanonicalBootstrapPeer {
        key_id,
        alias,
        pubkey_ed25519_base64,
        transport_hint,
        description,
    })
}

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

/// v0.9.2 (CIRISEdge#22 / CIRISPersist#109) — call a host engine's
/// `*_capsule` `#[pymethod]`, extract the typed reference from the
/// returned `PyCapsule`, and hand it to `map` to produce an owned
/// value that outlives the capsule.
///
/// The host engine is supplied as `Bound<'_, PyAny>` (NOT
/// `PyRef<PyEngine>`) because PyO3 `#[pyclass]` registration is
/// per-extension-module — when persist and edge ship as separate
/// `.so`s, each has its own `PyTypeInfo` for `PyEngine` and the
/// cross-module isinstance check rejects. `Bound<PyAny>` accepts any
/// object that exposes the named `#[pymethod]`; the capsule's
/// name-tag is what enforces the wrapped-type invariant instead.
///
/// The `map` closure runs while the capsule is alive (the `Bound`
/// owning it is on the stack frame here), so the `&T` it receives is
/// safe to dereference. Typical implementations clone an `Arc` out of
/// the reference or construct an owned struct field-by-field — both
/// produce an owned value the caller can carry past this function.
///
/// # Safety
///
/// The caller MUST guarantee that:
///
/// 1. `method` is the name of a `#[pymethod]` on `engine` that returns
///    a `PyCapsule` whose wrapped type is exactly `T`. The valid
///    `(method, T)` pairs are pinned by `ciris-persist`'s
///    `src/ffi/pyo3.rs` v2.7.0+ / v2.8.0+ docblocks:
///    - `"federation_directory_capsule"` wraps
///      `Arc<dyn ciris_persist::federation::FederationDirectory>` (v2.7.0)
///    - `"outbound_queue_capsule"` wraps
///      `ciris_persist::BackendDispatch` (v2.7.0)
///    - `"keyring_signer_capsule"` wraps
///      `ciris_persist::signing::KeyringSignerHandle` (v2.7.0)
///    - `"runtime_handle_capsule"` wraps
///      `tokio::runtime::Handle` (v2.8.0 — CIRISPersist#111
///      cross-cdylib statics fix)
///    - `"local_signer_capsule"` wraps
///      `std::sync::Arc<ciris_persist::signing::LocalSigner>`
///      (v3.1.1 — CIRISPersist#119; the 32-byte Ed25519 transport-
///      identity surface consumed by `ReticulumTransport::new` for
///      federation identity attestation under `hardware_hsm_only`
///      keyring storage). Extracted via the typed-fallback
///      [`extract_local_signer`] helper rather than this generic
///      helper, because it has a fall-back-able `Unavailable`
///      failure mode the others do not.
/// 2. Edge's `Cargo.toml` pins `ciris-persist = "3", tag = "v3.2.0"`
///    and pyproject.toml pins `ciris-persist>=3.2.0,<4` — together,
///    these enforce that the host engine's `*_capsule` pymethods exist,
///    return a `PyCapsule`, and carry the wrapped types persist's
///    docblocks document.
/// 3. `T` is `'static` and is the EXACT Rust type persist wraps. A
///    mismatched `T` here is undefined behaviour — the helper's
///    `unsafe` is precisely this assertion.
///
/// On engine-method-missing / capsule-type-mismatch this returns a
/// typed `PyTypeError` rather than panicking — the cohabitation
/// handshake is the well-defined error site for "engine doesn't
/// expose the persist 2.7.0+ cohabitation surface".
#[allow(unsafe_code)]
unsafe fn extract_capsule<T, R, F>(engine: &Bound<'_, PyAny>, method: &str, map: F) -> PyResult<R>
where
    T: 'static,
    F: FnOnce(&T) -> R,
{
    let result = engine.call_method0(method).map_err(|e| {
        PyTypeError::new_err(format!(
            "engine doesn't expose {method:?} method (persist 2.7.0+ \
             cohabitation surface required): {e}"
        ))
    })?;
    let cap: Bound<'_, PyCapsule> = result.cast_into::<PyCapsule>().map_err(|e| {
        PyTypeError::new_err(format!(
            "engine.{method}() did not return a PyCapsule (got {e}); \
             persist 2.7.0+ cohabitation contract violated"
        ))
    })?;
    // SAFETY: per the function-level `# Safety` clause, the caller has
    // committed that `T` matches the wrapped type persist's
    // `<method>_capsule` `#[pymethod]` produces. The crate pin floors
    // (Cargo.toml git tag v2.7.0; pyproject ciris-persist>=2.7.0)
    // enforce that the method exists and that its documented wrapped
    // type is in effect. The capsule is alive for the entire `map`
    // closure call — `cap` owns the `Bound` — so the `&T` reference
    // produced by `reference::<T>()` is valid for the duration of the
    // map closure. The deprecation on `PyCapsule::reference` is
    // acknowledged: 0.28 ships `pointer_checked` as the
    // non-deprecated alternative, and 0.29 REMOVES `reference()` —
    // edge v3.0.0 (CIRISEdge#89) consumes `pointer_checked` with the
    // same unsafe deref + cast at the call site. The safety surface
    // is unchanged from the .reference() era; the SAFETY comment on
    // the function-level docs still applies in full.
    // v3.0.0 (CIRISEdge#89) — pyo3 0.29's `pointer_checked(name)`
    // enforces a name match against the capsule's stored name when
    // `name` is `Some`; `None` is only valid for unnamed capsules.
    // Persist's capsules ALL have names (e.g.
    // `c"ciris_persist::federation_directory"`), so we MUST pass the
    // capsule's own name back through. Extracting via `cap.name()`
    // returns the capsule-stored name as a `CapsuleName`; the
    // `.as_cstr()` view feeds straight into `pointer_checked`.
    // SAFETY (cap.name().as_cstr()): `CapsuleName::as_cstr` requires
    // the capsule's name not to change between the `.name()` call and
    // the `.pointer_checked()` call. We hold `cap` (the `Bound`) for
    // both, no Python code runs between them, and the capsule's name
    // is set once at construction in persist — no SetName drift.
    let name = cap
        .name()
        .map_err(|e| PyTypeError::new_err(format!("engine.{method}(): capsule name: {e}")))?;
    let name_cstr = name.as_ref().map(|n| unsafe { n.as_cstr() });
    let ptr = cap
        .pointer_checked(name_cstr)
        .map_err(|e| PyTypeError::new_err(format!("engine.{method}(): pointer_checked: {e}")))?;
    let inner: &T = unsafe { &*(ptr.as_ptr() as *const T) };
    Ok(map(inner))
}

/// v0.16.1 cherry-pick (CIRISEdge#43 / CIRISPersist#119) — typed
/// outcome of the `local_signer_capsule` extraction attempt. Only
/// [`init_edge_runtime`] consumes this; the variants drive the
/// fallback-vs-hard-error decision in Step 3.5.
#[cfg(feature = "transport-reticulum")]
enum LocalSignerCapsuleError {
    /// Engine doesn't expose `local_signer_capsule` at all (persist
    /// older than v3.1.1). Fallback to keyring_signer for transport
    /// identity; log a warning naming the persist upgrade path.
    MethodAbsent,
    /// Engine exposes the method but raised the typed
    /// `ValueError("local_signer_unavailable")` — the agent
    /// constructed the engine without `local_key_id` + `local_key_path`
    /// (pre-2.12.0 / #112 init paths). Fallback to keyring_signer for
    /// transport identity; log a warning naming the init-path upgrade.
    Unavailable,
    /// Any other failure (capsule cast mismatch, unexpected exception
    /// type) — surface as a hard error from `init_edge_runtime` rather
    /// than silently fall back.
    Other(PyErr),
}

/// v0.20.0 RC1 (CIRISEdge#51 / CIRISPersist#129) — typed outcome of
/// the `trust_scoring_capsule` extraction attempt. Only
/// [`init_edge_runtime`] consumes this; the variants drive the
/// fallback-vs-hard-error decision at the v0.20.0 RC1 wiring site —
/// missing method AND the typed `trust_scoring_unavailable`
/// ValueError both fall back to the v0.19.6 bootstrap-permissive
/// `trust_scoring = None` posture.
#[cfg(feature = "transport-reticulum")]
enum TrustScoringCapsuleError {
    /// Engine doesn't expose `trust_scoring_capsule` at all (persist
    /// older than v3.5.1). Fallback to `None` posture (bootstrap-
    /// permissive); log a warning naming the persist upgrade path.
    MethodAbsent,
    /// Engine exposes the method but raised the typed
    /// `ValueError("trust_scoring_unavailable")` — no `AdmissionGate`
    /// has been installed via `Engine::set_admission_gate`.
    /// Fallback to `None` posture; log an info-level breadcrumb (this
    /// is the expected bootstrap default until the operator opts
    /// into trust-gated dispatch).
    Unavailable,
    /// Any other failure (capsule cast mismatch, unexpected exception
    /// type) — surface as a hard error from `init_edge_runtime` rather
    /// than silently fall back. Loud-fail per the v0.13.0 contract.
    Other(PyErr),
}

/// v0.20.0 RC1 (CIRISEdge#51 / CIRISPersist#129) — extract the
/// persist trust-scoring `Arc<dyn TrustScoring>` from the shared
/// engine's `trust_scoring_capsule()` pymethod.
///
/// Returns:
/// - `Ok(Arc<dyn TrustScoring>)` on success — the wrapped Arc is
///   cloned out of the capsule for the caller to keep beyond the
///   capsule's lifetime.
/// - `Err(TrustScoringCapsuleError::MethodAbsent)` when
///   `engine.hasattr("trust_scoring_capsule")` is false. Persist older
///   than v3.5.1 — fall back to the v0.19.6 `None` posture.
/// - `Err(TrustScoringCapsuleError::Unavailable)` when the method
///   exists but raised `ValueError("trust_scoring_unavailable")`.
///   Persist v3.5.1+ with no installed admission gate — also fall
///   back to the `None` posture (the bootstrap default).
/// - `Err(TrustScoringCapsuleError::Other(_))` for any other failure
///   (non-PyCapsule return value, wrong capsule name tag, etc.) —
///   loud-fail at the init boundary.
///
/// Mirrors [`extract_local_signer`]'s shape: a capsule with a
/// fall-back-able failure mode (typed
/// `trust_scoring_unavailable` ValueError) needs its own typed-outcome
/// helper rather than the generic [`extract_capsule`] path (which
/// hard-fails on any method-call exception).
///
/// Capsule contract (CIRISPersist v3.5.1 / src/ffi/pyo3.rs):
/// - Name tag: `"ciris_persist::trust_scoring"`
/// - Wrapped type: `Arc<dyn ciris_persist::federation::TrustScoring>`
#[cfg(feature = "transport-reticulum")]
#[allow(unsafe_code)]
fn extract_trust_scoring(
    engine: &Bound<'_, PyAny>,
) -> Result<Arc<dyn ciris_persist::federation::TrustScoring>, TrustScoringCapsuleError> {
    if !engine.hasattr("trust_scoring_capsule").unwrap_or(false) {
        return Err(TrustScoringCapsuleError::MethodAbsent);
    }
    let result = engine.call_method0("trust_scoring_capsule").map_err(|e| {
        // Distinguish the typed
        // `ValueError("trust_scoring_unavailable")` from any other
        // exception. Persist v3.5.1's `trust_scoring_capsule_py`
        // raises ONLY that exact ValueError when no
        // AdmissionGate is installed; anything else is a real
        // error.
        Python::attach(|py| {
            if e.is_instance_of::<PyValueError>(py)
                && e.value(py).to_string() == "trust_scoring_unavailable"
            {
                TrustScoringCapsuleError::Unavailable
            } else {
                TrustScoringCapsuleError::Other(PyTypeError::new_err(format!(
                    "engine.trust_scoring_capsule() raised: {e}"
                )))
            }
        })
    })?;
    let cap: Bound<'_, PyCapsule> = result.cast_into::<PyCapsule>().map_err(|e| {
        TrustScoringCapsuleError::Other(PyTypeError::new_err(format!(
            "engine.trust_scoring_capsule() did not return a PyCapsule (got {e}); \
             persist 3.5.1 cohabitation contract violated"
        )))
    })?;
    // SAFETY: persist v3.5.1+'s `trust_scoring_capsule_py` wraps an
    // `Arc<dyn ciris_persist::federation::TrustScoring>` under the
    // name tag `"ciris_persist::trust_scoring"`. The Cargo pin
    // (`ciris-persist = { tag = "v3.6.3", version = "3" }`) enforces
    // that contract (v3.6.3 carries v3.5.1's surface forward via
    // v3.5.2 + v3.6.0). The cloned `Arc` is owned by the caller —
    // the capsule reference doesn't escape this function.
    // v3.0.0 (CIRISEdge#89) — pyo3 0.29 removes `.reference()`;
    // use `pointer_checked` + cast (same safety contract as before).
    // pyo3 0.29's `pointer_checked(name)` enforces a name match; pass
    // the capsule's own name through. See `extract_engine_capsule_arc`
    // above for the matching pattern + SAFETY rationale.
    let name = cap.name().map_err(|e| {
        TrustScoringCapsuleError::Other(PyTypeError::new_err(format!(
            "trust_scoring_capsule: capsule name: {e}"
        )))
    })?;
    let name_cstr = name.as_ref().map(|n| unsafe { n.as_cstr() });
    let ptr = cap.pointer_checked(name_cstr).map_err(|e| {
        TrustScoringCapsuleError::Other(PyTypeError::new_err(format!(
            "trust_scoring_capsule: pointer_checked: {e}"
        )))
    })?;
    let inner: &Arc<dyn ciris_persist::federation::TrustScoring> =
        unsafe { &*(ptr.as_ptr() as *const Arc<dyn ciris_persist::federation::TrustScoring>) };
    Ok(Arc::clone(inner))
}

/// v0.16.1 cherry-pick (CIRISEdge#43 / CIRISPersist#119) — extract the
/// persist transport-identity `Arc<LocalSigner>` from the shared
/// engine's `local_signer_capsule()` pymethod.
///
/// Returns:
/// - `Ok(Arc<ciris_persist::signing::LocalSigner>)` on success — the
///   wrapped Arc is cloned out of the capsule for the caller to keep
///   beyond the capsule's lifetime.
/// - `Err(LocalSignerCapsuleError::MethodAbsent)` when
///   `engine.hasattr("local_signer_capsule")` is false.
/// - `Err(LocalSignerCapsuleError::Unavailable)` when the method
///   exists but raised `ValueError("local_signer_unavailable")`.
/// - `Err(LocalSignerCapsuleError::Other(_))` for any other failure
///   (non-PyCapsule return value, wrong capsule name tag, etc.).
///
/// Distinct from [`extract_capsule`] because the local_signer path
/// has a fall-back-able failure mode (the typed
/// `local_signer_unavailable` ValueError) that the other capsules do
/// not — for those, a missing method is a hard "wrong persist version"
/// error.
#[cfg(feature = "transport-reticulum")]
#[allow(unsafe_code)]
fn extract_local_signer(
    engine: &Bound<'_, PyAny>,
) -> Result<Arc<ciris_persist::signing::LocalSigner>, LocalSignerCapsuleError> {
    if !engine.hasattr("local_signer_capsule").unwrap_or(false) {
        return Err(LocalSignerCapsuleError::MethodAbsent);
    }
    let result = engine.call_method0("local_signer_capsule").map_err(|e| {
        // Distinguish the typed `ValueError("local_signer_unavailable")`
        // from any other exception. Persist v3.1.1's
        // `local_signer_capsule_py` raises ONLY that exact
        // ValueError when the engine wasn't constructed with
        // local_key_id + local_key_path; anything else is a real
        // error.
        Python::attach(|py| {
            if e.is_instance_of::<PyValueError>(py)
                && e.value(py).to_string() == "local_signer_unavailable"
            {
                LocalSignerCapsuleError::Unavailable
            } else {
                LocalSignerCapsuleError::Other(PyTypeError::new_err(format!(
                    "engine.local_signer_capsule() raised: {e}"
                )))
            }
        })
    })?;
    let cap: Bound<'_, PyCapsule> = result.cast_into::<PyCapsule>().map_err(|e| {
        LocalSignerCapsuleError::Other(PyTypeError::new_err(format!(
            "engine.local_signer_capsule() did not return a PyCapsule (got {e}); \
             persist 3.1.1 cohabitation contract violated"
        )))
    })?;
    // SAFETY: persist v3.1.1+'s `local_signer_capsule_py` wraps a
    // `Arc<ciris_persist::signing::LocalSigner>` under the name tag
    // `"ciris_persist::local_signer"`. The Cargo pin
    // (`ciris-persist = { tag = "v3.2.0", version = "3" }`) enforces
    // that contract (v3.2.0 carries v3.1.1's surface forward). The
    // cloned `Arc` is owned by the caller — the capsule reference
    // doesn't escape this function.
    // v3.0.0 (CIRISEdge#89) — pyo3 0.29 removes `.reference()`;
    // use `pointer_checked` + cast (same safety contract as before).
    // pyo3 0.29's `pointer_checked(name)` enforces a name match; pass
    // the capsule's own name through. See `extract_engine_capsule_arc`
    // above for the matching pattern + SAFETY rationale.
    let name = cap.name().map_err(|e| {
        LocalSignerCapsuleError::Other(PyTypeError::new_err(format!(
            "local_signer_capsule: capsule name: {e}"
        )))
    })?;
    let name_cstr = name.as_ref().map(|n| unsafe { n.as_cstr() });
    let ptr = cap.pointer_checked(name_cstr).map_err(|e| {
        LocalSignerCapsuleError::Other(PyTypeError::new_err(format!(
            "local_signer_capsule: pointer_checked: {e}"
        )))
    })?;
    let inner: &Arc<ciris_persist::signing::LocalSigner> =
        unsafe { &*(ptr.as_ptr() as *const Arc<ciris_persist::signing::LocalSigner>) };
    Ok(Arc::clone(inner))
}

/// Construct an [`Edge`] from the host's shared persist engine.
///
/// This is the CIRIS 3.0 cohabitation entry point (CIRISEdge#16,
/// merge blocker for CIRISPersist#85; v0.9.2 cohabitation fix per
/// CIRISEdge#22 / CIRISPersist#109). The Python agent calls this
/// **once** during process bootstrap, after constructing its
/// `ciris_persist.Engine`, and hands the returned [`PyEdge`] to
/// CIRISNodeCore + CIRISLensCore bootstrap functions.
///
/// # v0.9.2 cohabitation contract
///
/// `engine` is `Bound<'_, PyAny>` (NOT `PyRef<PyEngine>`) because
/// PyO3 `#[pyclass]` registration is per-extension-module: with
/// `ciris_persist.abi3.so` and `ciris_edge.abi3.so` shipped as separate
/// wheels, the cross-module isinstance check on `PyEngine` always
/// rejects (v0.9.1 production regression). We accept anything that
/// exposes the persist 2.7.0+ `*_capsule` `#[pymethod]` surface and
/// pull the substrate handles via `PyCapsule` opaque-pointer extraction
/// (see [`extract_capsule`] for the safety contract).
///
/// # Substrate composition
///
/// - Calls `engine.federation_directory_capsule()` → extracts
///   `Arc<dyn FederationDirectory>` → coerces to
///   `Arc<dyn VerifyDirectory>` via the blanket impl in
///   `crate::verify`.
/// - Calls `engine.outbound_queue_capsule()` → extracts
///   [`BackendDispatch`] → matches the variant → wraps as both
///   `Arc<dyn RootingDirectory>` and `Arc<dyn OutboundHandle>` via
///   the blanket impls in `crate::verify` and `crate::outbound`.
/// - Calls `engine.keyring_signer_capsule()` → extracts
///   `KeyringSignerHandle` (`Arc<dyn HardwareSigner>` +
///   `Option<Arc<dyn PqcSigner>>` + `key_id`) and wraps them in edge's
///   own [`LocalSigner`]. This drives the hot-path scrub-envelope
///   signing surface (`Edge::send_durable`). The keyring identity is
///   NOT re-bootstrapped — the cohabitation invariant is "one keyring
///   identity per host"
///   (`docs/COHABITATION.md` rule 1).
/// - v0.16.1 cherry-pick (CIRISEdge#43): Calls
///   `engine.local_signer_capsule()` → extracts
///   `Arc<ciris_persist::signing::LocalSigner>`, wraps it in
///   `ciris_persist::signing::LocalSignerHardwareAdapter` (32-byte raw
///   Ed25519 `public_key`), and threads it into the
///   `ReticulumAuth.signer` field as the federation Ed25519 identity.
///   When the engine raises the typed
///   `ValueError("local_signer_unavailable")` (older cohab-init paths
///   predating persist v2.12.0 / #112), falls back to using the
///   keyring signer for transport identity — the v0.13.0 behavior;
///   the operator gets a warning log naming the upgrade path. Under
///   `keyring_storage_kind = hardware_hsm_only` the fallback path
///   will fail at `ReticulumTransport::new` with the v0.13.0
///   65-byte-pubkey error shape (the diagnostic the operator needs
///   to see).
/// - v0.16.1 (CIRISEdge#33 durability flip): derives
///   `Arc<dyn BlackholeRules>` from the already-extracted
///   `BackendDispatch` and threads it into [`ReticulumAuth`] so the
///   transport's operator deny-list is persisted via the V052
///   `cirislens.blackhole_rules` table.
/// - Builds a [`ReticulumTransport`] with [`ReticulumAuth`] wiring
///   the transport-identity signer + rooting directory + the
///   configured hybrid policy + the durable blackhole store. The
///   transport's authenticated cold-start path (CIRISEdge#15, AV-42
///   closure) is then live.
/// - Assembles `Edge::builder().directory(..).queue(..).signer(..)
///   .transport(..).build()` and returns the [`PyEdge`] wrapper.
///
/// # Python signature
///
/// ```python
/// edge = ciris_edge.init_edge_runtime(
///     engine,                       # ciris_persist.Engine (or any
///                                   # object exposing the persist
///                                   # 2.7.0+ *_capsule pymethods)
///     identity_path="/var/lib/ciris/transport.id",
///     listen_addr="0.0.0.0:4242",
///     bootstrap_peers=["1.2.3.4:4242"],
///     announce_interval_seconds=300,
///     local_epoch=0,
///     hybrid_policy="strict",
///     enable_transport=True,        # CIRISEdge#168 (v5.0) — public
///                                   # fabric node forwards packets for
///                                   # NAT'd mobile edges (§24); leaf
///                                   # edges leave this False
///     agent_mode="server",          # v0.18.0 (CIRISEdge#45);
///                                   # v0.20.0 RC1 (CIRISEdge#51)
///                                   # extends to CEWP L0/L1 tier
///                                   # defaults
///     # Optional v0.20.0 RC1 operator overrides:
///     disk_budget_bytes=512 * 1024**3,  # Override Server's 1 TB L1
///                                       # default; advisory at edge
///     trust_recursion_depth=0,          # Override Server's depth=1
///                                       # default to strict
/// )
/// ```
///
/// # AV-17 invariant
///
/// The federation seed never crosses the FFI boundary — only the
/// `Arc<dyn HardwareSigner>` handle does, and only via the capsule
/// (which carries an opaque pointer the consumer reinterprets as the
/// pinned-by-version wrapped type). The transport-tier Reticulum
/// identity at `identity_path` is a separate dual-key identity
/// generated by the transport itself (`src/transport/reticulum.rs`
/// §"Identity model").
// v2.3.0 (CIRISEdge#100) — Reticulum shared-instance role token.
// Parsed once from `init_edge_runtime`'s `local_instance_role` kwarg
// and consumed by the election branch below. Module-private (no
// `pub`) because the only consumer is `init_edge_runtime` itself —
// hoisted out of the function body purely to satisfy
// `clippy::items_after_statements`.
#[cfg(feature = "transport-reticulum")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalInstanceRole {
    Auto,
    Server,
    Client,
}

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
    agent_mode = "proxy",
    canonical_bootstrap_peers = None,
    https_listen_addr = None,
    https_tls_cert_path = None,
    https_tls_key_path = None,
    https_mtls_required = false,
    https_bearer_secret = None,
    https_dev_self_signed = false,
    disable_reticulum = false,
    disk_budget_bytes = None,
    trust_recursion_depth = None,
    local_instance_name = None,
    local_instance_role = "auto",
    agent_occurrence_key_id = None,
    transport_identity_keyring_dir = None,
    enable_transport = false,
))]
#[allow(
    clippy::too_many_arguments,
    clippy::needless_pass_by_value,
    clippy::too_many_lines,
    clippy::fn_params_excessive_bools
)]
fn init_edge_runtime(
    py: Python<'_>,
    engine: Bound<'_, PyAny>,
    identity_path: &str,
    listen_addr: &str,
    bootstrap_peers: Vec<String>,
    announce_interval_seconds: u64,
    local_epoch: u64,
    hybrid_policy: &str,
    soft_freshness_window_seconds: u64,
    agent_mode: &str,
    canonical_bootstrap_peers: Option<Vec<Bound<'_, PyAny>>>,
    // v0.19.3 (CIRISEdge#49) — cross-wheel HTTPS init surface. All
    // six are additive optional kwargs; absence preserves the
    // v0.19.0 Reticulum-only behaviour exactly. Validation happens
    // in [`crate::transport::http::HttpsInitParams::parse`]; the
    // typed `HttpsInitError` variants translate to `PyValueError`
    // at the boundary below.
    https_listen_addr: Option<&str>,
    https_tls_cert_path: Option<&str>,
    https_tls_key_path: Option<&str>,
    https_mtls_required: bool,
    https_bearer_secret: Option<&[u8]>,
    https_dev_self_signed: bool,
    // v0.19.3 — HTTPS-only deployments. When `True`, the Reticulum
    // transport is NOT constructed; only HTTPS routes inbound +
    // outbound. Defaults to `False` so existing Reticulum-only +
    // Reticulum+HTTPS coexistence callers keep their behaviour.
    disable_reticulum: bool,
    // v0.20.0 RC1 (CIRISEdge#51) — optional operator overrides for the
    // CEWP L0/L1 tier defaults. `None` → use the `AgentMode`-derived
    // default (Client = 0, Proxy = 256 GB, Server = 1 TB for
    // `disk_budget_bytes`; Client = 0, Proxy = 0, Server = 1 for
    // `trust_recursion_depth`). `Some(_)` pins the per-deployment
    // value AFTER `AgentMode::apply_defaults` runs, so a curated
    // server (e.g.) can pin depth = 0 even though L1 default is 1.
    // `trust_recursion_depth` is clamped to `u8`'s range; persist's
    // `TrustScoring::trust_score(_, recursion_depth: u8)` consumes it
    // verbatim.
    disk_budget_bytes: Option<u64>,
    trust_recursion_depth: Option<u8>,
    // v2.3.0 (CIRISEdge#100) — Reticulum shared-instance mode. When
    // `local_instance_name` is `Some(name)`, the runtime joins (or
    // creates) the named AF_UNIX abstract socket so multiple
    // uvicorn workers can share one Reticulum link layer instead of
    // racing to bind it. Role disambiguation:
    //   - `"auto"`  → run leader election via persist's
    //     SharedInstanceDirectory (v5.6.0). Winner becomes server;
    //     losers attach as clients. A heartbeat task keeps the
    //     lease live; demotion is logged.
    //   - `"server"` → unconditionally bind as server (one-worker
    //     deploys / explicit topology).
    //   - `"client"` → unconditionally attach as client (the server
    //     is run out-of-band).
    // When `local_instance_name` is `None`, neither parameter has
    // any effect — v2.2.x behavior is preserved exactly.
    local_instance_name: Option<&str>,
    local_instance_role: &str,
    // v3.1.0 (CIRISEdge#108 / CIRISPersist#183, CEG §5.6.8.8.1) —
    // self-at-login transport_destination registration. When
    // `Some(occurrence_key_id)`, after the Reticulum transport
    // successfully binds, edge calls
    // `FederationDirectory::put_transport_destination` with the
    // resolved `(occurrence_key_id, "reticulum", local_dest_hash_hex)`
    // tuple — making this node's RNS destination hash discoverable
    // for peer reachability lookups. Idempotent (V078 composite PK on
    // `(occurrence_key_id, transport_kind, destination)`); re-asserts
    // on every `init_edge_runtime` call refresh `asserted_at`.
    //
    // The caller is expected to have run `Engine::self_at_login`
    // first to mint the agent occurrence + obtain its `key_id` —
    // edge does not derive the occurrence_key_id itself (the
    // identity/occurrence cardinality is a host-tier concern).
    //
    // `None` (the default) preserves the v3.0.x init behaviour
    // exactly; no transport_destination row is written.
    agent_occurrence_key_id: Option<&str>,
    // v3.1.0 (CIRISEdge#99) — when `Some(dir)`, edge constructs a
    // `ciris_keyring::BlobTransportKeystore::platform(signer_key_id,
    // dir)` and injects it into `ReticulumAuth::transport_identity_keystore`.
    // The keystore tier picks the best available backend (TPM /
    // Secure Enclave / StrongBox / encrypted software fallback) for
    // the host platform.
    //
    // First-call semantics depend on the on-disk state at
    // `identity_path`:
    //   - File exists → bytes are ADOPTED into the keystore and the
    //     file is renamed to `<identity_path>.migrated-<unix_ts>`.
    //     The destination hash is preserved (byte-identical
    //     adoption); peer routing tables + signed announces stay
    //     valid. Operator manually removes the recovery copy.
    //   - File absent → fresh bytes generated atomically in the
    //     keystore (hardware RNG where the tier offers it).
    //   - Keystore already populated for `signer_key_id` → those
    //     bytes are used directly; the file is not touched.
    //
    // `None` (the default) preserves v3.0.x chmod-600 file-only
    // behavior exactly.
    transport_identity_keyring_dir: Option<&str>,
    // CIRISEdge#168 (v5.0) — Reticulum Transport-node mode. When
    // `True`, this node forwards inbound packets destined for
    // non-local destinations across its warm interfaces — the
    // load-bearing half of §24 NAT-traversal. A public fabric node
    // (CIRISServer binding `0.0.0.0:4242`) MUST set this to `True`
    // for NAT'd / mobile edges to route through it. Defaults to
    // `False` (leaf-node mode; a mobile edge does not relay for
    // strangers). Maps to `ReticulumTransportConfig::enable_transport`
    // and through to leviculum's `enable_transport` builder knob.
    enable_transport: bool,
) -> PyResult<PyEdge> {
    // v0.19.3 (CIRISEdge#49) — validate the HTTPS init params BEFORE
    // any I/O. The mutual-exclusivity check (dev_self_signed vs cert
    // paths) and the cert+key-pair check both surface as typed
    // ValueError immediately, so the operator gets a clean diagnostic
    // before touching persist or the Reticulum identity files.
    //
    // When `transport-http` is NOT compiled in, ANY https_* param
    // being set is a hard error — the build doesn't carry the
    // HttpsTransport surface at all.
    #[cfg(not(feature = "transport-http"))]
    if https_listen_addr.is_some()
        || https_tls_cert_path.is_some()
        || https_tls_key_path.is_some()
        || https_mtls_required
        || https_bearer_secret.is_some()
        || https_dev_self_signed
        || disable_reticulum
    {
        return Err(PyValueError::new_err(
            "https_* init params (and disable_reticulum) require the transport-http \
             feature; this wheel was built without it",
        ));
    }

    #[cfg(feature = "transport-http")]
    let https_init_params: Option<crate::transport::http::HttpsInitParams> = {
        crate::transport::http::HttpsInitParams::parse(
            https_listen_addr,
            https_tls_cert_path,
            https_tls_key_path,
            https_mtls_required,
            https_bearer_secret,
            https_dev_self_signed,
        )
        .map_err(|e| PyValueError::new_err(e.to_string()))?
    };

    // v0.19.3 — `disable_reticulum=True` is only valid when an HTTPS
    // listener was also requested. An edge with no transports at all
    // can't dispatch anything; surface as a typed ValueError instead
    // of silently building a dead runtime.
    #[cfg(feature = "transport-http")]
    if disable_reticulum && https_init_params.is_none() {
        return Err(PyValueError::new_err(
            "disable_reticulum=True requires https_listen_addr to be set \
             (an edge with no transports cannot send or receive)",
        ));
    }

    // v2.3.0 (CIRISEdge#100) — validate the shared-instance params.
    // We surface typed errors here before any I/O so misconfiguration
    // is operator-visible immediately. `local_instance_role` is parsed
    // up-front; the actual leader-election call runs later (after the
    // federation_directory_capsule is extracted).
    let parsed_local_instance_role = match local_instance_role {
        "auto" => LocalInstanceRole::Auto,
        "server" => LocalInstanceRole::Server,
        "client" => LocalInstanceRole::Client,
        other => {
            return Err(PyValueError::new_err(format!(
                "local_instance_role must be one of 'auto'/'server'/'client', \
                 got {other:?}",
            )));
        }
    };
    if local_instance_name.is_some() && disable_reticulum {
        return Err(PyValueError::new_err(
            "local_instance_name is set but disable_reticulum=True — \
             shared-instance mode is a Reticulum-transport configuration \
             and has no effect without Reticulum",
        ));
    }
    #[cfg(not(feature = "transport-reticulum-local"))]
    if local_instance_name.is_some() {
        return Err(PyValueError::new_err(
            "local_instance_name requires the transport-reticulum-local \
             feature; this wheel was built without it",
        ));
    }

    // v0.18.0 (CIRISEdge#45) — decode the wire-string agent_mode token
    // BEFORE we do any other I/O, so a typed misconfiguration surfaces
    // a clean `ValueError` from the operator's POV instead of getting
    // tangled with persist / Reticulum errors downstream.
    let parsed_agent_mode = crate::AgentMode::from_wire(agent_mode).ok_or_else(|| {
        PyValueError::new_err(format!(
            "agent_mode must be one of 'client'/'proxy'/'server', got {agent_mode:?}",
        ))
    })?;

    // v0.18.0 (CIRISEdge#46) — decode the canonical_bootstrap_peers
    // list into Rust `CanonicalBootstrapPeer` rows. Each item must be
    // a dict-like object exposing `key_id` / `alias` /
    // `pubkey_ed25519_base64` and optional `transport_hint` /
    // `description` attributes (PyO3 supports both `obj["key_id"]` and
    // `obj.key_id` access; we use `getattr` first then fall back to
    // mapping access for dict literals).
    let canonical_peers: Vec<crate::CanonicalBootstrapPeer> =
        match canonical_bootstrap_peers.as_ref() {
            None => Vec::new(),
            Some(items) => {
                let mut out = Vec::with_capacity(items.len());
                for item in items {
                    out.push(extract_canonical_bootstrap_peer(item)?);
                }
                out
            }
        };
    let hybrid_policy = parse_hybrid_policy(hybrid_policy, soft_freshness_window_seconds)?;

    // ── Step 1: extract the substrate handles via PyCapsule from the
    // shared engine. Cross-module PyClass identity isn't involved —
    // capsules are opaque pointers with producer-set name tags, which
    // is the load-bearing primitive for cohabitation across separately-
    // built wheels (CIRISPersist#109 / CIRISEdge#22). The capsule name
    // tag + crate-pin floor (>=2.8.0) is what enforces the wrapped-type
    // invariant; see [`extract_capsule`] for the full safety argument.
    //
    // SAFETY (all four call sites — three substrate handles here +
    // `runtime_handle_capsule` in Step 5): `T` arguments below match
    // exactly the wrapped types persist's `*_capsule` `#[pymethod]`s
    // produce (`src/ffi/pyo3.rs` lines ~13955-14075 in the persist
    // tree):
    //   - federation_directory_capsule wraps Arc<dyn FederationDirectory>  (v2.7.0)
    //   - outbound_queue_capsule       wraps BackendDispatch               (v2.7.0)
    //   - keyring_signer_capsule       wraps KeyringSignerHandle           (v2.7.0)
    //   - runtime_handle_capsule       wraps tokio::runtime::Handle        (v2.8.0)
    // The crate-level `#[deny(unsafe_code)]` is the default lint
    // (relaxed from `forbid` in v0.9.2 specifically for these calls);
    // each call site below explicitly opts in via `#[allow(unsafe_code)]`.
    //
    // Ordering rationale: `runtime_handle_capsule` (v2.8.0) is
    // extracted FIRST so the persist-version-floor diagnostic surfaces
    // before the v2.7.0 substrate-handle extractions. A pre-v2.8.0
    // persist would still satisfy the three v2.7.0 capsule methods but
    // miss the v0.10.1 fix entirely — without the early check, the
    // operator would get a cryptic `"persist tokio runtime unavailable"`
    // at the old `current_runtime_handle()` site (v0.10.0 production
    // failure shape) instead of an actionable "upgrade ciris-persist"
    // message. The pre-check is `hasattr`-based so we don't waste a
    // method call on the missing path.
    if !engine.hasattr("runtime_handle_capsule").unwrap_or(false) {
        return Err(PyRuntimeError::new_err(
            "persist v2.8.0+ required for cross-cdylib runtime sharing — \
             your persist version doesn't expose runtime_handle_capsule. \
             Either upgrade ciris-persist (Cargo `tag = \"v2.8.0\"`, \
             pyproject `ciris-persist>=2.8.0,<3`) or run edge in \
             same-extension-module mode (CIRISEdge#22 / CIRISPersist#111).",
        ));
    }
    #[allow(unsafe_code)]
    let runtime: tokio::runtime::Handle = unsafe {
        extract_capsule::<tokio::runtime::Handle, _, _>(
            &engine,
            "runtime_handle_capsule",
            tokio::runtime::Handle::clone,
        )?
    };
    // Make the persist runtime current on this thread for the rest of
    // the init body. `enter()` returns a guard that restores the
    // previous runtime context (or absence thereof) on Drop. The
    // explicit `block_on` in Step 5 below DOES NOT require `enter()`
    // to schedule, but entering ensures any future refactor introducing
    // an intermediate `.await` (e.g. registering a transport handler
    // task) immediately has a current runtime and does not regress to
    // a "no reactor running" panic.
    let _runtime_guard = runtime.enter();

    // v1.1.8 (CIRISEdge#58 / CIRISEdge#59 / CIRISPersist#157) — the
    // ABI-stable executor capsule. Pre-v3.13.0 persist exposes only
    // `runtime_handle_capsule` (deprecated; cross-tokio-aliasing trap
    // documented in CIRISPersist#156); v3.13.0+ adds `executor_capsule`
    // whose vtable function pointers live inside `ciris_persist.abi3.so`
    // — invoking `vtable.spawn` from edge dispatches into persist's
    // .so, spawning onto persist's tokio without any cross-crate
    // dispatch. The hot-path send/recv pymethods consume this instead
    // of the raw `tokio::Handle`. See `run_async`'s docs.
    if !engine.hasattr("executor_capsule").unwrap_or(false) {
        return Err(PyRuntimeError::new_err(
            "persist v3.13.0+ required for ABI-stable async cohabitation — \
             your persist version doesn't expose executor_capsule. \
             Upgrade ciris-persist (Cargo `tag = \"v3.13.0\"`, pyproject \
             `ciris-persist>=3.13.0,<4`). See CIRISEdge#58 / CIRISPersist#157.",
        ));
    }
    // The executor capsule stores a `*mut AsyncExecutor as usize`
    // (persist's `build_capsule_with_destructor` passes the
    // `Box::into_raw`'d pointer cast to usize). Extract as `usize`,
    // then cast back to `*const AsyncExecutor` and bitwise-copy the
    // struct fields. The PyCapsule destructor (set by persist) calls
    // `vtable.drop` at Python GC time; edge only owns a reference
    // copy of the executor, never the destructor responsibility.
    #[allow(unsafe_code)]
    let executor: ciris_persist::ffi::executor_capsule::AsyncExecutor = unsafe {
        extract_capsule::<usize, _, _>(&engine, "executor_capsule", |raw_usize| {
            let ptr = *raw_usize as *const ciris_persist::ffi::executor_capsule::AsyncExecutor;
            // SAFETY: `raw_usize` is the `Box::into_raw`'d pointer
            // produced by persist's `build_capsule_with_destructor`.
            // The Box's allocation is alive for the lifetime of the
            // PyCapsule (its destructor runs `Box::from_raw` at GC
            // time), which is rooted in the Python `engine` object
            // outliving this extraction.
            let e = &*ptr;
            ciris_persist::ffi::executor_capsule::AsyncExecutor {
                data: e.data,
                vtable: e.vtable,
            }
        })?
    };
    // ABI version check — refuse mismatched capsule versions cleanly
    // rather than risk UB on a vtable-layout drift.
    if executor.vtable.abi_version
        != ciris_persist::ffi::executor_capsule::ASYNC_EXECUTOR_ABI_VERSION
    {
        return Err(PyRuntimeError::new_err(format!(
            "persist executor_capsule ABI version mismatch — capsule v{}, \
             edge expects v{}; upgrade ciris-persist or pin edge to a \
             compatible floor",
            executor.vtable.abi_version,
            ciris_persist::ffi::executor_capsule::ASYNC_EXECUTOR_ABI_VERSION,
        )));
    }
    let executor = Arc::new(executor);

    #[allow(unsafe_code)]
    let directory_arc: Arc<dyn ciris_persist::federation::FederationDirectory> = unsafe {
        extract_capsule::<Arc<dyn ciris_persist::federation::FederationDirectory>, _, _>(
            &engine,
            "federation_directory_capsule",
            Arc::clone,
        )?
    };
    #[allow(unsafe_code)]
    let queue_dispatch: BackendDispatch = unsafe {
        extract_capsule::<BackendDispatch, _, _>(
            &engine,
            "outbound_queue_capsule",
            BackendDispatch::clone,
        )?
    };
    #[allow(unsafe_code)]
    let signer_handle: ciris_persist::signing::KeyringSignerHandle = unsafe {
        extract_capsule::<ciris_persist::signing::KeyringSignerHandle, _, _>(
            &engine,
            "keyring_signer_capsule",
            // KeyringSignerHandle doesn't `derive(Clone)`, so build the
            // owned copy field-by-field. All three fields are cheap to
            // clone (two Arc refcount bumps + a String clone).
            |h| ciris_persist::signing::KeyringSignerHandle {
                signer: h.signer.clone(),
                pqc_signer: h.pqc_signer.clone(),
                key_id: h.key_id.clone(),
            },
        )?
    };

    // ── Step 2: directory + BackendDispatch → edge adapter Arcs.
    //
    // edge's `VerifyDirectory` / `RootingDirectory` traits have blanket
    // impls over `F: FederationDirectory + Send + Sync + 'static`
    // (`crate::verify`), but those blanket impls bind `F: Sized` and
    // therefore do NOT apply to `dyn FederationDirectory`. We need a
    // concrete sized type. `BackendDispatch`'s arms each carry the
    // concrete `Arc<PostgresBackend>` / `Arc<SqliteBackend>` — both
    // implement `FederationDirectory` AND `OutboundQueue`, so we can
    // lift them to all three trait objects edge holds.
    //
    // `directory_arc` from the federation_directory_capsule is the
    // already-coerced `Arc<dyn FederationDirectory>` from persist's
    // perspective; we cross-check it points at the same backend the
    // BackendDispatch arm carries (debug assertion only; in production
    // persist's `*_capsule` methods are carved from the engine's one
    // `BackendDispatch`, so the invariant holds by construction).
    debug_assert!(
        Arc::strong_count(&directory_arc) >= 1,
        "federation_directory_capsule produced a live Arc",
    );
    // v0.15.1 (CIRISEdge#26 mutation surface) — retain the
    // `Arc<dyn FederationDirectory>` for the UniFFI peer-mutation
    // entry points (`peer_add` / `peer_remove` /
    // `peer_set_{alias,trust,notes,policy}`). These need the concrete
    // FederationDirectory trait object — distinct from `verify_dir`
    // (which is an `Arc<dyn VerifyDirectory>` adapter). Both
    // ultimately reference the same backend (persist's
    // `federation_directory_capsule` is carved from the engine's one
    // `BackendDispatch`), but the trait-object identities differ
    // because edge holds two separate `dyn`-trait views.
    let federation_directory_for_edge: Arc<dyn ciris_persist::federation::FederationDirectory> =
        directory_arc;

    let (verify_dir, rooting_dir): (Arc<dyn VerifyDirectory>, Arc<dyn RootingDirectory>) =
        match &queue_dispatch {
            BackendDispatch::Postgres(b) => (b.clone(), b.clone()),
            BackendDispatch::Sqlite(b) => (b.clone(), b.clone()),
        };
    // v0.16.1 (CIRISEdge#33 durable flip / CIRISPersist#120) — derive
    // `Arc<dyn BlackholeRules>` from the same `BackendDispatch` arm.
    // Sibling trait to `FederationDirectory`; both backends impl it.
    // No new capsule needed — the existing `outbound_queue_capsule`
    // surface gives us everything (the V052 `cirislens.blackhole_rules`
    // table lives in the same DB as the outbound queue).
    let blackhole_rules: Arc<dyn ciris_persist::federation::BlackholeRules> = match &queue_dispatch
    {
        BackendDispatch::Postgres(b) => b.clone(),
        BackendDispatch::Sqlite(b) => b.clone(),
    };
    // v0.17.0 (CIRISEdge#39 emit_verdict flip / CIRISPersist#118) —
    // derive `Arc<dyn EdgeDetectionAdmission>` (the edge-side
    // object-safe wrapper over persist's `DerivedSchema`) from the
    // same `BackendDispatch` arm. Both `SqliteBackend` and
    // `PostgresBackend` impl `DerivedSchema`, and the blanket
    // [`EdgeDetectionAdmission for T: DerivedSchema`] impl in
    // `crate::detector` lifts them to the trait object the
    // `ProbePatternObserver` consumes for `put_edge_detection_event`.
    let derived_schema: Arc<dyn crate::detector::EdgeDetectionAdmission> = match &queue_dispatch {
        BackendDispatch::Postgres(b) => b.clone(),
        BackendDispatch::Sqlite(b) => b.clone(),
    };
    // v0.20.0 RC1 (CIRISEdge#51 / CIRISPersist#129) — close the
    // v0.19.6 cohabitation-deferral residual. Persist v3.5.1 shipped
    // the 7th cohabitation capsule (`trust_scoring_capsule()`), and
    // v3.6.3 (this Edge's pin) carries it forward. We attempt to
    // extract the `Arc<dyn TrustScoring>` from the engine's installed
    // `AdmissionGate`; the typed `TrustScoringCapsuleError` outcomes
    // map to:
    //
    //  - `MethodAbsent` → severely-stale persist (< v3.5.1); the
    //    v0.20.0 Cargo floor (v3.6.3) makes this branch unreachable
    //    in production but the warning fires defensively so a
    //    forced-pin mismatch surfaces loud.
    //  - `Unavailable` → typed `trust_scoring_unavailable` ValueError
    //    from persist (no `AdmissionGate` installed via
    //    `Engine::set_admission_gate`). This IS the bootstrap default
    //    posture — fall back to `None` so the dispatch short-circuit
    //    stays structurally disabled (matches `trust_threshold = 0.0`
    //    discipline). Log an info breadcrumb so the operator can
    //    correlate.
    //  - `Other(_)` → unexpected exception or capsule cast failure;
    //    loud-fail per the v0.13.0 contract.
    //
    // On success the wired scorer reaches `EdgeBuilder::trust_scoring`
    // at Step 6 below; in tandem with `EdgeConfig::trust_threshold`
    // (operator-configured) and the new `trust_recursion_depth` field
    // it gates the inbound short-circuit at `dispatch_inbound`.
    let trust_scoring: Option<Arc<dyn ciris_persist::federation::TrustScoring>> =
        match extract_trust_scoring(&engine) {
            Ok(scorer) => Some(scorer),
            Err(TrustScoringCapsuleError::Unavailable) => {
                tracing::info!(
                    "ciris_persist.Engine raised trust_scoring_unavailable from \
                     trust_scoring_capsule(); no AdmissionGate installed — \
                     dispatch_inbound trust short-circuit stays structurally \
                     disabled (bootstrap-permissive default, same as \
                     EdgeConfig::trust_threshold = 0.0). Install a gate via \
                     persist's Engine::set_admission_gate(...) to opt in."
                );
                None
            }
            Err(TrustScoringCapsuleError::MethodAbsent) => {
                tracing::warn!(
                    "ciris_persist.Engine does not expose trust_scoring_capsule() \
                     (persist < 3.5.1); falling back to None posture for \
                     dispatch_inbound trust short-circuit. v0.20.0 RC1's Cargo \
                     floor is `tag = \"v3.6.3\"`; this branch indicates a \
                     forced-pin mismatch on the consumer side."
                );
                None
            }
            Err(TrustScoringCapsuleError::Other(e)) => {
                return Err(e);
            }
        };
    let queue: Arc<dyn OutboundHandle> = match queue_dispatch {
        BackendDispatch::Postgres(b) => b,
        BackendDispatch::Sqlite(b) => b,
    };

    // ── Step 3: keyring signer parts → edge's hot-path LocalSigner.
    //
    // persist's `KeyringSignerHandle` already contains the cloned
    // `Arc<dyn HardwareSigner>` + optional `Arc<dyn PqcSigner>` the
    // host loaded; wrap them in edge's local-signer struct without
    // re-bootstrapping the keyring (AV-17 / COHABITATION rule 1). This
    // `signer` is the **scrub-envelope** signing surface threaded into
    // `Edge::builder().signer(...)` — `Edge::send_durable` and the
    // inbound dispatch ACK path use it for hybrid hardware-rooted
    // signatures.
    let signer = Arc::new(LocalSigner::new(
        signer_handle.key_id.clone(),
        signer_handle.signer.clone(),
        signer_handle.pqc_signer.clone(),
    ));

    // ── Step 3.5: local_signer_capsule → Reticulum transport-identity
    // signer (CIRISEdge#43 / CIRISPersist#119, v0.16.1 cherry-pick from
    // v0.13.1).
    //
    // The Reticulum transport's federation Ed25519 identity
    // attestation reads a 32-byte raw pubkey via `signer.classical
    // .public_key()` — see `src/transport/reticulum.rs`
    // `build_local_attestation`. The hardware-rooted keyring signer
    // (Step 3 above) emits a **65-byte hybrid pubkey** under
    // `keyring_storage_kind = hardware_hsm_only` (TPM P-256), which
    // `ReticulumTransport::new` correctly rejects with
    // `"federation Ed25519 pubkey must be 32 bytes, got 65"`. That was
    // the v0.13.0 production blocker for CIRISAgent 2.9.4's hardware-
    // keyring cohabitation init handshake.
    //
    // Persist v3.1.1 (CIRISPersist#119) exposes the agent's
    // transport-identity `Arc<LocalSigner>` (software Ed25519 loaded
    // from `local_key_path`) via `local_signer_capsule()`. We extract
    // it, wrap it in `LocalSignerHardwareAdapter` (an
    // `Arc<dyn HardwareSigner>` whose `public_key()` returns the
    // 32-byte raw Ed25519 — exactly the surface Reticulum needs), and
    // build a second edge `LocalSigner` over it. The hot-path
    // `signer` (Step 3) stays hardware-rooted; only the
    // `ReticulumAuth.signer` (Step 4 below) takes this transport-
    // identity signer.
    //
    // Fallback: when the engine raises
    // `ValueError("local_signer_unavailable")` (older cohab-init
    // paths — agent didn't construct the engine with
    // `from_shared_with_local` / `local_key_id` + `local_key_path`),
    // we log a warning and fall through to the v0.13.0 behavior:
    // ReticulumAuth.signer carries the keyring signer. Under
    // hardware_hsm_only that will still fail at transport build, but
    // with the same diagnostic v0.13.0 produced — the operator's
    // upgrade path is now clear. Software-only keyring deployments
    // (where the keyring signer also yields a 32-byte Ed25519
    // pubkey) continue to work unchanged.
    //
    // Method-absent (pre-v3.1.1 persist): same fallback path, named
    // separately for diagnostic clarity. Note the v0.16.1 floor is
    // v3.2.0 (BlackholeRules); the capsule was added at v3.1.1 so this
    // branch only fires against severely-stale persist installs the
    // v3.2.0 floor is already pulling forward.
    let reticulum_identity_signer: Arc<LocalSigner> = match extract_local_signer(&engine) {
        Ok(local_signer_arc) => {
            // Adapt persist's `Arc<LocalSigner>` to
            // `Arc<dyn HardwareSigner>` via persist's adapter — the
            // adapter's `public_key()` returns the 32-byte raw Ed25519
            // (`SigningKey::verifying_key().to_bytes()`). We thread it
            // into edge's `LocalSigner` `classical` slot. PQC stays
            // `None` here — the Reticulum attestation only signs the
            // Ed25519 transport-identity payload; PQC envelope signing
            // is the hot-path keyring signer's responsibility.
            let adapter: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(
                ciris_persist::signing::LocalSignerHardwareAdapter::new(local_signer_arc),
            );
            Arc::new(LocalSigner::new(
                signer_handle.key_id.clone(),
                adapter,
                None,
            ))
        }
        Err(LocalSignerCapsuleError::Unavailable) => {
            tracing::warn!(
                "ciris_persist.Engine raised local_signer_unavailable from \
                 local_signer_capsule(); falling back to keyring_signer for \
                 Reticulum transport identity. Under keyring_storage_kind = \
                 hardware_hsm_only this fallback will fail at \
                 ReticulumTransport::new with 'federation Ed25519 pubkey \
                 must be 32 bytes, got 65'. Upgrade the agent's cohab-init \
                 path to construct ciris_persist.Engine with local_key_id + \
                 local_key_path (Engine.from_shared_with_local, persist \
                 v2.12.0+ / #112)."
            );
            signer.clone()
        }
        Err(LocalSignerCapsuleError::MethodAbsent) => {
            tracing::warn!(
                "ciris_persist.Engine does not expose local_signer_capsule() \
                 (persist < 3.1.1); falling back to keyring_signer for \
                 Reticulum transport identity. Under keyring_storage_kind = \
                 hardware_hsm_only this fallback will fail at \
                 ReticulumTransport::new with 'federation Ed25519 pubkey \
                 must be 32 bytes, got 65'. v0.16.1's Cargo floor is \
                 `tag = \"v3.2.0\"`; this branch indicates a forced-pin \
                 mismatch on the consumer side."
            );
            signer.clone()
        }
        Err(LocalSignerCapsuleError::Other(e)) => {
            // Non-typed failure (capsule cast failure, etc.) — surface
            // as a hard error rather than silently fall back. This
            // preserves the v0.13.0 "loud failure on unexpected
            // capsule shape" contract.
            return Err(e);
        }
    };

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
    // v0.18.0 (CIRISEdge#45) — Reticulum still binds its TCP listener
    // by default; an explicit Client posture from the operator
    // (agent_mode="client") signals "egress only". The
    // `transport_config.listen_addr` field is the **socket** the TCP
    // server listens on; under Client mode we keep the default value
    // wired (the ReticulumNode itself always has an identity hash that
    // can receive responses to outbound dials) but suppress the
    // listener-bind on the v0.18.0 plumbing layer via
    // `EdgeConfig.listener_bound = false`. Transport-posture
    // translation (Roaming / Full / Gateway / AP) is deferred — see
    // `AgentMode` docblock.
    transport_config.listen_addr = listen_addr;
    transport_config.bootstrap_peers = bootstrap_peers;
    transport_config.announce_interval = Duration::from_secs(announce_interval_seconds);
    transport_config.local_epoch = local_epoch;
    // CIRISEdge#168 (v5.0) — Transport-node mode (§24 NAT-traversal).
    transport_config.enable_transport = enable_transport;

    // v2.3.0 (CIRISEdge#100) — shared-instance leader election +
    // LocalInterfaceConfig push. Only runs when the operator supplied
    // `local_instance_name`. For role="auto" we call persist's
    // `try_acquire_shared_instance` (v5.6.0 SharedInstanceDirectory);
    // the winner becomes the Local server, losers attach as clients.
    // The returned lease (if any) drives the heartbeat task spawned
    // after the transport build below.
    #[cfg(feature = "transport-reticulum-local")]
    let acquired_lease: Option<ciris_persist::federation::SharedInstanceLease> =
        if let Some(instance_name) = local_instance_name {
            let is_server: bool;
            let lease_to_track: Option<ciris_persist::federation::SharedInstanceLease>;
            match parsed_local_instance_role {
                LocalInstanceRole::Server => {
                    is_server = true;
                    lease_to_track = None;
                }
                LocalInstanceRole::Client => {
                    is_server = false;
                    lease_to_track = None;
                }
                LocalInstanceRole::Auto => {
                    let directory_for_election = Arc::clone(&federation_directory_for_edge);
                    let owner_pid: i32 = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
                    // Cross-platform best-effort hostname for the
                    // SharedInstanceLease diagnostic field. Linux/macOS
                    // expose HOSTNAME, Windows exposes COMPUTERNAME.
                    // Operator-only field (used in
                    // `SELECT * FROM shared_instance_leases` debugging);
                    // a fallback "unknown" is acceptable.
                    let owner_hostname: String = std::env::var("HOSTNAME")
                        .or_else(|_| std::env::var("COMPUTERNAME"))
                        .unwrap_or_else(|_| "unknown".to_string());
                    let name_for_election = instance_name.to_string();
                    let lease_result = run_async(&executor, async move {
                        directory_for_election
                            .try_acquire_shared_instance(
                                &name_for_election,
                                owner_pid,
                                &owner_hostname,
                                None,
                            )
                            .await
                    })
                    .map_err(|e| {
                        PyRuntimeError::new_err(format!(
                            "try_acquire_shared_instance({instance_name:?}): {e}"
                        ))
                    })?;
                    is_server = lease_result.is_some();
                    lease_to_track = lease_result;
                    tracing::info!(
                        instance_name = %instance_name,
                        elected_role = if is_server { "server" } else { "client" },
                        "Reticulum shared-instance election complete"
                    );
                }
            }
            transport_config = transport_config.add_interface(
                crate::transport::reticulum::ReticulumInterfaceConfig::Local(
                    crate::transport::reticulum::LocalInterfaceConfig {
                        is_server,
                        instance_name: instance_name.to_string(),
                    },
                ),
            );
            lease_to_track
        } else {
            None
        };

    // v0.18.0 (CIRISEdge#46) — reseed canonical bootstrap peers into
    // persist BEFORE the Edge is constructed. The reseed is
    // idempotent per peer; a Conflict (differing pubkey for an
    // existing key_id) propagates as a typed `PyRuntimeError` so
    // operator misconfiguration surfaces loudly at init time. Trust
    // state and `removed_at` are preserved (the v0.15.1 persist
    // contract). See `crate::reseed_canonical_bootstrap_peers`
    // for the full per-peer flow.
    if !canonical_peers.is_empty() {
        let directory_for_reseed = Arc::clone(&federation_directory_for_edge);
        let canonical_peers_for_reseed = canonical_peers.clone();
        py.detach(|| {
            runtime
                .block_on(async move {
                    crate::reseed_canonical_bootstrap_peers(
                        &directory_for_reseed,
                        &canonical_peers_for_reseed,
                    )
                    .await
                })
                .map_err(|e| {
                    PyRuntimeError::new_err(format!(
                        "reseed_canonical_bootstrap_peers: {e} (kind={kind})",
                        kind = e.kind()
                    ))
                })
        })?;
    }

    // CIRISEdge#34 (v0.14.0 wiring) — pre-construct the EventBus +
    // ReachabilityTracker so the Reticulum transport (built before
    // Edge) can emit announce / interface / **link** events into the
    // same bus Edge later registers via `EdgeBuilder::events(...)`.
    // The link half of #34 needs this so the transport's
    // Link{Established,Identified,Closed,Stale} hooks find a bus to
    // emit on; without it the channels stay quiet (the v0.13.0
    // posture).
    let event_bus = Arc::new(crate::events::EventBus::default());
    let reachability_tracker = Arc::new(crate::reachability::ReachabilityTracker::new(
        crate::edge::EdgeConfig::default().reachability_window_seconds,
    ));

    // v3.1.0 (CIRISEdge#99) — when the operator opts in, construct a
    // platform `BlobTransportKeystore` rooted at the operator-supplied
    // directory. The keystore picks the best available hardware tier
    // (TPM / SE / StrongBox) for the host; falls back to encrypted
    // software when no hardware tier is reachable. Errors at
    // construction time (e.g. directory not writable) surface as a
    // typed `PyRuntimeError` so the operator gets a clean diagnostic
    // before any transport bind.
    let transport_identity_keystore: Option<Arc<dyn ciris_keyring::TransportIdentityKeystore>> =
        if let Some(dir) = transport_identity_keyring_dir {
            use ciris_keyring::BlobTransportKeystore;
            let ks = BlobTransportKeystore::platform(signer.key_id.clone(), dir).map_err(|e| {
                PyRuntimeError::new_err(format!(
                    "transport_identity_keyring_dir={dir:?}: \
                 BlobTransportKeystore::platform({}): {e}",
                    signer.key_id
                ))
            })?;
            Some(Arc::new(ks) as Arc<dyn ciris_keyring::TransportIdentityKeystore>)
        } else {
            None
        };

    let auth = ReticulumAuth {
        // v0.16.1 cherry-pick (CIRISEdge#43): the Reticulum-identity
        // signer is split out from the hot-path keyring signer above.
        // When local_signer_capsule is available
        // (`from_shared_with_local`-constructed engine, persist
        // v3.1.1+), this carries the 32-byte raw Ed25519 transport
        // identity adapted via `LocalSignerHardwareAdapter`. When
        // unavailable, it falls through to the same `signer` the
        // envelope path uses (v0.13.0 behavior). See Step 3.5 above
        // for the fallback rationale.
        signer: Some(reticulum_identity_signer.clone()),
        rooting: Some(rooting_dir.clone()),
        resolver: None,
        hybrid_policy,
        event_bus: Some(Arc::clone(&event_bus)),
        reachability: Some(Arc::clone(&reachability_tracker)),
        // v0.16.1 (CIRISEdge#33 durable flip / CIRISPersist#120) —
        // route the routing-table FFI's deny-list through persist's
        // V052 `cirislens.blackhole_rules` table. Rules survive
        // process restarts; the in-memory HashMap is gone.
        blackhole_rules: Some(Arc::clone(&blackhole_rules)),
        // v3.1.0 (CIRISEdge#99) — keyring-tier RNS transport identity.
        transport_identity_keystore,
    };

    // ── Step 5: build the transport + Edge under the host runtime.
    //
    // The tokio runtime handle was extracted in Step 1 via the v2.8.0
    // `runtime_handle_capsule` (CIRISPersist#111) — the **statics**-
    // layer counterpart to #109's type-identity fix. `_runtime_guard`
    // (from `runtime.enter()`) is live for the rest of this body.
    //
    // Construction is async (Reticulum node start + identity load).
    // `Python::detach` (pyo3 0.28 rename of the older `allow_threads`)
    // releases the GIL while the persist runtime (held by the shared
    // `PyEngine`) drives the future to completion — the host's tokio
    // runtime owns the worker threads edge's transport schedules on.
    // v0.14.0 (CIRISEdge#32) — keep the typed `Arc<ReticulumTransport>`
    // for the Links FFI surface; `EdgeBuilder::reticulum_transport`
    // also upcasts + pushes it into the generic transport vec.
    //
    // v0.19.3 (CIRISEdge#49) — `disable_reticulum=True` skips the
    // Reticulum build entirely. The HTTPS-only deployment path
    // (conformance harness #3 / #4) needs an edge that does NOT
    // bind a TCP listener for Reticulum; instead the only inbound
    // path is the HTTPS POST handler. When `disable_reticulum=False`
    // (the default), v0.19.0 behaviour is preserved exactly: we
    // build Reticulum + (optionally) HTTPS, and both are active
    // concurrently as `EdgeBuilder::transport` entries.
    #[cfg(feature = "transport-http")]
    let reticulum_disabled = disable_reticulum;
    #[cfg(not(feature = "transport-http"))]
    let reticulum_disabled = false;

    let reticulum_transport: Option<Arc<ReticulumTransport>> = if reticulum_disabled {
        // HTTPS-only deployment — skip Reticulum entirely. The
        // `auth` and `transport_config` builds above were
        // intentionally NOT wrapped in this conditional so the
        // operator gets the same identity-load + canonical-reseed
        // diagnostics regardless of whether Reticulum then binds.
        // Drop them here so unused-binding lints don't fire (the
        // `auth` carries an Arc<ReticulumIdentity>; dropping the
        // single owner releases it cleanly).
        let _ = (transport_config, auth);
        None
    } else {
        let t: Arc<ReticulumTransport> = py.detach(|| {
            runtime
                .block_on(async {
                    ReticulumTransport::new(transport_config, auth)
                        .await
                        .map(Arc::new)
                })
                .map_err(|e| PyRuntimeError::new_err(format!("ReticulumTransport::new: {e}")))
        })?;
        Some(t)
    };

    // v3.1.0 (CIRISEdge#108 / CIRISPersist#183, CEG §5.6.8.8.1) —
    // self-at-login transport_destination registration. When the
    // caller supplied `agent_occurrence_key_id` AND we successfully
    // built the Reticulum transport, register this node's RNS
    // destination hash so peers querying
    // `list_transport_destinations_for(occurrence_key_id)` can dial
    // us. Idempotent on the (occurrence_key_id, transport_kind,
    // destination) PK; re-asserts update `asserted_at` in place.
    //
    // Skip silently when:
    //   - `agent_occurrence_key_id` is None (caller opted out;
    //     v3.0.x init behaviour preserved)
    //   - `reticulum_transport` is None (disable_reticulum=True; no
    //     RNS destination to advertise)
    //   - `local_dest_hash()` returns None (transport built but
    //     destination not yet computed — should not occur in
    //     practice; defensive)
    //
    // A registration failure is LOGGED but not raised — reachability
    // is mutable + disposable per persist's contract; a missed
    // assertion just means peers fall back to other addresses or
    // re-resolve next time. Failing init for a reachability hint is
    // disproportionate.
    #[cfg(feature = "_reticulum-module")]
    if let (Some(occurrence_key_id), Some(transport)) =
        (agent_occurrence_key_id, reticulum_transport.as_ref())
    {
        // ReticulumTransport::local_dest_hash returns [u8; 16] (not
        // Option) — the destination is set at transport construction
        // (see ReticulumTransport::new), so it's always available
        // here. Edge::local_dest_hash returns Option only because
        // the Edge wrapper may not have a Reticulum transport at
        // all (HTTPS-only paths); we're inside the
        // `reticulum_transport.is_some()` arm so the inner method
        // applies.
        let dest_hash = transport.local_dest_hash();
        {
            let destination_hex = hex::encode(dest_hash);
            let directory_for_register = Arc::clone(&federation_directory_for_edge);
            let row = ciris_persist::federation::self_at_login::TransportDestination {
                occurrence_key_id: occurrence_key_id.to_string(),
                transport_kind: "reticulum".to_string(),
                destination: destination_hex.clone(),
                asserted_at: chrono::Utc::now(),
                last_seen_at: None,
            };
            let occurrence_for_log = occurrence_key_id.to_string();
            let register_result = run_async(&executor, async move {
                directory_for_register.put_transport_destination(&row).await
            });
            match register_result {
                Ok(()) => {
                    tracing::info!(
                        occurrence_key_id = %occurrence_for_log,
                        transport_kind = "reticulum",
                        destination = %destination_hex,
                        "transport_destination registered (self-at-login)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        occurrence_key_id = %occurrence_for_log,
                        transport_kind = "reticulum",
                        destination = %destination_hex,
                        error = %e,
                        "transport_destination registration failed; peers may need \
                         to retry reachability lookup"
                    );
                }
            }
        }
    }

    // v2.3.0 (CIRISEdge#100) — heartbeat task for the shared-instance
    // lease (auto-elected server only). Persist's stale-after window is
    // 30s by default; we beat at 10s (≈3 beats before takeover) so a
    // GC pause or brief tokio stall doesn't drop the lease. A returned
    // `None` from `heartbeat_shared_instance` means the row was stolen
    // out from under us (sibling thought we were dead); we log loudly
    // — the running Reticulum server stays bound on its AF_UNIX socket
    // and continues to serve siblings, but the lease row no longer
    // reflects reality. Operator action: kill this process so the
    // orchestrator re-fires init_edge_runtime and the new winner takes
    // a clean lease. (Auto-restart of the transport mid-process is out
    // of scope for v2.3.0 — Reticulum interfaces aren't swappable
    // live; the orchestrator owns process lifecycle.)
    //
    // v2.4.0 (CIRISEdge#103) — the heartbeat loop now `tokio::select!`s
    // on a oneshot::Receiver so `PyEdge::close` can short-circuit it
    // (rather than waiting up to 10s for the loop's next iteration).
    // The matching Sender + lease + directory clone are stashed on
    // PyEdge below so close() can also call
    // `release_shared_instance_lease` to free the lease row
    // immediately (rather than waiting for the 30s staleness window).
    #[cfg(feature = "transport-reticulum-local")]
    let shared_instance_cleanup: Option<SharedInstanceCleanup> =
        if let Some(initial_lease) = acquired_lease {
            let directory_for_heartbeat = Arc::clone(&federation_directory_for_edge);
            let directory_for_cleanup = Arc::clone(&federation_directory_for_edge);
            let executor_for_heartbeat = Arc::clone(&executor);
            let instance_name_outer = initial_lease.instance_name.clone();
            let instance_name_inner = initial_lease.instance_name.clone();
            let lease_for_cleanup = initial_lease.clone();
            let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
            let heartbeat_fut: BoxedFut = Box::pin(async move {
                let mut lease = initial_lease;
                let mut consecutive_backend_errors: u32 = 0;
                let mut shutdown_rx = shutdown_rx;
                loop {
                    tokio::select! {
                        biased;
                        // Shutdown branch (biased so it preempts the sleep).
                        // Either explicit close() signal or close() dropped the
                        // sender without sending — both terminate the loop.
                        _ = &mut shutdown_rx => {
                            tracing::info!(
                                instance_name = %instance_name_inner,
                                "shared-instance heartbeat: shutdown signal received; \
                                 exiting loop"
                            );
                            return;
                        }
                        () = tokio::time::sleep(std::time::Duration::from_secs(10)) => {}
                    }
                    match directory_for_heartbeat
                        .heartbeat_shared_instance(&lease)
                        .await
                    {
                        Ok(Some(renewed)) => {
                            lease = renewed;
                            consecutive_backend_errors = 0;
                        }
                        Ok(None) => {
                            tracing::error!(
                                instance_name = %instance_name_inner,
                                "Reticulum shared-instance lease was stolen \
                                 (sibling promoted; this process is demoted to \
                                 a stale server). Restart this worker to re-elect."
                            );
                            return;
                        }
                        Err(e) => {
                            consecutive_backend_errors += 1;
                            tracing::warn!(
                                instance_name = %instance_name_inner,
                                error = %e,
                                consecutive_errors = consecutive_backend_errors,
                                "shared-instance heartbeat backend error"
                            );
                            if consecutive_backend_errors >= 6 {
                                tracing::error!(
                                    instance_name = %instance_name_inner,
                                    "shared-instance heartbeat: 6 consecutive backend \
                                     errors — abandoning heartbeat task. Lease will \
                                     expire after the staleness window."
                                );
                                return;
                            }
                        }
                    }
                }
            });
            let outer_box: Box<BoxedFut> = Box::new(heartbeat_fut);
            let task_ptr: *mut ciris_persist::ffi::executor_capsule::TaskOpaque =
                Box::into_raw(outer_box).cast();
            // SAFETY: same contract as `run_async` — `executor.data` and
            // `executor.vtable` come from the same `executor_capsule_v1`
            // PyCapsule extracted at the top of init; `task_ptr` is a
            // freshly-boxed `BoxedFut`. Fire-and-forget (no completion
            // channel); the spawned future loops until self-termination
            // (shutdown signal / lease stolen / repeated backend errors).
            #[allow(unsafe_code)]
            unsafe {
                (executor_for_heartbeat.vtable.spawn)(executor_for_heartbeat.data, task_ptr);
            }
            tracing::info!(
                instance_name = %instance_name_outer,
                "Reticulum shared-instance heartbeat task spawned (10s cadence)"
            );
            Some(SharedInstanceCleanup {
                shutdown_tx: Some(shutdown_tx),
                lease: lease_for_cleanup,
                directory: directory_for_cleanup,
            })
        } else {
            None
        };

    // ── Step 5.5 (v0.19.3 / CIRISEdge#49) — HTTPS transport build.
    //
    // When `https_init_params` resolves to `Some`, mint the dev cert
    // (if requested) into a tmpdir whose lifetime we extend across
    // the rest of init, then assemble `HttpServerConfig` + wire it
    // into an `HttpsTransport`. The transport joins the generic
    // `EdgeBuilder::transport` list — `Edge::run`'s
    // `dispatch_inbound` consumes the same `mpsc::Sender<InboundFrame>`
    // sink regardless of carrier (v0.13.0 / v0.18.1 contract).
    //
    // mTLS path: `verify_dir` is the federation directory edge
    // already holds; the `FederationCnVerifier` consults it at
    // handshake time. Same Arc both verify pipeline + mTLS verifier
    // share — operator deny-listing via `peer_set_trust(Blocked)`
    // does NOT revoke mTLS (AV-46, documented in docs/HTTPS_DEPLOYMENT.md
    // §2); the mTLS handshake checks `federation_keys.pubkey_ed25519_base64`,
    // not `TrustClass`.
    //
    // Bearer path: when `bearer_secret` is supplied, wire it as a
    // `BearerTokenAuth` whose directory is `verify_dir`. The
    // shared-HMAC secret is a v0.19.3 simplification for the
    // conformance harness — the production bearer mode signs JWTs
    // with the federation Ed25519 key (`mint_federation_jwt`); the
    // shared-secret path is harness-only.
    //
    // `_dev_cert_tmpdir` keeps the tempdir alive for the rest of
    // init (transport `listen` borrows the cert paths; if the
    // tempdir Drops, the files are deleted and rustls's startup
    // load would fail). The Arc is moved into the PyEdge wrapper
    // below so it lives for the whole Edge runtime.
    #[cfg(feature = "transport-http")]
    #[allow(clippy::items_after_statements)]
    let (https_transport, https_dev_cert_tmpdir): (
        Option<Arc<crate::transport::http::HttpsTransport>>,
        Option<Arc<tempfile::TempDir>>,
    ) = if let Some(params) = https_init_params {
        use crate::transport::http::{
            BearerTokenAuth, HttpClientConfig, HttpServerConfig, HttpsTransport,
        };
        use sha2::{Digest, Sha256};
        let (cert_path, key_path, tmpdir_handle, mark_dev) = if params.dev_self_signed {
            let tmp = tempfile::tempdir()
                .map_err(|e| PyRuntimeError::new_err(format!("dev-cert tmpdir: {e}")))?;
            // Deterministic seed = first 32 bytes of SHA-256 over
            // the federation key_id + a v0.19.3-pinned constant.
            // Avoids reusing the federation seed (AV-17) AND keeps
            // the dev cert reproducible per (key_id, build) so
            // conformance harness runs cross-check cleanly.
            let mut h = Sha256::new();
            h.update(b"ciris-edge::dev-self-signed::v1\0");
            h.update(signer.key_id.as_bytes());
            let digest = h.finalize();
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&digest);
            // DNS SAN = the host portion of `https_listen_addr`. If
            // bound to a wildcard (`0.0.0.0`), fall back to "localhost"
            // so the harness can dial via that name.
            let dns_san = match params.listen_addr.ip() {
                std::net::IpAddr::V4(v4) if v4.is_unspecified() => "localhost".to_string(),
                std::net::IpAddr::V6(v6) if v6.is_unspecified() => "localhost".to_string(),
                ip => ip.to_string(),
            };
            let (cert, key) = crate::transport::http::mint_dev_self_signed_pair(
                tmp.path(),
                &signer.key_id,
                &dns_san,
                &seed,
            )
            .map_err(|e| PyRuntimeError::new_err(format!("mint_dev_self_signed_pair: {e}")))?;
            (cert, key, Some(Arc::new(tmp)), true)
        } else {
            (
                params
                    .tls_cert_path
                    .expect("validated by HttpsInitParams::parse"),
                params
                    .tls_key_path
                    .expect("validated by HttpsInitParams::parse"),
                None,
                false,
            )
        };

        let bearer_auth = params.bearer_secret.as_ref().map(|_| BearerTokenAuth {
            directory: Arc::clone(&verify_dir),
            expected_audience: None,
        });

        let mut server_config = HttpServerConfig::new(params.listen_addr, cert_path, key_path);
        server_config.mtls_required = params.mtls_required;
        server_config.dev_self_signed = mark_dev;
        server_config.directory = if params.mtls_required {
            Some(Arc::clone(&verify_dir))
        } else {
            None
        };
        server_config.bearer_auth = bearer_auth;

        // No per-peer URL map at init time — the operator wires
        // those via the routing FFI in a follow-up (v0.20.0 #50
        // scope). HTTPS server-only at v0.19.3 closes the inbound
        // path that #3 / #4 need.
        let transport = HttpsTransport::new(
            Some(server_config),
            HttpClientConfig::default(),
            std::collections::HashMap::new(),
        )
        .map_err(|e| PyRuntimeError::new_err(format!("HttpsTransport::new: {e}")))?;

        (Some(Arc::new(transport)), tmpdir_handle)
    } else {
        (None, None)
    };

    // ── Step 6: assemble the Edge. The pre-built EventBus +
    // ReachabilityTracker are shared with the Reticulum transport
    // (auth above) so #34 link / announce / interface emissions reach
    // the same channels Edge's `subscribe_link_events` consumers
    // observe — the v0.14.0 close of #34's link half.
    //
    // v0.18.0 (CIRISEdge#45) — flow the operator-declared posture
    // through `AgentMode::apply_defaults` (the single source of truth
    // for mode → knob mapping) into the EdgeConfig the builder sees.
    // The default `EdgeConfig::default()` matches AgentMode::Proxy, so
    // a caller that omits `agent_mode` keeps v0.17.x behaviour exactly.
    let mut config = crate::edge::EdgeConfig {
        hybrid_policy,
        ..Default::default()
    };
    parsed_agent_mode.apply_defaults(&mut config);
    // v0.20.0 RC1 (CIRISEdge#51) — operator overrides for the CEWP
    // L0/L1 tier defaults. `apply_defaults` set both fields to the
    // mode-derived value; `Some(_)` here pins a per-deployment
    // override. The two knobs are orthogonal — disk_budget_bytes is
    // advisory at edge (persist/host enforces capacity), while
    // trust_recursion_depth threads through dispatch_inbound's
    // `TrustScoring::trust_score` call (depth 0 = strict direct
    // attestations; depth 1 = friend-of-friends via persist's
    // delegates_to walk).
    if let Some(bytes) = disk_budget_bytes {
        config.disk_budget_bytes = bytes;
    }
    if let Some(depth) = trust_recursion_depth {
        config.trust_recursion_depth = depth;
    }

    let mut builder = Edge::builder()
        .directory(Arc::clone(&verify_dir))
        .federation_directory(federation_directory_for_edge)
        .queue(queue)
        .signer(signer)
        // v1.1.2 (CIRISEdge#50 darwin follow-on completion) — also
        // pass the local-seed-derived signer extracted at Step 3.5.
        // `Edge::scrub_signer` (added in v1.1.1) routes envelope
        // signing through this in-memory adapter when its key_id
        // matches `signer.key_id`, mirroring CIRISPersist#137/#138
        // `select_signer`. v1.1.1 added the field + setter but
        // **omitted this builder call** (commit 534d53f), so
        // self.local_signer stayed None and signing routed through
        // the forensic keyring path — identical behavior to v1.1.0
        // on headless darwin. This line completes the fix.
        .local_signer(reticulum_identity_signer.clone())
        .events(Arc::clone(&event_bus))
        .reachability(Arc::clone(&reachability_tracker))
        // v0.17.0 (CIRISEdge#39 emit_verdict flip) — wire the persist
        // admission handle so the probe-pattern observer's
        // `emit_verdict` writes through `put_edge_detection_event`.
        // The observer itself only constructs when the deployment
        // sets `EdgeConfig::probe_pattern_observer_enabled = true`;
        // wiring the schema unconditionally is harmless when the
        // observer is off (Edge::detector stays None).
        .derived_schema(derived_schema)
        // v0.18.0 (CIRISEdge#46) — canonical bootstrap-peer set powers
        // the `peer_remove` hard-remove guard + the `EdgePeerInfo`
        // canonical-flag projection. The persist reseed already fired
        // above; this populates the in-memory HashSet.
        .canonical_bootstrap_peers(canonical_peers)
        // v0.18.0 (CIRISEdge#45) — flow the parsed agent_mode and its
        // derived listener_bound + outbound_queue_max into the Edge.
        .config(config);

    // v0.19.6 (CIRISEdge#48-B) — wire the optional trust scorer (see
    // the deferred-derivation comment at Step 2 / `trust_scoring`
    // binding above). When `None`, the short-circuit is
    // structurally disabled (the default cohab posture for v0.19.6).
    if let Some(scoring) = trust_scoring {
        builder = builder.trust_scoring(scoring);
    }

    // v0.19.3 — Reticulum is conditional (the `disable_reticulum`
    // posture); HTTPS is additive (push as a generic transport into
    // the builder's transport vec). Both can be active concurrently:
    // `Edge::run` iterates the transport vec and runs each `listen`
    // on a sibling tokio task; outbound `send` consults `transport_id`
    // routing to pick the right medium per envelope.
    if let Some(reticulum_t) = reticulum_transport {
        builder = builder.reticulum_transport(reticulum_t);
    }
    #[cfg(feature = "transport-http")]
    if let Some(https_t) = https_transport {
        builder = builder.transport(https_t as Arc<dyn crate::transport::Transport>);
    }

    let edge = builder
        .build()
        .map_err(|e| PyRuntimeError::new_err(format!("Edge::build: {e}")))?;

    let edge_arc = Arc::new(edge);

    // v0.13.0 (CIRISEdge#36 GO) — install the process-global
    // `Weak<Edge>` so the UniFFI bindings (`crate::ffi::uniffi_impl`)
    // can resolve to the same runtime on free-function calls. The
    // PyO3 surface is the entry; UniFFI peer_list / transport_list /
    // identity_hash / metrics_snapshot all reach back through this
    // weak handle. See `ffi::uniffi_impl::install_edge_handle` for
    // the registry shape.
    #[cfg(feature = "ffi-uniffi")]
    crate::ffi::uniffi_impl::install_edge_handle(&edge_arc);

    // Suppress unused-binding warning for `runtime` — kept in scope
    // for the init-body `runtime.enter()` guard but not stored on
    // PyEdge post-CIRISEdge#59 (the executor handles all spawns).
    let _ = runtime;
    // v2.1.0 (CIRISEdge#85 / CIRISLensCore#43) — retain a strong
    // reference to the host engine PyObject so [`PyEdge::engine`] can
    // hand it to cohabiting cdylibs. `Bound::unbind()` converts the
    // GIL-bound reference into a Send + Sync `Py<PyAny>` storable on
    // the PyEdge struct; Python's atomic refcount keeps the engine
    // alive at least until PyEdge drops. Cheap: one Python refcount
    // bump.
    let engine_handle = engine.clone().unbind();
    Ok(PyEdge {
        inner: edge_arc,
        executor,
        engine: Some(engine_handle),
        #[cfg(feature = "transport-http")]
        _dev_cert_tmpdir: https_dev_cert_tmpdir,
        #[cfg(feature = "transport-reticulum-local")]
        shared_instance_cleanup: std::sync::Mutex::new(shared_instance_cleanup),
    })
}

/// Top-level Python module entry point. `import ciris_edge` triggers
/// this; per-symbol bindings register here as they land.
// CIRISEdge#58 — diagnostic surface, gated under the `debug-tools`
// Cargo feature. When the feature is OFF (the default for every
// release wheel), neither pyfunction exists on the Python module
// and `crate::debug` is not compiled — no FFI surface, no env-var
// reading, no panic-capture machinery in the binary. See
// `Cargo.toml::[features].debug-tools` for the security rationale.
#[cfg(feature = "debug-tools")]
#[pyfunction]
/// Read the process-global background-thread panic count.
///
/// Counts every panic captured by the [`crate::debug::install_panic_logger`]
/// hook in this process since first install. Returns `0` if the hook
/// was never installed (i.e. `CIRIS_EDGE_PANIC_LOG` was unset).
/// Useful from harness scripts to detect "did any background thread
/// panic during this operation" without parsing the log file:
///
/// ```python
/// before = ciris_edge.panic_count()
/// edge.send_durable_inline_text(kid, "x")
/// if ciris_edge.panic_count() > before:
///     # Inspect $CIRIS_EDGE_PANIC_LOG.{pid} for the resolved backtrace.
///     ...
/// ```
fn panic_count() -> u64 {
    crate::debug::PANIC_COUNT.load(std::sync::atomic::Ordering::Relaxed)
}

#[cfg(feature = "debug-tools")]
#[pyfunction]
/// Install the panic-logging hook now.
///
/// Reads `CIRIS_EDGE_PANIC_LOG` at install time. Calling without the
/// env var set is a no-op. Returns `True` if the hook is active (or
/// already-installed), `False` if the env var was absent. Safe to
/// call repeatedly; only the first call installs.
fn install_panic_logger() -> bool {
    crate::debug::install_panic_logger()
}

// ─── CIRISEdge#123 — cross-wheel conformance surface ─────────────────
//
// Thin PyO3 wrappers over existing Rust pub fns in `transport::realtime_av`
// + `transport::federation_session` + the leviculum RNS destination-hash
// (CEG §5.6.8.8.1.1) so the published Python wheel can drive these
// surfaces under CIRISConformance — measuring the production cohabitation
// cost (cross-wheel / FFI) of the realtime A/V mesh profile.
//
// No wire/API change to the Rust crate. All bytes in / bytes out — none
// of the redacted-Debug newtypes (EpochDek / SessionKey / OwnKexKeys)
// escape the Python boundary; callers thread the raw 32-byte slices.

/// Coerce a Python `bytes`-like into a fixed-length array. Mirrors the
/// idiom used for the federation-session KEX keys + epoch DEKs.
fn fixed_bytes<const N: usize>(label: &str, b: &[u8]) -> PyResult<[u8; N]> {
    if b.len() != N {
        return Err(PyValueError::new_err(format!(
            "{label}: expected {N} bytes, got {}",
            b.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(b);
    Ok(out)
}

/// Seal a chunk under both the inner epoch DEK and the outer transit
/// key (CEG §10.5.5 E1). Returns the on-wire bytes
/// (`SealedAvChunk::to_bytes`) — caller threads them straight into the
/// RNS Link outbound queue.
#[pyfunction]
#[pyo3(signature = (plaintext, transit_key, link_id, link_seq, epoch_dek, stream_id, epoch, chunk_seq))]
#[allow(clippy::too_many_arguments)]
fn seal_av_chunk(
    plaintext: &[u8],
    transit_key: &[u8],
    link_id: &[u8],
    link_seq: u64,
    epoch_dek: &[u8],
    stream_id: &[u8],
    epoch: u64,
    chunk_seq: u64,
) -> PyResult<Vec<u8>> {
    use crate::transport::realtime_av;
    let transit = fixed_bytes::<32>("transit_key", transit_key)?;
    let dek_bytes = fixed_bytes::<32>("epoch_dek", epoch_dek)?;
    let stream = fixed_bytes::<32>("stream_id", stream_id)?;
    let dek = realtime_av::EpochDek::from_bytes(dek_bytes);
    // CIRISEdge#128 — this v3.7.0-shape PyO3 wrapper stamps the
    // codec-opaque marker so the resulting wire round-trips identically
    // to v3.7.0. The layered Python wrapper (CIRISEdge#128 follow-up)
    // will surface the `codec_id` / `layer` knobs.
    let sealed = realtime_av::seal_av_chunk(
        plaintext,
        &transit,
        link_id,
        link_seq,
        &dek,
        realtime_av::StreamId(stream),
        realtime_av::Epoch(epoch),
        realtime_av::ChunkSeq(chunk_seq),
        realtime_av::CODEC_OPAQUE,
        realtime_av::ChunkLayer::BASE,
    )
    .map_err(|e| PyRuntimeError::new_err(format!("seal_av_chunk: {e}")))?;
    Ok(sealed.to_bytes())
}

/// Open a sealed A/V chunk (inverse of [`seal_av_chunk`]). Input is the
/// on-wire bytes; returns the chunk plaintext.
#[pyfunction]
#[pyo3(signature = (sealed_bytes, transit_key, link_id, link_seq, epoch_dek))]
fn open_av_chunk(
    sealed_bytes: &[u8],
    transit_key: &[u8],
    link_id: &[u8],
    link_seq: u64,
    epoch_dek: &[u8],
) -> PyResult<Vec<u8>> {
    use crate::transport::realtime_av;
    let transit = fixed_bytes::<32>("transit_key", transit_key)?;
    let dek_bytes = fixed_bytes::<32>("epoch_dek", epoch_dek)?;
    let dek = realtime_av::EpochDek::from_bytes(dek_bytes);
    let sealed = realtime_av::SealedAvChunk::from_bytes(sealed_bytes)
        .map_err(|e| PyValueError::new_err(format!("open_av_chunk: parse: {e}")))?;
    realtime_av::open_av_chunk(&sealed, &transit, link_id, link_seq, &dek)
        .map_err(|e| PyRuntimeError::new_err(format!("open_av_chunk: aead: {e}")))
}

/// Inner-only seal — produces the inner AEAD ciphertext (E2E sealed
/// under the epoch DEK). CIRISEdge#122 fan-out optimization: call once
/// per chunk, then call [`seal_av_outer`] N times for the mesh.
#[pyfunction]
#[pyo3(signature = (plaintext, epoch_dek, stream_id, epoch, chunk_seq))]
fn seal_av_inner(
    plaintext: &[u8],
    epoch_dek: &[u8],
    stream_id: &[u8],
    epoch: u64,
    chunk_seq: u64,
) -> PyResult<Vec<u8>> {
    use crate::transport::realtime_av;
    let dek_bytes = fixed_bytes::<32>("epoch_dek", epoch_dek)?;
    let stream = fixed_bytes::<32>("stream_id", stream_id)?;
    let dek = realtime_av::EpochDek::from_bytes(dek_bytes);
    // CIRISEdge#128 — codec-opaque marker for v3.7.0 wire shape
    // compatibility on the existing FFI signature.
    let inner = realtime_av::seal_av_inner(
        plaintext,
        &dek,
        realtime_av::StreamId(stream),
        realtime_av::Epoch(epoch),
        realtime_av::ChunkSeq(chunk_seq),
        realtime_av::CODEC_OPAQUE,
        realtime_av::ChunkLayer::BASE,
    )
    .map_err(|e| PyRuntimeError::new_err(format!("seal_av_inner: {e}")))?;
    Ok(inner.inner_ciphertext().to_vec())
}

/// Outer-only seal — given a pre-computed inner ciphertext (from
/// [`seal_av_inner`]) and per-Link state, produces the on-wire bytes.
/// CIRISEdge#122 fan-out optimization companion.
///
/// `stream_id` / `epoch` / `chunk_seq` are the chunk-header fields
/// stamped into the wire shape (NOT inputs to the outer AEAD; the
/// outer nonce derives only from `link_id` + `link_seq`).
#[pyfunction]
#[pyo3(signature = (inner_ciphertext, transit_key, link_id, link_seq, stream_id, epoch, chunk_seq))]
#[allow(clippy::too_many_arguments)]
fn seal_av_outer(
    inner_ciphertext: &[u8],
    transit_key: &[u8],
    link_id: &[u8],
    link_seq: u64,
    stream_id: &[u8],
    epoch: u64,
    chunk_seq: u64,
) -> PyResult<Vec<u8>> {
    use crate::transport::realtime_av;
    let transit = fixed_bytes::<32>("transit_key", transit_key)?;
    let stream = fixed_bytes::<32>("stream_id", stream_id)?;
    // Rebuild the inner sealed handle from its parts. The Rust struct's
    // constructor is private; we go through the `seal_av_inner` ->
    // `seal_av_outer` path conceptually by reconstructing equivalent
    // bytes-equivalent state via a synthesized inner. Since the outer
    // step only reads `inner_ciphertext` + the chunk header, we wrap
    // them through the public ciphertext-bytes helper.
    // CIRISEdge#128 — codec-opaque marker for v3.7.0 wire shape
    // compatibility on the existing FFI signature.
    let inner = realtime_av::inner_sealed_from_parts(
        realtime_av::StreamId(stream),
        realtime_av::Epoch(epoch),
        realtime_av::ChunkSeq(chunk_seq),
        realtime_av::CODEC_OPAQUE,
        realtime_av::ChunkLayer::BASE,
        inner_ciphertext.to_vec(),
    );
    let sealed = realtime_av::seal_av_outer(&inner, &transit, link_id, link_seq)
        .map_err(|e| PyRuntimeError::new_err(format!("seal_av_outer: {e}")))?;
    Ok(sealed.to_bytes())
}

/// Hybrid X25519 + ML-KEM-768 KEX — initiator side (CIRISEdge#54).
///
/// `algorithm` is one of `"hybrid"`, `"hybrid-required"`, or `"classical"`.
/// HNDL-strict callers (realtime A/V, key_grant DEK distribution) should
/// pass `"hybrid-required"`: classical fallback is REJECTED rather than
/// silently negotiated down.
///
/// Returns `(handshake_msg_json_bytes, session_key, negotiated_algorithm_wire_id)`.
/// The handshake JSON round-trips through
/// [`federation_session_respond`]; the session key is 32 bytes (the
/// AES-256-GCM key for the transport layer).
#[pyfunction]
#[pyo3(signature = (peer_x25519_pub, peer_mlkem768_pub, algorithm))]
fn federation_session_initiate(
    peer_x25519_pub: &[u8],
    peer_mlkem768_pub: Option<&[u8]>,
    algorithm: &str,
) -> PyResult<(Vec<u8>, [u8; 32], String)> {
    use crate::transport::federation_session::{
        FederationSession, KexAlgorithm, PeerKexPubkeys, SessionHandshakeMsg,
    };
    let x_pub = fixed_bytes::<32>("peer_x25519_pub", peer_x25519_pub)?;
    let peer = PeerKexPubkeys {
        x25519_pub: x_pub,
        mlkem768_pub: peer_mlkem768_pub.map(<[u8]>::to_vec),
    };
    let requested = match algorithm {
        "hybrid" => KexAlgorithm::Hybrid,
        "hybrid-required" => KexAlgorithm::HybridRequired,
        "classical" => KexAlgorithm::Classical,
        other => {
            return Err(PyValueError::new_err(format!(
                "algorithm: expected 'hybrid' | 'hybrid-required' | 'classical', got {other:?}"
            )));
        }
    };
    let (msg, key) = FederationSession::initiate(&peer, requested)
        .map_err(|e| PyRuntimeError::new_err(format!("initiate: {e}")))?;
    let json = match &msg {
        SessionHandshakeMsg::Hybrid(m) => serde_json::to_vec(m),
        SessionHandshakeMsg::Classical(m) => serde_json::to_vec(m),
    }
    .map_err(|e| PyRuntimeError::new_err(format!("handshake encode: {e}")))?;
    let mut key_out = [0u8; 32];
    key_out.copy_from_slice(key.as_bytes());
    Ok((json, key_out, msg.algorithm().to_string()))
}

/// Hybrid X25519 + ML-KEM-768 KEX — responder side. Recomputes the same
/// 32-byte session key the initiator derived.
#[pyfunction]
#[pyo3(signature = (own_x25519_priv, own_mlkem768_priv, own_mlkem768_pub, handshake_msg_json))]
fn federation_session_respond(
    own_x25519_priv: &[u8],
    own_mlkem768_priv: Option<&[u8]>,
    own_mlkem768_pub: Option<&[u8]>,
    handshake_msg_json: &[u8],
) -> PyResult<[u8; 32]> {
    use crate::transport::federation_session::{
        FederationSession, OwnKexKeys, SessionHandshakeMsg,
    };
    use ciris_crypto::hybrid_kex::{
        ClassicalHandshakeMsg, HybridHandshakeMsg, KEX_ALGORITHM_CLASSICAL_V1,
        KEX_ALGORITHM_HYBRID_V1,
    };
    let x_priv = fixed_bytes::<32>("own_x25519_priv", own_x25519_priv)?;
    let own = OwnKexKeys {
        x25519_priv: x_priv,
        mlkem768_priv: own_mlkem768_priv.map(<[u8]>::to_vec),
        mlkem768_pub: own_mlkem768_pub.map(<[u8]>::to_vec),
    };
    // Peek at the algorithm field — the JSON object always has an
    // `algorithm` string at the top.
    let raw: serde_json::Value = serde_json::from_slice(handshake_msg_json)
        .map_err(|e| PyValueError::new_err(format!("handshake decode: {e}")))?;
    let algo = raw
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or_else(|| PyValueError::new_err("handshake missing `algorithm` field"))?;
    let msg = match algo {
        a if a == KEX_ALGORITHM_HYBRID_V1 => {
            let m: HybridHandshakeMsg = serde_json::from_slice(handshake_msg_json)
                .map_err(|e| PyValueError::new_err(format!("hybrid decode: {e}")))?;
            SessionHandshakeMsg::Hybrid(m)
        }
        a if a == KEX_ALGORITHM_CLASSICAL_V1 => {
            let m: ClassicalHandshakeMsg = serde_json::from_slice(handshake_msg_json)
                .map_err(|e| PyValueError::new_err(format!("classical decode: {e}")))?;
            SessionHandshakeMsg::Classical(m)
        }
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown algorithm: {other:?}"
            )));
        }
    };
    let key = FederationSession::respond(&own, &msg)
        .map_err(|e| PyRuntimeError::new_err(format!("respond: {e}")))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(key.as_bytes());
    Ok(out)
}

/// CEG §5.6.8.8.1.1 — RC6-pinned two-stage RNS destination-hash recompute.
/// Lets a conformance verifier independently derive an arbitrary peer's
/// `destination_hash` from its advertised `(x25519_pub, ed25519_pub)`
/// + the binding's app-name + aspect list.
///
/// Returns 16 bytes (the TRUNCATED_HASHLENGTH the spec pins). AV-42
/// destination-authenticity recompute (CIRISVerify#28).
#[cfg(feature = "transport-reticulum")]
#[pyfunction]
#[pyo3(signature = (app_name, aspects, x25519_pub, ed25519_pub))]
fn rns_destination_hash(
    app_name: &str,
    aspects: &Bound<'_, PyAny>,
    x25519_pub: &[u8],
    ed25519_pub: &[u8],
) -> PyResult<[u8; 16]> {
    use reticulum_core::{Destination, Identity};
    let x_pub = fixed_bytes::<32>("x25519_pub", x25519_pub)?;
    let ed_pub = fixed_bytes::<32>("ed25519_pub", ed25519_pub)?;
    let identity = Identity::from_public_keys(&x_pub, &ed_pub)
        .map_err(|e| PyValueError::new_err(format!("identity: {e:?}")))?;
    let aspects_vec: Vec<String> = aspects.extract()?;
    let aspects_ref: Vec<&str> = aspects_vec.iter().map(String::as_str).collect();
    let name_hash = Destination::compute_name_hash(app_name, &aspects_ref);
    let dest_hash = Destination::compute_destination_hash(&name_hash, identity.hash());
    Ok(*dest_hash.as_bytes())
}

// ─── CIRISEdge v3.8.0 — Layer 3 conformance surface ─────────────────
//
// PyO3 wrappers for the v3.8.0 realtime A/V additions:
//   • Codec namespace constants (CODEC_AV1_SVC / JPEG_XS / MDC / OPAQUE)
//   • MLS ciphersuite constant (0x004D X-Wing) for conformance attestation
//   • plan_layered_by_policy — policy-only fan-out filter (CIRISEdge#128)
//   • PyAvSession — MLS-backed stateful group session (CIRISEdge#129)
//   • PyRelayNode — SFU forwarding hop (CIRISEdge#66, gated on
//     `transport-reticulum` because the underlying RelayNode owns a
//     leviculum ReticulumNode handle)
//
// Bytes-in / bytes-out throughout. No redacted-Debug newtype
// (EpochDek / RootSecret / OwnKexKeys / SessionKey) escapes the Python
// boundary; callers thread raw 32-byte slices, JSON-encoded wire bytes,
// or per-tuple int/byte fields. AvSessionError / RelayError map to
// PyValueError (input validation) or PyRuntimeError (operation failed).
//
// Threading note — PyAvSession holds an MlsSession which embeds an
// Arc<LibcruxProvider> + an openmls MlsGroup + a SignatureKeyPair. The
// pyclass is constructed and mutated under the GIL; we do NOT mark it
// `unsendable` because callers may want to move the handle between
// asyncio tasks. If the openmls upstream surfaces a !Send field in a
// future cut, pin this with `#[pyclass(unsendable)]`.
//
// HNDL discipline — Member tuples with `mlkem768_pub = None` reject
// at conversion with PyValueError("…lacks ML-KEM-768…") BEFORE any MLS
// code runs (preserves the AvSessionError::PeerLacksMlkem semantics on
// the Python surface).

// CIRISEdge#128 — codec discriminators (re-export of
// `realtime_av::CODEC_*` constants for the Python surface).
const PY_CODEC_AV1_SVC: u8 = crate::transport::realtime_av::CODEC_AV1_SVC;
const PY_CODEC_JPEG_XS: u8 = crate::transport::realtime_av::CODEC_JPEG_XS;
const PY_CODEC_MDC: u8 = crate::transport::realtime_av::CODEC_MDC;
const PY_CODEC_OPAQUE: u8 = crate::transport::realtime_av::CODEC_OPAQUE;
/// CIRISEdge#129 — MLS X-Wing ciphersuite code point. Mirrors
/// `MlsSession::ciphersuite_id()`. Exposed as a constant so
/// CIRISConformance can attest the cohabiting wheel's MLS layer is
/// pinned to the post-quantum hybrid ciphersuite without invoking the
/// session constructor.
const PY_MLS_CIPHERSUITE_XWING_ID: u16 = crate::transport::realtime_av_mls::CIPHERSUITE_ID;

/// Decode a `(spatial, temporal, quality)` Python tuple into a
/// [`ChunkLayer`]. Returns `PyValueError` on shape mismatch.
fn chunk_layer_from_tuple(t: (u8, u8, u8)) -> crate::transport::realtime_av::ChunkLayer {
    crate::transport::realtime_av::ChunkLayer {
        spatial: t.0,
        temporal: t.1,
        quality: t.2,
    }
}

/// Decode a `(max_spatial, max_temporal, max_quality)` Python tuple
/// into a [`ReceiverLayerPolicy`].
fn receiver_policy_from_tuple(
    t: (u8, u8, u8),
) -> crate::transport::realtime_av::ReceiverLayerPolicy {
    crate::transport::realtime_av::ReceiverLayerPolicy {
        max_spatial: t.0,
        max_temporal: t.1,
        max_quality: t.2,
    }
}

/// CIRISEdge#128 / L2-A — policy-only layer-aware fan-out filter
/// exposed to Python.
///
/// **Reachability filtering is NOT included on this surface.** The
/// Rust-side `RealtimeFanout::plan_layered` takes a
/// `&ReachabilityTracker`; that tracker type is not Python-friendly
/// (cross-wheel handoff would require yet another capsule contract).
/// The Python wrapper assumes the caller has already filtered
/// participants by reachability via whatever mechanism is appropriate
/// at the call site (the cohabiting agent's outbound queue tracks
/// per-peer reachability separately, so the filter is a no-op for
/// many cohabitation flows). This filter then drops the remaining
/// participants whose per-receiver
/// [`ReceiverLayerPolicy`](crate::transport::realtime_av::ReceiverLayerPolicy)
/// does not admit the given chunk layer.
///
/// Equivalent to `RealtimeFanout::plan_layered` with the reachability
/// rule passed-through (every participant treated as reachable). Use
/// in conformance harnesses + Python-side mesh planners; for in-Rust
/// callers, use `RealtimeFanout::plan_layered` directly.
#[pyfunction]
#[pyo3(signature = (participants_with_policy, chunk_layer))]
fn plan_layered_by_policy(
    participants_with_policy: Vec<(String, (u8, u8, u8))>,
    chunk_layer: (u8, u8, u8),
) -> Vec<String> {
    let layer = chunk_layer_from_tuple(chunk_layer);
    participants_with_policy
        .into_iter()
        .filter_map(|(peer_key_id, policy_t)| {
            let policy = receiver_policy_from_tuple(policy_t);
            if policy.admits(layer) {
                Some(peer_key_id)
            } else {
                None
            }
        })
        .collect()
}

// ─── PyAvSession (CIRISEdge#129 / L2-B) ─────────────────────────────

/// Stateful MLS-backed group-key holder for one realtime stream.
/// CIRIS-shaped wrapper around `transport::realtime_av_session::AvSession`.
///
/// All membership-change verbs (join / leave) round-trip through
/// `advance_epoch_*`, returning the new epoch + MLS wire artifacts
/// (Commit bytes, Welcome bytes on Join) + the freshly-derived 32-byte
/// EpochDek. Existing members apply the same Commit via
/// `process_commit` to land on the same epoch.
///
/// **Joiner-side bootstrap is wired in Rust** (CIRISEdge#155 Gap 2:
/// `AvSession::new_joiner` + `AvSession::process_welcome`) but is not
/// yet exposed through this PyO3 surface — the joiner's opaque
/// `JoinerKeyMaterial` can't be rebuilt from raw KEX bytes, so the FFI
/// `process_welcome` returns a `RuntimeError`. Exercise the joiner
/// round-trip through the Rust-side `tests` module until the FFI
/// redesign (opaque pending-session handle) lands.
///
/// Member tuple shape (`key_id`, `x25519_pub`, `mlkem768_pub`) mirrors
/// the Rust `Member { key_id, kex_pubkeys: PeerKexPubkeys }`. A `None`
/// for `mlkem768_pub` rejects at conversion with `PyValueError` (HNDL
/// discipline — the 0x004D ciphersuite requires ML-KEM-768; the
/// pre-check fails closed before any MLS code runs).
#[pyclass(name = "AvSession", module = "ciris_edge")]
pub struct PyAvSession {
    inner: crate::transport::realtime_av_session::AvSession,
}

/// Convert a Python member tuple (`key_id`, `x25519_pub`,
/// `mlkem768_pub`) into the Rust [`Member`] shape, enforcing the HNDL
/// pre-check (mlkem768_pub MUST be Some). Failing here surfaces
/// `PyValueError` before the openmls layer is invoked.
fn member_from_py(
    label: &str,
    key_id: String,
    x25519_pub: &[u8],
    mlkem768_pub: Option<&[u8]>,
) -> PyResult<crate::transport::realtime_av_mls::Member> {
    use crate::transport::federation_session::PeerKexPubkeys;
    use crate::transport::realtime_av_mls::Member;
    let x = fixed_bytes::<32>(&format!("{label}.x25519_pub"), x25519_pub)?;
    let Some(mlkem) = mlkem768_pub else {
        return Err(PyValueError::new_err(format!(
            "{label}: ML-KEM-768 pubkey required by ciphersuite 0x004D (HNDL discipline) — peer {key_id}"
        )));
    };
    Ok(Member {
        key_id,
        kex_pubkeys: PeerKexPubkeys {
            x25519_pub: x,
            mlkem768_pub: Some(mlkem.to_vec()),
        },
    })
}

/// Map an `AvSessionError` to the appropriate `PyErr`.
///
/// - `PeerLacksMlkem`, `WelcomeMalformed`, `JoinerKeyPackageAbsent`,
///   and `AlreadyInitialized` are input-validation / caller-state
///   errors (`PyValueError`).
/// - `WelcomeRejected` + `Mls(_)` are operation failures
///   (`PyRuntimeError`).
///
/// Note: as of L5-C (CIRISEdge#131) `ReplaceNotSupported` no longer
/// exists — `RosterDelta::Replace` is implemented via batched
/// commits and any failure surfaces as `Mls(_)` instead.
fn map_av_session_err(e: &crate::transport::realtime_av_session::AvSessionError) -> PyErr {
    use crate::transport::realtime_av_session::AvSessionError;
    match e {
        AvSessionError::PeerLacksMlkem(_)
        | AvSessionError::WelcomeMalformed(_)
        | AvSessionError::JoinerKeyPackageAbsent
        | AvSessionError::AlreadyInitialized => PyValueError::new_err(format!("{e}")),
        AvSessionError::WelcomeRejected(_) | AvSessionError::Mls(_) => {
            PyRuntimeError::new_err(format!("{e}"))
        }
    }
}

#[pymethods]
impl PyAvSession {
    /// Create a fresh MLS-backed session for `stream_id`. The local
    /// participant is identified by `own_key_id`; `initial_members` is
    /// the peer set added at group genesis.
    ///
    /// Returns `(PyAvSession, initial_epoch_dek_32B)`. The DEK is the
    /// MLS first-epoch exporter secret; every group member derives the
    /// same 32 bytes from their own session at the same epoch.
    ///
    /// HNDL pre-check: any member tuple whose `mlkem768_pub` is `None`
    /// rejects with `ValueError` before any MLS code runs.
    #[staticmethod]
    #[pyo3(signature = (stream_id, own_key_id, initial_members))]
    fn create(
        stream_id: &[u8],
        own_key_id: &str,
        initial_members: Vec<(String, Vec<u8>, Option<Vec<u8>>)>,
    ) -> PyResult<(Self, [u8; 32])> {
        let stream_bytes = fixed_bytes::<32>("stream_id", stream_id)?;
        let stream = crate::transport::realtime_av::StreamId(stream_bytes);
        let mut members = Vec::with_capacity(initial_members.len());
        for (i, (key_id, x_pub, mlkem_pub)) in initial_members.into_iter().enumerate() {
            let label = format!("initial_members[{i}]");
            members.push(member_from_py(
                &label,
                key_id,
                &x_pub,
                mlkem_pub.as_deref(),
            )?);
        }
        let (session, dek) =
            crate::transport::realtime_av_session::AvSession::create(stream, own_key_id, members)
                .map_err(|e| map_av_session_err(&e))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(dek.as_bytes());
        Ok((Self { inner: session }, out))
    }

    /// Current epoch counter (matches the underlying MLS group epoch).
    fn epoch(&self) -> u64 {
        self.inner.epoch().0
    }

    /// Current stream id (32 bytes).
    fn stream_id(&self) -> [u8; 32] {
        self.inner.stream_id().0
    }

    /// Current roster size (count of members in the MLS group,
    /// including the local participant).
    fn roster_size(&self) -> usize {
        self.inner.roster_size()
    }

    /// Admit one new participant. Translates to an MLS `commit_add`
    /// and produces both a Commit (for existing members) and a
    /// Welcome (for the joiner) + the new 32-byte EpochDek.
    ///
    /// Returns `(new_epoch_u64, commit_bytes, welcome_bytes, new_dek_32B)`.
    /// HNDL pre-check applies (mlkem768_pub required).
    #[pyo3(signature = (new_member))]
    #[allow(clippy::type_complexity)] // 4-tuple is the wire shape callers expect
    fn advance_epoch_join(
        &mut self,
        new_member: (String, Vec<u8>, Option<Vec<u8>>),
    ) -> PyResult<(u64, Vec<u8>, Vec<u8>, [u8; 32])> {
        use crate::transport::realtime_av_session::RosterDelta;
        let (key_id, x_pub, mlkem_pub) = new_member;
        let member = member_from_py("new_member", key_id, &x_pub, mlkem_pub.as_deref())?;
        let artifacts = self
            .inner
            .advance_epoch(RosterDelta::Join(member))
            .map_err(|e| map_av_session_err(&e))?;
        // `welcome_bytes` is `Vec<Vec<u8>>` after L5-C. On a single-
        // Join path the AvSession contract gives us exactly one
        // Welcome; any other shape would be a regression.
        let mut welcome_list = artifacts.welcome_bytes;
        let welcome = match welcome_list.len() {
            1 => welcome_list.remove(0),
            n => {
                return Err(PyRuntimeError::new_err(format!(
                    "advance_epoch(Join) returned {n} Welcomes — internal invariant violated (want 1)"
                )));
            }
        };
        let mut dek_out = [0u8; 32];
        dek_out.copy_from_slice(artifacts.new_dek.as_bytes());
        Ok((
            artifacts.new_epoch.0,
            artifacts.commit_bytes,
            welcome,
            dek_out,
        ))
    }

    /// Evict one participant. Translates to an MLS `commit_remove`;
    /// the leaver is quarantined out of the group per RFC 9420 §13.4
    /// (forward secrecy on Leave).
    ///
    /// Returns `(new_epoch_u64, commit_bytes, new_dek_32B)`. No
    /// Welcome — only Join produces one.
    #[pyo3(signature = (member_key_id))]
    fn advance_epoch_leave(&mut self, member_key_id: &str) -> PyResult<(u64, Vec<u8>, [u8; 32])> {
        use crate::transport::realtime_av_session::RosterDelta;
        let artifacts = self
            .inner
            .advance_epoch(RosterDelta::Leave(member_key_id.to_string()))
            .map_err(|e| map_av_session_err(&e))?;
        let mut dek_out = [0u8; 32];
        dek_out.copy_from_slice(artifacts.new_dek.as_bytes());
        Ok((artifacts.new_epoch.0, artifacts.commit_bytes, dek_out))
    }

    /// Receiver-side — apply a Commit produced by another node's
    /// `advance_epoch_*`. Advances the local MLS group to the new
    /// epoch and returns the matching 32-byte EpochDek.
    ///
    /// Every existing member who applies the same commit derives the
    /// same EpochDek (RFC 9420 §8.5).
    #[pyo3(signature = (commit_bytes))]
    fn process_commit(&mut self, commit_bytes: &[u8]) -> PyResult<[u8; 32]> {
        let dek = self
            .inner
            .process_commit(commit_bytes)
            .map_err(|e| map_av_session_err(&e))?;
        let mut out = [0u8; 32];
        out.copy_from_slice(dek.as_bytes());
        Ok(out)
    }

    /// Joiner-side bootstrap from a Welcome.
    ///
    /// **Not exposed through this raw-bytes FFI signature.** The Rust
    /// joiner path (CIRISEdge#155 Gap 2) is now wired via
    /// `AvSession::new_joiner(stream_id, JoinerKeyMaterial)` +
    /// `AvSession::process_welcome(&mut self, welcome_bytes)`. The
    /// joiner's private leaf material lives inside an opaque openmls
    /// provider (`JoinerKeyMaterial`, minted by
    /// `realtime_av_mls::mint_joiner_key_material`) and cannot be
    /// reconstructed from the raw `(x25519_priv, mlkem768_priv,
    /// mlkem768_pub)` KEX bytes this signature accepts. Exposing the
    /// joiner path to Python requires a redesigned FFI surface that
    /// stages `JoinerKeyMaterial` Rust-side and hands Python an opaque
    /// pending-session handle — tracked as a follow-up.
    ///
    /// Returns a `RuntimeError` deliberately; the conformance harness
    /// should expect it and exercise the joiner round-trip through the
    /// Rust unit tests until the FFI redesign lands.
    ///
    /// Argument shape is retained for call-site compatibility; the HNDL
    /// pre-check still fires first (`own_mlkem768_pub == None` rejects
    /// with `ValueError`).
    #[staticmethod]
    #[pyo3(signature = (welcome_bytes, own_x25519_priv, own_mlkem768_priv, own_mlkem768_pub))]
    fn process_welcome(
        welcome_bytes: &[u8],
        own_x25519_priv: &[u8],
        own_mlkem768_priv: Option<&[u8]>,
        own_mlkem768_pub: Option<&[u8]>,
    ) -> PyResult<(Self, [u8; 32])> {
        let _ = (welcome_bytes, own_mlkem768_priv);
        let _ = fixed_bytes::<32>("own_x25519_priv", own_x25519_priv)?;
        // HNDL discipline mirrors `create` / `advance_epoch`: a joiner
        // without ML-KEM-768 is out-of-spec for the 0x004D ciphersuite.
        if own_mlkem768_pub.is_none() {
            return Err(PyValueError::new_err(
                "peer joiner lacks ML-KEM-768 — required by ciphersuite 0x004D (HNDL discipline)",
            ));
        }
        Err(PyRuntimeError::new_err(
            "joiner-side Welcome processing is wired in Rust \
             (AvSession::new_joiner + process_welcome) but not yet exposed through this \
             raw-bytes FFI signature; the joiner's KeyPackage material is opaque openmls \
             provider state that cannot be rebuilt from raw KEX bytes. FFI redesign tracked \
             as a follow-up.",
        ))
    }
}

// ─── PyRelayNode (CIRISEdge#66 / L2-C) ──────────────────────────────

/// Map a `RelayError` to the appropriate `PyErr`. `StreamNotFound` /
/// `SubscriberNotFound` are caller-input issues (PyValueError);
/// `TransitKeyMissing` (internal invariant) + `OuterSealFailed`
/// (crypto operation failed) map to PyRuntimeError.
#[cfg(feature = "transport-reticulum")]
fn map_relay_err(e: &crate::transport::realtime_av_relay::RelayError) -> PyErr {
    use crate::transport::realtime_av_relay::RelayError;
    match e {
        RelayError::StreamNotFound(_) | RelayError::SubscriberNotFound { .. } => {
            PyValueError::new_err(format!("{e}"))
        }
        RelayError::TransitKeyMissing { .. } | RelayError::OuterSealFailed(_) => {
            PyRuntimeError::new_err(format!("{e}"))
        }
    }
}

/// SFU forwarding hop — addressable Reticulum destination + per-stream
/// subscriber roster + per-(subscriber, stream) transit keys + per-
/// subscriber layer-admission policy.
///
/// CIRIS-shaped wrapper around
/// `transport::realtime_av_relay::RelayNode`. The relay never holds
/// the epoch DEK — structurally: there is no field of type EpochDek on
/// RelayNode or anything reachable from it. The plaintext invariant is
/// enforced by construction (E2E inner-AEAD opens only at the
/// subscriber, which holds the DEK; the relay re-seals the outer AEAD
/// only).
///
/// **Conformance-only constructor**: `with_synthetic_node` builds an
/// in-process leviculum ReticulumNode + a synthetic DestinationHash so
/// the CIRISConformance harness can exercise the relay surface
/// without a configured Reticulum interface. Production callers wire
/// the relay into an existing leviculum node via the Rust-side
/// `RelayNode::new(node: Arc<ReticulumNode>, address: DestinationHash)`
/// constructor — that path is not exposed through PyO3 (the
/// ReticulumNode handle is a Rust-only type).
#[cfg(feature = "transport-reticulum")]
#[pyclass(name = "RelayNode", module = "ciris_edge")]
pub struct PyRelayNode {
    inner: crate::transport::realtime_av_relay::RelayNode,
}

#[cfg(feature = "transport-reticulum")]
#[pymethods]
impl PyRelayNode {
    /// Build a relay backed by an in-process synthetic ReticulumNode.
    /// **Conformance-only**: the resulting relay has an addressable
    /// destination but the node is not configured with any real
    /// transport interface — `forward`'s output is the
    /// `(subscriber_key_id, sealed_chunk_bytes)` pairs the caller is
    /// expected to dispatch via whatever Layer 2 wiring is appropriate
    /// (in the conformance harness, that's typically a synchronous
    /// hand-off back to a peer's open path).
    ///
    /// `address_hash_bytes` is the 16-byte
    /// [`DestinationHash`](reticulum_core::DestinationHash) value
    /// (CEG §5.6.8.8.1.1 TRUNCATED_HASHLENGTH). Pass any synthetic
    /// 16-byte value for harness-only use; production callers should
    /// derive this via [`rns_destination_hash`].
    #[staticmethod]
    #[pyo3(signature = (address_hash_bytes))]
    fn with_synthetic_node(address_hash_bytes: &[u8]) -> PyResult<Self> {
        use reticulum_core::{DestinationHash, Identity};
        use reticulum_std::driver::ReticulumNodeBuilder;
        let addr_bytes = fixed_bytes::<16>("address_hash_bytes", address_hash_bytes)?;
        // Synthetic 64-byte private key — deterministic, never
        // intended for real I/O. Matches the relay's own test
        // fixture pattern (`tests::test_node`).
        let mut priv_bytes = [0u8; 64];
        for (i, b) in priv_bytes.iter_mut().enumerate() {
            *b = u8::try_from(i)
                .expect("index < 64")
                .wrapping_mul(31)
                .wrapping_add(1);
        }
        let identity = Identity::from_private_key_bytes(&priv_bytes)
            .map_err(|e| PyRuntimeError::new_err(format!("synthetic identity: {e:?}")))?;
        // Per-call temp storage directory so concurrent harness runs
        // don't collide. The node is never driven for I/O — this is
        // a structural requirement of ReticulumNodeBuilder, not an
        // operational one.
        let storage =
            std::env::temp_dir().join(format!("ciris-edge-pyrelay-{}", uuid::Uuid::new_v4()));
        let node = ReticulumNodeBuilder::new()
            .identity(identity)
            .storage_path(storage)
            .build_sync()
            .map_err(|e| PyRuntimeError::new_err(format!("synthetic node build: {e:?}")))?;
        let address = DestinationHash::new(addr_bytes);
        Ok(Self {
            inner: crate::transport::realtime_av_relay::RelayNode::new(
                std::sync::Arc::new(node),
                address,
            ),
        })
    }

    /// Register a subscriber on a stream with their pre-established
    /// 32-byte transit key (from
    /// [`federation_session_initiate`] / [`federation_session_respond`])
    /// and per-subscriber layer-admission policy.
    ///
    /// Idempotent: re-subscribing replaces the previous state (old
    /// transit key zeroizes on drop). `layer_policy` is `(max_spatial,
    /// max_temporal, max_quality)`; pass `(255, 255, 255)` for
    /// uncapped (admits every layer).
    #[pyo3(signature = (stream_id, subscriber_key_id, transit_key, layer_policy))]
    fn subscribe(
        &mut self,
        stream_id: &[u8],
        subscriber_key_id: String,
        transit_key: &[u8],
        layer_policy: (u8, u8, u8),
    ) -> PyResult<()> {
        let stream_bytes = fixed_bytes::<32>("stream_id", stream_id)?;
        let stream = crate::transport::realtime_av::StreamId(stream_bytes);
        let tk = fixed_bytes::<32>("transit_key", transit_key)?;
        let policy = receiver_policy_from_tuple(layer_policy);
        self.inner
            .subscribe(stream, subscriber_key_id, tk, policy)
            .map_err(|e| map_relay_err(&e))
    }

    /// Remove a subscriber from a stream. Zeroizes the per-link
    /// transit key on drop. Returns `ValueError` if the subscriber
    /// wasn't registered on this stream.
    #[pyo3(signature = (stream_id, subscriber_key_id))]
    fn unsubscribe(&mut self, stream_id: &[u8], subscriber_key_id: &str) -> PyResult<()> {
        let stream_bytes = fixed_bytes::<32>("stream_id", stream_id)?;
        let stream = crate::transport::realtime_av::StreamId(stream_bytes);
        self.inner
            .unsubscribe(stream, &subscriber_key_id.to_string())
            .map_err(|e| map_relay_err(&e))
    }

    /// Update the layer-admission policy for an already-subscribed
    /// (subscriber, stream) pair without re-subscribing. Preserves the
    /// transit key + per-link `link_seq` counter — only the policy
    /// changes. `ValueError` if the subscriber isn't registered.
    #[pyo3(signature = (stream_id, subscriber_key_id, new_policy))]
    fn set_policy(
        &mut self,
        stream_id: &[u8],
        subscriber_key_id: &str,
        new_policy: (u8, u8, u8),
    ) -> PyResult<()> {
        let stream_bytes = fixed_bytes::<32>("stream_id", stream_id)?;
        let stream = crate::transport::realtime_av::StreamId(stream_bytes);
        let policy = receiver_policy_from_tuple(new_policy);
        self.inner
            .set_policy(stream, &subscriber_key_id.to_string(), policy)
            .map_err(|e| map_relay_err(&e))
    }

    /// Forward an inner-sealed chunk to every ADMITTED subscriber on
    /// its stream.
    ///
    /// The wrapper reconstructs the Rust `InnerSealed` from the
    /// caller-provided ciphertext + chunk header fields (via the
    /// `inner_sealed_from_parts` helper). The relay then applies
    /// `seal_av_outer` once per admitted subscriber using their
    /// transit key + monotonic `link_seq` counter.
    ///
    /// Returns `[(subscriber_key_id, sealed_chunk_wire_bytes), ...]`
    /// — one entry per admitted subscriber, ready for the caller's
    /// Layer 2 dispatch. Subscribers whose layer policy rejects the
    /// chunk's `layer` are silently dropped (no entry in the result,
    /// no `link_seq` advance).
    ///
    /// `codec_id` accepts any of the CODEC_* constants; `layer` is
    /// `(spatial, temporal, quality)`. The chunk header invariant
    /// from [`seal_av_chunk`] applies — `codec_id = CODEC_OPAQUE`
    /// MUST have `layer = (0, 0, 0)` per the module contract (the
    /// admission filter is a no-op in that case anyway).
    #[pyo3(signature = (stream_id, inner_ciphertext, codec_id, layer, epoch_u64, chunk_seq_u64))]
    fn forward(
        &mut self,
        stream_id: &[u8],
        inner_ciphertext: &[u8],
        codec_id: u8,
        layer: (u8, u8, u8),
        epoch_u64: u64,
        chunk_seq_u64: u64,
    ) -> PyResult<Vec<(String, Vec<u8>)>> {
        use crate::transport::realtime_av;
        let stream_bytes = fixed_bytes::<32>("stream_id", stream_id)?;
        let stream = realtime_av::StreamId(stream_bytes);
        let chunk_layer = chunk_layer_from_tuple(layer);
        let inner = realtime_av::inner_sealed_from_parts(
            stream,
            realtime_av::Epoch(epoch_u64),
            realtime_av::ChunkSeq(chunk_seq_u64),
            codec_id,
            chunk_layer,
            inner_ciphertext.to_vec(),
        );
        let out = self
            .inner
            .forward(stream, &inner)
            .map_err(|e| map_relay_err(&e))?;
        Ok(out
            .into_iter()
            .map(|f| (f.subscriber, f.sealed.to_bytes()))
            .collect())
    }
}

// ─── PyStoreAndForward (CIRISEdge#169 / L1-B) ───────────────────────
//
// §24 NAT-traversal store-and-forward queue. CIRISServer (a public
// fabric node) instantiates this and operates the queue on behalf of
// asleep/offline mobile edges; mobile peers drain it on wake. Ungated
// (no leviculum dependency) so the queue runs regardless of which
// transport features a given wheel ships.
//
// The queued bytes are the byte-exact signed CEG envelope. Admission-
// time hybrid-PQC verification is the operator's responsibility (run
// the envelope through `verify` before `queue`); this surface is the
// transport-tier queue, not the policy tier.
#[pyclass(name = "StoreAndForward", module = "ciris_edge")]
pub struct PyStoreAndForward {
    inner: crate::transport::store_and_forward::MemoryStoreAndForward,
}

#[pymethods]
impl PyStoreAndForward {
    /// Build an in-memory queue. All three caps are optional; omitted
    /// values take the #169 defaults (256 entries/destination, 64 MiB
    /// total, 7-day TTL).
    #[new]
    #[pyo3(signature = (max_queued_per_destination=None, max_total_bytes=None, ttl_seconds=None))]
    fn new(
        max_queued_per_destination: Option<u32>,
        max_total_bytes: Option<u64>,
        ttl_seconds: Option<u64>,
    ) -> Self {
        use crate::transport::store_and_forward::StoreAndForwardConfig;
        let d = StoreAndForwardConfig::default();
        let config = StoreAndForwardConfig {
            max_queued_per_destination: max_queued_per_destination
                .unwrap_or(d.max_queued_per_destination),
            max_total_bytes: max_total_bytes.unwrap_or(d.max_total_bytes),
            ttl_seconds: ttl_seconds.unwrap_or(d.ttl_seconds),
        };
        Self {
            inner: crate::transport::store_and_forward::MemoryStoreAndForward::new(config),
        }
    }

    /// Queue a byte-exact signed envelope for a currently-unreachable
    /// destination. Raises `ValueError` if the envelope is larger than
    /// the entire byte budget.
    #[pyo3(signature = (dest, envelope_bytes))]
    fn queue(&self, dest: &str, envelope_bytes: &[u8]) -> PyResult<()> {
        use crate::transport::store_and_forward::StoreAndForward as _;
        self.inner
            .queue(dest, envelope_bytes)
            .map_err(|e| PyValueError::new_err(format!("{e}")))
    }

    /// Drain up to `limit` queued envelopes for `dest`, oldest-first.
    /// Consumed entries are evicted. Returns the raw envelope bytes.
    #[pyo3(signature = (dest, limit))]
    fn drain<'py>(
        &self,
        py: Python<'py>,
        dest: &str,
        limit: u32,
    ) -> PyResult<Vec<Bound<'py, pyo3::types::PyBytes>>> {
        use crate::transport::store_and_forward::StoreAndForward as _;
        let drained = self
            .inner
            .drain(dest, limit)
            .map_err(|e| PyRuntimeError::new_err(format!("{e}")))?;
        Ok(drained
            .into_iter()
            .map(|d| pyo3::types::PyBytes::new(py, &d.envelope_bytes))
            .collect())
    }

    /// Operator surface — number of envelopes currently queued for
    /// `dest`.
    #[pyo3(signature = (dest))]
    fn pending_count(&self, dest: &str) -> u32 {
        use crate::transport::store_and_forward::StoreAndForward as _;
        self.inner.pending_count(dest)
    }
}

#[pymodule]
fn ciris_edge(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // v1.1.7 (CIRISEdge#58) — diagnostic harness, gated under the
    // `debug-tools` Cargo feature. Default release wheels (where the
    // feature is OFF) compile NONE of this: no panic hook install,
    // no `CIRIS_EDGE_PANIC_LOG` env var reading, no FFI surface.
    // Harness wheels built with `--features debug-tools` auto-install
    // the hook on import (if the env var is set) and register the
    // `panic_count` / `install_panic_logger` pyfunctions.
    #[cfg(feature = "debug-tools")]
    crate::debug::install_panic_logger();

    m.add("__version__", VERSION)?;
    m.add(
        "SUPPORTED_SCHEMA_VERSIONS",
        SUPPORTED_SCHEMA_VERSIONS.to_vec(),
    )?;

    #[cfg(feature = "debug-tools")]
    {
        m.add_function(wrap_pyfunction!(panic_count, m)?)?;
        m.add_function(wrap_pyfunction!(install_panic_logger, m)?)?;
    }

    // PyEdge — the cohabitation handle wrapping Arc<Edge>.
    m.add_class::<PyEdge>()?;

    // CIRISEdge#22 Tier 2 (v0.9.0) — CommunicationBus replacement
    // pyclasses. `DurableHandle` is returned by
    // `PyEdge::send_durable_inline_text`; `SubscriptionHandle` is
    // returned by `PyEdge::register_inline_text_handler`.
    m.add_class::<PyDurableHandle>()?;
    m.add_class::<PySubscriptionHandle>()?;

    // CIRISEdge#22 Tier 3 (v0.17.0) — verified-envelope AsyncIterator
    // pyclass returned by `PyEdge::subscribe_feed`. Gates Agent
    // 2.10.0's Epistemic Commons inbound UI panes.
    m.add_class::<PyVerifiedFeedSubscription>()?;

    // CIRISEdge#34 (v0.19.0) — per-category network-event AsyncIterator
    // pyclass returned by every `PyEdge::subscribe_*` pymethod.
    m.add_class::<PyNetworkEventSubscription>()?;

    // CIRISEdge#65 v1 (v1.6.3) — replication runtime handle. Returned
    // by `PyEdge::start_replication`; the operator holds it for the
    // lifetime of their peer set and calls `register_peer` / `stop`.
    m.add_class::<PyReplicationHandle>()?;

    // init_edge_runtime — the CIRISEdge#16 / CIRIS-3.0 cohabitation
    // constructor. Only registered when the Reticulum transport is
    // compiled in — that is the canonical wire for the cohabitation
    // pattern; an HTTP-only build would expose a different entry
    // point in a future revision.
    #[cfg(feature = "transport-reticulum")]
    m.add_function(wrap_pyfunction!(init_edge_runtime, m)?)?;

    // CIRISEdge#123 — cross-wheel conformance surface for
    // realtime_av + federation_session + RNS dest-hash. Lets
    // CIRISConformance / CIRISServer drive the substrate's HNDL-safe
    // crypto paths from Python without reimplementing them. The
    // realtime_av + federation_session wrappers are always available;
    // the RNS dest-hash wrapper requires the leviculum reticulum-core
    // dep that ships under `transport-reticulum`.
    m.add_function(wrap_pyfunction!(seal_av_chunk, m)?)?;
    m.add_function(wrap_pyfunction!(open_av_chunk, m)?)?;
    m.add_function(wrap_pyfunction!(seal_av_inner, m)?)?;
    m.add_function(wrap_pyfunction!(seal_av_outer, m)?)?;
    m.add_function(wrap_pyfunction!(federation_session_initiate, m)?)?;
    m.add_function(wrap_pyfunction!(federation_session_respond, m)?)?;
    #[cfg(feature = "transport-reticulum")]
    m.add_function(wrap_pyfunction!(rns_destination_hash, m)?)?;

    // ─── CIRISEdge v3.8.0 — Layer 3 conformance surface ─────────────
    //
    // Codec namespace constants (CIRISEdge#128) — re-exported so the
    // Python caller can build chunk headers without re-encoding the
    // discriminator. Mirrors `transport::realtime_av::CODEC_*`.
    m.add("CODEC_AV1_SVC", PY_CODEC_AV1_SVC)?;
    m.add("CODEC_JPEG_XS", PY_CODEC_JPEG_XS)?;
    m.add("CODEC_MDC", PY_CODEC_MDC)?;
    m.add("CODEC_OPAQUE", PY_CODEC_OPAQUE)?;
    // MLS ciphersuite code point (CIRISEdge#129) — used by
    // CIRISConformance to attest that the cohabiting wheel's MLS
    // layer is pinned to the post-quantum hybrid X-Wing ciphersuite.
    m.add("MLS_CIPHERSUITE_XWING_ID", PY_MLS_CIPHERSUITE_XWING_ID)?;

    // CIRISEdge#128 / L2-A — policy-only layered fan-out filter.
    // Reachability filtering is the caller's responsibility (see the
    // function docstring for the rationale — the in-Rust
    // ReachabilityTracker isn't Python-friendly cross-wheel).
    m.add_function(wrap_pyfunction!(plan_layered_by_policy, m)?)?;

    // CIRISEdge#129 / L2-B — MLS-backed group session pyclass.
    m.add_class::<PyAvSession>()?;

    // CIRISEdge#66 / L2-C — SFU relay pyclass. Gated on
    // `transport-reticulum` because RelayNode owns a leviculum
    // ReticulumNode handle and a DestinationHash (the synthetic
    // constructor needs both types).
    #[cfg(feature = "transport-reticulum")]
    m.add_class::<PyRelayNode>()?;

    // CIRISEdge#169 / L1-B — §24 store-and-forward queue. Ungated; a
    // public fabric node (CIRISServer) operates it for asleep mobile
    // edges.
    m.add_class::<PyStoreAndForward>()?;

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

    /// v2.1.0 (CIRISEdge#85 / CIRISLensCore#43) — the `engine()`
    /// pymethod signature is the cross-wheel cohabitation contract for
    /// the host engine handoff. If this stops type-checking, lens-core
    /// (and any future cohabiting cdylib) loses its path to the
    /// shared engine. Locks `fn(&PyEdge, Python<'_>) -> PyResult<Py<PyAny>>`.
    #[test]
    fn engine_pymethod_signature_is_stable() {
        fn _assert_signature(p: &PyEdge, py: Python<'_>) -> PyResult<Py<PyAny>> {
            p.engine(py)
        }
        let _ = _assert_signature as fn(&PyEdge, Python<'_>) -> PyResult<Py<PyAny>>;
    }

    /// v2.1.0 — the `transport_identity_pubkeys()` pymethod signature is
    /// the cohabitation contract for persist's `LocalIdentityAggregate`
    /// RET-transport role (needed for CIRISAgent 2.9.6). If this stops
    /// type-checking, persist's aggregate constructor loses the
    /// edge-sourced X25519 + Ed25519 transport pubkey path. Locks
    /// `fn(&PyEdge, Python<'py>) -> PyResult<Option<Bound<'py, PyDict>>>`.
    #[test]
    fn transport_identity_pubkeys_pymethod_signature_is_stable() {
        fn _assert_signature<'py>(
            p: &PyEdge,
            py: Python<'py>,
        ) -> PyResult<Option<Bound<'py, pyo3::types::PyDict>>> {
            p.transport_identity_pubkeys(py)
        }
        let _ = _assert_signature
            as for<'py> fn(
                &PyEdge,
                Python<'py>,
            ) -> PyResult<Option<Bound<'py, pyo3::types::PyDict>>>;
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
        let signer = Arc::new(LocalSigner::new(
            "test-edge-cohabitation",
            classical,
            Some(pqc),
        ));

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
        let py_edge = PyEdge::for_test(Arc::new(edge), tokio::runtime::Handle::current());
        let handle: Arc<Edge> = py_edge.edge_handle();
        assert!(Arc::strong_count(&handle) >= 2);
    }

    // ─── CIRISEdge v3.8.0 — Layer 3 conformance surface tests ───────
    //
    // Rust-side smoke gates for the L3 PyO3 wrappers. These exercise
    // the bytes-in / bytes-out round-trip locally without standing up
    // an embedded Python interpreter for read-only constant checks; a
    // shared `init_python()` helper warms up the interpreter for the
    // wrappers that construct PyErrs (PyValueError / PyRuntimeError
    // need an initialized interpreter to allocate the exception
    // type). The full Python-driven coverage runs in CIRISConformance
    // after the v3.8.0 wheel publishes.
    fn l3_init_python() {
        use std::sync::OnceLock;
        static L3_INIT: OnceLock<()> = OnceLock::new();
        L3_INIT.get_or_init(Python::initialize);
    }

    /// L3 codec constants match their Rust-side counterparts. Locks
    /// the cross-wheel wire contract: if `transport::realtime_av`
    /// changes a discriminator, the Python-surface constant must
    /// follow in lockstep.
    #[test]
    fn pyo3_codec_constants_match_rust_side() {
        use crate::transport::realtime_av;
        assert_eq!(PY_CODEC_AV1_SVC, realtime_av::CODEC_AV1_SVC);
        assert_eq!(PY_CODEC_JPEG_XS, realtime_av::CODEC_JPEG_XS);
        assert_eq!(PY_CODEC_MDC, realtime_av::CODEC_MDC);
        assert_eq!(PY_CODEC_OPAQUE, realtime_av::CODEC_OPAQUE);
    }

    /// L3 MLS ciphersuite constant matches `MlsSession::ciphersuite_id()`.
    /// The conformance attestation expects 0x004D (X-Wing).
    #[test]
    fn pyo3_mls_ciphersuite_constant_pins_xwing() {
        use crate::transport::realtime_av_mls::MlsSession;
        assert_eq!(PY_MLS_CIPHERSUITE_XWING_ID, 0x004D);
        assert_eq!(PY_MLS_CIPHERSUITE_XWING_ID, MlsSession::ciphersuite_id());
    }

    /// `plan_layered_by_policy` filters by per-receiver policy only —
    /// the BLINKING_DOT policy admits `(0,0,0)` chunks and rejects
    /// everything above; UNCAPPED admits every layer.
    #[test]
    fn pyo3_plan_layered_by_policy_filters_by_admission() {
        let participants = vec![
            ("uncapped".to_string(), (255, 255, 255)),
            ("blinking_dot".to_string(), (0, 0, 0)),
            ("spatial_capped".to_string(), (1, 255, 255)),
        ];
        // Base layer (0,0,0) — admitted by all three.
        let base = plan_layered_by_policy(participants.clone(), (0, 0, 0));
        assert_eq!(base.len(), 3);
        // Layer (1,0,0) — admitted by uncapped + spatial_capped; rejected by blinking_dot.
        let enhancement = plan_layered_by_policy(participants.clone(), (1, 0, 0));
        assert!(enhancement.contains(&"uncapped".to_string()));
        assert!(enhancement.contains(&"spatial_capped".to_string()));
        assert!(!enhancement.contains(&"blinking_dot".to_string()));
        // Layer (2,0,0) — only uncapped admits.
        let high = plan_layered_by_policy(participants, (2, 0, 0));
        assert_eq!(high, vec!["uncapped".to_string()]);
    }

    /// HNDL pre-check fires at `PyAvSession::create` for any member
    /// with `mlkem768_pub = None`. The 0x004D ciphersuite requires
    /// ML-KEM-768 by spec; this preserves the AvSession structural
    /// invariant on the Python surface.
    #[test]
    fn pyo3_av_session_create_rejects_classical_only_member() {
        l3_init_python();
        let stream = [7u8; 32];
        let initial = vec![(
            "classical-only-peer".to_string(),
            vec![1u8; 32],
            None, // <- HNDL violation
        )];
        let Err(err) = PyAvSession::create(&stream, "creator", initial) else {
            panic!("classical-only member should be rejected");
        };
        let s = format!("{err}");
        assert!(
            s.contains("ML-KEM-768"),
            "expected HNDL diagnostic, got: {s}"
        );
    }

    /// `PyAvSession::create` round-trips with hybrid members and
    /// returns a non-zero 32-byte EpochDek (the MLS first-epoch
    /// exporter secret).
    #[test]
    fn pyo3_av_session_create_round_trips_with_hybrid_members() {
        l3_init_python();
        let stream = [0xABu8; 32];
        let initial = vec![(
            "bob".to_string(),
            vec![1u8; 32],
            Some(vec![0xABu8; 1184]), // ML-KEM-768 pubkey size
        )];
        let (session, dek) = PyAvSession::create(&stream, "alice", initial)
            .unwrap_or_else(|e| panic!("create should succeed: {e}"));
        assert_eq!(dek.len(), 32);
        assert_ne!(dek, [0u8; 32], "EpochDek must be non-zero");
        assert_eq!(session.epoch(), 1, "2-member group → 1 commit → epoch 1");
        assert_eq!(session.roster_size(), 2);
        assert_eq!(session.stream_id(), stream);
    }

    /// `PyAvSession::create` with a malformed stream_id (wrong length)
    /// rejects with `PyValueError` at conversion.
    #[test]
    fn pyo3_av_session_create_rejects_wrong_stream_id_length() {
        l3_init_python();
        let short_stream = [0u8; 16]; // wrong length
        let Err(err) = PyAvSession::create(&short_stream, "alice", vec![]) else {
            panic!("short stream_id should be rejected");
        };
        let s = format!("{err}");
        assert!(s.contains("stream_id"), "expected length error, got: {s}");
    }

    /// `PyAvSession::process_welcome` returns a `RuntimeError`: the
    /// Rust joiner path is wired (CIRISEdge#155 Gap 2) but the opaque
    /// `JoinerKeyMaterial` it needs can't be rebuilt from this
    /// signature's raw KEX bytes, so the FFI surface defers. Conformance
    /// harnesses exercise the joiner round-trip through the Rust unit
    /// tests until the FFI redesign lands.
    #[test]
    fn pyo3_av_session_process_welcome_surfaces_unwired_error() {
        l3_init_python();
        let own_x = [2u8; 32];
        let own_mlkem_priv = vec![0xCD; 2400];
        let own_mlkem_pub = vec![0xAB; 1184];
        let result = PyAvSession::process_welcome(
            b"synthetic-welcome-bytes",
            &own_x,
            Some(&own_mlkem_priv),
            Some(&own_mlkem_pub),
        );
        let Err(err) = result else {
            panic!("L3 wiring gap should surface — got Ok");
        };
        let s = format!("{err}");
        assert!(
            s.contains("L3") || s.contains("federation_directory") || s.contains("KeyPackage"),
            "expected JoinerSurfaceUnwired diagnostic, got: {s}"
        );
    }

    /// `PyRelayNode::with_synthetic_node` builds a relay handle and
    /// subscribe/unsubscribe cycle through the wrapper without
    /// panicking. Smoke-tests the bytes-in conversion shapes.
    #[test]
    fn pyo3_relay_synthetic_node_subscribe_unsubscribe() {
        l3_init_python();
        let addr = [0x42u8; 16];
        let mut relay =
            PyRelayNode::with_synthetic_node(&addr).expect("synthetic node should build");
        let stream = [0xA1u8; 32];
        let transit = [0x55u8; 32];
        relay
            .subscribe(
                &stream,
                "subscriber-1".to_string(),
                &transit,
                (255, 255, 255),
            )
            .expect("subscribe");
        relay
            .unsubscribe(&stream, "subscriber-1")
            .expect("unsubscribe");
        // Re-unsubscribe rejects with PyValueError per the wrapper
        // contract (caller-input error, not a runtime fault).
        let err = relay
            .unsubscribe(&stream, "subscriber-1")
            .expect_err("re-unsubscribe should reject");
        let s = format!("{err}");
        assert!(
            s.contains("not subscribed"),
            "expected diagnostic, got: {s}"
        );
    }

    /// `PyRelayNode::forward` produces one sealed wire bytes per
    /// admitted subscriber. Verifies the bytes-in / bytes-out shape:
    /// `inner_ciphertext` flows through the wrapper, the relay applies
    /// the outer AEAD, and the result decodes as a valid
    /// `SealedAvChunk` (round-trip via `SealedAvChunk::from_bytes`).
    #[test]
    fn pyo3_relay_forward_produces_decodable_wire_bytes() {
        use crate::transport::realtime_av::{
            seal_av_inner, ChunkLayer, ChunkSeq, Epoch, EpochDek, SealedAvChunk, StreamId,
            CODEC_OPAQUE,
        };
        l3_init_python();
        let addr = [0x42u8; 16];
        let mut relay = PyRelayNode::with_synthetic_node(&addr).expect("synthetic node");
        let stream_bytes = [0xA1u8; 32];
        let transit = [0x55u8; 32];
        relay
            .subscribe(
                &stream_bytes,
                "subscriber-1".to_string(),
                &transit,
                (255, 255, 255),
            )
            .expect("subscribe");

        // Build an inner-sealed chunk via the Rust API; pull its
        // ciphertext bytes out and feed them through the Python
        // `forward` shape.
        let dek = EpochDek::from_bytes([0x77u8; 32]);
        let inner = seal_av_inner(
            b"plaintext frame",
            &dek,
            StreamId(stream_bytes),
            Epoch(1),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal");
        let inner_ct = inner.inner_ciphertext().to_vec();

        let out = relay
            .forward(&stream_bytes, &inner_ct, CODEC_OPAQUE, (0, 0, 0), 1, 0)
            .expect("forward");
        assert_eq!(out.len(), 1, "1 subscriber → 1 forward output");
        assert_eq!(out[0].0, "subscriber-1");
        // The bytes are a valid SealedAvChunk wire encoding.
        let decoded = SealedAvChunk::from_bytes(&out[0].1).expect("wire round-trip");
        assert_eq!(decoded.codec_id, CODEC_OPAQUE);
        assert_eq!(decoded.layer, ChunkLayer::BASE);
    }
}

// ─── CIRISEdge#22 Tier 2 (v0.9.0) — PyO3 integration tests ──────────
//
// These tests exercise the `send_inline_text` / `send_durable_inline_text`
// / `register_inline_text_handler` / `DurableHandle` / `SubscriptionHandle`
// pymethods end-to-end through an embedded Python interpreter. They
// require `cargo test --features "transport-http transport-reticulum pyo3"`
// (NOT `extension-module` — that's wheels-only; libpython must link
// against the test binary).
//
// Lifecycle invariant: `Python::initialize()` (pyo3 0.28 equivalent of
// `prepare_freethreaded_python`) MUST be called exactly once per
// process before any `Python::attach` call. We guard it behind a
// `OnceLock` so multiple test functions can each call `init_python()`
// without crashing the interpreter.

#[cfg(test)]
#[cfg(all(feature = "transport-http", feature = "transport-reticulum"))]
mod pyo3_tier2_tests {
    //! Tier 2 pyo3 surface tests — CIRISEdge#22, v0.9.0.
    //!
    //! Each test composes:
    //! 1. An in-memory persist sqlite backend (directory + outbound
    //!    queue).
    //! 2. A software-tier `LocalSigner` (AV-17 heap-scan property
    //!    irrelevant — software signers ARE the dev-tier descriptor).
    //! 3. A `NoopTransport` stand-in for Reticulum (no socket bind).
    //! 4. A `PyEdge::for_test` wrapping the assembled `Edge` + the
    //!    current tokio runtime handle.
    //!
    //! The Python interpreter is initialized exactly once per process
    //! via `init_python()`; each test runs `Python::attach` to acquire
    //! the GIL and exercises the pymethods through Python-level calls.
    use super::*;
    use crate::transport::{InboundFrame, TransportId, TransportSendOutcome};

    use std::sync::OnceLock;
    use std::time::Duration;

    /// Initialize the embedded Python interpreter exactly once. Safe
    /// to call from every test; pyo3 0.28's `initialize()` is itself
    /// idempotent but the `OnceLock` makes the test-suite-wide
    /// initialization point explicit.
    fn init_python() {
        static INIT: OnceLock<()> = OnceLock::new();
        INIT.get_or_init(Python::initialize);
    }

    /// v0.10.1 — global serialization lock for tests that construct or
    /// inspect persist's `ENGINE_SINGLETON`. Cargo's default
    /// `--test-threads` is the host CPU count; without this lock, two
    /// tests concurrently calling `ciris_persist.Engine(...)` deadlock
    /// at the persist slot mutex × GIL × tokio-runtime-build interaction
    /// (`PyEngine::new` builds a fresh `Runtime` inside `py.detach`;
    /// concurrent tests racing for the GIL block each other's GIL
    /// release inside `Runtime::new`'s thread spawns).
    ///
    /// Every test below that constructs `Engine(...)` MUST acquire
    /// this lock for the duration of the engine-bearing critical
    /// section. Tests that use stub fixtures only (no real engine)
    /// don't need it.
    fn engine_lock() -> std::sync::MutexGuard<'static, ()> {
        static ENGINE_TEST_LOCK: OnceLock<std::sync::Mutex<()>> = OnceLock::new();
        ENGINE_TEST_LOCK
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Stub transport — accepts every outbound `send`, never listens.
    /// Used by every Tier 2 test; Reticulum would bind a real socket.
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

    /// Compose an `Edge` from in-memory persist primitives + a noop
    /// transport + a software-tier signer loaded from a temp-dir seed.
    /// Returns the outbound-queue `Arc<dyn OutboundHandle>` separately
    /// so tests that want to seed a delivered row can do so directly
    /// against the same backend (the durable-await-ack happy-path
    /// test does this).
    ///
    /// The temp dir is leaked (held in a `'static` via `Box::leak`) so
    /// the seed file outlives the test scope — these tests are
    /// short-lived; not worth threading a `TempDir` handle through.
    ///
    /// Directory + outbound queue share the same `SqliteBackend` so the
    /// outbound-queue FK to `federation_keys` resolves (V007 schema).
    /// A scrub-signed self-row for the signer's key_id is inserted so
    /// durable enqueues pass the FK check.
    async fn build_test_edge() -> (Arc<Edge>, Arc<dyn OutboundHandle>) {
        use base64::engine::general_purpose::STANDARD as B64;
        use base64::Engine as _;
        use ciris_crypto::{ClassicalSigner, Ed25519Signer};
        use ciris_persist::federation::FederationDirectory;
        use ciris_persist::prelude::{FederationDirectorySqlite, KeyRecord, SignedKeyRecord};
        use sha2::{Digest, Sha256};

        // Deterministic seed → signer pair. The temp dir is leaked
        // (Box::leak) so the seed file outlives the test scope.
        let tmp: &'static tempfile::TempDir = Box::leak(Box::new(
            tempfile::tempdir().expect("create tempdir for test seed"),
        ));
        let seed_path = tmp.path().join("ed25519.seed");
        let seed: [u8; 32] = [0x77; 32];
        std::fs::write(&seed_path, seed).expect("write seed");
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: "py-tier2-edge".into(),
            key_path: seed_path,
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load_local_seed");

        // Shared persist backend — directory + outbound queue + (test-
        // scope) inserts share one SqliteBackend connection, mirroring
        // the federation_announcement test's pattern. This is what
        // makes the outbound-queue FK to federation_keys resolve.
        let backend = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open federation directory sqlite");

        // Insert scrub-signed federation_keys rows for both the
        // sender's `key_id` AND the test recipient's `key_id`. The
        // edge_outbound_queue table FKs to federation_keys on BOTH
        // `sender_key_id` and `destination_key_id` (V007 schema), so
        // a durable enqueue rejects with `FOREIGN KEY constraint
        // failed` if either is missing.
        let ts = chrono::DateTime::parse_from_rfc3339("2026-05-01T00:00:00Z")
            .expect("ts")
            .with_timezone(&chrono::Utc);
        for (key_id, key_seed) in [
            ("py-tier2-edge", [0x77u8; 32]),
            ("recipient-key", [0x99u8; 32]),
        ] {
            let pubkey_b64 = B64.encode(
                Ed25519Signer::from_seed(&key_seed)
                    .expect("ed25519 from seed")
                    .public_key()
                    .expect("pubkey"),
            );
            let envelope = serde_json::json!({ "key_id": key_id });
            let canonical = serde_json::to_vec(&envelope).expect("serialize envelope");
            let digest = Sha256::digest(&canonical);
            // Self-sign each row — the scrub_signature gate is per-row;
            // for the durable enqueue we only need the FK to resolve.
            let sig = Ed25519Signer::from_seed(&key_seed)
                .expect("ed25519 from seed")
                .sign(digest.as_slice())
                .expect("scrub-sign");
            let record = KeyRecord {
                key_id: key_id.to_string(),
                pubkey_ed25519_base64: pubkey_b64,
                pubkey_ml_dsa_65_base64: None,
                algorithm: "hybrid".to_string(),
                identity_type: "steward".to_string(),
                identity_ref: key_id.to_string(),
                valid_from: ts,
                valid_until: None,
                registration_envelope: envelope,
                original_content_hash: hex::encode(digest),
                scrub_signature_classical: B64.encode(sig),
                scrub_signature_pqc: None,
                scrub_key_id: key_id.to_string(),
                scrub_timestamp: ts,
                pqc_completed_at: None,
                persist_row_hash: String::new(),
                roles: Vec::new(),
                // v2.5.0 (CIRISPersist#102 Ask 8) — non-accord-holder
                // rows carry None. Steward identity_type is not
                // accord-holder so the V048 CHECK admits None.
                attestation_evidence: None,
            };
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("put_public_key");
        }

        let queue: Arc<dyn OutboundHandle> = backend.clone();
        let signer = Arc::new(LocalSigner::new("py-tier2-edge", classical, None));
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let edge = Edge::builder()
            .directory(backend.clone() as Arc<dyn VerifyDirectory>)
            .queue(queue.clone())
            .signer(signer)
            .transport(transport)
            .build()
            .expect("Edge::build");
        (Arc::new(edge), queue)
    }

    /// `PyEdge::send_inline_text` returns a 64-char lowercase hex
    /// string — the `body_sha256` of the post-pipeline-scrub envelope
    /// body (the ACK match key into persist's `body_sha256_prefix`
    /// index). The agent's `EdgeCommunicationAdapter` joins on this.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_send_inline_text_returns_body_sha256() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge, tokio::runtime::Handle::current());
        let sha = Python::attach(|py| -> PyResult<String> {
            py_edge.send_inline_text(py, "recipient-key", "hello")
        })
        .expect("send_inline_text");
        assert_eq!(
            sha.len(),
            64,
            "body_sha256 hex must be 64 chars, got {}: {sha:?}",
            sha.len()
        );
        assert!(
            sha.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "body_sha256 must be lowercase hex"
        );
    }

    /// `PyEdge::send_durable_inline_text` returns a `DurableHandle`
    /// whose `body_sha256()` matches what an equivalent
    /// `send_inline_text` call would produce (both run the same
    /// pipeline + envelope-build path; the hex must agree).
    #[tokio::test(flavor = "multi_thread")]
    async fn py_send_durable_inline_text_returns_durable_handle() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge, tokio::runtime::Handle::current());
        // Both calls use the same `text`; the body_sha256 depends only
        // on the (post-pipeline) text bytes + envelope structure (the
        // sender's `key_id` is constant), so the two SHAs must agree.
        // EXCEPT the envelope `nonce` and `sent_at` differ between
        // envelopes — those vary the canonical-bytes but NOT the
        // body_sha256 (which is taken of `envelope.body` only, not
        // of the whole envelope). So the two SHAs MUST be equal.
        let durable_sha = Python::attach(|py| -> PyResult<String> {
            let h = py_edge.send_durable_inline_text(py, "recipient-key", "hello")?;
            Ok(h.body_sha256().to_string())
        })
        .expect("send_durable_inline_text");
        assert_eq!(durable_sha.len(), 64, "body_sha256 hex must be 64 chars");
        // Also verify the ephemeral path's SHA agrees (per the
        // pipeline-idempotence property — both paths produce the
        // same canonical body bytes).
        let ephemeral_sha = Python::attach(|py| -> PyResult<String> {
            py_edge.send_inline_text(py, "recipient-key", "hello")
        })
        .expect("send_inline_text");
        assert_eq!(
            durable_sha, ephemeral_sha,
            "durable + ephemeral body_sha256 must agree for the same text"
        );
    }

    /// `DurableHandle::await_ack` returns `False` when no ACK lands
    /// within `timeout_ms`. Polls at 50ms; a 100ms timeout sees at
    /// most 2-3 polls and exits cleanly.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_durable_handle_await_ack_times_out() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge, tokio::runtime::Handle::current());
        let (acked, elapsed) = Python::attach(|py| -> PyResult<(bool, Duration)> {
            let h = py_edge.send_durable_inline_text(py, "recipient-key", "no-ack-coming")?;
            let start = std::time::Instant::now();
            let result = h.await_ack(py, 100)?;
            Ok((result, start.elapsed()))
        })
        .expect("await_ack");
        assert!(
            !acked,
            "await_ack must return False when no ACK arrives within timeout"
        );
        assert!(
            elapsed >= Duration::from_millis(100),
            "await_ack must wait at least timeout_ms (waited {elapsed:?})"
        );
    }

    /// `DurableHandle::await_ack` returns `True` when the underlying
    /// outbound row reaches ACK'd-delivered terminal state. We seed
    /// the row directly via persist's `mark_transport_delivered` so
    /// the test doesn't depend on a real ACK envelope shape; the
    /// post-condition tested here is "the polling loop sees
    /// `DurableStatus::Terminal(DurableOutcome::Delivered)` and
    /// returns True".
    #[tokio::test(flavor = "multi_thread")]
    async fn py_durable_handle_await_ack_succeeds_when_acked() {
        init_python();
        let (edge, queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge, tokio::runtime::Handle::current());

        // Send a durable inline-text + extract the queue_id. Run inside
        // attach so we hold the GIL only as long as the pymethod call
        // needs it.
        let queue_id = Python::attach(|py| -> PyResult<String> {
            let h = py_edge.send_durable_inline_text(py, "recipient-key", "ack-coming")?;
            Ok(h.queue_id().to_string())
        })
        .expect("send_durable_inline_text");

        // Drive the row to Delivered terminal state. Persist enforces
        // the state machine; `InlineTextDurable` declares
        // `requires_ack=true`, so the full path is:
        //   pending → claim → sending → mark_transport_delivered
        //           → awaiting_ack → mark_ack_received → delivered
        let claimed = queue
            .claim_pending_outbound(10, 30, "test-claim")
            .await
            .expect("claim_pending_outbound");
        assert!(
            claimed.iter().any(|r| r.queue_id == queue_id),
            "newly-enqueued row must be claimable as pending"
        );
        queue
            .mark_transport_delivered(&queue_id, "noop")
            .await
            .expect("mark_transport_delivered");
        // Synthetic ACK envelope bytes — `mark_ack_received` doesn't
        // re-verify the bytes; it just stamps them on the row. Persist
        // requires NON-EMPTY bytes. The body is just bookkeeping for
        // this test; the real ACK matching path is the inbound
        // verify pipeline's `match_ack_to_outbound`.
        queue
            .mark_ack_received(&queue_id, br#"{"synthetic":"ack"}"#)
            .await
            .expect("mark_ack_received");

        // Now await_ack should observe the terminal state on the next
        // poll (well inside 5000ms).
        let acked = Python::attach(|py| -> PyResult<bool> {
            // Re-call send_durable_inline_text to get a fresh handle
            // for THE SAME queue_id? No — we need the same handle. We
            // can't get one back from queue_id directly; but we can
            // build a synthetic `PyDurableHandle` for the test.
            // Take the runtime + queue from the py_edge directly.
            let edge_arc = py_edge.edge_handle();
            let test_rt = std::sync::Arc::new(
                tokio::runtime::Builder::new_multi_thread()
                    .enable_all()
                    .worker_threads(1)
                    .build()
                    .expect("test handle runtime"),
            );
            let handle = PyDurableHandle {
                queue_id: queue_id.clone(),
                body_sha256_hex: "0".repeat(64),
                executor: Arc::new(
                    ciris_persist::ffi::executor_capsule::build_persist_executor(test_rt),
                ),
                queue: edge_arc.outbound_queue_handle(),
            };
            handle.await_ack(py, 5000)
        })
        .expect("await_ack");
        assert!(
            acked,
            "await_ack must return True once the row is Delivered"
        );
    }

    /// Register a Python callback, inject an inbound inline-text via
    /// the test fan-out helper, verify the callback observes
    /// `(sender_key_id, body_text)`. Pass criterion: a
    /// `threading.Event` set inside the callback flips within 1 second.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_register_inline_text_handler_fires_on_inbound() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge.clone(), tokio::runtime::Handle::current());

        // Set up the Python side: a threading.Event + a callback that
        // records the args + sets the event.
        //
        // Pass `evt` and `observed` as DEFAULT ARGUMENTS on the
        // callback signature so the def captures them by value — a
        // bare `def` in an exec context uses module-globals for
        // free-variable lookup, and our globals dict doesn't carry
        // `evt` / `observed`. Default args bind at def-time, no
        // closure capture needed.
        let (sub, evt, observed_holder) =
            Python::attach(|py| -> PyResult<(PySubscriptionHandle, Py<PyAny>, Py<PyAny>)> {
                let threading = py.import("threading")?;
                let evt = threading.call_method0("Event")?.unbind();
                let observed: Py<PyAny> = py.eval(c"[]", None, None)?.unbind();
                let locals = pyo3::types::PyDict::new(py);
                locals.set_item("evt", evt.clone_ref(py))?;
                locals.set_item("observed", observed.clone_ref(py))?;
                py.run(
                    c"def _cb(sender_key_id, body_text, _evt=evt, _obs=observed):\n    _obs.append((sender_key_id, body_text))\n    _evt.set()\n",
                    Some(&locals),
                    Some(&locals),
                )?;
                let cb: Py<PyAny> = locals.get_item("_cb")?.expect("cb defined").unbind();
                let sub = py_edge.register_inline_text_handler(cb)?;
                Ok((sub, evt, observed))
            })
            .expect("register callback");

        // Inject an inbound directly via the test fan-out helper
        // (bypasses verify; the post-verify dispatch path uses the
        // same `fan_out_inline_text` function under the hood).
        edge.fan_out_inline_text_for_test("agent-bob", "hello from bob");

        // Wait up to 1 second for the event. CRITICAL: release the
        // GIL during the wait — the drainer thread invokes the Python
        // callback under `Python::attach`, so holding the GIL here
        // would starve it. `py.detach` releases the GIL for the
        // duration of the inner closure; the drainer acquires + runs
        // the callback + sets the event; we re-acquire on return.
        let fired = Python::attach(|py| -> PyResult<bool> {
            py.detach(|| {
                // Acquire GIL briefly to call .wait, then release it
                // by exiting the inner attach. Tricky! Instead, since
                // we're already inside attach, do the wait via
                // `evt.call_method1` but use `wait` which Python
                // implements as a C-level blocking call that RELEASES
                // the GIL internally (threading.Event.wait drops GIL).
                Ok::<(), pyo3::PyErr>(())
            })
            .ok();
            // Threading.Event.wait is a GIL-releasing call inside
            // CPython — but pyo3's wrapper holds the GIL across the
            // call frame. To actually release the GIL we have to use
            // detach. Workaround: poll evt.is_set() with detach-yields.
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
            loop {
                let is_set: bool = evt.call_method0(py, "is_set")?.extract(py)?;
                if is_set {
                    return Ok(true);
                }
                if std::time::Instant::now() >= deadline {
                    return Ok(false);
                }
                py.detach(|| {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                });
            }
        })
        .expect("wait on event");
        assert!(fired, "callback must fire within 1 second");

        // Inspect the captured args.
        Python::attach(|py| {
            let observed_bound = observed_holder.bind(py);
            let entry = observed_bound.get_item(0).expect("first observed");
            let (sender, body): (String, String) = entry.extract().expect("extract (sender, body)");
            assert_eq!(sender, "agent-bob");
            assert_eq!(body, "hello from bob");
        });

        // Cleanly tear down to avoid leaking the drainer into other
        // tests' libpython state.
        Python::attach(|py| {
            sub.unsubscribe(py).expect("unsubscribe");
        });
    }

    /// `SubscriptionHandle::unsubscribe()` stops subsequent inbounds
    /// from invoking the callback. Pre-condition: one inbound fires
    /// (count=1); post-unsubscribe: another inbound does NOT increment
    /// the count.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_subscription_handle_unsubscribe_stops_callbacks() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge.clone(), tokio::runtime::Handle::current());

        // Callback that increments a Python list's int via append. We
        // use a list-as-counter pattern so the callback can mutate
        // shared state without closure capture (Python's `nonlocal`
        // doesn't compose with PyO3's exec well). The counter is
        // bound as a default arg on the def so it captures at
        // def-time (a free-variable `counter` would look in
        // module-globals at call time and miss).
        let (sub, counter) = Python::attach(|py| -> PyResult<(PySubscriptionHandle, Py<PyAny>)> {
            let counter: Py<PyAny> = py.eval(c"[0]", None, None)?.unbind();
            let locals = pyo3::types::PyDict::new(py);
            locals.set_item("counter", counter.clone_ref(py))?;
            py.run(
                c"def _cb(s, t, _c=counter):\n    _c[0] += 1\n",
                Some(&locals),
                Some(&locals),
            )?;
            let cb: Py<PyAny> = locals.get_item("_cb")?.expect("cb").unbind();
            let sub = py_edge.register_inline_text_handler(cb)?;
            Ok((sub, counter))
        })
        .expect("register");

        edge.fan_out_inline_text_for_test("sender-a", "msg-1");

        // Wait for the first call to land. The drainer thread is
        // asynchronous; poll the counter.
        let mut waited = Duration::ZERO;
        let step = Duration::from_millis(20);
        while waited < Duration::from_secs(1) {
            let n: i64 = Python::attach(|py| {
                let bound = counter.bind(py);
                bound.get_item(0).unwrap().extract().unwrap()
            });
            if n >= 1 {
                break;
            }
            tokio::time::sleep(step).await;
            waited += step;
        }
        let n_before: i64 =
            Python::attach(|py| counter.bind(py).get_item(0).unwrap().extract().unwrap());
        assert_eq!(n_before, 1, "first inbound must fire the callback");

        // Unsubscribe and verify the registry actually drops the entry.
        Python::attach(|py| sub.unsubscribe(py).unwrap());
        assert_eq!(
            edge.inline_text_subscriber_count(),
            0,
            "unsubscribe() must remove the registry entry"
        );

        // Fire another inbound — must NOT increment the counter.
        edge.fan_out_inline_text_for_test("sender-a", "msg-2");
        // Give the (now-defunct) drainer time to NOT process the
        // message — 200ms is well past any plausible scheduling delay.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let n_after: i64 =
            Python::attach(|py| counter.bind(py).get_item(0).unwrap().extract().unwrap());
        assert_eq!(
            n_after, 1,
            "post-unsubscribe inbound must NOT fire the callback"
        );
    }

    /// Context-manager exit unsubscribes — `with edge.register_inline_text_handler(cb) as sub:`
    /// + statements outside the block must NOT fire the callback.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_subscription_handle_context_manager_unsubscribes_on_exit() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        let py_edge = PyEdge::for_test(edge.clone(), tokio::runtime::Handle::current());

        // Build a counter + callback that increments it. Same
        // default-arg pattern as the other lifecycle tests — captures
        // `counter` at def-time, not via module-globals.
        let (sub, counter) = Python::attach(|py| -> PyResult<(PySubscriptionHandle, Py<PyAny>)> {
            let counter: Py<PyAny> = py.eval(c"[0]", None, None)?.unbind();
            let locals = pyo3::types::PyDict::new(py);
            locals.set_item("counter", counter.clone_ref(py))?;
            py.run(
                c"def _cb(s, t, _c=counter):\n    _c[0] += 1\n",
                Some(&locals),
                Some(&locals),
            )?;
            let cb: Py<PyAny> = locals.get_item("_cb")?.expect("cb").unbind();
            let sub = py_edge.register_inline_text_handler(cb)?;
            Ok((sub, counter))
        })
        .expect("register");

        // Inside the "with" block — fire an inbound, expect counter=1.
        edge.fan_out_inline_text_for_test("ctx-mgr", "inside");
        let mut waited = Duration::ZERO;
        while waited < Duration::from_secs(1) {
            let n: i64 =
                Python::attach(|py| counter.bind(py).get_item(0).unwrap().extract().unwrap());
            if n >= 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
            waited += Duration::from_millis(20);
        }

        // Now exit the "with" — call `__exit__` directly.
        Python::attach(|py| -> PyResult<bool> {
            let none = py.None();
            sub.__exit__(py, none.clone_ref(py), none.clone_ref(py), none)
        })
        .expect("__exit__");

        assert_eq!(
            edge.inline_text_subscriber_count(),
            0,
            "context-manager __exit__ must remove the registry entry"
        );

        // Fire another inbound — must NOT fire the callback.
        edge.fan_out_inline_text_for_test("ctx-mgr", "outside");
        tokio::time::sleep(Duration::from_millis(200)).await;
        let n_final: i64 =
            Python::attach(|py| counter.bind(py).get_item(0).unwrap().extract().unwrap());
        assert_eq!(
            n_final, 1,
            "post-__exit__ inbound must NOT fire the callback"
        );
    }

    /// The `send_inline_text` pipeline-invariant — when a `speak_pipeline`
    /// is configured, the Python-supplied text is scrubbed BEFORE the
    /// envelope is signed. We configure a trivial pipeline that
    /// uppercases the text (proxy for "the pipeline ran"); the
    /// post-call `body_sha256` must match the SHA of an envelope built
    /// from the UPPERCASED text, not the input text.
    ///
    /// This pins the load-bearing forensic-completeness invariant
    /// (FSD §1.4 — Classify + Scrub + EncryptAndStore must run before
    /// signing).
    /// Custom uppercase-everything stage used by [`py_inline_text_pipeline_scrub_runs`].
    /// Stand-in for the real ScrubAndEncrypt stage — we only need to
    /// observe "the stage ran" via a deterministic text transformation.
    /// Module-level (not inline in the test) to satisfy clippy's
    /// items-after-statements lint.
    struct UppercaseStage;

    impl ciris_persist::pipeline::Stage<ciris_persist::prelude::InlineTextEnvelope> for UppercaseStage {
        fn name(&self) -> &'static str {
            "uppercase_for_test"
        }
        async fn run(
            &self,
            env: &mut ciris_persist::prelude::InlineTextEnvelope,
            state: &mut ciris_persist::pipeline::PipelineState,
        ) -> Result<(), ciris_persist::pipeline::Error> {
            env.text = env.text.to_uppercase();
            state.fields_modified += 1;
            state.stages_executed.push("uppercase_for_test".into());
            Ok(())
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn py_inline_text_pipeline_scrub_runs() {
        use ciris_persist::pipeline::{Pipeline, PipelineBuilder};
        use ciris_persist::prelude::{
            EdgeOutboundQueueSqlite, FederationDirectorySqlite, InlineTextEnvelope,
        };

        init_python();

        let directory = FederationDirectorySqlite::open(":memory:")
            .await
            .expect("open directory");
        let queue = EdgeOutboundQueueSqlite::open(":memory:")
            .await
            .expect("open queue");

        let tmp: &'static tempfile::TempDir =
            Box::leak(Box::new(tempfile::tempdir().expect("tempdir")));
        let seed_path = tmp.path().join("ed25519.seed");
        std::fs::write(&seed_path, [0x88u8; 32]).expect("write seed");
        let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
            key_id: "py-tier2-pipeline-edge".into(),
            key_path: seed_path,
            pqc_key_id: None,
            pqc_key_path: None,
        })
        .await
        .expect("load_local_seed");
        let signer = Arc::new(LocalSigner::new("py-tier2-pipeline-edge", classical, None));
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let pipeline: Arc<Pipeline<InlineTextEnvelope>> = Arc::new(
            PipelineBuilder::new()
                .add_stage(UppercaseStage)
                .build()
                .expect("build uppercase pipeline"),
        );

        let edge = Edge::builder()
            .directory(directory)
            .queue(queue)
            .signer(signer)
            .transport(transport)
            .speak_pipeline(pipeline)
            .build()
            .expect("Edge::build with pipeline");
        let edge = Arc::new(edge);

        let py_edge = PyEdge::for_test(edge.clone(), tokio::runtime::Handle::current());

        // Send via the Python surface with lowercase input.
        let py_sha = Python::attach(|py| -> PyResult<String> {
            py_edge.send_inline_text(py, "recipient-key", "hello world")
        })
        .expect("send_inline_text");

        // Compute the expected SHA — build an envelope around the
        // UPPERCASED text (what the pipeline would have produced) and
        // hash its body. If py_sha matches, the pipeline ran (because
        // it transformed the body before the SHA was computed).
        let expected_envelope = crate::identity::build_envelope(
            crate::messages::MessageType::InlineText,
            "py-tier2-pipeline-edge",
            "recipient-key",
            &crate::messages::InlineText {
                text: "HELLO WORLD".to_string(),
            },
            None,
        )
        .expect("build expected envelope");
        let expected_sha = crate::identity::envelope_body_sha256(&expected_envelope);
        let expected_hex = {
            use std::fmt::Write as _;
            let mut s = String::with_capacity(64);
            for b in &expected_sha {
                let _ = write!(s, "{b:02x}");
            }
            s
        };
        assert_eq!(
            py_sha, expected_hex,
            "speak_pipeline MUST run on Python-supplied text before signing \
             (CIRISAgent#756 Q1 / FSD §1.4) — body_sha256 must reflect the \
             post-pipeline body, not the input"
        );
    }

    /// CIRISEdge#28 (v0.19.0) — `PyEdge::metrics_snapshot` round-trips
    /// through the PyO3 boundary as a dict of dicts. We bump a counter
    /// via Rust-side `inc_sent`, then read it back through the Python
    /// projection and assert the key + count survive.
    #[tokio::test(flavor = "multi_thread")]
    async fn metrics_snapshot_round_trip_through_pyo3() {
        init_python();
        let (edge, _queue) = build_test_edge().await;
        // Bump a counter on the live Edge metrics — exercises the
        // same Arc<RwLock<_>> path the production send/receive sites
        // walk.
        edge.metrics().inc_sent(&crate::MessageType::InlineText);
        edge.metrics().inc_sent(&crate::MessageType::InlineText);
        edge.metrics().inc_sent(&crate::MessageType::ContentFetch);
        edge.metrics()
            .inc_send_failure(crate::TransportId::HTTP, "timeout");

        let py_edge = PyEdge::for_test(edge.clone(), tokio::runtime::Handle::current());

        Python::attach(|py| {
            let snap = py_edge.metrics_snapshot(py).expect("metrics_snapshot");
            let snap_bound = snap.bind(py);
            let envelopes_sent = snap_bound
                .get_item("envelopes_sent_total")
                .expect("envelopes_sent_total key");
            let inline_text_count: u64 = envelopes_sent
                .get_item("InlineText")
                .expect("InlineText key")
                .extract()
                .expect("u64 extract");
            assert_eq!(inline_text_count, 2);
            let content_fetch_count: u64 = envelopes_sent
                .get_item("ContentFetch")
                .expect("ContentFetch key")
                .extract()
                .expect("u64 extract");
            assert_eq!(content_fetch_count, 1);

            let send_failures = snap_bound
                .get_item("send_failures_total")
                .expect("send_failures_total key");
            let http_timeout_count: u64 = send_failures
                .get_item("http:timeout")
                .expect("http:timeout key")
                .extract()
                .expect("u64 extract");
            assert_eq!(http_timeout_count, 1);
        });
    }

    // ── v0.9.2 (CIRISEdge#22 / CIRISPersist#109) — cohabitation
    // PyCapsule extraction tests ─────────────────────────────────────
    //
    // These exercise the `init_edge_runtime` happy path + the
    // typed-error path through the new `Bound<'_, PyAny>` signature
    // and the [`extract_capsule`] helper. The cross-module identity
    // invariant (the actual bug fix) requires loading two separately
    // built wheels into one Python process — that lives on
    // CIRISConformance; here we exercise the in-process contract: a
    // Python object exposing the persist 2.7.0+ `*_capsule` pymethods
    // round-trips through `init_edge_runtime` and produces a working
    // [`PyEdge`], and a Python object that doesn't expose those
    // methods is rejected with a typed `TypeError`.
    //
    // The happy-path test uses persist's actual `PyEngine`
    // constructor under Python::attach — since the test binary links
    // persist's `pyo3` feature, `PyEngine::new` is available and its
    // capsule pymethods produce real PyCapsules wrapping the
    // real substrate handles.

    /// Make persist's `PyEngine` available as `ciris_persist.Engine`
    /// to embedded Python in the test process. The persist crate's
    /// pymodule entry function (`fn ciris_persist`) is only invoked
    /// when Python imports `ciris_persist` from a wheel; in our
    /// in-process test we have to register the class ourselves.
    ///
    /// Idempotent — repeats are no-ops via the inner `if`. Safe to
    /// call from every test in this module under a fresh
    /// `Python::attach`.
    fn install_ciris_persist_module(py: Python<'_>) -> PyResult<()> {
        use pyo3::prelude::PyModule;
        use pyo3::types::PyAnyMethods;
        let sys = py.import("sys")?;
        let modules = sys.getattr("modules")?;
        if modules.contains("ciris_persist")? {
            return Ok(());
        }
        let m = PyModule::new(py, "ciris_persist")?;
        m.add_class::<ciris_persist::ffi::pyo3::PyEngine>()?;
        modules.set_item("ciris_persist", m)?;
        Ok(())
    }

    /// CIRISEdge#22 v0.9.2 happy path — `init_edge_runtime` accepts a
    /// `Bound<PyAny>` whose object exposes persist 2.7.0's
    /// `*_capsule` `#[pymethod]`s, and pulls the substrate handles
    /// via the [`extract_capsule`] helper without rejecting the
    /// engine on the cross-module PyClass-identity check the v0.9.1
    /// `PyRef<PyEngine>` signature would have triggered.
    ///
    /// The full end-to-end `init_edge_runtime` call cannot complete in
    /// this in-process embedded-Python test environment because:
    ///   1. The `signing_key_id` argument to `ciris_persist.Engine`
    ///      hits `get_platform_signer()`, which on a host with TPM
    ///      hardware (e.g. most laptops + CI runners with software
    ///      TPM) returns a P-256 / ECDSA signer rather than Ed25519.
    ///   2. Edge's Reticulum transport requires Ed25519 federation
    ///      keys (32 bytes raw); P-256 (65 bytes uncompressed) is
    ///      rejected at transport-config validation.
    ///
    /// That production-config mismatch (separate concern from the
    /// cohabitation capsule contract being tested here) means the
    /// `ReticulumTransport::new` step inside `init_edge_runtime`
    /// rejects with `"federation Ed25519 pubkey must be 32 bytes, got
    /// 65"`. **That error message itself proves the capsule extraction
    /// succeeded** — we reached the transport-config validation stage,
    /// which is downstream of capsule extraction. A failure of the
    /// v0.9.1 `PyRef<PyEngine>` signature would have errored MUCH
    /// earlier with a `TypeError: 'Engine' object is not an instance
    /// of 'Engine'` (no engine bytes ever reach the transport code).
    ///
    /// The test therefore accepts either:
    ///   - `Ok(_)` — the rare case where the test host's platform
    ///     keyring returns Ed25519 (no TPM available, software
    ///     fallback path);
    ///   - `Err(_)` containing a transport-validation message —
    ///     evidence the capsule extraction completed.
    ///
    /// What the test REJECTS:
    ///   - `TypeError` on the engine argument (the v0.9.1 regression);
    ///   - `TypeError` mentioning `*_capsule` (capsule extraction
    ///     itself failing — what `py_init_edge_runtime_rejects_non_engine_object_cleanly`
    ///     verifies on the negative path).
    ///
    /// Plain `#[test]` (not `#[tokio::test]`) because PyEngine's
    /// constructor builds its own tokio runtime via `Runtime::new()`,
    /// which panics if there's already a current runtime on the
    /// calling thread. `init_edge_runtime` then drives its async
    /// composition on that persist-owned runtime via
    /// `ciris_persist::current_runtime_handle()`.
    #[test]
    fn py_init_edge_runtime_via_capsule_succeeds() {
        init_python();
        let _engine_guard = engine_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");
        let local_seed_path = tmp.path().join("local.seed");
        std::fs::write(&local_seed_path, [0xAA_u8; 32]).expect("write local seed");

        // Engine kwargs. `local_key_id` + `local_key_path` bypass the
        // OS keyring's PQC sweep / cold-start path; signing_key_id
        // still hits the platform keyring. Random suffix on
        // signing_key_id ensures the keyring mints a fresh key each
        // run — important because keyring storage (software-fallback
        // and OS-keyring both) outlives the test process.
        let signer_key_id = format!(
            "edge-cohabit-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let outcome: Result<String, PyErr> = Python::attach(|py| -> PyResult<String> {
            install_ciris_persist_module(py)?;
            let ciris_persist_mod = py.import("ciris_persist")?;
            let engine_cls = ciris_persist_mod.getattr("Engine")?;
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("dsn", "sqlite::memory:")?;
            kwargs.set_item("signing_key_id", signer_key_id.as_str())?;
            kwargs.set_item("local_key_id", "edge-cohabit-local")?;
            kwargs.set_item("local_key_path", local_seed_path.to_string_lossy().as_ref())?;
            kwargs.set_item("pqc_sweep_on_init", false)?;
            let engine = engine_cls.call((), Some(&kwargs))?;
            let edge = init_edge_runtime(
                py,
                engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0 — shared-instance disabled in this test)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )?;
            Ok(edge.signer_key_id())
        });

        match outcome {
            Ok(key_id) => {
                // Happy path — the host's platform signer returned an
                // Ed25519 key (software-fallback path). Verify the
                // signer_key_id round-trip.
                assert_eq!(
                    key_id,
                    signer_key_id.as_str(),
                    "init_edge_runtime via capsule must return a PyEdge whose \
                     signer_key_id matches the engine's signing identity"
                );
            }
            Err(e) => {
                // Capsule extraction completed but a downstream stage
                // rejected (typically Reticulum transport-config
                // validation on hosts with TPM keyring returning
                // non-Ed25519 keys). We verify the error is downstream
                // of capsule extraction — the v0.9.2 cohabitation
                // contract is what this test pins.
                let msg = e.to_string();
                assert!(
                    !msg.contains("federation_directory_capsule")
                        && !msg.contains("outbound_queue_capsule")
                        && !msg.contains("keyring_signer_capsule")
                        && !msg.contains("local_signer_capsule"),
                    "init_edge_runtime must reach past capsule extraction with a \
                     valid PyEngine engine arg (the v0.9.2 cohabitation contract; \
                     v0.16.1 cherry-pick adds local_signer_capsule for CIRISEdge#43); \
                     got: {msg}"
                );
                // Also reject the v0.9.1 cross-module identity regression
                // shape — the bug we're fixing.
                assert!(
                    !msg.contains("not an instance of"),
                    "init_edge_runtime must NOT reject PyEngine on PyClass identity \
                     (v0.9.1 regression — CIRISEdge#22); got: {msg}"
                );
            }
        }
    }

    /// CIRISEdge#22 v0.9.2 negative path (updated for v0.10.1) —
    /// `init_edge_runtime` rejects any object that doesn't expose
    /// persist's `*_capsule` pymethods with a typed error (not a panic).
    ///
    /// In v0.9.2 a plain `dict` tripped `extract_capsule` on
    /// `federation_directory_capsule` and surfaced as a `PyTypeError`.
    /// In v0.10.1 the runtime-floor pre-check runs FIRST (because
    /// `runtime_handle_capsule` extraction moved to Step 1 — see the
    /// ordering rationale in `init_edge_runtime`), so a dict trips the
    /// `runtime_handle_capsule` hasattr-miss path and surfaces as a
    /// `PyRuntimeError` naming the v2.8.0 version floor. Either
    /// typed-error shape satisfies the "cleanly rejects" contract; the
    /// test verifies the rejection is typed (not a panic) and the
    /// message names a capsule method an operator can grep for.
    #[tokio::test(flavor = "multi_thread")]
    async fn py_init_edge_runtime_rejects_non_engine_object_cleanly() {
        init_python();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");

        let err = Python::attach(|py| -> PyErr {
            let not_engine = pyo3::types::PyDict::new(py).into_any();
            init_edge_runtime(
                py,
                not_engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )
            .err()
            .expect("init_edge_runtime must reject non-engine object")
        });

        Python::attach(|py| {
            // v0.10.1: the first capsule check is `runtime_handle_capsule`,
            // which surfaces as a `PyRuntimeError` (version-floor
            // diagnostic). Pre-v0.10.1 binaries tripped the
            // `federation_directory_capsule` `PyTypeError` first.
            // Accept either typed shape — the contract is "no panic,
            // typed error, names a capsule method".
            assert!(
                err.is_instance_of::<PyRuntimeError>(py) || err.is_instance_of::<PyTypeError>(py),
                "init_edge_runtime must reject non-engine objects with \
                 PyRuntimeError or PyTypeError (not panic) — got {err}",
            );
            let msg = err.to_string();
            assert!(
                msg.contains("runtime_handle_capsule")
                    || msg.contains("federation_directory_capsule"),
                "error message must name the missing capsule method so operators \
                 can diagnose; got: {msg}"
            );
        });
    }

    // ── v0.10.1 (CIRISEdge#22 cohabitation init-context regression) ──
    //
    // The v0.10.0 cohabitation-gate failed all 6 (3 OS × 2 backend)
    // cells at `init_handshake` with `'persist tokio runtime
    // unavailable'`. The root cause is the runtime-acquisition step in
    // `init_edge_runtime` returning `None` from
    // `ciris_persist::current_runtime_handle()` — meaning persist's
    // process-singleton runtime hadn't been bootstrapped (the host
    // hadn't yet constructed a `ciris_persist.Engine`, OR — the
    // production reality the gate exercises — the cross-cdylib symbol
    // resolution leaves edge's copy of the `ENGINE_SINGLETON` static
    // empty even after the persist `.so`'s copy is populated).
    //
    // v0.10.1 closes this by consuming persist v2.8.0's
    // `runtime_handle_capsule` (CIRISPersist#111) — the runtime handle
    // hops the FFI as an opaque PyCapsule, sidestepping the duplicated
    // static entirely. The two tests below pin the in-process contract:
    // when the engine singleton IS populated, init_edge_runtime
    // acquires the runtime via the capsule and reaches the
    // transport-construction stage; when the engine has been closed
    // (singleton cleared), init_edge_runtime raises a typed
    // `PyRuntimeError` with an actionable message. The cross-cdylib
    // path requires CIRISConformance's matrix to exercise (separately-
    // built wheels) and is the regression-gate the production failure
    // tripped — these in-process tests pin edge's contribution.

    /// Fixed engine fingerprint shared between the two v0.10.1 init-
    /// context tests so they can co-tenant the persist `ENGINE_SINGLETON`
    /// (persist v1.6.8 anti-orphan invariant — a second `Engine(...)`
    /// with the same config returns the existing handle; a different
    /// config raises `EngineConfigMismatch`).
    ///
    /// `signing_key_id` is a process-stable string (no time suffix) so
    /// any test in this module that runs after the first construction
    /// can attach to the same singleton. The other capsule tests use
    /// time-suffixed key_ids because they don't need to co-tenant.
    fn shared_init_context_engine_config(
        py: Python<'_>,
    ) -> PyResult<Bound<'_, pyo3::types::PyDict>> {
        let kwargs = pyo3::types::PyDict::new(py);
        kwargs.set_item("dsn", "sqlite::memory:")?;
        kwargs.set_item("signing_key_id", "edge-init-ctx-shared-fixture")?;
        kwargs.set_item("local_key_id", "edge-init-ctx-shared-local")?;
        // local_key_path is per-test (temp path); caller sets it.
        kwargs.set_item("pqc_sweep_on_init", false)?;
        Ok(kwargs)
    }

    /// `init_edge_runtime` succeeds in acquiring persist's tokio
    /// runtime handle when the host engine has been constructed. The
    /// "would have caught v0.10.0 in CI" test: pins that the runtime
    /// acquisition step does not error when the singleton is populated.
    ///
    /// Identical fixture shape to `py_init_edge_runtime_via_capsule_succeeds`
    /// (Engine + capsule extraction); the differentiating assertion is
    /// "no RuntimeError mentioning `persist tokio runtime`" or
    /// `runtime_handle_capsule`. A downstream transport-config error
    /// (TPM keyring P-256 mismatch on hosts without an Ed25519 platform
    /// signer) IS allowed — that's strictly downstream of the runtime
    /// acquisition.
    ///
    /// Uses [`shared_init_context_engine_config`] so the singleton can
    /// be co-tenanted with [`py_init_edge_runtime_fails_typed_when_no_persist_runtime`].
    /// This test runs first alphabetically (`acquires` < `fails`) and
    /// constructs the engine; the no-runtime test runs second, attaches
    /// to the same singleton via config-match, then closes it.
    #[test]
    fn py_init_edge_runtime_acquires_persist_runtime_context() {
        init_python();
        let _engine_guard = engine_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");
        let local_seed_path = tmp.path().join("local.seed");
        std::fs::write(&local_seed_path, [0xCC_u8; 32]).expect("write local seed");

        let outcome: Result<(), PyErr> = Python::attach(|py| -> PyResult<()> {
            install_ciris_persist_module(py)?;
            let ciris_persist_mod = py.import("ciris_persist")?;
            let engine_cls = ciris_persist_mod.getattr("Engine")?;
            let kwargs = shared_init_context_engine_config(py)?;
            kwargs.set_item("local_key_path", local_seed_path.to_string_lossy().as_ref())?;
            let engine = engine_cls.call((), Some(&kwargs))?;

            // Sanity: at this point the persist runtime singleton IS
            // populated (the Engine constructor builds it, OR attached
            // to an existing same-config singleton). This is the
            // pre-condition the cohabitation contract relies on — the
            // load-bearing assertion this test exists to gate.
            assert!(
                ciris_persist::current_runtime_handle().is_some(),
                "persist must install its tokio runtime singleton when \
                 Engine(...) constructs — pre-condition for init_edge_runtime; \
                 this is the v0.10.0 cohabitation-gate regression CIRISEdge#22 \
                 closes",
            );

            let _ = init_edge_runtime(
                py,
                engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0 — shared-instance disabled in this test)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )?;
            Ok(())
        });

        match outcome {
            Ok(()) => { /* end-to-end happy path on hosts with Ed25519 platform signer */ }
            Err(e) => {
                let msg = e.to_string();
                // The exact v0.10.0 failure signature MUST NOT appear.
                // Even partial matches indicate the runtime-acquire step
                // tripped, which is the regression this test gates.
                assert!(
                    !msg.contains("persist tokio runtime")
                        && !msg.contains("runtime_handle_capsule"),
                    "init_edge_runtime must NOT fail at the runtime-acquire \
                     step when the persist Engine singleton is populated \
                     (the v0.10.0 cohabitation-gate regression — CIRISEdge#22); \
                     got: {msg}"
                );
            }
        }
    }

    /// `init_edge_runtime` raises a typed `PyRuntimeError` (NOT a panic
    /// or TypeError) when the engine object lacks
    /// `runtime_handle_capsule` — i.e. when persist's version is
    /// pre-v2.8.0. The error message must point the operator at the
    /// upgrade path: pin `ciris-persist >= 2.8.0`.
    ///
    /// In v0.10.0 this same scenario surfaced as a cryptic
    /// `"persist tokio runtime unavailable"` from
    /// `current_runtime_handle()`'s `None` return. v0.10.1 pre-checks
    /// the capsule method exists and emits the version-floor diagnostic
    /// BEFORE attempting `extract_capsule`, so the operator sees a
    /// direct "upgrade ciris-persist" message rather than a deferred
    /// substrate-side error.
    ///
    /// We simulate the "no runtime capsule" condition by passing an
    /// engine-shaped Python object that exposes the three substrate
    /// `*_capsule` pymethods (the v0.9.2 / v2.7.0 surface) but NOT
    /// `runtime_handle_capsule` (the v2.8.0 addition). A real
    /// pre-v2.8.0 persist's `PyEngine` carries exactly this shape; we
    /// build a stand-in via Python attribute-shim because constructing
    /// an actual pre-v2.8.0 PyEngine in-tree would require a separate
    /// linked copy of persist.
    ///
    /// Runs as plain `#[test]` (not `#[tokio::test]`) so the calling
    /// thread carries no current tokio runtime — symmetric with the
    /// `acquires` test above.
    #[test]
    fn py_init_edge_runtime_fails_typed_when_no_persist_runtime() {
        init_python();
        let _engine_guard = engine_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");

        // Build a Python object shaped like a pre-v2.8.0 PyEngine: it
        // responds to the three v2.7.0 substrate capsule methods
        // (federation_directory_capsule / outbound_queue_capsule /
        // keyring_signer_capsule — we stub them as raisers since we
        // never reach them) but does NOT define `runtime_handle_capsule`.
        // `hasattr(engine, "runtime_handle_capsule")` is False → the
        // v0.10.1 pre-check in `init_edge_runtime` emits the
        // version-floor PyRuntimeError before any capsule call.
        let err = Python::attach(|py| -> PyErr {
            let pre_v280_engine: Bound<'_, PyAny> = {
                let locals = pyo3::types::PyDict::new(py);
                py.run(
                    c"class PreV280Engine:\n    def federation_directory_capsule(self):\n        raise RuntimeError('unreachable')\n    def outbound_queue_capsule(self):\n        raise RuntimeError('unreachable')\n    def keyring_signer_capsule(self):\n        raise RuntimeError('unreachable')\n_e = PreV280Engine()\n",
                    Some(&locals),
                    Some(&locals),
                )
                .expect("build pre-v2.8.0 stand-in");
                locals.get_item("_e").expect("got _e").expect("not None")
            };

            init_edge_runtime(
                py,
                pre_v280_engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )
            .err()
            .expect("init_edge_runtime must reject pre-v2.8.0-shaped engine")
        });

        Python::attach(|py| {
            assert!(
                err.is_instance_of::<PyRuntimeError>(py),
                "missing-runtime-capsule failure must surface as PyRuntimeError \
                 (not panic, not TypeError) so the Python-side handler treats it \
                 as a typed init error; got {err}",
            );
            let msg = err.to_string();
            // Pin the actionable parts of the diagnostic so future
            // edits don't accidentally regress the operator-facing
            // message:
            //   - mention persist v2.8.0+ as the required floor
            //   - name the missing method `runtime_handle_capsule`
            assert!(
                msg.contains("v2.8.0"),
                "error message must name the persist version floor; got: {msg}"
            );
            assert!(
                msg.contains("runtime_handle_capsule"),
                "error message must name the missing capsule method so operators \
                 can diagnose; got: {msg}"
            );
        });
    }

    // ── v0.16.1 cherry-pick (CIRISEdge#43 / CIRISPersist#119) — local_signer_capsule
    //
    // The federation-cohab unblocker for CIRISAgent 2.9.4 (originally
    // shipped at v0.13.1 on the `v0.13.x-line` branch; this is the
    // cherry-pick onto main so v0.16+ consumers get the fix too).
    // v0.13.0–v0.16.0 read the Reticulum transport-identity Ed25519
    // pubkey from `keyring_signer_capsule`, which under
    // `keyring_storage_kind = hardware_hsm_only` emits a 65-byte hybrid
    // pubkey (TPM P-256). `ReticulumTransport::new` correctly rejected
    // with `"federation Ed25519 pubkey must be 32 bytes, got 65"`,
    // blocking every hardware-keyring cohab init. Persist v3.1.1
    // adds `local_signer_capsule()` exposing the software Ed25519
    // transport-identity `Arc<LocalSigner>`; v0.16.1 routes the
    // Reticulum-identity primitive through it via
    // `LocalSignerHardwareAdapter`. The hot-path scrub-envelope
    // signing surface stays on `keyring_signer_capsule`.
    //
    // The two tests below pin:
    //   1. happy path — an engine constructed with `local_key_id` +
    //      `local_key_path` populates `local_signer_capsule`;
    //      `init_edge_runtime` extracts it and uses the 32-byte
    //      Ed25519 surface as the Reticulum identity. Transport
    //      construction succeeds.
    //   2. fallback path — an engine constructed WITHOUT
    //      `local_key_id` raises `ValueError("local_signer_unavailable")`
    //      from `local_signer_capsule()`; `init_edge_runtime` falls
    //      back to `keyring_signer` and logs a warning. The init then
    //      either succeeds (software-keyring host: keyring signer
    //      yields a 32-byte Ed25519 pubkey) or fails at
    //      `ReticulumTransport::new` with the v0.13.0 65-byte error
    //      (hardware-keyring host) — either shape is the documented
    //      fallback behavior.
    //
    // We can't directly assert "transport identity is 32 bytes" from
    // outside the transport (no public accessor); the test asserts the
    // INDIRECT INVARIANT: with local_signer_capsule available, init
    // reaches `signer_key_id()` cleanly (transport built successfully).
    // The 32-byte invariant is enforced by `build_local_attestation`'s
    // hard check (`src/transport/reticulum.rs`); any regression there
    // would surface as a `federation Ed25519 pubkey must be 32 bytes`
    // error message.

    /// v0.16.1 cherry-pick — happy path. Engine constructed with
    /// `local_key_id` + `local_key_path` exposes a populated
    /// `local_signer_capsule()`. `init_edge_runtime` routes the
    /// Reticulum-identity signer through `LocalSignerHardwareAdapter`
    /// and the transport builds cleanly (the 32-byte Ed25519 raw
    /// pubkey from `LocalSigner.signing_key.verifying_key().to_bytes()`
    /// satisfies `ReticulumTransport::new`'s identity validation,
    /// regardless of what the platform keyring's `signing_key_id`
    /// resolves to — hardware P-256 included).
    ///
    /// The test asserts `outcome` is `Ok` OR — if the platform keyring
    /// happens to fail in a DIFFERENT downstream stage (e.g. socket
    /// bind on a hostile CI runner) — at minimum the error message
    /// does NOT contain "32 bytes, got 65" (the v0.13.0 blocker shape)
    /// and does NOT contain "local_signer_capsule" (capsule extraction
    /// failure).
    #[test]
    fn py_init_edge_runtime_local_signer_capsule_supplies_reticulum_identity() {
        init_python();
        let _engine_guard = engine_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");
        let local_seed_path = tmp.path().join("local.seed");
        // A deterministic 32-byte seed → known software Ed25519
        // identity. `LocalSigner::from_config` reads this verbatim and
        // builds a `SigningKey::from_bytes(seed)`. The 32-byte raw
        // pubkey surface via `LocalSignerHardwareAdapter::public_key`
        // is what the Reticulum identity attestation consumes.
        std::fs::write(&local_seed_path, [0x42_u8; 32]).expect("write local seed");

        let signer_key_id = format!(
            "edge-cohabit-local-signer-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let outcome: Result<String, PyErr> = Python::attach(|py| -> PyResult<String> {
            install_ciris_persist_module(py)?;
            let ciris_persist_mod = py.import("ciris_persist")?;
            let engine_cls = ciris_persist_mod.getattr("Engine")?;
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("dsn", "sqlite::memory:")?;
            kwargs.set_item("signing_key_id", signer_key_id.as_str())?;
            kwargs.set_item("local_key_id", "edge-cohabit-local-id")?;
            kwargs.set_item("local_key_path", local_seed_path.to_string_lossy().as_ref())?;
            kwargs.set_item("pqc_sweep_on_init", false)?;
            let engine = engine_cls.call((), Some(&kwargs))?;
            // Sanity: the engine MUST expose local_signer_capsule under
            // persist v3.1.1+. If this hasattr returns false, the
            // Cargo pin (v3.2.0) didn't take — fail loudly so the
            // operator sees the wrong-persist diagnostic up front.
            assert!(
                engine.hasattr("local_signer_capsule")?,
                "ciris_persist v3.1.1+ MUST expose local_signer_capsule \
                 (CIRISPersist#119) — Cargo pin out of sync?"
            );
            let edge = init_edge_runtime(
                py,
                engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0 — shared-instance disabled in this test)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )?;
            Ok(edge.signer_key_id())
        });

        match outcome {
            Ok(key_id) => {
                // Happy path — local_signer_capsule supplied the 32-byte
                // Ed25519 transport identity; the hardware-rooted keyring
                // signer (which may have been P-256 / 65-byte under TPM)
                // drives the Edge::send_durable scrub envelope path.
                // signer_key_id is the keyring's key_id (the envelope-
                // signing identity), NOT the Reticulum-transport
                // identity — that's a separate dual-key identity loaded
                // from `identity_path`.
                assert_eq!(
                    key_id,
                    signer_key_id.as_str(),
                    "signer_key_id must round-trip the engine's signing identity \
                     (the keyring/envelope identity, not the Reticulum transport \
                     identity)"
                );
            }
            Err(e) => {
                // If init still fails, the failure MUST NOT be the
                // v0.13.0 "32 bytes, got 65" blocker — that's the
                // exact shape v0.16.1 is meant to close. Capsule
                // extraction itself must also not surface as the
                // failure point.
                let msg = e.to_string();
                assert!(
                    !msg.contains("32 bytes, got 65"),
                    "v0.16.1 must close the v0.13.0 'federation Ed25519 pubkey \
                     must be 32 bytes, got 65' blocker under hardware_hsm_only \
                     keyring storage. Got: {msg}"
                );
                assert!(
                    !msg.contains("local_signer_capsule"),
                    "local_signer_capsule extraction must succeed when the engine \
                     was constructed with local_key_id + local_key_path. Got: {msg}"
                );
                assert!(
                    !msg.contains("local_signer_unavailable"),
                    "local_signer_unavailable fallback must NOT trigger when \
                     local_key_path is supplied. Got: {msg}"
                );
            }
        }
    }

    /// v0.16.1 cherry-pick — fallback path. Engine constructed
    /// WITHOUT `local_key_id` (and without `local_key_path`) raises
    /// the typed `ValueError("local_signer_unavailable")` from
    /// `local_signer_capsule()`. `init_edge_runtime` MUST detect this
    /// typed shape and fall through to keyring_signer for the
    /// Reticulum-identity surface (logging a warning); it MUST NOT
    /// surface the unavailable signal as a hard PyError.
    ///
    /// Under a software-fallback keyring host (CI without TPM access),
    /// the keyring signer yields a 32-byte Ed25519 pubkey and the
    /// transport build succeeds — meaning the test path's outcome is
    /// `Ok` (signer_key_id round-trips). Under a hardware-keyring
    /// host (TPM P-256), the fallback path fails at
    /// `ReticulumTransport::new` with the v0.13.0 "32 bytes, got 65"
    /// shape — that's the diagnostic the operator needs to see; the
    /// test accepts that shape too.
    ///
    /// What the test REJECTS:
    ///   - `local_signer_unavailable` surfacing as a PyError (failure
    ///     of the fallback detection logic — would block init even on
    ///     software-keyring hosts).
    ///   - `local_signer_capsule` mentioned in a PyTypeError shape
    ///     (capsule extraction failure — should be caught + fall
    ///     through, not error).
    ///
    /// Persist's `from_shared_with_local` path requires both
    /// `local_key_id` AND `local_key_path` to be set; omitting one
    /// gives `LocalSignerError::PqcConfigInconsistent`-style errors at
    /// engine construction. We omit BOTH to land cleanly on the "no
    /// local signer" branch — `self.local_signer` ends up `None`,
    /// which is exactly what `local_signer_capsule_py` checks.
    #[test]
    fn py_init_edge_runtime_local_signer_unavailable_falls_back_cleanly() {
        init_python();
        let _engine_guard = engine_lock();
        let tmp = tempfile::tempdir().expect("tempdir");
        let identity_path = tmp.path().join("transport.id");

        let signer_key_id = format!(
            "edge-cohabit-nolocal-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );

        let outcome: Result<String, PyErr> = Python::attach(|py| -> PyResult<String> {
            install_ciris_persist_module(py)?;
            let ciris_persist_mod = py.import("ciris_persist")?;
            let engine_cls = ciris_persist_mod.getattr("Engine")?;
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("dsn", "sqlite::memory:")?;
            kwargs.set_item("signing_key_id", signer_key_id.as_str())?;
            // Deliberately NOT setting local_key_id / local_key_path —
            // this is the "older cohab init path" the v3.1.1
            // local_signer_capsule fallback contract documents.
            kwargs.set_item("pqc_sweep_on_init", false)?;
            let engine = engine_cls.call((), Some(&kwargs))?;
            // Sanity: the engine exposes local_signer_capsule (the
            // method exists on v3.1.1+), but it will raise
            // ValueError("local_signer_unavailable") when called
            // because `local_signer` is None on this engine.
            assert!(
                engine.hasattr("local_signer_capsule")?,
                "persist v3.1.1+ MUST expose local_signer_capsule even when \
                 local_signer is None (the method raises a typed error)"
            );
            let edge = init_edge_runtime(
                py,
                engine,
                identity_path.to_str().expect("identity path utf8"),
                "127.0.0.1:0",
                vec![],
                300,
                0,
                "strict",
                60,
                "proxy",
                None,
                None,   // https_listen_addr
                None,   // https_tls_cert_path
                None,   // https_tls_key_path
                false,  // https_mtls_required
                None,   // https_bearer_secret
                false,  // https_dev_self_signed
                false,  // disable_reticulum
                None,   // disk_budget_bytes (v0.20.0 RC1 — use AgentMode default)
                None,   // trust_recursion_depth (v0.20.0 RC1 — use AgentMode default)
                None,   // local_instance_name (v2.3.0 — shared-instance disabled in this test)
                "auto", // local_instance_role
                None,   // agent_occurrence_key_id (v3.1.0 — self-at-login opt-out)
                None,   // transport_identity_keyring_dir (v3.1.0 — file-only)
                false,  // enable_transport (CIRISEdge#168 — leaf-node default)
            )?;
            Ok(edge.signer_key_id())
        });

        match outcome {
            Ok(key_id) => {
                // Software-keyring host — fallback to keyring_signer
                // happened to yield a 32-byte Ed25519 pubkey, transport
                // built. The fallback warning was logged via tracing
                // (not asserted here — would need a tracing-subscriber
                // capture fixture for that).
                assert_eq!(
                    key_id,
                    signer_key_id.as_str(),
                    "fallback path must still round-trip signer_key_id when the \
                     keyring signer yields a 32-byte Ed25519 pubkey"
                );
            }
            Err(e) => {
                let msg = e.to_string();
                // The fallback MUST have detected
                // local_signer_unavailable as a typed signal — it must
                // NOT surface in the final error message (that would
                // mean the typed-error detection logic failed and the
                // error propagated as a hard failure).
                assert!(
                    !msg.contains("local_signer_unavailable"),
                    "local_signer_unavailable ValueError MUST be caught + drive \
                     fallback to keyring_signer. Surfacing it as a PyError is the \
                     bug v0.16.1's typed-error-detection branch closes. Got: {msg}"
                );
                // Capsule-extraction failure on local_signer_capsule
                // must not be the failure shape either.
                assert!(
                    !msg.contains("engine.local_signer_capsule() did not return"),
                    "local_signer_capsule extraction must follow the typed \
                     fallback contract, not the cast-failure path. Got: {msg}"
                );
                // Acceptable downstream failure: the 65-byte hardware
                // pubkey rejection from ReticulumTransport::new. That's
                // the v0.13.0 shape that hardware deployments WILL still
                // see when the engine wasn't built with local_key_path.
                // Document this in the test report — operator's upgrade
                // path is "build engine with local_key_path".
                let _ = msg;
            }
        }
    }

    // ── v0.19.5 (CIRISEdge#50) — durable-send runtime-context regression ─
    //
    // The CIRISConformance harness drives wheels through
    // `init_edge_runtime` and then makes `send_durable_inline_text`
    // calls. In v0.19.4 those calls SIGABRT with
    // `there is no reactor running` (tokio-1.52.3/src/time/interval.rs).
    // The trip-wire is the `send_durable_inline_text` pymethod itself
    // — the caller doesn't even get back a `DurableHandle`.
    //
    // Root cause: the pymethod ran `runtime.block_on(fut)` correctly,
    // but the `runtime` carried into the `PyDurableHandle` value
    // returned from the method was a clone of the SAME `RuntimeHandle`,
    // and the panic shape "no reactor running" only fires when the
    // host thread has NO current tokio runtime AND the call site
    // tries to construct a timer-bound primitive (e.g. via
    // `tokio::time::interval`) without entering one first.
    //
    // Repro: a plain (non-`#[tokio::test]`) `#[test]` that
    //   1. builds a multi-thread runtime via `Runtime::new()`,
    //   2. assembles the test `Edge` on it,
    //   3. drops out of the runtime context (the test thread is bare),
    //   4. calls `PyEdge::send_durable_inline_text` directly.
    //
    // With v0.19.4 this test will SIGABRT before returning (the v0.19.5
    // fix wraps the pymethod's `run_async` invocation in a
    // `runtime.enter()` guard so the call site has a current runtime
    // for the duration of the call). The fix is contained — same shape
    // for `send_inline_text` (which is exercised by the existing tests
    // and never SIGABRT'd in production, but takes the same `run_async`
    // path; the guard there is a defense-in-depth measure).
    //
    // No `#[tokio::test]`. The `Runtime::new()` is owned by the test
    // body; its handle is what the PyEdge consumes — exactly the shape
    // `init_edge_runtime` sees after extracting `runtime_handle_capsule`
    // from persist.

    /// Sync-context fixture matching the cohabitation harness shape:
    /// build a multi-thread runtime, assemble the test Edge on it,
    /// then EXIT the runtime context before returning the
    /// (PyEdge, queue, runtime) tuple. Callers exercise PyEdge
    /// pymethods from a thread with no current tokio runtime — exactly
    /// what `init_edge_runtime` produces after construction.
    ///
    /// The Runtime is returned to the caller so it stays alive (the
    /// PyEdge's `runtime: RuntimeHandle` is just a Handle clone; the
    /// Runtime itself owns the worker threads + reactor that drive the
    /// pymethod's `block_on`). Drop order: the caller drops PyEdge
    /// first (which drops the Arc<Edge>), then Runtime (which joins
    /// worker threads).
    fn build_sync_cohab_fixture() -> (PyEdge, Arc<dyn OutboundHandle>, tokio::runtime::Runtime) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("build multi-thread runtime");
        let (edge, queue) = runtime.block_on(build_test_edge());
        let handle = runtime.handle().clone();
        let py_edge = PyEdge::for_test(edge, handle);
        (py_edge, queue, runtime)
    }

    /// v0.19.5 (CIRISEdge#50) — acceptance gate. The bug shape is a
    /// hard SIGABRT (panic-on-drop in a tokio worker drop). Asserting
    /// "did not panic" is necessarily indirect: if the pymethod
    /// returns Ok with a DurableHandle, the bug did NOT fire. The
    /// existing v0.19.4 binary aborts the test process before this
    /// line; the v0.19.5 fix returns a valid handle.
    #[test]
    fn send_durable_inline_text_does_not_abort_in_sync_cohab() {
        init_python();
        let (py_edge, _queue, _runtime) = build_sync_cohab_fixture();
        let handle = Python::attach(|py| -> PyResult<PyDurableHandle> {
            py_edge.send_durable_inline_text(py, "recipient-key", "hello")
        })
        .expect("send_durable_inline_text must not abort in sync cohab context");
        // body_sha256 is the load-bearing forensic join key — its
        // presence (64-char lowercase hex) means the envelope was
        // built, signed, hashed, and enqueued. The pymethod ran to
        // completion.
        assert_eq!(handle.body_sha256().len(), 64);
        assert!(handle
            .body_sha256()
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()));
    }

    /// v0.19.5 (CIRISEdge#50) — the envelope MUST be visible in the
    /// persist outbound queue with `status=pending` after a successful
    /// `send_durable_inline_text` return.
    #[test]
    fn send_durable_inline_text_envelope_visible_in_outbound() {
        use ciris_persist::prelude::{OutboundFilter, OutboundStatus};

        init_python();
        let (py_edge, queue, runtime) = build_sync_cohab_fixture();
        let queue_id = Python::attach(|py| -> PyResult<String> {
            let h = py_edge.send_durable_inline_text(py, "recipient-key", "visible-row")?;
            Ok(h.queue_id().to_string())
        })
        .expect("send_durable_inline_text");

        // List pending outbound rows — the new envelope must appear.
        // Inspect via the same runtime the pymethod used.
        let rows = runtime.block_on(async {
            queue
                .list_outbound(
                    OutboundFilter {
                        status: Some(OutboundStatus::Pending),
                        destination_key_id: Some("recipient-key".to_string()),
                        ..Default::default()
                    },
                    16,
                )
                .await
                .expect("list_outbound")
        });
        assert!(
            rows.iter().any(|r| r.queue_id == queue_id),
            "enqueued envelope must be visible in list_outbound (queue_id={queue_id}, \
             observed {} rows): {:?}",
            rows.len(),
            rows.iter().map(|r| &r.queue_id).collect::<Vec<_>>(),
        );
    }

    /// v0.19.5 (CIRISEdge#50) — `metrics_snapshot()["durable_queue_depth"]`
    /// must increment by 1 per `send_durable_inline_text` call. The
    /// `Edge::send_durable_with_cohort_scope` body fires
    /// `metrics.inc_durable_queue(DeliveryClass::Durable)` AFTER the
    /// successful `enqueue_outbound`; the snapshot path projects it.
    #[test]
    fn send_durable_inline_text_increments_durable_queue_depth_metric() {
        init_python();
        let (py_edge, _queue, _runtime) = build_sync_cohab_fixture();

        // Baseline: 0 (fresh Edge, no prior durable sends).
        let baseline: u64 = Python::attach(|py| -> PyResult<u64> {
            let snap = py_edge.metrics_snapshot(py)?;
            let bound = snap.bind(py);
            let depth = bound.get_item("durable_queue_depth")?;
            // `durable_queue_depth` dict is keyed by DeliveryClass::as_str().
            // Missing key = 0 (no enqueue yet).
            match depth.get_item("durable") {
                Ok(v) => v.extract::<u64>(),
                Err(_) => Ok(0),
            }
        })
        .expect("metrics_snapshot baseline");

        // Single enqueue.
        Python::attach(|py| -> PyResult<()> {
            py_edge.send_durable_inline_text(py, "recipient-key", "metric-bump")?;
            Ok(())
        })
        .expect("send_durable_inline_text");

        // Post: baseline + 1.
        let post: u64 = Python::attach(|py| -> PyResult<u64> {
            let snap = py_edge.metrics_snapshot(py)?;
            let bound = snap.bind(py);
            let depth = bound.get_item("durable_queue_depth")?;
            depth.get_item("durable")?.extract()
        })
        .expect("metrics_snapshot post");
        assert_eq!(
            post,
            baseline + 1,
            "durable_queue_depth[durable] must increment by 1 per send_durable_inline_text \
             (baseline={baseline}, post={post})"
        );
    }
}
