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
use pyo3::types::PyAnyMethods;
use pyo3::wrap_pyfunction;
use tokio::runtime::Handle as RuntimeHandle;

use ciris_persist::ffi::pyo3::PyEngine;
use ciris_persist::BackendDispatch;

use crate::edge::Edge;
use crate::handler::{DurableOutcome, DurableStatus};
use crate::identity::LocalSigner;
use crate::messages::{InlineText, InlineTextDurable};
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
    /// Tokio runtime handle captured at construction time — used by the
    /// CIRISEdge#22 Tier 2 (v0.9.0) `send_inline_text` /
    /// `send_durable_inline_text` / `DurableHandle::await_ack` pymethods
    /// to drive `Edge`'s async surface from synchronous Python. Captured
    /// from `ciris_persist::current_runtime_handle()` under the
    /// cohabitation entry point ([`init_edge_runtime`]); test builds
    /// inject one explicitly via [`PyEdge::for_test`].
    runtime: RuntimeHandle,
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

    /// Test-only constructor — accepts a pre-built `Arc<Edge>` and an
    /// explicit tokio runtime handle. Used by the integration tests at
    /// the bottom of this module so a PyEdge can be exercised against
    /// an `Edge` assembled directly from substrate primitives (no
    /// `PyEngine` round-trip needed). Not exposed to Python.
    #[cfg(test)]
    pub(crate) fn for_test(inner: Arc<Edge>, runtime: RuntimeHandle) -> Self {
        Self { inner, runtime }
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
        let runtime = self.runtime.clone();
        py.detach(|| {
            run_async(&runtime, async move {
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
        let runtime = self.runtime.clone();
        let queue_arc: Arc<dyn OutboundHandle> = edge.outbound_queue_handle();
        let runtime_for_handle = runtime.clone();
        let queue_for_handle = queue_arc.clone();
        py.detach(|| {
            run_async(&runtime, async move {
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
                    runtime: runtime_for_handle,
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
    /// Tokio runtime to drive `OutboundHandle::outbound_status` polls
    /// from synchronous Python.
    runtime: RuntimeHandle,
    /// Shared outbound-queue handle — same `Arc<dyn OutboundHandle>`
    /// the `Edge` holds. Cloning the Arc lets the handle outlive the
    /// `PyEdge` that produced it (Python ownership semantics differ
    /// from Rust borrow lifetimes).
    queue: Arc<dyn OutboundHandle>,
}

/// Drive an async future to completion from a synchronous PyMethod
/// context. The complication: the calling thread might be a tokio
/// worker (in our integration tests, `#[tokio::test]` spins up a
/// runtime that drives the test fn AND the pymethod's `block_on`),
/// in which case a naive `runtime.block_on(fut)` panics with
/// "Cannot start a runtime from within a runtime". In production
/// (CIRISAgent's pyo3 entry: a Python thread that is NOT a tokio
/// worker), `runtime.block_on(fut)` is the correct path.
///
/// We detect the situation via [`tokio::runtime::Handle::try_current`]
/// and use [`tokio::task::block_in_place`] (multi-thread runtime only,
/// which the cohabitation runtime always is) to yield the worker
/// thread while we synchronously wait on the future. When no current
/// runtime is set on the calling thread, plain `runtime.block_on` is
/// correct and drives the future on a runtime worker thread.
fn run_async<F, T>(runtime: &RuntimeHandle, fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    if tokio::runtime::Handle::try_current().is_ok() {
        // We're on a tokio worker — yield via block_in_place + delegate
        // back to the same runtime's block_on under the released worker.
        // Requires a multi-thread runtime; CIRISAgent's cohabitation
        // runtime IS multi-thread (persist's `Runtime::new()` builds
        // a multi-thread runtime by default), and our pyo3 tests use
        // `#[tokio::test(flavor = "multi_thread")]`.
        tokio::task::block_in_place(|| runtime.block_on(fut))
    } else {
        runtime.block_on(fut)
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
        let runtime = self.runtime.clone();
        py.detach(|| {
            run_async(&runtime, async move {
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
        let queue_id = self.queue_id.clone();
        let queue = self.queue.clone();
        let runtime = self.runtime.clone();
        py.detach(|| {
            run_async(&runtime, async move {
                let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
                loop {
                    let row = queue
                        .outbound_status(&queue_id)
                        .await
                        .map_err(|e| PyRuntimeError::new_err(format!("outbound_status: {e}")))?;
                    if let Some(r) = row {
                        if matches!(
                            crate::edge::map_outbound_row_to_status(&r),
                            DurableStatus::Terminal(DurableOutcome::Delivered { .. }),
                        ) {
                            return Ok(true);
                        }
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Ok(false);
                    }
                    tokio::time::sleep(Duration::from_millis(AWAIT_ACK_POLL_INTERVAL_MS)).await;
                }
            })
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
        runtime,
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

    // CIRISEdge#22 Tier 2 (v0.9.0) — CommunicationBus replacement
    // pyclasses. `DurableHandle` is returned by
    // `PyEdge::send_durable_inline_text`; `SubscriptionHandle` is
    // returned by `PyEdge::register_inline_text_handler`.
    m.add_class::<PyDurableHandle>()?;
    m.add_class::<PySubscriptionHandle>()?;

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
        let py_edge = PyEdge::for_test(Arc::new(edge), tokio::runtime::Handle::current());
        let handle: Arc<Edge> = py_edge.edge_handle();
        assert!(Arc::strong_count(&handle) >= 2);
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
            };
            backend
                .put_public_key(SignedKeyRecord { record })
                .await
                .expect("put_public_key");
        }

        let queue: Arc<dyn OutboundHandle> = backend.clone();
        let signer = Arc::new(LocalSigner {
            key_id: "py-tier2-edge".into(),
            classical,
            pqc: None,
        });
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
            let handle = PyDurableHandle {
                queue_id: queue_id.clone(),
                body_sha256_hex: "0".repeat(64),
                runtime: tokio::runtime::Handle::current(),
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
        let signer = Arc::new(LocalSigner {
            key_id: "py-tier2-pipeline-edge".into(),
            classical,
            pqc: None,
        });
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
}
