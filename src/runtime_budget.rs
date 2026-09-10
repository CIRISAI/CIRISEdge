//! CIRISEdge#583 / CIRISServer#577 — the embedded fold's thread budget.
//!
//! # What this is for
//!
//! A CIRISServer node loads server + edge + persist + verify into ONE
//! process. Every runtime any of them builds multiplies that process's
//! thread count, and on the platforms the fold ships to (Android/Scudo,
//! iOS+macOS/libmalloc, Windows) there is no `M_ARENA_MAX` to fall back
//! on — each allocator carries a per-thread cache and thread count is the
//! multiplier in all of them. So the lever is thread count, and the fold
//! needs ONE knob that every runtime in it honours. The server half of
//! #577 already reads [`WORKERS_ENV`]; this is edge's half.
//!
//! # What was actually uncapped
//!
//! Not the worker threads. Edge's two production runtimes have pinned
//! theirs for some time — the pyo3 transport runtime at 2, the standalone
//! `edge_node` binary at 4 — and CIRISServer#577's own measurement agrees,
//! reading `ciris-edge-tran` flat at 2 threads on both a 32-core and a
//! 4-core host. The one uncapped multi-thread builder left in
//! `src/ffi/pyo3.rs` is inside `#[cfg(test)]` and never ships.
//!
//! What no edge runtime has ever set is **`max_blocking_threads`**, which
//! tokio defaults to **512 per runtime**. That became load-bearing with
//! CIRISPersist v43.1.0 (#829): persist now dispatches every SQL call off
//! the async runtime, and its `FSD/SQLITE_CONNECTION_MODEL.md` is explicit
//! that "the SQL — *and the wait for the connection* — runs on tokio's
//! blocking pool". Concurrent SQL stays bounded by persist's own read pool
//! (`available_parallelism().clamp(2, 8)`, plus one writer); concurrent
//! *waiters* do not. Each one pins a blocking thread.
//!
//! # Why the floor is not negotiable
//!
//! [`MIN_MAX_BLOCKING_THREADS`] is a hard clamp, not a suggestion, because
//! starving this pool can WEDGE a runtime rather than merely slow it.
//! Edge's replication directory adapter calls
//! [`tokio::task::block_in_place`] (`src/replication/directory.rs`, six
//! sites). That call transitions the calling worker into a blocking thread
//! and needs a replacement to take over its queue — drawn from this same
//! pool. Set the pool below what the in-flight `block_in_place` calls plus
//! persist's connection waiters need, and the runtime can run out of
//! threads to hand the work to. This is the same shape as the history
//! CIRISServer#446/#501 records, where a serving node with too few threads
//! stopped calling `accept()` while `Recv-Q` climbed.
//!
//! # What this deliberately does NOT address
//!
//! CIRISEdge#547 — the advertise-path corpus scan that held the single DB
//! connection while page-faulting — is a different problem, and #583 says
//! so directly: more workers did not help there because the threads were
//! parked in `futex_wait` behind one connection, and fewer would not have
//! helped either. A thread cap is not a fix for that, and persist v43.1.0's
//! read pool is the thing that addresses it.

use std::env;

/// The fold-wide worker-thread knob. Deliberately the SAME name
/// CIRISServer#577's half reads, so one export governs every runtime in
/// the process rather than each primitive owning a private spelling.
pub const WORKERS_ENV: &str = "CIRIS_RUNTIME_WORKERS";

/// The blocking-pool knob. Edge-specific because the server half does not
/// have one yet; if it grows one, it should read this name.
pub const MAX_BLOCKING_ENV: &str = "CIRIS_RUNTIME_MAX_BLOCKING_THREADS";

/// Default ceiling on the blocking pool, replacing tokio's 512.
///
/// Sized against what actually queues there in the fold: persist's read
/// pool tops out at 8 readers plus 1 writer, `block_in_place` replacements
/// are bounded by the runtime's worker count (2 or 4), and the rest is
/// headroom for bursts. 32 is ~3.5x the concurrent-SQL ceiling and 16x
/// below tokio's default.
pub const DEFAULT_MAX_BLOCKING_THREADS: usize = 32;

/// Hard floor on the blocking pool — see the module docs on wedging.
/// Covers persist's 9 concurrent connections plus a worker's worth of
/// `block_in_place` replacements, with room to spare.
pub const MIN_MAX_BLOCKING_THREADS: usize = 16;

/// A resolved thread budget for one tokio runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeBudget {
    /// Async worker threads.
    pub worker_threads: usize,
    /// Ceiling on the blocking pool (`spawn_blocking` + `block_in_place`
    /// replacements).
    pub max_blocking_threads: usize,
}

impl RuntimeBudget {
    /// Resolve the budget for a runtime whose built-in worker count is
    /// `default_workers`, letting the environment override it.
    ///
    /// With neither variable set the result is **byte-identical to what
    /// the call site shipped before** for workers — this exists to let a
    /// host lower the fold's footprint, never to change it by arriving.
    #[must_use]
    pub fn from_env(default_workers: usize) -> Self {
        Self::resolve(
            default_workers,
            read_env(WORKERS_ENV),
            read_env(MAX_BLOCKING_ENV),
        )
    }

    /// The pure core of [`from_env`](Self::from_env), so the clamps can be
    /// tested with the exact values an operator can actually export
    /// rather than with whatever the test process happens to have set.
    #[must_use]
    fn resolve(
        default_workers: usize,
        workers_env: Option<usize>,
        blocking_env: Option<usize>,
    ) -> Self {
        // `worker_threads(0)` panics inside tokio, so 0 is not a way to
        // ask for "the default" — it is a way to abort at startup.
        let requested_workers = workers_env.unwrap_or(default_workers);
        let worker_threads = requested_workers.max(1);
        if requested_workers != worker_threads {
            tracing::warn!(
                requested = requested_workers,
                using = worker_threads,
                env = WORKERS_ENV,
                "runtime budget: worker_threads(0) panics in tokio; raising to 1",
            );
        }

        let requested_blocking = blocking_env.unwrap_or(DEFAULT_MAX_BLOCKING_THREADS);
        let max_blocking_threads = requested_blocking.max(MIN_MAX_BLOCKING_THREADS);
        if requested_blocking != max_blocking_threads {
            // Loud, because the operator asked for something and did not
            // get it. The clamp is deliberate: below this the runtime can
            // wedge rather than slow down (see the module docs).
            tracing::warn!(
                requested = requested_blocking,
                using = max_blocking_threads,
                env = MAX_BLOCKING_ENV,
                "runtime budget: blocking pool floor enforced — persist's connection \
                 waiters and block_in_place replacements share this pool, and starving \
                 it stalls the runtime rather than slowing it",
            );
        }

        Self {
            worker_threads,
            max_blocking_threads,
        }
    }

    /// Apply this budget to a tokio builder.
    pub fn configure(self, builder: &mut tokio::runtime::Builder) -> &mut tokio::runtime::Builder {
        builder
            .worker_threads(self.worker_threads)
            .max_blocking_threads(self.max_blocking_threads)
    }
}

/// Read a positive integer from the environment. Absent, empty, or
/// unparseable all mean "unset" — a typo in a deployment script must not
/// silently become a thread budget, and warning is the only way an
/// operator finds out the export did nothing.
fn read_env(key: &str) -> Option<usize> {
    parse_budget(key, env::var(key).ok().as_deref())
}

/// The parse, split out from the lookup.
///
/// Not merely for tidiness: edge is `#![deny(unsafe_code)]` unless
/// `ffi-uniffi` is on, and since Rust 2024 `env::set_var` is `unsafe` — so
/// a test that reached for the real environment would not compile on most
/// of edge's feature lanes. Taking the raw value as an argument tests the
/// same logic against the exact strings an operator can export, with no
/// global state and no cross-test raciness.
fn parse_budget(key: &str, raw: Option<&str>) -> Option<usize> {
    let raw = raw?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let Ok(n) = trimmed.parse::<usize>() else {
        tracing::warn!(
            env = key,
            value = %raw,
            "runtime budget: value is not a non-negative integer; ignoring it \
             and using the built-in default",
        );
        return None;
    };
    Some(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_environment_preserves_each_call_sites_shipped_worker_count() {
        // The whole point: arriving must not change anyone's thread count.
        assert_eq!(RuntimeBudget::resolve(2, None, None).worker_threads, 2);
        assert_eq!(RuntimeBudget::resolve(4, None, None).worker_threads, 4);
    }

    #[test]
    fn the_blocking_pool_default_replaces_tokios_512() {
        let b = RuntimeBudget::resolve(2, None, None);
        assert_eq!(b.max_blocking_threads, DEFAULT_MAX_BLOCKING_THREADS);
        assert!(
            b.max_blocking_threads < 512,
            "the default must actually cap something",
        );
    }

    #[test]
    fn the_environment_overrides_the_call_sites_default() {
        let b = RuntimeBudget::resolve(4, Some(2), Some(64));
        assert_eq!(b.worker_threads, 2);
        assert_eq!(b.max_blocking_threads, 64);
    }

    #[test]
    fn zero_workers_is_raised_because_tokio_panics_on_it() {
        // Not clamped to the call-site default: an operator who exports 0
        // gets a running node, not a startup abort.
        assert_eq!(RuntimeBudget::resolve(4, Some(0), None).worker_threads, 1);
    }

    #[test]
    fn the_blocking_floor_holds_against_a_value_that_could_wedge_the_runtime() {
        for asked in [0, 1, 4, MIN_MAX_BLOCKING_THREADS - 1] {
            assert_eq!(
                RuntimeBudget::resolve(2, None, Some(asked)).max_blocking_threads,
                MIN_MAX_BLOCKING_THREADS,
                "asked for {asked}",
            );
        }
        // At and above the floor the operator's number is honoured verbatim.
        assert_eq!(
            RuntimeBudget::resolve(2, None, Some(MIN_MAX_BLOCKING_THREADS)).max_blocking_threads,
            MIN_MAX_BLOCKING_THREADS,
        );
        assert_eq!(
            RuntimeBudget::resolve(2, None, Some(9_000)).max_blocking_threads,
            9_000,
        );
    }

    #[test]
    fn the_floor_clears_what_actually_contends_for_the_pool() {
        // persist's read pool ceiling (8) + its writer, plus a
        // `block_in_place` replacement for every worker on edge's widest
        // production runtime (edge_node, 4).
        let persist_connections = 8 + 1;
        let widest_worker_count = 4;
        assert!(
            MIN_MAX_BLOCKING_THREADS >= persist_connections + widest_worker_count,
            "the floor must clear persist's connections plus block_in_place replacements",
        );
    }

    /// Exercises the real parser, not `resolve` with a hand-made `None`.
    #[test]
    fn the_parser_treats_junk_and_emptiness_as_unset() {
        let key = "CIRIS_RUNTIME_WORKERS";
        for junk in ["", "   ", "four", "2.5", "-1", "1e3", "8x", "0x10"] {
            assert_eq!(
                parse_budget(key, Some(junk)),
                None,
                "{junk:?} must not become a thread budget",
            );
        }

        // A real value parses, surrounding whitespace included — an export
        // in a deployment script often carries it.
        for (raw, want) in [("6", 6), (" 6 ", 6), ("\t8\n", 8), ("0", 0)] {
            assert_eq!(parse_budget(key, Some(raw)), Some(want), "{raw:?}");
        }

        assert_eq!(parse_budget(key, None), None, "an absent variable is unset");
    }
}
