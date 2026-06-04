//! Diagnostic helpers for the cohabitation harness.
//!
//! # When this module exists
//!
//! Gated under the `debug-tools` Cargo feature. Release wheels build
//! with the feature OFF and this module is not compiled — no panic
//! hook is installed, the `CIRIS_EDGE_PANIC_LOG` env var is never
//! read, and there is no FFI surface to enable any of it.
//!
//! Developer wheels for the `tools/race_repro.py` harness build with
//! `--features debug-tools` (and typically `--profile panic-debug`
//! for full DWARF). See `tools/README.md` for the workflow and
//! security posture.
//!
//! # What it captures (CIRISEdge#58 origin)
//!
//! The cohabitation harness drives wheels through Python subprocesses
//! that combine `ciris-edge`, `ciris-persist`, and `ciris-verify` into
//! one process. Tokio panics on background threads (most commonly
//! `"there is no reactor running"` from a `tokio::time::interval`
//! or `tokio::time::sleep_until` constructor called without a current
//! runtime) are caught by tokio's default panic hook, printed to
//! stderr, and silently dropped. The thread dies; the process keeps
//! going. The next operation on that subsystem either races to
//! success or hangs forever — making the failure mode invisible to
//! grep and impossible to attribute to a specific call site.
//!
//! This module installs an opt-in panic hook that captures every
//! panic with a (raw-IP) backtrace and writes a structured entry to a
//! per-pid log file. The default tokio behavior (print + continue)
//! is preserved by chaining the previous hook.
//!
//! # Usage from Python
//!
//! Set the env var `CIRIS_EDGE_PANIC_LOG=/path/to/edge-panic.log`
//! before importing `ciris_edge`. The pid is appended automatically
//! (or `{pid}` is expanded if present in the value). When the env
//! var is absent, the hook is not installed.
//!
//! On every panic the hook appends:
//!
//! ```text
//! === panic at unix_ms=<ms> === thread "<name>" (id <id>) ===
//! payload: <panic message>
//! location: <file>:<line>:<column>
//! backtrace (<n> lines):
//!   0: ip=0x…
//!   1: ip=0x…
//!   …
//! ============================================================
//! ```
//!
//! The raw IPs are resolved post-mortem with:
//!
//! ```bash
//! addr2line --exe <site-packages>/ciris_edge/ciris_edge.abi3.so \
//!   --functions --demangle 0x… 0x… …
//! ```
//!
//! Capture-time symbol resolution via `backtrace::Backtrace::new()`
//! is intentionally avoided — under cohabitation, the symbol
//! resolver aborts (not panics, so not catchable) when invoked
//! concurrently from two tokio background-thread panics. The
//! raw-IP path always succeeds; the post-mortem resolve step is
//! deterministic and matches the wheel's DWARF.
//!
//! # Counter
//!
//! [`PANIC_COUNT`] is a per-process atomic counter incremented for
//! every captured panic. Exposed to Python as `ciris_edge.panic_count()`.
//! Useful to detect "did any background-thread panic happen during
//! this operation" without parsing the log file.

use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, Once};

/// Process-wide counter of captured panics. Caller-readable via
/// `ciris_edge.panic_count()` from Python.
pub static PANIC_COUNT: AtomicU64 = AtomicU64::new(0);

static INIT: Once = Once::new();
static WRITE_GUARD: Mutex<()> = Mutex::new(());

/// Install the panic-logging hook if `CIRIS_EDGE_PANIC_LOG` is set.
/// Safe to call multiple times; only the first call installs.
///
/// Returns `true` if the hook is active (or already installed in a
/// prior call), `false` if the env var was absent.
pub fn install_panic_logger() -> bool {
    let Ok(raw_path) = std::env::var("CIRIS_EDGE_PANIC_LOG") else {
        return false;
    };

    INIT.call_once(|| {
        // {pid} placeholder expansion. Default appends ".{pid}" if no
        // placeholder is present — keeps multi-process harness runs
        // from overwriting each other's logs.
        let path = if raw_path.contains("{pid}") {
            raw_path.replace("{pid}", &std::process::id().to_string())
        } else {
            format!("{raw_path}.{}", std::process::id())
        };

        // Touch the file at install time so the harness can find it
        // immediately (even before any panic fires).
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path);

        let previous_hook = std::panic::take_hook();

        std::panic::set_hook(Box::new(move |info| {
            // CRITICAL: do NOT eprintln! from inside this hook. In
            // the cohabitation harness, concurrent background-thread
            // panics + Python's stdio locks can deadlock on stderr.
            // The hook MUST be file-only. `previous_hook(info)` at
            // the end of this closure is what fires tokio's default
            // stderr line; we don't second-guess it.
            PANIC_COUNT.fetch_add(1, Ordering::Relaxed);

            let thread = std::thread::current();
            let thread_name = thread.name().unwrap_or("<unnamed>").to_string();
            let thread_id = format!("{:?}", thread.id());

            let location = info.location().map_or_else(
                || "<unknown>".to_string(),
                |l| format!("{}:{}:{}", l.file(), l.line(), l.column()),
            );

            let payload = info
                .payload()
                .downcast_ref::<&str>()
                .copied()
                .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
                .unwrap_or("<non-string payload>")
                .to_string();

            // Raw-IP capture. `backtrace::Backtrace::new()` (which
            // calls the symbol resolver at capture time) aborts in
            // our cohab context — see module-level docs.
            // `backtrace::trace` walks the unwinder without touching
            // the symbol DB and is robust under concurrent panic.
            //
            // Each frame is also converted to a `<basename>+<offset>`
            // form via `dladdr` (libc) so the harness can run
            // `addr2line --exe <basename> <offset>` post-mortem
            // without needing the process's ASLR base from /proc/maps.
            // `dladdr` is signal-safe and present on every glibc /
            // musl / macOS dyld build path — no extra dep.
            let mut bt_text = String::with_capacity(2048);
            let mut frame_idx = 0usize;
            backtrace::trace(|frame| {
                let ip = frame.ip();
                let mut info: libc::Dl_info = unsafe { std::mem::zeroed() };
                let dl_ok = unsafe { libc::dladdr(ip.cast::<libc::c_void>(), &mut info) };
                if dl_ok != 0 && !info.dli_fname.is_null() && !info.dli_fbase.is_null() {
                    let fname_cstr = unsafe { std::ffi::CStr::from_ptr(info.dli_fname) };
                    let fname = fname_cstr.to_string_lossy();
                    let basename = std::path::Path::new(fname.as_ref())
                        .file_name()
                        .map_or_else(|| "?".to_string(), |b| b.to_string_lossy().into_owned());
                    let offset = (ip as usize).wrapping_sub(info.dli_fbase as usize);
                    let _ = std::fmt::Write::write_fmt(
                        &mut bt_text,
                        format_args!("  {frame_idx:3}: ip={ip:p}  {basename}+0x{offset:x}\n"),
                    );
                } else {
                    let _ = std::fmt::Write::write_fmt(
                        &mut bt_text,
                        format_args!("  {frame_idx:3}: ip={ip:p}  <dladdr failed>\n"),
                    );
                }
                frame_idx += 1;
                frame_idx < 80 // cap at 80 frames
            });

            // SystemTime + UNIX_EPOCH instead of chrono — chrono's
            // RFC3339 formatting hits thread-local timezone state
            // that can corrupt under cohabitation panicking. Plain
            // Unix-millis is sufficient for log correlation; the
            // harness layer can do human-readable conversion.
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_millis());

            let entry = format!(
                "\n=== panic at unix_ms={now_ms} === thread {thread_name:?} (id {thread_id}) ===\n\
                 payload: {payload}\n\
                 location: {location}\n\
                 backtrace ({frame_idx} frames):\n{bt_text}\
                 ============================================================\n",
            );

            // Re-open the file each panic — simpler and decoupled from
            // any Mutex<Option<File>> state. Mutex<()> guards the
            // open+write+flush sequence so concurrent panics don't
            // interleave; O_APPEND gives kernel-level write
            // serialization as a fallback. All paths silent on
            // failure: the panic count and tokio's chained stderr
            // line still surface the event.
            if let Ok(_guard) = WRITE_GUARD.lock() {
                if let Ok(mut file) = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(&path)
                {
                    let _ = file.write_all(entry.as_bytes());
                    let _ = file.flush();
                }
            }

            // Chain to the previous hook so default behavior (stderr,
            // panic propagation under panic=unwind) still fires.
            previous_hook(info);
        }));
    });

    true
}
