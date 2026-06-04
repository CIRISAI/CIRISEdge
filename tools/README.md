# Debugging harness — cohabitation races, hangs, and background-thread panics

When a cohabitation symptom is "subprocess sometimes returns fast, sometimes
hangs with empty stderr," the source is usually a tokio background thread
panicking silently (default panic hook: print stderr, drop thread, continue
process) and leaving its subsystem half-initialized for the next call to race
into. This directory has the toolchain to find these:

- A Rust panic hook in `src/debug/mod.rs` that captures every background-thread
  panic with a symbol-resolved backtrace, opt-in via env var
- A Cargo profile `panic-debug` (in root `Cargo.toml`) that keeps full DWARF
  symbols so backtraces resolve
- A Python harness `race_repro.py` that drives a scenario over N subprocess
  rounds, classifies each outcome (fast / hung / panicked / other), and
  surfaces every signal we can capture
- A gdb wrapper `debug_attach.sh` for the case where you want a live snapshot
  of every thread's call stack in a hung process

The harness is **two-layer opt-in** with strict security posture:

1. **`debug-tools` Cargo feature** (default OFF) — `src/debug/` is not
   compiled at all. The `panic_count` and `install_panic_logger`
   pyfunctions don't exist on the module. The `CIRIS_EDGE_PANIC_LOG`
   string isn't even *present* in the binary — there's no env var to
   inject. Release wheels published to PyPI build without this feature
   and carry **zero diagnostic surface**.
2. **`CIRIS_EDGE_PANIC_LOG` env var** (only consulted when the feature
   is ON) — the panic hook installs only when this is set. So even a
   developer panic-debug wheel is silent at runtime unless the env var
   is explicitly exported.

Verification:

```bash
# Production wheel (no debug-tools):
nm ciris_edge.abi3.so | grep -c panic_count          # → 0
nm ciris_edge.abi3.so | grep -c install_panic_logger # → 0
strings ciris_edge.abi3.so | grep -c CIRIS_EDGE_PANIC_LOG  # → 0
```

## Quick start — reproduce CIRISEdge#58 / CIRISPersist#139

```bash
# 1. Stand up a local postgres
docker run -d --name conformance-pg \
  -e POSTGRES_USER=postgres \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=conformance \
  -p 5433:5432 \
  postgres:16

# 2. Build a panic-debug wheel (~80s build; ~500MB .so — debug info is
#    huge but the wheel is dev-only). The `--strip false` override is
#    REQUIRED — pyproject.toml's [tool.maturin] sets strip=true for
#    release wheels, which would otherwise drop the debug info maturin
#    is meant to preserve under panic-debug. The `debug-tools` feature
#    enables the in-process panic hook + dladdr resolution.
maturin build --profile panic-debug \
  --features "pyo3 extension-module transport-http debug-tools" \
  --skip-auditwheel \
  --strip false \
  --include-debuginfo

# 3. Install into a clean venv
python3 -m venv /tmp/edge-debug && source /tmp/edge-debug/bin/activate
pip install --force-reinstall \
  target/wheels/ciris_edge-*-linux_x86_64.whl \
  ciris-persist==3.12.1 \
  ciris-verify==4.8.0

# 4. Run the harness with panic capture armed
python3 tools/race_repro.py \
  --scenario tools/scenarios/durable_send_postgres.py \
  --rounds 40 \
  --timeout 8 \
  --panic-log /tmp/edge-panic.log \
  --run-async-stall-ms 5000 \
  --out /tmp/edge-race-manifest.json
```

The harness prints a one-line summary per round and a structured summary at
the end. Every panic captured by the in-process hook is written to
`/tmp/edge-panic.log.{pid}` per subprocess — fully symbolicated under the
panic-debug profile.

## What the harness captures (and when)

| Signal | Captured by | Wheel build | Notes |
|---|---|---|---|
| Subprocess returncode + stdout + stderr | `race_repro.py` | any | Default; always on. |
| `panicked at <file>:<line>` first line | `race_repro.py` (stderr classifier) | any | What tokio's default hook prints. |
| Resolved-symbol backtrace for every panic | `src/debug/mod.rs` panic hook | **panic-debug** for symbols | `CIRIS_EDGE_PANIC_LOG=…` arms; release-strip wheel gives addresses. |
| Live all-thread call stacks at hang time | `tools/debug_attach.sh` | **panic-debug** for symbols | Needs `--gdb-on-hang` + ptrace permission. |
| Stall warning for `run_async` calls | wheel built-in | any | `CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS=5000`. Emits via tracing — only visible if a tracing subscriber is wired (Python wheels don't wire one by default; rely on the gdb / panic-log paths instead). |

## When to use which

- **First-time triage of a race or hang.** Start with `race_repro.py` against
  a scenario script. The classifier tells you fast/hung/panicked counts; the
  manifest JSON gives you per-round outcomes for later analysis.
- **"Why does this background thread panic?"** Build a panic-debug wheel and
  set `CIRIS_EDGE_PANIC_LOG`. Every panic gets a resolved backtrace pointing
  at the call site that constructed a timer outside a runtime context (the
  most common shape for our cohabitation panics).
- **"Why does this subprocess hang with no panic?"** Use `--gdb-on-hang` so
  the harness invokes `debug_attach.sh` automatically on every hung
  subprocess. The all-thread backtrace tells you what every worker is parked
  on — usually a futex with one thread in `ep_poll` (IO driver) and the rest
  waiting for a wakeup that isn't coming. Cross-reference with the panic log:
  if a panic preceded the hang, the dead thread is usually the wakeup source.

## ptrace permission

Linux distros default to `kernel.yama.ptrace_scope=1`, which means only the
direct parent of a process can ptrace it. `race_repro.py` IS the direct
parent of every scenario subprocess, so it can attach without sudo:

```bash
# By default
python3 tools/race_repro.py … --gdb-on-hang
```

If you're attaching from outside the harness (e.g. by hand to a running
process), you need either:

- `sudo sysctl kernel.yama.ptrace_scope=0` (system-wide; persists until reboot
  or until you set it back to 1)
- `sudo` on the gdb invocation
- The target opted in via `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` (you'd
  add `import prctl; prctl.set_ptracer(prctl.SET_PTRACER_ANY)` to the
  scenario script's preamble)

## Filtering tokio noise

Backtraces through tokio's runtime are long — a single `.await` adds 10+
scheduler frames. Two filters are wired in:

- `RUST_BACKTRACE=short,exclude=tokio::*` (Rust 1.80+) — drops tokio internal
  frames from the panic backtrace
- `CIRIS_GDB_FILTER_TOKIO=1` env var for `debug_attach.sh` — drops
  tokio-internal lines from the gdb dump

Both default off. Turn them on once you've confirmed the noise is in fact
tokio internals and not load-bearing application code in the trace.

## Building a panic-debug wheel into the conformance harness

For a one-off cohab debug pass against an under-test wheel:

```bash
maturin build --profile panic-debug \
  --features "pyo3 extension-module transport-http debug-tools" \
  --skip-auditwheel \
  --strip false \
  --include-debuginfo

# Use that wheel for the conformance test with CIRIS_EDGE_PANIC_LOG set:
CIRIS_EDGE_PANIC_LOG=/tmp/edge-panic.log \
  pytest tests/test_050_send_receive.py -xvs
```

`CIRIS_EDGE_PANIC_LOG` is read at module-import time by the wheel's
`#[pymodule]` init in `src/ffi/pyo3.rs`. As long as the env var is set
**before** `import ciris_edge`, every panic in the rest of the process gets
captured. Conformance's per-test fresh-subprocess pattern guarantees this
ordering naturally.

## Architecture, briefly

```
race_repro.py ─┐
               ├─ subprocess (clean venv, env vars set)
               │     │
               │     └── ciris_edge wheel
               │              │
               │              ├── #[cfg(feature = "debug-tools")] code path
               │              │   (compiled OUT of release wheels — zero surface)
               │              │
               │              ├── on `import ciris_edge`:
               │              │   reads CIRIS_EDGE_PANIC_LOG (only if feature on)
               │              │     └── debug::install_panic_logger()
               │              │         └── std::panic::set_hook(…)
               │              │             └── per panic:
               │              │                 ├── PANIC_COUNT++ (atomic, lock-free)
               │              │                 ├── backtrace::trace() raw IPs
               │              │                 ├── libc::dladdr() → <basename>+<offset>
               │              │                 └── append entry → /tmp/edge-panic.log.{pid}
               │              │
               │              └── PyEdge::send_…  → run_async  → runtime.spawn(fut)
               │                                       │
               │                                       └── stall watchdog (always-on; env-controlled)
               │
               └─ debug_attach.sh on hang (rust-gdb -batch -ex 't a a bt')
```

Symbol resolution flow (post-mortem, deterministic):

```
panic-log entry: "  3: ip=0x7a4e…  ciris_edge.abi3.so+0x1a78"
                                                       ─┬──
                                                        └── offset within the .so
                                                            (computed at capture via dladdr)
                                                            ↓
addr2line --exe <wheel>/ciris_edge/ciris_edge.abi3.so 0x1a78
  → ciris_edge::debug::install_panic_logger::{{closure}} at src/debug/mod.rs:184
```

The wheel's runtime overhead from this machinery is **zero** in the
default (no-feature) build — none of this code is in the binary.
With the feature enabled, the panic hook is still a no-op until
`CIRIS_EDGE_PANIC_LOG` is exported. The `run_async` stall watchdog
is independent of `debug-tools` and gated only by its own env var.

## References

- [Agoda Engineering — Debugging a Rust Service Deadlock with GDB](https://medium.com/agoda-engineering/when-the-profiler-becomes-the-problem-debugging-a-rust-service-deadlock-with-gdb-95fc186b6aca)
  — the `[profile.release] debug = true` pattern + `rust-gdb -p PID -batch -ex 't a a bt'`
  workflow this harness builds on.
- [wg-async — Async Stack Traces design doc](https://rust-lang.github.io/wg-async/design_docs/async_stack_traces.html)
  — why tokio doesn't yet have first-class goroutine-style backtraces;
  why panic hooks + tracing-spans remain the canonical tool for now.
- [`std::panic::set_hook`](https://doc.rust-lang.org/std/panic/fn.set_hook.html)
  — the API our hook wraps.
- CIRISEdge#58 / CIRISPersist#139 — the use-case this harness was designed
  to crack.
