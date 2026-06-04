#!/usr/bin/env bash
# debug_attach.sh — rust-gdb batch-mode all-thread backtrace against a running pid.
#
# Use this when a subprocess (typically driven by tools/race_repro.py)
# hangs and you want a snapshot of every thread's call stack to figure
# out where the deadlock or missed wakeup is. Works best against a
# wheel built with `[profile.panic-debug]` (see Cargo.toml) so DWARF
# symbols are present; on a stripped release wheel you get addresses
# you can post-process with `addr2line --exe target/.../*.so`.
#
# Usage:
#   tools/debug_attach.sh <pid>
#   tools/debug_attach.sh <pid> <output-file>
#
# Requires ONE of:
#   - kernel.yama.ptrace_scope=0 (system-wide; `sudo sysctl kernel.yama.ptrace_scope=0`)
#   - sudo / CAP_SYS_PTRACE on the harness
#   - The target called prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)
#     (race_repro.py does NOT do this by default; add it to your
#     scenario via `prctl.set_ptracer(prctl.SET_PTRACER_ANY)` from the
#     python-prctl package if you want non-sudo attach).
#
# Tokio-noise filter:
#   Set CIRIS_GDB_FILTER_TOKIO=1 to grep -v lines mentioning tokio
#   internals (poll, runtime, scheduler) — useful when chasing a
#   user-code deadlock through the runtime layer. Default off.

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "usage: $0 <pid> [output-file]" >&2
    exit 2
fi

PID="$1"
OUT="${2:-/tmp/edge-gdb-${PID}-$(date +%s).txt}"

if [[ ! -d "/proc/$PID" ]]; then
    echo "no such process: pid=$PID" >&2
    exit 1
fi

GDB="$(command -v rust-gdb || command -v gdb || true)"
if [[ -z "$GDB" ]]; then
    echo "neither rust-gdb nor gdb found in PATH" >&2
    exit 1
fi

# Sniff the target wheel's debug-info richness so the harness output
# tells us up-front whether to expect resolved symbols or hex addresses.
SO_PATH=$(awk '/ciris_edge\.abi3\.so/{print $NF; exit}' "/proc/$PID/maps" 2>/dev/null || true)
if [[ -n "$SO_PATH" ]]; then
    DEBUG_KIND=$(file "$SO_PATH" 2>/dev/null | grep -oE "(not stripped|with debug_info|stripped)" | head -1 || echo "unknown")
    echo "[debug_attach] target ciris_edge.so: $SO_PATH" >&2
    echo "[debug_attach] debug info: $DEBUG_KIND" >&2
    if [[ "$DEBUG_KIND" == "stripped" ]]; then
        echo "[debug_attach] WARNING: wheel is stripped; backtraces will be addresses" >&2
        echo "[debug_attach]          rebuild with 'maturin build --profile panic-debug --skip-auditwheel'" >&2
    fi
fi

# Batch-mode gdb script. `set pagination off` + `set print thread-events off`
# keep the output deterministic; `info threads` + `thread apply all bt 80`
# is the canonical "where is every thread blocked".
"$GDB" \
    -batch -quiet \
    -ex "set pagination off" \
    -ex "set print thread-events off" \
    -ex "set verbose off" \
    -ex "attach $PID" \
    -ex "info threads" \
    -ex "thread apply all bt 80" \
    -ex "detach" \
    -ex "quit" \
    2> "$OUT.stderr" > "$OUT.raw" || true

# Filter the dump to one consolidated file. Drop the obvious gdb noise.
{
    echo "=== debug_attach.sh dump for pid=$PID at $(date -Iseconds) ==="
    echo
    if [[ -n "${SO_PATH:-}" ]]; then
        echo "ciris_edge.so: $SO_PATH"
        echo "debug info   : ${DEBUG_KIND:-unknown}"
        echo
    fi
    grep -v -E "^Reading symbols|^Downloading|^\[New|^\[Switching|^Stopped due to|^Detaching from|^\[Inferior" "$OUT.raw" || cat "$OUT.raw"
} > "$OUT"
rm -f "$OUT.raw"

if [[ -s "$OUT.stderr" ]]; then
    echo "--- gdb stderr ---" >> "$OUT"
    cat "$OUT.stderr" >> "$OUT"
fi
rm -f "$OUT.stderr"

if [[ "${CIRIS_GDB_FILTER_TOKIO:-0}" == "1" ]]; then
    grep -v -E "tokio::runtime|tokio::task|tokio::sync|tokio::io|tokio::loom|tokio::macros|tokio::time::driver|tokio::time::wheel" "$OUT" > "$OUT.filtered"
    mv "$OUT.filtered" "$OUT"
    echo "[debug_attach] tokio-internal frames filtered" >&2
fi

echo "$OUT"
