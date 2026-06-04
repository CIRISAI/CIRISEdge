#!/usr/bin/env python3
"""
CIRISEdge race / hang diagnostic harness.

Drives a user-supplied scenario script in N fresh Python subprocesses,
detects races (mixed pass/fail/timeout outcomes) and hangs (>timeout),
and surfaces every signal we can capture without flaky guesswork:

  - Subprocess returncode + stdout + stderr
  - Background-thread panic backtraces (via the in-process panic hook
    if CIRIS_EDGE_PANIC_LOG is exported and the wheel was built with
    `panic-debug` profile so symbols resolve)
  - Optional: rust-gdb batch-mode all-thread backtrace on hung
    subprocesses (--gdb-on-hang; needs kernel.yama.ptrace_scope=0 or
    sudo)
  - Optional: tokio `run_async` stall watchdog from inside the wheel
    (CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS), captured via stderr stream

Typical use:

    # Race against postgres durable send (CIRISEdge#58 / Persist#139)
    docker run -d --name conformance-pg -e POSTGRES_USER=postgres \\
      -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=conformance \\
      -p 5433:5432 postgres:16

    python3 tools/race_repro.py \\
      --scenario tools/scenarios/durable_send_postgres.py \\
      --rounds 40 --timeout 8 \\
      --panic-log /tmp/edge-panic.log

Build a panic-debug wheel for full symbols (default release strips):

    maturin build --profile panic-debug \\
      --features "pyo3 extension-module transport-http" \\
      --skip-auditwheel
    pip install --force-reinstall \\
      target/wheels/ciris_edge-*-linux_x86_64.whl

The harness writes a per-run summary + dumps every captured panic +
saves a JSON manifest of all rounds for later analysis.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class Round:
    index: int
    returncode: int | None
    wall_ms: float
    stdout: str
    stderr: str
    timed_out: bool
    panic_log_delta: str = ""  # appended panic-log entries this round
    gdb_dump: str = ""  # rust-gdb dump if --gdb-on-hang triggered


@dataclass
class Summary:
    fast: int = 0
    hung: int = 0
    panicked: int = 0
    other_failures: int = 0
    timings_ms: list[float] = field(default_factory=list)
    rounds: list[Round] = field(default_factory=list)


def find_rust_gdb() -> str | None:
    return shutil.which("rust-gdb") or shutil.which("gdb")


def gdb_dump(pid: int, gdb_path: str) -> str:
    """Batch-mode 'thread apply all bt' against pid.

    Returns the captured stdout/stderr. Requires either
    `kernel.yama.ptrace_scope=0` or the harness running as root /
    with CAP_SYS_PTRACE.
    """
    try:
        proc = subprocess.run(
            [
                gdb_path,
                "-batch",
                "-quiet",
                "-ex", "set pagination off",
                "-ex", "set print thread-events off",
                "-ex", f"attach {pid}",
                "-ex", "info threads",
                "-ex", "thread apply all bt 80",
                "-ex", "detach",
                "-ex", "quit",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        return f"--- gdb stdout ---\n{proc.stdout}\n--- gdb stderr ---\n{proc.stderr}"
    except subprocess.TimeoutExpired:
        return "[gdb timed out after 30s]"
    except FileNotFoundError:
        return f"[gdb not found at {gdb_path}]"


def read_panic_log_delta(path: Path, last_size: int) -> tuple[str, int]:
    """Read appended bytes since the last position; returns (text, new_size)."""
    if not path.exists():
        return "", last_size
    new_size = path.stat().st_size
    if new_size <= last_size:
        return "", new_size
    with path.open("r") as f:
        f.seek(last_size)
        return f.read(), new_size


def run_one_round(
    args: argparse.Namespace,
    index: int,
    panic_log_path: Path | None,
    panic_log_size: int,
    gdb_path: str | None,
) -> Round:
    env = dict(os.environ)
    if panic_log_path is not None:
        # The Rust hook expands {pid} → actual pid; we strip that
        # placeholder here so all subprocesses write to the SAME parent
        # file (we already namespace by subprocess pid via the env).
        env["CIRIS_EDGE_PANIC_LOG"] = str(panic_log_path)
    if args.run_async_stall_ms is not None:
        env["CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS"] = str(args.run_async_stall_ms)
    env["RUST_BACKTRACE"] = args.backtrace

    started = time.perf_counter()
    proc = subprocess.Popen(
        [sys.executable, args.scenario],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        stdout, stderr = proc.communicate(timeout=args.timeout)
        wall_ms = (time.perf_counter() - started) * 1000
        # Panic-log delta capture.
        if panic_log_path is not None:
            # Look for any *.{pid} file the subprocess wrote.
            sibling = panic_log_path.with_name(panic_log_path.name + f".{proc.pid}")
            panic_delta, _ = read_panic_log_delta(sibling, 0)
        else:
            panic_delta = ""
        return Round(
            index=index,
            returncode=proc.returncode,
            wall_ms=wall_ms,
            stdout=stdout,
            stderr=stderr,
            timed_out=False,
            panic_log_delta=panic_delta,
        )
    except subprocess.TimeoutExpired:
        wall_ms = (time.perf_counter() - started) * 1000
        # On hang: optionally attach gdb BEFORE killing.
        gdb_text = ""
        if args.gdb_on_hang and gdb_path is not None:
            gdb_text = gdb_dump(proc.pid, gdb_path)

        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            stdout, stderr = "", "[stderr unreadable after kill]"

        if panic_log_path is not None:
            sibling = panic_log_path.with_name(panic_log_path.name + f".{proc.pid}")
            panic_delta, _ = read_panic_log_delta(sibling, 0)
        else:
            panic_delta = ""

        return Round(
            index=index,
            returncode=None,
            wall_ms=wall_ms,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
            panic_log_delta=panic_delta,
            gdb_dump=gdb_text,
        )


def classify(r: Round) -> str:
    if r.timed_out:
        return "hung"
    if r.returncode == 0 and (r.stdout or "").strip():
        return "fast"
    if "panicked" in (r.stderr or "") or "no reactor running" in (r.stderr or ""):
        return "panicked"
    return "other_failure"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CIRISEdge race/hang diagnostic harness",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--scenario", required=True, type=Path,
                        help="path to a scenario script (single-shot subprocess)")
    parser.add_argument("--rounds", type=int, default=30,
                        help="number of subprocess rounds (default 30)")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="per-round subprocess timeout in seconds (default 8)")
    parser.add_argument("--panic-log", type=Path, default=None,
                        help="parent path for CIRIS_EDGE_PANIC_LOG; .{pid} suffix added per subprocess")
    parser.add_argument("--run-async-stall-ms", type=int, default=None,
                        help="set CIRIS_EDGE_RUN_ASYNC_STALL_WARN_MS to control the stall watchdog")
    parser.add_argument("--backtrace", default="1",
                        choices=["0", "1", "full", "short"],
                        help="RUST_BACKTRACE value (default 1)")
    parser.add_argument("--gdb-on-hang", action="store_true",
                        help="rust-gdb attach + 'thread apply all bt' on every hung subprocess")
    parser.add_argument("--out", type=Path, default=None,
                        help="optional JSON manifest output path")
    args = parser.parse_args()

    if not args.scenario.exists():
        print(f"scenario not found: {args.scenario}", file=sys.stderr)
        return 2

    gdb_path = find_rust_gdb() if args.gdb_on_hang else None
    if args.gdb_on_hang and gdb_path is None:
        print("warning: --gdb-on-hang requested but rust-gdb / gdb not found in PATH",
              file=sys.stderr)

    summary = Summary()
    panic_size = 0

    print(f"running {args.rounds} rounds; timeout={args.timeout}s; scenario={args.scenario}")
    if args.panic_log:
        print(f"panic log parent: {args.panic_log} (per-pid suffix added by Rust hook)")
    if args.gdb_on_hang:
        print(f"gdb-on-hang armed via {gdb_path}")
    print()

    for i in range(args.rounds):
        r = run_one_round(args, i, args.panic_log, panic_size, gdb_path)
        klass = classify(r)
        if klass == "fast":
            summary.fast += 1
            summary.timings_ms.append(r.wall_ms)
            print(f"  [{i:02d}] OK     ({r.wall_ms:>6.0f}ms)")
        elif klass == "hung":
            summary.hung += 1
            print(f"  [{i:02d}] HANG   ({r.wall_ms:>6.0f}ms)")
        elif klass == "panicked":
            summary.panicked += 1
            last_panic = (r.stderr.strip().splitlines() or [""])[-1][:120]
            print(f"  [{i:02d}] PANIC  ({r.wall_ms:>6.0f}ms)  {last_panic}")
        else:
            summary.other_failures += 1
            tail = (r.stderr.strip().splitlines() or [""])[-1][:120]
            print(f"  [{i:02d}] FAIL   rc={r.returncode}  {tail}")
        summary.rounds.append(r)

    print()
    print("=== summary ===")
    print(f"  fast    : {summary.fast}")
    print(f"  hung    : {summary.hung}")
    print(f"  panic   : {summary.panicked}")
    print(f"  other   : {summary.other_failures}")
    if summary.timings_ms:
        t = sorted(summary.timings_ms)
        n = len(t)
        print(f"  timing  : min={t[0]:.0f}ms p50={t[n // 2]:.0f}ms "
              f"p95={t[int(n * 0.95)]:.0f}ms max={t[-1]:.0f}ms")

    # Surface the first panic / hang with full context.
    first_panic = next((r for r in summary.rounds if r.panic_log_delta or "panicked" in (r.stderr or "")), None)
    if first_panic:
        print()
        print(f"=== first panic-bearing round ({first_panic.index}) ===")
        if first_panic.panic_log_delta:
            print("--- panic log entry (symbol-resolved if panic-debug wheel) ---")
            print(first_panic.panic_log_delta)
        if "panicked" in (first_panic.stderr or ""):
            print("--- stderr panic lines ---")
            print(
                "\n".join(
                    line for line in first_panic.stderr.splitlines()
                    if "panic" in line.lower() or "reactor" in line.lower()
                )[:4000]
            )

    first_hang = next((r for r in summary.rounds if r.timed_out), None)
    if first_hang:
        print()
        print(f"=== first hang ({first_hang.index}) ===")
        print(f"stderr len={len(first_hang.stderr)}; stdout len={len(first_hang.stdout)}")
        if first_hang.gdb_dump:
            print("--- gdb 'thread apply all bt' ---")
            print(first_hang.gdb_dump[:8000])
        elif first_hang.stderr:
            print("--- last 20 stderr lines ---")
            print("\n".join(first_hang.stderr.splitlines()[-20:]))

    if args.out:
        # JSON-safe serialization.
        data = {
            "scenario": str(args.scenario),
            "rounds_total": args.rounds,
            "timeout_s": args.timeout,
            "fast": summary.fast,
            "hung": summary.hung,
            "panicked": summary.panicked,
            "other_failures": summary.other_failures,
            "rounds": [
                {
                    "index": r.index,
                    "returncode": r.returncode,
                    "wall_ms": r.wall_ms,
                    "timed_out": r.timed_out,
                    "stdout_len": len(r.stdout),
                    "stderr_len": len(r.stderr),
                    "stderr_tail": "\n".join(r.stderr.splitlines()[-10:]),
                    "panic_log_present": bool(r.panic_log_delta),
                    "gdb_dump_present": bool(r.gdb_dump),
                }
                for r in summary.rounds
            ],
        }
        args.out.write_text(json.dumps(data, indent=2))
        print(f"\nmanifest written to {args.out}")

    return 0 if summary.hung == 0 and summary.panicked == 0 and summary.other_failures == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
