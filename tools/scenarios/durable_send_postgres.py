"""Scenario: single send_durable_inline_text against postgres.

Reproduces CIRISEdge#58 / CIRISPersist#139 — intermittent hang in the
postgres durable-send path with sub-25% rate. Designed to be driven
by tools/race_repro.py.

Expects: postgres reachable at $CIRIS_REPRO_DSN
(default postgres://postgres:postgres@localhost:5433/conformance).

On Linux, the subprocess opts into PR_SET_PTRACER_ANY via libc.prctl
at the very start of main() so the harness's `--gdb-on-hang` can
attach without `kernel.yama.ptrace_scope=0` / sudo. No effect on
macOS / Windows.
"""
import ctypes
import ctypes.util
import json
import os
import platform
import secrets
import sys
import tempfile


def _opt_in_ptrace() -> None:
    """Allow non-parent ptrace attach.

    Linux's Yama LSM defaults `kernel.yama.ptrace_scope=1`, meaning only
    a direct parent can ptrace this process. Calling
    `prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY)` from inside the tracee
    relaxes that to "any process with the same uid". Required so the
    harness's `tools/debug_attach.sh` (and `race_repro.py --gdb-on-hang`)
    can attach to capture all-thread backtraces during a hang.
    """
    if platform.system() != "Linux":
        return
    PR_SET_PTRACER = 0x59616D61          # 1499766118
    PR_SET_PTRACER_ANY = ctypes.c_ulong(-1).value  # libc uses (unsigned long)-1
    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    libc = ctypes.CDLL(libc_name, use_errno=True)
    libc.prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)

DB = os.environ.get(
    "CIRIS_REPRO_DSN",
    "postgres://postgres:postgres@localhost:5433/conformance",
)


def stamp(phase: str) -> None:
    """Emit a phase marker so the harness can localize a hang to a step."""
    import time
    print(f"PHASE {time.perf_counter() * 1000:.1f}ms {phase}", file=sys.stderr, flush=True)


def main() -> None:
    _opt_in_ptrace()
    stamp("python_start")
    import ciris_persist as cp
    stamp("import_persist")
    from ciris_edge.ciris_edge import init_edge_runtime
    stamp("import_edge")

    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    open(seed_path, "wb").write(secrets.token_bytes(32))
    idp = os.path.join(d, "t.id")
    open(idp, "wb").write(b"\x00" * 64)

    cp.reset_engine()
    key_id = "d-" + secrets.token_hex(8)

    stamp("pre_engine")
    engine = cp.Engine(DB, key_id, local_key_id=key_id, local_key_path=seed_path)
    stamp("post_engine")

    kid = engine.register_federation_key("agent", "ref", None, None, None)
    stamp("post_register_key")

    edge = init_edge_runtime(engine, idp, listen_addr="127.0.0.1:0")
    stamp("post_init_edge_runtime")

    handle = edge.send_durable_inline_text(kid, "race-probe")
    stamp("post_send_durable")

    payload = {
        "durable_returned": type(handle).__name__,
    }
    # Capture the wheel's panic count if the build exposes it (v1.1.7+).
    import ciris_edge
    if hasattr(ciris_edge, "panic_count"):
        payload["panic_count"] = ciris_edge.panic_count()

    print(json.dumps(payload))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
