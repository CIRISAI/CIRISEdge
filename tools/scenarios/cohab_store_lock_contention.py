"""Scenario: edge inbound verify against a persist reader, on one SQLite store.

Witness for the cross-wheel lost wakeup on persist's SQLite writer mutex: the
first `dispatch_inbound_bytes` after `init_edge_runtime` hung forever in
v45.0.0 / v45.0.2 at about 1 run in 20 under parallel load. Designed to be
driven by tools/race_repro.py:

    python3 tools/race_repro.py \\
      --scenario tools/scenarios/cohab_store_lock_contention.py \\
      --rounds 20 --timeout 40 --gdb-on-hang

Mechanism. `ciris_edge.abi3.so` and `ciris_persist.abi3.so` each statically
link `parking_lot_core`, whose waiter queue is a per-binary static. A concrete
persist backend lifted out of a capsule runs edge's COMPILED COPY of persist's
store code, so edge and the wheel take the same `parking_lot::Mutex` (the
SQLite writer) through two different queues. A thread that parks on
contention is never woken by an unlock from the other binary: the unlock finds
no waiter in its own queue and clears the parked bit, so the mutex is free and
the parked thread sleeps forever.

This scenario makes the contention constant instead of rare: one Python thread
loops `Engine.lookup_public_key` (persist's `.so` takes the writer of a
`sqlite::memory:` store), while the main thread loops freshly signed envelopes
through `dispatch_inbound_bytes` (each one's verify looks the sender's key up
on the same writer). On a wheel with the defect a dispatch or a persist read
parks for good within a second or two; the scenario then never exits and the
harness reports it hung. On a fixed wheel it runs `CONTEND_SECS` (default 5)
and prints a JSON line. It also exits 3 if the persist reader alone stops
making progress for 3 s while dispatches continue (the other direction of the
same defect).

Each envelope carries a fresh nonce, so each dispatch reaches the directory
lookup (a replayed envelope is refused before it).
"""
import ctypes
import ctypes.util
import base64
import json
import os
import platform
import secrets
import sys
import tempfile
import threading
import time


def _opt_in_ptrace() -> None:
    """Let the harness's `--gdb-on-hang` attach (Linux Yama ptrace_scope=1)."""
    if platform.system() != "Linux":
        return
    PR_SET_PTRACER = 0x59616D61
    PR_SET_PTRACER_ANY = ctypes.c_ulong(-1).value
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.prctl(PR_SET_PTRACER, ctypes.c_ulong(PR_SET_PTRACER_ANY), 0, 0, 0)


def main() -> int:
    _opt_in_ptrace()
    secs = float(os.environ.get("CONTEND_SECS", "5"))
    import ciris_persist as cp
    from ciris_edge.ciris_edge import init_edge_runtime

    seed = secrets.token_bytes(32)
    pqc_seed = secrets.token_bytes(32)
    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    pqc_path = os.path.join(d, "p")
    with open(seed_path, "wb") as f:
        f.write(seed)
    with open(pqc_path, "wb") as f:
        f.write(pqc_seed)
    identity_path = os.path.join(d, "t.id")
    with open(identity_path, "wb") as f:
        f.write(b"\x00" * 64)

    cp.reset_engine()
    k = "node-" + secrets.token_hex(8)
    engine = cp.Engine(
        "sqlite::memory:", k,
        local_key_id=k, local_key_path=seed_path,
        local_pqc_key_id=k + "-pqc", local_pqc_key_path=pqc_path,
    )
    kid = engine.register_self_federation_key("agent", "intake-ref", None, None, None)
    edge = init_edge_runtime(
        engine, identity_path,
        disable_reticulum=True,
        https_listen_addr="127.0.0.1:0",
        https_dev_self_signed=True,
    )
    dest = edge.signer_key_id()
    body = json.dumps({"kind": 7, "payload": base64.b64encode(b"intake").decode()})

    stop = threading.Event()
    reads = [0]

    def persist_reader() -> None:
        while not stop.is_set():
            engine.lookup_public_key(kid)
            reads[0] += 1

    threading.Thread(target=persist_reader, daemon=True).start()

    dispatches = 0
    t0 = time.monotonic()
    last_check = t0
    last_reads = -1
    stalled = 0
    while time.monotonic() - t0 < secs:
        env = edge.build_signed_inbound_envelope(kid, seed, dest, "OpaqueEvent", body, pqc_seed)
        outcome = edge.dispatch_inbound_bytes(env, "http")["outcome"]
        if outcome != "received":
            print(json.dumps({"error": "unexpected_outcome", "outcome": outcome}))
            return 4
        dispatches += 1
        now = time.monotonic()
        if now - last_check >= 1.0:
            last_check = now
            stalled = stalled + 1 if reads[0] == last_reads else 0
            last_reads = reads[0]
            if stalled >= 3:
                print(json.dumps({"error": "persist_reader_stalled",
                                  "dispatches": dispatches, "persist_reads": reads[0]}))
                sys.stdout.flush()
                os._exit(3)
    stop.set()
    print(json.dumps({"dispatches": dispatches, "persist_reads": reads[0]}))
    sys.stdout.flush()
    # Skip interpreter teardown: the reader thread may be inside a persist call.
    os._exit(0)


if __name__ == "__main__":
    sys.exit(main())
