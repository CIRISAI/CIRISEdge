"""Scenario: two two-wheel nodes over Reticulum on loopback, under persist-side
store contention (CIRISEdge#988).

The complete fix moved three views off edge's compiled copy of persist's store
code onto persist's directory-ops capsule: Reticulum rooting (announce
handling: key lookups and the transport-binding write-through), the blackhole
rules (read on every send) and the edge-detection writer. Nothing else drives
them across two separately built wheels. This scenario runs two processes,
each loading the `ciris_persist` and `ciris_edge` wheels side by side:

- each node registers its key, learns the other's key row, and comes up with
  Reticulum on loopback (`listen_addr` 127.0.0.1, the other as its bootstrap
  peer, a short announce interval), so each handles the other's announces;
- a thread in each process loops `Engine.lookup_public_key` (persist's own
  library takes the store lock) for the whole run;
- each node sends opaque events to the other (the send path reads the
  blackhole rules) for `CONTEND_SECS`.

A node that hangs never prints its report: the parent's timeout reports it.
A node exits 3 if its persist reader stops progressing for 3 s while it is
otherwise alive (the other direction of the lost wakeup).

The edge-detection writer is NOT reachable from a binding process: the
binding builds its `EdgeConfig` with `probe_pattern_observer_enabled = false`
and exposes no switch, so no detection event is written; the scenario says so
in its report rather than claiming coverage.

    python3 tools/scenarios/cohab_reticulum_two_node.py            # parent
"""
import base64
import ctypes
import ctypes.util
import json
import os
import platform
import secrets
import socket
import subprocess
import sys
import tempfile
import threading
import time


def _opt_in_ptrace() -> None:
    if platform.system() != "Linux":
        return
    libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
    libc.prctl(0x59616D61, ctypes.c_ulong(ctypes.c_ulong(-1).value), 0, 0, 0)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def wait_for(path: str, deadline: float) -> str:
    while time.monotonic() < deadline:
        if os.path.exists(path):
            with open(path) as f:
                data = f.read()
            if data:
                return data
        time.sleep(0.05)
    raise TimeoutError(path)


def node(role: str, shared: str, my_port: int, peer_port: int) -> int:
    _opt_in_ptrace()
    secs = float(os.environ.get("CONTEND_SECS", "8"))
    import ciris_persist as cp
    from ciris_edge.ciris_edge import init_edge_runtime

    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    pqc_path = os.path.join(d, "p")
    with open(seed_path, "wb") as f:
        f.write(secrets.token_bytes(32))
    with open(pqc_path, "wb") as f:
        f.write(secrets.token_bytes(32))
    identity_path = os.path.join(d, "t.id")
    with open(identity_path, "wb") as f:
        f.write(b"\x00" * 64)
    cp.reset_engine()
    k = f"node-{role}-" + secrets.token_hex(6)
    engine = cp.Engine(
        "sqlite::memory:", k,
        local_key_id=k, local_key_path=seed_path,
        local_pqc_key_id=k + "-pqc", local_pqc_key_path=pqc_path,
    )
    kid = engine.register_self_federation_key("agent", f"ref-{role}", None, None, None)
    mine = engine.lookup_public_key(kid)
    with open(os.path.join(shared, f"{role}.key.tmp"), "w") as f:
        f.write(json.dumps({"kid": kid, "record": json.loads(mine)}))
    os.replace(os.path.join(shared, f"{role}.key.tmp"), os.path.join(shared, f"{role}.key"))
    other = "b" if role == "a" else "a"
    peer = json.loads(wait_for(os.path.join(shared, f"{other}.key"), time.monotonic() + 30))
    try:
        engine.put_public_key(json.dumps({"record": peer["record"]}))
    except Exception as e:  # a held row is not an error here
        sys.stderr.write(f"put_public_key(peer): {e}\n")

    edge = init_edge_runtime(
        engine, identity_path,
        listen_addr=f"127.0.0.1:{my_port}",
        bootstrap_peers=[f"127.0.0.1:{peer_port}"],
        announce_interval_seconds=1,
    )

    stop = threading.Event()
    reads = [0]

    def persist_reader() -> None:
        while not stop.is_set():
            engine.lookup_public_key(kid)
            reads[0] += 1

    threading.Thread(target=persist_reader, daemon=True).start()

    sends = 0
    send_errors = 0
    rooted_seen = False
    t0 = time.monotonic()
    last_check = t0
    last_reads = -1
    stalled = 0
    while time.monotonic() - t0 < secs:
        rooted = edge.rooted_peers()
        rooted_seen = rooted_seen or peer["kid"] in rooted
        try:
            edge.send_opaque_event(peer["kid"], 7, b"two-wheel")
            sends += 1
        except Exception:
            send_errors += 1
        time.sleep(0.05)
        now = time.monotonic()
        if now - last_check >= 1.0:
            last_check = now
            stalled = stalled + 1 if reads[0] == last_reads else 0
            last_reads = reads[0]
            if stalled >= 3:
                print(json.dumps({"role": role, "error": "persist_reader_stalled",
                                  "persist_reads": reads[0]}))
                sys.stdout.flush()
                os._exit(3)
    stop.set()
    print(json.dumps({
        "role": role,
        "persist_reads": reads[0],
        "sends": sends,
        "send_errors": send_errors,
        "peer_rooted": rooted_seen,
        "rooted_peers": len(edge.rooted_peers()),
        "detection_writer": "not reachable from the binding (probe observer off)",
    }))
    sys.stdout.flush()
    os._exit(0)


def parent() -> int:
    timeout = float(os.environ.get("NODE_TIMEOUT", "60"))
    shared = tempfile.mkdtemp()
    pa, pb = free_port(), free_port()
    procs = {}
    for role, mine, theirs in (("a", pa, pb), ("b", pb, pa)):
        procs[role] = subprocess.Popen(
            [sys.executable, "-I", __file__, "node", role, shared, str(mine), str(theirs)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
    results = {}
    rc = 0
    for role, p in procs.items():
        try:
            out, err = p.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            results[role] = {"role": role, "error": "hung", "pid": p.pid}
            if os.environ.get("KEEP_HUNG") == "1":
                continue
            p.kill()
            p.communicate()
            rc = 124
            continue
        line = (out.strip().splitlines() or ["{}"])[-1]
        try:
            results[role] = json.loads(line)
        except json.JSONDecodeError:
            results[role] = {"role": role, "error": f"rc={p.returncode}", "stderr": err[-400:]}
        if p.returncode != 0:
            rc = rc or p.returncode
    print(json.dumps(results))
    return rc


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "node":
        sys.exit(node(sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])))
    sys.exit(parent())
