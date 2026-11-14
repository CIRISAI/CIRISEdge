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

The two nodes do not root EACH OTHER (self-registered agent keys have no
provenance chain to a steward bootstrap, and the wheel carries no test
anchor): each announce of the peer runs the rooting reads and refuses. Each
node does root the baked canonical, which drives the rooting WRITES
(`PutSignedTransportDestination`, `RecordAnnouncedPeer`,
`PutTransportDestination`) and the unfolded route reads through the proxy,
and a send to a rooted peer leases a link whose first step reads the
blackhole rules (`BlackholeList`). With `CIRIS_PERSIST_TRACE=1` and
`SCENARIO_LOG_DIR` set, each node's stderr (persist's op trace) is kept so
the ops can be counted.

A node that hangs never prints its report: the parent's timeout reports it.
A node exits 3 if its persist reader stops progressing for 3 s while it is
otherwise alive (the other direction of the lost wakeup).

The edge-detection writer is NOT reachable from a binding process: the
binding builds its `EdgeConfig` with `probe_pattern_observer_enabled = false`
and exposes no switch, so no detection event is written; the scenario says so
in its report rather than claiming coverage.

    python3 tools/scenarios/cohab_reticulum_two_node.py            # parent

Mixed versions (the LTS week, when a released node runs beside a new one):
`PY_A` / `PY_B` name each node's interpreter (each a venv holding its own
pair of wheels), and `IDLE_SECS` > 0 adds a quiet phase after the sends. Each
node then also reports what it observed of the other: announces received
(`subscribe_announces`), its links by direction (`link_list`), opaque frames
received from the peer, the replication counters moved during the send phase
after a `kick` toward every peer, and the counters moved during the quiet
phase (persist reads per caller, applied / duplicate / refused). Counter
families a version does not have are reported absent, not zero.
"""
import asyncio
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


# Counter families both v45.0.2 and v45.1 carry, plus the 45.1 ones (absent on
# an older node). Only these are diffed.
FAMILIES = (
    "replication_applied_total", "replication_duplicate_total",
    "apply_refusals_by_class", "apply_refusals_by_kind", "apply_refusals",
    "attestation_apply_refusals_by_reason", "key_apply_refusals_by_reason",
    "replication_round_outcomes_total", "responder_rounds_total",
    "replication_envelopes_served_total", "envelope_kind_retired_refusals",
    "announce_intake", "inbound_links", "outbound_links", "link_seal",
    "transport_inbound_drops", "forward_refusals_total",
    "replication_io", "peer_activity", "persist_reads",
)


def flatten(v, prefix: str, out: dict) -> None:
    if isinstance(v, bool):
        return
    if isinstance(v, (int, float)):
        out[prefix] = v
    elif isinstance(v, dict):
        for k, x in v.items():
            flatten(x, f"{prefix}.{k}" if prefix else str(k), out)


def counters(edge) -> dict:
    snap = edge.metrics_snapshot()
    out = {}
    for fam in FAMILIES:
        if fam in snap:
            flatten(snap[fam], fam, out)
    return out, sorted(f for f in FAMILIES if f not in snap)


def delta(before: dict, after: dict) -> dict:
    d = {}
    for k, v in after.items():
        dv = v - before.get(k, 0)
        if dv:
            d[k] = dv
    return dict(sorted(d.items()))


def count_by(events: list, field: str) -> dict:
    out: dict = {}
    for e in events:
        k = str(e.get(field))
        out[k] = out.get(k, 0) + 1
    return out


def watch_announces(edge, seen: list, stop: threading.Event) -> None:
    async def run() -> None:
        sub = edge.subscribe_announces()
        while not stop.is_set():
            try:
                ev = await asyncio.wait_for(sub.__anext__(), 0.5)
            except asyncio.TimeoutError:
                continue
            except StopAsyncIteration:
                return
            seen.append(ev if isinstance(ev, dict) else {"event": repr(ev)})

    try:
        asyncio.run(run())
    except Exception as e:  # report, never hide
        seen.append({"watch_error": repr(e)})


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
        # Each node its own transport identity (MIXED runs); the original
        # scenario's all-zero file gives both nodes the same one.
        f.write(secrets.token_bytes(64) if float(os.environ.get("IDLE_SECS", "0")) > 0
                else b"\x00" * 64)
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

    # The rooted map is keyed by the node identity a peer announces, which is
    # the edge's signer, not the agent key registered above: publish ours,
    # read the peer's.
    with open(os.path.join(shared, f"{role}.signer.tmp"), "w") as f:
        f.write(edge.signer_key_id())
    os.replace(os.path.join(shared, f"{role}.signer.tmp"), os.path.join(shared, f"{role}.signer"))
    peer_signer = wait_for(os.path.join(shared, f"{other}.signer"), time.monotonic() + 30)

    stop = threading.Event()
    reads = [0]

    def persist_reader() -> None:
        while not stop.is_set():
            engine.lookup_public_key(kid)
            reads[0] += 1

    threading.Thread(target=persist_reader, daemon=True).start()

    idle_secs = float(os.environ.get("IDLE_SECS", "0"))
    mixed = idle_secs > 0
    announces: list = []
    frames_from: dict = {}
    watch_stop = threading.Event()
    if mixed:
        threading.Thread(target=watch_announces, args=(edge, announces, watch_stop),
                         daemon=True).start()

        def on_opaque(sender, kind, payload) -> None:
            frames_from[sender] = frames_from.get(sender, 0) + 1

        opaque_sub = edge.subscribe_opaque(7, on_opaque)
        send_before, absent = counters(edge)

    sends = 0
    send_errors = 0
    rooted_seen = False
    t0 = time.monotonic()
    last_check = t0
    last_reads = -1
    stalled = 0
    while time.monotonic() - t0 < secs:
        rooted = edge.rooted_peers()
        rooted_seen = rooted_seen or peer_signer in rooted
        # The peer's agent key, and every rooted peer: a send to a rooted peer
        # leases a link, whose first step reads the blackhole rules.
        for to in [peer["kid"], *rooted]:
            try:
                edge.send_opaque_event(to, 7, b"two-wheel")
                sends += 1
            except Exception:
                send_errors += 1
        if mixed and int((time.monotonic() - t0) * 20) % 40 == 0:
            try:
                edge.kick(None)
            except Exception as e:
                sys.stderr.write(f"kick: {e}\n")
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
    mixed_report = {}
    if mixed:
        send_after, _ = counters(edge)
        links = edge.link_list()
        # The quiet phase: no sends, no kicks; only the cadence and the peer.
        reads_before_idle = reads[0]
        time.sleep(idle_secs)
        idle_after, _ = counters(edge)
        watch_stop.set()
        del opaque_sub
        mixed_report = {
            "edge_version": edge_version(),
            "persist_version": getattr(cp, "__version__", None),
            "absent_families": absent,
            "announces_received": len(announces),
            "announces_by_key": count_by(announces, "peer_key_id"),
            "announce_messages": count_by(announces, "message"),
            "links": [{k: l.get(k) for k in ("peer_identity_hash", "state", "direction")}
                      for l in links],
            "frames_received_by_sender": frames_from,
            "peer_agent_kid": peer["kid"],
            "send_phase": delta(send_before, send_after),
            "idle_phase": delta(send_after, idle_after),
            "idle_secs": idle_secs,
            "idle_lookup_public_key_loops": reads[0] - reads_before_idle,
        }
    stop.set()
    print(json.dumps({
        "role": role,
        "persist_reads": reads[0],
        "sends": sends,
        "send_errors": send_errors,
        "peer_rooted": rooted_seen,
        "rooted_peers": sorted(edge.rooted_peers()),
        "peer_signer": peer_signer,
        "detection_writer": "not reachable from the binding (probe observer off)",
        **mixed_report,
    }, default=str))
    sys.stdout.flush()
    os._exit(0)


def edge_version():
    try:
        from importlib.metadata import version
        return version("ciris-edge")
    except Exception:
        return None


def parent() -> int:
    timeout = float(os.environ.get("NODE_TIMEOUT", "60"))
    shared = tempfile.mkdtemp()
    pa, pb = free_port(), free_port()
    procs = {}
    for role, mine, theirs in (("a", pa, pb), ("b", pb, pa)):
        py = os.environ.get(f"PY_{role.upper()}", sys.executable)
        procs[role] = subprocess.Popen(
            [py, "-I", __file__, "node", role, shared, str(mine), str(theirs)],
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
        log_dir = os.environ.get("SCENARIO_LOG_DIR")
        if log_dir:
            with open(os.path.join(log_dir, f"{role}.err"), "w") as f:
                f.write(err)
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
