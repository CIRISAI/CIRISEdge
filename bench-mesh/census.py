#!/usr/bin/env python3
"""Role-contract census over a bench-mesh results JSONL, and the host
pre-flight that decides whether a census may be rendered at all.

    census.py <results.jsonl> [rc] [--late-joiner NODE] [--expect n1,n2,..]
    census.py --preflight --nodes N [--build] [--phase pre|post] ...
    census.py --self-test

Two honesty rules live here, and they are the same rule pointed at two
different things.

The FIRST is about the legs: a leg that did not run is a failed run.
The SECOND is about the box: a verdict is a claim about the code, so a
verdict rendered on a host that could not support the run is a claim the
harness cannot support. That one exits 75 — NOT MEASURED — and never a
leg census. See the "Host capacity" section below for the mechanism it
was built for (CIRISEdge#536) and where its numbers come from.

Honesty, restated for the per-role shape: the flat rule used to be "any
`ran: false` fails the run", which could never reach 100% because two
legs are ROLE-INAPPLICABLE by design — the deliberate late joiner is
admitted mid-stream, so `conformance.rotation_frame_loss` (zero-loss is
about members present ACROSS the advance) and `scope.seal` (it holds no
superseded epoch) can never apply to it. The contract below says, per
role, which legs MUST run and pass; everything else stays honest:

  1. every EXPECTED leg for a node's role must be present with
     ran=true AND ok=true — a missing row or a not_run of an expected
     leg FAILS the run;
  2. a not_run row OUTSIDE the contract is allowed and printed — it
     stays in the JSONL as documentation of why it did not apply;
  3. any row with ran=true and ok!=true FAILS regardless of contract —
     a failed measurement is never excusable;
  4. duplicate (node, leg) rows refuse the whole file, exactly as
     before — a merged file's numbers are ambiguous;
  5. a `mesh.role_completion` row FAILS the run: edge_node.rs emits it
     ONLY as a not_run bail marker when a role's runner returned Err,
     so its presence is a declared mid-run failure, never a skip.

The expected sets are derived from the emitters in src/bin/edge_node.rs
(`rep.ran(` / `rep.not_run(`) — the code is the authority, not this
comment. `mesh.standup` is emitted by every role from main().

  6. two `host` rows (`mesh.hoststate.pre` / `.post`) carry the memory,
     swap and disk state the point STARTED and ENDED in. They are
     evidence, not legs, so rules 1 and 3 do not apply to them — a
     breached floor is not a failure of the code. What they do is
     decide whether this file's verdict is admissible at all: see
     "The degradation doctrine" below.
"""

import argparse
import collections
import json
import os
import shutil
import sys
import tempfile
import time

# ── The role contracts ──────────────────────────────────────────────
#
# NOTE `conformance.seal_retires` is expected-for-publisher on the
# assumption of the parallel Track C fix (today it not_runs with the
# explicit-hash-cannot-announce diagnosis; the coordinator integrates
# both). Until Track C lands, a run's only contract violation should be
# exactly that leg.
EXPECTED = {
    "publisher": {
        "mesh.standup",
        "mesh.rooting",
        "ladder.discover",
        "ladder.discover_by_fedid",
        "cohort.join",
        "scope.install",
        "perf.publish_fanout",
        "scope.rotation",
        "perf.blob_fanout",
        "conformance.seal_retires",
        "mesh.member_reports",
    },
    "subscriber": {
        "mesh.standup",
        "mesh.rooting",
        "ladder.discover",
        "ladder.discover_by_fedid",
        "cohort.join",
        "scope.install",
        "perf.receive",
        "conformance.rotation_frame_loss",
        "conformance.member_can_fetch",
        "scope.seal",
    },
    # The late joiner is a subscriber admitted mid-stream: same runner,
    # minus the two legs that are about having been present ACROSS the
    # epoch advance. It uniquely emits nothing extra.
    "late-joiner": {
        "mesh.standup",
        "mesh.rooting",
        "cohort.join",
        "scope.install",
        "perf.receive",
        "conformance.member_can_fetch",
    },
    "relay": {
        "mesh.standup",
        "mesh.rooting",
        "conformance.relay_holds_no_cohort_address",
    },
    "nonmember": {
        "mesh.standup",
        "mesh.rooting",
        "conformance.nonmember_cannot_fetch",
    },
}

# Emitted by main() for ANY role, only as a bail marker on Err.
BAIL_LEG = "mesh.role_completion"

# The host's own rows. Not a role: `host` is not a node under test, and
# the contracts above deliberately do not cover it.
HOST_NODE = "host"
HOST_ROLE = "host"
HOSTSTATE_PRE = "mesh.hoststate.pre"
HOSTSTATE_POST = "mesh.hoststate.post"
HOST_LEGS = (HOSTSTATE_PRE, HOSTSTATE_POST)


# ════════════════════════════════════════════════════════════════════
# Host capacity — the pre-flight, and why it REFUSES instead of reporting
# ════════════════════════════════════════════════════════════════════
#
# CIRISEdge#536. `run.sh --sweep` ran M=1 → M=2 → M=4 in that order on
# one box that never recovered between points: each point tore down its
# containers and volumes, but page cache, swap and docker churn
# accumulated across the whole sweep. M=4 is the heaviest point — seven
# containers — and always landed last, on the most degraded host. There
# it failed reproducibly with
#
#     mesh.role_completion: waiting for Ready/Welcome:
#                           no control frame within 300s
#
# and 24 cascading legs. It failed IDENTICALLY regardless of code, which
# was proven from both directions: a bit-identical BuildKit-cached
# v18.6.0 image passed M=4 at 47 legs / 0 violations on a fresh box and
# failed at 36 / 24 on a loaded one; and v18.7.0, which failed as a
# sweep's third point, passed 47 / 0 when M=4 was run alone. Three false
# failure verdicts in one session, and the #532 dial fix cancelled on a
# bisect this artefact confounded — the bisect was measuring run ORDER,
# not the change.
#
# The census already refuses to call a skipped leg green. This is that
# same rule aimed at the box. A measuring instrument that cannot tell you
# it is out of calibration will eventually tell you something false with
# total confidence.
#
# ── Where these numbers come from ───────────────────────────────────
#
# Two kinds of evidence, and they are NOT equally strong. The comments
# say which is which, so a later reader can tighten the weak one instead
# of trusting it.
#
# SWAP — the decisive signal, and we have BOTH sides of it:
#     every run that PASSED sat at <= 4.0 GiB of 8 GiB swap  (<= 50 %)
#     every run that FALSELY FAILED sat at 7.0 GiB of 8 GiB  (   87 %)
# Same image, opposite verdicts, at those two figures. That is a measured
# boundary, not a correlation.
#
# We refuse above 60 % — deliberately NOT the 68 % midpoint of 50 and 87.
# The pre-flight reads the box BEFORE seven containers add their own
# pressure, and swap utilisation only ever climbs during a run (nothing
# in the run frees anonymous pages). A box already at 68 % at t=0 is past
# 87 % by the time the last node is up, which is the exact state that
# produced the false reds. 60 % of an 8 GiB swap is 4.8 GiB: 0.8 GiB of
# slack above the highest figure that has ever passed, which is where the
# slack is anchored rather than at a round number.
SWAP_UTIL_FLOOR = 0.60

# The evidence boundary (4.0 GiB passes, 7.0 GiB fails) lies ABOVE the
# entire swap of a small-swap box, so a percentage of such a swap is not
# the same quantity and must not refuse on its own. Below this total the
# swap reading is reported as INFORMATIONAL and MemAvailable carries the
# whole capacity check. Set at 4.0 GiB = the largest swap figure ever
# observed to pass, for exactly that reason.
SWAP_SIGNAL_MIN_TOTAL_MIB = 4.0 * 1024

# MEMORY — we only have the PASSING side: 17-23 GiB MemAvailable across
# the runs that came back 47 / 0 at M=4. That is what those boxes HAD
# spare, not what the run NEEDED; the minimum has never been measured.
#
# So the floor is deliberately NOT 17 GiB. A floor set at the lowest
# observed pass refuses boxes that have never been shown to fail, and a
# harness that refuses to run is its own kind of dishonest. We take HALF
# the lowest observed pass — 8.5 GiB — as the requirement of the heaviest
# point (7 nodes): 17 GiB is known-sufficient, the minimum is unknown,
# and halving a known-sufficient figure is the lowest number we can name
# without inventing a measurement we never took.
#
# That 8.5 GiB is then spread as a fixed base plus a per-node budget, so
# the light points are not held to the heaviest point's bar:
#
#     floor = 2048 MiB + 950 MiB x nodes            (+ build headroom)
#
#     M=1  (4 nodes)  5.71 GiB     M=4  (7 nodes)  8.49 GiB
#     M=2  (5 nodes)  6.64 GiB     K=2,M=4 (8)     9.42 GiB
#
# The 2048 MiB base is the fixed cost that does not scale with the
# topology: dockerd, the buildx daemon, the debian container that reads
# the results volume, and this shell. The 950 MiB per node falls out of
# the 8.5 GiB anchor once that base is removed (6.5 GiB / 7).
#
# IF A RUN IS EVER REFUSED AT, SAY, 9 GiB AND WOULD HAVE PASSED, record
# it here and lower the anchor. This comment is the log; the numbers are
# only as good as the evidence cited beside them.
BASE_MIB = 2048
PER_NODE_MIB = 950

# The build is the single heaviest consumer in the whole harness — a
# release cargo build of openmls + libcrux + leviculum + persist, all
# from git, with parallel rustc. This repo's own recorded experience
# (MEMORY: "stagger agent builds") is that four concurrent cargo builds
# OOM-kill a host of exactly this class, 32 GiB + 8 GiB swap, which puts
# one build's peak on the order of a quarter of that envelope. 2 GiB is
# that bound. `--no-build` drops it, because then nothing compiles.
BUILD_HEADROOM_MIB = 2048

# DISK — no run has ever been observed to fail on ENOSPC, so this floor
# is derived from the artefacts rather than from a failure. A cold build
# wants, roughly: the rust:1.97-bookworm build stage with cmake/clang/
# libsqlite3-dev (~3 GiB), the ffmpeg media stage (~0.5 GiB), the runtime
# image, and the three BuildKit cache mounts — cargo registry, cargo git
# checkouts, and a RELEASE `/src/target` for this dependency graph (this
# repo's recorded figure for a worktree `target/` is 1-2 GiB, and that is
# a debug tree; release with git deps is several times that). 20 GiB
# covers those with room for layer churn.
#
# It is in the pre-flight because ENOSPC in the docker data root kills
# containers mid-run and presents as exactly the failure this whole
# section is about — a cohort that never forms. And this host in
# particular arrives at runs with little headroom: MEMORY records
# parallel worktrees filling 935 GB to 98 %.
DISK_FLOOR_BUILD_GIB = 20.0
DISK_FLOOR_RUN_GIB = 5.0

# 75 is EX_TEMPFAIL from sysexits.h — "temporary failure, indicating
# something that is not really an error", which is precisely the claim:
# nothing is wrong with the code, the box could not host the measurement,
# try again later. It is distinct from 0 (measured, clean), 1 (measured,
# violations) and 2 (usage), and below 126 so it can never be confused
# with a shell's "not executable" / "not found" / 128+signal codes.
NOT_MEASURED = 75

# How often the recovery wait re-reads the box. Ten seconds is short
# enough that a point does not idle after the floor comes back and long
# enough that the poll itself is not the load.
RECOVER_POLL_SECS = 10

GIB_KB = 1024.0 * 1024.0
MIB_KB = 1024.0


def mem_floor_mib(nodes, build):
    """The MemAvailable floor for a point of this weight. See BASE_MIB."""
    return BASE_MIB + PER_NODE_MIB * nodes + (BUILD_HEADROOM_MIB if build else 0)


def disk_floor_gib(build):
    return DISK_FLOOR_BUILD_GIB if build else DISK_FLOOR_RUN_GIB


# The injection seam, and why it is safe to have one.
#
# The pre-flight has to be testable on a box other than the one it
# guards — a CI runner, a laptop, this file's own --self-test. So
# MESH_PREFLIGHT_MEMINFO names a file to read INSTEAD of /proc/meminfo,
# and MESH_PREFLIGHT_DISK_FREE_GIB substitutes the disk reading.
#
# A backdoor that lets someone tell the gate "the box is fine" would be
# worse than no gate at all, so it leaves a fingerprint: `meminfo_source`
# goes into the host row, and census.py treats any row whose source is
# not /proc/meminfo as NO host evidence at all — it prints a loud warning
# and falls back to the plain verdict. An override can therefore make the
# harness refuse to run; it can NEVER make a red admissible, and it can
# never make a degraded file look clean.
MEMINFO_ENV = "MESH_PREFLIGHT_MEMINFO"
DISK_FREE_ENV = "MESH_PREFLIGHT_DISK_FREE_GIB"
REAL_MEMINFO = "/proc/meminfo"


def read_meminfo(text=None):
    """/proc/meminfo as {key: kB}. `text` makes it injectable for tests."""
    if text is None:
        with open(os.environ.get(MEMINFO_ENV) or REAL_MEMINFO, "r") as fh:
            text = fh.read()
    out = {}
    for line in text.splitlines():
        key, _, rest = line.partition(":")
        field = rest.split()
        if not field:
            continue
        try:
            out[key.strip()] = int(field[0])
        except ValueError:
            pass
    return out


def docker_disk_free(path=None):
    """(path, free_bytes) for the filesystem holding docker's data root.

    We do NOT ask docker — the pre-flight must be answerable without
    starting a daemon call, and `docker info` on a box already thrashing
    is itself slow. `/var/lib/docker` is typically mode 0710 root:root,
    so statvfs on it can fail for a non-root caller; we walk up to the
    nearest ancestor that answers, which on a default install is the same
    filesystem. If docker's data root has been moved to another
    filesystem, set MESH_DOCKER_ROOT."""
    cands = [c for c in (path, os.environ.get("MESH_DOCKER_ROOT"),
                         "/var/lib/docker", ".") if c]
    for cand in cands:
        probe = os.path.abspath(cand)
        while True:
            try:
                return probe, shutil.disk_usage(probe).free
            except OSError:
                parent = os.path.dirname(probe)
                if parent == probe:
                    break
                probe = parent
    return "/", 0


def probe_host(nodes, build, meminfo_text=None, disk=None):
    """Read the box and hold it to the floors for a point of `nodes`
    containers. `meminfo_text` and `disk=(path, free_bytes)` are the
    injection seams the self-test drives — nothing here touches docker
    and nothing here has a side effect."""
    kb = read_meminfo(meminfo_text)

    mem_total = kb.get("MemTotal", 0) / MIB_KB
    estimated = "MemAvailable" not in kb
    if estimated:
        # Pre-3.14 kernels. Worse than MemAvailable (it counts cache that
        # is not actually reclaimable) so the row says it is an estimate
        # rather than quietly presenting it as the same number.
        mem_avail = (kb.get("MemFree", 0) + kb.get("Cached", 0)) / MIB_KB
    else:
        mem_avail = kb["MemAvailable"] / MIB_KB

    swap_total = kb.get("SwapTotal", 0) / MIB_KB
    swap_free = kb.get("SwapFree", 0) / MIB_KB
    swap_used = max(0.0, swap_total - swap_free)
    swap_util = (swap_used / swap_total) if swap_total > 0 else 0.0
    swap_decisive = swap_total >= SWAP_SIGNAL_MIN_TOTAL_MIB

    if disk is not None:
        dpath, dfree = disk
    elif os.environ.get(DISK_FREE_ENV):
        dpath = f"<{DISK_FREE_ENV}>"
        dfree = float(os.environ[DISK_FREE_ENV]) * (1024 ** 3)
    else:
        dpath, dfree = docker_disk_free()
    disk_free = dfree / float(1024 ** 3)

    # The fingerprint. `disk` / `meminfo_text` are the in-process
    # injection the self-test uses; the env vars are the out-of-process
    # one run.sh's own dry-run uses. Either way the row says so.
    if meminfo_text is not None or disk is not None:
        source = "<injected>"
    else:
        source = os.environ.get(MEMINFO_ENV) or REAL_MEMINFO
        if os.environ.get(DISK_FREE_ENV):
            source += f" + {DISK_FREE_ENV}"

    floor_mem = mem_floor_mib(nodes, build)
    floor_disk = disk_floor_gib(build)

    breaches = []
    if mem_avail < floor_mem:
        breaches.append({
            "resource": "memory available",
            "value": f"{mem_avail / 1024.0:.2f} GiB",
            "floor": f">= {floor_mem / 1024.0:.2f} GiB",
            "why": f"{nodes} nodes x {PER_NODE_MIB} MiB + {BASE_MIB} MiB base"
                   + (f" + {BUILD_HEADROOM_MIB} MiB build" if build else ""),
        })
    if swap_decisive and swap_util > SWAP_UTIL_FLOOR:
        breaches.append({
            "resource": "swap utilisation",
            "value": f"{swap_used / 1024.0:.2f} GiB of "
                     f"{swap_total / 1024.0:.2f} GiB = {swap_util * 100:.0f}%",
            "floor": f"<= {SWAP_UTIL_FLOOR * 100:.0f}%",
            "why": "the runs that produced #536's false reds sat at 87%; "
                   "every run that passed sat at 50% or below",
        })
    if disk_free < floor_disk:
        breaches.append({
            "resource": "disk free",
            "value": f"{disk_free:.1f} GiB on {dpath}",
            "floor": f">= {floor_disk:.0f} GiB",
            "why": "ENOSPC in docker's data root kills containers mid-run "
                   "and presents as a cohort that never forms",
        })

    return {
        "nodes": nodes,
        "build": bool(build),
        "meminfo_source": source,
        "mem_total_mib": round(mem_total),
        "mem_available_mib": round(mem_avail),
        "mem_available_gib": round(mem_avail / 1024.0, 2),
        "mem_available_estimated": estimated,
        "mem_floor_mib": floor_mem,
        "swap_total_mib": round(swap_total),
        "swap_used_mib": round(swap_used),
        "swap_used_gib": round(swap_used / 1024.0, 2),
        "swap_util": round(swap_util, 4),
        "swap_util_floor": SWAP_UTIL_FLOOR,
        "swap_signal_decisive": swap_decisive,
        "disk_path": dpath,
        "disk_free_gib": round(disk_free, 1),
        "disk_floor_gib": floor_disk,
        "fit": not breaches,
        "breaches": breaches,
    }


def hoststate_row(state, phase, attempt=1, point=None):
    """One JSONL row for the results file. `ok` mirrors `fit`, but the
    census exempts host rows from rule 3 — a breached floor is not a
    failure of the code, it is a fact about the box that decides whether
    this file's verdict is admissible."""
    detail = dict(state)
    detail["phase"] = phase
    detail["attempt"] = attempt
    if point:
        detail["point"] = point
    return {
        "node": HOST_NODE,
        "role": HOST_ROLE,
        "leg": HOSTSTATE_PRE if phase == "pre" else HOSTSTATE_POST,
        "ran": True,
        "ok": bool(state["fit"]),
        "detail": detail,
    }


def is_synthetic(state):
    """True when this reading did not come from the real /proc/meminfo."""
    return (state.get("meminfo_source") or REAL_MEMINFO) != REAL_MEMINFO


def state_one_line(state):
    swap = (f"swap {state['swap_used_gib']:.2f}/"
            f"{state['swap_total_mib'] / 1024.0:.2f} GiB "
            f"({state['swap_util'] * 100:.0f}%)")
    if not state["swap_signal_decisive"]:
        swap += " [informational: swap too small to carry #536's boundary]"
    line = (f"mem {state['mem_available_gib']:.2f} GiB avail "
            f"(floor {state['mem_floor_mib'] / 1024.0:.2f})  |  {swap}  |  "
            f"disk {state['disk_free_gib']:.1f} GiB free "
            f"(floor {state['disk_floor_gib']:.0f})")
    if is_synthetic(state):
        line += f"   [SYNTHETIC: {state.get('meminfo_source')}]"
    return line


RULE = "=" * 70


def render_refusal(state, point_label, waited=0):
    """The 2 a.m. output. It must be impossible to mistake for a census:
    no leg counts, no node table, no per-role lines — nothing that looks
    like a verdict about the code, because none was reached."""
    out = [
        "",
        RULE,
        f"  NOT MEASURED  —  {point_label}  ({state['nodes']} nodes"
        + (", build" if state["build"] else ", no build") + ")",
        RULE,
        "  This is NOT a leg census. No verdict was rendered about the",
        "  code, because this host could not support the run:",
        "",
    ]
    for b in state["breaches"]:
        out.append(f"    {b['resource']:<18} {b['value']}")
        out.append(f"    {'':<18} floor: {b['floor']}   ({b['why']})")
    out.append("")
    out.append(f"    full state: {state_one_line(state)}")
    if waited:
        out.append(f"    waited {waited}s for the floor to be re-attained; "
                   f"it was not.")
    out += [
        "",
        "  Why this refuses rather than reports (CIRISEdge#536): the same",
        "  bit-identical image has passed M=4 at 47 legs / 0 violations on",
        "  a fresh box and failed at 36 / 24 on a loaded one. A verdict is",
        "  a claim about the code. A verdict from this box would be a claim",
        "  the box cannot support.",
        "",
        f"  exit {NOT_MEASURED} (EX_TEMPFAIL) — nothing is wrong with the tree.",
        "  Free the named resource and re-run this point.",
        RULE,
        "",
    ]
    return out


def await_floor(nodes, build, timeout, probe=probe_host, sleep=time.sleep,
                clock=time.monotonic, log=None):
    """Poll until the box meets the floor, or give up. Returns the last
    state and the seconds waited. The wait is never silent — a harness
    that hangs quietly at 2 a.m. is its own bug."""
    log = log or (lambda _s: None)
    started = clock()
    state = probe(nodes, build)
    if state["fit"] or timeout <= 0:
        return state, 0
    log(f"  host below the floor for this point; waiting up to {timeout}s "
        f"for it to recover")
    log(f"    {state_one_line(state)}")
    while True:
        waited = clock() - started
        if waited >= timeout:
            return state, int(waited)
        sleep(min(RECOVER_POLL_SECS, timeout - waited))
        state = probe(nodes, build)
        waited = int(clock() - started)
        if state["fit"]:
            log(f"  host recovered after {waited}s: {state_one_line(state)}")
            return state, waited
        log(f"    +{waited}s  {state_one_line(state)}")


def role_from_name(node):
    """Compose's fixed naming contract, for nodes that emitted nothing."""
    if node == "publisher":
        return "publisher"
    if node == "nonmember":
        return "nonmember"
    if node.startswith("relay-"):
        return "relay"
    if node.startswith("sub-"):
        return "subscriber"
    return None


def infer_late_joiner(legs):
    """The publisher's scope.rotation detail names the joiner when the
    mid-stream advance was a member_join. Explicit --late-joiner wins."""
    for l in legs:
        if l.get("leg") == "scope.rotation" and l.get("ran"):
            d = l.get("detail") or {}
            if d.get("kind") == "member_join":
                return d.get("late_joiner")
    return None


# Sentinel: "no --late-joiner flag given, infer from the publisher's
# scope.rotation detail". Distinct from None, which means "there is none".
INFER = object()


# ── The degradation doctrine ────────────────────────────────────────
#
# The pre-flight can only speak for the box at t=0. #536's mechanism is
# that the box degrades DURING the point — swap climbed as the seventh
# container came up — so run.sh records the state at the end too, and the
# rule below is applied here rather than in run.sh so that re-censusing a
# committed baseline (`./run.sh --census-only`) reproduces the identical
# verdict from the file alone.
#
# The rule is asymmetric, and the asymmetry is the whole point:
#
#   degraded AND violations  ->  NOT MEASURED (75). This is #536 exactly.
#   degraded AND clean       ->  the PASS STANDS (0), loudly annotated.
#   healthy  AND violations  ->  a real red (1). No excuse exists.
#
# A pass under degradation stands because host degradation can only
# manufacture false REDS, never false greens. Under memory pressure a leg
# either fails or never runs, and rules 1 and 3 already fail both of
# those. There is no path by which a starved box turns a broken leg
# green. So the doctrine only ever WITHHOLDS a verdict; it never grants
# one. The perf numbers in a degraded file are still junk, and the
# annotation says so — but "did the mesh work" survives.
def _host_note(state_rows):
    """Human lines for the host rows, in file order."""
    lines = []
    for r in state_rows:
        d = r.get("detail") or {}
        phase = d.get("phase", r.get("leg", "?"))
        att = d.get("attempt", 1)
        mark = "within floor" if r.get("ok") else "BELOW FLOOR"
        lines.append(
            f"  host {phase:<4} (attempt {att}): {mark}"
        )
        try:
            lines.append("    " + state_one_line(d))
        except (KeyError, TypeError):
            lines.append("    (host row present but malformed; "
                         "cannot be read as a state)")
        for b in d.get("breaches") or []:
            lines.append(f"    breach: {b.get('resource')} = {b.get('value')} "
                         f"(floor {b.get('floor')})")
    return lines


def _read_leg_rows(path):
    """Parse a results JSONL, recovering lines that carry more than one record.

    Returns `(rows, corrupt_reason_or_None)`.

    Every node in the mesh appends to ONE file on a shared volume. A non-atomic
    append can therefore put two complete JSON objects on a single line, which
    `json.loads` rejects as `Extra data` — observed at M=4, the point with the
    most concurrent deliveries. The writer now emits each record in a single
    `write()` (CIRISEdge#532), but this reader must not depend on that: an older
    node image writing into a newer harness is exactly the mixed-version case a
    mesh harness exists to run.

    Concatenated COMPLETE objects are unambiguous, so they are recovered rather
    than discarded — throwing away a ten-minute M=4 run over a formatting
    artifact would be its own kind of dishonesty. Anything genuinely unparseable
    is reported, and the caller refuses the verdict.
    """
    rows, decoder = [], json.JSONDecoder()
    with open(path) as fh:
        for lineno, raw in enumerate(fh, start=1):
            line = raw.strip()
            if not line.startswith("{"):
                continue
            idx = 0
            while idx < len(line):
                try:
                    obj, end = decoder.raw_decode(line, idx)
                except ValueError as exc:
                    return rows, f"line {lineno} is not valid JSON ({exc})"
                rows.append(obj)
                idx = end
                while idx < len(line) and line[idx].isspace():
                    idx += 1
    return rows, None


def census(path, rc, late_joiner=INFER, expect_nodes=None):
    """Returns (exit_code, printed lines). Never prints a number it did
    not read out of the file."""
    out = []
    # `all_rows`, not `rows`: the per-node loop below rebinds `rows` to
    # one node's slice, and a name collision there would be silent.
    all_rows, corrupt = _read_leg_rows(path)
    if corrupt:
        # A results file we cannot fully read is a run we cannot report on.
        # Same doctrine as the host pre-flight (#536): refuse the verdict
        # rather than produce one from whatever happened to parse. A partial
        # file would under-count legs, and an under-counted census reads as
        # "legs did not run" — a measurement fault wearing a contract
        # violation's clothes, which is the worst of both.
        out.append(f"  NOT MEASURED  {path}: {corrupt}")
        out.append("  the results file could not be read in full — refusing to "
                   "report a leg census from a partial file")
        return NOT_MEASURED, out

    # Rule 4: duplicates refuse the file outright (a merged file). Host
    # rows are included on purpose — a merged file duplicates those too,
    # and that is a fine second way to catch it.
    dupes = [
        k
        for k, n in collections.Counter((l["node"], l["leg"]) for l in all_rows).items()
        if n > 1
    ]
    if dupes:
        out.append(
            f"  CONTAMINATED: {len(dupes)} (node, leg) pairs appear more than "
            f"once — this file merges multiple runs and none of its numbers "
            f"can be trusted."
        )
        for d in dupes[:8]:
            out.append(f"    duplicated: {d[0]}/{d[1]}")
        return 1, out

    # Rule 6: the host rows are evidence, not legs. Pull them out before
    # anything role-shaped touches them.
    def _is_host(r):
        return r.get("node") == HOST_NODE and r.get("leg") in HOST_LEGS

    host_rows = [r for r in all_rows if _is_host(r)]
    degraded = [r for r in host_rows if r.get("ok") is not True]
    synthetic = any(is_synthetic(r.get("detail") or {}) for r in host_rows)
    legs = [r for r in all_rows if not _is_host(r)]

    def _verdict(code):
        """Apply the degradation doctrine to a computed exit code."""
        # `nonlocal`: the augmented assignments below would otherwise make
        # `out` a fresh local and silently drop every line above.
        nonlocal out
        # A synthetic host reading is fiction, and fiction may not decide
        # admissibility. Say so loudly and fall through to the plain
        # verdict, which is the strictest available answer — this is the
        # one path by which the injection seam CANNOT launder a red.
        if synthetic:
            out.extend(_host_note(host_rows))
            out += [
                "  WARNING: this file's host rows are SYNTHETIC — they came "
                "from an injected reading, not /proc/meminfo. They are",
                "  printed as documentation only and were NOT allowed to "
                "affect the verdict. This file is a dry run, not a baseline.",
            ]
            return code
        if not host_rows:
            out.append(
                "  host state: NOT RECORDED in this file — it predates "
                "CIRISEdge#536, so whether the box could support the run is "
                "unknown and this verdict cannot be checked against it."
            )
            return code
        out.extend(_host_note(host_rows))
        if not degraded:
            return code
        if code == 0:
            out += [
                "  NOTE: the host was below the floor at one of the sampled",
                "  points, and this run still met every contract. The PASS",
                "  STANDS — degradation manufactures false reds, never false",
                "  greens: a starved box makes a leg fail or not run, and both",
                "  of those already fail the census. The perf numbers in this",
                "  file are NOT comparable to a healthy point's.",
            ]
            return 0
        out += [
            "",
            RULE,
            "  NOT MEASURED  —  this file's failures are not admissible",
            RULE,
            "  The host fell below the floor for this point, and the run",
            "  reported failures. Those two facts together are CIRISEdge#536:",
            "  the same bit-identical image has passed at 47 legs / 0",
            "  violations on a fresh box and failed at 36 / 24 on a loaded",
            "  one. This harness cannot tell those apart, so it does not",
            "  guess — the verdict is WITHHELD, not rendered.",
            "",
            "  The violations above are printed as evidence, not as a claim.",
            "  Re-run this point on a recovered box to get a real verdict.",
            f"  exit {NOT_MEASURED} (EX_TEMPFAIL).",
            RULE,
        ]
        return NOT_MEASURED

    if not legs:
        out.append("  NO LEGS — nothing was measured.")
        return _verdict(1), out

    if late_joiner is INFER:
        late_joiner = infer_late_joiner(legs)

    by_node = collections.defaultdict(list)
    for l in legs:
        by_node[l["node"]].append(l)

    # A node run.sh expected that emitted NOTHING is a violation the
    # rows alone cannot show; --expect makes it visible.
    nodes = list(by_node)
    for n in expect_nodes or []:
        if n not in by_node:
            nodes.append(n)

    violations = []
    for node in sorted(nodes):
        rows = by_node.get(node, [])
        role = rows[0].get("role") if rows else role_from_name(node)
        if node == late_joiner:
            role = "late-joiner"
        expected = EXPECTED.get(role)
        if expected is None:
            violations.append(f"{node}: unknown role {role!r} — no contract to hold it to")
            out.append(f"  {node:<12} role={role!r}  UNKNOWN ROLE")
            continue
        if not rows:
            violations.append(f"{node}: expected by the topology but emitted no rows at all")
            out.append(f"  {node:<12} role={role:<12} expected={len(expected)}  ran+ok=0  EMITTED NOTHING")
            continue

        present = {r["leg"]: r for r in rows}
        node_viol = []
        # Rule 5: the bail marker is a declared mid-run failure.
        if BAIL_LEG in present:
            node_viol.append(
                f"{BAIL_LEG} present — the role runner bailed: "
                f"{present[BAIL_LEG].get('not_run_reason')}"
            )
        # Rule 1: every expected leg present, ran, and ok.
        for leg in sorted(expected):
            r = present.get(leg)
            if r is None:
                node_viol.append(f"expected leg {leg} is MISSING")
            elif not r.get("ran"):
                node_viol.append(
                    f"expected leg {leg} did not run: {r.get('not_run_reason')}"
                )
            elif r.get("ok") is not True:
                node_viol.append(f"expected leg {leg} ran and FAILED")
        # Rule 3: a failed measurement is never excusable, contract or not.
        for r in rows:
            if r["leg"] not in expected and r["leg"] != BAIL_LEG:
                if r.get("ran") and r.get("ok") is not True:
                    node_viol.append(f"out-of-contract leg {r['leg']} ran and FAILED")

        ran_ok = sum(
            1 for leg in expected
            if present.get(leg, {}).get("ran") and present[leg].get("ok") is True
        )
        out.append(
            f"  {node:<12} role={role:<12} expected={len(expected)}  "
            f"ran+ok={ran_ok}/{len(expected)}"
            + ("" if not node_viol else "  CONTRACT VIOLATIONS:")
        )
        for v in node_viol:
            out.append(f"    VIOLATION  {node}: {v}")
        # Rule 2: out-of-contract not_run rows are documentation.
        for r in rows:
            if r["leg"] not in expected and r["leg"] != BAIL_LEG and not r.get("ran"):
                out.append(
                    f"    not-in-contract (allowed)  {r['leg']}: "
                    f"{(r.get('not_run_reason') or '')[:110]}"
                )
        violations.extend(f"{node}: {v}" for v in node_viol)

    out.append(
        f"  legs recorded: {len(legs)}  |  nodes: {len(nodes)}  |  "
        f"late joiner: {late_joiner or 'none'}  |  contract violations: {len(violations)}"
    )
    # Informational only — the exit code does not soften. See the note on
    # EXPECTED: this leg is in the publisher's contract on the assumption
    # of the Track C seal-probe fix.
    if any(
        v.startswith("publisher: expected leg conformance.seal_retires did not run")
        for v in violations
    ):
        out.append(
            "  note: conformance.seal_retires not running is the KNOWN Track C "
            "gap (seal-probe dialability); the contract expects it on the "
            "assumption of that fix, so this run still exits non-zero."
        )
    if rc != 0:
        out.append(f"  PUBLISHER EXIT: rc={rc} — the orchestrator itself failed.")
    # The degradation doctrine is applied LAST, over the finished verdict,
    # so that everything above is printed exactly as it always was. It can
    # turn a 1 into a 75; it can never turn anything into a 0.
    return _verdict(0 if rc == 0 and not violations else 1), out


# ── Self-test: every rule, no docker ────────────────────────────────

def _row(node, role, leg, ran=True, ok=True, reason=None, detail=None):
    r = {"node": node, "role": role, "leg": leg, "ran": ran,
         "ok": (ok if ran else None), "detail": detail or {}}
    if not ran:
        r["not_run_reason"] = reason or "synthetic"
    return r


def _golden():
    """A minimal healthy relays=1 subs=2 run, sub-2 the late joiner."""
    rows = []
    for node, role in [("publisher", "publisher"), ("relay-1", "relay"),
                       ("sub-1", "subscriber"), ("sub-2", "subscriber"),
                       ("nonmember", "nonmember")]:
        rows.append(_row(node, role, "mesh.standup"))
        rows.append(_row(node, role, "mesh.rooting"))
        # CIRISEdge#554 — every node that roots must also be able to ADDRESS its
        # peers; the two are different claims and the ladder needs the second.
        if role in ("publisher", "subscriber"):
            rows.append(_row(node, role, "ladder.discover"))
            rows.append(_row(node, role, "ladder.discover_by_fedid"))
    for leg in ["cohort.join", "scope.install", "perf.publish_fanout",
                "perf.blob_fanout", "conformance.seal_retires",
                "mesh.member_reports"]:
        rows.append(_row("publisher", "publisher", leg))
    rows.append(_row("publisher", "publisher", "scope.rotation",
                     detail={"kind": "member_join", "late_joiner": "sub-2"}))
    for leg in ["cohort.join", "scope.install", "perf.receive",
                "conformance.member_can_fetch"]:
        rows.append(_row("sub-1", "subscriber", leg))
        rows.append(_row("sub-2", "subscriber", leg))
    rows.append(_row("sub-1", "subscriber", "conformance.rotation_frame_loss"))
    rows.append(_row("sub-1", "subscriber", "scope.seal"))
    # The late joiner's two principled, out-of-contract not_runs.
    rows.append(_row("sub-2", "subscriber", "conformance.rotation_frame_loss",
                     ran=False, reason="admitted mid-stream"))
    rows.append(_row("sub-2", "subscriber", "scope.seal",
                     ran=False, reason="no superseded epoch"))
    rows.append(_row("relay-1", "relay", "conformance.relay_holds_no_cohort_address"))
    rows.append(_row("nonmember", "nonmember", "conformance.nonmember_cannot_fetch"))
    return rows


EXPECT_NODES = ["publisher", "relay-1", "sub-1", "sub-2", "nonmember"]


# ── Synthetic /proc/meminfo, in the shapes #536 actually recorded ───
#
# Only the four fields the probe reads, plus Cached so the pre-3.14
# fallback path can be driven too. Figures are kB, as the kernel writes
# them.
def _meminfo(mem_total_gib=31.08, mem_avail_gib=20.0,
             swap_total_gib=8.0, swap_used_gib=1.0, with_available=True,
             swap_used_kb=None):
    g = 1024 * 1024
    swap_total_kb = int(swap_total_gib * g)
    if swap_used_kb is None:
        swap_used_kb = int(swap_used_gib * g)
    lines = [f"MemTotal:       {int(mem_total_gib * g)} kB",
             f"MemFree:        {int(mem_avail_gib * g * 0.2)} kB"]
    if with_available:
        lines.append(f"MemAvailable:   {int(mem_avail_gib * g)} kB")
    lines += [f"Cached:         {int(mem_avail_gib * g * 0.8)} kB",
              f"SwapTotal:      {swap_total_kb} kB",
              f"SwapFree:       {swap_total_kb - swap_used_kb} kB"]
    return "\n".join(lines) + "\n"


# The two boxes from the issue, by name, so the self-test output says
# which real observation each case stands for.
HEALTHY_BOX = _meminfo(mem_avail_gib=20.0, swap_used_gib=1.0)   # 17-23 GiB, <= 4
LOADED_BOX = _meminfo(mem_avail_gib=3.1, swap_used_gib=7.0)     # the false reds
BIG_DISK = ("/var/lib/docker", int(200 * 1024 ** 3))
FULL_DISK = ("/var/lib/docker", int(3 * 1024 ** 3))


def _as_real(state):
    """Relabel an injected reading as if it came from /proc/meminfo.

    The doctrine tests need this because an injected reading is exactly
    what the doctrine must NOT act on — see the synthetic case at the end
    of preflight_self_test(), which checks that in the other direction."""
    return dict(state, meminfo_source=REAL_MEMINFO)


def _host_rows(pre_state, post_state, attempt=1):
    return [hoststate_row(_as_real(pre_state), "pre", attempt),
            hoststate_row(_as_real(post_state), "post", attempt)]


def preflight_self_test():
    """The pre-flight and the doctrine, with no /proc and no docker."""
    failures = 0

    def want(name, got, expect):
        nonlocal failures
        ok = got == expect
        if not ok:
            failures += 1
        print(f"── self-test [{name}]: got={got} want={expect}  "
              f"{'ok' if ok else 'SELF-TEST FAILURE'}")

    # 1. The floor arithmetic, per point. These are the numbers the
    #    comment on BASE_MIB claims; if the comment and the code drift
    #    apart, this is what catches it.
    print("── floors (MemAvailable), no build:")
    for nodes, label in [(4, "M=1  relays=1"), (5, "M=2  relays=1"),
                         (7, "M=4  relays=1"), (8, "M=4  relays=2")]:
        print(f"     {label:<14} {nodes} nodes -> "
              f"{mem_floor_mib(nodes, False) / 1024.0:.2f} GiB "
              f"(with build {mem_floor_mib(nodes, True) / 1024.0:.2f} GiB)")
    want("heaviest point floor is half the lowest observed pass (17 GiB)",
         round(mem_floor_mib(7, False) / 1024.0, 2), 8.49)

    # 2. The two boxes from #536, at the point that produced the false
    #    reds. Same point, same code, opposite admissibility.
    healthy = probe_host(7, True, meminfo_text=HEALTHY_BOX, disk=BIG_DISK)
    want("healthy box (20 GiB avail, 12% swap) admits M=4", healthy["fit"], True)
    print(f"     {state_one_line(healthy)}")

    loaded = probe_host(7, True, meminfo_text=LOADED_BOX, disk=BIG_DISK)
    want("loaded box (3.1 GiB avail, 87% swap) REFUSES M=4",
         loaded["fit"], False)
    want("...and names BOTH failing resources",
         sorted(b["resource"] for b in loaded["breaches"]),
         ["memory available", "swap utilisation"])

    # 3. Swap alone must be able to refuse. This is the decisive signal:
    #    a box with plenty of free memory but 87% of swap consumed has
    #    already been thrashing, and that is the state that failed.
    swap_only = probe_host(7, True, disk=BIG_DISK,
                           meminfo_text=_meminfo(mem_avail_gib=20.0,
                                                 swap_used_gib=7.0))
    want("swap alone refuses (20 GiB free, 87% swap)", swap_only["fit"], False)
    want("...naming swap and nothing else",
         [b["resource"] for b in swap_only["breaches"]], ["swap utilisation"])

    # 4. And the boundary is where the comment says it is. 4.0 GiB of 8
    #    (50 %) passed in the field and must pass here. The floor itself
    #    is 60 % = 5033164.8 kB of an 8 GiB swap, which is not a whole
    #    number of kB — so the two cases straddling it are given in kB,
    #    exactly, rather than in a GiB figure that rounds across the line
    #    and makes the test look like a bug in the check. The comparison
    #    is strict (`>`), so sitting ON the floor is not a breach.
    boundary_kb = int(SWAP_UTIL_FLOOR * 8 * 1024 * 1024)      # 5033164
    for used_kb, expect_fit, label in [
        (4 * 1024 * 1024, True, "4.00 GiB = 50%, the highest that ever passed"),
        (boundary_kb, True, "exactly on the 60% floor"),
        (boundary_kb + 1, False, "one kB over the 60% floor"),
        (7 * 1024 * 1024, False, "7.00 GiB = 87%, #536's false reds"),
    ]:
        s = probe_host(7, True, disk=BIG_DISK,
                       meminfo_text=_meminfo(mem_avail_gib=20.0,
                                             swap_used_kb=used_kb))
        want(f"swap {used_kb} kB ({label}) fit={expect_fit}",
             s["fit"], expect_fit)

    # 5. A small swap cannot carry the #536 boundary, so it must not
    #    refuse on its own — MemAvailable is the only signal there.
    tiny = probe_host(7, True, disk=BIG_DISK,
                      meminfo_text=_meminfo(mem_avail_gib=20.0,
                                            swap_total_gib=1.0,
                                            swap_used_gib=0.95))
    want("95% of a 1 GiB swap is informational, not a refusal",
         tiny["fit"], True)
    want("...and the row says so", tiny["swap_signal_decisive"], False)

    # 6. A swapless box: utilisation is 0, not a division by zero.
    noswap = probe_host(7, True, disk=BIG_DISK,
                        meminfo_text=_meminfo(mem_avail_gib=20.0,
                                              swap_total_gib=0.0,
                                              swap_used_gib=0.0))
    want("swapless box does not divide by zero", noswap["swap_util"], 0.0)

    # 7. Disk, and the build headroom that only applies when we build.
    full = probe_host(7, True, meminfo_text=HEALTHY_BOX, disk=FULL_DISK)
    want("3 GiB free refuses a building run", full["fit"], False)
    full_nobuild = probe_host(7, False, meminfo_text=HEALTHY_BOX, disk=FULL_DISK)
    want("...and still refuses --no-build (3 GiB < 5 GiB floor)",
         full_nobuild["fit"], False)
    tight = probe_host(7, True, meminfo_text=_meminfo(mem_avail_gib=9.0),
                       disk=BIG_DISK)
    want("9 GiB avail refuses WITH a build (floor 10.49)", tight["fit"], False)
    tight_nb = probe_host(7, False, meminfo_text=_meminfo(mem_avail_gib=9.0),
                          disk=BIG_DISK)
    want("...and admits it with --no-build (floor 8.49)", tight_nb["fit"], True)

    # 8. The pre-3.14 fallback: no MemAvailable, and the row must say the
    #    figure is an estimate rather than pass it off as the same number.
    est = probe_host(7, True, disk=BIG_DISK,
                     meminfo_text=_meminfo(mem_avail_gib=20.0,
                                           with_available=False))
    want("MemAvailable absent -> estimated, and labelled",
         est["mem_available_estimated"], True)

    # 9. The recovery wait. Injected probe + clock, so this is instant.
    seq = [dict(loaded, fit=False), dict(loaded, fit=False),
           dict(healthy, fit=True)]
    calls = {"n": 0}

    def fake_probe(_n, _b):
        s = seq[min(calls["n"], len(seq) - 1)]
        calls["n"] += 1
        return s

    ticks = {"t": 0.0}

    def fake_clock():
        return ticks["t"]

    def fake_sleep(secs):
        ticks["t"] += secs

    state, waited = await_floor(7, True, 300, probe=fake_probe,
                                sleep=fake_sleep, clock=fake_clock)
    want("await_floor returns as soon as the floor is re-attained",
         (state["fit"], waited), (True, 20))

    calls["n"] = 0
    ticks["t"] = 0.0
    seq = [dict(loaded, fit=False)]
    state, waited = await_floor(7, True, 45, probe=fake_probe,
                                sleep=fake_sleep, clock=fake_clock)
    want("await_floor gives up at the timeout and stays unfit",
         (state["fit"], waited >= 45), (False, True))

    # 10. The degradation doctrine, over synthetic files. This is the
    #     asymmetry: it can withhold a red, and it can never grant a green.
    def doctrine(name, rows, want_exit, show=False):
        nonlocal failures
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False,
                                         dir=tempfile.gettempdir()) as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
            path = f.name
        try:
            code, out = census(path, 0, expect_nodes=EXPECT_NODES)
        finally:
            os.unlink(path)
        ok = code == want_exit
        if not ok:
            failures += 1
        print(f"── self-test [{name}]: exit={code} want={want_exit}  "
              f"{'ok' if ok else 'SELF-TEST FAILURE'}")
        if show:
            for line in out:
                print(line)

    broken = [r for r in _golden()
              if not (r["node"] == "sub-1" and r["leg"] == "scope.seal")]

    doctrine("healthy host + clean run -> 0",
             _golden() + _host_rows(healthy, healthy), 0)
    doctrine("healthy host + violations -> 1 (a real red, no excuse)",
             broken + _host_rows(healthy, healthy), 1)
    doctrine("DEGRADED host + violations -> 75 NOT MEASURED (#536)",
             broken + _host_rows(healthy, loaded), NOT_MEASURED, show=True)
    doctrine("degraded host + clean run -> 0, the pass STANDS",
             _golden() + _host_rows(healthy, loaded), 0, show=True)
    doctrine("degraded at the START too -> still 75",
             broken + _host_rows(loaded, loaded), NOT_MEASURED)
    doctrine("no host rows (a pre-#536 baseline) -> unchanged verdict",
             broken, 1)
    doctrine("no host rows, clean -> unchanged verdict",
             _golden(), 0)
    doctrine("host rows do NOT count as a node or a leg",
             _golden() + _host_rows(healthy, healthy), 0)
    doctrine("empty file + degraded host -> 75, not a bare NO LEGS",
             _host_rows(healthy, loaded), NOT_MEASURED)
    doctrine("empty file + healthy host -> 1, nothing was measured",
             _host_rows(healthy, healthy), 1)
    doctrine("duplicated host rows refuse the file (a merged run)",
             _golden() + _host_rows(healthy, healthy)
             + _host_rows(healthy, healthy), 1)

    # 10b. The injection seam cannot launder a red. Identical to the #536
    #      case above except that the host rows keep their `<injected>`
    #      fingerprint — and the verdict comes back 1, not 75.
    doctrine("SYNTHETIC host rows may NOT withhold a red -> 1, not 75",
             broken + [hoststate_row(healthy, "pre"),
                       hoststate_row(loaded, "post")], 1, show=True)

    # 10c. And the fingerprint survives the env-var path, which is what
    #      run.sh's own dry-run uses.
    fake = tempfile.NamedTemporaryFile("w", suffix=".meminfo", delete=False,
                                       dir=tempfile.gettempdir())
    fake.write(HEALTHY_BOX)
    fake.close()
    saved = (os.environ.get(MEMINFO_ENV), os.environ.get(DISK_FREE_ENV))
    try:
        os.environ[MEMINFO_ENV] = fake.name
        os.environ[DISK_FREE_ENV] = "400"
        env_state = probe_host(7, True)
        want(f"{MEMINFO_ENV} is read and fingerprinted",
             (env_state["fit"], is_synthetic(env_state)), (True, True))
        want(f"{DISK_FREE_ENV} substitutes the disk reading",
             env_state["disk_free_gib"], 400.0)
    finally:
        for k, v in zip((MEMINFO_ENV, DISK_FREE_ENV), saved):
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        os.unlink(fake.name)
    want("a real reading is NOT fingerprinted as synthetic",
         is_synthetic({"meminfo_source": REAL_MEMINFO}), False)

    # 11. The refusal text itself. This is the 2 a.m. output; if it ever
    #     starts to look like a census, that is the regression.
    print("── the NOT MEASURED refusal, verbatim:")
    for line in render_refusal(loaded, "relays=1 subs=4", waited=180):
        print(line)
    forbidden = ("ran+ok=", "contract violations:", "legs recorded:")
    text = "\n".join(render_refusal(loaded, "relays=1 subs=4"))
    want("the refusal contains no census-shaped line",
         [f for f in forbidden if f in text], [])

    return failures


def self_test():
    failures = 0

    def check(name, rows, want_exit, expect_nodes=EXPECT_NODES):
        nonlocal failures
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, dir=tempfile.gettempdir()
        ) as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
            path = f.name
        try:
            code, out = census(path, 0, expect_nodes=expect_nodes)
        finally:
            os.unlink(path)
        verdict = "ok" if code == want_exit else "SELF-TEST FAILURE"
        if code != want_exit:
            failures += 1
        print(f"── self-test [{name}]: exit={code} want={want_exit}  {verdict}")
        for line in out:
            print(line)

    def check_raw(name, text, want_exit):
        """Like `check`, but writes the file BYTE-EXACTLY — the concurrency
        artifacts below are properties of the bytes on disk, and round-tripping
        them through `json.dumps` per row would erase the very thing under test.
        """
        nonlocal failures
        with tempfile.NamedTemporaryFile(
            "w", suffix=".jsonl", delete=False, dir=tempfile.gettempdir()
        ) as f:
            f.write(text)
            path = f.name
        try:
            code, out = census(path, 0)
        finally:
            os.unlink(path)
        verdict = "ok" if code == want_exit else "SELF-TEST FAILURE"
        if code != want_exit:
            failures += 1
        print(f"── self-test [{name}]: exit={code} want={want_exit}  {verdict}")

    # CIRISEdge#532 — every node appends to ONE file on a shared volume, so a
    # non-atomic append can land two complete records on one line. This killed a
    # ten-minute M=4 run with `JSONDecodeError: Extra data` — a MEASUREMENT
    # fault that presented as a failed run. Two complete objects are unambiguous,
    # so they are recovered; the run is reported, not thrown away.
    golden_text = "".join(json.dumps(r) + "\n" for r in _golden())
    glued = golden_text.replace("}\n{", "}{", 1)
    check_raw("two records glued onto one line are RECOVERED, not fatal", glued, 0)

    # But a TORN record is not recoverable, and guessing at one would be worse
    # than refusing. NOT MEASURED, like the host pre-flight — never a verdict
    # assembled from a partial file, which would under-count legs and read as
    # "legs did not run".
    torn = golden_text + '{"node":"sub-9","le\n'
    check_raw("a torn record refuses the verdict (NOT MEASURED)", torn, NOT_MEASURED)

    check("golden: all contracts met, late-joiner skips allowed", _golden(), 0)

    rows = [r for r in _golden()
            if not (r["node"] == "sub-1" and r["leg"] == "scope.seal")]
    check("missing expected leg (sub-1 scope.seal dropped)", rows, 1)

    rows = [r for r in _golden()
            if not (r["node"] == "publisher" and r["leg"] == "conformance.seal_retires")]
    rows.append(_row("publisher", "publisher", "conformance.seal_retires",
                     ran=False, reason="pre-seal dials did not establish"))
    check("expected leg not_run (publisher seal_retires)", rows, 1)

    rows = _golden()
    rows.append(_row("relay-1", "relay", "perf.extra_probe", ran=True, ok=False))
    check("failed NON-expected leg (relay perf.extra_probe ok=false)", rows, 1)

    rows = _golden()
    rows.append(_row("nonmember", "nonmember", "conformance.extra_probe",
                     ran=False, reason="did not apply to this topology"))
    check("allowed NON-expected not_run (nonmember extra probe)", rows, 0)

    rows = _golden() + [_row("sub-1", "subscriber", "mesh.standup")]
    check("duplicate (node, leg) row refused", rows, 1)

    rows = _golden()
    rows.append(_row("sub-1", "subscriber", "mesh.role_completion",
                     ran=False, reason="apply_remote_commit: WrongEpoch"))
    check("role_completion bail marker fails", rows, 1)

    rows = [r for r in _golden() if r["node"] != "relay-1"]
    check("expected node emitted nothing (relay-1 silent)", rows, 1)

    print("")
    print("══ host capacity: the pre-flight and the degradation doctrine ══")
    failures += preflight_self_test()

    print(f"── self-test: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
    return 1 if failures else 0


def run_preflight(args):
    """`--preflight`. Two phases, and their exit codes mean different
    things on purpose:

      --phase pre   a GATE. Exits 75 if the box cannot support the point,
                    after waiting up to --wait seconds for it to recover.
                    run.sh must not start a container on a 75.
      --phase post  a RECORDER. Always exits 0. It samples the box the
                    point ended on and writes the row; the ADMISSIBILITY
                    decision is the census's, from the file, so that
                    re-censusing a committed baseline reaches the same
                    verdict without the box being present.

    Either way the JSONL row goes to --row-out (or stdout) and the human
    text goes to stderr, so run.sh can capture one without the other."""
    def log(line):
        print(line, file=sys.stderr)

    if args.phase == "pre":
        state, waited = await_floor(args.nodes, args.build, args.wait, log=log)
    else:
        state, waited = probe_host(args.nodes, args.build), 0

    row = hoststate_row(state, args.phase, args.attempt, args.point)
    text = json.dumps(row, sort_keys=True)
    if args.row_out:
        with open(args.row_out, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)

    if state["fit"]:
        log(f"  host {args.phase}-flight ({args.nodes} nodes"
            + (", build" if args.build else "") + "): within floor")
        log(f"    {state_one_line(state)}")
        return 0

    if args.phase == "post":
        # Not a gate: say it loudly and let the census decide, because the
        # census can also see whether anything actually failed.
        log(f"  host post-flight: BELOW FLOOR — {state_one_line(state)}")
        log("  the box degraded under this point; the census decides "
            "whether its verdict is admissible.")
        return 0

    for line in render_refusal(state, args.point or f"{args.nodes} nodes",
                               waited=waited):
        log(line)
    return NOT_MEASURED


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("path", nargs="?", help="results JSONL")
    ap.add_argument("rc", nargs="?", type=int, default=0,
                    help="publisher container exit code (default 0)")
    ap.add_argument("--late-joiner", default=None,
                    help="node id of the deliberate late joiner; empty string "
                         "= none; omitted = infer from publisher scope.rotation")
    ap.add_argument("--expect", default=None,
                    help="comma-separated node ids the topology started — a "
                         "silent node then fails instead of vanishing")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--preflight", action="store_true",
                    help="hold the HOST to the floor for a point of --nodes "
                         "containers; exit 75 (NOT MEASURED) if it cannot")
    ap.add_argument("--nodes", type=int, default=0,
                    help="containers this point will start (publisher + "
                         "relays + subscribers + nonmember)")
    ap.add_argument("--build", action="store_true",
                    help="this point will also build the image, which is the "
                         "heaviest single consumer in the harness")
    ap.add_argument("--phase", choices=("pre", "post"), default="pre",
                    help="pre = gate before the first container; "
                         "post = record the state the point ended in")
    ap.add_argument("--attempt", type=int, default=1,
                    help="1, or 2 for a re-run after a NOT MEASURED")
    ap.add_argument("--wait", type=int, default=0,
                    help="seconds to wait for the floor to be re-attained "
                         "before refusing (--phase pre only)")
    ap.add_argument("--point", default=None,
                    help="human label for this point, e.g. 'relays=1 subs=4'")
    ap.add_argument("--row-out", default=None,
                    help="write the mesh.hoststate JSONL row here instead of "
                         "stdout")
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if args.preflight:
        if args.nodes < 1:
            ap.error("--preflight needs --nodes N (how many containers)")
        sys.exit(run_preflight(args))
    if not args.path:
        ap.error("a results JSONL path is required (or --self-test/--preflight)")
    # Omitted flag = infer from the file; explicit "" = there is none.
    lj = INFER if args.late_joiner is None else (args.late_joiner or None)
    expect = [n for n in (args.expect or "").split(",") if n] or None
    code, out = census(args.path, args.rc, late_joiner=lj, expect_nodes=expect)
    for line in out:
        print(line)
    sys.exit(code)


if __name__ == "__main__":
    main()
