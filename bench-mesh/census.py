#!/usr/bin/env python3
"""Role-contract census over a bench-mesh results JSONL.

    census.py <results.jsonl> [rc] [--late-joiner NODE] [--expect n1,n2,..]
    census.py --self-test

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
"""

import argparse
import collections
import json
import os
import sys
import tempfile

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


def census(path, rc, late_joiner=INFER, expect_nodes=None):
    """Returns (exit_code, printed lines). Never prints a number it did
    not read out of the file."""
    out = []
    legs = [json.loads(l) for l in open(path) if l.strip().startswith("{")]

    # Rule 4: duplicates refuse the file outright (a merged file).
    dupes = [
        k
        for k, n in collections.Counter((l["node"], l["leg"]) for l in legs).items()
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

    if not legs:
        out.append("  NO LEGS — nothing was measured.")
        return 1, out

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
    return (0 if rc == 0 and not violations else 1), out


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

    print(f"── self-test: {'ALL PASSED' if failures == 0 else f'{failures} FAILED'}")
    return 1 if failures else 0


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
    args = ap.parse_args()

    if args.self_test:
        sys.exit(self_test())
    if not args.path:
        ap.error("a results JSONL path is required (or --self-test)")
    # Omitted flag = infer from the file; explicit "" = there is none.
    lj = INFER if args.late_joiner is None else (args.late_joiner or None)
    expect = [n for n in (args.expect or "").split(",") if n] or None
    code, out = census(args.path, args.rc, late_joiner=lj, expect_nodes=expect)
    for line in out:
        print(line)
    sys.exit(code)


if __name__ == "__main__":
    main()
