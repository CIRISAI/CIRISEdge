#!/usr/bin/env python3
"""Check a recorded capped-uplink run against what the model can reach.

    python3 trace_check.py OBSERVED.txt RUN.json         # a run as JSON
    python3 trace_check.py OBSERVED.txt --log EDGE.log   # straight from the test's stderr

OBSERVED.txt is what run_matrix.py writes per scenario: every distinct
observation a terminal state of that scenario makes (CallCongestion.tla
`Observed`). Run the scenario whose switches are the recorded run's pins
(recorded_runs/*.json name it).

A recorded run CONFORMS when at least one reachable observation matches
every field the run records, within the tolerance:

- first_torn: per node, seconds from the cap to the first leg torn down AT
  that node (exhausted as the dialer, stale as the receiver), or null for
  none. Matched within TOL_TICKS ticks (100 ms each).
  - From the log: the `ciris_edge::link_close` lines with reason
    ChannelExhausted / Stale, minus the "G8 cap on" line's time.
  - From the test's context line: "first teardown after the cap (P, A, B, C, T)".
- exhausted: links torn down by retry exhaustion. A count, or [lo, hi].
- direct / relayed: P's direct children / listeners on a relay at the end.
- sheds, verdicts: the ALM counters `shed` and `alm_uplink_stall`. The model
  counts a verdict per rise, as edge labels it.
- heard_pct: per listener, a [lo, hi] percent of what P published.

A run that matches nothing is either a model gap or a code path the model
does not have; the script prints the nearest observation and the fields
that differ, which is where to look.
"""
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_matrix import tokens, value  # noqa: E402

TOL_TICKS = 3
TICK_S = 0.1


def load_observed(path):
    out = []
    for line in open(path):
        line = line.strip()
        if line:
            v, _ = value(tokens(line))
            out.append(v)
    return out


def fn(v):
    return v[1] if isinstance(v, tuple) and v and v[0] == "fn" else v


def within(x, want):
    if want is None:
        return True
    if isinstance(want, list):
        return want[0] <= x <= want[1]
    return x == want


def mismatches(obs, run):
    bad = []
    ft = fn(obs["first_torn"])
    for node, want in (run.get("first_torn") or {}).items():
        got = ft.get(node, -1)
        if want is None:
            if got != -1:
                bad.append(f"first_torn[{node}]: model {got * TICK_S:.1f}s, run none")
            continue
        lo, hi = (want if isinstance(want, list) else [want, want])
        if got == -1 or not (lo / TICK_S - TOL_TICKS <= got - run["cap_at_ticks"] <= hi / TICK_S + TOL_TICKS):
            shown = "none" if got == -1 else f"{(got - run['cap_at_ticks']) * TICK_S:.1f}s"
            bad.append(f"first_torn[{node}]: model {shown}, run {want}")
    for k in ("exhausted", "direct", "relayed", "sheds", "verdicts"):
        if k in run and not within(obs[k], run[k]):
            bad.append(f"{k}: model {obs[k]}, run {run[k]}")
    hp = fn(obs["heard_pct"])
    for c, want in (run.get("heard_pct") or {}).items():
        if not within(hp[c], want):
            bad.append(f"heard_pct[{c}]: model {hp[c]}, run {want}")
    for rule in run.get("order", []):   # e.g. ["A<P"]: A's first teardown before P's
        a, b = rule.split("<")
        ta, tb = ft.get(a, -1), ft.get(b, -1)
        if ta == -1 or (tb != -1 and ta > tb):
            bad.append(f"order {rule}: model {a}={ta} {b}={tb}")
    return bad


def from_log(path):
    """first_torn and exhausted from the edge test's stderr."""
    cap_t, names, closes = None, {}, []
    ts = re.compile(r"(\d{4}-\d\d-\d\dT\d\d:\d\d:(\d\d\.\d+))Z")

    def secs(line):
        m = ts.search(line)
        if not m:
            return None
        hh, mm = m.group(1)[11:13], m.group(1)[14:16]
        return int(hh) * 3600 + int(mm) * 60 + float(m.group(2))

    for line in open(path):
        if "G8 cap on" in line:
            cap_t = secs(line)
            for role, key in re.findall(r'\("(\w)", "([0-9a-f]+)"\)', line):
                names[key] = role
        elif "link closed" in line and "ciris_edge::link_close" in line:
            node = re.search(r"node=(\S+)", line)
            reason = re.search(r"reason=(\w+)", line)
            closes.append((secs(line), node.group(1) if node else "?",
                           reason.group(1) if reason else "?"))
    first, exhausted = {}, 0
    for t, node, reason in closes:
        if cap_t is None or t is None or t < cap_t:
            continue
        role = names.get(node, node)
        if reason in ("ChannelExhausted", "Stale", "Timeout"):
            exhausted += reason == "ChannelExhausted"
            first.setdefault(role, round(t - cap_t, 2))
    return {"first_torn": first, "exhausted": exhausted, "cap_at_ticks": 10}


def main():
    observed = load_observed(sys.argv[1])
    run = from_log(sys.argv[3]) if sys.argv[2] == "--log" else json.load(open(sys.argv[2]))
    run.setdefault("cap_at_ticks", 10)
    best = None
    for obs in observed:
        bad = mismatches(obs, run)
        if not bad:
            print(f"CONFORMS: {run.get('name', sys.argv[2])} is reachable "
                  f"({len(observed)} terminal observations)")
            print("  witness:", obs)
            return 0
        if best is None or len(bad) < len(best[1]):
            best = (obs, bad)
    print(f"DOES NOT CONFORM: {run.get('name', sys.argv[2])}; nearest observation differs in:")
    for b in best[1]:
        print("  -", b)
    print("  nearest:", best[0])
    return 1


if __name__ == "__main__":
    sys.exit(main())
