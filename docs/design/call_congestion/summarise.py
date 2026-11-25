#!/usr/bin/env python3
"""Quality figures per scenario, from run_matrix.py's OUTDIR/<name>.observed.txt.

    python3 summarise.py OUTDIR [REGEX]

For each scenario, over every distinct terminal observation (so: over the
offer and window phases, the tie-breaks, the re-punch times, ...), the
min / median / max of:

- verdict_s: the first stall verdict, seconds after the cap (-: none);
- shed_s: the first shed, seconds after the cap;
- q_at_shed_s: P's queue delay when the first shed landed;
- max_q_s: the largest queue delay P's uplink reached;
- end_q_s: the queue delay at the horizon;
- heard_min_pct: the worst listener's heard share;
- full_at_s: when every listener first had P as its parent (from t=0).

Ticks are 100 ms. Values are over distinct observations, not weighted by
how many behaviours reach each one: reachability, not likelihood.
"""
import json
import os
import re
import statistics
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_matrix import tokens, value, scenarios, BASE  # noqa: E402


def fn(v):
    return v[1] if isinstance(v, tuple) and v and v[0] == "fn" else v


def stats(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return "-"
    return f"{min(xs):.1f} / {statistics.median(xs):.1f} / {max(xs):.1f}"


def main():
    outdir = sys.argv[1]
    pat = sys.argv[2] if len(sys.argv) > 2 else ".*"
    rows = ["| scenario | verdict_s | shed_s | q_at_shed_s | max_q_s | end_q_s | heard_min_pct | full_at_s | parent_gap_s | media_gap_s | drain_clear_s | cap_end_q_s | zero_direct_s | ok_after_kill_s | admits_ignored | max_parentless_s | probe_fails | obs |",
            "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for name, params in scenarios():
        if not re.fullmatch(pat, name):
            continue
        path = os.path.join(outdir, name + ".observed.txt")
        if not os.path.exists(path):
            continue
        cap = int(dict(BASE, **params)["CAPAT"])
        dead = dict(BASE, **params)["DEAD"].strip('"')   # a departed node's heard is not judged
        obs = []
        for line in open(path):
            line = line.strip()
            if line:
                obs.append(value(tokens(line))[0])
        if not obs:
            continue
        t = lambda k: [((o[k] - cap) / 10 if o[k] >= 0 else None) for o in obs]
        rows.append("| " + " | ".join([
            name,
            stats(t("first_verdict")),
            stats(t("first_shed")),
            stats([o["q_at_shed"] / 10 if o["q_at_shed"] >= 0 else None for o in obs]),
            stats([o["max_qdelay"] / 10 for o in obs]),
            stats([o["qdelay"] / 10 for o in obs]),
            stats([min(v for k, v in fn(o["heard_pct"]).items() if k != dead) for o in obs]),
            stats([o["full_at"] / 10 if o["full_at"] >= 0 else None for o in obs]),
            stats([o["parent_gap"] / 10 for o in obs]),
            stats([o["media_gap"] / 10 for o in obs]),
            stats([(o["drain_clear"] - o["first_shed"]) / 10 if o["drain_clear"] >= 0 and o["first_shed"] >= 0 else None for o in obs]),
            stats([o["cap_end_q"] / 10 if o["cap_end_q"] >= 0 else None for o in obs]),
            stats([o["zero_direct"] / 10 for o in obs]),
            stats([o["all_ok_after_kill"] / 10 if o.get("all_ok_after_kill", -1) >= 0 else None for o in obs]),
            stats([o.get("admits_ignored", 0) for o in obs]),
            stats([o.get("max_parentless", 0) / 10 for o in obs]),
            stats([o.get("probe_fails", 0) for o in obs]),
            str(len(obs))]) + " |")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
