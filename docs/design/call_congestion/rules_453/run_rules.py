#!/usr/bin/env python3
"""Run TLC on the 45.3 rule rows (R24-R29) and tabulate what holds.

    python3 docs/design/call_congestion/rules_453/run_rules.py OUTDIR [--only REGEX] [--split]

--split runs each invariant on its own (a state that breaks two invariants is
reported under the first only, even with -continue).

Each scenario is one module, one constant assignment, and the invariants
and/or temporal properties it checks. TLC runs once per (scenario, property)
per temporal property, and once per scenario for all its invariants
(with -continue, so every violated invariant is listed). Results go
to OUTDIR/rules.json and OUTDIR/rules.md.

TLC goes through the host scheduler at low priority, the same convention as
../run_matrix.py: GRACE_SCHED_* + cargo_guard.sh, nice 19, ionice idle,
2 workers, declared peak 3 GB (these specs measure well under 1 GB).
"""
import json
import os
import re
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JAR = os.path.expanduser("~/.cache/ciris-kernel/tla2tools-1.7.4.jar")
GUARD = os.path.expanduser("~/CIRISGrace/bin/cargo_guard.sh")
CAP_SECS = 1800


def B(x):
    return "TRUE" if x else "FALSE"


def S(x):
    return f'"{x}"'


# ------------------------------------------------------------------- R29
OAL = dict(OfferEvery=4, Life=10, StaleB=4, BMax=12, Depth=1, Suspect=6,
           DownSilence=20, Cap=40, GraceSigned=B(False), PubLate=B(True),
           LoseOne=B(True))


def oal(kind, rule, **kw):
    return dict(OAL, Kind=S(kind), Rule=S(rule), **kw)


SCEN = []


def add(name, module, consts, invs=(), props=()):
    SCEN.append(dict(name=name, module=module, consts=consts,
                     invs=list(invs), props=list(props)))


# The lying relay, publisher never late (nothing to excuse).
for rule in ("current", "signed"):
    for gs in (False, True):
        if rule == "current" and gs:
            continue
        tag = rule + ("-gs" if gs else "")
        c = oal("liar", rule, PubLate=B(False), GraceSigned=B(gs))
        add(f"R29-liar-ontime-{tag}", "OfferAsLife", c,
            invs=["TypeOK", "LiarHeldTotal"], props=["LiarFailsOver"])
# The lying relay, the publisher late at times (a real late stamp to replay).
for rule, gs in (("current", False), ("signed", False), ("signed", True)):
    tag = rule + ("-gs" if gs else "")
    c = oal("liar", rule, GraceSigned=B(gs))
    add(f"R29-liar-late-{tag}", "OfferAsLife", c,
        invs=["TypeOK", "LiarWithinDown", "LiarAfterCalm"])
# The honest cases, every rule.
for rule, gs in (("current", False), ("signed_pubage", True), ("signed", True)):
    tag = rule + ("-gs" if gs else "")
    add(f"R29-honest-{tag}", "OfferAsLife", oal("honest", rule, GraceSigned=B(gs)),
        invs=["TypeOK", "NeverFailsOver", "NotChargedAtOnce"])
    add(f"R29-gone-{tag}", "OfferAsLife", oal("gone", rule, GraceSigned=B(gs)),
        invs=["TypeOK", "OffersStopBound", "NotChargedAtOnce"])
    add(f"R29-blackhole-{tag}", "OfferAsLife", oal("blackhole", rule, GraceSigned=B(gs)),
        invs=["TypeOK", "BlackHoleBound", "NotChargedAtOnce"])
# The honest case with a short backlog (<= Life): signed_pubage holds there.
add("R29-honest-signed_pubage-gs-bmax8", "OfferAsLife",
    oal("honest", "signed_pubage", GraceSigned=B(True), BMax=8),
    invs=["TypeOK", "NeverFailsOver"])

# Rows R24-R28 register themselves from rows_453.py (kept apart so row 6 runs
# on its own first).
try:
    sys.path.insert(0, HERE)
    import rows_453  # noqa: E402
    rows_453.register(add, B, S)
except ImportError:
    pass


def cfg_text(s, inv=None, prop=None):
    lines = ["CONSTANTS"] + [f"    {k} = {v}" for k, v in s["consts"].items()]
    lines.append("SPECIFICATION Spec")
    if inv:
        lines.append(f"INVARIANTS {inv}")
    if prop:
        lines.append(f"PROPERTIES {prop}")
    lines.append("CHECK_DEADLOCK FALSE")
    return "\n".join(lines) + "\n"


def tlc(outdir, run, cfgtext, module, extra=()):
    cfg = os.path.join(outdir, run + ".cfg")
    open(cfg, "w").write(cfgtext)
    env = dict(os.environ, GRACE_SCHED_OWNER="edge",
               GRACE_SCHED_KIND="edge: call rules TLC", GRACE_SCHED_PEAK_GB="3",
               GRACE_SCHED_PRIORITY="low")
    cmd = ["timeout", str(CAP_SECS), "nice", "-n", "19", "ionice", "-c3", GUARD,
           "java", "-Xmx2g", "-Xss64m", "-XX:+UseParallelGC", "-cp", JAR, "tlc2.TLC",
           "-workers", "2", *extra, "-config", cfg,
           "-metadir", os.path.join(outdir, run + ".states"),
           os.path.join(outdir, module + ".tla")]
    log = os.path.join(outdir, run + ".log")
    with open(log, "w") as fh:
        rc = subprocess.call(cmd, stdout=fh, stderr=subprocess.STDOUT, cwd=outdir, env=env)
    text = open(log).read()
    shutil.rmtree(os.path.join(outdir, run + ".states"), ignore_errors=True)
    res = dict(run=run, rc=rc)
    m = re.findall(r"(\d+) states generated, (\d+) distinct states found", text)
    if m:
        res["states"], res["distinct"] = int(m[-1][0]), int(m[-1][1])
    m = re.search(r"depth of the complete state graph search is (\d+)", text)
    if m:
        res["depth"] = int(m.group(1))
    bad = sorted(set(re.findall(r"Invariant (\S+) is violated", text)))
    if "Temporal properties were violated" in text:
        bad.append("(temporal)")
    if bad:
        res["verdict"] = "FAIL: " + ", ".join(bad)
    elif "No error has been found" in text or ("Model checking completed" in text
                                                and "Error:" not in text):
        res["verdict"] = "pass"
    else:
        res["verdict"] = "error, see log"
    if bad:
        # The counterexample's states, for the .md's plain words.
        res["trace_states"] = len(re.findall(r"^State \d+:", text, re.M))
        if "Stuttering" in text or "Back to state" in text:
            res["lasso"] = True
    return res


def main():
    outdir = os.path.abspath(sys.argv[1])
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    os.makedirs(outdir, exist_ok=True)
    for f in os.listdir(HERE):
        if f.endswith(".tla"):
            shutil.copy(os.path.join(HERE, f), outdir)
    results = []
    for s in SCEN:
        if only and not re.search(only, s["name"]):
            continue
        if s["invs"] and "--split" in sys.argv:
            for inv in s["invs"]:
                if inv == "TypeOK":
                    continue
                if "--inv" in sys.argv and inv != sys.argv[sys.argv.index("--inv") + 1]:
                    continue
                run = f'{s["name"]}.{inv}'
                r = tlc(outdir, run, cfg_text(s, inv="TypeOK " + inv), s["module"])
                r["checked"] = inv
                results.append(r)
                print(json.dumps(r), flush=True)
        elif s["invs"]:
            # every invariant in one run; -continue lists each one violated
            run = f'{s["name"]}.inv'
            r = tlc(outdir, run, cfg_text(s, inv=" ".join(s["invs"])), s["module"],
                    extra=("-continue",))
            r["checked"] = " ".join(s["invs"])
            results.append(r)
            print(json.dumps(r), flush=True)
        for prop in s["props"]:
            run = f'{s["name"]}.{prop}'
            r = tlc(outdir, run, cfg_text(s, prop=prop), s["module"])
            results.append(r)
            print(json.dumps(r), flush=True)
    json.dump(results, open(os.path.join(outdir, "rules.json"), "w"), indent=1)
    with open(os.path.join(outdir, "rules.md"), "w") as fh:
        fh.write("| run | checked | states | distinct | depth | verdict |\n|---|---|---|---|---|---|\n")
        for r in results:
            fh.write(f'| {r["run"]} | {r.get("checked", r["run"].split(".")[-1])} | {r.get("states", "-")} | {r.get("distinct", "-")} | '
                     f'{r.get("depth", "-")} | {r["verdict"]} |\n')


if __name__ == "__main__":
    main()
