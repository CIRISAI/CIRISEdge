#!/usr/bin/env python3
"""Run TLC on CallCongestion.tla for each scenario and tabulate what holds.

    python3 docs/design/call_congestion/run_matrix.py OUTDIR [--only REGEX]
    python3 docs/design/call_congestion/run_matrix.py OUTDIR --trace NAME PROPERTY
    python3 docs/design/call_congestion/run_matrix.py OUTDIR --reparse

check mode: for each scenario this writes OUTDIR/<name>.cfg and runs TLC on
MCCallCongestion.tla with -continue, so every violated invariant is listed,
not just the first; the outcome probe (RecordOutcome) prints the outcome of
every terminal state. The summary goes to OUTDIR/matrix.json and matrix.md.

trace mode: one scenario, TraceOn = TRUE, the traced variant T_<PROPERTY>
only; the first violation prints the compact per-tick history, rendered to
OUTDIR/<name>.<PROPERTY>.trace.txt. (This TLC build prints no error trace
for this spec past ~23 states, so the history is the trace.)

TLC goes through the host's scheduler (one run at a time, honest memory
figure): GRACE_SCHED_* + cargo_guard.sh, nice 19, ionice idle.
Same conventions as leviculum docs/direct_link/run_matrix.py.
"""
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
JAR = os.path.expanduser("~/.cache/ciris-kernel/tla2tools-1.7.4.jar")
GUARD = os.path.expanduser("~/CIRISGrace/bin/cargo_guard.sh")
CAP_SECS = 5400

ALL_OFF = dict(RPA="FALSE", RTO="FALSE", HOLD="FALSE", SOV="FALSE", RKO="FALSE",
               SS="FALSE", RPU="FALSE", DRAIN="FALSE", PEER="FALSE", RXMOVE="FALSE",
               PBO="FALSE", HASH="FALSE", STAG="FALSE", SERIAL="FALSE", PROBE2="FALSE")
SWITCH = dict(RPA="ReceiptsPerAttempt", RTO="RtoLearnsDelay", HOLD="Hold113",
              SOV="ShedOnVerdict", RKO="RoomKeepsOne", SS="SlowStart",
              RPU="RedialOnPathUp", DRAIN="ShedDrains", PEER="PeerLiveness",
              RXMOVE="ReceiverMoves", PBO="ProbeBackoff", HASH="HashRank",
              STAG="StaggeredSetup", SERIAL="SerialRedial", PROBE2="ProbeTwoLegs")
INVS = "TypeOK RecordOutcome"   # the properties fold into `bad`, read per terminal state
BASE = dict(ALL_OFF, CLOSELOST="FALSE", LSEQ="Listeners3", RANK="Rank3", RCAP="4", CAPAT="10",
            CAPUNTIL="50", HORIZON="230", STALE="100", SRTTCAP="17", WATCH="2",
            SLOTS="1", PUNCH="{10, 30}", PPH="{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}",
            LPH="{0, 5}", WPH="{0, 5}", NPICK="2", DEAD='"none"', INIT="1", SETUP="0",
            DWELL="20", CSTALE="20", GAP="15",
            DEADAT="0", TRACE="FALSE", WIDE="FALSE", INVS=INVS, PROPS="")


def on(*keys):
    return {k: "TRUE" for k in keys}


# Today's code at each pin, as switches (CallCongestion.md, "The switches").
TODAY_LEV_C86 = on("HOLD")                    # leviculum c8699c3d6 (#113 hold only)
TODAY_LEV_C75 = on("HOLD", "RPA")             # leviculum c75fdeb01 (+ per-attempt receipts)
EDGE_WIP = on("SOV", "RKO")                   # calls2's alm.rs (shed on rise, latch, room)
SIX = on("RPA", "RTO", "SOV", "RKO", "SS", "RPU")       # the brief's six
EIGHT = dict(SIX, **on("HOLD", "DRAIN"))                # + the #113 hold, make-before-break
ALL = dict(EIGHT, **on("PEER", "RXMOVE", "PBO"))        # + what the model found missing
# The lead's proposed minimum for 45.2.0's safety properties.
MIN = on("PEER", "SOV", "RKO", "PBO", "SERIAL")
SETUP = dict(SETUP="40")                      # ~1 s of P's queue per leg set up (F11)


def scenarios():
    yield "smoke-baseline", dict(PPH="{3}", LPH="{0}", WPH="{0}", NPICK="1", PUNCH="{10}")
    yield "baseline", {}
    for k in SWITCH:
        yield f"only-{SWITCH[k]}", on(k)
    yield "pin-c8699c3d6", TODAY_LEV_C86
    yield "pin-c75fdeb01", TODAY_LEV_C75
    yield "pin-c75fdeb01+edge-wip", dict(TODAY_LEV_C75, **EDGE_WIP)
    yield "six-on", SIX
    yield "eight-on", EIGHT
    yield "all-on", ALL
    for k in ALL:
        yield f"all-but-{SWITCH[k]}", dict(ALL, **{k: "FALSE"})
    # ReceiverMoves without the wire addition: a rank every member computes.
    yield "all-on-hashrank", dict(ALL, HASH="TRUE")
    yield "cap-stays-all-on-hashrank", dict(ALL, HASH="TRUE", CAPUNTIL="1000")
    # The minimum safety set, and its leave-one-outs (with and without setup cost).
    for tag, extra in [("", {}), ("-setup", SETUP)]:
        yield f"min{tag}", dict(MIN, **extra)
        for k in MIN:
            yield f"min{tag}-but-{SWITCH[k]}", dict(MIN, **{k: "FALSE"}, **extra)
        yield f"cap-stays-min{tag}", dict(MIN, CAPUNTIL="1000", **extra)
    yield "peer-only-setup", dict(on("PEER"), **SETUP)
    # Setup cost (F11) and the redial storm.
    yield "baseline-setup", SETUP
    yield "all-on-setup", dict(ALL, **SETUP)
    yield "all-on-setup-serial", dict(ALL, SERIAL="TRUE", **SETUP)
    # A call that STARTS on a weak uplink (its own legs' setup in the queue).
    for stag in ["FALSE", "TRUE"]:
        t = "stag" if stag == "TRUE" else "burst"
        yield f"start-weak-{t}-min", dict(MIN, CAPAT="0", STAG=stag, **SETUP)
        yield f"start-weak-{t}-all-on", dict(ALL, CAPAT="0", STAG=stag, **SETUP)
    # The first room (probe) at 1, 2, N: time on a relay at the start vs peak queue.
    for n in ["1", "2", "3"]:
        yield f"probe{n}-uncapped", dict(ALL, INIT=n, CAPAT="1000", CAPUNTIL="1000")
        yield f"probe{n}-start-capped", dict(ALL, INIT=n, CAPAT="0")
    # The shed alone (SOV + RKO, receipts in, no peer hold): queue depth at the
    # shed and its peak, by overload (RCap 3 = 3.0x, 4 = 2.25x, 5 = 1.8x, 6 = 1.5x)
    # and by verdict latency (the offer phases); and with ProbeTwoLegs.
    for r in ["3", "4", "5", "6"]:
        yield f"shed-alone-rcap{r}", dict(on("RPA", "SOV", "RKO"), RCAP=r)
        yield f"shed-probe2-rcap{r}", dict(on("RPA", "SOV", "RKO", "PROBE2"), RCAP=r)
    yield "cap-stays-all-on", dict(ALL, CAPUNTIL="1000")
    yield "start-capped-all-on", dict(ALL, CAPAT="0")
    yield "n3-baseline", dict(LSEQ="Listeners2", RANK="Rank2")
    yield "n3-all-on", dict(ALL, LSEQ="Listeners2", RANK="Rank2")
    # A dead peer (#1030): the fixes must not hide it (evidence stops => the
    # hold stops). No cap; the stale bound and the SRTT cap scaled together.
    dead = dict(DEAD='"B"', DEADAT="30", STALE="40", SRTTCAP="6", CAPAT="1000", CAPUNTIL="1000")
    yield "dead-B-baseline", dead
    yield "dead-B-peer-only", dict(on("PEER"), **dead)
    yield "dead-B-all-on", dict(ALL, **dead)
    yield "dead-B-all-on-close-lost", dict(ALL, CLOSELOST="TRUE", **dead)
    yield "dead-B-capped-all-on", dict(ALL, **dict(dead, CAPAT="10"))
    yield "close-lost-all-on", dict(ALL, CLOSELOST="TRUE")
    yield "watch3-all-on", dict(ALL, WATCH="3")
    # The dwell and the ceiling staleness at the code's values (10 s, 60 s).
    yield "unscaled-all-on", dict(ALL, DWELL="100", CSTALE="600", HORIZON="330")
    yield "unscaled-min", dict(MIN, DWELL="100", CSTALE="600", HORIZON="330")
    yield "conf-run1", dict(TODAY_LEV_C86, CAPUNTIL="1000", HORIZON="200")
    yield "conf-run2", dict(TODAY_LEV_C75, CAPUNTIL="1000", HORIZON="200")
    for n, p in [("baseline", {}), ("pin-c75fdeb01", TODAY_LEV_C75), ("all-on", ALL), ("min", MIN)]:
        yield f"wide-{n}", dict(p, WIDE="TRUE")


def recover_by(p):
    """EndFullFanOut's bound (ticks after the cap lifts): the verdict's latch
    (20) and the window it closes in (10), the dwell and a window for the
    move, and the widenings: with SlowStart one stream per two clean windows,
    each waiting out the probe backoff (2W x 2^fails, fails <= 2, stepping
    down after each probe that held); without it, the ceiling's staleness."""
    n = 2 if p["LSEQ"] == "Listeners2" else 3
    w = 10
    if p["SS"] == "TRUE":
        fmax = 2 if p["PBO"] == "TRUE" else 0
        grow = sum(2 * w * 2 ** max(0, fmax - i) for i in range(max(0, n - int(p["INIT"]))))
    else:
        grow = int(p["CSTALE"])
    return str(20 + w + int(p["DWELL"]) + w + grow)


def max_reparents(p):
    """ReparentBound: the join, the move to a relay at the first congestion,
    the move back after a lift, and two per probe; with the probe backoff
    (2 windows x 2^fails) at most floor(log2(H / 2W)) + 1 probes fit."""
    import math
    h = int(p["HORIZON"])
    return str(3 + 2 * (int(math.log2(max(1, h // 20))) + 1))


def cfg_text(params):
    p = dict(BASE, **params)
    p.setdefault("RECOVER", recover_by(p))
    if "MAXREP" not in params:
        p["MAXREP"] = max_reparents(p)
    text = open(os.path.join(HERE, "base.cfg.tmpl")).read()
    for k, v in p.items():
        text = text.replace(f"@{k}@", v)
    assert "@" not in text, text
    return text


def tlc(outdir, name, cfgtext, extra=()):
    cfg = os.path.join(outdir, name + ".cfg")
    open(cfg, "w").write(cfgtext)
    env = dict(os.environ, GRACE_SCHED_OWNER="edge",
               GRACE_SCHED_KIND="edge: tlc call model", GRACE_SCHED_PEAK_GB="2")
    cmd = ["timeout", str(CAP_SECS), "nice", "-n", "19", "ionice", "-c3", GUARD,
           "java", "-Xmx2g", "-Xss64m", "-XX:+UseParallelGC", "-cp", JAR, "tlc2.TLC",
           "-workers", "2", *extra, "-config", cfg,
           "-metadir", os.path.join(outdir, name + ".states"),
           os.path.join(outdir, "MCCallCongestion.tla")]
    log = os.path.join(outdir, name + ".log")
    counts, obs = {}, set()
    with open(log, "w") as fh:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                cwd=outdir, text=True, env=env)
        buf = None
        for line in proc.stdout:
            # TLC pretty-prints a long value over several lines: join them.
            if buf is not None or line.lstrip().startswith(('<< "OUTCOME"', '<<"OUTCOME"')):
                buf = (buf or "") + " " + line.strip()
                if not line.rstrip().endswith(">>"):
                    continue
                line, buf = re.sub(r"\s+", " ", buf).replace("<< ", "<<").replace(" >>", ">>"), None
            m = re.search(r'<<"OUTCOME", "([^"]+)", \{([^}]*)\}, (\[.*\])>>', line)
            if m:
                obs.add(m.group(3))
                bad = ",".join(sorted(x.strip().strip('"') for x in m.group(2).split(",") if x.strip()))
                key = m.group(1) + (" [" + bad + "]" if bad else "")
                counts[key] = counts.get(key, 0) + 1
            else:
                fh.write(line)
        proc.wait()
        fh.write("OUTCOME_COUNTS " + json.dumps(counts) + "\n")
    # Every distinct observation a terminal state makes (trace_check.py reads it).
    with open(os.path.join(outdir, name + ".observed.txt"), "w") as fh:
        fh.write("\n".join(sorted(obs)) + "\n")
    subprocess.run(["rm", "-rf", os.path.join(outdir, name + ".states")])
    return log


def parse_log(log, params):
    t = open(log).read()
    violated = sorted(set(re.findall(r"Invariant (\w+) is violated", t)))
    for m in re.findall(r"OUTCOME_COUNTS (\{.*\})", t):
        for k in json.loads(m):
            if "[" in k:
                violated = sorted(set(violated) | set(k.split("[")[1].rstrip("]").split(",")))
    temporal = sorted(set(re.findall(r"Temporal propert(?:y|ies) (\w+)? ?(?:is|were) violated", t)))
    if "Temporal properties were violated" in t:
        temporal = temporal or ["(temporal)"]
    distinct = re.findall(r"([\d,]+) distinct states found", t)
    depth = re.findall(r"depth of the complete state graph search is (\d+)", t)
    outcomes = {}
    for m in re.findall(r"OUTCOME_COUNTS (\{.*\})", t):
        for k, v in json.loads(m).items():
            outcomes[k] = outcomes.get(k, 0) + v
    errors = [l for l in t.splitlines() if l.startswith("Error:") and "is violated" not in l
              and "behavior up to" not in l]
    return dict(violated=violated, temporal=temporal, finished="Finished in" in t,
                distinct=int(distinct[-1].replace(",", "")) if distinct else None,
                depth=int(depth[-1]) if depth else None, outcomes=outcomes,
                errors=errors[:3], params=params)


# --- a small reader for TLA+ values as TLC prints them -----------------------
TOK = re.compile(r'\s*(<<|>>|\|->|:>|@@|\\in|"(?:[^"\\]|\\.)*"|-?\d+|[A-Za-z_][A-Za-z_0-9]*|[\[\]{}(),])')


def tokens(s):
    pos, out = 0, []
    while pos < len(s):
        m = TOK.match(s, pos)
        if not m:
            if s[pos:].strip() == "":
                break
            raise ValueError(s[pos:pos + 40])
        out.append(m.group(1))
        pos = m.end()
    return out


def value(ts, i=0):
    t = ts[i]
    if t == "<<":
        items, i = [], i + 1
        while ts[i] != ">>":
            v, i = value(ts, i)
            items.append(v)
            if ts[i] == ",":
                i += 1
        return tuple(items), i + 1
    if t == "{":
        items, i = [], i + 1
        while ts[i] != "}":
            v, i = value(ts, i)
            items.append(v)
            if ts[i] == ",":
                i += 1
        return ("set", tuple(items)), i + 1
    if t == "[":
        rec, i = {}, i + 1
        while ts[i] != "]":
            k = ts[i]
            assert ts[i + 1] == "|->", ts[i:i + 3]
            v, i = value(ts, i + 2)
            rec[k] = v
            if ts[i] == ",":
                i += 1
        return rec, i + 1
    if t == "(":
        fn, i = {}, i + 1
        while ts[i] != ")":
            k, i = value(ts, i)
            assert ts[i] == ":>"
            v, i = value(ts, i + 1)
            fn[k] = v
            if ts[i] == "@@":
                i += 1
        return ("fn", fn), i + 1
    if t.startswith('"'):
        return t[1:-1], i + 1
    if t in ("TRUE", "FALSE"):
        return t == "TRUE", i + 1
    if re.fullmatch(r"-?\d+", t):
        return int(t), i + 1
    return t, i + 1


def show(v):
    if isinstance(v, tuple) and len(v) == 2 and v[0] == "set":
        return "{" + ", ".join(sorted(show(x) for x in v[1])) + "}"
    if isinstance(v, tuple) and len(v) == 2 and v[0] == "fn":
        return "(" + ", ".join(f"{show(k)}:{show(x)}" for k, x in v[1].items()) + ")"
    if isinstance(v, tuple):
        return "<" + ",".join(show(x) for x in v) + ">"
    if isinstance(v, dict):
        return "[" + " ".join(f"{k}={show(x)}" for k, x in v.items()) + "]"
    if isinstance(v, bool):
        return "T" if v else "F"
    return str(v)


def render_trace(text):
    """The compact history printed by Dump, one line per tick that changed."""
    line = next((l for l in text.splitlines() if l.startswith('<<"TRACE", ')), None)
    if line is None:
        return None
    hist, _ = value(tokens(line[len('<<"TRACE", '):-2]))
    lines, prev = [], {}
    for snap in hist:
        cur = {k: show(v) for k, v in snap.items()}
        changed = {k: v for k, v in cur.items() if prev.get(k) != v and k != "t"}
        prev = cur
        if changed:
            lines.append(f"t={cur['t']:>3}  " + "  ".join(f"{k}={v}" for k, v in changed.items()))
    return "\n".join(lines) + "\n"


def run_chunked(outdir, name, params):
    """One TLC run per P offer phase, merged: the behaviours are independent
    (every choice is fixed at Init), and a 5,120-wide BFS frontier of these
    states does not fit a 3 GB heap. Same coverage as one run."""
    p = dict(BASE, **params)
    phases = [x.strip() for x in p["PPH"].strip("{}").split(",")]
    merged = None
    obs = set()
    for ph in phases:
        part = f"{name}@{ph}"
        log = tlc(outdir, part, cfg_text(dict(params, PPH="{" + ph + "}")), extra=[])
        r = parse_log(log, params)
        o = os.path.join(outdir, part + ".observed.txt")
        obs |= {l for l in open(o).read().splitlines() if l}
        os.remove(o)
        if merged is None:
            merged = r
            merged["chunks"] = 1
            continue
        merged["violated"] = sorted(set(merged["violated"]) | set(r["violated"]))
        merged["temporal"] = sorted(set(merged["temporal"]) | set(r["temporal"]))
        merged["finished"] = merged["finished"] and r["finished"]
        merged["distinct"] = (merged["distinct"] or 0) + (r["distinct"] or 0)
        merged["depth"] = max(merged["depth"] or 0, r["depth"] or 0)
        for k, v in r["outcomes"].items():
            merged["outcomes"][k] = merged["outcomes"].get(k, 0) + v
        merged["errors"] = (merged["errors"] + r["errors"])[:3]
        merged["chunks"] += 1
    open(os.path.join(outdir, name + ".observed.txt"), "w").write("\n".join(sorted(obs)) + "\n")
    return merged


def prepare(outdir):
    os.makedirs(outdir, exist_ok=True)
    for f in ["CallCongestion.tla", "MCCallCongestion.tla"]:
        subprocess.run(["cp", os.path.join(HERE, f), outdir], check=True)


def trace(outdir, name, prop):
    prepare(outdir)
    params = dict(scenarios())[name]
    p = dict(params, TRACE="TRUE", INVS=f"T_{prop}")
    log = tlc(outdir, f"{name}.{prop}", cfg_text(p))
    text = open(log).read()
    out = render_trace(text)
    path = os.path.join(outdir, f"{name}.{prop}.trace.txt")
    open(path, "w").write(out or "no violation (or no trace printed)\n" + text[-2000:])
    print(path)
    print(out if out else text[-1500:])


PROPS_ORDER = ["NoSpuriousTeardown", "KeepsOneChild", "NeverTwoParents", "MakeBeforeBreak",
               "StallShedGap", "NoIdleWithOffer",
               "NothingWaitsForever", "ReparentBound", "EndParented", "EndHeard",
               "EndFullFanOut", "EndQueueDrained", "DeadDetected"]
SHORT = dict(StallShedGap="Gap", NoIdleWithOffer="Idle", NoSpuriousTeardown="NoTear", KeepsOneChild="One", NeverTwoParents="Two",
             MakeBeforeBreak="MBB", NothingWaitsForever="Wait", ReparentBound="Rep",
             EndParented="Par", EndHeard="Heard", EndFullFanOut="Full",
             EndQueueDrained="Queue", DeadDetected="Dead")


def grid(results):
    """Scenario x property: ok, or the share of terminal states that broke it."""
    head = "| scenario | " + " | ".join(SHORT[p] for p in PROPS_ORDER) + " | outcomes | states |"
    out = [head, "|---" * (len(PROPS_ORDER) + 3) + "|"]
    for name, r in results.items():
        total = sum(r["outcomes"].values()) or 1
        cells = []
        for prop in PROPS_ORDER:
            bad = sum(v for k, v in r["outcomes"].items() if "[" in k and prop in k.split("[")[1])
            cells.append("ok" if bad == 0 else f"**{bad}/{total}**")
        oc = {}
        for k, v in r["outcomes"].items():
            kk = k.split(" [")[0]
            oc[kk] = oc.get(kk, 0) + v
        ocs = ", ".join(f"{k} {v}" for k, v in sorted(oc.items()))
        run = f"{r['distinct']}" + ("" if r["finished"] else " PARTIAL") + (" ERR" if r.get("errors") else "")
        out.append(f"| {name} | " + " | ".join(cells) + f" | {ocs} | {run} |")
    return "\n".join(out) + "\n"


def table(results):
    return grid(results) + "\n" + table_detail(results)


def table_detail(results):
    out = ["| scenario | switches on | violated | outcomes (terminal states) | states / depth |",
           "|---|---|---|---|---|"]
    for name, r in results.items():
        p = r["params"]
        sw = ", ".join(SWITCH[k] for k in SWITCH if p.get(k) == "TRUE") or "none"
        oc = ", ".join(f"{k} x{v}" for k, v in sorted(r["outcomes"].items())) or "-"
        bad = ", ".join(r["violated"] + r["temporal"]) or "none"
        run = f"{r['distinct']} / {r['depth']}" + ("" if r["finished"] else " PARTIAL")
        if r.get("errors"):
            run += " ERR " + "; ".join(r["errors"])
        out.append(f"| {name} | {sw} | {bad} | {oc} | {run} |")
    return "\n".join(out) + "\n"


def main():
    outdir = sys.argv[1]
    if len(sys.argv) > 2 and sys.argv[2] == "--trace":
        return trace(outdir, sys.argv[3], sys.argv[4])
    resfile = os.path.join(outdir, "matrix.json")
    if len(sys.argv) > 2 and sys.argv[2] == "--reparse":
        res = {n: parse_log(os.path.join(outdir, n + ".log"), p) for n, p in scenarios()
               if os.path.exists(os.path.join(outdir, n + ".log"))}
        json.dump(res, open(resfile, "w"), indent=1)
        open(os.path.join(outdir, "matrix.md"), "w").write(table(res))
        return
    only = sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--only" else None
    prepare(outdir)
    results = json.load(open(resfile)) if os.path.exists(resfile) else {}
    for name, params in scenarios():
        if only and not re.fullmatch(only, name):
            continue
        if name in results and not only:
            continue
        if params.get("WIDE") == "TRUE":
            results[name] = run_chunked(outdir, name, params)
        else:
            log = tlc(outdir, name, cfg_text(params), extra=[])
            results[name] = parse_log(log, params)
        json.dump(results, open(resfile, "w"), indent=1)
        r = results[name]
        print(name, r["distinct"], r["depth"], r["outcomes"], r["violated"], r["temporal"],
              r["errors"], flush=True)
    open(os.path.join(outdir, "matrix.md"), "w").write(table(results))


if __name__ == "__main__":
    main()
