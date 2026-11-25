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
               PBO="FALSE", HASH="FALSE", STAG="FALSE", SERIAL="FALSE", PROBE2="FALSE",
               SILENCE="FALSE", SDRAIN="FALSE", FRESH="FALSE", CRTO="FALSE",
               REPLAY="FALSE", DELAYP="FALSE", OWNGUARD="FALSE", DEPHOLD="FALSE",
               GRACEFUL="FALSE")
SWITCH = dict(RPA="ReceiptsPerAttempt", RTO="RtoLearnsDelay", HOLD="Hold113",
              SOV="ShedOnVerdict", RKO="RoomKeepsOne", SS="SlowStart",
              RPU="RedialOnPathUp", DRAIN="ShedDrains", PEER="PeerLiveness",
              RXMOVE="ReceiverMoves", PBO="ProbeBackoff", HASH="HashRank",
              STAG="StaggeredSetup", SERIAL="SerialRedial", PROBE2="ProbeTwoLegs",
              SILENCE="SilenceFailover", SDRAIN="StallDrain", FRESH="FreshEvidence",
              CRTO="ConditionalRto", REPLAY="ReplayAttack", DELAYP="DelayProofs",
              OWNGUARD="OwnDownlinkGuard", DEPHOLD="DepartureHolds", GRACEFUL="Graceful")
INVS = "TypeOK RecordOutcome"   # the properties fold into `bad`, read per terminal state
BASE = dict(ALL_OFF, CLOSELOST="FALSE", LSEQ="Listeners3", RANK="Rank3", RCAP="4", CAPAT="10",
            CAPUNTIL="50", HORIZON="260", STALE="100", SRTTCAP="17", WATCH="2",
            SLOTS="1", PUNCH="{10, 30}", PPH="{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}",
            LPH="{0, 5}", WPH="{0, 5}", NPICK="2", DEAD='"none"', INIT="1", SETUP="0",
            DWELL="20", CSTALE="20", GAP="15", M="3", SILENTT="3", DRAINPCT="50", SLOWNODE='"none"', SLOWTICKS="0", SCOPE='"member"', HOLDT="0", FEED='"none"', BINDEVERY="0", BINDPARTS="10", BINDSIZE="17", RETX="TRUE", BINDSKIP="FALSE", BINDSKIPMAX="3", BINDPACE="1", BINDEXP="FALSE", SILENT="FALSE", KEEPFRESH="FALSE", REPAIR="FALSE", CLEANUP="FALSE", CTRLBG="0", NCEVERY="10", KILLAT="0", UPSHED="FALSE", PAD="FALSE", DHOLD="10", LATEADMIT="FALSE", ASKSHED="FALSE", ASKLOSS="FALSE", PLADMIT="FALSE", DGUARD="FALSE", RFREE="40", PROMOTE="FALSE", SU="FALSE", BRIDGE="0", PRESET="FALSE", STARVEAT="0", SUNSUB="FALSE", PFMAX="2", EXT="0", EXTAT="0", OCSHED="FALSE", CRAISE="FALSE", REOPEN="FALSE",
            DEADAT="0", TRACE="FALSE", WIDE="FALSE", INVS=INVS, PROPS="")


def on(*keys):
    return {k: "TRUE" for k in keys}


# Today's code at each pin, as switches (CallCongestion.md, "The switches").
TODAY_LEV_C86 = on("HOLD")                    # leviculum c8699c3d6 (#113 hold only)
TODAY_LEV_C75 = on("HOLD", "RPA")             # leviculum c75fdeb01 (+ per-attempt receipts)
EDGE_WIP = on("SOV", "RKO")                   # calls2's alm.rs (shed on rise, latch, room)
SIX = on("RPA", "RTO", "SOV", "RKO", "SS", "RPU")       # the brief's six
EIGHT = dict(SIX, **on("HOLD", "DRAIN"))                # + the #113 hold, make-before-break
ALL = dict(EIGHT, **on("PEER", "RXMOVE", "PBO", "FRESH", "CRTO"))        # + what the model found missing
# The lead's proposed minimum for 45.2.0's safety properties.
# (+ RPA and HOLD: already in leviculum c75fdeb01; without per-attempt
# receipts, fresh-only evidence starves a shed child's leg toward P.)
MIN = on("PEER", "SOV", "RKO", "PBO", "SERIAL", "FRESH", "CRTO", "RPA", "HOLD")
MIN_NO_RPA = on("PEER", "SOV", "RKO", "PBO", "SERIAL", "FRESH", "CRTO")
SETUP = dict(SETUP="40")
# What ships in 45.2.0: the minimum set + ReceiverMoves on the hash rank, P
# reading any direct child's departure as late (no wire reason), the
# own-downlink guard.
SHIP = dict(MIN, **on("RXMOVE", "HASH", "DEPHOLD", "OWNGUARD", "SS"), INIT="2", HOLDT="100",
            SCOPE='"offer"')                      # ~1 s of P's queue per leg set up (F11)


def scenarios():
    yield "smoke-baseline", dict(PPH="{3}", LPH="{0}", WPH="{0}", NPICK="1", PUNCH="{10}")
    yield "baseline", {}
    for k in SWITCH:
        if k not in ("REPLAY", "DELAYP", "GRACEFUL"):
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
    # The lead's comparison (copy = 12 units, control 1 unit ~ 0.08 copy):
    # the minimum set plus SilenceFailover (300 / 500 ms), StallDrain (25 /
    # 50 / 75 % of a copy), both, and ProbeTwoLegs, at 2.25x, 1.8x, 1.5x.
    for r, tag in [("16", "x225"), ("20", "x18"), ("24", "x15")]:
        fine = dict(MIN, M="12", RCAP=r, CAPUNTIL="1000")
        yield f"cmp-{tag}-min", fine
        yield f"cmp-{tag}-silence3", dict(fine, SILENCE="TRUE", SILENTT="3")
        yield f"cmp-{tag}-silence5", dict(fine, SILENCE="TRUE", SILENTT="5")
        for d in ["25", "50", "75"]:
            yield f"cmp-{tag}-drain{d}", dict(fine, SDRAIN="TRUE", DRAINPCT=d)
        yield f"cmp-{tag}-silence3-drain50", dict(fine, SILENCE="TRUE", SILENTT="3", SDRAIN="TRUE", DRAINPCT="50")
        yield f"cmp-{tag}-probe2", dict(fine, PROBE2="TRUE")
        yield f"cmp-{tag}-probe2-drain50", dict(fine, PROBE2="TRUE", SDRAIN="TRUE", DRAINPCT="50")
        yield f"cmp-{tag}-rxmove-hash", dict(fine, RXMOVE="TRUE", HASH="TRUE")
    # F12: what P sends a standby after a stall shed (copy = 12 units, 2.25x,
    # cap held). The edge test's configuration (receipts + fast shed + slow
    # start, no ReceiverMoves yet) and the shipping set, each with the
    # standby fed a full copy (today's contract) and with the fix.
    test = dict(MIN, **on("SS"), INIT="2", HOLDT="100", M="12", RCAP="16", CAPUNTIL="1000")
    for feed in ["none", "full", "fix", "fix2"]:
        yield f"f12-test-feed-{feed}", dict(test, FEED=f'"{feed}"')
        yield f"f12-ship-feed-{feed}", dict(SHIP, M="12", RCAP="16", CAPUNTIL="1000", FEED=f'"{feed}"')
    # The kept child dies mid-stall: what the fix costs its relayed listeners.
    for feed in ["full", "fix", "fix2"]:
        yield f"kept-dies-feed-{feed}", dict(test, FEED=f'"{feed}"', DEAD='"A"', DEADAT="30")
    # F13: the 10 s binding re-announce (10 parts of ~3.5 KB per leg; copy =
    # 12 units ~ 2.4 KB a tick, so a part ~ 17 units), at 2.25x, cap held.
    f13 = dict(SHIP, M="12", RCAP="16", CAPUNTIL="1000", FEED='"fix2"', BINDEVERY="100")
    yield "f13-ship-reannounce", f13
    yield "f13-ship-reannounce-no-retx", dict(f13, RETX="FALSE")
    for mx in ["1", "3", "100"]:
        yield f"f13-ship-reannounce-skip{mx}", dict(f13, BINDSKIP="TRUE", BINDSKIPMAX=mx)
    yield "f13-ship-no-reannounce", dict(f13, BINDEVERY="0")
    # Remedies: parts expire instead of retrying; parts paced across the period.
    yield "f13-ship-expire", dict(f13, BINDEXP="TRUE")
    yield "f13-ship-expire-skip3", dict(f13, BINDEXP="TRUE", BINDSKIP="TRUE")
    yield "f13-ship-pace5", dict(f13, BINDPACE="5")
    yield "f13-ship-pace5-expire", dict(f13, BINDPACE="5", BINDEXP="TRUE")
    yield "f13-ship-pace5-expire-skip3", dict(f13, BINDPACE="5", BINDEXP="TRUE", BINDSKIP="TRUE")
    yield "f13-ship-pace9-expire-skip3", dict(f13, BINDPACE="9", BINDEXP="TRUE", BINDSKIP="TRUE")
    # F14: silent listeners (nothing periodic on their leg to P), the
    # both-sides keep-fresh rule (D1), and tree repair; 2.25x, cap held, the
    # standby fix in, the re-announce off (F13 handled apart).
    f14 = dict(SHIP, M="12", RCAP="16", CAPUNTIL="1000", FEED='"fix2"', SILENT="TRUE")
    # where the verdict latches: the edge test's configuration (no RM yet), and
    # the shipping set with the re-announce bursts (paced + expiring + skip)
    f14t = dict(MIN, **on("SS"), INIT="2", HOLDT="100", M="12", RCAP="16", CAPUNTIL="1000",
                FEED='"fix2"', SILENT="TRUE")
    yield "f14-test-silent", f14t
    yield "f14-test-silent-keepfresh", dict(f14t, KEEPFRESH="TRUE")
    f14b = dict(f14, BINDEVERY="100", BINDPACE="9", BINDEXP="TRUE", BINDSKIP="TRUE")
    yield "f14-bind-silent", f14b
    yield "f14-bind-silent-keepfresh", dict(f14b, KEEPFRESH="TRUE")
    yield "f14-silent", f14
    yield "f14-silent-keepfresh", dict(f14, KEEPFRESH="TRUE")
    yield "f14-silent-repair", dict(f14, REPAIR="TRUE")
    yield "f14-silent-keepfresh-repair", dict(f14, KEEPFRESH="TRUE", REPAIR="TRUE")
    yield "f14-silent-keepfresh-repair-lift", dict(f14, KEEPFRESH="TRUE", REPAIR="TRUE", CAPUNTIL="50")
    yield "f14-silent-keepfresh-repair-dead-A", dict(f14, KEEPFRESH="TRUE", REPAIR="TRUE",
                                                    DEAD='"A"', DEADAT="30")
    yield "f14-silent-keepfresh-dead-A", dict(f14, KEEPFRESH="TRUE", DEAD='"A"', DEADAT="30")
    yield "f14-silent-keepfresh-repair-cleanup-dead-A", dict(f14, KEEPFRESH="TRUE", REPAIR="TRUE",
                                                            CLEANUP="TRUE", DEAD='"A"', DEADAT="30")
    yield "f14-silent-keepfresh-cleanup-dead-A", dict(f14, KEEPFRESH="TRUE", CLEANUP="TRUE",
                                                     DEAD='"A"', DEADAT="30")
    yield "f14-test-silent-keepfresh-cleanup", dict(f14t, KEEPFRESH="TRUE", CLEANUP="TRUE")
    yield "f14-test-silent-keepfresh-repair-cleanup", dict(f14t, KEEPFRESH="TRUE", REPAIR="TRUE",
                                                          CLEANUP="TRUE")
    # The last queue term: P's other control (load only), against the 0.33-copy
    # leftover (4 units at RCap 16, copy 12): (a) re-announce paced 1 part/s/leg
    # and suspended while latched, (b) offers to non-children every 2 s.
    f15 = dict(SHIP, M="12", RCAP="16", CAPUNTIL="1000", FEED='"fix2"', SILENT="TRUE",
               KEEPFRESH="TRUE", CLEANUP="TRUE", BINDEVERY="100", BINDPACE="10", BINDEXP="TRUE",
               BINDSKIP="TRUE", BINDSKIPMAX="100")
    for bg in ["0", "1", "2", "3", "4"]:
        yield f"ctrl-bg{bg}", dict(f15, CTRLBG=bg)
        yield f"ctrl-bg{bg}-nc2s", dict(f15, CTRLBG=bg, NCEVERY="20")
    yield "ctrl-nc2s-dead-C", dict(f15, NCEVERY="20", DEAD='"C"', DEADAT="30")
    yield "ctrl-nc1s-dead-C", dict(f15, DEAD='"C"', DEADAT="30")
    # The kill witness: P's leg to its first direct child torn mid-cap (t = 12 s).
    kill = dict(f15, KILLAT="120", HORIZON="260")
    yield "kill", kill
    yield "kill-upstream-shed", dict(kill, UPSHED="TRUE")
    yield "kill-test-config", dict(MIN, **on("SS"), INIT="2", HOLDT="100", M="12", RCAP="16",
                                   CAPUNTIL="1000", FEED='"fix2"', SILENT="TRUE", KEEPFRESH="TRUE",
                                   KILLAT="120")
    yield "kill-test-config-upstream-shed", dict(MIN, **on("SS"), INIT="2", HOLDT="100", M="12",
                                                 RCAP="16", CAPUNTIL="1000", FEED='"fix2"',
                                                 SILENT="TRUE", KEEPFRESH="TRUE", KILLAT="120",
                                                 UPSHED="TRUE")
    # ProbeAfterDrain (the ceiling path, no SlowStart), dwell and ceiling at
    # the code's values (10 s, 60 s): after a lift, and with the cap held.
    padb = dict(SHIP, SS="FALSE", M="12", RCAP="16", FEED='"fix2"', SILENT="TRUE", KEEPFRESH="TRUE",
                CLEANUP="TRUE", DWELL="100", CSTALE="600", HORIZON="460")
    yield "pad-off-lift", dict(padb, RECOVER="350")   # judged against ProbeAfterDrain's bound
    for h in ["2", "10", "50", "150"]:
        yield f"pad-hold{h}-lift", dict(padb, PAD="TRUE", DHOLD=h)
        yield f"pad-hold{h}-cap-held", dict(padb, PAD="TRUE", DHOLD=h, CAPUNTIL="1000")
    yield "pad-hold10-lift-no-backoff", dict(padb, PAD="TRUE", DHOLD="10", PBO="FALSE")
    yield "pad-hold10-cap-held-no-backoff", dict(padb, PAD="TRUE", DHOLD="10", PBO="FALSE", CAPUNTIL="1000")
    # ADMITs set aside: the queue longer than the subscribe timeout (no RM).
    adm = dict(MIN, M="12", RCAP="16", CAPUNTIL="1000", FEED='"fix2"', SILENT="TRUE", KEEPFRESH="TRUE")
    yield "admit-aside", adm
    yield "admit-aside-late-accept", dict(adm, LATEADMIT="TRUE")
    yield "admit-aside-ship", dict(SHIP, M="12", RCAP="16", CAPUNTIL="1000", FEED='"fix2"', SILENT="TRUE",
                                   KEEPFRESH="TRUE")
    # S3 narrowed vs ask-after-shed, and refusal-as-demand with its guard.
    # Base: the code's release shape (shipping set + silent listeners + keep-
    # fresh + admit cleanup + paced re-announce + fix2 + ProbeAfterDrain + a
    # primary-less P admits); 2.25x; cap lifts at 5 s (post-lift over-growth).
    s3 = dict(SHIP, M="12", RCAP="16", FEED='"fix2"', SILENT="TRUE", KEEPFRESH="TRUE", CLEANUP="TRUE",
              BINDEVERY="100", BINDPACE="10", BINDEXP="TRUE", BINDSKIP="TRUE", BINDSKIPMAX="100",
              PAD="TRUE", DHOLD="10", PLADMIT="TRUE", RFREE="80",
              RXMOVE="FALSE", HASH="FALSE")   # sheds happen (no ReceiverMoves), so S3 is exercised
    for tag, sw in [("ask-after-shed", dict(ASKSHED="TRUE")), ("ask-after-loss", dict(ASKLOSS="TRUE"))]:
        for g in ["FALSE", "TRUE"]:
            gt = "-guard" if g == "TRUE" else ""
            yield f"s3-{tag}{gt}", dict(s3, DGUARD=g, **sw)
            yield f"s3-{tag}{gt}-cap-held", dict(s3, DGUARD=g, CAPUNTIL="1000", **sw)
            yield f"s3-{tag}{gt}-kill", dict(s3, DGUARD=g, CAPUNTIL="1000", KILLAT="120", **sw)
    # Nobody relays (RelaySlots 0): the third child must still get in, through
    # refusals counted as demand; uncapped and capped.
    nr = dict(s3, ASKLOSS="TRUE", SLOTS="0", RXMOVE="FALSE")
    for g in ["FALSE", "TRUE"]:
        gt = "-guard" if g == "TRUE" else ""
        yield f"norelay{gt}-uncapped", dict(nr, DGUARD=g, CAPAT="1000", CAPUNTIL="1000")
        yield f"norelay{gt}-capped", dict(nr, DGUARD=g)
        yield f"norelay{gt}-no-demand-uncapped", dict(nr, DGUARD=g, CAPAT="1000", CAPUNTIL="1000", SS="FALSE")
    # SU (shared upstream): A and B both on C (P's one direct child; relays take
    # two), each the other's warm standby; P's leg to C is killed mid-cap, C
    # goes silent, A and B lose C by silence at the same watch tick.
    su = dict(s3, ASKLOSS="TRUE", SLOTS="2", PROMOTE="TRUE", REPAIR="TRUE", CAPUNTIL="1000", KILLAT="120",
              HASH="TRUE", INIT="1")
    # From the tree itself (C on P, A and B on C, standbys crossed), cap from
    # the start, P's leg to C killed at 5 s; offer phases are what vary.
    sut = dict(su, PRESET="TRUE", CAPAT="0", KILLAT="0", STARVEAT="50", SS="FALSE", INIT="3")
    yield "su-tree-off", sut
    yield "su-tree-on", dict(sut, SU="TRUE")
    yield "su-tree-on-bridge", dict(sut, SU="TRUE", BRIDGE="20")
    yield "su-tree-on-no-askloss", dict(sut, SU="TRUE", ASKLOSS="FALSE")
    yield "su-tree-off-unsub", dict(sut, SUNSUB="TRUE")
    yield "su-tree-on-unsub", dict(sut, SU="TRUE", SUNSUB="TRUE")
    yield "su-tree-on-unsub-bridge", dict(sut, SU="TRUE", SUNSUB="TRUE", BRIDGE="20")
    yield "su-off", su
    yield "su-on", dict(su, SU="TRUE")
    yield "su-on-bridge", dict(su, SU="TRUE", BRIDGE="20")
    yield "su-off-nokill", dict(su, KILLAT="0")
    yield "su-on-nokill", dict(su, SU="TRUE", KILLAT="0")
    # RO (i) with the 2 s bridge renewal (nobody relays).
    yield "norelay-guard-bridge-uncapped", dict(nr, DGUARD="TRUE", BRIDGE="20", CAPAT="1000", CAPUNTIL="1000")
    yield "s3-ask-after-loss-guard-bridge", dict(s3, ASKLOSS="TRUE", DGUARD="TRUE", BRIDGE="20")
    # Several admissions on one uplink: P also relays EXT other streams' copies
    # from 6 s (after the lift at 5 s). Today's code: demand on every refusal,
    # ageless; over-committed shed with no verdict; the clean-window raise;
    # fails <= 2. The combined rule (Reopen + ProbeAfterDrain, drained for 2 s,
    # fails <= 6). Uncapped 80 units = 6.7 copies; own 3 + external 2 fit.
    today = dict(s3, ASKLOSS="TRUE", EXT="2", EXTAT="60", OCSHED="TRUE", CRAISE="TRUE", PAD="FALSE",
                 HORIZON="460", DWELL="100", CSTALE="600")
    combined = dict(today, REOPEN="TRUE", DGUARD="TRUE", PAD="TRUE", DHOLD="20", PFMAX="6")
    yield "ro-today", today
    yield "ro-today-no-ext", dict(today, EXT="0")
    yield "ro-combined", combined
    yield "ro-combined-no-clean-raise", dict(combined, CRAISE="FALSE")
    yield "ro-combined-no-ext", dict(combined, EXT="0")
    yield "ro-combined-cap-held", dict(combined, CAPUNTIL="1000", EXT="0")   # relayed load is not sheddable in the model
    yield "ro-combined-cap-held-pf2", dict(combined, CAPUNTIL="1000", PFMAX="2", EXT="0")
    yield "ro-combined-norelay", dict(combined, SLOTS="0", EXT="0", CAPAT="1000", CAPUNTIL="1000", HORIZON="260")
    yield "ro-clean-raise-only", dict(today, OCSHED="FALSE", EXT="0")
    # The shipping set.
    for r, tag in [("16", "x225"), ("20", "x18"), ("24", "x15")]:
        fine = dict(SHIP, M="12", RCAP=r)
        yield f"ship-{tag}-cap-held", dict(fine, CAPUNTIL="1000")
        yield f"ship-{tag}-cap-lifts", fine
    yield "ship", SHIP
    # RM4: whom the receivers spare (cap held: the steady state must keep one).
    for sc in ["member", "child", "offer"]:
        yield f"ship-scope-{sc}-cap-held", dict(SHIP, SCOPE=f'"{sc}"', CAPUNTIL="1000")
        yield f"ship-scope-{sc}-x225-cap-held", dict(SHIP, SCOPE=f'"{sc}"', M="12", RCAP="16",
                                                     CAPUNTIL="1000")
    yield "cap-stays-ship", dict(SHIP, CAPUNTIL="1000")
    yield "ship-setup", dict(SHIP, **SETUP)
    yield "ship-unscaled", dict(SHIP, DWELL="100", CSTALE="600", HORIZON="400")
    # (i) a receiver whose own downlink is slow (no cap: P is fine).
    slow = dict(SLOWNODE='"B"', SLOWTICKS="3", CAPAT="1000", CAPUNTIL="1000")
    yield "ship-slow-B", dict(SHIP, **slow)
    yield "ship-slow-B-no-guard", dict(SHIP, OWNGUARD="FALSE", **slow)
    # (ii) a direct child hangs up after the cap lifts, others still on relays.
    hang = dict(DEAD='"B"', DEADAT="58", GRACEFUL="TRUE")
    yield "ship-hangup", dict(SHIP, **hang)
    yield "ship-hangup-with-reason", dict(SHIP, DEPHOLD="FALSE", **hang)
    yield "ship-hangup-uncapped", dict(SHIP, CAPAT="1000", CAPUNTIL="1000", **hang)
    # Review checks on the shipping set.
    yield "dead-after-queue-ship", dict(SHIP, DEAD='"B"', DEADAT="52")
    yield "delay-proofs-A-ship", dict(SHIP, DELAYP="TRUE")
    # The review (leviculum): fresh evidence, the conditional RTO, adversaries.
    dq = dict(DEAD='"B"', DEADAT="52")           # B dies just after the cap lifts (SRTT at its cap)
    yield "dead-after-queue-min", dict(MIN, **dq)
    yield "dead-after-queue-min-learned-rto", dict(MIN, RTO="TRUE", **dq)
    yield "dead-after-queue-min-learned-rto-unconditional", dict(MIN, RTO="TRUE", CRTO="FALSE", **dq)
    yield "dead-after-queue-all-on", dict(ALL, **dq)
    rp = dict(DEAD='"B"', DEADAT="30", STALE="40", SRTTCAP="6", CAPAT="1000", CAPUNTIL="1000",
              REPLAY="TRUE")
    yield "replay-dead-B-min", dict(MIN, **rp)
    yield "replay-dead-B-min-stale-evidence", dict(MIN, FRESH="FALSE", **rp)
    yield "delay-proofs-A-min", dict(MIN, DELAYP="TRUE")
    yield "delay-proofs-A-no-peer", dict(MIN, PEER="FALSE", DELAYP="TRUE")
    yield "delay-proofs-A-uncapped-min", dict(MIN, DELAYP="TRUE", CAPAT="1000", CAPUNTIL="1000")
    # What closes the stall-shed gap on the minimum set.
    yield "min-without-receipts", MIN_NO_RPA
    yield "cap-stays-min-without-receipts", dict(MIN_NO_RPA, CAPUNTIL="1000")
    yield "min+probe2", dict(MIN, PROBE2="TRUE")
    yield "min+rxmove-hash", dict(MIN, RXMOVE="TRUE", HASH="TRUE")
    yield "min+probe2+rxmove-hash", dict(MIN, PROBE2="TRUE", RXMOVE="TRUE", HASH="TRUE")
    yield "cap-stays-min+rxmove-hash", dict(MIN, RXMOVE="TRUE", HASH="TRUE", CAPUNTIL="1000")
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
    # Conformance with calls2's per-link witness logs (cap held 30 s, as the
    # test does; the pins of each log as switches; recorded_runs/README).
    c30 = dict(CAPUNTIL="1000", HORIZON="330")
    shed = on("SOV", "RKO")
    yield "conf-t1", dict(TODAY_LEV_C75, **c30)                                  # receipts, edge 5be3874
    yield "conf-t2", dict(shed, **c30)                                           # pre-receipts, edge 6ffc24b
    yield "conf-t3", dict(shed, **on("SS"), INIT="2", HOLDT="100", **c30)        # + slow start
    yield "conf-t4", dict(TODAY_LEV_C75, **shed, **on("SS"), INIT="2", HOLDT="100", **c30)
    yield "conf-t5", dict(shed, **on("SS"), INIT="2", HOLDT="100", **c30)        # + publish fix
    yield "conf-t4lev2", dict(TODAY_LEV_C75, **shed, **on("SS"), INIT="2", HOLDT="100",
                              FEED='"full"', **c30)                              # F12
    yield "conf-run1", dict(TODAY_LEV_C86, CAPUNTIL="1000", HORIZON="200")
    yield "conf-run2", dict(TODAY_LEV_C75, CAPUNTIL="1000", HORIZON="200")
    for n, p in [("baseline", {}), ("pin-c75fdeb01", TODAY_LEV_C75), ("all-on", ALL), ("min", MIN)]:
        yield f"wide-{n}", dict(p, WIDE="TRUE")


def recover_by(p):
    """EndFullFanOut's bound (ticks after the cap lifts): the verdict's latch
    (20) and the window it closes in (10), the widenings, the dwell and a
    window for the move. With SlowStart each stream above the first room
    waits out the probe backoff (2W x 2^fails, fails <= 2, stepping down
    after each probe that held) and, for the first, the hold after a stall;
    without SlowStart, the ceiling's staleness."""
    n = 2 if p["LSEQ"] == "Listeners2" else 3
    w = 10
    if p["SS"] == "TRUE":
        fmax = 2 if p["PBO"] == "TRUE" else 0
        # a stall or a late departure restarts the room from one stream, so
        # the climb back is n - 1 widenings whatever the first room was
        climb = n - 1 if p["HOLDT"] != "0" or p["RXMOVE"] == "TRUE" else n - int(p["INIT"])
        steps = [2 * w * 2 ** max(0, fmax - i) for i in range(max(0, climb))]
        if steps:
            steps[0] = max(steps[0], int(p["HOLDT"]))
        grow = sum(steps)
    elif p.get("PAD") == "TRUE":
        # ProbeAfterDrain: the drain hold, then n - 1 widenings (the room
        # restarts from one), each a dwell or the backoff, whichever is longer
        fmax = 2 if p["PBO"] == "TRUE" else 0
        grow = int(p["DHOLD"]) + sum(max(int(p["DWELL"]), 2 * w * 2 ** max(0, fmax - i))
                                     for i in range(n - 1))
    else:
        grow = int(p["CSTALE"])
    return str(20 + w + grow + int(p["DWELL"]) + w)


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
               GRACE_SCHED_KIND="edge: call model TLC", GRACE_SCHED_PEAK_GB="3",
               GRACE_SCHED_PRIORITY="low")   # yields to builds; measured peak <= 2.2 GB
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
