#!/usr/bin/env python3
"""R35 BUDGET — a discrete-time simulation of edge's egress budget
(src/transport/egress_budget.rs, release/45.3.1 851909ee) on one capped
publisher uplink, for the optimisation sweep TLC cannot do.

    python3 budget_sim.py [--sweep]

The publisher sends one copy (30 Hz x 600 B, about 360 kbit/s on the wire
with its chunking and per-chunk overhead) to its kept child (G8 keeps one
direct child; the others hear it through relays), plus call control that
grows with N (offers, stamps, proofs: CTRL_PER_MEMBER bits/s a member),
never held. The uplink is one FIFO drained at the cap. The budget observes
once a watch tick (250 ms) the send-clock backlog: the age of the kept leg's
oldest unproved control message less the RTT floor; a message is proved one
return path after it is delivered; nothing outstanding reads as clear.
STALE drops media while that reading is over 800 ms. Phases: 45 s baseline,
90 s capped, 60 s lifted (as the server av_mesh matrix).
"""
import itertools
import statistics
import sys
from collections import deque

DT = 0.01                       # 10 ms steps
FRAME_BITS = 12_000           # one 600 B frame on the wire: ~3 chunks of ~246 B + ~286 B overhead each (360 kbit/s at 30 Hz)
FPS = 30
CTRL_PER_MEMBER = 3_200         # bits/s per member: offers, stamps, proofs
RTT_FLOOR = 0.05                # s, the leg's min RTT
RETURN = 0.025                  # s, the proof's way back (uncapped peer)
WATCH = 0.25
BASE, CAPPED, LIFTED = 45.0, 90.0, 60.0
UNCAPPED = 20_000_000


class Params:
    def __init__(self, **kw):
        self.md_above = 0.4
        self.ai_below = 0.1
        self.md_factor = 0.7
        self.md_every = 0.5
        self.md_max = 1.0
        self.ai_floor = 8_000.0
        self.ai_div = 32.0
        self.fast_after = 5.0
        self.fast_div = 8.0
        self.min_bps = 64_000.0
        self.depth = 0.25
        self.lift_after = 3.0
        self.lift_use = 0.6
        self.lift_force = 1.0           # 45.3.1
        self.video_reserve = 0.04
        self.stale = 0.8
        self.cut_from = "rate"          # "rate" (as built) | "delivered"
        self.deliv_frac = 0.9           # cut_from=delivered: R <- frac x delivered rate
        self.ai_target = None           # None | "delivered": AI capped at delivered x 1.1
        self.__dict__.update(kw)


def run(p, cap, n, seed=0):
    t = 0.0
    q = deque()                  # [send_t, bits_left, kind, bits]
    rate = None
    tokens = 0.0
    last_md = None
    clear_since = None
    used_win = deque()           # (t, bits) sent in the last 1 s
    used_against = None
    win_rate = None
    win_start = 0.0
    win_bits = 0.0
    used_bps = 0.0
    deliv = deque()              # (t, bits) media+ctrl delivered, last 1 s
    outstanding = deque()        # control send times, not yet proved
    proved_at = deque()          # (prove time, send time)
    next_frame = 0.0
    next_ctrl = 0.0
    next_watch = WATCH
    reading = None
    hist_read = deque()          # (t, reading) over the last second, for "slope"
    stats = dict(cap_ok=0, cap_frames=0, cap_late=0, cap_drop_budget=0, cap_drop_stale=0,
                 lift_t=None, max_age_deliv=0.0, rates=[], ages=[], lift_ok=0, lift_frames=0)
    total = BASE + CAPPED + LIFTED
    ctrl_bps = n * CTRL_PER_MEMBER
    while t < total:
        capped = BASE <= t < BASE + CAPPED
        c = cap if capped else UNCAPPED
        phase = "cap" if capped else ("lift" if t >= BASE + CAPPED else "base")
        # refill
        if rate is not None:
            tokens = min(tokens + rate * DT, rate * p.depth)
        # window
        if t - win_start >= 1.0:
            used_bps = win_bits / (t - win_start)
            used_against = win_rate
            win_rate = rate
            win_start = t
            win_bits = 0.0
        # control: never held, one message a watch tick on the kept leg
        if t >= next_ctrl:
            bits = ctrl_bps * WATCH
            q.append([t, bits, "c", bits])
            outstanding.append(t)
            if rate is not None:
                tokens -= bits
            win_bits += bits
            next_ctrl += WATCH
        # media
        if t >= next_frame:
            next_frame += 1.0 / FPS
            if phase == "cap":
                stats["cap_frames"] += 1
            if phase == "lift":
                stats["lift_frames"] += 1
            if reading is not None and reading > p.stale:
                if phase == "cap":
                    stats["cap_drop_stale"] += 1
            else:
                ok = rate is None or tokens - FRAME_BITS >= rate * p.video_reserve
                if ok:
                    if rate is not None:
                        tokens -= FRAME_BITS
                    win_bits += FRAME_BITS
                    q.append([t, FRAME_BITS, "m", FRAME_BITS])
                elif phase == "cap":
                    stats["cap_drop_budget"] += 1
        # the uplink drains
        room = c * DT
        while q and room > 0:
            head = q[0]
            take = min(room, head[1])
            head[1] -= take
            room -= take
            if head[1] <= 1e-9:
                q.popleft()
                age = t + DT - head[0] + 0.025
                deliv.append((t, head[3]))
                if head[2] == "m":
                    if phase == "cap":
                        if age <= p.stale:
                            stats["cap_ok"] += 1
                        else:
                            stats["cap_late"] += 1
                            if t >= BASE + 5.0:
                                stats["late_steady"] = stats.get("late_steady", 0) + 1
                        stats["ages"].append(age)
                    if phase == "lift" and age <= p.stale:
                        stats["lift_ok"] += 1
                    stats["max_age_deliv"] = max(stats["max_age_deliv"], age)
                else:
                    proved_at.append((t + RETURN + 0.025, head[0]))
        while proved_at and proved_at[0][0] <= t:
            _, s = proved_at.popleft()
            if outstanding and outstanding[0] == s:
                outstanding.popleft()
        while deliv and deliv[0][0] < t - 1.0:
            deliv.popleft()
        # observe, once a watch tick
        if t >= next_watch:
            next_watch += WATCH
            reading = (t - outstanding[0] - RTT_FLOOR) if outstanding else None
            if reading is not None and reading < 0:
                reading = 0.0
            b = reading or 0.0
            hist_read.append((t, b))
            while hist_read and hist_read[0][0] < t - 1.0:
                hist_read.popleft()
            delivered_bps = sum(x[1] for x in deliv)
            if p.cut_from == "slope" or p.ai_target == "slope":
                # no new signal: C ~ sent / (1 + the queue delay's growth per s)
                g = (b - hist_read[0][1]) / max(t - hist_read[0][0], WATCH)
                delivered_bps = used_bps / (1.0 + max(g, 0.0)) if used_bps else 0.0
            if b > p.md_above:
                clear_since = None
                if last_md is None or t - last_md >= min(max(b, p.md_every), p.md_max):
                    if p.cut_from in ("delivered", "slope") and rate is not None:
                        new = max(delivered_bps * p.deliv_frac, p.min_bps)
                        rate = min(rate, new) if rate is not None else new
                    else:
                        base = rate if rate is not None else max(used_bps, p.min_bps)
                        rate = max(base * p.md_factor, p.min_bps)
                    last_md = t
                    tokens = min(tokens, 0.0)
            elif b < p.ai_below:
                if clear_since is None:
                    clear_since = t
                if rate is not None:
                    clear_for = t - clear_since
                    unused = used_against is not None and used_bps < used_against * p.lift_use
                    if (clear_for >= p.lift_after and unused) or clear_for >= p.lift_force:
                        rate = None
                        tokens = 0.0
                    elif clear_for >= p.fast_after:
                        rate = rate + rate / p.fast_div
                    else:
                        rate = rate + max(rate / p.ai_div, p.ai_floor)
                    if p.ai_target in ("delivered", "slope") and rate is not None:
                        rate = min(rate, max(delivered_bps * 1.1, p.min_bps))
            else:
                clear_since = None
            if phase == "cap":
                stats["rates"].append(rate if rate is not None else -1)
            if phase == "lift" and stats["lift_t"] is None:
                demand = FPS * FRAME_BITS + ctrl_bps
                if rate is None or rate >= demand:
                    stats["lift_t"] = t - (BASE + CAPPED)
        t += DT
    cf = stats["cap_frames"]
    good_bits = stats["cap_ok"] * FRAME_BITS
    rates = [r for r in stats["rates"] if r >= 0]
    return dict(
        heard=stats["cap_ok"] / cf if cf else 0,
        goodput=good_bits / (cap * CAPPED),
        late=stats.get("late_steady", 0) / cf if cf else 0,      # past the onset's 5 s
        late_onset=(stats["cap_late"] - stats.get("late_steady", 0)) / cf if cf else 0,
        drop_budget=stats["cap_drop_budget"] / cf if cf else 0,
        drop_stale=stats["cap_drop_stale"] / cf if cf else 0,
        lift_s=stats["lift_t"],
        lift_heard=stats["lift_ok"] / stats["lift_frames"] if stats["lift_frames"] else 0,
        max_age=stats["max_age_deliv"],
        p95_age=sorted(stats["ages"])[int(0.95 * len(stats["ages"]))] if stats["ages"] else 0,
        rate_mean=statistics.mean(rates) if rates else 0,
        rate_sd=statistics.pstdev(rates) if rates else 0,
        unbudgeted=sum(1 for r in stats["rates"] if r < 0) / max(1, len(stats["rates"])),
    )


def fmt(r):
    return (f"heard {r['heard']:.2f} goodput {r['goodput']:.2f} late {r['late']:.3f} "
            f"onsetlate {r['late_onset']:.3f} "
            f"dropB {r['drop_budget']:.2f} dropS {r['drop_stale']:.2f} "
            f"lift {r['lift_s']} liftheard {r['lift_heard']:.3f} p95age {r['p95_age']:.2f} "
            f"rate {r['rate_mean']/1000:.0f}+-{r['rate_sd']/1000:.0f}k unbudg {r['unbudgeted']:.2f}")


if __name__ == "__main__":
    cases = [(300_000, 4), (300_000, 6), (250_000, 4), (250_000, 6)]
    print("as built (45.3.1):")
    for cap, n in cases:
        print(f"  cap {cap//1000} N={n}: {fmt(run(Params(), cap, n))}")
    if "--sweep" in sys.argv:
        best = []
        sig = [a for a in sys.argv if a.startswith("--signal=")]
        sig = sig[0].split("=", 1)[1] if sig else "delivered"
        grid = dict(md_factor=[0.7, 0.8, 0.9], md_above=[0.2, 0.3, 0.4],
                    lift_force=[1.0, 1e9], cut_from=["rate", sig],
                    deliv_frac=[0.9, 0.95],
                    fast_after=[0.25, 0.5, 1.0, 5.0], fast_div=[2.0, 4.0, 8.0, 10.0],
                    ai_target=[None, sig])
        keys = list(grid)
        for vals in itertools.product(*(grid[k] for k in keys)):
            kw = dict(zip(keys, vals))
            res = [run(Params(**kw), cap, n) for cap, n in cases]
            ok = all(r["late"] == 0 and r["lift_s"] is not None and r["lift_s"] <= 1.0 for r in res)
            score = min(r["goodput"] for r in res)
            best.append((ok, score, kw, res))
        best.sort(key=lambda x: (x[0], x[1]), reverse=True)
        print("best by min goodput, constraints: no delivered age > 800 ms; lift <= 1 s")
        for ok, score, kw, res in best[:6]:
            print(ok, f"{score:.2f}", kw)
            for (cap, n), r in zip(cases, res):
                print(f"    cap {cap//1000} N={n}: {fmt(r)}")
