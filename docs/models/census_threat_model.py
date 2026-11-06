"""Census threat model numbers (docs/MESH_CENSUS_PROPOSAL_2026-10-22.md section 7).

Deterministic (seeded). Three questions:
  1. Stuffing: how far can a fraction f of Sybil returns, each reporting the
     largest bucket, move sum / mean / median / 10%-trimmed mean of a per-node
     quantity?
  2. Differencing: when one node joins a cell, how often does the PUBLISHED
     value change, exact versus rounded to a grid?
  3. Withholding: with a base that may fall at most d per period, how many
     periods does an adversary silencing a fraction s of returns need to cut
     the base by half?
"""
import math, random, statistics as st

rng = random.Random(887)

def trimmed_mean(xs, trim=0.10):
    xs = sorted(xs); k = int(len(xs) * trim)
    return st.mean(xs[k:len(xs) - k])

def bucket(v):  # log2 bucket upper bound, the value a return can claim
    return 0 if v <= 0 else 2 ** math.ceil(math.log2(v + 1)) - 1

print("1. stuffing a per-node quantity (rows held; honest lognormal, median ~2,000)")
N = 1000
honest = [bucket(int(rng.lognormvariate(math.log(2000), 1.2))) for _ in range(N)]
CEIL = 2 ** 20 - 1  # per-field clamp: the largest bucket a return may claim
print(f"   {'f':>5} {'sum':>9} {'mean':>9} {'median':>9} {'trim10':>9}")
for f in (0.01, 0.05, 0.09, 0.20):
    s = int(N * f)
    mixed = honest[: N - s] + [CEIL] * s
    base = honest
    row = [sum(mixed) / sum(base) - 1, st.mean(mixed) / st.mean(base) - 1,
           st.median(mixed) / st.median(base) - 1, trimmed_mean(mixed) / trimmed_mean(base) - 1]
    print(f"   {f:5.2f} " + " ".join(f"{x:+9.1%}" for x in row))

print("\n2. differencing: one join into a cell of n returns; P(published value changes)")
for n in (10, 30, 100, 1000):
    exact = 1.0
    # rounded to a grid of g = max(k, 2 sig. figs.): the value changes only if
    # the join crosses a grid boundary
    g = max(10, 10 ** max(0, int(math.log10(n)) - 1))
    p_round = sum(1 for m in range(n, n + 10 * g) if (m // g) != ((m + 1) // g)) / (10 * g)
    print(f"   n={n:5d} exact={exact:.2f}  grid={g:4d} rounded={p_round:.2f}")

print("\n3. withholding: base ratchet, max fall d per period, floor = small-community size")
for d in (0.05, 0.10):
    for s in (0.3, 0.5, 0.9):
        target = 0.5
        periods = math.ceil(math.log(max(target, 1 - s)) / math.log(1 - d))
        reach = max(target, 1 - s)
        print(f"   d={d:.2f} silence={s:.0%}: base reaches {reach:.0%} of true after >= {periods} periods"
              + ("" if 1 - s <= target else " (silencing alone cannot halve it)"))
