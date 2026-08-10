#!/usr/bin/env python3
"""CIRISEdge#461 — the instruction-count gate's parse + compare.

Kept as a standalone script (not a YAML-embedded heredoc: Python's own
indentation cannot coexist with a `run: |` block scalar's required indent).

Usage:
    icount_gate.py HEAD_RAW [BASE_RAW]

Reads the raw `cargo bench --bench icount` console output (which prints an exact,
deterministic `Instructions: N` per bench under Callgrind), extracts one count
per bench id, and — when a base is given — fails (exit 1) if any head count
exceeds its base by more than the threshold. Exit 3 if a run produced ZERO counts
(the bench did not actually run — never let that pass as a vacuous green).
"""
import re
import sys

THRESHOLD_PCT = 5.0
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_BENCH = re.compile(r"canonicalize\s+(\w+):")
_INSTR = re.compile(r"Instructions:\s+([0-9]+)")


def parse(path):
    """path -> {bench_id: instructions}. The bench id appears on one line, its
    `Instructions:` count on a following line."""
    counts, name = {}, None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = _ANSI.sub("", line)
            m = _BENCH.search(line)
            if m:
                name = m.group(1)
            m = _INSTR.search(line)
            if m and name is not None:
                counts[name] = int(m.group(1))
                name = None
    return counts


def main():
    head = parse(sys.argv[1])
    base = parse(sys.argv[2]) if len(sys.argv) > 2 else {}

    if not head:
        print("::error::icount HEAD produced ZERO instruction counts — the bench did not run")
        return 3

    if not base:
        print("no base counts — establishing baseline only (no gate this run):")
        for k in sorted(head):
            print(f"  {k:8} {head[k]:>10}")
        return 0

    worst, failed = 0.0, []
    for k in sorted(head):
        h = head[k]
        b = base.get(k)
        if b is None:
            print(f"  {k:8} head={h:>10}  (new bench, no base)")
            continue
        pct = (h - b) / b * 100.0
        worst = max(worst, pct)
        flag = f"  <== REGRESSION > {THRESHOLD_PCT:.0f}%" if pct > THRESHOLD_PCT else ""
        print(f"  {k:8} base={b:>10} head={h:>10}  {pct:+7.3f}%{flag}")
        if pct > THRESHOLD_PCT:
            failed.append((k, pct))

    if failed:
        detail = ", ".join(f"{k} {p:+.3f}%" for k, p in failed)
        print(f"::error::instruction-count regression (> {THRESHOLD_PCT:.0f}%): {detail}")
        return 1

    print(f"OK — worst delta {worst:+.3f}% (threshold +{THRESHOLD_PCT:.0f}%)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
