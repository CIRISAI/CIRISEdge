# Recorded runs for trace conformance

- `run1_c8699c3d6.json`, `run2_c75fdeb01.json`: the first two runs, as numbers from the leviculum#113 comment and the brief (no per-link log).
- The later per-link witness logs (calls2, 2026-11-24) contain literal addresses, so they are not committed. Point `trace_check.py --witness` at a local copy:

| Log | Pins | Scenario |
|---|---|---|
| t1_run1 | leviculum c75fdeb01 (receipts + hold), edge 5be3874 (stall flag, window shed) | conf-t1 |
| t2_wit | leviculum v0.34.0+ciris.3 (no receipts, no hold), edge 6ffc24b (shed on the verdict's rise) | conf-t2 |
| t3_wit2 | as t2, edge 6c67851 (+ slow start) | conf-t3 |
| t4_lev | c75fdeb01, edge 6c67851; heard capped at ~256 by the end drain: do not judge heard | conf-t4 |
| t5_wit2 | as t2, edge 407f5ee (+ publish never waits) | conf-t5 |
| t4_lev2 | c75fdeb01, edge 407f5ee; F12 (peak queue 8.97 s) | conf-t4lev2 (standby fed a full copy) |

`python3 trace_check.py OUTDIR/<scenario>.observed.txt --witness LOG`
