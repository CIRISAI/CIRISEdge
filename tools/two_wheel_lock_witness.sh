#!/usr/bin/env bash
# Two-wheel store-lock witness: the published ciris_persist and ciris_edge
# wheels installed SIDE BY SIDE, as a two-wheel host runs them. Every cargo
# test links one persist into one binary (one parking_lot, one tokio) and
# cannot see the cross-wheel lost wakeup; this can.
#
#   tools/two_wheel_lock_witness.sh <persist.whl> <edge.whl> [rounds] [width]
#
# Runs tools/scenarios/cohab_store_lock_contention.py `rounds` times, `width`
# at a time, each in a fresh interpreter, and classifies every run:
#   pass             the scenario finished (exit 0)
#   edge_side_hang   it never finished (a dispatch or the persist reader is
#                    parked for good; the timeout kills it)
#   persist_side     exit 3: the persist reader stopped while edge went on
#   other            anything else (exit code and stderr tail are printed)
# Exit 0 only when every run passed.
set -uo pipefail
[ $# -ge 2 ] || { echo "usage: $0 <persist.whl> <edge.whl> [rounds] [width]" >&2; exit 2; }
persist_whl=$1; edge_whl=$2; rounds=${3:-40}; width=${4:-4}
here=$(cd "$(dirname "$0")" && pwd)
scenario="$here/scenarios/cohab_store_lock_contention.py"
work=$(mktemp -d)
python3 -m venv "$work/venv"
"$work/venv/bin/pip" install -q --no-deps "$persist_whl" "$edge_whl" || exit 2
py="$work/venv/bin/python"
pass=0; hang=0; persist_side=0; other=0
run=0
while [ "$run" -lt "$rounds" ]; do
  pids=()
  for _ in $(seq 1 "$width"); do
    [ "$run" -lt "$rounds" ] || break
    run=$((run + 1))
    ( timeout 40 "$py" -I "$scenario" >"$work/o.$run" 2>"$work/e.$run"; echo $? >"$work/rc.$run" ) &
    pids+=($!)
  done
  wait "${pids[@]}"
done
for i in $(seq 1 "$rounds"); do
  rc=$(cat "$work/rc.$i")
  case "$rc" in
    0) pass=$((pass + 1)) ;;
    124|137) hang=$((hang + 1)) ;;
    3) persist_side=$((persist_side + 1)) ;;
    *) other=$((other + 1)); echo "run $i: rc=$rc $(tail -c 300 "$work/e.$i" | tr '\n' ' ')" ;;
  esac
done
echo "rounds=$rounds pass=$pass edge_side_hang=$hang persist_side=$persist_side other=$other (logs: $work)"
[ "$pass" -eq "$rounds" ]
