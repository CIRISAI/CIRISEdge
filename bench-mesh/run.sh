#!/usr/bin/env bash
#
# One command to run the mesh harness.
#
#   ./run.sh                       # K=1 relay, M=2 subscribers
#   ./run.sh --relays 2 --subs 4   # two relay hops, four subscribers
#   ./run.sh --sweep               # M ∈ {4,2,1}, for the fan-out curve
#   ./run.sh --clean               # drop every volume (fresh identities)
#
# The roster is a hard barrier: every node waits until every id in
# EDGE_EXPECT has published its public record. So the EXPECT list must
# match exactly the set of containers that will start — which is why this
# script computes it rather than compose hard-coding one.
#
# Honesty: this script NEVER reports a result it did not read out of the
# results volume, and it exits non-zero if any node exited non-zero or if
# any node breaks its ROLE CONTRACT (census.py): every leg expected of a
# node's role must run AND pass; a not_run outside the contract is the
# leg's own documentation of why it did not apply (the deliberate late
# joiner can never satisfy the two across-the-advance legs); a leg that
# ran and failed is never excusable. `./run.sh --census-only <file>`
# re-runs just the census on an existing JSONL, without docker.
#
# The same honesty aimed at the BOX (CIRISEdge#536). A verdict is a claim
# about the code, so it may only be rendered on a host that could support
# the run. Three guards, and none of them can turn a red into a green:
#
#   * a PRE-FLIGHT before the first container of each point, holding the
#     host's memory / swap / disk to a floor derived from the point's
#     weight. Below it the point exits 75 = NOT MEASURED, never a census;
#   * each point independent — the sweep runs HEAVIEST FIRST and waits
#     for the floor between points, and a NOT-MEASURED point is re-run
#     ONCE from a recovered box, labelled `attempt 2` in the output and
#     in the file. A point that FAILED on a box that held its floor is a
#     real failure and is never re-run;
#   * the host state at each point's start and end is written INTO the
#     results JSONL as two `host` rows, so the box is part of the
#     committed baseline and `--census-only` re-derives the same verdict.
#
#   exit 0  = measured, every contract met
#   exit 1  = measured, contract violations — a real red
#   exit 2  = usage error
#   exit 75 = NOT MEASURED (EX_TEMPFAIL). Nothing is wrong with the tree.

set -euo pipefail

cd "$(dirname "$0")"

RELAYS=1
SUBS=2
SWEEP=0
CLEAN=0
FRAMES="${MESH_FRAMES:-120}"
NO_BUILD=0
CENSUS_ONLY=""
RETRY=1

# The distinct status for "the box could not host this measurement".
# 75 is EX_TEMPFAIL from sysexits.h — "temporary failure, indicating
# something that is not really an error", which is exactly the claim.
# census.py owns the same constant; they must not drift.
NOT_MEASURED=75

# How long a point waits for the host to come back to its floor before
# refusing. The memory a teardown frees lands within seconds, so a wait
# longer than this is waiting for something ELSE on the box to finish —
# which is not the harness's business, and the honest answer then is NOT
# MEASURED, which the operator can act on. 180s is also the harness's own
# MESH_ROOT_TIMEOUT_SECS, so the two ceilings stay in the same order.
RECOVER_SECS="${MESH_RECOVER_TIMEOUT_SECS:-180}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --relays) RELAYS="$2"; shift 2 ;;
    --subs)   SUBS="$2";   shift 2 ;;
    --frames) FRAMES="$2"; shift 2 ;;
    --sweep)  SWEEP=1;     shift ;;
    --clean)  CLEAN=1;     shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --no-retry) RETRY=0;   shift ;;
    --recover-timeout) RECOVER_SECS="$2"; shift 2 ;;
    --census-only) CENSUS_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,43p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

# Census-only: hold an existing JSONL to the role contracts, no docker,
# no lock. The late joiner is inferred from the publisher's
# scope.rotation detail; the full-run path below passes it explicitly.
if [[ -n "$CENSUS_ONLY" ]]; then
  exec python3 census.py "$CENSUS_ONLY" 0
fi

# A killed build leaves an orphaned buildx process holding the
# `sharing=locked` target-cache mount, after which every later build
# blocks on it and looks merely slow. Clear any orphan before starting.
reap_orphan_builds() {
  local mine=$$
  pgrep -f 'docker-buildx bake' 2>/dev/null | while read -r pid; do
    # Only reap a bake whose parent has already died (orphan reparented
    # to init) — never one another live run is driving.
    local ppid
    ppid=$(ps -o ppid= -p "$pid" 2>/dev/null | tr -d ' ')
    if [[ -n "$ppid" && "$ppid" == "1" ]]; then
      echo "reaping orphaned buildx bake pid=$pid (it holds the build cache lock)" >&2
      kill -9 "$pid" 2>/dev/null || true
    fi
  done
  : "$mine"
}

if ! command -v docker >/dev/null 2>&1; then
  echo '{"fatal":"docker is not available on this host; the mesh harness cannot run"}' >&2
  exit 1
fi

# Exactly one run at a time. Two concurrent runs tear down each other's
# containers between `up` and `docker wait`, and neither ever finishes —
# a livelock that presents as a mysteriously slow run rather than an
# error. The lock turns it into a refusal.
LOCK="${TMPDIR:-/tmp}/ciris-edge-bench-mesh.lock"
exec 9>"$LOCK"
if ! flock -n 9; then
  echo "another bench-mesh run holds $LOCK — refusing to start a second one" >&2
  exit 1
fi

compose() { docker compose -f compose.yaml "$@"; }

# The compose profiles declare subscribers in blocks (subs2, subs4), so
# only these counts produce a container set that MATCHES the EXPECT list.
# Any other value would leave the roster barrier waiting on a node that
# never starts — a hang, not a measurement.
case "$SUBS" in
  1|2|4) ;;
  *) echo "--subs must be 1, 2, or 4 (compose profiles come in blocks)" >&2; exit 2 ;;
esac
case "$RELAYS" in
  1|2) ;;
  *) echo "--relays must be 1 or 2" >&2; exit 2 ;;
esac

if [[ "$CLEAN" == 1 ]]; then
  compose --profile relays2 --profile subs2 --profile subs4 down -v --remove-orphans || true
  docker ps -aq --filter "name=^bm-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls --format '{{.Name}}' \
    | grep '^ciris-edge-bench-mesh_' \
    | xargs -r docker volume rm -f >/dev/null 2>&1 || true
  echo "volumes dropped; the next run mints fresh identities"
  exit 0
fi

# ── Topology → profiles + roster lists ──────────────────────────────
build_topology() {
  local subs="$1" relays="$2"
  PROFILES=()
  local nodes=("publisher" "relay-1")
  [[ "$relays" -ge 2 ]] && { PROFILES+=("--profile" "relays2"); nodes+=("relay-2"); }
  [[ "$subs" -ge 2 ]] && PROFILES+=("--profile" "subs2")
  [[ "$subs" -ge 3 ]] && PROFILES+=("--profile" "subs4")
  local cohort=("publisher")
  for i in $(seq 1 "$subs"); do
    nodes+=("sub-$i"); cohort+=("sub-$i")
  done
  nodes+=("nonmember")
  MESH_EXPECT="$(IFS=,; echo "${nodes[*]}")"
  MESH_COHORT="$(IFS=,; echo "${cohort[*]}")"
  # sub-3/sub-4 sit behind relay-2 when there is one, so those two are a
  # genuine second hop from the publisher.
  if [[ "$relays" -ge 2 ]]; then MESH_DEEP_BOOTSTRAP="relay-2:4242"; else MESH_DEEP_BOOTSTRAP="relay-1:4242"; fi
  export MESH_EXPECT MESH_COHORT MESH_DEEP_BOOTSTRAP
}

# One attempt at one point. Returns 0 (measured, clean), 1 (measured,
# violations) or $NOT_MEASURED (the box could not host the measurement).
run_point_once() {
  local subs="$1" relays="$2" attempt="$3"
  build_topology "$subs" "$relays"
  export MESH_FRAMES="$FRAMES"
  # The late joiner is the LAST subscriber, so at least one member is
  # present across the whole stream for the zero-loss assertion.
  # A single-subscriber run has nobody to hold back: the late joiner
  # would BE the only member, leaving no one present ACROSS the advance
  # to assert zero-loss on. In that case the publisher rekeys with
  # `CohortGroup::rotate()` instead — still a real MLS epoch advance.
  if [[ "$subs" -ge 2 ]]; then
    export MESH_LATE_JOINER="sub-${subs}"
  else
    export MESH_LATE_JOINER=""
  fi
  export MESH_ROTATE_AT="$(( FRAMES / 2 ))"
  # The non-member is a rooted peer on the mesh that the publisher
  # deliberately addresses ciphertext to, so its refusal is falsifiable.
  export MESH_OBSERVERS="nonmember"

  local label="relays=${relays} subs=${subs}"
  echo "── mesh: relays=${relays} subscribers=${subs} frames=${FRAMES}"
  [[ "$attempt" -gt 1 ]] && echo "   ATTEMPT ${attempt} (the previous attempt was NOT MEASURED)"
  echo "   expect: ${MESH_EXPECT}"
  echo "   cohort: ${MESH_COHORT}"
  echo "   late joiner: ${MESH_LATE_JOINER} at frame ${MESH_ROTATE_AT}"

  # ── Pre-flight, before the first container ────────────────────────
  #
  # An orphaned buildx bake is reaped FIRST: it holds both the target
  # cache lock and a large chunk of memory, and freeing it may be the
  # difference between a fit box and a refusal. Reaping only touches
  # bakes already reparented to init, never a live run's.
  reap_orphan_builds

  # Node count = publisher + relays + subscribers + nonmember. This is
  # what the floor scales on, so it must match the container set compose
  # will actually start — the same list build_topology just computed.
  local nodes=$(( 1 + relays + subs + 1 ))
  local buildflag=()
  [[ "$NO_BUILD" == 0 ]] && buildflag=(--build)

  local out="results/relays-${relays}-subs-${subs}.jsonl"
  local prerow="${TMPDIR:-/tmp}/bm-hoststate-pre.$$"
  local postrow="${TMPDIR:-/tmp}/bm-hoststate-post.$$"
  mkdir -p results

  local pf=0
  python3 census.py --preflight --nodes "$nodes" "${buildflag[@]}" \
    --phase pre --attempt "$attempt" --wait "$RECOVER_SECS" \
    --point "$label" --row-out "$prerow" || pf=$?
  if [[ "$pf" != 0 ]]; then
    # Keep the evidence, under a name that can never be mistaken for a
    # results JSONL — this file is a record of a run that did not happen.
    mv -f "$prerow" "results/relays-${relays}-subs-${subs}.not-measured.json" \
      2>/dev/null || true
    return "$NOT_MEASURED"
  fi
  # A point that DID run replaces any refusal record from a previous
  # attempt, so a stale one can never be read as this run's state.
  rm -f "results/relays-${relays}-subs-${subs}.not-measured.json"

  # Fresh volumes per point: identities and MLS state must not carry over
  # between measurements, and `CohortGroup::join` refuses a second join
  # into a community it already holds state for.
  #
  # `down -v` alone is NOT enough, and the reason is a trap worth naming:
  # reading the results with `docker run -v <name>:/r` RE-CREATES that
  # volume without compose's project labels, after which `compose down -v`
  # silently leaves it behind. The results then accumulate across runs and
  # a "results file" is really several runs merged. So the volumes are
  # removed by NAME, unconditionally, and the leg census below refuses a
  # file that still contains duplicates.
  compose "${PROFILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  docker ps -aq --filter "name=^bm-" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker volume ls --format '{{.Name}}' \
    | grep '^ciris-edge-bench-mesh_' \
    | xargs -r docker volume rm -f >/dev/null 2>&1 || true

  if [[ "$NO_BUILD" == 0 ]]; then
    reap_orphan_builds
    compose "${PROFILES[@]}" build
  fi

  # Detached, then wait on the PUBLISHER specifically. `--abort-on-
  # container-exit` would kill every container the moment any one of them
  # finished normally — which is how the first run lost every subscriber
  # leg, including the zero-loss acceptance criterion. The publisher is
  # the orchestrator and the last to finish, so its exit is the run's.
  local rc=0
  compose "${PROFILES[@]}" up -d
  trap 'compose "${PROFILES[@]}" down -v --remove-orphans >/dev/null 2>&1 || true' INT TERM
  rc=$(docker wait bm-publisher 2>/dev/null || echo 1)
  # Give the leaves a moment to flush their final legs, then stop.
  sleep 5

  # ── Post-flight, while the containers are still resident ──────────
  #
  # The pre-flight can only speak for the box at t=0, and #536's actual
  # mechanism is that the box degrades DURING the point — swap climbed as
  # the seventh container came up. So sample again here, BEFORE `stop`
  # frees the containers, which makes this a lower bound on the pressure
  # the point ran under rather than a reading of the box after it. This
  # phase never gates: it records, and census.py decides from the file
  # whether the verdict is admissible.
  python3 census.py --preflight --nodes "$nodes" "${buildflag[@]}" \
    --phase post --attempt "$attempt" --point "$label" \
    --row-out "$postrow" || true

  compose "${PROFILES[@]}" logs --no-color --tail 2000 > "logs-relays-${relays}-subs-${subs}.txt" 2>&1 || true
  compose "${PROFILES[@]}" stop >/dev/null 2>&1 || true

  # Read the results out of the volume — never out of scrollback.
  docker run --rm -v ciris-edge-bench-mesh_results:/r debian:bookworm-slim \
    sh -c 'cat /r/mesh.jsonl 2>/dev/null || true' > "$out" || true

  if [[ ! -s "$out" ]]; then
    echo "NO RESULTS: the harness produced no JSONL. The run did not measure anything." >&2
  fi

  # The host state goes INTO the results file, before the census reads
  # it. #536: had this been in the file, the pattern would have been
  # visible on the first comparison instead of the fifth run — so it is
  # not a log line, it is a row, and it survives into the committed
  # baseline and into `--census-only`.
  #
  # Appended even when the run produced nothing: an empty point on a
  # degraded box is exactly the case that must come back NOT MEASURED
  # rather than as a bare failure, and census.py can only tell those
  # apart if the host rows are in the file.
  cat "$prerow" "$postrow" >> "$out" 2>/dev/null || true
  rm -f "$prerow" "$postrow"

  # The role-contract census (census.py): every leg EXPECTED of a node's
  # role must be present, ran, and ok; a not_run outside the contract is
  # allowed documentation; a leg that ran and failed is never excusable;
  # duplicate (node, leg) rows still refuse the whole file. run.sh is the
  # authority on the topology, so it names the late joiner and the full
  # node roster explicitly rather than letting the census infer them.
  # It may also return $NOT_MEASURED — see the degradation doctrine.
  local cc=0
  python3 census.py "$out" "$rc" \
    --late-joiner "$MESH_LATE_JOINER" \
    --expect "$MESH_EXPECT" || cc=$?
  return "$cc"
}

# One point, with at most one re-run. The re-run is only ever reachable
# from NOT MEASURED — a point that FAILED on a box which held its floor
# is a real failure and is never re-run, because a retry that can erase a
# red is not a guard, it is a way of eventually getting the answer you
# wanted. The pre-flight inside the second attempt does the waiting.
run_point() {
  local subs="$1" relays="$2"
  local rc=0
  run_point_once "$subs" "$relays" 1 || rc=$?
  if [[ "$rc" == "$NOT_MEASURED" && "$RETRY" == 1 ]]; then
    echo ""
    echo "── NOT MEASURED: relays=${relays} subs=${subs}. Re-running ONCE from"
    echo "   a recovered box (attempt 2). A retry can only follow a"
    echo "   NOT-MEASURED point; a point that failed on a healthy box is"
    echo "   never re-run."
    rc=0
    run_point_once "$subs" "$relays" 2 || rc=$?
    case "$rc" in
      0) echo "   attempt 2 PASSED. Attempt 1 was not a verdict — it was withheld." ;;
      "$NOT_MEASURED") echo "   attempt 2 was ALSO not measurable. This point has no verdict." ;;
      *) echo "   attempt 2 FAILED on a box that held its floor. That is a real red." ;;
    esac
  fi
  return "$rc"
}

overall=0
not_measured=0
SUMMARY=()

track() {
  local subs="$1" relays="$2" rc=0
  run_point "$subs" "$relays" || rc=$?
  case "$rc" in
    0)  SUMMARY+=("  relays=${relays} subs=${subs}  MEASURED, clean") ;;
    "$NOT_MEASURED")
        SUMMARY+=("  relays=${relays} subs=${subs}  NOT MEASURED — the host could not support it")
        not_measured=1 ;;
    *)  SUMMARY+=("  relays=${relays} subs=${subs}  FAILED (contract violations)")
        overall=1 ;;
  esac
}

if [[ "$SWEEP" == 1 ]]; then
  # HEAVIEST FIRST (CIRISEdge#536). The sweep used to run 1 → 2 → 4, so
  # M=4 — seven containers, the heaviest point — always landed on the box
  # the two lighter points had already loaded, and failed there
  # reproducibly regardless of code. Reversing the order costs nothing
  # and gives the point most likely to be falsely reddened the freshest
  # host. The lighter points now inherit the degraded box, which is the
  # right trade: they are far less likely to be starved, and if they are,
  # the pre-flight refuses instead of reporting.
  for m in 4 2 1; do
    track "$m" "$RELAYS"
  done
  echo "── fan-out curve: one results/relays-*-subs-*.jsonl per point"
  echo "   (measured heaviest-first; the curve is read by M, not by order)"
else
  track "$SUBS" "$RELAYS"
fi

if [[ "${#SUMMARY[@]}" -gt 1 ]]; then
  echo ""
  echo "── sweep summary"
  printf '%s\n' "${SUMMARY[@]}"
fi

# Precedence: a real red outranks an unknown, and an unknown outranks a
# green — a sweep with a NOT-MEASURED point is an incomplete sweep, and
# must never exit 0 and be filed as a clean acceptance run.
if [[ "$overall" != 0 ]]; then
  exit 1
fi
if [[ "$not_measured" != 0 ]]; then
  echo ""
  echo "exit ${NOT_MEASURED}: at least one point was NOT MEASURED. No verdict was"
  echo "rendered about the code for it. Nothing here says the tree is bad."
  exit "$NOT_MEASURED"
fi
exit 0
