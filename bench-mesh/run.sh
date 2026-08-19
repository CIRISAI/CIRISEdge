#!/usr/bin/env bash
#
# One command to run the mesh harness.
#
#   ./run.sh                       # K=1 relay, M=2 subscribers
#   ./run.sh --relays 2 --subs 4   # two relay hops, four subscribers
#   ./run.sh --sweep               # M ∈ {1,2,4}, for the fan-out curve
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

set -euo pipefail

cd "$(dirname "$0")"

RELAYS=1
SUBS=2
SWEEP=0
CLEAN=0
FRAMES="${MESH_FRAMES:-120}"
NO_BUILD=0
CENSUS_ONLY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --relays) RELAYS="$2"; shift 2 ;;
    --subs)   SUBS="$2";   shift 2 ;;
    --frames) FRAMES="$2"; shift 2 ;;
    --sweep)  SWEEP=1;     shift ;;
    --clean)  CLEAN=1;     shift ;;
    --no-build) NO_BUILD=1; shift ;;
    --census-only) CENSUS_ONLY="$2"; shift 2 ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
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

run_point() {
  local subs="$1" relays="$2"
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

  echo "── mesh: relays=${relays} subscribers=${subs} frames=${FRAMES}"
  echo "   expect: ${MESH_EXPECT}"
  echo "   cohort: ${MESH_COHORT}"
  echo "   late joiner: ${MESH_LATE_JOINER} at frame ${MESH_ROTATE_AT}"

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
  compose "${PROFILES[@]}" logs --no-color --tail 2000 > "logs-relays-${relays}-subs-${subs}.txt" 2>&1 || true
  compose "${PROFILES[@]}" stop >/dev/null 2>&1 || true

  # Read the results out of the volume — never out of scrollback.
  local out="results/relays-${relays}-subs-${subs}.jsonl"
  mkdir -p results
  docker run --rm -v ciris-edge-bench-mesh_results:/r debian:bookworm-slim \
    sh -c 'cat /r/mesh.jsonl 2>/dev/null || true' > "$out" || true

  if [[ ! -s "$out" ]]; then
    echo "NO RESULTS: the harness produced no JSONL. The run did not measure anything." >&2
    return 1
  fi

  # The role-contract census (census.py): every leg EXPECTED of a node's
  # role must be present, ran, and ok; a not_run outside the contract is
  # allowed documentation; a leg that ran and failed is never excusable;
  # duplicate (node, leg) rows still refuse the whole file. run.sh is the
  # authority on the topology, so it names the late joiner and the full
  # node roster explicitly rather than letting the census infer them.
  python3 census.py "$out" "$rc" \
    --late-joiner "$MESH_LATE_JOINER" \
    --expect "$MESH_EXPECT"
}

overall=0
if [[ "$SWEEP" == 1 ]]; then
  for m in 1 2 4; do
    run_point "$m" "$RELAYS" || overall=1
  done
  echo "── fan-out curve: one results/relays-*-subs-*.jsonl per point"
else
  run_point "$SUBS" "$RELAYS" || overall=1
fi

exit "$overall"
