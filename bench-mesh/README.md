# bench-mesh — the multi-container mesh harness

`benches/` measures **what the substrate costs per operation**, in
process, on synthetic payloads. This measures **whether real edge
occurrences deliver real video to N peers across a real network while the
roster changes**.

Those are different questions and neither answer substitutes for the
other. `benches/` stays exactly as it is — it feeds the deterministic
instruction-count regression gate (CIRISEdge#461), and deleting any of it
would blind that alarm.

---

## Run it

```sh
cd bench-mesh
./run.sh                        # 1 relay, 2 subscribers, 120 frames
./run.sh --relays 2 --subs 4    # two relay hops, four subscribers
./run.sh --sweep                # M ∈ {4,2,1} — the fan-out curve, heaviest first
./run.sh --clean                # drop every volume; next run mints fresh identities
```

Requires `docker` with compose v2+. Nothing else — ffmpeg, the Rust
toolchain, and libsqlite3 all live inside the image.

**Read the exit code, not the scrollback.**

| Exit | Means |
|---|---|
| `0` | measured, every role contract met |
| `1` | measured, contract violations — a real red |
| `2` | usage error |
| `75` | **NOT MEASURED.** The host could not support the run. No verdict was rendered about the code; nothing here says the tree is bad. See [The pre-flight](#the-pre-flight-and-why-it-refuses). |

`--no-build` skips the image build when you know the image is current —
useful when running the sweep points one at a time. Check with
`docker images ciris-edge-bench-mesh --format '{{.CreatedAt}}'` against
the mtime of `src/bin/edge_node.rs`; a stale image will silently measure
old code.

Only one run at a time: `run.sh` takes an exclusive lock and refuses a
second. Two concurrent runs tear down each other's containers between
`up` and `docker wait` and neither ever finishes, which presents as a
mysteriously slow run rather than an error.

The first build is slow (openmls + libcrux + leviculum + persist come
from git). Cargo's registry, git checkouts, and `target/` are BuildKit
caches, so an edit to `src/bin/edge_node.rs` rebuilds that crate and
nothing else.

Results land in `bench-mesh/results/relays-K-subs-M.jsonl`, one JSON
object per leg per node, plus two `host` rows carrying the state of the
box the point ran on.

A point the harness refused to run writes
`results/relays-K-subs-M.not-measured.json` instead — a single host row,
under an extension that can never be read as a results file.

---

## The pre-flight, and why it refuses

`run.sh` checks the host's memory, swap and disk against a floor derived
from the point's weight **before the first container**, and exits `75`
without running anything if the box is below it. That is a refusal, not a
result: it prints no leg census, no node table, no counts — nothing
shaped like a verdict, because none was reached.

### The mechanism it was built for (CIRISEdge#536)

`--sweep` used to run M=1 → M=2 → M=4 on one box that never recovered
between points. Each point tore down its containers and volumes, but page
cache, swap and docker churn accumulated across the whole sweep, so M=4 —
seven containers, the heaviest point — always landed on the most degraded
host. There it failed reproducibly with `mesh.role_completion: waiting
for Ready/Welcome: no control frame within 300s` and 24 cascading legs.

It failed **identically regardless of code**, proven from both
directions: a bit-identical BuildKit-cached v18.6.0 image passed M=4 at
47 legs / 0 violations on a fresh box and failed at 36 / 24 on a loaded
one; and v18.7.0, which failed as a sweep's third point, passed 47 / 0
when M=4 ran alone. Three false failure verdicts in one session, and the
#532 dial fix cancelled on a bisect the artefact confounded — the bisect
was measuring run *order*, not the change.

This harness's own rule is that a leg which did not run is a failed run.
The pre-flight is that rule aimed at the box. **A verdict is a claim
about the code**; a harness that renders one on a host that could not
support the run is claiming something it cannot know.

### The thresholds, and the evidence for each

The two kinds of evidence are not equally strong, and `census.py` says
which is which so a later reader can tighten the weak one rather than
trust it.

| Signal | Floor | Evidence |
|---|---|---|
| **swap utilisation** | refuse above **60 %** | The decisive one, and both sides are measured: every run that passed sat at ≤ 4.0 GiB of 8 GiB (≤ 50 %); every run that falsely failed sat at 7.0 GiB (87 %). 60 %, not the 68 % midpoint, because the pre-flight reads the box *before* seven containers add their own pressure and swap only ever climbs during a run — a box at 68 % at t=0 is past 87 % by the time the last node is up. 60 % of an 8 GiB swap is 4.8 GiB, i.e. 0.8 GiB above the highest figure that ever passed. |
| **memory available** | `2048 MiB + 950 MiB × nodes` (+ 2048 MiB when building) | Only the *passing* side is known: 17–23 GiB across the runs that came back 47 / 0 at M=4. That is what those boxes **had**, not what the run **needed**, so the floor is deliberately not 17 GiB — a floor at the lowest observed pass refuses boxes never shown to fail. Half the lowest observed pass, 8.5 GiB, is taken as the heaviest point's requirement and spread as a fixed base (dockerd, buildx, the results reader, the shell) plus a per-node budget. |
| **disk free** | 20 GiB building, 5 GiB with `--no-build` | Derived from the artefacts, not from a failure: the rust build stage with cmake/clang/libsqlite3-dev, the ffmpeg media stage, and the three BuildKit cache mounts including a **release** `target/` for this dependency graph. ENOSPC in docker's data root kills containers mid-run and presents as exactly the cohort-never-forms failure above. |

Resulting memory floors, without a build:

```
M=1  relays=1   4 nodes   5.71 GiB        M=4  relays=1   7 nodes   8.49 GiB
M=2  relays=1   5 nodes   6.64 GiB        M=4  relays=2   8 nodes   9.42 GiB
```

A swap smaller than 4 GiB cannot carry the 4-passed/7-failed boundary at
all — a percentage of it is not the same quantity — so on such a box the
swap reading is reported as *informational* and `MemAvailable` carries
the whole check. The output says so.

**If a run is ever refused at, say, 9 GiB and would have passed, lower
the anchor and record it in the comment on `BASE_MIB`.** That comment is
the log; the numbers are only as good as the evidence cited beside them.

### Each point's verdict is independent

Three changes, and none of them can turn a red into a green.

1. **Heaviest first.** `--sweep` now runs M ∈ {4,2,1}. It costs nothing
   and gives the point most likely to be falsely reddened the freshest
   box. The lighter points inherit the degraded one, which is the right
   trade: they are far less likely to be starved, and if they are, the
   pre-flight refuses instead of reporting. The curve is read by M, not
   by order, so nothing about the measurement changes.
2. **A recovery gate between points.** Each point's pre-flight waits up
   to `MESH_RECOVER_TIMEOUT_SECS` (default 180) for the floor to be
   re-attained, logging the box every 10 s so the wait is never a silent
   hang, and refuses if it is not. 180 s because the memory a teardown
   frees lands within seconds — a longer wait is waiting for something
   *else* on the box, which is not the harness's business, and the honest
   answer then is NOT MEASURED.
3. **One labelled retry, reachable only from NOT MEASURED.** A point that
   came back 75 is re-run once from a recovered box, marked `ATTEMPT 2`
   in the output and `attempt: 2` in the file. **A point that FAILED on a
   box which held its floor is never re-run** — a retry that can erase a
   red is not a guard, it is a way of eventually getting the answer you
   wanted. `--no-retry` disables it.

Across a sweep, a real red outranks an unknown and an unknown outranks a
green: a sweep with a NOT-MEASURED point exits 75 and must never be filed
as a clean acceptance run.

### The host state is in the file

Every results JSONL carries two rows the census reads and holds itself
to:

```json
{"node":"host","role":"host","leg":"mesh.hoststate.pre","ran":true,"ok":true,
 "detail":{"phase":"pre","attempt":1,"point":"relays=1 subs=4","nodes":7,
           "mem_available_gib":19.8,"mem_floor_mib":10746,
           "swap_used_gib":0.9,"swap_util":0.11,"disk_free_gib":134.2,
           "meminfo_source":"/proc/meminfo","fit":true,"breaches":[]}}
```

`pre` is sampled before the first container; `post` is sampled after the
publisher exits but **before** `compose stop`, while the containers are
still resident, which makes it a lower bound on the pressure the point
ran under rather than a reading of the box afterwards. Had these been in
the file, #536's pattern would have been visible on the first comparison
instead of the fifth run — so they are rows, not log lines, and they
survive into the committed baseline and into `--census-only`.

They are **evidence, not legs**. `host` is not a role and has no
contract, so rules 1 and 3 do not apply to it: a breached floor is not a
failure of the code.

### The degradation doctrine

The pre-flight can only speak for the box at t=0, and #536's actual
mechanism is that the box degrades *during* the point. So `census.py`
combines the two host rows with the leg verdict, and the rule is
asymmetric on purpose:

| host | run | verdict |
|---|---|---|
| held its floor | clean | `0` |
| held its floor | violations | `1` — a real red, no excuse exists |
| fell below | violations | **`75` NOT MEASURED** — this is #536 exactly |
| fell below | clean | `0`, the **pass stands**, loudly annotated |

A pass under degradation stands because host degradation can only
manufacture false **reds**, never false greens: under memory pressure a
leg either fails or never runs, and the census already fails both of
those. There is no path by which a starved box turns a broken leg green.
The doctrine therefore only ever *withholds* a verdict; it never grants
one. The perf numbers in a degraded file are still junk and the
annotation says so, but "did the mesh work" survives.

A file with no host rows is a pre-#536 baseline: the census says so and
leaves the verdict alone.

### Testing it without docker

`python3 census.py --self-test` drives the floors, the probe, the
recovery wait and the whole doctrine over synthetic `/proc/meminfo` text
and synthetic JSONL. Nothing it does touches a container.

`MESH_PREFLIGHT_MEMINFO` names a file to read instead of `/proc/meminfo`,
and `MESH_PREFLIGHT_DISK_FREE_GIB` substitutes the disk reading, so the
gate can be exercised on a box other than the one it guards. A backdoor
that let someone tell the gate "the box is fine" would be worse than no
gate, so it leaves a fingerprint: `meminfo_source` goes into the host row
and the census treats any row whose source is not `/proc/meminfo` as **no
host evidence at all** — it prints a loud warning and falls through to
the plain verdict. An override can make the harness refuse to run; it can
never make a red admissible.

---

## The topology, and why

```
publisher ──► relay-1 ──► sub-1, sub-2, nonmember
                 └──────► relay-2 ──► sub-3, sub-4
```

Connectivity over Reticulum TCP interfaces is exactly "who dialled whom".
A subscriber that only dials a relay **cannot** reach the publisher
directly, so publisher↔subscriber traffic genuinely transits a relay, and
`sub-3`/`sub-4` genuinely transit two hops. That is what makes `relay` a
real role — it runs with `with_transport_node(true)` and carries other
nodes' frames — rather than a third leaf.

**Every container is a distinct occurrence.** Each gets its own named
volume at `/state` holding its own Ed25519 federation seed (CSPRNG-minted
on first boot, never leaving that volume), its own leviculum transport
identity, and its own XChaCha-sealed KV. The only shared writable volume
is `/mesh`, and it carries **public bootstrap data only**: the roster of
`(key_id, public key, host:port)` and the steward-signed `federation_keys`
rows. That is exactly the data production learns through directory-cache
anti-entropy (CIRISEdge#175). No private key is ever written there. If a
future edit makes two containers share `/state`, the harness stops
measuring what it claims to measure.

The `nonmember` container exists so the refusal assertion is falsifiable.
It is rooted, reachable, and handed the same ciphertext as everyone else,
and it must still be unable to derive a cohort-scoped address or open a
frame. Without it, "a non-member cannot fetch" could pass by refusing
everything.

---

## What is real

- **Real distinct identities.** Per-container federation seed, transport
  identity, sealed KV, persist directory handle.
- **Real Reticulum transport** over TCP on a real docker network, and
  **real announce-based rooting** — a node learns its peers by verifying
  their signed announce attestations against the federation directory.
  No primed peer binding on the federation plane.
- **Real MLS.** openmls 0.8.1, X-Wing ciphersuite 0x004D, joined across
  process boundaries: the joiner mints a real KeyPackage, ships it over
  the real wire, and the creator's `add_member` Welcome comes back the
  same way.
- **The scope-address lifecycle driven exactly as documented**, with the
  live `ReticulumTransport` as the `ScopedDestinationSink`:
  ```rust
  let snap = cohort_addressing::snapshot(&community).await?;
  lifecycle.install(&scope, &snap)?;   // or .advance(&scope, &snap, now)
  lifecycle.seal_due(now);
  ```
  So an install registers a destination on the leviculum node and a seal
  retires it — both halves, on the real node.
- **Real encoded video.** ffmpeg generates a fixed-duration, fixed-size,
  fixed-rate, bit-exact-flagged H.264 elementary stream at image-build
  time; its SHA-256 is printed in the build log. The publisher reads real
  Annex-B access units out of it and seals each with `seal_av_inner` under
  an MLS-derived key, then `seal_av_outer` per link. Never `vec![0u8; N]`.
- **A real blob** — the media file itself, chunked and fanned out over the
  same transport, verified end to end by SHA-256.

## What is stubbed, and where

Two seams. Each is a named trait in `src/bin/edge_node.rs` so the real
API drops in as a second impl without touching measurement or reporting.

| Seam | Trait | Today | Blocked on |
|---|---|---|---|
| A/V chunk transport | `MediaLink` | `Transport::send` — the real RNS resource path | `src/transport/av_spine.rs` (join→subscribe→relay→heal), in flight |
| Scope-native blob fetch | `BlobPlane` | push over the transport, gated on cohort membership | `src/blob_swarm/` scope-native fetch, in flight |

The A/V seam exists for a structural reason worth knowing: `AvPublisher`
/ `AvRelay` / `LeviculumAvSender` / `LinkDataPump` all need an
`Arc<ReticulumNode>`, and `ReticulumTransport::node()` is `pub(crate)`
and `#[cfg(feature = "pyo3")]`. A downstream consumer holding a
`ReticulumTransport` cannot reach the node, so it cannot construct the
real-RNS A/V sender at all.

(An earlier third seam, `ScopedDialer`, installed a peer binding by hand
and tried to `link_open` a scope-derived address. It is gone: a scoped
address is an explicit-hash destination and cannot be routed to at all,
so the seal-retirement leg now measures the admission seam instead —
see the `conformance.seal_retires` row below.)

**The media DEK and the per-link transit key are a labelled harness
derivation** (`epoch_keys`, HKDF over the cohort's record-plane exporter
with a `ciris-edge/bench-mesh/media/v1` info string). Production takes
the DEK from an `AvSession`'s own MLS group and the transit key from a
`FederationSession` hybrid KEX; neither is reachable across processes
today (the A/V session join rides the in-flight spine, and
`SessionHandshakeMsg` has no serde wire form). The substitute is still a
real MLS exporter that every member derives identically and that changes
on every epoch advance — which is the property the rotation leg turns on
— but it is not the production key schedule, and the code says so.

---

## Reading the numbers

Every line is one leg from one node:

```json
{"leg":"perf.publish_fanout","node":"publisher","role":"publisher",
 "ran":true,"ok":true,"detail":{...}}
```

`ran` and `ok` are separate on purpose, and `ok` is absent when `ran` is
false. **There is no way to spell "green because we skipped it."**
`run.sh` and each container's exit code both treat a leg that did not run
as a failed run.

### Performance legs

| Leg | Field | Means |
|---|---|---|
| `perf.publish_fanout` | `send_latency.p50_us` / `p95_us` / `p99_us` | per-chunk publisher-side delivery latency, microseconds |
| | `fanout_chunks_per_s` | chunks × subscribers per second — the fan-out throughput at this M. Excludes the rotation barrier (`rotation_stall_ms`), which is a wait for a peer to show up, not fan-out work. Leaving it in made this number two orders of magnitude apart between M=1 and M=2 for reasons that had nothing to do with fan-out. |
| | `rotation_stall_ms` | wall time the publisher spent waiting at the mid-stream rotation. Large values mean the late joiner was slow to present its KeyPackage, not that the mesh was slow. |
| | `fanout_bytes_per_s` | sealed bytes per second |
| | `access_units_in_file` | how many real encoded access units the media held |
| `perf.receive` | `time_to_first_frame_ms` | from the subscriber entering its receive loop to the first frame |
| | `open_latency.p50_us` … | double-AEAD open cost per chunk |
| | `delivery_ratio` | distinct sequence numbers opened ÷ frames the publisher announced |
| `perf.blob_fanout` | `completion_ms_per_peer` | per-peer blob completion, milliseconds. `null` means that peer did not complete — never 0 |
| `conformance.member_can_fetch` | `chunks_arrived_before_announcement` | chunks that outran their `BlobStart`. Control and data ride separate channels, so nothing orders them; a non-zero value is normal and means the receiver's hold-and-replay path did its job. `early_chunks_dropped_over_budget > 0` means it overflowed and the completion is genuinely short. |
| `conformance.member_can_fetch` | `completion_ms` | receiver-side blob completion |

**The curve, not one point.** `--sweep` runs M ∈ {4,2,1} — heaviest first
(CIRISEdge#536) — and writes one file per point; `fanout_chunks_per_s`
across those files is the fan-out throughput curve. A single point cannot
show where fan-out stops scaling. Read each point's `mesh.hoststate.*`
rows before comparing perf numbers across files: a point measured on a
degraded box is not comparable to one measured on a fresh one, even when
both passed.

### Conformance legs — these matter more

| Leg | Passes when |
|---|---|
| `conformance.rotation_frame_loss` | a member present across the mid-stream epoch advance saw `missing_seqs: []` **and** `crossed_an_epoch_advance: true`. This is the acceptance criterion for CIRISEdge#499's make-before-break design: **zero frames may be lost across a rotation.** A node admitted *at* the rotation reports this leg as `ran: false` with the reason — pre-admission frames are not losses, and scoring it would score the wrong node. |
| `conformance.nonmember_cannot_fetch` | the non-member derived **no** scoped address and opened **zero** frames, *and* `ciphertext_frames_offered > 0`. If no ciphertext ever reached it the leg reports `ran: false` — a leg that refuses nothing proves nothing. Only the first few frames are addressed to it (`observer_frames_each`): the refusal is an AEAD key it does not hold, which fails identically on every frame, and addressing it the whole stream would make the publisher pay a transport timeout per frame the moment the observer stops reading — quietly turning `fanout_chunks_per_s` into a measure of how fast a dead peer fails. Observer sends are excluded from the throughput numbers (`observer_sends_excluded_from_throughput`). |
| `conformance.member_can_fetch` | a member reassembled the blob and the SHA-256 matched. The paired half of the above: the two together are what stop the test passing by refusing everything. |
| `scope.seal` | the **owner-side** half of retirement, measured by the member that owns the address: after the convergence window, `sealed > 0`, `unretired: 0`, the superseded address is gone from the table, and the live one still answers. |
| `conformance.seal_retires` | the **peer-side** half, measured at the **admission seam**: a *different* node (the publisher) sends application-level `AddressProbe`s over the owner's announced, rooted node destination — through the relay — naming the owner's live and superseded scope addresses, before and after the seal. The owner answers each probe from the **production** arrival-admission lookup (`ReticulumTransport::inbound_scope` → `ScopeAddressTable::accepts_inbound`, the same reverse index that stamps `arrival_scope` on every arriving frame), so the answer is the admission decision, not bookkeeping. After the seal the superseded address must answer `held: false` **while** the live one still answers `held: true` — the live answer is the aliveness control that makes "refused" distinguishable from "node down". The prober derives both addresses from its **own** table, so a `held: true` answer is also cross-node derivation agreement. If the before-reading did not establish both addresses held, or a post-seal probe goes silent (silence is transport loss, not a refusal — a refusal is an ack carrying `held: false`), the leg reports `ran: false` with the reason rather than guessing. See below for why it probes instead of dialling. |
| `conformance.relay_holds_no_cohort_address` | a relay, which is not in the cohort roster, derived no address — no exporter secret reaches it. |

### Two shapes of epoch advance

At **M ≥ 2** the advance is a real roster change: the last subscriber is
held back and admitted mid-stream via `add_member`, which is the case
CIRISEdge#499's criterion is written about. `scope.rotation` reports
`kind: "member_join"`.

At **M = 1** there is nobody to hold back — the late joiner would *be*
the only member, leaving no one present across the advance to assert
zero-loss on. The publisher rekeys with `CohortGroup::rotate()` instead:
still a real MLS epoch advance and still a full address re-derivation,
but no roster change. `scope.rotation` reports `kind: "rekey_only"`, so
the two are never confused in a results file.

The node admitted at the rotation reports
`conformance.rotation_frame_loss` as `ran: false` — the frames that
preceded its admission are not losses, and scoring them against it would
score the wrong node.

### Why `conformance.seal_retires` probes instead of dialling

An earlier shape of this leg tried to RNS-dial the owner's scope-derived
address directly through the relay, and reported `ran: false` on every
run. That was structural, and **by design** (CIRISEdge#499):

A scope-derived destination is registered with
`Destination::with_explicit_hash`, and an explicit-hash destination
**cannot announce** (`AnnounceError::ExplicitHashCannotAnnounce`;
leviculum answers a path request for one with silence, because a path
response *is* an announce and an announce for a caller-supplied hash is
unverifiable by reference RNS). So no multi-hop RNS path to a scoped
address can exist — and this topology deliberately puts a relay between
the prober and the owner.

The federation-scope destination does not have this problem because a
node also registers an *announceable* named destination alongside it. A
scope-derived address has no such twin, by design: announcing one would
publish the very reachability fact the derivation exists to withhold. A
scoped address is an **arrival discriminator, not a routable endpoint**.

So the leg now measures retirement where it actually lives: at the
**admission seam**. The publisher *can* reach the owner over its
announced node destination (`mesh.rooting` proves those paths exist
through the relay), so it probes over that path and the owner answers
from the same lookup the transport's arrival path consults for every
real frame. The two halves together: `scope.seal` is the owner's own
table-and-transport view, `conformance.seal_retires` is a different
node observing the production admission decision flip across the seal.

### A measured limit: M=4 through a single relay

A run of `--subs 4 --relays 1` on a laptop-class host degraded hard and
the harness reported it rather than smoothing it: the publisher's rooting
took 31.5 s against 0.5 s for every other node, `send_latency.p95` hit
~4.0 s (the transport timeout), `fanout_chunks_per_s` fell to 0.37, and
no peer completed the blob (`completion_ms_per_peer` all `null`). Twelve
legs reported `ran: false`, including `scope.seal` with
`send SealProbe: transport timeout after 30s`.

Six nodes all routing through one relay is a plausible saturation point
and this is exactly the class of thing the harness exists to find — but
it has not been root-caused, and it may be an artefact of the topology
rather than a substrate limit. Run `--subs 4 --relays 2` (which puts
`sub-3`/`sub-4` behind a second relay) before drawing a conclusion. Do
not read the M=4 point as a substrate number.

**And now suspect that observation itself.** It was recorded from a sweep
that ran M=4 last, on the box the two lighter points had already loaded —
the exact artefact CIRISEdge#536 turned out to be. That reading carried
no host state, so there is no way to tell from the file whether the
laptop-class host was below the floor when it was taken. Nothing above is
retracted, because nobody has re-measured it; but it is not evidence of a
topology limit until it reproduces on a box that passed the pre-flight,
with its `mesh.hoststate.*` rows in the file.

### How to read a regression

0. **The exit code and the `host` rows.** A `75` is not a regression —
   the box could not host the measurement and no verdict exists. And a
   `1` on a file whose `mesh.hoststate.post` says `ok: false` is already
   withheld by the census; if you are looking at one, you fetched the
   file rather than the exit code.
1. **Any `ran: false`.** Read `not_run_reason` first. Nothing else in the
   file is trustworthy until you know which legs actually executed.
2. **`conformance.*` before `perf.*`.** A conformance failure is a claim
   the release makes turning out to be false; a perf move is a number. If
   `rotation_frame_loss` fails with a non-empty `missing_seqs`, the
   make-before-break window is wrong — either the convergence window is
   too short for this topology (`MESH_CONVERGENCE_SECS`) or the rotation
   is not actually make-before-break.
3. **`p99` moving while `p50` holds** is tail behaviour: relay queueing or
   link re-establishment, not per-chunk cost. Compare against
   `benches/transport_reticulum_loopback` — if the micro-bench is flat and
   this moved, it is the *mesh*, not the substrate.
4. **`fanout_chunks_per_s` falling as M rises** across the sweep is the
   expected shape; what matters is where the knee is versus the previous
   run at the same M. Compare like for like — a curve point is only
   comparable to the same point.
5. **`delivery_ratio < 1` on a member present across the advance** is the
   loudest signal in the file. That is the rotation dropping frames.

### The results file is refused if it merges runs

`run.sh` asserts that each `(node, leg)` pair appears **at most once** in
a results file and fails the point outright if it does not. That guard
exists because of a trap this harness fell into once: reading the results
with `docker run -v <volume>:/r` re-creates the volume *without* compose's
project labels, after which `docker compose down -v` silently leaves it
behind and the next run appends to it. The file then looks normal and is
several runs merged. `run.sh` now removes the volumes by name, and the
duplicate check is the backstop that would catch it happening again.

### What the harness will not do

It will not report a number it did not measure. Absent statistics are
`null`, not zero; an empty latency sample yields `null` percentiles, not
`0`; a peer that did not complete the blob is `null`, not a time. If a
leg cannot run it says so and the run fails. This exists because a green
summary over a skipped leg is worse than a red one.

It will also not render a verdict on a box that could not host the run.
A red summary over a starved host is worse than no summary at all,
because it looks like a fact about the code — and it costs whoever
believes it a bisect. If the box is below the floor the harness says NOT
MEASURED and exits 75, and if it fell below the floor mid-run and legs
failed, the census withholds the verdict rather than guessing which of
the two it was.

---

## CI

Wire as `workflow_dispatch` + weekly only — **never per-PR.** This starts
eight containers and builds a full release image; the repo has a
documented runner budget and `.github/workflows/bench.yml` already guards
cost the same way. The per-operation regression alarm is the
instruction-count gate on `benches/`, and that one is cheap; this is the
periodic "does the mesh still work end to end" instrument.

**A CI wiring must distinguish `75` from `1`.** Folding NOT MEASURED into
"failed" reintroduces the whole of CIRISEdge#536 at the workflow level: a
red board that means "the runner was too small" reads identically to one
that means "the mesh broke", and someone will bisect the difference. A
`75` should surface as *skipped* or as its own status, and should not
block a release; a `1` should.

`python3 census.py --self-test` is cheap, needs no docker, and holds both
the role contracts and the host floors to their evidence. It belongs on
every PR that touches `bench-mesh/`.

---

## Environment reference

Set by `run.sh`; override for one-off runs.

| Variable | Default | Meaning |
|---|---|---|
| `EDGE_ROLE` | — | `publisher` \| `relay` \| `subscriber` \| `nonmember` |
| `EDGE_NODE_ID` | — | this occurrence's federation key id |
| `EDGE_EXPECT` | — | every node id in the mesh; the roster barrier waits for all of them |
| `EDGE_COHORT_MEMBERS` | — | the cohort roster, **publisher first** |
| `EDGE_BOOTSTRAP` | — | comma-separated `host:port` to dial |
| `EDGE_SCOPE` | `cohort:bench` | `family` or `cohort:<id>` |
| `MESH_FRAMES` | 120 | frames to publish |
| `MESH_ROTATE_AT` | frames/2 | frame index at which the late joiner is admitted |
| `MESH_LATE_JOINER` | last subscriber | which node joins mid-stream |
| `MESH_CONVERGENCE_SECS` | 20 | make-before-break window before a seal |
| `MESH_ROOT_TIMEOUT_SECS` | 180 | ceiling on announce-rooting cold start |
| `MESH_BARRIER_TIMEOUT_SECS` | 300 | ceiling on any single barrier |
| `MESH_RECOVER_TIMEOUT_SECS` | 180 | how long a point's pre-flight waits for the host to come back to its floor before refusing (`--recover-timeout`) |
| `MESH_DOCKER_ROOT` | `/var/lib/docker` | which filesystem the disk check measures; set it if docker's data root has been moved |
| `MESH_PREFLIGHT_MEMINFO` | — | **test seam.** A file to read instead of `/proc/meminfo`. Fingerprinted into the host row; a file carrying such a row is a dry run, not a baseline, and its host state is not allowed to affect any verdict |
| `MESH_PREFLIGHT_DISK_FREE_GIB` | — | **test seam.** Substitutes the disk reading. Same fingerprint |
