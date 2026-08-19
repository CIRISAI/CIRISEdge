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
./run.sh --sweep                # M ∈ {1,2,4} — the fan-out curve
./run.sh --clean                # drop every volume; next run mints fresh identities
```

Requires `docker` with compose v2+. Nothing else — ffmpeg, the Rust
toolchain, and libsqlite3 all live inside the image.

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
object per leg per node.

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

Three seams. Each is a named trait in `src/bin/edge_node.rs` so the real
API drops in as a second impl without touching measurement or reporting.

| Seam | Trait | Today | Blocked on |
|---|---|---|---|
| A/V chunk transport | `MediaLink` | `Transport::send` — the real RNS resource path | `src/transport/av_spine.rs` (join→subscribe→relay→heal), in flight |
| Dialling a scope-derived address | `ScopedDialer` | the harness installs the peer binding itself, then `link_open` | no transport verb accepts a `ScopeAddressTable::send_address` result |
| Scope-native blob fetch | `BlobPlane` | push over the transport, gated on cohort membership | `src/blob_swarm/` scope-native fetch, in flight |

The A/V seam exists for a structural reason worth knowing: `AvPublisher`
/ `AvRelay` / `LeviculumAvSender` / `LinkDataPump` all need an
`Arc<ReticulumNode>`, and `ReticulumTransport::node()` is `pub(crate)`
and `#[cfg(feature = "pyo3")]`. A downstream consumer holding a
`ReticulumTransport` cannot reach the node, so it cannot construct the
real-RNS A/V sender at all.

The `ScopedDialer` leg stamps `dial_binding: "harness_installed"` on its
own output, so nobody can read the seal-retirement result as evidence
that a production dial path exists.

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

**The curve, not one point.** `--sweep` runs M ∈ {1,2,4} and writes one
file per point; `fanout_chunks_per_s` across those files is the fan-out
throughput curve. A single point cannot show where fan-out stops scaling.

### Conformance legs — these matter more

| Leg | Passes when |
|---|---|
| `conformance.rotation_frame_loss` | a member present across the mid-stream epoch advance saw `missing_seqs: []` **and** `crossed_an_epoch_advance: true`. This is the acceptance criterion for CIRISEdge#499's make-before-break design: **zero frames may be lost across a rotation.** A node admitted *at* the rotation reports this leg as `ran: false` with the reason — pre-admission frames are not losses, and scoring it would score the wrong node. |
| `conformance.nonmember_cannot_fetch` | the non-member derived **no** scoped address and opened **zero** frames, *and* `ciphertext_frames_offered > 0`. If no ciphertext ever reached it the leg reports `ran: false` — a leg that refuses nothing proves nothing. Only the first few frames are addressed to it (`observer_frames_each`): the refusal is an AEAD key it does not hold, which fails identically on every frame, and addressing it the whole stream would make the publisher pay a transport timeout per frame the moment the observer stops reading — quietly turning `fanout_chunks_per_s` into a measure of how fast a dead peer fails. Observer sends are excluded from the throughput numbers (`observer_sends_excluded_from_throughput`). |
| `conformance.member_can_fetch` | a member reassembled the blob and the SHA-256 matched. The paired half of the above: the two together are what stop the test passing by refusing everything. |
| `scope.seal` | the **owner-side** half of retirement, measured by the member that owns the address: after the convergence window, `sealed > 0`, `unretired: 0`, the superseded address is gone from the table, and the live one still answers. |
| `conformance.seal_retires` | the **peer-side** half: a *different* node dials the owner's live and superseded addresses, before and after the seal, and the superseded one must stop answering while the live one keeps answering. The dialler derives both addresses from its **own** table, so a dial that lands is also cross-node derivation agreement. Both are dialled **before** the seal; if they did not both answer then, the leg reports `ran: false` rather than scoring a pass off a dead dial. **This leg currently reports `ran: false` on this branch — see below.** |
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

### A known `ran: false`: `conformance.seal_retires`

On this branch the peer-side dial does not establish, and the leg says so
with the diagnosis rather than a shrug. The cause is not a failed seal:

A scope-derived destination is registered with
`Destination::with_explicit_hash`, and an explicit-hash destination
**cannot announce** (`AnnounceError::ExplicitHashCannotAnnounce`;
leviculum answers a path request for one with silence, because a path
response *is* an announce and an announce for a caller-supplied hash is
unverifiable by reference RNS). So no multi-hop RNS path to a scoped
address can exist — and this topology deliberately puts a relay between
the dialler and the owner.

The federation-scope destination does not have this problem because a
node also registers an *announceable* named destination alongside it. A
scope-derived address has no such twin, by design: announcing one would
publish the very reachability fact the derivation exists to withhold.

What that means for the claim: the **owner-side** half is measured and
passes (`scope.seal` — table closed, transport retired, `unretired: 0`,
live address still answering). The **peer-dials-it** half is not
measurable from a relayed peer today. Do not read the `ran: false` as a
seal failure, and do not "fix" it by putting the dialler on the same
link as the owner — that would make the leg pass while measuring
something narrower than it claims.

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

### How to read a regression

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

---

## CI

Wire as `workflow_dispatch` + weekly only — **never per-PR.** This starts
eight containers and builds a full release image; the repo has a
documented runner budget and `.github/workflows/bench.yml` already guards
cost the same way. The per-operation regression alarm is the
instruction-count gate on `benches/`, and that one is cheap; this is the
periodic "does the mesh still work end to end" instrument.

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
