# CALM — the ALM control frame (C3) — wire layout

Source for the CC rc16 draft (CC 5.3.3.2.3 / 6.1.6, with `FSD/CIRIS_MESH.md`
§4). Everything here is read from the code on branch `feat/onion-v44`;
`file:line` points at it. Paths are under `src/`. Integers are big-endian.
There is no CBOR and no JSON: every frame is a fixed concatenation.

The codec is `transport/realtime_av_alm/controller/wire.rs`, pure and
synchronous. The call layer that sends and applies frames is
`transport/av_call.rs` with `transport/av_call/alm.rs`. Admission is
`transport/realtime_av_alm/controller/admission.rs` and the parent selector is
`.../controller/selector.rs`.

## 1. Where CALM rides

- **On a call's A/V links** (the member-to-member links a call dials to derived
  call addresses), never on an identity, scoped or relayed transport link.
- **Inside the E1 link seal** (CC 5.3.3.5), like every frame on the link. It
  takes **no A/V outer seal and no hop counter**, like a binding part
  (`docs/av_chunk_auth_wire.md` §1.4). A receiver's pending hop gap is carried
  past a CALM frame unchanged (`av_call.rs:2557`).
- **In either direction of a link.** Each member pair normally holds two links,
  one dialled by each end. A member sends on the leg it dialled when it has
  one. Otherwise it sends on the reverse direction of the link the peer dialled
  to it (`send_alm`, `av_call.rs:2359`).

## 2. Framing

```
frame = magic "CALM" (4) ‖ version 0x01 (1) ‖ kind (1) ‖ body
```

| Constant | Value | Cite |
|---|---|---|
| `CONTROL_MAGIC` | `43 41 4c 4d` ("CALM") | `wire.rs:46` |
| `CONTROL_VERSION` | `0x01` | `wire.rs:48` |
| header length | 6 bytes | `wire.rs:49` (`HEADER_LEN`) |

A frame is a CALM frame iff it is at least 6 bytes long and starts
`"CALM" 0x01` (`is_control_frame`, `wire.rs:82`).

**Telling a frame from a chunk.** A chunk's first 32 bytes are its stream id. A
publisher never mints a stream id that begins `"CALM" 0x01`: `start_stream`
draws the join nonce again (`av_call.rs:1869`; `collides_with_control_frame`,
`wire.rs:76`). It already redraws for `"CSKB" 0x01`.

**Version.** A frame with an unknown version is not a CALM frame. It falls
through to the binding and chunk parsers and fails there. A later version gets
a new version byte together with a new capability bit (§4), so it is never
sent to a peer that did not ask for it.

## 3. Messages

`stream` is the 32-byte stream id the message is about. `role` is `0x00`
primary (the full stream) or `0x01` standby (base layer and codec-opaque audio
only; `role_code`, `wire.rs:136`). Any other role byte is malformed.

| Kind | Code | Body | Total length |
|---|---|---|---|
| `CAPS` | `0x01` | `caps u32` | 10 |
| `SUBSCRIBE` | `0x02` | `stream[32] ‖ role u8 ‖ flags u8` | 40 |
| `UNSUBSCRIBE` | `0x03` | `stream[32]` | 38 |
| `ADMIT` | `0x04` | `stream[32] ‖ role u8` | 39 |
| `REFUSE` | `0x05` | `stream[32] ‖ reason u8 ‖ retry_after_ms u32` | 43 |
| `SHED` | `0x06` | `stream[32] ‖ reason u8` | 39 |
| `OFFER` | `0x07` | `stream[32] ‖ depth u8 ‖ forwarding u8 ‖ headroom_bps u64 ‖ forwarder_headroom_bps u64 ‖ upstream_latency_ms u32 ‖ n u8 ‖ n × (len u16 ‖ utf8 key id)` | 64 + Σ(2 + len) |

The kind constants are at `wire.rs:61–67`. The encoder is `encode` /
`encode_caps` (`wire.rs:153`, `:162`) and the decoder is `decode`
(`wire.rs:269`).

Field rules (enforced at decode):

- **CAPS** is a bit set (`wire.rs:52–56`):
  - bit 0: speaks C3 v1;
  - bit 1: this node's leviculum takes timed Channel frames (0xFD00/0xFD01,
    leviculum v0.33+);
  - bit 2: offers relay.

  Unknown bits are ignored. This build sends `0b011`, or `0b111` when it relays
  (`CAPS_THIS_BUILD`, `wire.rs:59`).
- **SUBSCRIBE** `flags`: bit 0 means the requester can itself forward
  (`forward_capable`). The other bits are ignored.
- **REFUSE** `reason`:
  - the code is `RefuseReason::code` (`controller/mod.rs:450`); unknown codes
    are malformed (§6);
  - `retry_after_ms` saturates at `u32::MAX`.
- **SHED** `reason` is `ShedReason::code` (`controller/mod.rs:530`): 0
  over-committed, 1 upstream lost, 2 preempted, 3 load shed. Unknown codes are
  malformed.
- **OFFER**:
  - `depth`: 0 is the publisher itself, and only the publisher may claim it
    (§4 rule 5).
  - `forwarding`: `0x01` means the sender is receiving the stream now; any
    other value reads as false.
  - Both headroom fields are in the selector's nominal units: the forwarder
    scales its measured headroom to them (`av_call/alm.rs`, `nominal`).
  - The ancestry is root first, `n ≤ 8` (`MAX_ANCESTRY`, `wire.rs:70`). Each
    key id is `1 ≤ len ≤ 256` (`MAX_KEY_ID_LEN`, `wire.rs:72`) and valid
    UTF-8 (`wire.rs:332–341`). An encoder truncates silently to these bounds; a
    decoder refuses an over-long count or entry.
- **Trailing bytes** after a complete body make the frame malformed
  (`r.end()`, `wire.rs:359`).

## 4. Normative rules

1. **The sender is the link peer and is never named in a frame.** No message
   carries the subscriber, forwarder or offerer. `decode(frame, peer)` fills
   every peer field (`SubscribeRequest::subscriber`, the unsubscribing member,
   `Offer::from`) from the link's attributed peer, the CC 5.3.3.5 E1 / #393
   attribution (`wire.rs:269`; witness
   `the_sender_can_not_name_another_subscriber`). A member therefore cannot
   subscribe, unsubscribe or offer in another's name.
2. **CAPS first, from the responder, on the reverse direction.** The responder
   of each A/V link sends `CAPS` on the reverse direction of the link it
   accepted, right after the stream hello (`av_call.rs:2286`). It is the first
   CALM frame on that link.
   - A pre-C3 dialler never reads that direction: it dropped its receiver, and
     the transport counts and drops the frame (`AvDelivery::ConsumerGone`). It
     is harmless there.
   - A C3 dialler answers with its own `CAPS` on its leg, once, only after
     hearing one (`handle_c3`, `av_call.rs:2449`; `out_leg_reader`,
     `:2489`).
   - **No other kind is sent to a peer that has not sent `CAPS` with bit 0**
     (`send_alm` filters on `speaks_c3`, `av_call.rs:2359`;
     `av_call/alm.rs:269`). A pre-C3 peer would read a CALM frame as a chunk
     that fails to open.
   - **Pre-C3 peers are served as before:** the full stream, plus the legacy
     first-hand relay when this node relays (`own_exclude`,
     `av_call/alm.rs:478`).
3. **Membership gates media parents, in both directions** (CC 5.4.6 forwarder
   paragraph, E1 item 1, CC 6.1.6: tree nodes are members). The roster is the
   room's MLS group, updated at every epoch roll.
   - **Subscriber side.** A candidate outside the roster is never a primary or
     a standby (`selector.rs:724`; `set_members`, `:271`). An `OFFER` from a
     non-member is ignored (`av_call/alm.rs:759`). A parent that leaves the
     roster is dropped.
   - **Forwarder side.** `SUBSCRIBE` is refused `relay_nonmember_fanout` when
     the requester, or this forwarder itself, is outside the roster
     (`admission.rs:577–579`).
   - **Non-member transport forwarders.** The canonical, or a non-member
     contact, is a transport forwarder of one member-to-member link 1:1, never a
     tree node. A second downstream leg of one stream through it is refused
     `relay_nonmember_fanout` (`admission.rs:584`; FSD §4.4 M2).
   - **The canonical** is never a primary (video) parent
     (`relay_class_refused:video`, `admission.rs:590`; FSD §6.4 V1). It is
     audio only, within 5 % of its capacity (V2).
4. **A forwarder sends a stream only to the members it admitted**: primaries
   get the full stream, standbys base-layer and codec-opaque chunks only. It
   forwards only chunks that arrive from its own primary (or promoting) parent,
   once each, and never back to their sender or publisher (`forward_exclude`,
   `av_call/alm.rs:508`). This replaces the `CallOptions::relay` flood.
   - **Direct first (FSD R1).** A viable publisher (depth 0) is taken before
     any relay, whatever the relays score, and a relay gives way to a publisher
     that becomes viable. A publisher with no room stops being viable, which is
     how it sheds subscribers to relays.
   - **One exception: the join gap.** A publisher keeps sending its own stream
     to a C3 member that has not yet chosen a parent, for at most 10 s
     (`PROVISIONAL_MS`). The member's `SUBSCRIBE` or `UNSUBSCRIBE` ends it.

5. **Depth 0 is the stream's publisher, and the binding says who that is.**
   An `OFFER` is attributed by the link (rule 1) but not signed, so a claim of
   depth 0 is checked on receipt against the publisher named by the stream's
   verified key binding (`docs/av_chunk_auth_wire.md`; a stream id is derived
   from its publisher, so a member cannot bind another's). This is a receive
   rule with no change to the frame.
   - A claim from anyone else is **dropped whole**: it does not name the
     publisher, does not reach the selector and is not scored as direct.
     Nothing honest sends one. It is not clamped to a relay's depth, because
     that would keep a liar as a candidate with a made-up depth and an empty
     ancestry, which blinds the loop check.
   - With no binding held yet the claim cannot be checked, so it is dropped
     too. Chunks cannot be verified without the binding either, and the
     publisher offers again within `OFFER_EVERY_MS` (1 s).
   - Each drop is counted (`alm_offer_refused`, with
     `alm_offer_refused:not_publisher` or `alm_offer_refused:unbound`;
     `AlmCounts::offers_refused`) and recorded in the C7 decision log
     (`DecisionKind::OfferRefused`). `unbound` is normal at a join.
   - The stream hello is unsigned too. It only supplies a first guess at the
     publisher, which a binding overrides and which never overrides a binding
     (`note_publisher`, `av_call/alm.rs`).

## 5. Refusal and shed tokens

Each refusal is logged with its token, counted in `av_plane` under the token
and under `alm_refuse`, and recorded in the C7 decision log.

| Token | Code | Meaning | Cite |
|---|---|---|---|
| `relay_capacity` | 0 | no usable capacity (C2: `0.65 × min(advertised, measured) − committed − reserve`, one trial slot while unmeasured) | `admission.rs:692` |
| `relay_loop` | 1 | the requester is in this forwarder's ancestry | `admission.rs:601` |
| `relay_depth_limit` | 2 | the child would sit past `max_depth` (3) | `admission.rs:607` |
| `relay_upstream_unhealthy` | 3 | no healthy delivering upstream, or this node does not forward the stream | `admission.rs:604`; `av_call/alm.rs` (`on_control`, `SUBSCRIBE` for an unforwarded stream) |
| `relay_nonmember_fanout` | 4 | the requester or the forwarder is not a member, or a non-member's second leg of a stream | `admission.rs:579`, `:584` |
| `relay_class_refused:video` | 5 | a primary (video) asked of a forwarder that never carries video (the canonical) | `admission.rs:590` |
| `load_refuse:admit_closed` | 6 | the service tier closed admission to new relay work (FSD §7.2) | `admission.rs:598` |

Shed tokens (`ShedReason::token`, `controller/mod.rs:519`):
`relay_shed:over_committed`, `relay_shed:upstream_lost`, `relay_shed:preempted`,
`load_shed:audio`. A `load_shed` is make-before-break: the forwarder keeps
sending to the shed child until it unsubscribes or 5 s pass.

Decode failures (`WireError::token`, `wire.rs`): `alm_c3_not_control`,
`alm_c3_unknown_kind`, `alm_c3_malformed`. They are counted under
`alm_c3_malformed` and the frame is dropped. **A malformed CALM frame never
closes the link**: the E1 seal already authenticated its sender.

## 6. Acceptance and validation order

**Receiving (pump, `av_call.rs:2557`)**, per frame on an A/V link:

1. The E1 link seal opens it, or the transport closes the link (CC 5.3.3.5).
2. The hop gap reported with the frame is folded in and stays pending.
   The gap a chunk finally opens at, less this node's own age drops, is what
   the receiver's path meter reads as loss. The counter takes no chunk the
   sender's layer policy filtered or its link refused, so it needs no word on
   the wire about that policy; CALM has none. `chunk_seq` gaps are not read as
   loss on any path, because every layer spends that one sequence
   (`realtime_av_alm/controller/path_meter.rs`).
3. If the frame starts `"CALM" 0x01` it is C3. It is decoded with the link's
   attributed peer as the sender (§4.1):
   1. framing: magic, version, a known kind;
   2. the body length for that kind, every field read in order;
   3. the field ranges: role byte, reason codes, ancestry count and entry
      lengths, UTF-8;
   4. no trailing bytes.

   Any failure is §5's decode refusal.
4. A decoded frame is applied (`on_control`, `av_call/alm.rs:668`):
   - **`CAPS`** records the peer's bits. On the first `CAPS` from a member with
     bit 0, that member enters the join gap; with bit 1, its media is sent
     timed from then on.
   - **`SUBSCRIBE`**:
     - for this node's own stream, the publisher's admission answers;
     - for a stream this node forwards, that relay admission answers;
     - otherwise the answer is `relay_upstream_unhealthy`.

     The admission checks, in order (`admission.rs:577–692`):
     1. membership: of the forwarder and of the requester;
     2. the non-member one-leg rule (M2);
     3. the class policy (no video);
     4. admit-close;
     5. loop (the requester is in the ancestry);
     6. upstream health;
     7. depth;
     8. capacity, with forwarder preemption.

     The answer is sent back as `ADMIT` or `REFUSE`. Any preempted children get
     `SHED` (preempted).
   - **`UNSUBSCRIBE`** releases the sender's commitment, including a draining
     one.
   - **`ADMIT` / `REFUSE`** go to the selector for that stream. A stale answer
     to something no longer wanted is unsubscribed. A refusal backs the
     candidate off for `max(retry_after_ms, jittered backoff)`.
   - **`SHED`** goes to the selector. The shedding parent is marked as
     draining, and is unsubscribed once a replacement primary is up.
   - **`OFFER`**:
     - ignored from a non-member, or about this node's own stream;
     - a claim of depth 0 from anyone but the publisher the binding names is
       dropped, logged and counted (§4 rule 5);
     - otherwise it feeds the selector. An offer older than 5 s is not a
       candidate. It never names the publisher: the binding does.

**Sending.** `send_alm` (`av_call.rs:2359`) sends nothing to a peer without
`CAPS` bit 0. It sends on this node's own leg to the peer (five brief
backpressure retries), or, without a leg, on the reverse direction of the
peer's link to this node. A frame on a leg settles that leg for 50 ms
(`C3_SETTLE`, `realtime_av_dispatcher.rs:534`): the Channel opens at a window of 2,
so without it the chunk right behind an `OFFER` is refused and lost.

**Delivery.** `OFFER` is periodic: one the link refuses is dropped, and the
next replaces it. **Every other kind must arrive**, because it changes state on
one side only (`is_periodic`, `wire.rs:89`). One the link refuses is resent off
the data path for up to 2 s (`resend_c3`, `av_call.rs:2413`), inside the 3 s request
timeout.

**Binding bursts are paced** (`send_binding_paced`, `av_call.rs:2764`): a
re-announced binding (about ten Channel messages on a base-MTU link) goes out
one part per hold of the publisher lock, so publishing and forwarding run
between its parts; a relay re-forwards it off its receive loop. **Unproven:**
reverting this to one burst under one lock hold was not caught by the A8 or
forge witnesses in 24 pinned runs (12 + 12, two cores). It stays in because
the burst measurably held the lock for its whole length; it is not shown to be
what lost frame 12.

**A lost answer never strands a commitment.** A `SUBSCRIBE` unanswered after
`REQUEST_TIMEOUT_MS` (3 s) is withdrawn with `UNSUBSCRIBE`, or, when it was a
standby asking for the primary role, with `SUBSCRIBE` standby
(`selector.rs:1010`, in `tick`). Without this a lost `ADMIT` leaves the forwarder
committed to a subscriber that does not know it, and its offers then show that
subscriber no room, so it never asks again.

## 7. KAT vectors

These come from `calm_kat_vectors` (`realtime_av_alm/controller/wire.rs`, tests
module), which asserts every vector byte for byte. It also decodes each one
back with the link peer `node-kat-b` filling every peer field. Run it with
`--nocapture` to print them.

**Inputs**:
- stream `00 01 02 … 1f`;
- CAPS = 7 (C3 v1 | timed | relay);
- SUBSCRIBE: standby, forward-capable;
- ADMIT: primary;
- REFUSE: `relay_class_refused:video`, retry 1500 ms;
- SHED: `load_shed:audio`;
- OFFER: depth 1, forwarding, headroom 2 000 000, forwarder headroom
  3 000 000, upstream latency 42 ms, ancestry `["node-kat-a"]`.

```
CAPS        (10 B) 43414c4d 01 01 00000007
SUBSCRIBE   (40 B) 43414c4d 01 02 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 01 01
UNSUBSCRIBE (38 B) 43414c4d 01 03 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ADMIT       (39 B) 43414c4d 01 04 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 00
REFUSE      (43 B) 43414c4d 01 05 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 05 000005dc
SHED        (39 B) 43414c4d 01 06 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f 03
OFFER       (73 B) 43414c4d 01 07 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
                   01 01 00000000001e8480 00000000002dc6c0 0000002a 01 000a 6e6f64652d6b61742d61
```

The v2 chunk trailer's KAT (the signed source timestamp) is in
`docs/av_chunk_auth_wire.md` §5, from `kat_vectors_are_deterministic`.
