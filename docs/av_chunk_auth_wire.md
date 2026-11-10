# A/V chunk source authentication — wire layout

Source for the CC 5.3.3.2.3 draft. Everything here is read from the code at
this commit; `file:line` points at it. "Binding" means a
`StreamKeyBinding`; "trailer" means the 64-byte chunk signature. Paths are
under `src/` unless stated.

Integer encodings are big-endian throughout. There is no CBOR and no JSON:
every structure below is a fixed concatenation.

## 1. StreamKeyBinding

### 1.1 Members and encoding

A binding states that one Ed25519 public key signs one stream's chunks in one
epoch. Defined at `transport/av_chunk_auth.rs` (struct `StreamKeyBinding`);
encoded by `unsigned_body` (`:501`) and `to_bytes` (`:569`), and parsed by
`from_bytes` (`:580`).

| # | Member | Encoding | Bytes |
|---|---|---|---|
| 1 | version | `u8`: `0x01` (`BINDING_VERSION`), or `0x02` for a v2 binding (§1.8) | 1 |
| 2 | room | `u16` BE length, then UTF-8 (the community key id) | 2 + n |
| 3 | publisher | `u16` BE length, then UTF-8 (the publisher's federation key id) | 2 + n |
| 4 | join_nonce | raw | 32 |
| 5 | stream_id | raw; must equal `call_stream_id(room, publisher, join_nonce)` | 32 |
| 6 | epoch | `u64` BE (the room's MLS epoch) | 8 |
| 7 | chunk_key | raw Ed25519 public key | 32 |
| 8 | sig_ed25519 | `u16` BE length (must be 64), then the signature | 2 + 64 |
| 9 | sig_ml_dsa_65 | `u16` BE length (non-zero), then the signature (3309 for ML-DSA-65) | 2 + 3309 |

Members 1–7 are the **unsigned body**; members 8–9 follow it. The string
writers are `put_str` (`:459`) and `put_bytes` (`:465`).

Parse rules (`from_bytes`, `:580`):
- the whole encoding is at most 8192 bytes (`MAX_BINDING_LEN`, `:144`);
- room and publisher lengths must be 1..=1024 (`MAX_ID_LEN`, `:150`; `Reader::string`, `:490`) and valid UTF-8;
- trailing bytes are refused.

`stream_id` is derived at `transport/av_call.rs:730`:
`SHA-256("ciris-edge:call-stream:v2" ‖ utf8(room) ‖ utf8(publisher) ‖ join_nonce)`,
with no length prefixes. Re-deriving it is how a receiver knows the stream is
the publisher's.

The size is 3486 + len(room) + len(publisher) bytes. The KAT binding below is
3504 bytes.

### 1.2 Signing bytes and the hybrid signature

```
signed_bytes = "ciris-edge:av-stream-key:v1"      (27 bytes ASCII, BINDING_DOMAIN :119)
             ‖ unsigned_body                       (members 1–7 exactly as encoded above)
```

`signed_bytes` is at `:516`. The signature is made by `StreamKeyBinding::sign`
(`:528`) through `identity::sign_bound_hybrid` (`identity.rs:464`):

- `sig_ed25519 = Ed25519.sign(fed_ed25519_key, signed_bytes)`
- `sig_ml_dsa_65 = ML-DSA-65.sign(fed_ml_dsa_key, signed_bytes ‖ sig_ed25519)`

So ML-DSA covers the Ed25519 signature (the CIRIS bound-hybrid form, AV-33).
Both halves are carried raw: the base64 that `sign_bound_hybrid` returns is
decoded before encoding. The signing key is the publisher's federation key
(`LocalSigner` whose `key_id` is the publisher). `Call::join` refuses a signer
whose key id is not the node's own (`transport/av_call.rs:1269`).

Verification (`verify_signature`, `:683`) re-encodes both halves as base64
and calls persist's `verify_hybrid_via_directory` under `HybridPolicy::Strict`.
Only `VerifyOutcome::HybridVerified` passes (`:740`).

The keyring's ML-DSA-65 signs deterministically (the KAT signs twice and
compares). A verifier should still check ML-DSA by verification, never by
byte equality, because FIPS 204 also permits hedged signing.

### 1.3 Receiver acceptance order

`ChunkAuth::accept_binding` (`:988`) does these steps in order. Cheap checks
come before the directory lookup.

1. **Parse.** On failure: `av_binding_malformed`.
2. **Already seen.** If the binding id (§1.4) is in the 128-entry seen ring
   (`SEEN_IDS`, `:155`), return `Known` with no re-verification and no
   re-install.
3. **Check the shape** (`check_shape`, `:666`):
   - the room equals the call's room, else `av_binding_other_room`;
   - the stream id re-derives from the publisher and nonce, else `av_binding_stream_not_derived`;
   - the publisher is in the room's MLS group (`CohortGroup::member_key_ids`, read by the caller at `transport/av_call.rs:2661`), else `av_binding_publisher_not_member`.
4. **Verify the hybrid signature** against the directory. On failure: `av_binding_signature_unverified`.
5. **Install** (`install`, `:1039`):
   - an epoch older than the second-newest held for that stream is refused (`av_binding_stale_epoch`);
   - each stream keeps only its two newest epochs;
   - each publisher keeps its four newest streams (`MAX_STREAMS_PER_PUBLISHER`, `:152`).

Refusals are not cached. The cause may pass (a member list that lags, a
directory still learning the key), and the checks before step 4 cost nothing.

### 1.4 Part framing

A binding is larger than one Channel message, so it travels as parts
(`parts`, `:631`).

```
part = "CSKB"                    4  BINDING_PART_MAGIC (:126)
     ‖ 0x01                      1  BINDING_PART_VERSION (:127)
     ‖ id                        8  SHA-256(binding encoding)[0..8]  (id_of :581)
     ‖ index                     1  u8, 0-based
     ‖ count                     1  u8, 1..=64 (MAX_PARTS :133)
     ‖ payload                   ≥1 the encoding cut in order
```

The part header is 15 bytes (`PART_HEADER_LEN`, `:141`).

**Sizing per link.** Payload = the link's Channel message limit − 15. The
payload must be at least 64, or nothing is sent. The limit comes from:
- `AvLinkSender::message_limit`, which the Reticulum sender implements (`transport/realtime_av_runtime.rs:1587`);
- otherwise 1024 (`FALLBACK_PART_LIMIT`, `:161`);
- or, on a fresh leg, the dialled link's `channel_limit` (`transport/av_call.rs:2122`).

Parts of one binding are cut per link, so their sizes differ between links.
The id does not.

**Reassembly** (`BindingAssembler::push`, `:807`) is per link:
- a frame is a part iff it is at least 15 bytes and starts `"CSKB" 0x01`;
- at most 4 bindings are in flight per link (`MAX_PENDING`, `:148`), and the oldest is dropped when a fifth starts;
- each binding reassembles to at most 8192 bytes;
- the count must be the same in every part of an id;
- a duplicate index is ignored;
- a completed reassembly must hash to its id;
- every failure is `av_binding_part_malformed`.

Parts may arrive in any order and interleaved with other bindings' parts.

**Telling parts from chunks.** A chunk's first 32 bytes are its stream id. A
publisher never mints a stream id that begins `"CSKB" 0x01`: `start_stream`
draws the join nonce again (`transport/av_call.rs:1834`;
`collides_with_binding_part`, `:167`).

A part takes no A/V outer seal and no hop `link_seq`. The E1 link seal still
covers it, like every frame on the link. A part's drop report stays pending
for the next chunk (`HopGap`, `transport/av_call.rs:2519`).

### 1.5 When a publisher sends its binding

These are all in `transport/av_call.rs`.

- **On every new leg** (`dial_leg`, `:2076`):
  1. the link's transit KEX;
  2. the stream hello `"CHLO" ‖ 0x01 ‖ stream_id[32]` (`encode_hello`, `:747`; 37 bytes, unsigned);
  3. under the publisher lock, the current binding's parts and, if this node relays, every binding it holds whose publisher is not the dialled member (`:2122`);
  4. only then is the leg added to the fan-out roster, so no chunk precedes the binding.

  Sends wait out backpressure until the hello budget expires (`send_patiently`, `:2190`).
- **At an epoch roll** (`roll_if_moved`, `:1899`). The order is fixed:
  1. derive the new DEK (`:1912`);
  2. mint the new chunk key and its binding (`mint_own_key`, `:1920`; a failure leaves the stream un-rolled);
  3. roll the publisher (`:1929`);
  4. swap in the new key (`:1933`);
  5. remove departed members' legs;
  6. send the new binding on every remaining leg (`send_control_report`, `:1952`).

  All of this happens under the publisher lock, which `publish` must also
  take to seal and sign (`:1559`). So the new binding precedes the new
  epoch's first chunk on every leg. Control sends retry backpressure 20 × 10 ms
  per part (`transport/realtime_av_dispatcher.rs:804`).
- **Settling after a burst.** A binding is about ten Channel messages on a
  base-MTU link, and it fills the link's Channel window just ahead of the
  next chunk. Chunks are sent without queueing and dropped when the link
  reports congestion (#591). So a leg that has just carried a binding
  SETTLES for 150 ms (`CONTROL_SETTLE`, `transport/realtime_av_dispatcher.rs:529`):
  - a congested chunk send on it is retried every 5 ms instead of dropped;
  - after the window, a congested send is dropped at once as before.

  `send_control_report` sets this on every leg it sends to. `dial_leg` sets it
  on a fresh leg (`settle`, `transport/realtime_av_dispatcher.rs:881`, called
  at `transport/av_call.rs:2157`).
- **Every 10 s** (`BINDING_REANNOUNCE`, `av_chunk_auth.rs:158`): the current
  binding is re-sent on every leg. This runs every 40 ticks of the 250 ms
  `WATCH_TICK` (`reannounce`, `:2728`; `reannounce_ticks`, `:2839`). It
  replaces a binding lost to an inbound-queue overflow.

### 1.6 How member relays forward bindings

"Relay" in this document always means a **member relay**: a node in the call
with `CallOptions::relay`, which is a member of the room's MLS group. A
non-member transport forwarder (a contact relaying at the Reticulum layer)
is not a relay in this sense. It never receives or verifies a binding, and
it forwards E1-sealed frames opaque. A binding names the room and the
publisher, so it is never handed to a non-member (§1.7).

A member relay (`take_binding`, `transport/av_call.rs:2660`):
- forwards a completed binding, whether `Installed` or `Known`, to every
  other leg, but only when the binding's publisher is the peer of the link it
  arrived on, i.e. heard first-hand (`:2694`). It is never sent back to that
  peer. This passes the publisher's periodic re-send along and cannot loop;
- sends every binding it holds on each leg it dials (§1.5);
- verifies each binding (§1.3) before forwarding it.

### 1.7 Bindings travel only on member-to-member A/V legs

The code sends a binding in three places, and each reaches a room member
only (`transport/av_call.rs`):

- **A leg this node dials** (`dial_leg`). `reconcile_legs` dials only the
  names in `shared.members` (`:2041`). That list is the room's MLS group:
  set at join (`admit`), and replaced at each roll from
  `room_group.member_key_ids()` (`:1906`, `:1955`). The dial goes to the
  member's own derived A/V call address (`send_address`, `:2081`), and the
  link is keyed by the E1 transit KEX to that node. The binding parts go on
  that link before it joins the fan-out roster (`:2143`).
- **The fan-out roster** (`send_control_report` at the roll, re-announce and
  member-relay forwarding). The roster's legs are added only by `dial_leg`
  (`:2143`). A departed member's leg is removed at the roll (`:1947`), before
  the new binding is sent (`:1952`).
- **Inbound links** carry no binding outward. A link from a non-member is
  closed before any frame is read (`:2224`).

Every frame on these legs is under the E1 per-link seal, so a Reticulum
transport node that forwards the link's packets sees ciphertext only.

One window remains. Between a member's removal from the MLS group and this
node's next roll (one 250 ms watch tick, or the next `publish`), the departed
member's leg is still on the roster. A re-announce in that window would send
it the current binding, which it already holds as a member of the epoch.

### 1.8 The v2 binding: the codec map, `replaces`, `end`, `final_seq` (45.1)

**Status: a CC reading (rc17) of 5.3.3.2.1–.3, pending text.** The per-class
codec map and the in-place stream replacement are not yet CC text; they
become text once this layout and its vectors exist. Class `0x04` is rc17
text.

The chunk header's `codec_id` carries the layer CLASS only (`0x01` SVC,
`0x04` temporal-layered, `0xFF` codec-opaque); the stream's binding names the
codec of each class it uses. One stream per publisher carries its audio and
video (P5): a phone's stream is `{0x04: h264, 0xFF: opus}`, an audio-only one
`{0xFF: opus}`.

A v2 binding is the v1 binding with member 1 `version = 0x02` and these
members after member 7 (`chunk_key`):

| # | Member | Encoding | Bytes |
|---|---|---|---|
| 7a | codecs | `u8 count` (0..=8), then per class, sorted by class, no class twice: `class u8 ‖ u16_be len ‖ token` (1..=32 bytes of printable ASCII) | 1 + Σ(3 + len) |
| 7b | replaces | `u8 present` (0 or 1), then, when 1, the publisher's earlier `stream_id` this one replaces in place | 1 or 33 |
| 7c | end | `u8`: 0 live; 1 left; 2 left, backgrounded | 1 |
| 7d | final_seq | only when `end` ≠ 0: `u64` BE, the last `chunk_seq` the publisher sealed in this epoch (`u64::MAX`: none) | 0 or 8 |

`count` 0 (no map) is allowed only when `replaces` or `end` is set: an end or
a replacement of a stream that declared no codecs. A v2 binding with none of
the three is malformed.

Members 1–7d are the v2 unsigned body. The signing bytes use their own
domain tag:

```
signed_bytes_v2 = "ciris-edge:av-stream-key:v2"   (27 bytes ASCII)
                ‖ unsigned_body_v2                (members 1–7d as encoded)
```

The hybrid signature is made as in §1.2 over `signed_bytes_v2`.

Registered tokens:

| Token | Class |
|---|---|
| `av1` | `0x01` (SVC) |
| `h264` | `0x04` (temporal-layered) |
| `vp8` | `0x04` |
| `vp9` | `0x04` |
| `opus` | `0xFF` (codec-opaque) |

The token table is CC's to register.

Parse rules. These are refused as `av_binding_malformed`:
- a registered token under a class that is not its own;
- a token of 0 or more than 32 bytes, or one that is not printable ASCII;
- a map with more than 8 entries, out of class order, or with a class twice;
- a `present` byte other than 0 or 1;
- an `end` byte above 2.

An **unregistered** token binds: on this receiver its class is undecodable,
so a codec registered later never takes the audio away from an older client.

Rules:
- **Chunk class.** On a stream whose v2 binding named a map, a chunk's
  `codec_id` class is checked after its signature verifies
  (`ChunkAuth::check_timed`):
  - no entry for the class: refused `av_chunk_class_unlisted`;
  - an unregistered token: dropped here, `av_chunk_class_undecodable`,
    counted `undecodable`. The binding stands and the other classes play.

  A v1-only stream is not checked. v44 sends video as `0x01` under a v1
  binding, so a v2 receiver checking it would break v44↔v45 video.
- **The map is fixed for the stream's life.** A later v2 binding for the same
  stream naming another map, in the same or any later epoch, is refused
  `av_binding_codec_changed`. Dropping or adding a class is another map.
  Changing codec is `Call::replace_stream`: a new join nonce, so a new
  stream, whose v2 binding says `replaces: <old stream>`.
- **`end` is final.** `end = 1` and `end = 2` are both final leaves.
  - Once a receiver verified either for a stream, it takes no further binding
    for that stream, `end = 0` included: `av_binding_stream_ended`, refused
    before any hybrid verification.
  - A return is a new stream. No signed binding means "backgrounded and
    still present": on background a client leaves and reports
    `backgrounded`.
  - The ended streams are remembered apart from the bound ones (256). A
    replayed old end can neither evict a live stream nor end a new one.
- **`final_seq` closes the tail**, standing in for 5.3.3.1's terminator.
  - A chunk whose `chunk_seq` is above a verified `final_seq` for its
    `(stream, epoch)` is refused `av_chunk_past_end` and never played.
  - The verdict waits the longest reorder window (`END_VERDICT_AFTER` =
    `REORDER_WINDOW_MAX`, 400 ms) after the end lands, read at the next
    watch tick, because tail chunks up to `final_seq` may still be in flight
    behind it. Those still verify and play. The `AttendeeLeft` for the end
    is emitted then, not when the end lands.
  - A receiver that still has not verified up to `final_seq` by then reports
    the tail as truncated: the `truncated` counter (once per stream),
    `av_call_stream_truncated`, and the `truncated` field of
    `CallEvent::AttendeeLeft`. Chunks past `final_seq` never count.
- **`replaces` and `end` count only as signed.** A receiver learns that a new
  stream replaces an old one, or that a stream ended and why, only from these
  verified members. No unsigned control frame announces either, so a relay
  cannot take a tile down. A second stream of a publisher with no `replaces`
  (a screen share, say) stays a separate stream.
- **A binding is no presence.** An `end = 0` binding alone makes nobody an
  attendee: an `AttendeeLeft` fires only for a stream this receiver verified
  a chunk of (`ChunkAuth::heard`). Attendance otherwise comes from the
  `chat:call:v1` row (`AttendeeJoined`, `attendees()`) and live chunks.
- **v1 and v2 side by side.** A v1-only receiver refuses version 2 as
  malformed. So a publisher that names codecs, replaces a stream, or ends one
  signs a v1 binding for each epoch, and a v2 binding when it has v2 members.
  - It sends v1 on every leg.
  - It sends v2 additionally to each peer whose C3 `CAPS` carry bit 5
    (`CAP_BINDING_V2`): at the epoch roll, at the reannounce, and on that
    peer's first `CAPS`.
  - Both encodings bind the same chunk key, and a receiver holds both.
  - A member relay forwards the v1 encoding to every leg and the v2 one only
    to the legs with bit 5. So a v1 peer behind a v2 relay still binds
    (`a_v1_peer_behind_a_v2_relay_still_binds_and_hears`).
  - A v1-only peer cannot read a signed end and sees the leaver as `Lost`.
- **Delivery, not timers.** A leave closes each leg once that leg's Channel
  proved the signed end delivered. A replacement switches to the new stream
  once every leg's Channel proved the new bindings delivered. The proof is
  per message: right after the send, edge reads each leg's newest Channel
  sequence, and waits until the oldest message still unproved on that leg
  was sent after it (`AvLinkStats::delivered_through`, leviculum
  +ciris.3). Media sent meanwhile keeps the tx ring busy but does not hide
  the proof. A datagram leg's binding rides its Channel too. The ceilings
  (2 s and 3 s) are safety nets, counted `end_flush_unconfirmed` and
  `replace_switch_unconfirmed`.

KAT (`binding_v2_signed_bytes_kat`), with the inputs of §5. Vector 1 is the
map `{0x04: h264, 0xFF: opus}`, no `replaces`, `end` 0:

```
63697269732d656467653a61762d73747265616d2d6b65793a7632020008726f6f6d2d6b6174
000a6e6f64652d6b61742d610707070707070707070707070707070707070707070707070707
070707070707c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8
00000000000000050b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e3
9f2d0204000468323634ff00046f7075730000
```

Vector 2 is the same map, `replaces` stream `aa`×32, `end` 1 (left),
`final_seq` 42. Everything up to `9f2d` is identical to vector 1:

```
…9f2d0204000468323634ff00046f70757301aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaaaaaaaaaa01000000000000002a
```

Both are the v1 signed bytes of the same inputs with the v2 domain, version
`02`, and the v2 members appended; the v1 signed bytes themselves are
unchanged. The v2 signatures' KAT values are pinned at the first build of
this branch.

## 2. The 72-byte trailer (v2: source timestamp + signature)

> **CHANGED in ALM stage 2 (edge v44.0.0) — FLAG FOR THE CC (5.3.3.2.3).**
> The trailer now carries the publisher's source timestamp, and the
> signature covers it. The domain tag moved `v1` → `v2`, so a `v1` trailer
> does not verify (`av_chunk_trailer_invalid`). The timestamp is the ALM C1
> meter's latency input: a receiver measures each path's latency ABOVE the
> fastest delivery it has seen for the stream, so the clock offset between
> the hosts cancels. It is signed so a relay cannot make its path look
> faster than it is (a member relay re-seals only the outer layer and
> forwards the trailer byte for byte).

### 2.1 What it signs

`chunk_sig_message` (`av_chunk_auth.rs`):

```
msg = "ciris-edge:av-chunk-sig:v2"   26 bytes ASCII (CHUNK_SIG_DOMAIN)
    ‖ stream_id                      32
    ‖ u64_be(epoch)                  8
    ‖ u64_be(chunk_seq)              8
    ‖ codec_id                       1
    ‖ spatial ‖ temporal ‖ quality   3
    ‖ u64_be(source_ms)              8   the publisher's wall clock, UNIX ms, at seal
    ‖ inner_aead                     the inner AES-256-GCM ciphertext INCLUDING its 16-byte tag
trailer = u64_be(source_ms) ‖ Ed25519.sign(chunk_key[stream, epoch], msg)
                                     8 + 64 = 72 bytes (CHUNK_TRAILER_LEN; CHUNK_SIG_LEN = 64)
```

The signer is `ChunkSigner::sign_at` (`:373`; `sign`, `:363`, stamps now). It refuses a chunk of another
stream or epoch than the key's. The chunk key is an ephemeral Ed25519 key
generated per `(stream, epoch)`.

### 2.2 Where it sits

The chunk header is unchanged:

```
SealedAvChunk wire (realtime_av.rs:360):
  stream_id[32] ‖ epoch u64 ‖ chunk_seq u64 ‖ codec_id ‖ spatial ‖ temporal ‖ quality
  ‖ OuterAEAD_transit( inner_aead ‖ trailer )
```

The trailer is appended to the inner unit, after the inner ciphertext and
inside the outer (hop) seal. A hop opens the outer seal (`open_av_outer`,
`realtime_av.rs:852`) and gets `inner_aead ‖ trailer`. The trailer is the
last 72 bytes: the first 8 are `source_ms`, the last 64 the signature. A member relay forwards that unit byte for byte, re-sealing only
the outer layer.

### 2.3 Verification order

**Member relay** (no DEK needed for any step; `pump`, `transport/av_call.rs:2496`):
1. If the frame is a binding part, reassemble it (§1.4) and stop.
2. Parse `SealedAvChunk`; on failure count `av_call_frame_unopened`.
3. Open the outer seal at the hop counter (`open_hop_outer`, `realtime_av_dispatcher.rs:252`); on failure count `av_call_frame_unopened`.
4. `ChunkAuth::check_timed` (`av_chunk_auth.rs:1128`; `check`, `:1118`, drops the timestamp; called at `av_call.rs:2580`):
   1. look up the bound key for `(stream_id, epoch)`, else `av_chunk_unbound`;
   2. take the last 72 bytes as the trailer, else `av_chunk_trailer_missing`;
   3. split it `source_ms[8] ‖ sig[64]`; Ed25519 `verify_strict(key, msg, sig)` with `msg` built from the header, `source_ms` and the remaining bytes, else `av_chunk_trailer_invalid`.
5. Forward only if this node relays, the link's hello named this stream, and
   the verified publisher is the link's peer (`:2769`). The forwarded unit
   still carries the trailer.

**Receiver**: steps 1–4 as above, then:

5. Look up the DEK for `(stream, epoch)`; on failure `av_call_frame_no_key`.
6. Open the inner seal on `inner_aead` (the trailer removed); on failure `av_call_frame_unopened`.
7. Pass it to the reorder window. `ReceivedFrame.publisher` is the binding's
   publisher, never the hello.

No step reads persist, and no step runs a hybrid verification.

## 3. Per-frame budget

From `Call::chunk_plaintext_budget` (`transport/av_call.rs:1427`):

```
channel_limit(link) = min(link_mdu − 6, 65535) − 25        (reticulum.rs:431; 6 = Channel envelope,
                                                            25 = E1 seal header 9 + tag 16, link_seal.rs:114)
AV_CHUNK_WIRE_OVERHEAD = 48 + 4 + 16 + 16 = 84            (realtime_av.rs:824: header, codec/layer, inner tag, outer tag)
max plaintext before   = channel_limit − 84
max plaintext after    = channel_limit − 84 − 72 = channel_limit − 156     (v2 trailer)
```

`link_mdu` is leviculum's `floor((mtu − 1 − 19 − 48) / 16) × 16 − 1`.

| Link MTU | link MDU | Channel limit | Max plaintext before | after | Binding parts (KAT size) |
|---|---|---|---|---|---|
| 500 (base) | 431 | 400 | 316 | 244 | 10 × ≤400 B |
| 1400 (punched direct, `direct_path.rs:666`) | 1327 | 1296 | 1212 | 1140 | 3 × ≤1296 B |

The call refuses a frame over the budget before sealing it. A smaller MTU
shrinks every number in the row.

## 4. Refusal tokens

There is one enum, `AvAuthRefusal` (`av_chunk_auth.rs:215`), whose `as_str`
(`:256`) gives the spellings. `refusal_tokens_are_stable_and_distinct`
(`av_chunk_auth/tests.rs:570`) checks them. A relay and a receiver run the
same code, so the tokens are identical on both. A non-member transport
forwarder runs none of this and emits none of them. Each refusal:
- is logged with `reason = <token>`;
- increments the `av_plane` counter of the same name;
- increments one aggregate counter (`observability.rs:922–931`): `av_call_frame_forged`, `av_call_frame_unbound` or `av_call_binding_refused`.

| Token | Meaning | Aggregate counter |
|---|---|---|
| `av_binding_part_malformed` | bad part header, inconsistent count, over the bound, hash ≠ id | `av_call_binding_refused` |
| `av_binding_malformed` | reassembled binding does not parse | `av_call_binding_refused` |
| `av_binding_other_room` | binding for another room | `av_call_binding_refused` |
| `av_binding_publisher_not_member` | publisher not in the room's MLS group | `av_call_binding_refused` |
| `av_binding_stream_not_derived` | stream id ≠ `call_stream_id(room, publisher, nonce)` | `av_call_binding_refused` |
| `av_binding_signature_unverified` | hybrid signature not `HybridVerified` | `av_call_binding_refused` |
| `av_binding_stale_epoch` | epoch older than the two held for the stream | `av_call_binding_refused` |
| `av_binding_codec_changed` | a v2 binding naming another codec map than its stream is bound to (§1.8) | `av_call_binding_refused` |
| `av_chunk_unbound` | no verified binding for the chunk's `(stream, epoch)`; this covers an unknown stream, and an epoch whose key was dropped two rolls ago | `av_call_frame_unbound` |
| `av_chunk_trailer_missing` | inner unit shorter than 72 bytes | `av_call_frame_forged` |
| `av_chunk_trailer_invalid` | trailer does not verify under the bound key | `av_call_frame_forged` |
| `av_binding_stream_ended` | a binding for a stream whose signed end was already verified (§1.8) | `av_call_binding_refused` |
| `av_chunk_class_unlisted` | the stream's v2 codec map names no codec for the chunk's class (§1.8) | `av_call_frame_unbound` |
| `av_chunk_class_undecodable` | the map's codec for the chunk's class is unregistered here; dropped, the binding standing (§1.8) | `av_call_frame_unbound` |
| `av_chunk_past_end` | the chunk's `chunk_seq` is above its stream's signed `final_seq` (§1.8) | `av_call_frame_unbound` |

A successfully installed binding counts `av_call_binding_installed`.

## 5. KAT vectors

These come from `kat_vectors_are_deterministic` (`av_chunk_auth/tests.rs:468`).
It asserts the constants in `mod kat` (`:435`) and prints them with
`--nocapture`.

**Inputs**
- publisher key id `node-kat-a`: Ed25519 seed `01`×32, ML-DSA-65 seed `54`×32 (ciris-keyring software signers);
- room `room-kat`; join nonce `07`×32; epoch 5;
- chunk key: Ed25519 seed `0c`×32;
- DEK `42`×32;
- chunk_seq 0, codec `ff`, layer (0,0,0), plaintext ASCII `kat-chunk-0`;
- source timestamp `1790000000000` ms (`000001a0c4506c00`);
- inner seal: AES-256-GCM, with the nonce from `derive_inner_nonce` (`realtime_av.rs:491`);
- forger chunk key: Ed25519 seed `0f`×32.

**Outputs**

```
STREAM_ID            c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8
CHUNK_KEY_PUB        0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d
BINDING_SIGNED_BYTES 63697269732d656467653a61762d73747265616d2d6b65793a7631   "ciris-edge:av-stream-key:v1"
                     01                                                       version
                     0008 726f6f6d2d6b6174                                    room
                     000a 6e6f64652d6b61742d61                                publisher
                     0707070707070707070707070707070707070707070707070707070707070707   join_nonce
                     c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8   stream_id
                     0000000000000005                                         epoch
                     0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d   chunk_key
BINDING_SIG_ED25519  cfee152e5695500e16a6138276132a1e4f3684951dfbfb838e3eade0240eee6b
                     0cc7d1976935d8e4ea2bf11f3ea802cf8dfcb5cf93671856b5e1c66290130008
SHA-256(BINDING_SIG_ML_DSA_65) f4c5aec87ce37cd46f8ab10370e9c321cac1daba2ff6d89594b9e3dc0baf21d3
SHA-256(binding encoding)      558daab6b4434ced81ddd497f38ade2c2f8d109be3e22a663174bb2d156fc4f8
BINDING_ID (part id)           558daab6b4434ced
INNER_AEAD           b3b432abd9ea536a45a933956e21b34dc01e4571e5196d0aa08396
CHUNK_SIG_MESSAGE    63697269732d656467653a61762d6368756e6b2d7369673a7632   "ciris-edge:av-chunk-sig:v2"
                     c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8   stream_id
                     0000000000000005 0000000000000000                        epoch, chunk_seq
                     ff 000000                                                codec, layer
                     000001a0c4506c00                                         source_ms
                     b3b432abd9ea536a45a933956e21b34dc01e4571e5196d0aa08396   inner_aead
TRAILER              000001a0c4506c00                                         source_ms
                     cf846332f5b31fbf08b8b340514a53895515dff7d164b22be777779fe38a3f3f
                     f5d55e896cba1ae768320aa633ad0b6a09fb2c58ea19154eb1b6b6d00a14ff09
VERDICT              verified, publisher node-kat-a
FORGED_TRAILER       000001a0c4506c00
                     8d2ebc021ef41a20e0734ac2ef78e408da634e1c47a3a0c6ab55132a9e3a6b97
                     7742bdef28be63574723b24c60a061a6da2340a064a70785195d093b80454006
VERDICT (forged)     av_chunk_trailer_invalid
VERDICT (inner unit truncated to 20 bytes)   av_chunk_trailer_missing
```

The full 3309-byte ML-DSA-65 signature is not printed. It is fixed by the
inputs; the hash pins it.

## 6. The ALM control frame (C3, stage 2) — FLAG FOR THE CC

**The full specification (layout, rules, validation order, KAT) is
`docs/alm_calm_wire.md`; this section summarises it.**

A call's A/V links also carry the ALM controller's control frames
(`realtime_av_alm/controller/wire.rs`). Like a binding part, a C3 frame takes
no A/V outer seal and no hop counter; the E1 link seal covers it.

```
frame = "CALM" ‖ 0x01 ‖ kind ‖ body
CAPS 0x01: caps u32_be (bit 0 C3 v1, bit 1 timed Channel frames, bit 2 offers relay,
           bit 3 link datagrams, bit 4 layer cap on SUBSCRIBE (lever, default off),
           bit 5 parses v2 bindings)
SUBSCRIBE 0x02: stream[32] ‖ role u8 (0 primary, 1 standby) ‖ flags u8 (bit 0 forward-capable,
           bit 1 layer cap follows) [‖ mode u8 = 1 ‖ max_spatial ‖ max_temporal ‖ max_quality]
UNSUBSCRIBE 0x03: stream[32]
ADMIT 0x04: stream[32] ‖ role u8
REFUSE 0x05: stream[32] ‖ reason u8 ‖ retry_after_ms u32_be
SHED 0x06: stream[32] ‖ reason u8
OFFER 0x07: stream[32] ‖ depth u8 ‖ forwarding u8 ‖ headroom_bps u64_be
            ‖ forwarder_headroom_bps u64_be ‖ upstream_latency_ms u32_be
            ‖ n u8 ‖ n × (len u16_be ‖ utf8 key id)       (ancestry, root first, n ≤ 8)
```

- The sender of a frame is never in it: the link's attributed peer is.
- Capability gate: the RESPONDER of each A/V link sends `CAPS` first, on the
  reverse direction of the link it accepted; a dialler answers with its own
  only after hearing one. Nothing else is sent to a peer that never said
  `CAPS` (a pre-C3 peer would read a frame as a chunk that fails to open).
- A stream id beginning `"CALM" 0x01` is never minted (`collides_with_control_frame`).
- Refusal tokens: `relay_capacity`, `relay_loop`, `relay_depth_limit`,
  `relay_upstream_unhealthy`, `relay_nonmember_fanout`,
  `relay_class_refused:video`, `load_refuse:admit_closed`; shed tokens
  `relay_shed:{over_committed,upstream_lost,preempted}`, `load_shed:audio`.

## 7. Status in the format

The binding and the trailer are part of the A/V chunk format, not an
optional layer:
- every chunk carries the trailer;
- every stream's chunks are keyed by a binding;
- a chunk with neither is refused (§4).

The per-frame plaintext budget in §3 is the format's budget.
