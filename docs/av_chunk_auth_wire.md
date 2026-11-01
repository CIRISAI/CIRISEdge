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
encoded by `unsigned_body` (`:465`) and `to_bytes` (`:533`), and parsed by
`from_bytes` (`:544`).

| # | Member | Encoding | Bytes |
|---|---|---|---|
| 1 | version | `u8`, must be `0x01` (`BINDING_VERSION`, `:124`) | 1 |
| 2 | room | `u16` BE length, then UTF-8 (the community key id) | 2 + n |
| 3 | publisher | `u16` BE length, then UTF-8 (the publisher's federation key id) | 2 + n |
| 4 | join_nonce | raw | 32 |
| 5 | stream_id | raw; must equal `call_stream_id(room, publisher, join_nonce)` | 32 |
| 6 | epoch | `u64` BE (the room's MLS epoch) | 8 |
| 7 | chunk_key | raw Ed25519 public key | 32 |
| 8 | sig_ed25519 | `u16` BE length (must be 64), then the signature | 2 + 64 |
| 9 | sig_ml_dsa_65 | `u16` BE length (non-zero), then the signature (3309 for ML-DSA-65) | 2 + 3309 |

Members 1–7 are the **unsigned body**; members 8–9 follow it. The string
writers are `put_str` (`:423`) and `put_bytes` (`:429`).

Parse rules (`from_bytes`, `:544`):
- the whole encoding is at most 8192 bytes (`MAX_BINDING_LEN`, `:133`);
- room and publisher lengths must be 1..=1024 (`MAX_ID_LEN`, `:139`; `Reader::string`, `:454`) and valid UTF-8;
- trailing bytes are refused.

`stream_id` is derived at `transport/av_call.rs:669`:
`SHA-256("ciris-edge:call-stream:v2" ‖ utf8(room) ‖ utf8(publisher) ‖ join_nonce)`,
with no length prefixes. Re-deriving it is how a receiver knows the stream is
the publisher's.

The size is 3486 + len(room) + len(publisher) bytes. The KAT binding below is
3504 bytes.

### 1.2 Signing bytes and the hybrid signature

```
signed_bytes = "ciris-edge:av-stream-key:v1"      (27 bytes ASCII, BINDING_DOMAIN :121)
             ‖ unsigned_body                       (members 1–7 exactly as encoded above)
```

`signed_bytes` is at `:480`. The signature is made by `StreamKeyBinding::sign`
(`:492`) through `identity::sign_bound_hybrid` (`identity.rs:464`):

- `sig_ed25519 = Ed25519.sign(fed_ed25519_key, signed_bytes)`
- `sig_ml_dsa_65 = ML-DSA-65.sign(fed_ml_dsa_key, signed_bytes ‖ sig_ed25519)`

So ML-DSA covers the Ed25519 signature (the CIRIS bound-hybrid form, AV-33).
Both halves are carried raw: the base64 that `sign_bound_hybrid` returns is
decoded before encoding. The signing key is the publisher's federation key
(`LocalSigner` whose `key_id` is the publisher). `Call::join` refuses a signer
whose key id is not the node's own (`transport/av_call.rs:1178`).

Verification (`verify_signature`, `:646`) re-encodes both halves as base64
and calls persist's `verify_hybrid_via_directory` under `HybridPolicy::Strict`.
Only `VerifyOutcome::HybridVerified` passes (`:683`).

The keyring's ML-DSA-65 signs deterministically (the KAT signs twice and
compares). A verifier should still check ML-DSA by verification, never by
byte equality, because FIPS 204 also permits hedged signing.

### 1.3 Receiver acceptance order

`ChunkAuth::accept_binding` (`:951`) does these steps in order. Cheap checks
come before the directory lookup.

1. **Parse.** On failure: `av_binding_malformed`.
2. **Already seen.** If the binding id (§1.4) is in the 128-entry seen ring
   (`SEEN_IDS`, `:144`), return `Known` with no re-verification and no
   re-install.
3. **Check the shape** (`check_shape`, `:629`):
   - the room equals the call's room, else `av_binding_other_room`;
   - the stream id re-derives from the publisher and nonce, else `av_binding_stream_not_derived`;
   - the publisher is in the room's MLS group (`CohortGroup::member_key_ids`, read by the caller at `transport/av_call.rs:2120`), else `av_binding_publisher_not_member`.
4. **Verify the hybrid signature** against the directory. On failure: `av_binding_signature_unverified`.
5. **Install** (`install`, `:1002`):
   - an epoch older than the second-newest held for that stream is refused (`av_binding_stale_epoch`);
   - each stream keeps only its two newest epochs;
   - each publisher keeps its four newest streams (`MAX_STREAMS_PER_PUBLISHER`, `:141`).

Refusals are not cached. The cause may pass (a member list that lags, a
directory still learning the key), and the checks before step 4 cost nothing.

### 1.4 Part framing

A binding is larger than one Channel message, so it travels as parts
(`parts`, `:594`).

```
part = "CSKB"                    4  BINDING_PART_MAGIC (:128)
     ‖ 0x01                      1  BINDING_PART_VERSION (:129)
     ‖ id                        8  SHA-256(binding encoding)[0..8]  (id_of :583)
     ‖ index                     1  u8, 0-based
     ‖ count                     1  u8, 1..=64 (MAX_PARTS :135)
     ‖ payload                   ≥1 the encoding cut in order
```

The part header is 15 bytes (`PART_HEADER_LEN`, `:130`).

**Sizing per link.** Payload = the link's Channel message limit − 15. The
payload must be at least 64, or nothing is sent. The limit comes from:
- `AvLinkSender::message_limit`, which the Reticulum sender implements (`transport/realtime_av_runtime.rs:1530`);
- otherwise 1024 (`FALLBACK_PART_LIMIT`, `:150`);
- or, on a fresh leg, the dialled link's `channel_limit` (`transport/av_call.rs:1891`).

Parts of one binding are cut per link, so their sizes differ between links.
The id does not.

**Reassembly** (`BindingAssembler::push`, `:770`) is per link:
- a frame is a part iff it is at least 15 bytes and starts `"CSKB" 0x01`;
- at most 4 bindings are in flight per link (`MAX_PENDING`, `:137`), and the oldest is dropped when a fifth starts;
- each binding reassembles to at most 8192 bytes;
- the count must be the same in every part of an id;
- a duplicate index is ignored;
- a completed reassembly must hash to its id;
- every failure is `av_binding_part_malformed`.

Parts may arrive in any order and interleaved with other bindings' parts.

**Telling parts from chunks.** A chunk's first 32 bytes are its stream id. A
publisher never mints a stream id that begins `"CSKB" 0x01`: `start_stream`
draws the join nonce again (`transport/av_call.rs:1606`;
`collides_with_binding_part`, `:156`).

A part takes no A/V outer seal and no hop `link_seq`. The E1 link seal still
covers it, like every frame on the link. A part's drop report stays pending
for the next chunk (`HopGap`, `transport/av_call.rs:2016`).

### 1.5 When a publisher sends its binding

These are all in `transport/av_call.rs`.

- **On every new leg** (`dial_leg`, `:1844`):
  1. the link's transit KEX;
  2. the stream hello `"CHLO" ‖ 0x01 ‖ stream_id[32]` (`encode_hello`, `:686`; 37 bytes, unsigned);
  3. under the publisher lock, the current binding's parts and, if this node relays, every binding it holds whose publisher is not the dialled member (`:1888`);
  4. only then is the leg added to the fan-out roster, so no chunk precedes the binding.

  Sends wait out backpressure until the hello budget expires (`send_patiently`, `:1940`).
- **At an epoch roll** (`roll_if_moved`, `:1671`). The order is fixed:
  1. derive the new DEK (`:1684`);
  2. mint the new chunk key and its binding (`mint_own_key`, `:1692`; a failure leaves the stream un-rolled);
  3. roll the publisher (`:1701`);
  4. swap in the new key (`:1705`);
  5. remove departed members' legs;
  6. send the new binding on every remaining leg (`send_control_report`, `:1724`).

  All of this happens under the publisher lock, which `publish` must also
  take to seal and sign (`:1375`). So the new binding precedes the new
  epoch's first chunk on every leg. Control sends retry backpressure 20 × 10 ms
  per part (`transport/realtime_av_dispatcher.rs:754`).
- **Every 10 s** (`BINDING_REANNOUNCE`, `av_chunk_auth.rs:147`): the current
  binding is re-sent on every leg. This runs every 40 ticks of the 250 ms
  `WATCH_TICK` (`reannounce`, `:2168`; `reannounce_ticks`, `:2237`). It
  replaces a binding lost to an inbound-queue overflow.

### 1.6 How relays forward bindings

A node with `CallOptions::relay` (`take_binding`, `transport/av_call.rs:2120`):
- forwards a completed binding, whether `Installed` or `Known`, to every
  other leg, but only when the binding's publisher is the peer of the link it
  arrived on, i.e. heard first-hand (`:2152`). It is never sent back to that
  peer. This passes the publisher's periodic re-send along and cannot loop;
- sends every binding it holds on each leg it dials (§1.5);
- verifies each binding (§1.3) before forwarding it.

## 2. The 64-byte trailer

### 2.1 What it signs

`chunk_sig_message` (`av_chunk_auth.rs:162`):

```
msg = "ciris-edge:av-chunk-sig:v1"   26 bytes ASCII (CHUNK_SIG_DOMAIN :118)
    ‖ stream_id                      32
    ‖ u64_be(epoch)                  8
    ‖ u64_be(chunk_seq)              8
    ‖ codec_id                       1
    ‖ spatial ‖ temporal ‖ quality   3
    ‖ inner_aead                     the inner AES-256-GCM ciphertext INCLUDING its 16-byte tag
trailer = Ed25519.sign(chunk_key[stream, epoch], msg)          64 bytes (CHUNK_SIG_LEN :115)
```

The signer is `ChunkSigner::sign` (`:342`). It refuses a chunk of another
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
last 64 bytes. A relay forwards that unit byte for byte, re-sealing only the
outer layer.

### 2.3 Verification order

**Relay** (no DEK needed for any step; `pump`, `transport/av_call.rs:1997`):
1. If the frame is a binding part, reassemble it (§1.4) and stop.
2. Parse `SealedAvChunk`; on failure count `av_call_frame_unopened`.
3. Open the outer seal at the hop counter (`open_hop_outer`, `realtime_av_dispatcher.rs:252`); on failure count `av_call_frame_unopened`.
4. `ChunkAuth::check` (`av_chunk_auth.rs:1082`, called at `av_call.rs:2055`):
   1. look up the bound key for `(stream_id, epoch)`, else `av_chunk_unbound`;
   2. take the last 64 bytes as the trailer, else `av_chunk_trailer_missing`;
   3. Ed25519 `verify_strict(key, msg, trailer)` with `msg` built from the header and the remaining bytes, else `av_chunk_trailer_invalid`.
5. Forward only if this node relays, the link's hello named this stream, and
   the verified publisher is the link's peer (`:2079`). The forwarded unit
   still carries the trailer.

**Receiver**: steps 1–4 as above, then:

5. Look up the DEK for `(stream, epoch)`; on failure `av_call_frame_no_key`.
6. Open the inner seal on `inner_aead` (the trailer removed); on failure `av_call_frame_unopened`.
7. Pass it to the reorder window. `ReceivedFrame.publisher` is the binding's
   publisher, never the hello.

No step reads persist, and no step runs a hybrid verification.

## 3. Per-frame budget

From `Call::chunk_plaintext_budget` (`transport/av_call.rs:1315`):

```
channel_limit(link) = min(link_mdu − 6, 65535) − 25        (reticulum.rs:430; 6 = Channel envelope,
                                                            25 = E1 seal header 9 + tag 16, link_seal.rs:114)
AV_CHUNK_WIRE_OVERHEAD = 48 + 4 + 16 + 16 = 84            (realtime_av.rs:824: header, codec/layer, inner tag, outer tag)
max plaintext before   = channel_limit − 84
max plaintext after    = channel_limit − 84 − 64 = channel_limit − 148
```

`link_mdu` is leviculum's `floor((mtu − 1 − 19 − 48) / 16) × 16 − 1`.

| Link MTU | link MDU | Channel limit | Max plaintext before | after | Binding parts (KAT size) |
|---|---|---|---|---|---|
| 500 (base) | 431 | 400 | 316 | 252 | 10 × ≤400 B |
| 1400 (punched direct, `direct_path.rs:469`) | 1327 | 1296 | 1212 | 1148 | 3 × ≤1296 B |

The call refuses a frame over the budget before sealing it. A smaller MTU
shrinks every number in the row.

## 4. Refusal tokens

There is one enum, `AvAuthRefusal` (`av_chunk_auth.rs:194`), whose `as_str`
(`:235`) gives the spellings. `refusal_tokens_are_stable_and_distinct`
(`av_chunk_auth/tests.rs:563`) checks them. A relay and a receiver run the
same code, so the tokens are identical on both. Each refusal:
- is logged with `reason = <token>`;
- increments the `av_plane` counter of the same name;
- increments one aggregate counter (`observability.rs:927–936`): `av_call_frame_forged`, `av_call_frame_unbound` or `av_call_binding_refused`.

| Token | Meaning | Aggregate counter |
|---|---|---|
| `av_binding_part_malformed` | bad part header, inconsistent count, over the bound, hash ≠ id | `av_call_binding_refused` |
| `av_binding_malformed` | reassembled binding does not parse | `av_call_binding_refused` |
| `av_binding_other_room` | binding for another room | `av_call_binding_refused` |
| `av_binding_publisher_not_member` | publisher not in the room's MLS group | `av_call_binding_refused` |
| `av_binding_stream_not_derived` | stream id ≠ `call_stream_id(room, publisher, nonce)` | `av_call_binding_refused` |
| `av_binding_signature_unverified` | hybrid signature not `HybridVerified` | `av_call_binding_refused` |
| `av_binding_stale_epoch` | epoch older than the two held for the stream | `av_call_binding_refused` |
| `av_chunk_unbound` | no verified binding for the chunk's `(stream, epoch)`; this covers an unknown stream, and an epoch whose key was dropped two rolls ago | `av_call_frame_unbound` |
| `av_chunk_trailer_missing` | inner unit shorter than 64 bytes | `av_call_frame_forged` |
| `av_chunk_trailer_invalid` | trailer does not verify under the bound key | `av_call_frame_forged` |

A successfully installed binding counts `av_call_binding_installed`.

## 5. KAT vectors

These come from `kat_vectors_are_deterministic` (`av_chunk_auth/tests.rs:467`).
It asserts the constants in `mod kat` (`:435`) and prints them with
`--nocapture`.

**Inputs**
- publisher key id `node-kat-a`: Ed25519 seed `01`×32, ML-DSA-65 seed `54`×32 (ciris-keyring software signers);
- room `room-kat`; join nonce `07`×32; epoch 5;
- chunk key: Ed25519 seed `0c`×32;
- DEK `42`×32;
- chunk_seq 0, codec `ff`, layer (0,0,0), plaintext ASCII `kat-chunk-0`;
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
CHUNK_SIG_MESSAGE    63697269732d656467653a61762d6368756e6b2d7369673a7631   "ciris-edge:av-chunk-sig:v1"
                     c7adfc999afbc7643b24eab3b57ca66540315d345e52bbb33cfa1d5dfb9c18d8   stream_id
                     0000000000000005 0000000000000000                        epoch, chunk_seq
                     ff 000000                                                codec, layer
                     b3b432abd9ea536a45a933956e21b34dc01e4571e5196d0aa08396   inner_aead
TRAILER              3e88ffce0fa074ab1b2b88fb04095d427fcb46d8f1f49dac851f92761e861a16
                     61865b999ccd22fc4608da5a20e51ec900f13f8ef1b5ba7ce9d8dc1b3261f807
VERDICT              verified, publisher node-kat-a
FORGED_TRAILER       14627f17213c016c8efaaa43ef4fe52d30f0ff97d3ac6943359132d68e4a46a6
                     3950bc46b98d2f9c4044b204997bfa6f41db9ae624d3ebde874d0845c0f00c0c
VERDICT (forged)     av_chunk_trailer_invalid
VERDICT (inner unit truncated to 20 bytes)   av_chunk_trailer_missing
```

The full 3309-byte ML-DSA-65 signature is not printed. It is fixed by the
inputs; the hash pins it.

## 6. Compatibility

This is enforced at once:
- a peer without this change sends no bindings, so its chunks are refused as `av_chunk_unbound`;
- that peer cannot open this node's chunks, because the trailer breaks its inner AEAD;
- the per-frame plaintext budget drops by 64 bytes.
