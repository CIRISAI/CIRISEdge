# `outfox-xwing-v1`: the onion packet (edge's submission for CC 5.4.6 item 3)

**Status:** edge's proposal for the CC to pin. It is implemented in
`src/onion/packet.rs`, and the tier ships dormant in edge v44. The known
answers in §8 are produced by `kat_outfox_xwing_v1` and
`kat_split_and_seed_forms_agree`; CIRISVerify is the intended carrier.

## Construction identifier

| Name | Value |
|---|---|
| Construction identifier (CC 5.1) | `onion_xwing06_hkdf_sha3_256_aes256gcm_lioness_shake256` |
| Format name, used on the rendezvous row (CC 3.1.4) | `outfox-xwing-v1` |

The identifier names the combiner, KDF, AEAD and body cipher. Changing any of
them makes a different construction, with a different identifier.

## The two binding properties of CC 5.4.6 item 3

### (a) The hop KEM is X-Wing as the draft defines it

The KEM is draft-connolly-cfrg-xwing-kem-06: ML-KEM-768 and X25519, joined by
the draft's own combiner:

```
ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")      ("\.//^\" = 5c 2e 2f 2f 5e 5c)
```

- **Implementation.** Encapsulation and seed-form decapsulation are libcrux
  0.0.10's `XWingKemDraft06`.
- **Byte layouts.** All three follow the draft-06 order.

  | Item | Layout |
  |---|---|
  | Ciphertext | `ct_M (1088) ‖ ct_X (32)` = 1120 bytes |
  | Public key | `pk_M (1184) ‖ pk_X (32)` = 1216 bytes |
  | Private key | the draft's 32-byte seed |

- **Split form.** A hop may also hold its key split into an ML-KEM-768
  `d ‖ z` seed and an X25519 scalar, which is the shape of today's transit
  custody. In that form edge decapsulates ML-KEM with ciris-crypto's RustCrypto
  `ml-kem`, runs X25519 through `x25519-dalek`, and computes the combiner above
  itself (`xwing_combiner`).
- **Cross-check.** The two forms agree byte for byte on the public key and the
  shared secret (`kat_split_and_seed_forms_agree`).
- **Not the HKDF hybrid.** This is not CIRISVerify's HKDF-SHA256-combined
  `hybrid_kex` (CIRISVerify#324). The two share a key shape but are not
  interoperable.

### (b) The body is tagging-resistant

Each hop removes one layer of **LIONESS**, a wide-block cipher over the whole
8192-byte body (§4).

- **Why this gives tag resistance.** LIONESS is a strong pseudorandom
  permutation when its stream and hash are a PRG and a PRF. Altering any input
  byte makes the hop's output pseudorandom in every position. Every later layer
  then sees random bytes.
- **Where tampering is caught.** The exit checks that the plaintext body
  begins with 16 zero bytes. A body altered anywhere on the path fails this
  check with probability `1 − 2⁻¹²⁸` and is refused as `onion_body_tampered`.
- **What the witness covers.** `tag_resistance_a_body_byte_flipped_at_hop_one_fails_at_the_exit`
  flips one bit at six positions: in L, at the L/R boundary, in R, and on the
  last byte. Each time, hop 2 cannot tell, and more than 90% of the body bytes
  hop 2 holds differ from the untampered run. The exit refuses every time.
- **Why the alternatives fail.** Per-hop XOR keystreams fail this property.
  The withdrawn draft of this format used them, and a hop-1/hop-3 pair could
  mark a packet and recognise the mark. A per-layer AEAD over the body alone
  also fails it: hop 2 would drop the packet, which is detectable, but it
  cannot be composed with the reply-blob construction of item 6.

### Header tagging

The CC text addresses the body only. The header is also covered here:

- **Chained commitments.** Every routing block commits to the slot its
  successor will receive (§3). A hop refuses to forward a packet whose next
  slot does not match (`onion_next_slot_mismatch`).
- **Where tampering is caught.** If a hop alters any later hop's header
  material, the next honest hop catches it. This happens before a colluding
  later hop can see the mark.
- **What the witness covers.** `a_later_hops_slot_altered_at_hop_one_is_refused_by_hop_two`.

## 1. Sizes

| Item | Bytes | Constant |
|---|---|---|
| X-Wing ciphertext `ct_M ‖ ct_X` | 1120 | `KEM_CT` |
| Routing block, plaintext | 48 | `BLOCK_PLAIN` |
| Routing block, sealed (AES-256-GCM, 16-byte tag) | 64 | `BLOCK` |
| Slot = ciphertext ‖ sealed block | 1184 | `SLOT` |
| Header = 6 slots | 7104 | `HEADER` |
| Body | 8192 | `BODY` |
| **Packet**, the same length at every hop | **15,296** | `PACKET` |
| Body payload capacity (8192 − 16 check − 2 length) | 8174 | `BODY_CAPACITY` |

A route is three hops. A targeted delivery is six: the sender's three plus the
receiver's three, carried in the receiver's blob (CC 5.4.6 items 4 and 6).

## 2. Routing block (48 bytes, plaintext)

| Offset | Length | Field |
|---|---|---|
| 0 | 16 | `next_dest`: the next relay's identity destination hash. All zero on a final hop. |
| 16 | 1 | `flags`: `0x01` FINAL (store the publication), `0x02` MAILBOX (rendezvous seat), `0x04` FETCH. Other bits must be zero. |
| 17 | 2 | `delay_ms`, u16 big-endian: the mixing delay the sender chose for this hop. A relay clamps it to 60 s. |
| 19 | 4 | `period`, u32 big-endian: the low 32 bits of the rendezvous period `floor(unix/3600)`. |
| 23 | 16 | `next_commit`: the first 16 bytes of `SHA3-256("ciris-onion/v1/slot-commit" ‖ successor's slot as received)`. Zero on a final hop. |
| 39 | 9 | Reserved, zero. A non-zero byte is refused as malformed. |

The block is sealed with AES-256-GCM:

- **key** `k_hdr`;
- **nonce** 12 zero bytes;
- **AAD** the hop's 1120-byte X-Wing ciphertext.

The fixed nonce is sound because `k_hdr` is unique to each encapsulation.

## 3. Key derivation (one X-Wing shared secret `ss` per hop)

Each key is `HKDF-SHA3-256(ikm = ss, salt = "" , info = CONSTRUCTION_ID ‖ label, L)`:

| Label | L | Use |
|---|---|---|
| `/hdr` | 32 | `k_hdr`, the routing block's AES-256-GCM key |
| `/stream` | 32 | `k_stream` |
| `/lioness` | 128 | `k1 ‖ k2 ‖ k3 ‖ k4`, the LIONESS round keys |

The remaining keyed values use SHA3 and SHAKE256. Every input string is ASCII
with no terminator.

| Item | Definition |
|---|---|
| Header stream (7104 bytes) | `SHAKE256("ciris-onion/v1/header-stream" ‖ k_stream)` |
| Replay tag | `SHA3-256("ciris-onion/v1/replay" ‖ ct)` |
| Slot commitment | `SHA3-256("ciris-onion/v1/slot-commit" ‖ slot)[0..16]` |
| Hop seed from custody | `HKDF-SHA3-256(root64, "", "ciris-onion-hop/v1/xwing-seed", 32)`. This is edge's custody convention, not part of the wire format. |

## 4. The body

**Plaintext layout.**

```
0^16 (check) ‖ len u16 BE ‖ payload ‖ 0-pad    (8192 bytes)
```

**LIONESS.** The body is split into L (bytes 0..32) and R (bytes 32..8192).

```
S(x)    = SHAKE256("ciris-onion/v1/lioness-stream" ‖ x)[0..8160]
H(k, R) = SHA3-256("ciris-onion/v1/lioness-hash" ‖ k ‖ R)

encrypt:  R ^= S(L ^ k1);  L ^= H(k2, R);  R ^= S(L ^ k3);  L ^= H(k4, R)
decrypt:  L ^= H(k4, R);  R ^= S(L ^ k3);  L ^= H(k2, R);  R ^= S(L ^ k1)
```

**Who encrypts and who decrypts.**

- **Sender, publication.** The sender encrypts innermost first: hop n's layer,
  then hop n−1's, and so on up to hop 1's.
- **Each hop.** Each hop decrypts its own layer.
- **Targeted delivery.** The sender layers only its own hops. Each private hop
  decrypts its layer. When the receiver fetches the body, it re-applies its
  private hops' encryption, innermost first, which removes their layers. It
  then checks the 16 zero bytes.

## 5. Header build and peel

**Build.** The header is built innermost-out over `inner`, a 6-slot header the
last hop hands on: random slots for a standalone route, or the receiver's blob
plus 3 random slots. For each hop i, from last to first:

1. `(ss, ct) = XWing.EncapsDerand(pk_i, eseed64)`. Here `eseed64` is 64 fresh
   random bytes: the ML-KEM `m` followed by the X25519 ephemeral scalar.
2. `commit = 0^16` if the hop is final, else `slot_commit(next[0..1184])`.
3. `slot_i = ct ‖ AES-256-GCM(k_hdr, 0^12, aad = ct, block_i ‖ commit)`.
4. `header_i = slot_i ‖ (next[0..5·1184] ⊕ HeaderStream_i[0..5·1184])`.
5. `next = header_i`.

**Acceptance order at a relay.** A relay accepts a packet in this order
(`src/onion/relay.rs` and `src/onion/packet.rs` `peel`). The first failing
step names the refusal.

| # | Step | Refusal |
|---|---|---|
| 1 | The link the packet arrived on is shaped. This is checked before any cryptography. | `onion_unshaped_link` |
| 2 | The length is exactly 15,296 bytes. | `onion_packet_malformed` |
| 3 | `ss = XWing.Decaps(sk, packet[0..1120])`. During one period of rotation overlap, the previous key is tried if the current one fails. | — |
| 4 | Derive the keys. Open the block with GCM, using AAD = ct. | `onion_hdr_open_failed` |
| 5 | Check the block's shape: reserved bytes zero and flags known. | `onion_packet_malformed` |
| 6 | Build the next packet: `(packet[1184..7104] ‖ 0^1184) ⊕ HeaderStream`, then the body with this hop's LIONESS layer removed. | — |
| 7 | Non-final hop: `slot_commit(next[0..1184]) == next_commit`. | `onion_next_slot_mismatch` |
| 8 | FINAL hop: the body's first 16 bytes are zero. | `onion_body_tampered` |
| 9 | `period` is this period or the last (low 32 bits). | `onion_period_mismatch` |
| 10 | The replay tag is unseen within two periods. | `onion_replay` |
| 11 | Forward only: fewer than 256 packets are held. | `onion_hold_deferred` |

After step 11:

- **Forward.** The relay holds the packet for `min(delay_ms, 60 s)`, then
  queues it on the shaped link to `next_dest`. If no such link exists, it
  refuses with `onion_next_hop_unroutable`.
- **FINAL hop.** The relay stores the payload. In v44 the payload waits for
  persist's door (`onion_exit_pending_persist`).
- **MAILBOX hop.** The relay keeps the body for the receiver to fetch.

## 6. Carriage on a link

**Framing.** An onion packet travels as the Channel frame `CONP` ‖ packet. On a
shaped link that frame is fragmented into the link's constant-size `SHPF`
frames, so it looks like any other real frame (CC 5.4.6 item 5).

**Where it is refused.** A `CONP` frame is refused in three cases:

- it arrives on an unshaped link;
- it reaches a node that is not relaying, either because the tier is not active
  there or because the device policy says no;
- it reaches a node without a valid hop key.

## 7. Refusal tokens

**Registered by the CC:**

- `onion_tier_unavailable_floor`
- `onion_tier_unavailable_liveness`

**Edge's own** (`src/onion/tokens.rs`):

| Token | Meaning |
|---|---|
| `onion_tier_not_opted_in` | The tier is not in use because the person has not opted in. |
| `onion_relay_dormant` | The node is not relaying because the tier is not active here. |
| `onion_relay_device_policy` | The device policy rules out relaying (CC 5.4.6 item 1; a phone not on Wi-Fi and charging). |
| `onion_relay_opted_out` | The person has opted out of relaying. Honoured for non-seat nodes only. |
| `onion_no_valid_hop_key` | The node has no valid hop key. |
| `onion_unshaped_link` | Acceptance step 1: the frame arrived on an unshaped link. |
| `onion_packet_malformed` | Acceptance steps 2 and 5: wrong length, or a malformed block. |
| `onion_hdr_open_failed` | Acceptance step 4: the routing block did not open. |
| `onion_next_slot_mismatch` | Acceptance step 7: the successor's slot does not match the commitment. |
| `onion_body_tampered` | Acceptance step 8: the exit's zero check failed. |
| `onion_period_mismatch` | Acceptance step 9: the period is neither this one nor the last. |
| `onion_replay` | Acceptance step 10: the replay tag was already seen. |
| `onion_hold_deferred` | Acceptance step 11: the relay already holds 256 packets. |
| `onion_next_hop_unroutable` | No shaped link to the next hop. |
| `onion_exit_pending_persist` | A FINAL or MAILBOX packet waits for persist's door (v44). |
| `onion_first_hop_unshaped` | Sender: the link to the first hop is not shaped. |
| `onion_route_failed` | Sender: a route could not be built. |
| `onion_route_length` | Build: a route of the wrong length. |
| `onion_body_too_large` | Build: the payload exceeds the body capacity. |
| `onion_anonymous_no_media` | Anonymous mode is row-plane only (CC 5.4.3 rc16): no calls or streams while the tier is active. |

## 8. Known answers

The known answers come from the fixed seed `KAT_SEED = "CIRIS outfox-xwing-v1 KAT 2026-11-01"`.

**Hop keys.** Hop n's X-Wing seed is `SHA3-256(KAT_SEED ‖ "/hop" ‖ n)`, for
n = 1, 2, 3.

**Entropy.** Randomness is read in order from
`SHAKE256(KAT_SEED ‖ label)`:

| Label | Draws |
|---|---|
| `/encaps` | One 64-byte encapsulation seed to hop 1 |
| `/packet` | First the 6 random inner slots, then each hop's 64-byte `eseed`, innermost hop first |

**Route and payload.**

| Field | Value |
|---|---|
| `next_dest` | hop 1 → `22…22`, hop 2 → `33…33`, hop 3 → zero with FINAL |
| `delay_ms` | 2000 |
| `period` | 496000 |
| Payload | `"CIRIS onion KAT payload"` |

**Expected values.**

| name | SHA3-256 / value (hex) |
|---|---|
| `hop1_pk_sha3` | `ea7ad961f646e19457f1d666f48ea2b7e244090a13745129743b1cc337a8d4a8` |
| `encaps_ss` | `ffde16940725ed13e97b2cf083082d66e5c04e55977cfb570093df0ab17002fd` |
| `encaps_ct_sha3` | `e8f9c18b704a22bf63686b93ae1d5f5feea82602407eecc6ead04af98c53f902` |
| `layer_keys_sha3` | `18313dcac98e9196e2f04b0fd2898586f2a270c5da220394d2eacac92a766ca2` |
| `packet_hop1_sha3` | `e9faf4a79667150531566b987426f0c8807c0d798851a79135ca0a603aa25bd0` |
| `packet_hop2_sha3` | `c3e8e62224e83975787f33a7ddf197507fe63a626936edf8c5162948fce235ef` |
| `packet_hop3_sha3` | `51b0365613b76361d936751fabc0eea7e3f0449e879caeafeccfcc221faa4ad5` |
| `exit_body_sha3` | `13e3ef27d46cab4f8cde8cfce6b423447408fd94e0bdffdee4fcee11f87d8386` |
| `replay_tag_hop1` | `d4005ef344b5bacd6c0a0dfa36f869cbd9f6b4a50fa2a3811e351be1ae7ce005` |

`encaps_ss` is the raw X-Wing shared secret; `layer_keys_sha3` is SHA3-256 of `k_hdr ‖ k_stream ‖ k1..k4`; `packet_hopN_sha3` is SHA3-256 of the 15,296 bytes hop N receives; `exit_body_sha3` is SHA3-256 of the plaintext body at the exit; `replay_tag_hop1` is hop 1's replay tag. The cross-form check (`kat_split_and_seed_forms_agree`) additionally asserts, for four seeds, that libcrux's seed-form X-Wing and the split form (RustCrypto ML-KEM-768 + x25519-dalek + this combiner) yield identical public keys and shared secrets.

## 9. Open items for the CC and Verify

- **Pinning.** The CC pins §1–§5 and §7, or answers with changes.
- **Carrying the KATs.** CIRISVerify carries the §8 vectors. It may also move
  the construction into `ciris-crypto` (the crypto-DRY rule); edge would then
  call it.
- **Known gaps in v44.**
  - Mailbox and fetch framing beyond the FETCH flag is not specified
    (FSD/ONION_ROUTING.md §8).
  - Persist has no `onion_hop_pubkeys` reader before 61.0.1 (CIRISPersist#1181).
  - Persist has no `pseudonym` or rendezvous gate (CIRISPersist#1149).
