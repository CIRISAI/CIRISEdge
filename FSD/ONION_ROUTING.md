# FSD: The Anonymous Tier — onion routing over the shaped mesh (CC 5.4.6)

**Status:** DESIGN, locked to CC 1.0-rc10 at `89e6915` (2026-10-22). Nothing here is built; the one
piece of code is the layer deal (`src/transport/onion_layers.rs`), written first because its witness is
the determinism the CC requires. Edge vendors CC rc8.1 today (its namespace matcher is persist's); the
rc10 families arrive with persist's rc10 adoption.

**Normative sources, in order:** CC 5.4.6 "The Anonymous Tier: onion routing" items 1–8; CC 3.3.6.2
"The onion hop key", "The opt-out marker", "The hop key's shape"; CC 3.1.4 "Rendezvous route leaf"
(`rendezvous:route:v1`); CC 1.13.3.1 operator guidance; CC 5.4.3 link shaping; CC 5.3.3.5 E1.
Claims: `CLM-onion-relay-mandatory`, `CLM-onion-hop-key`, `CLM-onion-route`, `CLM-onion-layer-deal`,
`CLM-rendezvous-route` (all staged on CIRISConstitution#172).

**Model:** `docs/ONION_TIER_MODEL_2026-10-22.md` (+ `docs/models/onion_tier_model.py`). **Prior art:**
Outfox (Rial, Piotrowska, Halpin, WPES 2025); KEM Sphinx (Stainton 2023); Loopix; Veilid private routes
(the receiver-published route only).

§12 states, item by item, what is normative in CC and what is edge's own.

---

## 1. What the tier is for, in one paragraph

A publisher at federation scope hands a fixed-length onion packet to the first of three relays; each
relay strips one layer, learns only the next hop, holds the packet a sender-chosen exponential delay, and
sends it on a **shaped** link, so the link looks the same whether or not an onion packet is inside it. The
third relay is a serve seat that stores the publication (or, for targeted delivery, a receiver's mailbox).
The storage node sees the last relay, never the publisher. Every node relays by default; a non-seat node
may opt out; a seat may not. Using the tier is the user's opt-in.

## 2. Parties and what each learns (the table the CC asked for)

| Party | Learns | Does not learn |
|---|---|---|
| Wire observer / GPA | that shaped links exist between relays and when they were set up (CC 5.4.3); nothing about which shaped frames carry onion packets, nor which relay pair a publication crossed, beyond link existence | publisher, receiver, timing of a publication (shaping), contents |
| Relay (hop *i*) | its predecessor's link identity and its successor's destination hash (both relays); that *a* packet passed, its size class (all packets are one length), the sender-chosen delay for its hop; for a reused rendezvous route, the count of packets per period through it (CC 5.4.6 item 8) | the publisher (unless hop 1 and the publisher's link peer are one, which the publisher's own shaped links hide), the destination (unless it is hop 3), the body, the other hops |
| Hop 1 specifically | the publisher's node as its link peer — the publisher is one of the nodes it holds a shaped link with | which of its link peers published WHEN (shaping) |
| Rendezvous / storage node (hop 3) | the rendezvous key (not the receiver), the body ciphertext, packet count/size/timing per rendezvous key, the last relay | the publisher, the receiver's identity, the plaintext (sealed to the receiver's rendezvous key) |
| Receiver | everything addressed to it; nothing about the publisher beyond what the publisher signs inside the body | — |
| Directory / peers | who carries a hop key, who opted out, the layer deal (a pure function anyone computes), rendezvous rows (fresh keys, unlinkable to receivers) | who uses the tier |
| Honest-but-curious seat | the above for its role; a seat holding a mailbox learns rendezvous-level volume | — |

The anonymity set of a publisher is the set of nodes hop 1 holds shaped links with that could have
emitted in the mixing window; at today's fleet size the model says that set is small and the client says
so (CC 5.4.6 item 8, CC 1.13.3.4).

## 3. The hop key and the opt-out marker (CC 3.3.6.2 — normative)

On the signed `transport_destination` binding, envelope-only (never a field of the typed projection, for
the same content-hash-stability reason persist v56 gave the transit pair), JCS-sorted:

```json
"onion_hop_pubkeys": {
  "ml_kem_768_base64": "<base64 of exactly 1184 bytes>",
  "x25519_base64":     "<base64 of exactly 32 bytes>"
},
"onion_relay": { "opt_out": true }
```

- The hop key is an X-Wing public key: the ML-KEM-768 encapsulation key and the X25519 public key. Four
  properties as the transit pair: attester = the identity; hybrid-signed with the row; rotatable by
  `supersedes`; replicated inside the occurrence envelope. In-row separation at admission (persist):
  distinct from both halves of `transit_kex_pubkeys`, the transport x25519/ed25519 and the signer's keys;
  refusals `onion_hop_x25519_reuse`, `onion_hop_ml_kem_768_reuse`; a wrong-length half is malformed under
  the transit pair's rule (persist's token; edge emits none). Cross-row at use (edge): a hop key equal to
  any key on the identity's current occurrence ⇒ no valid hop key.
- The marker is absent by default. Opting out = the marker **and** the hop key withdrawn on the same
  superseding row. A seat with the marker: `seat_opted_out`; a seat without a valid hop key:
  `seat_without_hop_key` (both are conformance names, surfaced by the register; edge counts them under
  `onion_relay_seat_violation`). A node with neither key nor marker is not yet capable and is not placed.
- **Edge producer** (`self_route`, the row this node signs about itself): emits the hop key whenever
  `onion_relay` is on (default on); on `off`, the next row carries the marker and no hop key. The hop key
  is a static pair in the node's custody beside the transit pair (`transit_kex_custody`'s twin
  `onion_hop_custody`), rotated on the global clock (§9) never on group events.
- **Persist readers (asked, CIRISPersist follow-up):** `SignedTransportDestination::onion_hop_pair()`,
  `::onion_opt_out()`; identity_type `rendezvous` for §8.

## 4. Relay membership and the layer deal (CC 5.4.6 item 4 — normative; functions edge's own)

Implemented: `src/transport/onion_layers.rs` (pure; witnessed over T0–T19).

**Inputs (the fold, read at deal time, per node):** `row_live` (the current signed `transport_destination`
row is not retired), `announced` (the node is announced — the CC 5.3 serve-seat rule's twin; edge's
`node_is_announced`), `hop_key_valid` (§3, admission and the cross-row rule), `opted_out` (§3),
`owner_bound_under_bundle_root` (the identity has an owner-binding whose owner's trust root is in the
genesis bundle's charter set — persist `owner_of` + `trusted_roots_of` ∩ bundle roots), `is_seat` (the
bundle's serve seats). "The fold" is whatever rows the computing node holds at the moment it computes;
determinism means *same rows ⇒ same deal*, not that every node holds the same rows. A node with stale rows
deals a stale layer set and its routes fail at the stale hop; it rebuilds (§7). Relays do not need the deal
to forward: a relay forwards to whatever next hop the packet names, so a sender's view is the only one
that matters, and the cap and floor are enforced at the sender's route selection and in the client's
"available / unavailable" answer.

**Membership:** `is_relay = row_live ∧ announced ∧ hop_key_valid ∧ ¬opted_out ∧ owner_bound_under_bundle_root`.
Shaped layer links are checked at use (§6), not here.

**Period:** the rendezvous period, `period = floor(unix_seconds / 3600)` on the global clock (CC 3.1.4).
A deal is computed for the period of the send; a packet in flight across a period boundary is unaffected
(relays do not consult the deal to forward). Rendezvous routes (§8) are built per period.

**H:** `SHA-256("ciris:onion:layer-deal:v1" ‖ UTF-8(key_id) ‖ BE64(period))` (edge's instantiation of the
CC's `H(key_id ‖ period)`; the domain tag keeps it apart from every other hash of a key id).

**The deal:** sort relays by `(¬is_seat, H, key_id)`; deal seats round-robin over layers 0, 1, 2; continue
the round-robin with non-seats, each into the next layer with cap room (`non_seats_in_layer <
c × seats_in_layer`), else into `capped` (they wait for the next period; rotation by period gives them
turns). `c` is a steward setting, default 2. **Floor:** every layer ≥ 3 members, else `available = false`
and the client says the tier is unavailable this period; the tier never runs a thin layer.

**Finding (model §b):** the cap bounds a layer to (1 + c) × its seats, so with three seats every layer is
three nodes and nearly every other relay waits every period; the Sybil bound this buys is c/(1 + c) per
layer with all strangers hostile. Capacity and anonymity set grow with seats, not with volunteers. Edge
keeps the rule as ruled and flags it; an additive `k₀` is the one-line relaxation if the steward wants
larger layers at a stated Sybil cost.

## 5. The packet — `outfox-xwing-v1` (CC 5.4.6 item 3 normative in principle; layout edge's own)

Fixed length for every packet, so a wire or relay cannot tell publication from targeted delivery:

| Field | Bytes | Notes |
|---|---|---|
| `slot[0..6)` | 6 × 1168 = 7008 | one slot per hop: X-Wing ciphertext (1120) ‖ routing block (48). Slots 0–2 are the sender's safety route; slots 3–5 the receiver's private route (§8) or, for publication, three random slots |
| `body` | 8192 | the payload under per-hop body keys; the publication or the targeted message, padded to the full body |
| **total** | **15,200** | 12 shaped frames at a 1360-byte body (fleet TCP MDU); 43 at 360 (RNS base MTU) |

Routing block (48 B = 32 B plaintext + 16 B AES-256-GCM tag): `next_dest_hash` (16; the next relay's
identity destination hash, which is what the relay dials; the last relay sees the all-zero hash and the
`final` flag), `flags` (1: `0x01` final/store, `0x02` rendezvous-mailbox, `0x04` fetch), `delay_ms` (2,
big-endian; the sender-chosen mixing delay for this hop, drawn Exp(μ)), `period` (4, low 32 bits, so a
relay refuses a packet built against hop keys of another period after the grace), `reserved` (9, zero).

**Per hop:** `ss_i = XWing.Decaps(sk_hop, ct_i)`; keys by HKDF-SHA256 with the construction identifier bound
into the info, CC 5.1's one-construction-one-identifier rule: identifier
`onion_xwing_hkdf_sha256_aes256_gcm`; `k_hdr_i = HKDF(ss_i, salt = ct_i[0..32], info = id ‖ "/hdr")`,
`k_body_i = HKDF(…, "/body")`, `k_pad_i = HKDF(…, "/pad")`. The relay opens slot 0's routing block under
`k_hdr_i` with AAD = the slot's ciphertext (binding the block to its encapsulation), shifts slots 1–5 down,
appends a sixth slot of 1168 pseudorandom bytes from `k_pad_i` (so the header stays one length and the
appended slot is unpredictable to the previous hop), removes one layer of the body under `k_body_i`
(AES-256-GCM over the fixed body with a per-layer nonce from `k_body_i`; the last layer carries the tag,
inner layers are GCM-as-stream over a fixed length so no length grows), waits `delay_ms`, and sends the
packet as shaped-frame bodies on its shaped link to `next_dest_hash`.

**Sender:** draws fresh X-Wing encapsulations to each hop's published key in the period's deal, builds slots
outermost-last so the body's layers peel in order, and sets each slot's routing block to the next hop. For a
publication the final slot names the layer-3 seat chosen by the sender (deterministically over the deal, or
at random among layer 3), with `final`; for targeted delivery slots 3–5 are copied from the receiver's
`route_blob` (§8) and slot 2's routing block names the blob's first hop.

**Replay:** a relay keeps the set of `ct_i` hashes it has decapsulated for the current and previous period;
a repeat is dropped (`onion_replay`). Fresh encapsulation per packet makes every honest `ct_i` unique.

**Fragmentation:** on a shaped link the 15,200 bytes are CFRG-fragmented to the shaped frame body and
queued on the link's shaper like any other frame (CC 5.4.6 item 5); the receiving relay reassembles the
frame and recognises the packet by the `CONP` tag that prefixes it inside the frame.

## 6. Relay-side rules (edge's own under CC 5.4.6 items 1, 4, 5)

- A relay accepts onion packets only on **shaped** identity links (`link_shaping` agreed) and sends them
  only on shaped links: an unshaped link carries no onion packet in either direction (`onion_unshaped_link`,
  the packet dropped, the link kept). Layer links are therefore ordinary sealed, attributed identity links
  between relays with shaping on; a relay that cannot shape (class `off`) cannot relay and should opt out.
- The per-hop delay is honoured by holding the reassembled packet `delay_ms` before enqueueing it on the
  next hop's shaper; the shaper's own Poisson wait adds on top (the measured base in the model §e).
- A relay forwards without consulting the deal (§4). It refuses: a packet whose routing block does not
  open (`onion_hdr_open_failed`), one for another period past grace (`onion_period_mismatch`), a replay
  (`onion_replay`), a next hop it holds no route or hop key for (`onion_next_hop_unroutable`), and a
  packet from an unshaped link (`onion_unshaped_link`). All are counted under `onion_relay`; none closes
  the link (the frame was a valid shaped frame).
- Capacity: a relay bounds held packets (`onion_hold_max`, default 256 ≈ 3.7 MB) and reports deferral;
  nothing is silently dropped.

## 7. The sender's safety route (edge's own)

The sender computes the deal for the current period, picks one relay per layer uniformly from the
dealt members (never a capped one; never itself; hop 1 must be a node it holds, or can open, a shaped
identity link with), draws three delays Exp(μ) with μ a knob (default 2 s), and builds the packet. A route
that fails (no shaped link to hop 1, or no acknowledgement of storage within a budget) is rebuilt with a
fresh pick; the publication is retried at most `onion_route_retries` (default 3) times per period. Routes
are per packet; nothing about a sender's choice is published.

## 8. Rendezvous (CC 3.1.4, 5.4.6 item 6 — normative; mailbox edge's own)

**Row `rendezvous:route:v1`** (federation scope; attester = subject = the rendezvous key; reach everyone;
retention the period plus one grace period; each period's row `supersedes` the previous; never hard_case,
never fountain). Payload:

```json
{
  "format": "outfox-xwing-v1",
  "period": 496000,
  "valid_from": "<period start>", "valid_until": "<period end + 3600 s>",
  "rendezvous_node_key_id": "<a layer-3 serve seat>",
  "route_blob_base64": "<3 slots = 3504 bytes → 4672 base64: the receiver's private route, built
                         outermost-first toward the rendezvous node, every slot encapsulated to that
                         period's hop keys; the last slot's block carries flags = mailbox>",
  "rendezvous_key_record": { "<the fresh key's key:record:v1 row, identity_type rendezvous>" }
}
```

Row size ≈ 5.1 KB + the inline hybrid key record ≈ 17 KB ≈ 22 KB. The receiver mints a fresh hybrid
keypair per period, builds the private route from the period's deal (its own view), and publishes the row
through the ordinary replication door; senders find it by the rendezvous key (the targeted-publication
rendezvous: the sender was given the key out of band or by a prior message; the Tor-model blinded index for
broadcast stays open, CC 5.4.6 item 7 covers its rotation).

**The mailbox (edge's own):** a layer-3 seat receiving a packet with `mailbox` stores the body under the
rendezvous key named by the final slot for `valid_until` of that key's current row (period + grace),
bounded per key (`rendezvous_mailbox_max`, default 64 packets ≈ 950 KB) and per node (operator budget);
over the bound it refuses by name (`rendezvous_mailbox_full`) and counts. **Fetch:** the receiver sends,
through its own fresh safety route, a `fetch` packet whose body carries a signed fetch request (the
rendezvous key's hybrid signature over `period ‖ nonce ‖ its own current private route`), and the seat
answers each stored body as a packet along that route; stored bodies are deleted on fetch or at expiry.
The seat learns the rendezvous key, counts, sizes and times; never the receiver's identity (the fetch
arrives through three hops) and never the publisher. **Why a seat:** the model's §d — a route reused for an
hour must survive the hour, and seats do not churn.

## 9. Rotation (CC 5.4.6 item 7 — normative)

Hop keys: rotated by `supersedes` on a global-clock cadence (edge default: weekly, `onion_hop_key_rotation`;
both the current and the previous key are decapsulated during one period of overlap so packets built just
before a rotation still open). Layer deal: per period (§4). Rendezvous keys and routes: per period (§8).
Never on group events.

## 10. The device policy and the knobs (CC 5.4.6 item 1 — normative policy; knobs edge's own)

| Knob | Default | Meaning |
|---|---|---|
| `onion_relay` | on | relay for others; `off` ⇒ next row carries the marker, no hop key (a seat cannot set `off`: edge refuses the setting on a seat and names `seat_opted_out`) |
| device policy (client) | phone-class: relay on Wi-Fi while charging only; off on battery or metered; servers and home nodes: on | the client maps device state to `onion_relay` and states the cost: at the eight-link node cap a phone-wifi relay spends ≈ 29 GB/month and keeps the radio awake; cellular ≈ 7 GB/month metered |
| `onion_cap_factor` (c) | 2 | CC's steward setting |
| `onion_mix_mean_delay_ms` (μ) | 2000 | sender-chosen per-hop delay |
| `onion_hold_max`, `rendezvous_mailbox_max` | 256, 64 | relay hold and mailbox bounds |
| `onion_hop_key_rotation` | 7 days | hop-key cadence |
| `onion_route_retries` | 3 | per publication per period |

Edge's `ShapingPolicy` is a prerequisite: a relay's links to its layer neighbours are shaped at its class.

## 11. Refusal and error names (edge's own; the two seat names are CC's)

`seat_opted_out`, `seat_without_hop_key` (CC); `onion_unshaped_link`, `onion_hdr_open_failed`,
`onion_period_mismatch`, `onion_replay`, `onion_next_hop_unroutable`, `onion_hold_deferred`,
`onion_no_valid_hop_key` (use-time: the cross-row rule), `onion_tier_unavailable` (the floor, said to the
client with the layer sizes), `onion_route_failed` (sender, after retries), `rendezvous_route_stale`
(a row past `valid_until`), `rendezvous_mailbox_full`, `rendezvous_fetch_unsigned`. Metric families
`onion_relay`, `onion_send`, `rendezvous`.

## 12. Normative in CC versus edge's own

| Item | CC (normative) | Edge's own |
|---|---|---|
| opt-in to use / default-on relaying / seats cannot opt out / device policy | 5.4.6 item 1, 1.13.3.1 | the knob names, the cost figures |
| hop key member, shape, separation, "no valid hop key cannot relay" | 3.3.6.2 | custody, rotation cadence |
| opt-out marker, `seat_opted_out`, `seat_without_hop_key` | 3.3.6.2, 5.4.6 item 1 | counting them |
| membership predicate, deal order, cap c (default 2), floor 3, pure function of the fold | 5.4.6 item 4 | H's instantiation, round-robin continuation, the `capped` list, the `k₀` option (proposed, not adopted) |
| three hops, one per layer; post-quantum every hop; one ciphertext per hop | 5.4.6 items 3–4 | slot layout, sizes, KDF labels, identifier string, body size, flags, replay rule |
| carried as shaped-frame bodies; unshaped links carry none | 5.4.6 items 4–5 | the `CONP` tag, hold bound, per-hop delay distribution and μ |
| rendezvous row family, payload, reach, retention, one-hour period, multi-use route | 3.1.4, 5.4.6 item 6 | the mailbox, fetch protocol, bounds |
| rotation on global clocks | 5.4.6 item 7 | cadences |
| the count leak and the small-set caveat | 5.4.6 item 8 | the model's numbers |

## 13. Build plan (not in 43.2; the cut after)

1. persist: hop-key and marker readers, in-row separation refusals, identity_type `rendezvous`, the
   `rendezvous:route:v1` family admission (CIRISPersist follow-up).
2. ciris-crypto: `onion_xwing_hkdf_sha256_aes256_gcm` — slot build/open, KATs.
3. edge: custody + producer (§3); layer deal wiring (§4, done as a function); relay hop and shaped-link
   gate (§6); sender (§7); rendezvous row producer/consumer and the seat mailbox (§8); knobs (§10);
   metrics (§11); witnesses: the five CC claims as `src/…#symbol` rows.
4. Client: the device policy and the two wizard options' copy (option 2 "relay for others", option 3
   "publish anonymously"), both stating costs and the anonymity-set caveat.
