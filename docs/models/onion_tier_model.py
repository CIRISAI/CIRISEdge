#!/usr/bin/env python3
"""MODELLED: the Anonymous Tier's layer deal, Sybil bound, churn and latency.

CC 5.4.6 item 4 (rc10 89e6915). Everything here is arithmetic/simulation over
stated assumptions; the measured anchors are the shaping grid
(docs/SHAPING_RHO_W_2026-10-22.md) and the Rust witness in
src/transport/onion_layers.rs. Run: python3 -I docs/models/onion_tier_model.py
"""
import math, random, hashlib

random.seed(7)
LAYERS, FLOOR = 3, 3

def deal(relays, period, c):
    """relays: list of (key_id, is_seat). Mirrors src/transport/onion_layers.rs."""
    def h(k):
        return hashlib.sha256(b"ciris:onion:layer-deal:v1" + k.encode() + period.to_bytes(8, "big")).digest()
    rs = sorted(relays, key=lambda r: (not r[1], h(r[0]), r[0]))
    layers = [[] for _ in range(LAYERS)]; seats = [0]*LAYERS; non = [0]*LAYERS; capped = []
    nxt = 0
    for k, s in rs:
        if s:
            layers[nxt].append(k); seats[nxt] += 1; nxt = (nxt+1) % LAYERS
    for k, s in rs:
        if s: continue
        placed = False
        for step in range(LAYERS):
            l = (nxt+step) % LAYERS
            if non[l] < c*seats[l]:
                layers[l].append(k); non[l] += 1; nxt = (l+1) % LAYERS; placed = True; break
        if not placed: capped.append(k)
    return layers, capped, all(len(l) >= FLOOR for l in layers)

print("## (b) layer sizes, floor, anonymity set per layer vs adoption  [MODELLED]")
print("Assumptions: seats = canonicals; phones = 60% of non-seat nodes; device policy relays a phone only on")
print("Wi-Fi while charging (30% of phones at any time); 10% of eligible non-phones opt out; opt-in to USE = adoption.")
print(f"{'N':>7} {'seats':>5} {'relays':>7} {'dealt/layer':>12} {'capped':>7} {'avail':>5} | crowd per relay per 10-min window at adoption 1%/5%/20% (users×1 msg/h)")
cases = [(1,0),(2,1),(3,1),(4,1),(7,1),(10,1),(50,2),(1_000,3),(1_000,10),(10_000,10),(10_000,30),(100_000,30),(100_000,100)]
for N, seats in cases:
    non = N - seats
    phones = int(0.6*non); others = non - phones
    relays = seats + int(0.3*phones) + int(0.9*others)
    rl = [(f"s{i}", True) for i in range(seats)] + [(f"n{i}", False) for i in range(relays-seats)]
    layers, capped, avail = deal(rl, 496_000, 2)
    sizes = [len(l) for l in layers]
    per_relay_members = sum(sizes)
    crowds = []
    for adoption in (0.01, 0.05, 0.20):
        users = N*adoption
        msgs_per_window = users * (1/6)  # 1 msg/h each, 10-min window
        crowds.append(msgs_per_window / max(1, sizes[0]))
    print(f"{N:>7} {seats:>5} {relays:>7} {str(sizes):>12} {len(capped):>7} {str(avail):>5} | {crowds[0]:.2f} / {crowds[1]:.2f} / {crowds[2]:.2f}")
print("Reading: the cap ties the dealt set to 3 × (1+c) × seats-per-layer; with one seat per layer each layer holds ≤ 3 members, the floor just passes, and")
print("everything else waits. The anonymity set per layer is the layer size; the crowd per relay per window is what mixing actually needs (≫1).\n")

print("## (c) the Sybil bound the cap buys  [MODELLED]")
print("Adversary controls fraction f of the non-seat relays and no seat. Within a layer its share ≤ c·f/(1+c) (cap saturated, worst case).")
print(f"{'c':>2} {'f':>4} {'adv share/layer':>15} {'P(all 3 hops adv)':>18} {'P(hop1 & hop3 adv)':>19}")
for c in (1,2,3):
    for f in (0.1,0.5,0.9,1.0):
        share = c*f/(1+c)
        print(f"{c:>2} {f:>4} {share:>15.3f} {share**3:>18.4f} {share**2:>19.4f}")
print("Reading: at c=2 with EVERY non-seat relay hostile, a layer is at most 2/3 hostile: 44% of routes have both ends hostile (the")
print("timing-correlation case) and 30% are hostile end to end; c=1 gives 25% / 12.5%, c=3 gives 56% / 42%.")
print("Seats being honest is the assumption that does the work; the cap converts 'how many seats' into 'how hostile a layer can get'.\n")

print("## (d) delivery with phone churn: device policy vs phones always relaying  [MODELLED]")
print("A 3-hop route built at t0; each hop must still be online when the packet reaches it (t0+Δ, Δ≈10 s/hop under shaping); a phone")
print("relaying only on Wi-Fi+charging churns ~5%/h; a phone always relaying churns ~40%/h (sleep, carrier NAT, battery). Non-phones 1%/h.")
def p_alive(churn_per_h, dt_s): return math.exp(-churn_per_h*dt_s/3600)
for label, phone_frac_in_layers, phone_churn in (("device policy", 0.25, 0.05), ("phones always relay", 0.60, 0.40)):
    tot = 1.0
    for hop in range(1, 4):
        dt = 10*hop
        p = phone_frac_in_layers*p_alive(phone_churn, dt) + (1-phone_frac_in_layers)*p_alive(0.01, dt)
        tot *= p
    print(f"  {label:22} P(delivery, single try) = {tot:.4f}; with one retry over a fresh route ≈ {1-(1-tot)**2:.4f}")
print("  A route REUSED for an hour (the rendezvous blob) must survive the whole period: ", end="")
for label, pf, ch in (("device policy", 0.25, 0.05), ("always", 0.60, 0.40)):
    p = (pf*p_alive(ch, 3600) + (1-pf)*p_alive(0.01, 3600))**3
    print(f"{label} {p:.3f}; ", end="")
print("\nReading: per-packet delivery barely moves; the REUSED receiver route is what phone churn breaks (0.51 vs 0.94 survival over the hour), which is why")
print("the policy matters and why a rendezvous node should be a seat.\n")

print("## (e) latency per hop and end to end  [MEASURED base from the shaping grid; MODELLED sum]")
print("Packet = 15,200 B = 12 shaped frames at 1360 B body (TCP) or 43 at 360 B (RNS base). Per-hop wait ≈ (frames+1)/λ under budget")
print("(the grid's Poisson base), plus the sender-chosen mixing delay Exp(μ), μ = 2 s (edge knob).")
for name, lam_tcp, lam_rns in (("server", 5.0, 17.5), ("home", 2.0, 7.0), ("phone-wifi", 1.0, 3.5)):
    hop_tcp = 13/lam_tcp + 2; hop_rns = 44/lam_rns + 2
    print(f"  {name:11} per hop: {hop_tcp:5.1f} s (TCP) / {hop_rns:5.1f} s (RNS base); 3-hop publication {3*hop_tcp:5.1f} s / {3*hop_rns:5.1f} s;"
          f" targeted (6 hops + mailbox fetch 3 hops) {9*hop_tcp:5.1f} s / {9*hop_rns:5.1f} s")
print("Reading: a server-class path publishes in ~15 s over TCP; a home-class path in ~25 s; phone relays push a targeted delivery toward 2–3 minutes.\n")

print("## (f) sizes against the carrier bounds  [MODELLED, exact arithmetic]")
slot = 1120 + 48; header = 6*slot; body = 8192; packet = header + body
print(f"  X-Wing ct 1120 B + routing block 48 B = slot {slot} B; 6 slots (safety 3 + private 3, always) = {header} B; body {body} B; packet {packet} B")
print(f"  frames: TCP 1400 B MDU (1360 body) → {math.ceil(packet/1360)}; RNS base 400 B (360 body) → {math.ceil(packet/360)}; CFRG body bound 8 MiB → fine; Channel u16 envelope → fragments anyway")
blob = 3*slot
print(f"  rendezvous route blob = 3 slots = {blob} B raw, {math.ceil(blob/3)*4} B base64; row payload ≈ {math.ceil(blob/3)*4 + 400} B + inline hybrid key record ≈ 17,000 B → ≈ {math.ceil(blob/3)*4 + 400 + 17000} B per row")
print(f"  mailbox per rendezvous key per period at 64 packets cap: {64*packet/1024:.0f} KiB; a seat holding 1,000 active rendezvous keys: {64*packet*1000/2**20:.0f} MiB")
