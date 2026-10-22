//! CC 5.4.6 item 3 — the **`outfox-xwing-v1` onion packet** (FSD/ONION_ROUTING.md §5).
//!
//! A fixed-length layered packet: [`SLOTS`] header slots of [`SLOT`] bytes and a
//! [`BODY`]-byte body, [`PACKET`] bytes at every hop, so a relay cannot tell a
//! publication from a targeted delivery or its position on the path. Each slot
//! is one hop's hybrid encapsulation (X25519 ‖ ML-KEM-768, [`KEM_CT`] bytes) to
//! that hop's onion hop key, followed by its routing block sealed under a key
//! derived from that encapsulation ([`BLOCK`] bytes, AES-256-GCM, the
//! encapsulation as AAD). Every layer is post-quantum: a construction whose
//! per-hop key agreement were X25519 alone would not be conformant (CC 5.4.6
//! item 3, CC 5.3.3.5 E1). Because ML-KEM cannot be blinded, the header carries
//! one ciphertext per hop (no Sphinx group element).
//!
//! **Peeling.** A relay decapsulates slot 0, opens its routing block, XORs the
//! remaining five slots and five fresh zero slots with its header keystream —
//! the first five become the next header's slots, the sixth is the appended pad
//! that keeps the length — and XORs its body keystream over the body. No hop
//! learns more than its predecessor's link and its successor's destination.
//!
//! **Composition (CC 5.4.6 item 6).** A receiver builds the three-slot route to
//! its rendezvous seat ([`build_route_blob`]) and publishes it; a sender builds
//! its own three hops ONTO that blob ([`build_packet_onto_blob`]). The sender
//! never learns the private hops' keys, and the receiver never learns the
//! sender's. With at most [`SLOTS`] hops the appended pads are never read, so no
//! Sphinx filler is needed.
//!
//! **Combiner.** The X-Wing key shape (CC 3.3.6.2 `onion_hop_pubkeys`) with the
//! stack's HKDF-SHA256 combiner over both shared secrets, both ciphertexts and
//! the recipient's public key, the identifier bound into the info (the
//! `transit_kex` pattern, CIRISVerify#309); CC 5.1's one-construction-one-
//! identifier rule names it [`CONSTRUCTION_ID`].
//!
//! **Residuals (stated).** The body layers are XOR keystreams, so a hostile hop
//! can flip body bits that a colluding later hop observes (the tagging attack
//! LIONESS closes in Sphinx). Publication and delivery bodies carry their own
//! end-to-end signature or seal, so a tampered body is refused at the consumer,
//! but the observation channel stays: a wide-block body cipher is the v2 item.

use ciris_crypto::{aes_gcm, kdf, ml_kem, x25519};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

/// CC 5.1 — the construction's identifier, bound into every derivation.
pub const CONSTRUCTION_ID: &[u8] = b"onion_xwing_hkdf_sha256_aes256_gcm";
/// The packet format's name on the rendezvous row (`format`, CC 3.1.4).
pub const FORMAT: &str = "outfox-xwing-v1";
/// X25519 ephemeral public key ‖ ML-KEM-768 ciphertext.
pub const KEM_CT: usize = 32 + ml_kem::ML_KEM_768_CIPHERTEXT_LEN;
/// Routing block plaintext.
pub const BLOCK_PLAIN: usize = 32;
/// Routing block sealed (plaintext + GCM tag).
pub const BLOCK: usize = BLOCK_PLAIN + 16;
/// One header slot.
pub const SLOT: usize = KEM_CT + BLOCK;
/// Header slots: the sender's three hops and the receiver's three.
pub const SLOTS: usize = 6;
/// The header.
pub const HEADER: usize = SLOT * SLOTS;
/// The body.
pub const BODY: usize = 8192;
/// The whole packet, the same at every hop.
pub const PACKET: usize = HEADER + BODY;
/// Most a body carries: the body less its two-byte length prefix.
pub const BODY_CAPACITY: usize = BODY - 2;

const _: () = assert!(SLOT == 1168);
const _: () = assert!(PACKET == 15_200);

/// Routing block flag: this hop stores the publication (CC 5.4.6, the final hop).
pub const FLAG_FINAL: u8 = 0x01;
/// Routing block flag: this hop is a rendezvous seat; store under the mailbox.
pub const FLAG_MAILBOX: u8 = 0x02;
/// Routing block flag: this packet is a mailbox fetch.
pub const FLAG_FETCH: u8 = 0x04;

/// A hop's public onion hop key (CC 3.3.6.2 `onion_hop_pubkeys`).
#[derive(Clone, PartialEq, Eq)]
pub struct HopKey {
    /// X25519 public key.
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key.
    pub ml_kem_768: Box<[u8; ml_kem::ML_KEM_768_PUBKEY_LEN]>,
}

impl std::fmt::Debug for HopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopKey").finish_non_exhaustive()
    }
}

/// A relay's onion hop secret.
pub struct HopSecret {
    x25519: Zeroizing<[u8; 32]>,
    ml_kem_768_seed: Zeroizing<Vec<u8>>,
    public: HopKey,
}

impl std::fmt::Debug for HopSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopSecret").finish_non_exhaustive()
    }
}

impl HopSecret {
    /// A hop secret from a 64-byte root seed (the custody seed): X25519 and the
    /// ML-KEM-768 seed are derived under distinct labels.
    ///
    /// # Errors
    /// [`OnionError::Crypto`] from the primitives.
    pub fn from_root_seed(seed: &[u8; 64]) -> Result<Self, OnionError> {
        let x = kdf::hkdf_sha256(seed, b"", b"ciris-onion-hop/v1/x25519", 32).map_err(crypto)?;
        let mut x25519 = Zeroizing::new([0u8; 32]);
        x25519.copy_from_slice(&x);
        let m = Zeroizing::new(
            kdf::hkdf_sha256(seed, b"", b"ciris-onion-hop/v1/ml-kem-768", 64).map_err(crypto)?,
        );
        let (sk, pk) = ml_kem::generate_keypair_deterministic(&m).map_err(crypto)?;
        let mut ml_pk = Box::new([0u8; ml_kem::ML_KEM_768_PUBKEY_LEN]);
        ml_pk.copy_from_slice(&pk);
        Ok(Self {
            public: HopKey {
                x25519: x25519::public_from_secret(&x25519),
                ml_kem_768: ml_pk,
            },
            x25519,
            ml_kem_768_seed: Zeroizing::new(sk),
        })
    }

    /// The public hop key published on the signed route row.
    #[must_use]
    pub fn public(&self) -> &HopKey {
        &self.public
    }
}

/// One hop's routing instructions (FSD §5): where to send next and what to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutingBlock {
    /// The next relay's identity destination hash (all zero on a final hop).
    pub next_dest: [u8; 16],
    /// [`FLAG_FINAL`] / [`FLAG_MAILBOX`] / [`FLAG_FETCH`].
    pub flags: u8,
    /// The sender-chosen mixing delay for this hop, in milliseconds.
    pub delay_ms: u16,
    /// The low 32 bits of the rendezvous period the packet was built for.
    pub period: u32,
}

impl RoutingBlock {
    fn encode(&self) -> [u8; BLOCK_PLAIN] {
        let mut b = [0u8; BLOCK_PLAIN];
        b[..16].copy_from_slice(&self.next_dest);
        b[16] = self.flags;
        b[17..19].copy_from_slice(&self.delay_ms.to_be_bytes());
        b[19..23].copy_from_slice(&self.period.to_be_bytes());
        b
    }

    fn decode(b: &[u8]) -> Result<Self, OnionError> {
        if b.len() != BLOCK_PLAIN || b[23..].iter().any(|&x| x != 0) {
            return Err(OnionError::Malformed("routing block"));
        }
        let mut next_dest = [0u8; 16];
        next_dest.copy_from_slice(&b[..16]);
        Ok(Self {
            next_dest,
            flags: b[16],
            delay_ms: u16::from_be_bytes([b[17], b[18]]),
            period: u32::from_be_bytes([b[19], b[20], b[21], b[22]]),
        })
    }

    /// Whether this hop is the end of the route.
    #[must_use]
    pub fn is_final(&self) -> bool {
        self.flags & (FLAG_FINAL | FLAG_MAILBOX) != 0
    }
}

/// A hop on a route being built: its public key and its instructions.
#[derive(Debug, Clone)]
pub struct HopSpec {
    /// The hop's published onion hop key.
    pub key: HopKey,
    /// What the hop does with the packet.
    pub block: RoutingBlock,
}

/// Why an onion operation failed. Named, never silent (FSD §11).
#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    /// A primitive refused.
    #[error("onion crypto: {0}")]
    Crypto(String),
    /// The packet or a field is the wrong shape.
    #[error("onion packet malformed: {0}")]
    Malformed(&'static str),
    /// The routing block did not open under this hop's key
    /// (`onion_hdr_open_failed`).
    #[error("onion routing block did not open (onion_hdr_open_failed)")]
    HeaderOpenFailed,
    /// A route longer than the header holds, or empty.
    #[error("onion route of {0} hops; between 1 and {SLOTS} fit")]
    RouteLength(usize),
    /// A body too large for the fixed body.
    #[error("onion body of {0} bytes; at most {BODY_CAPACITY} fit")]
    BodyTooLarge(usize),
}

impl OnionError {
    /// The stable refusal token (FSD §11).
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::HeaderOpenFailed => "onion_hdr_open_failed",
            Self::Crypto(_) | Self::Malformed(_) => "onion_packet_malformed",
            Self::RouteLength(_) => "onion_route_length",
            Self::BodyTooLarge(_) => "onion_body_too_large",
        }
    }
}

fn crypto(e: impl std::fmt::Display) -> OnionError {
    OnionError::Crypto(e.to_string())
}

/// One hop's derived keys. Zeroized on drop.
pub struct LayerKeys {
    hdr: Zeroizing<[u8; 32]>,
    stream: Zeroizing<Vec<u8>>,
    body: Zeroizing<Vec<u8>>,
}

impl std::fmt::Debug for LayerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerKeys").finish_non_exhaustive()
    }
}

fn derive(ss: &[u8], ct: &[u8; KEM_CT], recipient: &HopKey) -> Result<LayerKeys, OnionError> {
    // The combiner: both shared secrets (in `ss`), bound to both ciphertexts
    // and the recipient's whole public key through the salt.
    let mut h = Sha256::new();
    h.update(CONSTRUCTION_ID);
    h.update(ct);
    h.update(recipient.x25519);
    h.update(&recipient.ml_kem_768[..]);
    let salt = h.finalize();
    let ex = |label: &[u8], n: usize| -> Result<Vec<u8>, OnionError> {
        let mut info = CONSTRUCTION_ID.to_vec();
        info.extend_from_slice(label);
        kdf::hkdf_sha256(ss, &salt, &info, n).map_err(crypto)
    };
    let hdr_v = ex(b"/hdr", 32)?;
    let mut hdr = Zeroizing::new([0u8; 32]);
    hdr.copy_from_slice(&hdr_v);
    let stream = Zeroizing::new(ex(b"/stream", SLOT * SLOTS)?);
    let mut body = ex(b"/body/0", BODY / 2)?;
    body.extend(ex(b"/body/1", BODY / 2)?);
    Ok(LayerKeys {
        hdr,
        stream,
        body: Zeroizing::new(body),
    })
}

fn encapsulate(to: &HopKey) -> Result<([u8; KEM_CT], LayerKeys), OnionError> {
    let (eph_pub, ss_x) = x25519::ephemeral_dh(&to.x25519).map_err(crypto)?;
    let (ct_m, ss_m) = ml_kem::encapsulate(&to.ml_kem_768[..]).map_err(crypto)?;
    let mut ct = [0u8; KEM_CT];
    ct[..32].copy_from_slice(&eph_pub);
    ct[32..].copy_from_slice(&ct_m);
    let mut ss = Zeroizing::new([0u8; 64]);
    ss[..32].copy_from_slice(&ss_x);
    ss[32..].copy_from_slice(&ss_m);
    let keys = derive(&ss[..], &ct, to)?;
    Ok((ct, keys))
}

fn decapsulate(secret: &HopSecret, ct: &[u8; KEM_CT]) -> Result<LayerKeys, OnionError> {
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&ct[..32]);
    let ss_x = Zeroizing::new(x25519::dh(&secret.x25519, &eph).map_err(crypto)?);
    let ss_m =
        Zeroizing::new(ml_kem::decapsulate(&secret.ml_kem_768_seed, &ct[32..]).map_err(crypto)?);
    let mut ss = Zeroizing::new([0u8; 64]);
    ss[..32].copy_from_slice(&ss_x[..]);
    ss[32..].copy_from_slice(&ss_m[..]);
    derive(&ss[..], ct, &secret.public)
}

fn xor(dst: &mut [u8], ks: &[u8]) {
    for (d, k) in dst.iter_mut().zip(ks) {
        *d ^= k;
    }
}

fn seal_block(
    keys: &LayerKeys,
    ct: &[u8; KEM_CT],
    block: &RoutingBlock,
) -> Result<Vec<u8>, OnionError> {
    // The header key is unique per encapsulation, so a fixed nonce is sound.
    aes_gcm::encrypt_aad(&keys.hdr, &[0u8; 12], ct, &block.encode()).map_err(crypto)
}

fn random_slots(n: usize) -> Result<Vec<u8>, OnionError> {
    // ciris-crypto's RNG: refuses when its SP 800-90B health latch has failed.
    ciris_crypto::random::bytes(n * SLOT).map_err(crypto)
}

/// The sender's (or receiver's) per-hop keys for a route it built, outermost
/// first. The sender layers the body with them; a receiver keeps its private
/// route's to remove their body layers at fetch.
pub type RouteKeys = Vec<LayerKeys>;

/// Build a header for `hops` on top of `inner` (the header the last of `hops`
/// hands on: random slots for a standalone route, or a receiver's route blob).
/// Returns the header and the hops' keys, outermost first.
fn build_header_onto(hops: &[HopSpec], inner: Vec<u8>) -> Result<(Vec<u8>, RouteKeys), OnionError> {
    if hops.is_empty() || hops.len() > SLOTS {
        return Err(OnionError::RouteLength(hops.len()));
    }
    debug_assert_eq!(inner.len(), HEADER);
    // `next` is the header hop i+1 must receive; build innermost-out.
    let mut next = inner;
    let mut keys_rev = Vec::with_capacity(hops.len());
    for hop in hops.iter().rev() {
        let (ct, keys) = encapsulate(&hop.key)?;
        let sealed = seal_block(&keys, &ct, &hop.block)?;
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(&ct);
        header.extend_from_slice(&sealed);
        // The hop will XOR slots 1..6 with its stream and get `next[0..5]`.
        let mut tail = next[..SLOT * (SLOTS - 1)].to_vec();
        xor(&mut tail, &keys.stream[..SLOT * (SLOTS - 1)]);
        header.extend_from_slice(&tail);
        next = header;
        keys_rev.push(keys);
    }
    keys_rev.reverse();
    Ok((next, keys_rev))
}

/// A receiver's published route to its rendezvous seat (CC 3.1.4
/// `route_blob_base64`): the first three slots of a header built over its
/// private hops, the last hop's block carrying [`FLAG_MAILBOX`].
pub struct RouteBlob {
    /// The three slots.
    pub slots: Vec<u8>,
}

/// The receiver side: build the private route and keep its keys for the
/// period, to remove the private hops' body layers when it fetches.
///
/// # Errors
/// [`OnionError::RouteLength`] unless `hops` is 1..=3; a primitive's refusal.
pub fn build_route_blob(hops: &[HopSpec]) -> Result<(RouteBlob, RouteKeys), OnionError> {
    if hops.is_empty() || hops.len() > SLOTS / 2 {
        return Err(OnionError::RouteLength(hops.len()));
    }
    let (header, keys) = build_header_onto(hops, random_slots(SLOTS)?)?;
    Ok((
        RouteBlob {
            slots: header[..SLOT * (SLOTS / 2)].to_vec(),
        },
        keys,
    ))
}

fn encode_body(payload: &[u8]) -> Result<Vec<u8>, OnionError> {
    if payload.len() > BODY_CAPACITY {
        return Err(OnionError::BodyTooLarge(payload.len()));
    }
    let mut body = vec![0u8; BODY];
    #[allow(clippy::cast_possible_truncation)] // ≤ BODY_CAPACITY < u16::MAX
    let len = payload.len() as u16;
    body[..2].copy_from_slice(&len.to_be_bytes());
    body[2..2 + payload.len()].copy_from_slice(payload);
    Ok(body)
}

/// Read a body's payload once every layer is off.
///
/// # Errors
/// [`OnionError::Malformed`] for a length past the body.
pub fn decode_body(body: &[u8]) -> Result<Vec<u8>, OnionError> {
    if body.len() != BODY {
        return Err(OnionError::Malformed("body length"));
    }
    let len = usize::from(u16::from_be_bytes([body[0], body[1]]));
    if len > BODY_CAPACITY {
        return Err(OnionError::Malformed("body payload length"));
    }
    Ok(body[2..2 + len].to_vec())
}

fn assemble(header: Vec<u8>, keys: &RouteKeys, payload: &[u8]) -> Result<Vec<u8>, OnionError> {
    let mut body = encode_body(payload)?;
    // Each hop XORs its own body stream; applying all of them here means the
    // body the final hop is left holding is the plaintext.
    for k in keys {
        xor(&mut body, &k.body);
    }
    let mut packet = header;
    packet.extend_from_slice(&body);
    debug_assert_eq!(packet.len(), PACKET);
    Ok(packet)
}

/// A standalone route (CC 5.4.6 item 2, publication): the sender's hops, the
/// last carrying [`FLAG_FINAL`]. Returns the packet for the first hop.
///
/// # Errors
/// [`OnionError::RouteLength`] / [`OnionError::BodyTooLarge`]; a primitive's refusal.
pub fn build_packet(hops: &[HopSpec], payload: &[u8]) -> Result<Vec<u8>, OnionError> {
    let (header, keys) = build_header_onto(hops, random_slots(SLOTS)?)?;
    assemble(header, &keys, payload)
}

/// A targeted delivery (CC 5.4.6 item 6): the sender's hops onto a receiver's
/// published route blob. The sender's last hop names the blob's first hop as
/// `next_dest`. The private hops' body layers stay on the body; the receiver
/// removes them ([`open_fetched_body`]).
///
/// # Errors
/// As [`build_packet`]; [`OnionError::Malformed`] for a blob of the wrong size.
pub fn build_packet_onto_blob(
    hops: &[HopSpec],
    blob: &RouteBlob,
    payload: &[u8],
) -> Result<Vec<u8>, OnionError> {
    if blob.slots.len() != SLOT * (SLOTS / 2) || hops.len() > SLOTS / 2 {
        return Err(OnionError::Malformed("route blob or sender route length"));
    }
    let mut inner = blob.slots.clone();
    inner.extend(random_slots(SLOTS / 2)?);
    let (header, keys) = build_header_onto(hops, inner)?;
    assemble(header, &keys, payload)
}

/// What a relay learns when it peels its layer.
#[derive(Debug)]
pub struct Peeled {
    /// Its routing instructions.
    pub block: RoutingBlock,
    /// The packet to send to `block.next_dest` (or, on a final hop, the packet
    /// whose body is the payload: [`decode_body`] on its body).
    pub packet: Vec<u8>,
    /// SHA-256 of this hop's encapsulation: the relay's replay key
    /// (`onion_replay`, FSD §5).
    pub replay_tag: [u8; 32],
}

impl Peeled {
    /// The body of the peeled packet.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.packet[HEADER..]
    }
}

/// A relay's step: remove one layer.
///
/// # Errors
/// [`OnionError::Malformed`] for a packet of the wrong length;
/// [`OnionError::HeaderOpenFailed`] when the routing block does not open
/// (not this hop's layer, or tampered).
pub fn peel(secret: &HopSecret, packet: &[u8]) -> Result<Peeled, OnionError> {
    if packet.len() != PACKET {
        return Err(OnionError::Malformed("packet length"));
    }
    let mut ct = [0u8; KEM_CT];
    ct.copy_from_slice(&packet[..KEM_CT]);
    let keys = decapsulate(secret, &ct)?;
    let plain = aes_gcm::decrypt_aad(&keys.hdr, &[0u8; 12], &ct, &packet[KEM_CT..SLOT])
        .map_err(|_| OnionError::HeaderOpenFailed)?;
    let block = RoutingBlock::decode(&plain)?;
    let mut next = Vec::with_capacity(PACKET);
    let mut rest = packet[SLOT..HEADER].to_vec();
    rest.resize(SLOT * SLOTS, 0);
    xor(&mut rest, &keys.stream);
    next.extend_from_slice(&rest);
    let mut body = packet[HEADER..].to_vec();
    xor(&mut body, &keys.body);
    next.extend_from_slice(&body);
    let replay_tag: [u8; 32] = Sha256::digest(ct).into();
    let mut plain = plain;
    plain.zeroize();
    Ok(Peeled {
        block,
        packet: next,
        replay_tag,
    })
}

/// The receiver's step for a fetched mailbox body: remove the private hops'
/// body layers with the keys it kept from [`build_route_blob`], then read it.
///
/// # Errors
/// [`decode_body`]'s.
pub fn open_fetched_body(body: &[u8], private_keys: &RouteKeys) -> Result<Vec<u8>, OnionError> {
    let mut b = body.to_vec();
    for k in private_keys {
        xor(&mut b, &k.body);
    }
    decode_body(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u8) -> HopSecret {
        HopSecret::from_root_seed(&[n; 64]).expect("hop secret")
    }

    fn spec(to: &HopSecret, next: [u8; 16], flags: u8) -> HopSpec {
        HopSpec {
            key: to.public().clone(),
            block: RoutingBlock {
                next_dest: next,
                flags,
                delay_ms: 2000,
                period: 496_000,
            },
        }
    }

    /// CLM-onion-route — a three-hop publication: every hop sees one fixed
    /// length, learns only its successor, and the final hop recovers the
    /// payload; no slot 0 repeats across hops.
    #[test]
    fn a_three_hop_publication_peels_in_order_at_one_length() {
        let (r1, r2, r3) = (relay(1), relay(2), relay(3));
        let hops = [
            spec(&r1, [0x22; 16], 0),
            spec(&r2, [0x33; 16], 0),
            spec(&r3, [0; 16], FLAG_FINAL),
        ];
        let payload = b"a federation-scope publication".to_vec();
        let p0 = build_packet(&hops, &payload).expect("build");
        assert_eq!(p0.len(), PACKET);
        let a = peel(&r1, &p0).expect("hop 1");
        assert_eq!(a.block.next_dest, [0x22; 16]);
        assert!(!a.block.is_final());
        assert_eq!(a.packet.len(), PACKET);
        let b = peel(&r2, &a.packet).expect("hop 2");
        assert_eq!(b.block.next_dest, [0x33; 16]);
        let c = peel(&r3, &b.packet).expect("hop 3");
        assert!(c.block.is_final());
        assert_eq!(decode_body(c.body()).unwrap(), payload);
        assert_ne!(p0[..SLOT], a.packet[..SLOT]);
        assert_ne!(a.packet[..SLOT], b.packet[..SLOT]);
        assert_ne!(a.replay_tag, b.replay_tag);
        assert_eq!(c.block.delay_ms, 2000);
        assert_eq!(c.block.period, 496_000);
    }

    /// CLM-onion-route — a layer is opened only by its own hop: another
    /// relay's secret fails by name, and a flipped routing-block byte fails.
    #[test]
    fn a_layer_opens_only_for_its_hop_and_only_untampered() {
        let (r1, r2) = (relay(1), relay(2));
        let p = build_packet(
            &[spec(&r1, [9; 16], 0), spec(&r2, [0; 16], FLAG_FINAL)],
            b"x",
        )
        .unwrap();
        assert!(matches!(peel(&r2, &p), Err(OnionError::HeaderOpenFailed)));
        let mut t = p.clone();
        t[KEM_CT + 3] ^= 1;
        assert!(matches!(peel(&r1, &t), Err(OnionError::HeaderOpenFailed)));
        let mut c = p.clone();
        c[40] ^= 1;
        assert!(matches!(
            peel(&r1, &c),
            Err(OnionError::HeaderOpenFailed | OnionError::Crypto(_))
        ));
        assert!(matches!(
            peel(&r1, &p[..100]),
            Err(OnionError::Malformed(_))
        ));
        assert_eq!(
            OnionError::HeaderOpenFailed.label(),
            "onion_hdr_open_failed"
        );
    }

    /// CC 5.4.6 item 6 — a targeted delivery: the sender's three hops onto the
    /// receiver's three-hop route blob. Six peels, the sixth at the rendezvous
    /// seat with the mailbox flag; the receiver alone removes the private
    /// layers from the stored body.
    #[test]
    fn a_sender_route_composes_onto_a_receivers_blob_and_only_the_receiver_reads_it() {
        let s: Vec<_> = (1..=3).map(relay).collect();
        let p: Vec<_> = (4..=6).map(relay).collect();
        let (blob, private_keys) = build_route_blob(&[
            spec(&p[0], [0x55; 16], 0),
            spec(&p[1], [0x66; 16], 0),
            spec(&p[2], [0; 16], FLAG_MAILBOX),
        ])
        .expect("blob");
        assert_eq!(blob.slots.len(), 3 * SLOT);
        let payload = b"sealed to the rendezvous key".to_vec();
        let mut pkt = build_packet_onto_blob(
            &[
                spec(&s[0], [0x22; 16], 0),
                spec(&s[1], [0x33; 16], 0),
                spec(&s[2], [0x44; 16], 0),
            ],
            &blob,
            &payload,
        )
        .expect("compose");
        let order: Vec<&HopSecret> = s.iter().chain(p.iter()).collect();
        let mut last = None;
        for (i, hop) in order.iter().enumerate() {
            let out = peel(hop, &pkt).unwrap_or_else(|e| panic!("hop {i}: {e}"));
            assert_eq!(out.packet.len(), PACKET);
            pkt = out.packet.clone();
            last = Some(out);
        }
        let last = last.unwrap();
        assert!(last.block.flags & FLAG_MAILBOX != 0);
        // The seat cannot read it; the receiver can.
        assert_ne!(decode_body(last.body()).ok(), Some(payload.clone()));
        assert_eq!(
            open_fetched_body(last.body(), &private_keys).unwrap(),
            payload
        );
    }

    #[test]
    fn route_and_body_bounds_are_refused_by_name() {
        let r = relay(1);
        assert!(matches!(
            build_packet(&[], b""),
            Err(OnionError::RouteLength(0))
        ));
        let seven: Vec<_> = (0..7).map(|_| spec(&r, [0; 16], 0)).collect();
        assert!(matches!(
            build_packet(&seven, b""),
            Err(OnionError::RouteLength(7))
        ));
        let big = vec![0u8; BODY_CAPACITY + 1];
        assert!(matches!(
            build_packet(&[spec(&r, [0; 16], FLAG_FINAL)], &big),
            Err(OnionError::BodyTooLarge(_))
        ));
        assert!(build_packet(&[spec(&r, [0; 16], FLAG_FINAL)], &vec![7u8; BODY_CAPACITY]).is_ok());
    }

    #[test]
    fn a_hop_secret_is_deterministic_from_its_seed() {
        assert_eq!(relay(1).public(), relay(1).public());
        assert_ne!(relay(1).public(), relay(2).public());
    }
}
