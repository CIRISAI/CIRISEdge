//! CC 5.4.6 item 3 (rc16) — the **`outfox-xwing-v1` onion packet**, edge's
//! submission for the CC to pin. The byte layout, every key-derivation label,
//! the AEAD, the acceptance order and the refusal tokens are written out in
//! `docs/onion_packet_wire.md`; the fixed-seed known answers are the
//! `kat_*` tests at the bottom of this file.
//!
//! A fixed-length layered packet: [`SLOTS`] header slots of [`SLOT`] bytes and
//! a [`BODY`]-byte body, [`PACKET`] bytes at every hop, so a relay cannot tell
//! a publication from a targeted delivery or its position on the path.
//!
//! **The hop KEM is X-Wing as the draft defines it** (CC 5.4.6 item 3, binding
//! property (a)): draft-connolly-cfrg-xwing-kem-06, ML-KEM-768 ‖ X25519 with
//! the draft's SHA3-256 combiner `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")`,
//! from libcrux (`libcrux_kem::Algorithm::XWingKemDraft06`). The ciphertext is
//! `ct_M ‖ ct_X` (1088 + 32 bytes). Because ML-KEM cannot be blinded, the
//! header carries one ciphertext per hop (no Sphinx group element). A hop key
//! held in the split form (an ML-KEM-768 `d ‖ z` seed and an X25519 scalar,
//! the shape of today's transit custody) decapsulates through the same
//! combiner computed here ([`xwing_combiner`]); the `kat_split_and_seed_forms_agree`
//! witness proves the two forms give the same shared secret byte for byte.
//!
//! **The body is tagging-resistant** (binding property (b)): each hop removes
//! one layer of LIONESS (Anderson–Biham), a four-round unbalanced Feistel
//! wide-block cipher over the whole 8192-byte body, with SHAKE256 as the
//! stream and keyed SHA3-256 as the hash. A wide-block cipher is a strong
//! pseudorandom permutation: changing any byte of its input changes every
//! byte of its output unpredictably. So a hop that alters any body byte
//! leaves every later hop holding random bytes, and the exit's 16-byte zero
//! check ([`BODY_CHECK`]) fails with probability `1 − 2⁻¹²⁸`
//! (`onion_body_tampered`). A per-layer XOR or a per-layer AEAD over the body
//! alone would not do this (CC 5.4.6 item 3: it lets an on-path pair mark a
//! packet at entry and recognise it at exit).
//!
//! **The header is tagging-resistant too** (beyond the CC's text): each
//! routing block commits to the first 16 bytes of
//! `SHA3-256("ciris-onion/v1/slot-commit" ‖ next hop's slot)` as that hop will
//! receive it, and a hop refuses (`onion_next_slot_mismatch`) when the slot it
//! is about to forward does not match. Each slot's own block carries the next
//! commitment, so the chain covers every later hop's slot: a hop that alters
//! any byte of a later hop's header material is caught by the next honest hop,
//! before a colluding later hop can see the mark. The commitment is computed
//! by whoever builds the segment, so it survives composing a sender's route
//! onto a receiver's blob (the sender commits its last hop to the blob's first
//! slot; the receiver committed its own hops when it built the blob).
//!
//! **Composition (CC 5.4.6 item 6).** A receiver builds the three-slot route
//! to its rendezvous seat ([`build_route_blob`]) and publishes it; a sender
//! builds its own three hops ONTO that blob ([`build_packet_onto_blob`]). The
//! sender never learns the private hops' keys, and the receiver never learns
//! the sender's. With at most [`SLOTS`] hops the appended pads are never read,
//! so no Sphinx filler is needed.

use ciris_crypto::{aes_gcm, kdf, ml_kem, x25519};
use zeroize::{Zeroize, Zeroizing};

/// CC 5.1 — the construction's identifier, bound into every key derivation.
/// The combiner, KDF, AEAD and body cipher are all in the name: a change to
/// any of them is another construction with another identifier.
pub const CONSTRUCTION_ID: &[u8] = b"onion_xwing06_hkdf_sha3_256_aes256gcm_lioness_shake256";
/// The packet format's name on the rendezvous row (`format`, CC 3.1.4).
pub const FORMAT: &str = "outfox-xwing-v1";
/// The X-Wing draft-06 combiner label, `"\.//^\"`.
pub const XWING_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
/// ML-KEM-768 ciphertext.
pub const ML_KEM_CT: usize = ml_kem::ML_KEM_768_CIPHERTEXT_LEN;
/// An X-Wing ciphertext: `ct_M ‖ ct_X`.
pub const KEM_CT: usize = ML_KEM_CT + 32;
/// An X-Wing public key: `pk_M ‖ pk_X`.
pub const XWING_PK: usize = ml_kem::ML_KEM_768_PUBKEY_LEN + 32;
/// Routing block plaintext.
pub const BLOCK_PLAIN: usize = 48;
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
/// The body's integrity check: this many zero bytes lead the plaintext body.
pub const BODY_CHECK: usize = 16;
/// Most a body carries: the body less the check and the two-byte length.
pub const BODY_CAPACITY: usize = BODY - BODY_CHECK - 2;
/// The slot commitment carried in a routing block.
pub const COMMIT: usize = 16;
/// LIONESS left half (the hash width).
const LIONESS_L: usize = 32;

const _: () = assert!(KEM_CT == 1120);
const _: () = assert!(SLOT == 1184);
const _: () = assert!(PACKET == 15_296);

/// HKDF info suffix for the routing block's AES-256-GCM key.
pub const LABEL_HDR: &[u8] = b"/hdr";
/// HKDF info suffix for the header stream key.
pub const LABEL_STREAM: &[u8] = b"/stream";
/// HKDF info suffix for the four LIONESS round keys (4 × 32 bytes).
pub const LABEL_LIONESS: &[u8] = b"/lioness";
/// SHAKE256 domain of the header stream.
pub const DS_HEADER_STREAM: &[u8] = b"ciris-onion/v1/header-stream";
/// SHAKE256 domain of the LIONESS stream rounds.
pub const DS_LIONESS_STREAM: &[u8] = b"ciris-onion/v1/lioness-stream";
/// SHA3-256 domain of the LIONESS hash rounds.
pub const DS_LIONESS_HASH: &[u8] = b"ciris-onion/v1/lioness-hash";
/// SHA3-256 domain of the slot commitment.
pub const DS_SLOT_COMMIT: &[u8] = b"ciris-onion/v1/slot-commit";
/// SHA3-256 domain of the replay tag.
pub const DS_REPLAY: &[u8] = b"ciris-onion/v1/replay";

/// Routing block flag: this hop stores the publication (CC 5.4.6, the final hop).
pub const FLAG_FINAL: u8 = 0x01;
/// Routing block flag: this hop is a rendezvous seat; store under the mailbox.
pub const FLAG_MAILBOX: u8 = 0x02;
/// Routing block flag: this packet is a mailbox fetch.
pub const FLAG_FETCH: u8 = 0x04;
const FLAGS_KNOWN: u8 = FLAG_FINAL | FLAG_MAILBOX | FLAG_FETCH;

/// A hop's public onion hop key (CC 3.3.6.2 `onion_hop_pubkeys`): an X-Wing
/// public key's two halves.
#[derive(Clone, PartialEq, Eq)]
pub struct HopKey {
    /// X25519 public key (`pk_X`).
    pub x25519: [u8; 32],
    /// ML-KEM-768 encapsulation key (`pk_M`).
    pub ml_kem_768: Box<[u8; ml_kem::ML_KEM_768_PUBKEY_LEN]>,
}

impl std::fmt::Debug for HopKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopKey").finish_non_exhaustive()
    }
}

impl HopKey {
    /// The X-Wing public key bytes, `pk_M ‖ pk_X` (draft-06 order).
    #[must_use]
    pub fn xwing_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(XWING_PK);
        v.extend_from_slice(&self.ml_kem_768[..]);
        v.extend_from_slice(&self.x25519);
        v
    }

    fn libcrux(&self) -> Result<libcrux_kem::PublicKey, OnionError> {
        libcrux_kem::PublicKey::decode(libcrux_kem::Algorithm::XWingKemDraft06, &self.xwing_bytes())
            .map_err(|e| OnionError::Crypto(format!("x-wing public key: {e:?}")))
    }
}

/// The two forms a hop's private key may take.
enum SecretForm {
    /// The X-Wing draft's own private key: a 32-byte seed, expanded with
    /// SHAKE256 by the draft.
    Seed(Zeroizing<[u8; 32]>),
    /// The expanded halves: an ML-KEM-768 `d ‖ z` keygen seed and an X25519
    /// scalar (the shape transit custody holds, CIRISEdge#805).
    Split {
        ml_kem_dz: Zeroizing<[u8; 64]>,
        x25519: Zeroizing<[u8; 32]>,
    },
}

/// A relay's onion hop secret and its public key.
pub struct HopSecret {
    form: SecretForm,
    public: HopKey,
}

impl std::fmt::Debug for HopSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HopSecret").finish_non_exhaustive()
    }
}

fn split_public(pk: &[u8]) -> Result<HopKey, OnionError> {
    if pk.len() != XWING_PK {
        return Err(OnionError::Malformed("x-wing public key length"));
    }
    let mut ml = Box::new([0u8; ml_kem::ML_KEM_768_PUBKEY_LEN]);
    ml.copy_from_slice(&pk[..ml_kem::ML_KEM_768_PUBKEY_LEN]);
    let mut x = [0u8; 32];
    x.copy_from_slice(&pk[ml_kem::ML_KEM_768_PUBKEY_LEN..]);
    Ok(HopKey {
        x25519: x,
        ml_kem_768: ml,
    })
}

impl HopSecret {
    /// The X-Wing key pair of a 32-byte draft seed (`KeyGen` of draft-06,
    /// through libcrux).
    ///
    /// # Errors
    /// [`OnionError::Crypto`] from libcrux.
    pub fn from_xwing_seed(seed: &[u8; 32]) -> Result<Self, OnionError> {
        let (_, pk) = libcrux_kem::key_gen_derand(libcrux_kem::Algorithm::XWingKemDraft06, seed)
            .map_err(|e| OnionError::Crypto(format!("x-wing keygen: {e:?}")))?;
        Ok(Self {
            public: split_public(&pk.encode())?,
            form: SecretForm::Seed(Zeroizing::new(*seed)),
        })
    }

    /// A hop secret from custody's 64-byte root seed: the X-Wing seed is
    /// `HKDF-SHA3-256(root, salt = "", info = "ciris-onion-hop/v1/xwing-seed", 32)`.
    ///
    /// # Errors
    /// [`OnionError::Crypto`] from the primitives.
    pub fn from_root_seed(root: &[u8; 64]) -> Result<Self, OnionError> {
        let s = Zeroizing::new(
            kdf::hkdf_sha3_256(root, b"", b"ciris-onion-hop/v1/xwing-seed", 32).map_err(crypto)?,
        );
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&s);
        Self::from_xwing_seed(&seed)
    }

    /// A hop secret in the split form: the ML-KEM-768 `d ‖ z` seed and the
    /// X25519 scalar, with the public halves they produce. This is how a node
    /// decapsulates to a hop key it holds as today's transit pair (the
    /// stand-in accessor, `crate::onion::hop_key`).
    ///
    /// # Errors
    /// [`OnionError::Crypto`] from the primitives.
    pub fn from_split(ml_kem_dz: &[u8; 64], x25519_scalar: &[u8; 32]) -> Result<Self, OnionError> {
        let (_, pk_m) = ml_kem::generate_keypair_deterministic(ml_kem_dz).map_err(crypto)?;
        let mut ml = Box::new([0u8; ml_kem::ML_KEM_768_PUBKEY_LEN]);
        if pk_m.len() != ml.len() {
            return Err(OnionError::Malformed("ml-kem public key length"));
        }
        ml.copy_from_slice(&pk_m);
        Ok(Self {
            public: HopKey {
                x25519: x25519::public_from_secret(x25519_scalar),
                ml_kem_768: ml,
            },
            form: SecretForm::Split {
                ml_kem_dz: Zeroizing::new(*ml_kem_dz),
                x25519: Zeroizing::new(*x25519_scalar),
            },
        })
    }

    /// The split form of an X-Wing seed, expanded exactly as draft-06 does
    /// (`SHAKE256(seed, 96)`: the first 64 bytes are ML-KEM's `d ‖ z`, the
    /// last 32 the X25519 scalar). For the cross-form witness.
    ///
    /// # Errors
    /// As [`Self::from_split`].
    pub fn split_of_xwing_seed(seed: &[u8; 32]) -> Result<Self, OnionError> {
        let mut e = Zeroizing::new(libcrux_sha3::shake256::<96>(seed));
        let mut dz = [0u8; 64];
        dz.copy_from_slice(&e[..64]);
        let mut x = [0u8; 32];
        x.copy_from_slice(&e[64..]);
        e.zeroize();
        let out = Self::from_split(&dz, &x);
        dz.zeroize();
        x.zeroize();
        out
    }

    /// The public hop key published on the signed route row.
    #[must_use]
    pub fn public(&self) -> &HopKey {
        &self.public
    }

    /// X-Wing `Decaps`: the 32-byte shared secret of `ct` (`ct_M ‖ ct_X`).
    fn decapsulate(&self, ct: &[u8; KEM_CT]) -> Result<Zeroizing<[u8; 32]>, OnionError> {
        match &self.form {
            SecretForm::Seed(seed) => {
                let sk = libcrux_kem::PrivateKey::decode(
                    libcrux_kem::Algorithm::XWingKemDraft06,
                    &seed[..],
                )
                .map_err(|_| OnionError::HeaderOpenFailed)?;
                let ct = libcrux_kem::Ct::decode(libcrux_kem::Algorithm::XWingKemDraft06, ct)
                    .map_err(|_| OnionError::HeaderOpenFailed)?;
                let ss = ct
                    .decapsulate(&sk)
                    .map_err(|_| OnionError::HeaderOpenFailed)?;
                let enc = Zeroizing::new(ss.encode());
                let mut out = Zeroizing::new([0u8; 32]);
                if enc.len() != 32 {
                    return Err(OnionError::HeaderOpenFailed);
                }
                out.copy_from_slice(&enc);
                Ok(out)
            }
            SecretForm::Split { ml_kem_dz, x25519 } => {
                let ss_m = Zeroizing::new(
                    ml_kem::decapsulate(&ml_kem_dz[..], &ct[..ML_KEM_CT])
                        .map_err(|_| OnionError::HeaderOpenFailed)?,
                );
                let mut ct_x = [0u8; 32];
                ct_x.copy_from_slice(&ct[ML_KEM_CT..]);
                let ss_x = Zeroizing::new(
                    x25519::dh(x25519, &ct_x).map_err(|_| OnionError::HeaderOpenFailed)?,
                );
                Ok(xwing_combiner(&ss_m, &ss_x, &ct_x, &self.public.x25519))
            }
        }
    }
}

/// The X-Wing draft-06 combiner:
/// `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ "\.//^\")`.
#[must_use]
pub fn xwing_combiner(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> Zeroizing<[u8; 32]> {
    let mut buf = Zeroizing::new([0u8; 32 * 4 + 6]);
    buf[..32].copy_from_slice(ss_m);
    buf[32..64].copy_from_slice(ss_x);
    buf[64..96].copy_from_slice(ct_x);
    buf[96..128].copy_from_slice(pk_x);
    buf[128..].copy_from_slice(&XWING_LABEL);
    Zeroizing::new(libcrux_sha3::sha256(&buf[..]))
}

/// One hop's routing instructions: where to send next and what to do.
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
    fn encode(&self, commit: &[u8; COMMIT]) -> [u8; BLOCK_PLAIN] {
        let mut b = [0u8; BLOCK_PLAIN];
        b[..16].copy_from_slice(&self.next_dest);
        b[16] = self.flags;
        b[17..19].copy_from_slice(&self.delay_ms.to_be_bytes());
        b[19..23].copy_from_slice(&self.period.to_be_bytes());
        b[23..23 + COMMIT].copy_from_slice(commit);
        b
    }

    fn decode(b: &[u8]) -> Result<(Self, [u8; COMMIT]), OnionError> {
        if b.len() != BLOCK_PLAIN || b[23 + COMMIT..].iter().any(|&x| x != 0) {
            return Err(OnionError::Malformed("routing block"));
        }
        if b[16] & !FLAGS_KNOWN != 0 {
            return Err(OnionError::Malformed("routing block flags"));
        }
        let mut next_dest = [0u8; 16];
        next_dest.copy_from_slice(&b[..16]);
        let mut commit = [0u8; COMMIT];
        commit.copy_from_slice(&b[23..23 + COMMIT]);
        Ok((
            Self {
                next_dest,
                flags: b[16],
                delay_ms: u16::from_be_bytes([b[17], b[18]]),
                period: u32::from_be_bytes([b[19], b[20], b[21], b[22]]),
            },
            commit,
        ))
    }

    /// Whether this hop is the end of the route (it forwards nothing).
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

/// Why an onion operation failed. Named, never silent.
#[derive(Debug, thiserror::Error)]
pub enum OnionError {
    /// A primitive refused.
    #[error("onion crypto: {0}")]
    Crypto(String),
    /// The packet or a field is the wrong shape.
    #[error("onion packet malformed: {0}")]
    Malformed(&'static str),
    /// The routing block did not open under this hop's key.
    #[error("onion routing block did not open (onion_hdr_open_failed)")]
    HeaderOpenFailed,
    /// The slot this hop would forward is not the one its block committed to:
    /// a hop before this one altered later header material.
    #[error("the next hop's slot does not match its commitment (onion_next_slot_mismatch)")]
    NextSlotMismatch,
    /// The body's check failed after every layer came off: some hop altered
    /// the body (or the packet was built wrongly).
    #[error("the onion body's check failed (onion_body_tampered)")]
    BodyTampered,
    /// A route longer than the header holds, or empty.
    #[error("onion route of {0} hops; between 1 and {SLOTS} fit")]
    RouteLength(usize),
    /// A body too large for the fixed body.
    #[error("onion body of {0} bytes; at most {BODY_CAPACITY} fit")]
    BodyTooLarge(usize),
}

impl OnionError {
    /// The stable refusal token.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::HeaderOpenFailed => "onion_hdr_open_failed",
            Self::NextSlotMismatch => "onion_next_slot_mismatch",
            Self::BodyTampered => "onion_body_tampered",
            Self::Crypto(_) | Self::Malformed(_) => "onion_packet_malformed",
            Self::RouteLength(_) => "onion_route_length",
            Self::BodyTooLarge(_) => "onion_body_too_large",
        }
    }
}

fn crypto(e: impl std::fmt::Display) -> OnionError {
    OnionError::Crypto(e.to_string())
}

/// Where a build draws its randomness: the encapsulation seeds and the
/// random header slots. Production draws from `ciris_crypto::random`; the
/// known-answer tests draw from a fixed SHAKE256 stream.
pub trait Entropy {
    /// Fill `buf`.
    ///
    /// # Errors
    /// [`OnionError::Crypto`] when the source refuses.
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), OnionError>;
}

/// `ciris_crypto::random`: refuses when its SP 800-90B health latch has failed.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemEntropy;

impl Entropy for SystemEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), OnionError> {
        ciris_crypto::random::fill(buf).map_err(crypto)
    }
}

/// A deterministic stream: `SHAKE256(seed)` read in order. For known answers
/// only — never for a packet that leaves the node.
pub struct FixedEntropy {
    stream: Vec<u8>,
    at: usize,
}

impl FixedEntropy {
    /// A stream of `len` bytes from `seed`.
    #[must_use]
    pub fn new(seed: &[u8], len: usize) -> Self {
        let mut stream = vec![0u8; len];
        libcrux_sha3::shake256_ema(&mut stream, seed);
        Self { stream, at: 0 }
    }
}

impl Entropy for FixedEntropy {
    fn fill(&mut self, buf: &mut [u8]) -> Result<(), OnionError> {
        let end = self.at + buf.len();
        if end > self.stream.len() {
            return Err(OnionError::Crypto("fixed entropy exhausted".to_owned()));
        }
        buf.copy_from_slice(&self.stream[self.at..end]);
        self.at = end;
        Ok(())
    }
}

/// One hop's derived keys. Zeroized on drop.
pub struct LayerKeys {
    hdr: Zeroizing<[u8; 32]>,
    stream: Zeroizing<[u8; 32]>,
    lioness: Zeroizing<[u8; 128]>,
}

impl std::fmt::Debug for LayerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LayerKeys").finish_non_exhaustive()
    }
}

fn hkdf(ss: &[u8; 32], label: &[u8], n: usize) -> Result<Zeroizing<Vec<u8>>, OnionError> {
    let mut info = CONSTRUCTION_ID.to_vec();
    info.extend_from_slice(label);
    Ok(Zeroizing::new(
        kdf::hkdf_sha3_256(&ss[..], b"", &info, n).map_err(crypto)?,
    ))
}

impl LayerKeys {
    /// The keys of one X-Wing shared secret:
    /// `HKDF-SHA3-256(ikm = ss, salt = "", info = CONSTRUCTION_ID ‖ label)`.
    fn derive(ss: &[u8; 32]) -> Result<Self, OnionError> {
        let mut hdr = Zeroizing::new([0u8; 32]);
        hdr.copy_from_slice(&hkdf(ss, LABEL_HDR, 32)?);
        let mut stream = Zeroizing::new([0u8; 32]);
        stream.copy_from_slice(&hkdf(ss, LABEL_STREAM, 32)?);
        let mut lioness = Zeroizing::new([0u8; 128]);
        lioness.copy_from_slice(&hkdf(ss, LABEL_LIONESS, 128)?);
        Ok(Self {
            hdr,
            stream,
            lioness,
        })
    }

    /// The header stream, `SHAKE256(DS_HEADER_STREAM ‖ k_stream)`, one header long.
    fn header_stream(&self) -> Zeroizing<Vec<u8>> {
        let mut input = DS_HEADER_STREAM.to_vec();
        input.extend_from_slice(&self.stream[..]);
        let mut out = Zeroizing::new(vec![0u8; HEADER]);
        libcrux_sha3::shake256_ema(&mut out, &input);
        input.zeroize();
        out
    }

    fn lk(&self, i: usize) -> &[u8] {
        &self.lioness[i * 32..(i + 1) * 32]
    }
}

fn xor(dst: &mut [u8], ks: &[u8]) {
    for (d, k) in dst.iter_mut().zip(ks) {
        *d ^= k;
    }
}

/// LIONESS stream round: `R ⊕= SHAKE256(DS_LIONESS_STREAM ‖ (L ⊕ k))`.
fn lioness_stream(l: &[u8], k: &[u8], r: &mut [u8]) {
    let mut input = DS_LIONESS_STREAM.to_vec();
    input.extend(l.iter().zip(k).map(|(a, b)| a ^ b));
    let mut ks = Zeroizing::new(vec![0u8; r.len()]);
    libcrux_sha3::shake256_ema(&mut ks, &input);
    input.zeroize();
    xor(r, &ks);
}

/// LIONESS hash round: `L ⊕= SHA3-256(DS_LIONESS_HASH ‖ k ‖ R)`.
fn lioness_hash(k: &[u8], r: &[u8], l: &mut [u8]) {
    let mut input = Vec::with_capacity(DS_LIONESS_HASH.len() + 32 + r.len());
    input.extend_from_slice(DS_LIONESS_HASH);
    input.extend_from_slice(k);
    input.extend_from_slice(r);
    let h = libcrux_sha3::sha256(&input);
    input.zeroize();
    xor(l, &h);
}

/// LIONESS encryption (the sender wraps a layer): stream k1, hash k2,
/// stream k3, hash k4.
fn lioness_encrypt(keys: &LayerKeys, body: &mut [u8]) {
    let (l, r) = body.split_at_mut(LIONESS_L);
    lioness_stream(l, keys.lk(0), r);
    lioness_hash(keys.lk(1), r, l);
    lioness_stream(l, keys.lk(2), r);
    lioness_hash(keys.lk(3), r, l);
}

/// LIONESS decryption (a hop removes its layer): the rounds in reverse.
fn lioness_decrypt(keys: &LayerKeys, body: &mut [u8]) {
    let (l, r) = body.split_at_mut(LIONESS_L);
    lioness_hash(keys.lk(3), r, l);
    lioness_stream(l, keys.lk(2), r);
    lioness_hash(keys.lk(1), r, l);
    lioness_stream(l, keys.lk(0), r);
}

/// The commitment to a slot: the first [`COMMIT`] bytes of
/// `SHA3-256(DS_SLOT_COMMIT ‖ slot)`.
fn slot_commit(slot: &[u8]) -> [u8; COMMIT] {
    let mut input = DS_SLOT_COMMIT.to_vec();
    input.extend_from_slice(slot);
    let h = libcrux_sha3::sha256(&input);
    let mut c = [0u8; COMMIT];
    c.copy_from_slice(&h[..COMMIT]);
    c
}

fn encapsulate(
    to: &HopKey,
    rng: &mut dyn Entropy,
) -> Result<([u8; KEM_CT], LayerKeys), OnionError> {
    let pk = to.libcrux()?;
    let mut eseed = Zeroizing::new([0u8; 64]);
    rng.fill(&mut eseed[..])?;
    let (ss, ct) = pk
        .encapsulate_derand(&eseed[..])
        .map_err(|e| OnionError::Crypto(format!("x-wing encaps: {e:?}")))?;
    let ct_b = ct.encode();
    let ss_b = Zeroizing::new(ss.encode());
    if ct_b.len() != KEM_CT || ss_b.len() != 32 {
        return Err(OnionError::Malformed("x-wing output length"));
    }
    let mut ct_a = [0u8; KEM_CT];
    ct_a.copy_from_slice(&ct_b);
    let mut ss_a = Zeroizing::new([0u8; 32]);
    ss_a.copy_from_slice(&ss_b);
    Ok((ct_a, LayerKeys::derive(&ss_a)?))
}

fn seal_block(
    keys: &LayerKeys,
    ct: &[u8; KEM_CT],
    block: &RoutingBlock,
    commit: &[u8; COMMIT],
) -> Result<Vec<u8>, OnionError> {
    // The header key is unique per encapsulation, so a fixed nonce is sound.
    let mut plain = block.encode(commit);
    let out = aes_gcm::encrypt_aad(&keys.hdr, &[0u8; 12], ct, &plain).map_err(crypto);
    plain.zeroize();
    out
}

fn random_slots(n: usize, rng: &mut dyn Entropy) -> Result<Vec<u8>, OnionError> {
    let mut v = vec![0u8; n * SLOT];
    rng.fill(&mut v)?;
    Ok(v)
}

/// The sender's (or receiver's) per-hop keys for a route it built, outermost
/// first. The sender layers the body with them; a receiver keeps its private
/// route's to remove their body layers at fetch.
pub type RouteKeys = Vec<LayerKeys>;

/// Build a header for `hops` on top of `inner` (the header the last of
/// `hops` hands on: random slots for a standalone route, or a receiver's
/// route blob followed by random slots). Built innermost-out; each block
/// commits to the slot its successor will receive (zero on a final hop).
fn build_header_onto(
    hops: &[HopSpec],
    inner: Vec<u8>,
    rng: &mut dyn Entropy,
) -> Result<(Vec<u8>, RouteKeys), OnionError> {
    if hops.is_empty() || hops.len() > SLOTS {
        return Err(OnionError::RouteLength(hops.len()));
    }
    debug_assert_eq!(inner.len(), HEADER);
    let mut next = inner;
    let mut keys_rev = Vec::with_capacity(hops.len());
    for hop in hops.iter().rev() {
        let (ct, keys) = encapsulate(&hop.key, rng)?;
        let commit = if hop.block.is_final() {
            [0u8; COMMIT]
        } else {
            slot_commit(&next[..SLOT])
        };
        let sealed = seal_block(&keys, &ct, &hop.block, &commit)?;
        let stream = keys.header_stream();
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(&ct);
        header.extend_from_slice(&sealed);
        // The hop will XOR slots 1..6 (plus one zero slot) with its stream
        // and get `next[0..5]` followed by its pad.
        let mut tail = next[..SLOT * (SLOTS - 1)].to_vec();
        xor(&mut tail, &stream[..SLOT * (SLOTS - 1)]);
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
    build_route_blob_with(hops, &mut SystemEntropy)
}

/// [`build_route_blob`] with an explicit entropy source.
///
/// # Errors
/// As [`build_route_blob`].
pub fn build_route_blob_with(
    hops: &[HopSpec],
    rng: &mut dyn Entropy,
) -> Result<(RouteBlob, RouteKeys), OnionError> {
    if hops.is_empty() || hops.len() > SLOTS / 2 {
        return Err(OnionError::RouteLength(hops.len()));
    }
    let inner = random_slots(SLOTS, rng)?;
    let (header, keys) = build_header_onto(hops, inner, rng)?;
    Ok((
        RouteBlob {
            slots: header[..SLOT * (SLOTS / 2)].to_vec(),
        },
        keys,
    ))
}

/// The plaintext body: [`BODY_CHECK`] zero bytes ‖ length (u16 BE) ‖ payload
/// ‖ zero pad.
fn encode_body(payload: &[u8]) -> Result<Vec<u8>, OnionError> {
    if payload.len() > BODY_CAPACITY {
        return Err(OnionError::BodyTooLarge(payload.len()));
    }
    let mut body = vec![0u8; BODY];
    #[allow(clippy::cast_possible_truncation)] // ≤ BODY_CAPACITY < u16::MAX
    let len = payload.len() as u16;
    body[BODY_CHECK..BODY_CHECK + 2].copy_from_slice(&len.to_be_bytes());
    body[BODY_CHECK + 2..BODY_CHECK + 2 + payload.len()].copy_from_slice(payload);
    Ok(body)
}

/// Read a body's payload once every layer is off: the check first, then the
/// length.
///
/// # Errors
/// [`OnionError::BodyTampered`] when the check is not all zero;
/// [`OnionError::Malformed`] for a length past the body.
pub fn open_body(body: &[u8]) -> Result<Vec<u8>, OnionError> {
    if body.len() != BODY {
        return Err(OnionError::Malformed("body length"));
    }
    if body[..BODY_CHECK].iter().any(|&b| b != 0) {
        return Err(OnionError::BodyTampered);
    }
    let len = usize::from(u16::from_be_bytes([body[BODY_CHECK], body[BODY_CHECK + 1]]));
    if len > BODY_CAPACITY {
        return Err(OnionError::Malformed("body payload length"));
    }
    Ok(body[BODY_CHECK + 2..BODY_CHECK + 2 + len].to_vec())
}

fn assemble(header: Vec<u8>, keys: &RouteKeys, payload: &[u8]) -> Result<Vec<u8>, OnionError> {
    let mut body = encode_body(payload)?;
    // Hop 1 removes its layer first, so it is the outermost: wrap innermost
    // (the last hop's) first.
    for k in keys.iter().rev() {
        lioness_encrypt(k, &mut body);
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
    build_packet_with(hops, payload, &mut SystemEntropy)
}

/// [`build_packet`] with an explicit entropy source.
///
/// # Errors
/// As [`build_packet`].
pub fn build_packet_with(
    hops: &[HopSpec],
    payload: &[u8],
    rng: &mut dyn Entropy,
) -> Result<Vec<u8>, OnionError> {
    // Bounds first, before any randomness is drawn.
    if hops.is_empty() || hops.len() > SLOTS {
        return Err(OnionError::RouteLength(hops.len()));
    }
    if payload.len() > BODY_CAPACITY {
        return Err(OnionError::BodyTooLarge(payload.len()));
    }
    let inner = random_slots(SLOTS, rng)?;
    let (header, keys) = build_header_onto(hops, inner, rng)?;
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
    build_packet_onto_blob_with(hops, blob, payload, &mut SystemEntropy)
}

/// [`build_packet_onto_blob`] with an explicit entropy source.
///
/// # Errors
/// As [`build_packet_onto_blob`].
pub fn build_packet_onto_blob_with(
    hops: &[HopSpec],
    blob: &RouteBlob,
    payload: &[u8],
    rng: &mut dyn Entropy,
) -> Result<Vec<u8>, OnionError> {
    if blob.slots.len() != SLOT * (SLOTS / 2) || hops.is_empty() || hops.len() > SLOTS / 2 {
        return Err(OnionError::Malformed("route blob or sender route length"));
    }
    if hops.iter().any(|h| h.block.is_final()) {
        return Err(OnionError::Malformed(
            "a sender hop onto a blob is never final",
        ));
    }
    let mut inner = blob.slots.clone();
    inner.extend(random_slots(SLOTS / 2, rng)?);
    let (header, keys) = build_header_onto(hops, inner, rng)?;
    assemble(header, &keys, payload)
}

/// What a relay learns when it peels its layer.
#[derive(Debug)]
pub struct Peeled {
    /// Its routing instructions.
    pub block: RoutingBlock,
    /// The packet to send to `block.next_dest` (or, on a final hop, the packet
    /// whose body this hop stores).
    pub packet: Vec<u8>,
    /// `SHA3-256(DS_REPLAY ‖ ct)` of this hop's encapsulation: the relay's
    /// replay key (`onion_replay`).
    pub replay_tag: [u8; 32],
}

impl Peeled {
    /// The body of the peeled packet.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.packet[HEADER..]
    }

    /// On a [`FLAG_FINAL`] hop, the payload ([`open_body`]).
    ///
    /// # Errors
    /// [`open_body`]'s.
    pub fn payload(&self) -> Result<Vec<u8>, OnionError> {
        open_body(self.body())
    }
}

/// A relay's step: remove one layer. The acceptance order is the wire
/// document's (`docs/onion_packet_wire.md` §5): length, decapsulation and
/// the routing block's AEAD, the block's shape, the header shift and the body
/// layer, the successor slot's commitment (non-final hops), the body check
/// ([`FLAG_FINAL`] hops). Replay and period are the relay's
/// (`crate::onion::relay`), on the returned tag and block.
///
/// # Errors
/// [`OnionError::Malformed`]; [`OnionError::HeaderOpenFailed`] when the
/// routing block does not open (not this hop's layer, or tampered);
/// [`OnionError::NextSlotMismatch`]; [`OnionError::BodyTampered`].
pub fn peel(secret: &HopSecret, packet: &[u8]) -> Result<Peeled, OnionError> {
    if packet.len() != PACKET {
        return Err(OnionError::Malformed("packet length"));
    }
    let mut ct = [0u8; KEM_CT];
    ct.copy_from_slice(&packet[..KEM_CT]);
    let ss = secret.decapsulate(&ct)?;
    let keys = LayerKeys::derive(&ss)?;
    let mut plain = Zeroizing::new(
        aes_gcm::decrypt_aad(&keys.hdr, &[0u8; 12], &ct, &packet[KEM_CT..SLOT])
            .map_err(|_| OnionError::HeaderOpenFailed)?,
    );
    let (block, commit) = RoutingBlock::decode(&plain)?;
    plain.zeroize();
    let stream = keys.header_stream();
    let mut next = Vec::with_capacity(PACKET);
    let mut rest = packet[SLOT..HEADER].to_vec();
    rest.resize(HEADER, 0);
    xor(&mut rest, &stream);
    next.extend_from_slice(&rest);
    let mut body = packet[HEADER..].to_vec();
    lioness_decrypt(&keys, &mut body);
    next.extend_from_slice(&body);
    if !block.is_final() && slot_commit(&next[..SLOT]) != commit {
        return Err(OnionError::NextSlotMismatch);
    }
    let out = Peeled {
        block,
        packet: next,
        replay_tag: replay_tag(&ct),
    };
    if block.flags & FLAG_FINAL != 0 {
        out.payload()?;
    }
    Ok(out)
}

fn replay_tag(ct: &[u8; KEM_CT]) -> [u8; 32] {
    let mut input = DS_REPLAY.to_vec();
    input.extend_from_slice(ct);
    libcrux_sha3::sha256(&input)
}

/// The receiver's step for a fetched mailbox body: put back the private
/// hops' body layers in reverse (each hop removed one with LIONESS
/// decryption; the receiver re-applies encryption, innermost first), then
/// read it.
///
/// # Errors
/// [`open_body`]'s.
pub fn open_fetched_body(body: &[u8], private_keys: &RouteKeys) -> Result<Vec<u8>, OnionError> {
    if body.len() != BODY {
        return Err(OnionError::Malformed("body length"));
    }
    let mut b = body.to_vec();
    for k in private_keys.iter().rev() {
        lioness_encrypt(k, &mut b);
    }
    open_body(&b)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn relay(n: u8) -> HopSecret {
        HopSecret::from_xwing_seed(&[n; 32]).expect("hop secret")
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

    fn three() -> (HopSecret, HopSecret, HopSecret, [HopSpec; 3]) {
        let (r1, r2, r3) = (relay(1), relay(2), relay(3));
        let hops = [
            spec(&r1, [0x22; 16], 0),
            spec(&r2, [0x33; 16], 0),
            spec(&r3, [0; 16], FLAG_FINAL),
        ];
        (r1, r2, r3, hops)
    }

    /// CLM-onion-route — a three-hop publication: every hop sees one fixed
    /// length, learns only its successor, and the final hop recovers the
    /// payload; no slot 0 repeats across hops.
    #[test]
    fn a_three_hop_publication_peels_in_order_at_one_length() {
        let (r1, r2, r3, hops) = three();
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
        assert_eq!(c.payload().unwrap(), payload);
        assert_ne!(p0[..SLOT], a.packet[..SLOT]);
        assert_ne!(a.packet[..SLOT], b.packet[..SLOT]);
        assert_ne!(a.replay_tag, b.replay_tag);
        assert_eq!(c.block.delay_ms, 2000);
        assert_eq!(c.block.period, 496_000);
        // Before the exit, a hop holding the body sees no plaintext.
        assert!(open_body(a.body()).is_err());
        assert!(open_body(b.body()).is_err());
    }

    /// CC 5.4.6 item 3 binding property (b) — **tagging resistance**: a byte
    /// of the body flipped after hop 1 (at the head, in the middle, at the
    /// end) leaves hop 2 and hop 3 unable to tell, and the exit refuses the
    /// body by name. Hop 2 sees bytes that differ from the untampered run in
    /// almost every position (the whole-body diffusion a wide-block cipher
    /// gives), not in one.
    #[test]
    fn tag_resistance_a_body_byte_flipped_at_hop_one_fails_at_the_exit() {
        let (r1, r2, r3, hops) = three();
        let p0 = build_packet(&hops, b"mark me if you can").unwrap();
        let a = peel(&r1, &p0).unwrap();
        let clean_b = peel(&r2, &a.packet).unwrap();
        for pos in [
            HEADER,
            HEADER + 7,
            HEADER + 31,
            HEADER + 32,
            HEADER + 4000,
            PACKET - 1,
        ] {
            let mut t = a.packet.clone();
            t[pos] ^= 0x01;
            let b = peel(&r2, &t).expect("hop 2 cannot tell");
            let differing = b
                .body()
                .iter()
                .zip(clean_b.body())
                .filter(|(x, y)| x != y)
                .count();
            assert!(
                differing > BODY * 9 / 10,
                "flip at {pos}: only {differing} of {BODY} body bytes changed at hop 2"
            );
            assert!(
                matches!(peel(&r3, &b.packet), Err(OnionError::BodyTampered)),
                "flip at {pos} must fail at the exit"
            );
        }
        assert_eq!(OnionError::BodyTampered.label(), "onion_body_tampered");
    }

    /// Header tagging: a byte of hop 3's slot flipped by hop 1 is caught by
    /// hop 2 (the next honest hop), before the colluding exit sees it.
    #[test]
    fn a_later_hops_slot_altered_at_hop_one_is_refused_by_hop_two() {
        let (r1, r2, _r3, hops) = three();
        let p0 = build_packet(&hops, b"x").unwrap();
        let a = peel(&r1, &p0).unwrap();
        for pos in [SLOT + 5, SLOT + KEM_CT + 3, 2 * SLOT - 1] {
            let mut t = a.packet.clone();
            t[pos] ^= 0x80;
            assert!(
                matches!(peel(&r2, &t), Err(OnionError::NextSlotMismatch)),
                "pos {pos}"
            );
        }
        // Hop 2's own slot tampered: its block does not open.
        let mut t = a.packet.clone();
        t[KEM_CT + 1] ^= 1;
        assert!(matches!(peel(&r2, &t), Err(OnionError::HeaderOpenFailed)));
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
        assert!(matches!(peel(&r1, &c), Err(OnionError::HeaderOpenFailed)));
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
    /// receiver's three-hop route blob. Six peels, the sixth at the
    /// rendezvous seat with the mailbox flag; the seat cannot read it, the
    /// receiver alone removes the private layers.
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
        assert!(open_body(last.body()).is_err(), "the seat cannot read it");
        assert_eq!(
            open_fetched_body(last.body(), &private_keys).unwrap(),
            payload
        );
        // A body tampered at the seat fails at the receiver.
        let mut t = last.body().to_vec();
        t[100] ^= 1;
        assert!(matches!(
            open_fetched_body(&t, &private_keys),
            Err(OnionError::BodyTampered)
        ));
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
        let full = vec![7u8; BODY_CAPACITY];
        let p = build_packet(&[spec(&r, [0; 16], FLAG_FINAL)], &full).unwrap();
        assert_eq!(peel(&r, &p).unwrap().payload().unwrap(), full);
    }

    #[test]
    fn a_hop_secret_is_deterministic_from_its_seed() {
        assert_eq!(relay(1).public(), relay(1).public());
        assert_ne!(relay(1).public(), relay(2).public());
        let root = [9u8; 64];
        assert_eq!(
            HopSecret::from_root_seed(&root).unwrap().public(),
            HopSecret::from_root_seed(&root).unwrap().public()
        );
    }

    // ─── Known answers (for the CC submission; docs/onion_packet_wire.md §8) ───

    const KAT_SEED: &[u8] = b"CIRIS outfox-xwing-v1 KAT 2026-11-01";

    fn hex32(b: &[u8]) -> String {
        hex::encode(libcrux_sha3::sha256(b))
    }

    /// Binding property (a): the split form (ML-KEM-768 via ciris-crypto's
    /// RustCrypto `ml-kem`, X25519 via `x25519-dalek`, the combiner computed
    /// here) and the draft's seed form (libcrux end to end) give the same
    /// public key and the same shared secret for the same ciphertext. Two
    /// independent ML-KEM implementations and two computations of the draft
    /// combiner agree byte for byte.
    #[test]
    fn kat_split_and_seed_forms_agree() {
        for n in 0u8..4 {
            let seed = libcrux_sha3::sha256(&[KAT_SEED, &[n]].concat());
            let a = HopSecret::from_xwing_seed(&seed).unwrap();
            let b = HopSecret::split_of_xwing_seed(&seed).unwrap();
            assert_eq!(a.public(), b.public(), "public keys, seed {n}");
            let mut rng = FixedEntropy::new(&[KAT_SEED, b"/encaps", &[n]].concat(), 64);
            let (ct, _) = encapsulate(a.public(), &mut rng).unwrap();
            assert_eq!(
                *a.decapsulate(&ct).unwrap(),
                *b.decapsulate(&ct).unwrap(),
                "shared secrets, seed {n}"
            );
        }
    }

    /// Fixed-seed known answers: one X-Wing encapsulation (the shared secret
    /// and the ciphertext's SHA3-256), the derived keys' SHA3-256, and a whole
    /// three-hop publication's SHA3-256 at every hop. Regenerate with
    /// `ONION_KAT_PRINT=1` only when the construction identifier changes.
    #[test]
    fn kat_outfox_xwing_v1() {
        let seeds: Vec<[u8; 32]> = (1u8..=3)
            .map(|n| libcrux_sha3::sha256(&[KAT_SEED, b"/hop", &[n]].concat()))
            .collect();
        let hops_s: Vec<HopSecret> = seeds
            .iter()
            .map(|s| HopSecret::from_xwing_seed(s).unwrap())
            .collect();
        // One encapsulation.
        let mut rng = FixedEntropy::new(&[KAT_SEED, b"/encaps"].concat(), 64);
        let mut eseed = [0u8; 64];
        rng.fill(&mut eseed).unwrap();
        let (ss, ct) = hops_s[0]
            .public()
            .libcrux()
            .unwrap()
            .encapsulate_derand(&eseed)
            .unwrap();
        let ss = ss.encode();
        let ct = ct.encode();
        let mut ss_a = [0u8; 32];
        ss_a.copy_from_slice(&ss);
        let k = LayerKeys::derive(&ss_a).unwrap();
        let mut keys = Vec::new();
        keys.extend_from_slice(&k.hdr[..]);
        keys.extend_from_slice(&k.stream[..]);
        keys.extend_from_slice(&k.lioness[..]);

        let hops = [
            spec(&hops_s[0], [0x22; 16], 0),
            spec(&hops_s[1], [0x33; 16], 0),
            spec(&hops_s[2], [0; 16], FLAG_FINAL),
        ];
        let mut rng = FixedEntropy::new(&[KAT_SEED, b"/packet"].concat(), 16 * 1024);
        let p0 = build_packet_with(&hops, b"CIRIS onion KAT payload", &mut rng).unwrap();
        let a = peel(&hops_s[0], &p0).unwrap();
        let b = peel(&hops_s[1], &a.packet).unwrap();
        let c = peel(&hops_s[2], &b.packet).unwrap();
        assert_eq!(c.payload().unwrap(), b"CIRIS onion KAT payload");

        let got = [
            ("hop1_pk_sha3", hex32(&hops_s[0].public().xwing_bytes())),
            ("encaps_ss", hex::encode(&ss)),
            ("encaps_ct_sha3", hex32(&ct)),
            ("layer_keys_sha3", hex32(&keys)),
            ("packet_hop1_sha3", hex32(&p0)),
            ("packet_hop2_sha3", hex32(&a.packet)),
            ("packet_hop3_sha3", hex32(&b.packet)),
            ("exit_body_sha3", hex32(c.body())),
            ("replay_tag_hop1", hex::encode(a.replay_tag)),
        ];
        if std::env::var_os("ONION_KAT_PRINT").is_some() {
            for (k, v) in &got {
                println!("KAT {k} = {v}");
            }
        }
        for ((name, got), want) in got.iter().zip(KAT_EXPECTED) {
            assert_eq!(got, want, "KAT {name}");
        }
    }

    const KAT_EXPECTED: [&str; 9] = [
        "ea7ad961f646e19457f1d666f48ea2b7e244090a13745129743b1cc337a8d4a8", // hop1_pk_sha3
        "ffde16940725ed13e97b2cf083082d66e5c04e55977cfb570093df0ab17002fd", // encaps_ss
        "e8f9c18b704a22bf63686b93ae1d5f5feea82602407eecc6ead04af98c53f902", // encaps_ct_sha3
        "18313dcac98e9196e2f04b0fd2898586f2a270c5da220394d2eacac92a766ca2", // layer_keys_sha3
        "e9faf4a79667150531566b987426f0c8807c0d798851a79135ca0a603aa25bd0", // packet_hop1_sha3
        "c3e8e62224e83975787f33a7ddf197507fe63a626936edf8c5162948fce235ef", // packet_hop2_sha3
        "51b0365613b76361d936751fabc0eea7e3f0449e879caeafeccfcc221faa4ad5", // packet_hop3_sha3
        "13e3ef27d46cab4f8cde8cfce6b423447408fd94e0bdffdee4fcee11f87d8386", // exit_body_sha3
        "d4005ef344b5bacd6c0a0dfa36f869cbd9f6b4a50fa2a3811e351be1ae7ce005", // replay_tag_hop1
    ];
}
