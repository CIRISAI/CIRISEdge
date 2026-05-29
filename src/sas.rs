//! Short Authentication String (SAS) helpers — CIRISEdge#47, v0.17.0.
//!
//! Mission: give two operators a short, memorable, human-readable
//! representation of their shared identity tuple so they can verbally
//! confirm out-of-band that they are talking to the right peer. The
//! purpose is MITM-resistance for the federation-key bootstrap path:
//! an attacker who substitutes a different 32-byte pubkey would
//! produce a different SAS, observable as soon as the two operators
//! compare strings.
//!
//! # Locked decisions
//!
//! - **Hash**: SHA-256 (already in deps via `sha2`). No BLAKE3.
//! - **Wordlist**: BIP39 English (2048 words = 11 bits each;
//!   5 words ≈ 55 bits, matching CIRISEdge#47's stated entropy bar).
//! - **Order independence**: concatenate `local_pub || peer_pub` then
//!   `sort` before hashing so `peer_sas(A, B) == peer_sas(B, A)` —
//!   neither operator has to know who is "local".
//! - **Protocol constant**: [`CIRIS_SAS_PROTOCOL_CONSTANT`] — a
//!   versioned ASCII tag. Locks the wire-spec; bump `v1 → v2` to
//!   roll if the algorithm ever changes (algorithm + constant is the
//!   wire shape; both must stay stable across edge versions to
//!   preserve the verbal-comparison contract).
//!
//! # Determinism
//!
//! The derivation is a pure function of the two pubkeys + the
//! protocol constant — no clock, no randomness. Same inputs always
//! produce the same output. Regression-protected by
//! [`tests::peer_sas_protocol_constant_locked`] (asserts the exact
//! byte string) and the round-trip tests below.

use std::collections::HashMap;

use sha2::{Digest, Sha256};

/// Protocol-version-tagged constant mixed into the SAS hash. The
/// trailing `::v1` lets a future protocol revision break cleanly
/// (`b"ciris-edge::peer-sas::v2\0"`) without breaking the v1
/// implementation.
///
/// Locked at v0.17.0; DO NOT change without bumping the version tag.
pub const CIRIS_SAS_PROTOCOL_CONSTANT: &[u8] = b"ciris-edge::peer-sas::v1\0";

/// Default word count for [`peer_sas`]. Five BIP39 words × 11 bits each
/// = 55 bits of entropy, the bar called out in CIRISEdge#47.
pub const DEFAULT_SAS_WORDS: usize = 5;

/// Default digit count for [`peer_sas_digits`]. Six decimal digits ≈
/// 19.93 bits of entropy — the same bar as a six-digit
/// authentication code (TOTP / SAS over Signal).
pub const DEFAULT_SAS_DIGITS: usize = 6;

/// Compute the 32-byte SAS digest for a `(local_pub, peer_pub)` pair.
///
/// Pure function — order-independent, deterministic.
///
/// 1. Concatenate the two pubkeys.
/// 2. Sort the concatenation (so swapping the two inputs yields the
///    same digest — neither operator has to know who is "local").
/// 3. Append [`CIRIS_SAS_PROTOCOL_CONSTANT`].
/// 4. SHA-256 the whole thing.
#[must_use]
pub fn peer_sas_digest(local_pub: &[u8; 32], peer_pub: &[u8; 32]) -> [u8; 32] {
    let mut buf: Vec<u8> = Vec::with_capacity(64 + CIRIS_SAS_PROTOCOL_CONSTANT.len());
    buf.extend_from_slice(local_pub);
    buf.extend_from_slice(peer_pub);
    buf.sort_unstable();
    buf.extend_from_slice(CIRIS_SAS_PROTOCOL_CONSTANT);
    let digest = Sha256::digest(&buf);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Render the SAS digest as `words` BIP39-English words. The default
/// (5 words) gives ≈55 bits of entropy.
///
/// 11 bits per word; we walk the digest as a bitstream, reading 11
/// bits at a time and indexing into the BIP39 English wordlist
/// (2048 entries). `words` must be in `1..=23` (23 × 11 = 253 bits ≤
/// 256 bits of digest).
///
/// # Errors
///
/// Returns `Err(SasError::WordsOutOfRange)` if `words == 0` or
/// `words > 23`.
pub fn peer_sas_words(
    local_pub: &[u8; 32],
    peer_pub: &[u8; 32],
    words: usize,
) -> Result<Vec<String>, SasError> {
    if words == 0 || words > 23 {
        return Err(SasError::WordsOutOfRange(words));
    }
    let digest = peer_sas_digest(local_pub, peer_pub);
    let wordlist = bip39::Language::English.word_list();
    let mut out = Vec::with_capacity(words);
    for i in 0..words {
        let bit_offset = i * 11;
        let byte_offset = bit_offset / 8;
        let bit_in_byte = bit_offset % 8;
        // Read 11 bits starting at `bit_offset`. SHA-256 is 256 bits,
        // 23 words × 11 = 253 bits, so we have at most 3 bits of
        // headroom; the 3-byte window covers the read in all cases.
        let b0 = u32::from(digest[byte_offset]);
        let b1 = u32::from(digest[byte_offset + 1]);
        let b2 = u32::from(digest[byte_offset + 2]);
        let chunk = (b0 << 16) | (b1 << 8) | b2;
        // Shift right to drop the bits below our 11-bit window, then
        // mask the high 11 bits.
        let shift = 24 - 11 - bit_in_byte;
        let index = ((chunk >> shift) & 0x7FF) as usize;
        out.push(wordlist[index].to_string());
    }
    Ok(out)
}

/// Render the SAS digest as a zero-padded `digits`-digit decimal
/// string. The default (6 digits) gives ≈19.93 bits of entropy —
/// the same bar as TOTP / Signal's SAS.
///
/// Reads `ceil(digits * log2(10))` ≈ `digits * 3.4` bits from the
/// digest (rounded up to whole bytes), takes the value `mod 10^digits`,
/// and zero-pads to `digits` characters.
///
/// # Errors
///
/// Returns `Err(SasError::DigitsOutOfRange)` if `digits == 0` or
/// `digits > 19` (19 decimal digits ≤ `u64::MAX`).
pub fn peer_sas_digits(
    local_pub: &[u8; 32],
    peer_pub: &[u8; 32],
    digits: usize,
) -> Result<String, SasError> {
    if digits == 0 || digits > 19 {
        return Err(SasError::DigitsOutOfRange(digits));
    }
    let digest = peer_sas_digest(local_pub, peer_pub);
    // First 8 bytes → u64; mod 10^digits → decimal string.
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&digest[..8]);
    let n = u64::from_be_bytes(raw);
    let modulus = 10u64.pow(u32::try_from(digits).expect("digits <= 19 fits in u32"));
    let value = n % modulus;
    Ok(format!("{value:0>digits$}"))
}

/// SAS-derivation errors.
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq)]
pub enum SasError {
    /// `words` argument out of `1..=23` range.
    #[error("peer_sas words must be in 1..=23, got {0}")]
    WordsOutOfRange(usize),
    /// `digits` argument out of `1..=19` range.
    #[error("peer_sas_digits digits must be in 1..=19, got {0}")]
    DigitsOutOfRange(usize),
    /// Peer lookup miss — the caller asked for a `peer_key_id` not in
    /// the federation directory. Surfaced from
    /// [`PeerKeyResolver::resolve_peer_pubkey`].
    #[error("peer key_id not found in federation directory: {0:?}")]
    PeerNotFound(String),
}

/// Trait used by the PyO3 `peer_sas` pyfunction to resolve a
/// `peer_key_id` to a 32-byte Ed25519 pubkey. Lives at module scope
/// so non-FFI consumers can also drive the SAS derivation against
/// any directory implementation.
#[async_trait::async_trait]
pub trait PeerKeyResolver: Send + Sync {
    /// Resolve `peer_key_id` to the 32-byte Ed25519 public key.
    /// `Err(SasError::PeerNotFound)` on directory miss.
    async fn resolve_peer_pubkey(&self, peer_key_id: &str) -> Result<[u8; 32], SasError>;
}

/// In-memory `PeerKeyResolver` — used by unit tests to drive the
/// derivation without standing up a real federation directory.
#[doc(hidden)]
pub struct StaticPeerKeyResolver {
    map: HashMap<String, [u8; 32]>,
}

impl StaticPeerKeyResolver {
    #[must_use]
    pub fn new(map: HashMap<String, [u8; 32]>) -> Self {
        Self { map }
    }
}

#[async_trait::async_trait]
impl PeerKeyResolver for StaticPeerKeyResolver {
    async fn resolve_peer_pubkey(&self, peer_key_id: &str) -> Result<[u8; 32], SasError> {
        self.map
            .get(peer_key_id)
            .copied()
            .ok_or_else(|| SasError::PeerNotFound(peer_key_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pub_a() -> [u8; 32] {
        [0x11; 32]
    }
    fn pub_b() -> [u8; 32] {
        [0x22; 32]
    }

    /// Determinism — same inputs always produce same words.
    #[test]
    fn peer_sas_deterministic_round_trip() {
        let a = pub_a();
        let b = pub_b();
        let w1 = peer_sas_words(&a, &b, 5).expect("5 words");
        let w2 = peer_sas_words(&a, &b, 5).expect("5 words again");
        assert_eq!(w1, w2);
    }

    /// Order independence — swapping the inputs yields the same SAS.
    /// This is the load-bearing property: neither operator needs to
    /// know who is "local" in the verbal-comparison protocol.
    #[test]
    fn peer_sas_order_independent() {
        let a = pub_a();
        let b = pub_b();
        let forward = peer_sas_words(&a, &b, 5).expect("forward");
        let reverse = peer_sas_words(&b, &a, 5).expect("reverse");
        assert_eq!(
            forward, reverse,
            "peer_sas MUST be order-independent (local↔peer swap = same words)"
        );
    }

    /// Default 5 words give ≈55 bits of entropy. We don't check the
    /// entropy figure directly (that's a property of the algorithm,
    /// not a runtime invariant), but we DO check the count.
    #[test]
    fn peer_sas_default_words_is_5_giving_55_bits() {
        let words = peer_sas_words(&pub_a(), &pub_b(), DEFAULT_SAS_WORDS).expect("default words");
        assert_eq!(words.len(), DEFAULT_SAS_WORDS);
        assert_eq!(DEFAULT_SAS_WORDS * 11, 55, "5 words × 11 bits = 55 bits");
        // All words must be from the BIP39 English wordlist.
        let wordlist: std::collections::HashSet<&str> = bip39::Language::English
            .word_list()
            .iter()
            .copied()
            .collect();
        for w in &words {
            assert!(
                wordlist.contains(w.as_str()),
                "word {w:?} must be in BIP39 English wordlist"
            );
        }
    }

    /// Default 6-digit output is zero-padded decimal.
    #[test]
    fn peer_sas_digits_default_6_zero_padded() {
        let s = peer_sas_digits(&pub_a(), &pub_b(), DEFAULT_SAS_DIGITS).expect("default digits");
        assert_eq!(s.len(), DEFAULT_SAS_DIGITS);
        assert!(
            s.chars().all(|c| c.is_ascii_digit()),
            "digits string must be all ASCII digits: {s:?}"
        );
    }

    /// Digits path is order-independent too.
    #[test]
    fn peer_sas_digits_order_independent() {
        let forward = peer_sas_digits(&pub_a(), &pub_b(), 6).expect("forward");
        let reverse = peer_sas_digits(&pub_b(), &pub_a(), 6).expect("reverse");
        assert_eq!(forward, reverse);
    }

    /// Protocol constant lock — regression guard against silent
    /// algorithm drift. If the constant ever changes, every existing
    /// `peer_sas(A, B)` shifts, breaking the verbal-comparison
    /// contract across edge versions.
    #[test]
    fn peer_sas_protocol_constant_locked() {
        assert_eq!(
            CIRIS_SAS_PROTOCOL_CONSTANT, b"ciris-edge::peer-sas::v1\0",
            "DO NOT change CIRIS_SAS_PROTOCOL_CONSTANT — bump v1->v2 instead",
        );
        assert_eq!(CIRIS_SAS_PROTOCOL_CONSTANT.len(), 25);
    }

    /// Different inputs → different SAS (with overwhelming probability —
    /// SHA-256 collisions are not a thing we worry about).
    #[test]
    fn peer_sas_different_keys_different_sas() {
        let a = pub_a();
        let b = pub_b();
        let c = [0x33; 32];
        let ab = peer_sas_words(&a, &b, 5).expect("ab");
        let ac = peer_sas_words(&a, &c, 5).expect("ac");
        assert_ne!(
            ab, ac,
            "different peer keys MUST produce different SAS words"
        );
    }

    /// `peer_sas_digest` produces the canonical 32-byte SHA-256 of
    /// the sorted-concat + protocol-constant input. Algorithm-level
    /// pin so a refactor that changes the order of operations would
    /// trip immediately.
    #[test]
    fn peer_sas_digest_matches_canonical_recipe() {
        let a = pub_a();
        let b = pub_b();
        // Manual recipe (mirrors the function body) — sort the
        // concatenation, then SHA-256 with the protocol constant
        // tail.
        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(&a);
        buf.extend_from_slice(&b);
        buf.sort_unstable();
        buf.extend_from_slice(CIRIS_SAS_PROTOCOL_CONSTANT);
        let expected: [u8; 32] = Sha256::digest(&buf).into();
        let actual = peer_sas_digest(&a, &b);
        assert_eq!(actual, expected);
    }

    /// Out-of-range word counts surface a typed error.
    #[test]
    fn peer_sas_words_out_of_range_is_error() {
        assert!(matches!(
            peer_sas_words(&pub_a(), &pub_b(), 0),
            Err(SasError::WordsOutOfRange(0))
        ));
        assert!(matches!(
            peer_sas_words(&pub_a(), &pub_b(), 24),
            Err(SasError::WordsOutOfRange(24))
        ));
    }

    /// Out-of-range digit counts surface a typed error.
    #[test]
    fn peer_sas_digits_out_of_range_is_error() {
        assert!(matches!(
            peer_sas_digits(&pub_a(), &pub_b(), 0),
            Err(SasError::DigitsOutOfRange(0))
        ));
        assert!(matches!(
            peer_sas_digits(&pub_a(), &pub_b(), 20),
            Err(SasError::DigitsOutOfRange(20))
        ));
    }

    /// Resolver miss surfaces `PeerNotFound`. Exercises the public
    /// `PeerKeyResolver` trait via the `StaticPeerKeyResolver` test
    /// stub so the PyO3 pyfunction's error shape is pinned by a
    /// non-pyo3 test.
    #[tokio::test]
    async fn peer_sas_unknown_peer_returns_value_error() {
        let resolver = StaticPeerKeyResolver::new(HashMap::new());
        let err = resolver
            .resolve_peer_pubkey("nonexistent-peer")
            .await
            .expect_err("unknown peer must error");
        assert!(matches!(err, SasError::PeerNotFound(_)));
    }
}
