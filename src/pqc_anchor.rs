//! CC 5.3.3.5 item 6 (constitution a22e42e), form CC 2.6.8 — the PQC
//! commitment a dialler held BEFORE it dialled (CIRISEdge#964).
//!
//! A `key:record:v1` row that arrives in the pre-seal route fetch (`CTKA`)
//! authenticates nothing by itself: persist's key door checks proof of
//! possession and the #1103 Ed25519 fingerprint, and nothing there binds the
//! ML-DSA-65 half. A `CIRIS-V3-` code carries that binding — `sha256(raw
//! ML-DSA-65 pubkey)`, 64 lowercase hex — and this module is where the
//! commitment a caller decoded waits between the contact call
//! ([`crate::contact::resolve_contact_with_commitment`],
//! [`crate::contact::discover_with_commitment`]) and the dial that first
//! fetches or reads the peer's record.
//!
//! # What is checked, and with what
//!
//! One rule, shared with CIRISServer: [`check_ml_dsa_65`] calls
//! `ciris_verify_core::fedcode::verify_pulled_ml_dsa_65_pubkey` and nothing
//! else decides a match. A record with no ML-DSA half, or one that will not
//! decode, cannot satisfy a commitment and is a mismatch.
//!
//! # Additive only (the 2.6.1.8 migration)
//!
//! With no anchor for a key, [`check_ml_dsa_65`] answers [`Anchor::None`] and
//! every caller behaves exactly as before. Refusing a fetched record that has
//! NO anchor is item 6's fail-closed half and is normative only with the v62
//! handshake, after v3 codes are minted in the field; it is not done here.
//!
//! # Scope and bounds
//!
//! The registry is process-wide. A commitment is a fact about a KEY (the hash
//! of that key's own ML-DSA half), not about the node that was told it, so a
//! true commitment is true for every transport in the process; one process is
//! one node in production. It is bounded by [`ANCHOR_CAP`] (the oldest entry is
//! evicted) and [`ANCHOR_TTL`], and an entry is cleared once a record that
//! matched it is admitted and its pair used — after that the record is held, and a held record is
//! itself an anchor (5.3.3.5 item 6 (2)). A mismatch does not clear it: a
//! retried dial against the same forged record is refused the same way until
//! the TTL lapses.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Hex characters in an API-form commitment (`sha256` = 32 bytes).
pub const PQC_COMMITMENT_HEX_LEN: usize = 64;

/// How long a commitment waits for the dial that uses it. A contact is often
/// added well before its first message; an hour covers that without keeping
/// a stale anchor indefinitely.
pub const ANCHOR_TTL: Duration = Duration::from_secs(60 * 60);

/// Most commitments held at once. Each is set by a person adding a contact,
/// so the cap is a backstop, not a working limit.
pub const ANCHOR_CAP: usize = 1024;

/// The stable refusal token for a record whose ML-DSA-65 half does not hash to
/// the pre-held commitment (the route-fetch metric label is
/// [`crate::observability::LINK_SEAL_REFUSED_ROUTE_ANSWER_PQC_COMMITMENT`]).
pub const PQC_COMMITMENT_MISMATCH: &str = "pqc_commitment_mismatch";

/// A well-formed API-form commitment: exactly 64 lowercase hex characters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PqcCommitment(String);

impl PqcCommitment {
    /// Parse an API-form commitment. Rejected, never repaired: uppercase is
    /// not lowered, whitespace is not trimmed, a short digest is not padded —
    /// two spellings of one identity must not both be accepted (CC 2.6.8).
    ///
    /// # Errors
    /// A description of what is wrong with `raw`.
    pub fn parse(raw: &str) -> Result<Self, String> {
        if raw.len() != PQC_COMMITMENT_HEX_LEN {
            return Err(format!(
                "pqc_commitment must be {PQC_COMMITMENT_HEX_LEN} lowercase hex characters, got {}",
                raw.len()
            ));
        }
        if !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(
                "pqc_commitment must be lowercase hex (0-9, a-f); it is rejected, never repaired"
                    .to_owned(),
            );
        }
        Ok(Self(raw.to_owned()))
    }

    /// The commitment, as 64 lowercase hex characters.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// What the pre-held commitment says about one record's ML-DSA-65 half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Anchor {
    /// No commitment is held for the key: behave exactly as before.
    None,
    /// The ML-DSA-65 half hashes to the commitment.
    Matched,
    /// It does not (or the record carries no decodable ML-DSA-65 half).
    Mismatch(String),
}

struct Entry {
    commitment: PqcCommitment,
    at: Instant,
    /// Insertion order: eviction drops the lowest, so two entries made in
    /// the same clock tick still evict deterministically.
    seq: u64,
}

/// The bounded commitment store. The process uses one ([`anchor`],
/// [`pending`], [`clear`], [`check_ml_dsa_65`]); a test builds its own so
/// filling it to the cap never touches another test's anchors.
pub struct AnchorRegistry {
    map: Mutex<HashMap<String, Entry>>,
    next_seq: AtomicU64,
    cap: usize,
    ttl: Duration,
}

impl AnchorRegistry {
    /// An empty store holding at most `cap` commitments, each for `ttl`.
    #[must_use]
    pub fn new(cap: usize, ttl: Duration) -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
            next_seq: AtomicU64::new(0),
            cap: cap.max(1),
            ttl,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Entry>> {
        self.map
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// See [`anchor`].
    pub fn anchor(&self, key_id: &str, commitment: PqcCommitment) {
        let now = Instant::now();
        let ttl = self.ttl;
        let mut reg = self.lock();
        reg.retain(|_, e| now.duration_since(e.at) < ttl);
        if !reg.contains_key(key_id) && reg.len() >= self.cap {
            if let Some(oldest) = reg
                .iter()
                .min_by_key(|(_, e)| e.seq)
                .map(|(k, _)| k.clone())
            {
                reg.remove(&oldest);
            }
        }
        if reg
            .get(key_id)
            .is_some_and(|prev| prev.commitment != commitment)
        {
            tracing::info!(
                key_id,
                "pqc anchor: a new commitment replaces the one held for this key \
                 (CC 5.3.3.5 item 6)"
            );
        }
        reg.insert(
            key_id.to_owned(),
            Entry {
                commitment,
                at: now,
                seq: self.next_seq.fetch_add(1, Ordering::Relaxed),
            },
        );
    }

    /// See [`pending`].
    #[must_use]
    pub fn pending(&self, key_id: &str) -> Option<PqcCommitment> {
        let mut reg = self.lock();
        match reg.get(key_id) {
            Some(e) if e.at.elapsed() < self.ttl => Some(e.commitment.clone()),
            Some(_) => {
                reg.remove(key_id);
                None
            }
            None => None,
        }
    }

    /// See [`clear`].
    pub fn clear(&self, key_id: &str) {
        self.lock().remove(key_id);
    }

    /// How many commitments are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether none is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// See [`check_ml_dsa_65`].
    #[must_use]
    pub fn check_ml_dsa_65(&self, key_id: &str, ml_dsa_65_pubkey_base64: Option<&str>) -> Anchor {
        use base64::Engine as _;
        let Some(commitment) = self.pending(key_id) else {
            return Anchor::None;
        };
        let verdict = match ml_dsa_65_pubkey_base64
            .map(|b| base64::engine::general_purpose::STANDARD.decode(b.as_bytes()))
        {
            None => Err("the record carries no ML-DSA-65 public key".to_owned()),
            Some(Err(e)) => Err(format!(
                "the record's ML-DSA-65 public key is not base64: {e}"
            )),
            Some(Ok(raw)) => {
                // The check reads only the code's commitment; its other
                // fields are not consulted.
                let fc = ciris_verify_core::fedcode::FedCode::new(
                    ciris_verify_core::fedcode::FedKind::Node,
                    key_id,
                    "",
                )
                .with_ml_dsa_65_pubkey_sha256(commitment.as_str());
                ciris_verify_core::fedcode::verify_pulled_ml_dsa_65_pubkey(&fc, &raw)
                    .map_err(|e| e.to_string())
            }
        };
        match verdict {
            Ok(()) => {
                tracing::debug!(
                    key_id,
                    "pqc anchor: the record's ML-DSA-65 key matches the pre-held commitment \
                     (CC 5.3.3.5 item 6 (1))"
                );
                Anchor::Matched
            }
            Err(detail) => {
                MISMATCHES.fetch_add(1, Ordering::Relaxed);
                let crate::log_throttle::ThrottleDecision::Emit { suppressed_prev } =
                    mismatch_log().check(key_id)
                else {
                    return Anchor::Mismatch(detail);
                };
                tracing::warn!(
                    key_id,
                    reason = PQC_COMMITMENT_MISMATCH,
                    detail = %detail,
                    suppressed_prev,
                    "pqc anchor: REFUSED — the record's ML-DSA-65 key does not hash to the \
                     commitment the dialler held before dialling (CC 5.3.3.5 item 6, \
                     CIRISEdge#964); the record is not admitted and its transit pair is not used"
                );
                Anchor::Mismatch(detail)
            }
        }
    }
}

fn registry() -> &'static AnchorRegistry {
    static REG: OnceLock<AnchorRegistry> = OnceLock::new();
    REG.get_or_init(|| AnchorRegistry::new(ANCHOR_CAP, ANCHOR_TTL))
}

static MISMATCHES: AtomicU64 = AtomicU64::new(0);

/// A mismatch is logged once per key per minute; a retried dial against the
/// same record is counted, not re-logged.
fn mismatch_log() -> &'static crate::log_throttle::LogThrottle {
    static LOG: OnceLock<crate::log_throttle::LogThrottle> = OnceLock::new();
    LOG.get_or_init(|| crate::log_throttle::LogThrottle::new(1, Duration::from_secs(60), 256))
}

/// Hold `commitment` for `key_id` until a record matches it or [`ANCHOR_TTL`]
/// lapses. A second commitment for the same key replaces the first (the most
/// recent contact a person added is the one they mean). Past [`ANCHOR_CAP`]
/// the oldest entry is evicted.
pub fn anchor(key_id: &str, commitment: PqcCommitment) {
    registry().anchor(key_id, commitment);
}

/// The commitment held for `key_id`, if one is held and live.
#[must_use]
pub fn pending(key_id: &str) -> Option<PqcCommitment> {
    registry().pending(key_id)
}

/// Drop any commitment held for `key_id`.
pub fn clear(key_id: &str) {
    registry().clear(key_id);
}

/// Records refused against a commitment since the process started (every
/// path; the route fetch also counts its own `link_seal` label).
#[must_use]
pub fn mismatch_count() -> u64 {
    MISMATCHES.load(Ordering::Relaxed)
}

/// Check `key_id`'s record's ML-DSA-65 half (`ml_dsa_65_pubkey_base64`, the
/// raw key in standard base64) against the commitment held for it, with the
/// shared rule `ciris_verify_core::fedcode::verify_pulled_ml_dsa_65_pubkey`.
/// A mismatch is counted and logged by name. A match does NOT clear the
/// anchor: the caller clears it ([`clear`]) once the record it checked is
/// actually admitted and its pair used, so a match whose admission then fails
/// leaves the next attempt still checked.
#[must_use]
pub fn check_ml_dsa_65(key_id: &str, ml_dsa_65_pubkey_base64: Option<&str>) -> Anchor {
    registry().check_ml_dsa_65(key_id, ml_dsa_65_pubkey_base64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest as _;

    fn commitment_of(bytes: &[u8]) -> PqcCommitment {
        PqcCommitment::parse(&hex::encode(sha2::Sha256::digest(bytes))).expect("well-formed")
    }

    fn b64(bytes: &[u8]) -> String {
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes)
    }

    /// CIRISEdge#964 — a malformed commitment is rejected, never repaired:
    /// uppercase, wrong length, non-hex, surrounding whitespace.
    #[test]
    fn a_malformed_commitment_is_rejected_never_repaired_964() {
        let good = hex::encode([0xabu8; 32]);
        assert!(PqcCommitment::parse(&good).is_ok());
        for bad in [
            good.to_ascii_uppercase(),
            good[..63].to_owned(),
            format!("{good}0"),
            format!("{}g", &good[..63]),
            format!(" {}", &good[..63]),
            String::new(),
        ] {
            assert!(
                PqcCommitment::parse(&bad).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    /// CIRISEdge#964 — no anchor: no opinion. A matching key matches; a
    /// mismatching (or absent, or undecodable) one is refused and keeps it.
    #[test]
    fn the_anchor_matches_refuses_and_clears_964() {
        let reg = AnchorRegistry::new(8, ANCHOR_TTL);
        let key = "pqc-anchor-unit-964-key";
        let ml_dsa = [7u8; 1952];
        assert_eq!(reg.check_ml_dsa_65(key, Some(&b64(&ml_dsa))), Anchor::None);

        reg.anchor(key, commitment_of(&ml_dsa));
        let before = mismatch_count();
        assert!(matches!(
            reg.check_ml_dsa_65(key, Some(&b64(&[8u8; 1952]))),
            Anchor::Mismatch(_)
        ));
        assert!(matches!(
            reg.check_ml_dsa_65(key, None),
            Anchor::Mismatch(_)
        ));
        assert!(matches!(
            reg.check_ml_dsa_65(key, Some("not base64!")),
            Anchor::Mismatch(_)
        ));
        assert!(mismatch_count() >= before + 3);
        assert!(reg.pending(key).is_some(), "a mismatch keeps the anchor");

        assert_eq!(
            reg.check_ml_dsa_65(key, Some(&b64(&ml_dsa))),
            Anchor::Matched
        );
        assert!(reg.pending(key).is_some(), "a match alone keeps the anchor");
        reg.clear(key);
        assert_eq!(
            reg.check_ml_dsa_65(key, Some(&b64(&[8u8; 1952]))),
            Anchor::None
        );
    }

    /// CIRISEdge#964 — the registry is bounded: past the cap the oldest
    /// entry goes.
    #[test]
    fn the_registry_is_bounded_964() {
        let reg = AnchorRegistry::new(4, ANCHOR_TTL);
        let c = commitment_of(b"cap");
        reg.anchor("first", c.clone());
        for i in 0..4 {
            reg.anchor(&format!("k{i}"), c.clone());
        }
        assert!(
            reg.pending("first").is_none(),
            "the oldest entry was evicted"
        );
        assert_eq!(reg.len(), 4);
        assert!(reg.pending("k3").is_some());
    }

    /// CIRISEdge#964 — an anchor past its TTL is gone.
    #[test]
    fn an_anchor_lapses_at_its_ttl_964() {
        let reg = AnchorRegistry::new(4, Duration::ZERO);
        reg.anchor("k", commitment_of(b"ttl"));
        assert!(reg.pending("k").is_none());
        assert_eq!(reg.check_ml_dsa_65("k", None), Anchor::None);
    }
}
