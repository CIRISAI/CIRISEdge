//! CC 5.4.6 item 9 (rc16) — **the publication key**. A federation-scope item
//! published through the tier is signed like every row, by a FRESH hybrid key
//! pair (Ed25519 + ML-DSA-65) whose `key:record:v1` travels inline, of
//! `identity_type` `pseudonym`, with no occurrence and no standing. The key
//! plane refuses it as an identity exactly as it refuses a rendezvous key
//! (persist's gate; not in persist v59 — CIRISPersist#1149 / 61.x). A reader
//! composes its rows as a stranger's. There is no ring signature. A person
//! may later bind a pseudonym to themselves by a signed row; nothing else
//! links them, so this module never derives a pseudonym from any other key.

use ciris_crypto::{
    ClassicalSigner, Ed25519Signer, HybridSignature, HybridSigner, MlDsa65Signer, PqcSigner,
};
use sha2::{Digest, Sha256};

/// The identity type of a publication key (CC 5.4.6 item 9).
pub const IDENTITY_TYPE_PSEUDONYM: &str = "pseudonym";
/// The algorithm string of a hybrid key record.
pub const ALGORITHM_HYBRID: &str = "hybrid";

/// A fresh publication key. Dropped after use: one pseudonym per
/// publication unless the publisher chooses to reuse it.
pub struct PseudonymKey {
    signer: HybridSigner<Ed25519Signer, MlDsa65Signer>,
    ed25519: Vec<u8>,
    ml_dsa_65: Vec<u8>,
    key_id: String,
}

impl std::fmt::Debug for PseudonymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PseudonymKey")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

impl PseudonymKey {
    /// Mint a fresh key pair from the system RNG (never from another key).
    ///
    /// # Errors
    /// The primitives' (including the RNG health latch).
    pub fn fresh() -> Result<Self, ciris_crypto::CryptoError> {
        let classical = Ed25519Signer::random()?;
        let pqc = MlDsa65Signer::new()?;
        let ed25519 = classical.public_key()?;
        let ml_dsa_65 = pqc.public_key()?;
        let mut h = Sha256::new();
        h.update(b"ciris-onion/v1/pseudonym-key-id");
        h.update(&ed25519);
        h.update(&ml_dsa_65);
        let key_id = format!("pseudonym-{}", hex::encode(&h.finalize()[..16]));
        Ok(Self {
            signer: HybridSigner::new(classical, pqc)?,
            ed25519,
            ml_dsa_65,
            key_id,
        })
    }

    /// The key id rows signed by this key name.
    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    /// The inline key record's public fields (`key:record:v1`): the two
    /// public keys, `algorithm` `hybrid`, `identity_type` `pseudonym`, and an
    /// `identity_ref` that is the key id itself (it names no one).
    #[must_use]
    pub fn key_record(&self) -> serde_json::Value {
        use base64::Engine as _;
        let b64 = base64::engine::general_purpose::STANDARD;
        serde_json::json!({
            "key_id": self.key_id,
            "pubkey_ed25519_base64": b64.encode(&self.ed25519),
            "pubkey_ml_dsa_65_base64": b64.encode(&self.ml_dsa_65),
            "algorithm": ALGORITHM_HYBRID,
            "identity_type": IDENTITY_TYPE_PSEUDONYM,
            "identity_ref": self.key_id,
        })
    }

    /// Hybrid-sign a row's canonical bytes (`Ed25519(data)`, then
    /// `ML-DSA-65(data ‖ classical_sig)`).
    ///
    /// # Errors
    /// The primitives'.
    pub fn sign(&self, canonical: &[u8]) -> Result<HybridSignature, ciris_crypto::CryptoError> {
        self.signer.sign(canonical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two publications, two strangers: fresh keys share nothing, the record
    /// says `pseudonym`, and the signature is hybrid over the given bytes.
    #[test]
    fn every_pseudonym_is_fresh_and_names_no_one() {
        let a = PseudonymKey::fresh().unwrap();
        let b = PseudonymKey::fresh().unwrap();
        assert_ne!(a.key_id(), b.key_id());
        let r = a.key_record();
        assert_eq!(r["identity_type"], IDENTITY_TYPE_PSEUDONYM);
        assert_eq!(r["identity_ref"], a.key_id());
        let sig = a.sign(b"row").unwrap();
        assert!(!sig.classical.signature.is_empty());
        assert!(!sig.pqc.signature.is_empty());
        assert_eq!(sig.classical.public_key, a.ed25519);
    }
}
