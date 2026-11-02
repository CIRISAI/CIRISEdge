//! CC 3.3.6.2 — **the onion hop key**: where a node's hop key is read, how it
//! is checked at use, and where this node keeps its own.
//!
//! # One accessor (the persist 61.0.1 switch is here and only here)
//!
//! Persist v59 (edge main) reads only `transit_kex_pubkeys` off a signed
//! `transport_destination` row; the CC's own member, `onion_hop_pubkeys`, and
//! the `onion_relay` opt-out marker arrive with persist 61.0.1
//! (CIRISPersist#1181). Until then [`HOP_KEY_SOURCE`] is
//! [`HopKeySource::TransitStandIn`]: [`hop_key_for`] returns the transit pair
//! (the same two halves, ML-KEM-768 and X25519) and the node decapsulates with
//! its transit custody in the split form ([`local_hop_secret_from_transit`]).
//! The stand-in cannot satisfy the CC's in-row separation (the hop key must
//! differ from the transit pair), which is one more reason the tier stays
//! dormant until the switch. At 61.0.1 the switch flips [`HOP_KEY_SOURCE`],
//! reads `onion_hop_pubkeys`, and the node uses [`HopCustody`]'s own seed.

use std::path::{Path, PathBuf};

use super::packet::{HopKey, HopSecret, OnionError};

/// Where the hop key is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopKeySource {
    /// persist < 61.0.1: the transit pair stands in (`transit_kex_pubkeys`).
    TransitStandIn,
    /// persist ≥ 61.0.1: the CC's member (`onion_hop_pubkeys`).
    OnionHopPubkeys,
}

impl HopKeySource {
    /// The envelope member read.
    #[must_use]
    pub const fn member(self) -> &'static str {
        match self {
            Self::TransitStandIn => "transit_kex_pubkeys",
            Self::OnionHopPubkeys => "onion_hop_pubkeys",
        }
    }
}

/// The source in force on this build.
pub const HOP_KEY_SOURCE: HopKeySource = HopKeySource::TransitStandIn;

/// A hop key from the transit pair's two halves (the stand-in).
#[must_use]
pub fn hop_key_from_transit_pair(
    p: &ciris_persist::federation::self_at_login::TransitKexPair,
) -> HopKey {
    HopKey {
        x25519: p.x25519,
        ml_kem_768: p.ml_kem_768.clone(),
    }
}

/// **The accessor**: `key_id`'s hop key off its live signed
/// `transport_destination` row, or `None` when it carries none.
///
/// # Errors
/// The directory's.
pub async fn hop_key_for<D>(
    dir: &D,
    key_id: &str,
) -> Result<Option<HopKey>, ciris_persist::federation::Error>
where
    D: ciris_persist::federation::FederationDirectory + ?Sized,
{
    let pair = ciris_persist::federation::self_at_login::transit_kex_pair_for(dir, key_id).await?;
    Ok(pair.as_ref().map(hop_key_from_transit_pair))
}

/// CC 3.3.6.2 — the use-time rule: a hop key equal (either half) to any other
/// key on the identity's current occurrence means the node carries no valid
/// hop key. `other_keys` are the occurrence's other raw keys (transport x25519
/// and ed25519, the signer's pinned keys, and — once the switch lands — the
/// transit pair's halves).
#[must_use]
pub fn hop_key_valid(hop: &HopKey, other_keys: &[&[u8]]) -> bool {
    !other_keys
        .iter()
        .any(|k| *k == hop.x25519.as_slice() || *k == &hop.ml_kem_768[..])
}

/// The node's own hop secret under the stand-in: its transit custody, in the
/// split form.
///
/// # Errors
/// [`OnionError::Crypto`] from the primitives.
#[cfg(feature = "_reticulum-module")]
pub fn local_hop_secret_from_transit(
    t: &crate::transport::transit_kex_custody::TransitKexSecret,
) -> Result<HopSecret, OnionError> {
    HopSecret::from_split(t.ml_kem_768_dk_seed(), t.x25519_private())
}

/// Custody of this node's own hop seed (used once [`HOP_KEY_SOURCE`] is
/// [`HopKeySource::OnionHopPubkeys`]): one random 64-byte root seed at
/// `<identity_path>.onion-hop`, chmod 600, from which the X-Wing seed is
/// derived ([`HopSecret::from_root_seed`]). Independent of every other key,
/// so the producer's cross-row separation duty holds by construction.
#[derive(Debug, Clone, Copy)]
pub struct HopCustody;

impl HopCustody {
    /// The seed file for a transport identity at `identity_path`.
    #[must_use]
    pub fn seed_path(identity_path: &Path) -> PathBuf {
        let mut p = identity_path.as_os_str().to_owned();
        p.push(".onion-hop");
        PathBuf::from(p)
    }

    /// Load the hop secret, or mint and store a fresh one. A stored seed of
    /// the wrong length is an error, never a regenerate (that would rotate
    /// the published key under every sender).
    ///
    /// # Errors
    /// I/O, a wrong-length seed, or the primitives.
    pub fn load_or_generate_file(identity_path: &Path) -> Result<HopSecret, OnionError> {
        let path = Self::seed_path(identity_path);
        let io =
            |e: std::io::Error| OnionError::Crypto(format!("hop seed {}: {e}", path.display()));
        let mut seed = zeroize::Zeroizing::new([0u8; 64]);
        match std::fs::read(&path) {
            Ok(bytes) => {
                let bytes = zeroize::Zeroizing::new(bytes);
                if bytes.len() != 64 {
                    return Err(OnionError::Malformed("stored hop seed length"));
                }
                seed.copy_from_slice(&bytes);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                ciris_crypto::random::fill(&mut seed[..])
                    .map_err(|e| OnionError::Crypto(e.to_string()))?;
                std::fs::write(&path, &seed[..]).map_err(io)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
                        .map_err(io)?;
                }
            }
            Err(e) => return Err(io(e)),
        }
        HopSecret::from_root_seed(&seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn use_time_separation_refuses_a_hop_key_equal_to_another_key() {
        let s = HopSecret::from_xwing_seed(&[4; 32]).unwrap();
        let hop = s.public();
        assert!(hop_key_valid(hop, &[&[1u8; 32], &[2u8; 32]]));
        assert!(!hop_key_valid(hop, &[&hop.x25519]));
        assert!(!hop_key_valid(hop, &[&hop.ml_kem_768[..]]));
    }

    #[test]
    fn custody_mints_once_and_reloads_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let id = dir.path().join("identity");
        let a = HopCustody::load_or_generate_file(&id).unwrap();
        let b = HopCustody::load_or_generate_file(&id).unwrap();
        assert_eq!(a.public(), b.public());
        std::fs::write(HopCustody::seed_path(&id), [0u8; 10]).unwrap();
        assert!(HopCustody::load_or_generate_file(&id).is_err());
    }

    #[test]
    fn the_stand_in_is_named_until_the_switch() {
        assert_eq!(HOP_KEY_SOURCE.member(), "transit_kex_pubkeys");
        assert_eq!(HopKeySource::OnionHopPubkeys.member(), "onion_hop_pubkeys");
    }
}
