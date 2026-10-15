//! CIRISEdge#805 (CC 3.3.6.2 / 5.3.3.5 E1) — custody of this node's STATIC
//! transit KEX pair: the `{x25519, ml_kem_768}` keys a relay publishes on its
//! signed `transport_destination` binding so a dialler can run
//! `ciris_crypto::transit_kex::initiate` against them.
//!
//! # One 64-byte root seed
//!
//! The host's [`ciris_keyring::TransportIdentityKeystore`] holds exactly
//! 64-byte entries, and the two transit private keys would be 96 bytes. So
//! custody stores ONE random 64-byte root seed and derives both keys from it
//! with HKDF-SHA256, domain-separated by label:
//!
//! - x25519 private = `HKDF(seed, info = "ciris-transit-kex/v1/x25519", 32)`;
//! - ML-KEM-768 keygen seed `d ‖ z` =
//!   `HKDF(seed, info = "ciris-transit-kex/v1/ml-kem-768", 64)`, expanded by
//!   FIPS 203 deterministic keygen.
//!
//! The root seed is independent of the Reticulum transport identity (a fresh
//! CSPRNG draw, never derived from it), so the transit x25519 is never the
//! link x25519 persist's admission refuses as `transit_kex_key_reuse`.
//!
//! # Storage mirrors the transport identity
//!
//! - keystore wired: entry `transit-kex:v1:<transport identity storage key>`,
//!   with the identity's adopt-and-migrate step for a pre-existing file;
//! - no keystore: `<identity_path>.transit-kex`, 64 raw bytes, chmod 600.
//!
//! A stored seed of the wrong length is a hard error, never a regenerate:
//! regenerating would silently rotate the published pair under every peer.
//!
//! The seed and both private keys are zeroized on drop and never logged.

use std::path::{Path, PathBuf};

use ciris_persist::federation::self_at_login::{
    TransitKexPair, TRANSIT_KEX_ML_KEM_768_LEN, TRANSIT_KEX_X25519_LEN,
};
use zeroize::Zeroizing;

use crate::transport::TransportError;

/// Length of the stored root seed (the keystore's fixed entry size).
pub const TRANSIT_KEX_SEED_LEN: usize = ciris_keyring::TRANSPORT_IDENTITY_LEN;

/// Length of the ML-KEM-768 decapsulation key in the seed form
/// `ciris_crypto::ml_kem::decapsulate` takes (`d ‖ z`).
pub const ML_KEM_768_DK_SEED_LEN: usize = 64;

/// HKDF info label for the transit x25519 private key.
const INFO_X25519: &[u8] = b"ciris-transit-kex/v1/x25519";

/// HKDF info label for the transit ML-KEM-768 keygen seed.
const INFO_ML_KEM_768: &[u8] = b"ciris-transit-kex/v1/ml-kem-768";

/// Keystore entry prefix; the suffix is the transport identity's storage key.
const KEYSTORE_PREFIX: &str = "transit-kex:v1:";

/// Suffix appended to the transport identity path for the file-backed seed.
const FILE_SUFFIX: &str = ".transit-kex";

/// This node's transit KEX keys: both privates plus the public pair it
/// publishes. Built once at transport start and held by the transport.
pub struct TransitKexSecret {
    x25519_private: Zeroizing<[u8; TRANSIT_KEX_X25519_LEN]>,
    ml_kem_768_dk_seed: Zeroizing<[u8; ML_KEM_768_DK_SEED_LEN]>,
    pair: TransitKexPair,
}

impl std::fmt::Debug for TransitKexSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransitKexSecret")
            .field("x25519_public", &hex::encode(self.pair.x25519))
            .finish_non_exhaustive()
    }
}

impl TransitKexSecret {
    /// Derive both transit keys from a 64-byte root seed.
    ///
    /// # Errors
    ///
    /// [`TransportError::Config`] if HKDF or the ML-KEM keygen fails (neither
    /// can for these fixed lengths; the arm stays loud rather than panic).
    pub fn from_root_seed(seed: &[u8; TRANSIT_KEX_SEED_LEN]) -> Result<Self, TransportError> {
        let derive = |info: &[u8], len: usize| {
            ciris_crypto::kdf::hkdf_sha256(seed, &[], info, len)
                .map(Zeroizing::new)
                .map_err(|e| TransportError::Config(format!("transit kex hkdf: {e}")))
        };

        let x_okm = derive(INFO_X25519, TRANSIT_KEX_X25519_LEN)?;
        let mut x25519_private = Zeroizing::new([0u8; TRANSIT_KEX_X25519_LEN]);
        x25519_private.copy_from_slice(&x_okm);
        let x25519_public = ciris_crypto::x25519::public_from_secret(&x25519_private);

        let d_z = derive(INFO_ML_KEM_768, ML_KEM_768_DK_SEED_LEN)?;
        let (dk_seed, ek) = ciris_crypto::ml_kem::generate_keypair_deterministic(&d_z)
            .map_err(|e| TransportError::Config(format!("transit kex ml-kem keygen: {e}")))?;
        let dk_seed = Zeroizing::new(dk_seed);
        let mut ml_kem_768_dk_seed = Zeroizing::new([0u8; ML_KEM_768_DK_SEED_LEN]);
        if dk_seed.len() != ML_KEM_768_DK_SEED_LEN {
            return Err(TransportError::Config(format!(
                "transit kex ml-kem dk seed is {} bytes, expected {ML_KEM_768_DK_SEED_LEN}",
                dk_seed.len()
            )));
        }
        ml_kem_768_dk_seed.copy_from_slice(&dk_seed);
        let ml_kem_768 = Box::<[u8; TRANSIT_KEX_ML_KEM_768_LEN]>::try_from(ek.into_boxed_slice())
            .map_err(|ek| {
            TransportError::Config(format!(
                "transit kex ml-kem ek is {} bytes, expected {TRANSIT_KEX_ML_KEM_768_LEN}",
                ek.len()
            ))
        })?;

        Ok(Self {
            x25519_private,
            ml_kem_768_dk_seed,
            pair: TransitKexPair {
                x25519: x25519_public,
                ml_kem_768,
            },
        })
    }

    /// The public pair this node publishes in `transit_kex_pubkeys`.
    #[must_use]
    pub fn pair(&self) -> &TransitKexPair {
        &self.pair
    }

    /// The transit x25519 private key (`relay_x25519_priv` for
    /// `transit_kex::respond`).
    #[must_use]
    pub fn x25519_private(&self) -> &[u8; TRANSIT_KEX_X25519_LEN] {
        &self.x25519_private
    }

    /// The ML-KEM-768 decapsulation key in its 64-byte seed form, which is
    /// what `ciris_crypto::ml_kem::decapsulate` (and so
    /// `transit_kex::respond`'s `relay_mlkem768_priv`) takes.
    #[must_use]
    pub fn ml_kem_768_dk_seed(&self) -> &[u8; ML_KEM_768_DK_SEED_LEN] {
        &self.ml_kem_768_dk_seed
    }

    /// File-backed custody: load `<identity_path>.transit-kex`, or generate
    /// and persist a fresh seed (chmod 600) on first run.
    ///
    /// # Errors
    ///
    /// [`TransportError::Config`] on an I/O fault, a file of the wrong length
    /// (never regenerated), or an RNG health-latch refusal.
    pub fn load_or_generate_file(identity_path: &Path) -> Result<Self, TransportError> {
        let path = seed_path(identity_path);
        if path.exists() {
            let seed = read_seed_file(&path)?;
            return Self::from_root_seed(&seed);
        }

        let mut seed = Zeroizing::new([0u8; TRANSIT_KEX_SEED_LEN]);
        ciris_crypto::random::fill(seed.as_mut())
            .map_err(|e| TransportError::Config(format!("transit kex seed csprng: {e}")))?;
        write_seed_file(&path, &seed)?;
        tracing::info!(path = %path.display(), "generated new transit KEX seed");
        Self::from_root_seed(&seed)
    }

    /// Keystore-backed custody, mirroring the transport identity's
    /// precedence: keystore hit → use it; miss with a seed file present →
    /// adopt it into the keystore and archive the file; miss with no file →
    /// `generate_and_store`.
    ///
    /// # Errors
    ///
    /// [`TransportError::Config`] on any keystore or file fault, including a
    /// stored entry of the wrong length.
    pub fn load_or_adopt_or_generate_with_keystore(
        identity_path: &Path,
        storage_key: &str,
        keystore: &dyn ciris_keyring::TransportIdentityKeystore,
    ) -> Result<Self, TransportError> {
        let key_id = keystore_key_id(storage_key);
        let load = |what: &str| {
            keystore
                .load(&key_id)
                .map(|o| o.map(Zeroizing::new))
                .map_err(|e| {
                    TransportError::Config(format!("{what} transit kex seed {key_id}: {e}"))
                })
        };

        if let Some(seed) = load("keystore load")? {
            tracing::info!(
                key_id,
                hardware_backed = keystore.is_hardware_backed(),
                "loaded transit KEX seed from keystore"
            );
            return Self::from_root_seed(&seed);
        }

        let path = seed_path(identity_path);
        if path.exists() {
            let seed = read_seed_file(&path)?;
            keystore.store(&key_id, &seed).map_err(|e| {
                TransportError::Config(format!("adopt: keystore store for {key_id}: {e}"))
            })?;
            archive_adopted_file(&path, &key_id);
            return Self::from_root_seed(&seed);
        }

        keystore.generate_and_store(&key_id).map_err(|e| {
            TransportError::Config(format!("generate_and_store transit kex seed {key_id}: {e}"))
        })?;
        let seed = load("post-generate load")?.ok_or_else(|| {
            TransportError::Config(format!(
                "post-generate load for {key_id} returned None — keystore contract violation"
            ))
        })?;
        tracing::info!(
            key_id,
            hardware_backed = keystore.is_hardware_backed(),
            "generated fresh transit KEX seed in keystore"
        );
        Self::from_root_seed(&seed)
    }
}

/// The keystore entry the transit seed lives under.
#[must_use]
pub fn keystore_key_id(storage_key: &str) -> String {
    format!("{KEYSTORE_PREFIX}{storage_key}")
}

/// `<identity_path>.transit-kex` — appended, never an extension swap, so it
/// cannot collide with the identity's own `.migrated-<ts>` archive.
#[must_use]
pub fn seed_path(identity_path: &Path) -> PathBuf {
    let mut p = identity_path.as_os_str().to_os_string();
    p.push(FILE_SUFFIX);
    PathBuf::from(p)
}

fn read_seed_file(path: &Path) -> Result<Zeroizing<[u8; TRANSIT_KEX_SEED_LEN]>, TransportError> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| {
        TransportError::Config(format!("read transit kex seed {}: {e}", path.display()))
    })?);
    let mut seed = Zeroizing::new([0u8; TRANSIT_KEX_SEED_LEN]);
    if bytes.len() != TRANSIT_KEX_SEED_LEN {
        return Err(TransportError::Config(format!(
            "transit kex seed {} is {} bytes, expected {TRANSIT_KEX_SEED_LEN}; refusing to \
             regenerate (that would rotate the published pair)",
            path.display(),
            bytes.len()
        )));
    }
    seed.copy_from_slice(&bytes);
    Ok(seed)
}

fn write_seed_file(path: &Path, seed: &[u8; TRANSIT_KEX_SEED_LEN]) -> Result<(), TransportError> {
    use std::io::Write as _;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| {
                TransportError::Config(format!(
                    "create transit kex seed dir {}: {e}",
                    parent.display()
                ))
            })?;
        }
    }
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| {
        TransportError::Config(format!("create transit kex seed {}: {e}", path.display()))
    })?;
    f.write_all(seed).and_then(|()| f.sync_all()).map_err(|e| {
        TransportError::Config(format!("write transit kex seed {}: {e}", path.display()))
    })?;
    set_owner_only(path)
}

/// Rename an adopted seed file to `<path>.migrated-<ts>`. Best-effort: the
/// keystore copy is already durable.
fn archive_adopted_file(path: &Path, key_id: &str) {
    let suffix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    let mut archived = path.as_os_str().to_os_string();
    archived.push(format!(".migrated-{suffix}"));
    let archived = PathBuf::from(archived);
    match std::fs::rename(path, &archived) {
        Ok(()) => tracing::warn!(
            key_id,
            archived = %archived.display(),
            "adopted transit KEX seed from file into keystore; original archived"
        ),
        Err(e) => tracing::warn!(
            key_id,
            path = %path.display(),
            error = %e,
            "adopted transit KEX seed into keystore BUT failed to archive the original \
             file; operator should move/secure it"
        ),
    }
}

#[cfg(unix)]
fn set_owner_only(path: &Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| TransportError::Config(format!("chmod 600 {}: {e}", path.display())))
}

#[cfg(not(unix))]
fn set_owner_only(_path: &Path) -> Result<(), TransportError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_keyring::storage::SoftwareSecureBlobStorage;
    use ciris_keyring::{BlobTransportKeystore, TransportIdentityKeystore};

    fn software_keystore(dir: &Path) -> BlobTransportKeystore {
        let storage = SoftwareSecureBlobStorage::new("transit-kex-test", dir).expect("storage");
        BlobTransportKeystore::new(Box::new(storage))
    }

    fn assert_same(a: &TransitKexSecret, b: &TransitKexSecret) {
        assert_eq!(a.pair(), b.pair());
        assert_eq!(a.x25519_private(), b.x25519_private());
        assert_eq!(a.ml_kem_768_dk_seed(), b.ml_kem_768_dk_seed());
    }

    #[test]
    fn file_load_or_generate_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = dir.path().join("rns").join("identity");
        let first = TransitKexSecret::load_or_generate_file(&id).expect("generate");
        let path = seed_path(&id);
        assert_eq!(
            std::fs::read(&path).expect("seed").len(),
            TRANSIT_KEX_SEED_LEN
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "seed file must be owner-only");
        }
        let second = TransitKexSecret::load_or_generate_file(&id).expect("reload");
        assert_same(&first, &second);
    }

    #[test]
    fn keystore_load_or_generate_is_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ks = software_keystore(&dir.path().join("ks"));
        let id = dir.path().join("identity");
        let first = TransitKexSecret::load_or_adopt_or_generate_with_keystore(&id, "node-key", &ks)
            .expect("generate");
        assert!(
            ks.load(&keystore_key_id("node-key"))
                .expect("load")
                .is_some(),
            "seed stored under transit-kex:v1:<storage key>"
        );
        assert!(
            ks.load("node-key").expect("load").is_none(),
            "never written over the transport identity's own entry"
        );
        assert!(!seed_path(&id).exists(), "keystore path writes no file");
        let second =
            TransitKexSecret::load_or_adopt_or_generate_with_keystore(&id, "node-key", &ks)
                .expect("reload");
        assert_same(&first, &second);
    }

    #[test]
    fn keystore_adopts_an_existing_seed_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = dir.path().join("identity");
        let from_file = TransitKexSecret::load_or_generate_file(&id).expect("file");
        let ks = software_keystore(&dir.path().join("ks"));
        let adopted =
            TransitKexSecret::load_or_adopt_or_generate_with_keystore(&id, "node-key", &ks)
                .expect("adopt");
        assert_same(&from_file, &adopted);
        assert!(!seed_path(&id).exists(), "adopted file is archived");
    }

    #[test]
    fn derived_keys_are_separated_from_each_other_and_the_identity() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = dir.path().join("identity");
        let identity = leviculum_std::generate_identity();
        let id_priv = identity.private_key_bytes().expect("identity priv");
        let id_pub = identity.public_key_bytes();
        std::fs::write(&id, id_priv).expect("write identity");

        let s = TransitKexSecret::load_or_generate_file(&id).expect("generate");
        let x_pub = s.pair().x25519;
        let x_priv = *s.x25519_private();
        let dk = *s.ml_kem_768_dk_seed();

        // The two derived keys differ from each other.
        assert_ne!(&x_priv[..], &dk[..32]);
        assert_ne!(&x_priv[..], &dk[32..]);
        // And from every half of the Reticulum identity, public and private.
        for half in [
            &id_pub[..32],
            &id_pub[32..64],
            &id_priv[..32],
            &id_priv[32..64],
        ] {
            assert_ne!(&x_pub[..], half);
            assert_ne!(&x_priv[..], half);
            assert_ne!(&dk[..32], half);
            assert_ne!(&dk[32..], half);
        }
        // The seed file is not the identity bytes either.
        assert_ne!(
            std::fs::read(seed_path(&id)).expect("seed"),
            id_priv.to_vec()
        );
        // The public halves really are those of the privates.
        assert_eq!(x_pub, ciris_crypto::x25519::public_from_secret(&x_priv));
        let (_, ek) = ciris_crypto::ml_kem::generate_keypair_deterministic(&dk).expect("ek");
        assert_eq!(&ek[..], &s.pair().ml_kem_768[..]);
    }

    #[test]
    fn derivation_is_domain_separated_and_deterministic() {
        let a = TransitKexSecret::from_root_seed(&[7u8; TRANSIT_KEX_SEED_LEN]).expect("a");
        let b = TransitKexSecret::from_root_seed(&[7u8; TRANSIT_KEX_SEED_LEN]).expect("b");
        let c = TransitKexSecret::from_root_seed(&[8u8; TRANSIT_KEX_SEED_LEN]).expect("c");
        assert_same(&a, &b);
        assert_ne!(a.pair(), c.pair());
        // Neither private is the raw seed.
        assert_ne!(&a.x25519_private()[..], &[7u8; 32][..]);
        assert_ne!(&a.ml_kem_768_dk_seed()[..], &[7u8; 64][..]);
    }

    #[test]
    fn the_pair_completes_a_transit_kem_round_trip() {
        let s = TransitKexSecret::from_root_seed(&[9u8; TRANSIT_KEX_SEED_LEN]).expect("s");
        let (ct, ss) = ciris_crypto::ml_kem::encapsulate(&s.pair().ml_kem_768[..]).expect("encap");
        let ss2 =
            ciris_crypto::ml_kem::decapsulate(s.ml_kem_768_dk_seed(), &ct).expect("decapsulate");
        assert_eq!(ss, ss2, "the dk seed is the form decapsulate takes");
        let (eph_secret, eph_public) =
            ciris_crypto::x25519::generate_ephemeral_keypair().expect("eph");
        assert_eq!(
            ciris_crypto::x25519::dh(&eph_secret, &s.pair().x25519).expect("dh i"),
            ciris_crypto::x25519::dh(s.x25519_private(), &eph_public).expect("dh r"),
        );
    }

    #[test]
    fn wrong_length_file_is_a_hard_error_never_a_regenerate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let id = dir.path().join("identity");
        let path = seed_path(&id);
        for bad in [0usize, 32, 63, 65, 96] {
            std::fs::write(&path, vec![0x5a; bad]).expect("write");
            let err = TransitKexSecret::load_or_generate_file(&id).expect_err("must refuse");
            assert!(matches!(err, TransportError::Config(_)), "{bad}: {err:?}");
            assert_eq!(
                std::fs::read(&path).expect("still there"),
                vec![0x5a; bad],
                "{bad}: the bad file is left untouched, not overwritten"
            );
            // The keystore adopt path refuses it too.
            let ks = software_keystore(&dir.path().join(format!("ks-{bad}")));
            assert!(
                TransitKexSecret::load_or_adopt_or_generate_with_keystore(&id, "k", &ks).is_err()
            );
            assert!(ks.load(&keystore_key_id("k")).expect("load").is_none());
        }
    }

    #[test]
    fn debug_never_prints_private_material() {
        let s = TransitKexSecret::from_root_seed(&[3u8; TRANSIT_KEX_SEED_LEN]).expect("s");
        let dbg = format!("{s:?}");
        assert!(!dbg.contains(&hex::encode(s.x25519_private())));
        assert!(!dbg.contains(&hex::encode(&s.ml_kem_768_dk_seed()[..16])));
    }
}
