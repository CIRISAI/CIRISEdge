//! Panic isolation for openmls crypto, and the KeyPackage key-length gate
//! (CIRISEdge#822 — RUSTSEC-2026-0330 / RUSTSEC-2026-0331).
//!
//! # Why this exists
//!
//! Both MLS planes (the persistent cohort groups in
//! [`super::cohort_group`] and the realtime A/V sessions in
//! [`crate::transport::realtime_av_mls`]) run on
//! `openmls_libcrux_crypto` 0.3.1, which pins `hpke-rs-libcrux` 0.6.1 and
//! through it `libcrux-kem` 0.0.7. That `libcrux-kem` PANICS (slice
//! indexing) instead of returning an error when it decodes an X-Wing
//! public key shorter than the 1184-byte ML-KEM-768 half
//! (`PublicKey::decode`), a short private key (`PrivateKey::decode`), or
//! encapsulates under a seed shorter than 32 bytes
//! (`encapsulate_derand`). The pinned ciphersuite is 0x004D, X-Wing.
//!
//! A peer can publish a correctly SIGNED KeyPackage whose HPKE `init_key`
//! or leaf `encryption_key` is short. Nothing in a KeyPackage signature
//! check looks at key lengths, so it validates. The panic fires later,
//! when this node HPKE-encrypts to that key: the Welcome's group secrets
//! on an Add (`init_key`), or a path secret on ANY later commit whose
//! copath resolution contains the leaf (`encryption_key`). Nothing above
//! openmls caught it, so the panic unwound through the caller's task and
//! (on the cohort plane) through a held `tokio::sync::Mutex` guard.
//!
//! The dependency fix is `libcrux-kem` >= 0.0.10, which no
//! `openmls_libcrux_crypto` release uses yet; removal of the cargo-deny
//! ignore is tracked on CIRISEdge#822. Until then this module is the
//! mitigation, in two layers:
//!
//! 1. **Refuse early.** [`check_key_package_key_lengths`] refuses a
//!    KeyPackage whose `init_key` or leaf `encryption_key` is not exactly
//!    [`xwing_public_key_len`] bytes. It runs at every KeyPackage ingress:
//!    `cohort_group::key_package_from_bytes` (the only way a
//!    directory-published KeyPackage becomes a typed one) and
//!    `MlsSession::commit_add_published` (the A/V admit of a
//!    joiner-published KeyPackage).
//! 2. **Contain what gets past.** Keys also arrive inside a Welcome's
//!    ratchet tree and inside a remote commit's UpdatePath, where no
//!    KeyPackage gate sees them. Every openmls call that can
//!    HPKE-encrypt, decrypt, or decode a key therefore runs under
//!    [`catch_crypto_panic`] or [`guard_group_op`], which turn a panic
//!    into an `Err` the caller maps to its plane's `CryptoPanic` variant.
//!
//! No panic hook is installed or changed: `catch_unwind` needs none, and a
//! process-global hook is not this module's to own. The default hook still
//! prints the panic message to stderr when one is caught.
//!
//! # State after a caught panic
//!
//! An `MlsGroup` writes every state change through to its provider's
//! storage, and [`MlsGroup::load`] rebuilds the whole group from that
//! storage. That is the invariant the cohort plane's snapshot persistence
//! already rests on. [`guard_group_op`] takes a copy of the storage map
//! before the operation. If the operation panics, it builds a FRESH
//! provider holding that copy, swaps it in for the old one, and reloads
//! the group from it. The group is then exactly the group the operation
//! started from, including no pending commit, whatever the panic
//! interrupted.
//!
//! The provider is replaced rather than repaired because of its std
//! locks: the storage map's `RwLock` and the RNG's `Mutex`.
//! `openmls_memory_storage` `unwrap`s its lock, so a poisoned one would
//! turn every later operation on the group into a panic, and
//! `RwLock::clear_poison` is newer than the crate's 1.75 MSRV. The
//! libcrux panic fires inside an HPKE call, which holds neither lock
//! (`hpke_seal`/`hpke_open` build their own `hpke-rs` context and PRNG;
//! the store holds its lock only around map operations), so in practice
//! nothing is poisoned. A fresh provider makes that irrelevant: whatever
//! the panic held, the group continues on locks it never touched.

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Arc, OnceLock, PoisonError};

use openmls::prelude::{Ciphersuite, KeyPackage, MlsGroup};
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::crypto::OpenMlsCrypto;
use openmls_traits::OpenMlsProvider;
use tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};

/// Render a `catch_unwind` payload as text. `panic!` with a literal
/// carries a `&'static str`, a formatted one a `String`; anything else is
/// opaque.
fn panic_message(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "non-string panic payload".to_owned()
    }
}

/// Run `op`, turning a panic into `Err(message)`.
///
/// For operations that hold no group state to restore: a group being
/// created or joined (its provider is discarded on error), or a
/// stateless check such as KeyPackage validation.
pub(crate) fn catch_crypto_panic<T>(op: impl FnOnce() -> T) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(op)).map_err(|payload| {
        let message = panic_message(payload.as_ref());
        tracing::error!(
            panic = %message,
            "openmls crypto panicked; contained and refused (CIRISEdge#822, \
             RUSTSEC-2026-0330/0331)"
        );
        message
    })
}

type StorageMap = HashMap<Vec<u8>, Vec<u8>>;

fn copy_storage(provider: &LibcruxProvider) -> StorageMap {
    provider
        .storage()
        .values
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// A new provider whose storage is `map`: fresh locks, fresh RNG.
fn provider_holding(map: StorageMap) -> Arc<LibcruxProvider> {
    let provider = LibcruxProvider::default();
    *provider
        .storage()
        .values
        .write()
        .unwrap_or_else(PoisonError::into_inner) = map;
    Arc::new(provider)
}

/// Run a state-changing openmls operation on `group`, turning a panic
/// into `Err(message)` and putting `group` and its storage back as they
/// were before the call (module docs, "State after a caught panic").
///
/// `Ok` carries `op`'s own result, which is NOT rolled back on `Err`:
/// openmls's error paths are the caller's to handle, as before.
///
/// On a panic `*provider` is REPLACED (module docs): callers must hold
/// the provider only through the field passed here, never a clone of the
/// `Arc` taken before the call.
///
/// The returned message says whether the restore succeeded. A restore can
/// fail only if `MlsGroup::load` cannot read back a map that a live group
/// was just running on; the group and provider are then left as the panic
/// left them, and the message says so.
pub(crate) fn guard_group_op<T>(
    provider: &mut Arc<LibcruxProvider>,
    group: &mut MlsGroup,
    op: impl FnOnce(&mut MlsGroup, &LibcruxProvider) -> T,
) -> Result<T, String> {
    let before = copy_storage(provider);
    let group_id = group.group_id().clone();
    let current = Arc::clone(provider);
    let message = match catch_unwind(AssertUnwindSafe(|| op(group, &current))) {
        Ok(out) => return Ok(out),
        Err(payload) => panic_message(payload.as_ref()),
    };
    let fresh = provider_holding(before);
    match MlsGroup::load(fresh.storage(), &group_id) {
        Ok(Some(reloaded)) => {
            *group = reloaded;
            *provider = fresh;
            tracing::error!(
                panic = %message,
                epoch = group.epoch().as_u64(),
                "openmls crypto panicked; contained, group restored to its pre-operation \
                 state (CIRISEdge#822, RUSTSEC-2026-0330/0331)"
            );
            Err(format!(
                "{message} (group restored to its pre-operation state)"
            ))
        }
        other => {
            let why = match other {
                Ok(_) => "no group under its id in the restored storage".to_owned(),
                Err(e) => format!("{e:?}"),
            };
            tracing::error!(
                panic = %message,
                restore_error = %why,
                "openmls crypto panicked and the group could NOT be restored; it is left as \
                 the panic left it (CIRISEdge#822)"
            );
            Err(format!("{message} (group restore FAILED: {why})"))
        }
    }
}

/// The exact HPKE public-key length of `ciphersuite`'s KEM, measured from
/// the crypto provider itself rather than written down: derive a key pair
/// under the suite's HPKE config and count the public half.
///
/// For 0x004D that is X-Wing (draft-connolly-cfrg-xwing-kem-06): the
/// ML-KEM-768 encapsulation key (1184 bytes) followed by the X25519
/// public key (32 bytes), 1216 bytes. The unit test pins the number so a
/// provider bump that changes it is seen.
///
/// # Errors
/// The provider refused to derive a key pair for the suite.
pub(crate) fn hpke_public_key_len(ciphersuite: Ciphersuite) -> Result<usize, String> {
    let provider = LibcruxProvider::default();
    catch_crypto_panic(|| {
        provider
            .crypto()
            .derive_hpke_keypair(ciphersuite.hpke_config(), &[0u8; 32])
    })?
    .map(|pair| pair.public.len())
    .map_err(|e| format!("derive_hpke_keypair: {e:?}"))
}

/// [`hpke_public_key_len`] for the pinned 0x004D suite, measured once.
///
/// # Errors
/// As [`hpke_public_key_len`]; a failure is cached, and every KeyPackage
/// is then refused (fail closed).
pub(crate) fn xwing_public_key_len() -> Result<usize, String> {
    static LEN: OnceLock<Result<usize, String>> = OnceLock::new();
    LEN.get_or_init(|| hpke_public_key_len(super::cohort_group::CIPHERSUITE))
        .clone()
}

/// Refuse a KeyPackage whose HPKE `init_key` or leaf `encryption_key` is
/// not exactly the pinned suite's public-key length. Run it after
/// `validate`: a signature does not vouch for a key's length, and a short
/// key panics `libcrux-kem` 0.0.7 the first time this node encrypts to it.
///
/// # Errors
/// A human-readable reason naming the key and both lengths.
pub(crate) fn check_key_package_key_lengths(key_package: &KeyPackage) -> Result<(), String> {
    let want = xwing_public_key_len()?;
    let init_len = key_package.hpke_init_key().as_slice().len();
    if init_len != want {
        return Err(format!(
            "init_key length {init_len}, the 0x004D (X-Wing) public key is {want} bytes"
        ));
    }
    // `EncryptionKey::as_slice` is crate-private in openmls 0.8.1; its
    // TLS form is the key as `opaque<V>`, which `VLBytes` reads back.
    let enc = key_package
        .leaf_node()
        .encryption_key()
        .tls_serialize_detached()
        .map_err(|e| format!("encryption_key encode: {e:?}"))?;
    let (enc, rest) = VLBytes::tls_deserialize_bytes(&enc)
        .map_err(|e| format!("encryption_key decode: {e:?}"))?;
    let enc_len = enc.as_slice().len();
    if !rest.is_empty() || enc_len != want {
        return Err(format!(
            "leaf encryption_key length {enc_len}, the 0x004D (X-Wing) public key is {want} bytes"
        ));
    }
    Ok(())
}

/// Forge the attack input both planes' tests need: a correctly SIGNED
/// KeyPackage whose keys are short. Exactly what a hostile peer can
/// publish, because the KeyPackage's own signature key is theirs.
#[cfg(test)]
pub(crate) mod test_support {
    use openmls::prelude::{
        KeyPackage, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut, ProtocolVersion,
    };
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::signatures::Signer;
    use openmls_traits::OpenMlsProvider;
    use tls_codec::{Deserialize as _, DeserializeBytes as _, Serialize as _, VLBytes};

    /// An Ed25519 signature as `opaque<V>`: a 2-byte varint length
    /// (64 >= 64) and the 64 signature bytes.
    const SIG_TRAILER: usize = 66;

    fn vl(bytes: &[u8]) -> Vec<u8> {
        VLBytes::new(bytes.to_vec())
            .tls_serialize_detached()
            .unwrap()
    }

    /// RFC 9420 §5.1.2 SignWithLabel.
    fn sign_with_label(signer: &impl Signer, label: &str, content: &[u8]) -> Vec<u8> {
        let mut sign_content = vl(format!("MLS 1.0 {label}").as_bytes());
        sign_content.extend(vl(content));
        signer.sign(&sign_content).unwrap()
    }

    /// Strip a trailing Ed25519 `opaque<V>` signature.
    fn without_signature(bytes: &[u8]) -> &[u8] {
        let (body, sig) = bytes.split_at(bytes.len() - SIG_TRAILER);
        assert_eq!(&sig[..2], &[0x40, 0x40], "trailer is a 64-byte opaque<V>");
        body
    }

    /// Re-encode `key_package` with its `init_key` truncated to
    /// `init_len` and/or its leaf `encryption_key` truncated to `enc_len`,
    /// re-signing the leaf node and the KeyPackage with `signer` (the
    /// KeyPackage's own signature key) so `validate` passes. Returns the
    /// `MlsMessage`-framed wire form `key_package_from_bytes` reads.
    pub(crate) fn forge_short_keys(
        key_package: &KeyPackage,
        signer: &impl Signer,
        init_len: Option<usize>,
        enc_len: Option<usize>,
    ) -> Vec<u8> {
        let kp = key_package.tls_serialize_detached().unwrap();
        let (header, after_header) = kp.split_at(4); // version ‖ ciphersuite
        let (init, rest) = VLBytes::tls_deserialize_bytes(after_header).unwrap();
        let leaf = key_package.leaf_node().tls_serialize_detached().unwrap();
        assert!(rest.starts_with(&leaf), "leaf node follows init_key");
        let extensions = without_signature(&rest[leaf.len()..]);

        // The leaf: encryption_key ‖ the rest of LeafNodeTBS ‖ signature.
        // A KeyPackage-sourced LeafNodeTBS carries no group context.
        let (enc, leaf_after_enc) = VLBytes::tls_deserialize_bytes(&leaf).unwrap();
        let leaf_middle = without_signature(leaf_after_enc);
        let enc = enc.as_slice();
        let mut leaf_tbs = vl(&enc[..enc_len.unwrap_or(enc.len())]);
        leaf_tbs.extend_from_slice(leaf_middle);
        let mut new_leaf = leaf_tbs.clone();
        new_leaf.extend(vl(&sign_with_label(signer, "LeafNodeTBS", &leaf_tbs)));

        let init = init.as_slice();
        let mut tbs = header.to_vec();
        tbs.extend(vl(&init[..init_len.unwrap_or(init.len())]));
        tbs.extend(new_leaf);
        tbs.extend_from_slice(extensions);
        let mut forged = tbs.clone();
        forged.extend(vl(&sign_with_label(signer, "KeyPackageTBS", &tbs)));

        // MlsMessage framing (version ‖ wire_format), copied from the real one.
        let framed = MlsMessageOut::from(key_package.clone())
            .tls_serialize_detached()
            .unwrap();
        let mut out = framed[..framed.len() - kp.len()].to_vec();
        out.extend(forged);
        out
    }

    /// Decode and VALIDATE (signature, version, ciphersuite) without the
    /// key-length gate: the typed KeyPackage an attacker's bytes become if
    /// that gate is bypassed.
    pub(crate) fn validate_without_length_gate(bytes: &[u8]) -> KeyPackage {
        let msg = MlsMessageIn::tls_deserialize(&mut &*bytes).unwrap();
        let MlsMessageBodyIn::KeyPackage(kp_in) = msg.extract() else {
            panic!("not a KeyPackage");
        };
        kp_in
            .validate(LibcruxProvider::default().crypto(), ProtocolVersion::Mls10)
            .expect("a forged KeyPackage re-signed by its own key validates")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The derived length is X-Wing draft-06's public key: ML-KEM-768's
    /// 1184-byte encapsulation key ‖ a 32-byte X25519 key.
    #[test]
    fn the_pinned_suite_public_key_is_the_xwing_length() {
        assert_eq!(xwing_public_key_len(), Ok(1184 + 32));
    }

    /// The provider seam every edge group seals through (fork-822's
    /// witness on CIRISEdge#822): HPKE-seal to a short X-Wing key under
    /// the guard is an `Err` either way, a contained panic on
    /// `libcrux-kem` 0.0.7 or a refusal once the dependency is fixed, and
    /// never an unwind out of the call.
    #[test]
    fn hpke_seal_to_a_short_xwing_key_never_escapes_the_guard() {
        let provider = LibcruxProvider::default();
        for len in [0, 1, 32, 1183, 1215] {
            let pk = vec![0x5a; len];
            let sealed = catch_crypto_panic(|| {
                provider.crypto().hpke_seal(
                    super::super::cohort_group::CIPHERSUITE.hpke_config(),
                    &pk,
                    b"info",
                    b"aad",
                    b"ptxt",
                )
            });
            assert!(
                matches!(sealed, Err(_) | Ok(Err(_))),
                "len {len}: sealed to a short key"
            );
        }
    }

    /// A panic that fires while holding the provider's storage write
    /// guard poisons that `RwLock`, and `openmls_memory_storage` would
    /// panic on it forever after. The guard leaves the poisoned provider
    /// behind: afterwards the provider is a different, unpoisoned one, the
    /// group is at its pre-call epoch, and it goes on committing.
    #[test]
    fn a_poisoned_storage_lock_is_left_behind_and_the_group_keeps_committing() {
        use openmls::prelude::{
            BasicCredential, CredentialWithKey, LeafNodeParameters, MlsGroupCreateConfig,
        };
        use openmls_basic_credential::SignatureKeyPair;
        use openmls_traits::types::SignatureScheme;

        let mut provider = Arc::new(LibcruxProvider::default());
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(provider.storage()).unwrap();
        let config = MlsGroupCreateConfig::builder()
            .ciphersuite(super::super::cohort_group::CIPHERSUITE)
            .build();
        let mut group = MlsGroup::new(
            provider.as_ref(),
            &signer,
            &config,
            CredentialWithKey {
                credential: BasicCredential::new(b"node-a".to_vec()).into(),
                signature_key: signer.to_public_vec().into(),
            },
        )
        .unwrap();
        let epoch = group.epoch().as_u64();
        let old = Arc::clone(&provider);

        let r: Result<(), String> = guard_group_op(&mut provider, &mut group, |group, p| {
            group
                .self_update(p, &signer, LeafNodeParameters::default())
                .unwrap();
            let _held = p.storage().values.write().unwrap();
            panic!("poisoned on purpose");
        });
        let message = r.expect_err("the panic is contained");
        assert!(
            message.contains("restored to its pre-operation state"),
            "{message}"
        );
        assert!(
            old.storage().values.is_poisoned(),
            "the test did poison the old lock"
        );
        assert!(!Arc::ptr_eq(&old, &provider), "the provider was replaced");
        assert!(!provider.storage().values.is_poisoned());
        assert_eq!(group.epoch().as_u64(), epoch);
        assert!(
            group.pending_commit().is_none(),
            "the staged commit is gone"
        );

        guard_group_op(&mut provider, &mut group, |group, p| {
            group
                .self_update(p, &signer, LeafNodeParameters::default())
                .unwrap();
            group.merge_pending_commit(p).unwrap();
        })
        .expect("the group commits on the fresh provider");
        assert_eq!(group.epoch().as_u64(), epoch + 1);
    }

    #[test]
    fn a_panic_becomes_its_message() {
        assert_eq!(catch_crypto_panic(|| 7), Ok(7));
        let r: Result<(), String> = catch_crypto_panic(|| panic!("short key {}", 32));
        assert_eq!(r, Err("short key 32".to_owned()));
    }
}
