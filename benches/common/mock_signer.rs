//! Software Ed25519 signer for bench fixtures.
//!
//! Wraps `ciris-keyring::load_local_seed` over a deterministic
//! 32-byte seed file written to a `tempfile::TempDir`. The bench
//! re-uses the same path persist's keyring loader expects
//! (`ed25519.seed` at the directory root) so we share the production
//! load-bearing code path — no bench-only shortcut into the signer.

#![allow(
    clippy::pedantic,
    clippy::needless_pass_by_value,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::cast_possible_truncation,
    clippy::cast_lossless,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::items_after_statements,
    clippy::used_underscore_binding,
    clippy::field_reassign_with_default,
    clippy::needless_raw_string_hashes
)]

use std::sync::Arc;

use ciris_edge::identity::LocalSigner;

use super::mock_directory::BenchFedKey;

/// Build a software-backed `LocalSigner` over the given identity.
/// The bench harness owns the `tempfile::TempDir`'s lifetime;
/// dropping the dir after the bench finishes is the cleanup.
///
/// Returns an `Arc<LocalSigner>` ready to pass to `EdgeBuilder::signer`.
pub async fn bench_local_signer(me: &BenchFedKey, tmp: &tempfile::TempDir) -> Arc<LocalSigner> {
    let seed_dir = me.write_seed_dir(tmp.path());
    let (classical, _pqc) = ciris_keyring::load_local_seed(ciris_keyring::LocalSeedConfig {
        key_id: me.key_id.clone(),
        key_path: seed_dir.join("ed25519.seed"),
        pqc_key_id: None,
        pqc_key_path: None,
    })
    .await
    .expect("load_local_seed");

    Arc::new(LocalSigner {
        key_id: me.key_id.clone(),
        classical,
        pqc: None,
    })
}
