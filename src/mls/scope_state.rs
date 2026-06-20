//! Substrate-tier MLS state provider (CIRISEdge#175, v6.0.0).
//!
//! Backed by [`ciris_persist::encrypted_kv::XChaChaKvStore`] — the
//! persist v9.2.0 app-layer XChaCha20-Poly1305-sealed KV store. The
//! at-rest database file is **opaque** to anyone who reads it
//! without the boot passphrase (CEWP `SCOPE_PRIVACY.md` §6 / §7.8
//! cold-state opacity property).
//!
//! # What this is in v6.0.0
//!
//! The persistent KV surface CIRISEdge layers substrate-tier MLS
//! group state on. Per FSD §6.1 the openmls 0.8
//! [`openmls_traits::storage::StorageProvider`] implementation is
//! the eventual landing point; v6.0.0 ships the
//! [`ScopeStateProvider`] scaffold that owns the KV handle, the
//! namespace conventions (one per `(community_id, group_epoch)`),
//! and the [`crate::mls::archive_mode::ArchiveMode`] get/put surface.
//!
//! The full `StorageProvider` trait surface (~60 methods spanning
//! group state, ratchet trees, secrets, proposals, key packages,
//! own-leaf bookkeeping) is **DEFERRED to v6.1.0** so this cut
//! doesn't carry a half-implemented MLS storage layer. The deferred
//! work lives at [`StorageProvider impl`](https://github.com/CIRISAI/CIRISEdge/issues/175)
//! — the v6.0.0 cut intentionally hands edge an opaque KV with the
//! right namespace conventions, and v6.1.0 will implement the trait
//! over THIS exact scaffold.
//!
//! # Namespace conventions
//!
//! Per-community state is namespaced as
//! `"mls/{community_id}/{kind}"` so a single
//! `XChaChaKvStore` houses every community the operator participates
//! in without cross-namespace AEAD bleed (persist's namespace
//! isolation is cryptographic: `K_value(ns)` is HKDF-bound to the
//! namespace bytes — see persist v9.2.0 `encrypted_kv` module docs).
//!
//! Kinds defined in v6.0.0:
//! - [`KIND_ARCHIVE_MODE`] — the §3.5 per-community archive policy
//!   (stored under [`super::archive_mode::ARCHIVE_MODE_NAMESPACE`]
//!   sub-key).
//! - [`KIND_GROUP_STATE`] — opaque MLS group serialization
//!   (v6.1.0 fills in via `StorageProvider`).

use std::sync::Arc;

use ciris_persist::encrypted_kv::{EncryptedKVStore, KVError, XChaChaKvStore};

use super::archive_mode::{ArchiveMode, ArchiveModeError, ARCHIVE_MODE_NAMESPACE};

/// MLS group-state kind. The opaque MLS serialization
/// (`MlsGroup::save` output, or the v6.1.0 `StorageProvider`-
/// produced serialization).
pub const KIND_GROUP_STATE: &str = "group_state";

/// Archive-mode kind — see [`ARCHIVE_MODE_NAMESPACE`].
pub const KIND_ARCHIVE_MODE: &str = ARCHIVE_MODE_NAMESPACE;

/// Build the per-community namespace for a kind under
/// `mls/{community_id}/{kind}`.
#[must_use]
fn namespace_for(community_id: &str, kind: &str) -> String {
    format!("mls/{community_id}/{kind}")
}

/// Substrate-tier MLS state provider — the KV-backed surface the
/// v6.1.0 openmls 0.8 [`StorageProvider`] will implement over.
///
/// # Cloning
///
/// `ScopeStateProvider` holds an [`Arc<XChaChaKvStore>`]. Cheap to
/// clone; clones share the same on-disk database and boot
/// passphrase.
///
/// # v6.0.0 surface
///
/// - [`Self::archive_mode_get`] / [`Self::archive_mode_put`] — §3.5
///   per-community archive policy.
/// - [`Self::group_state_get`] / [`Self::group_state_put`] —
///   opaque MLS group serialization slot. Will be the entry point
///   for v6.1.0's `StorageProvider::write_group_state` /
///   `read_group_state`.
#[derive(Clone)]
pub struct ScopeStateProvider {
    kv: Arc<XChaChaKvStore>,
}

/// Errors from the substrate-tier MLS state provider.
#[derive(Debug, thiserror::Error)]
pub enum ScopeStateProviderError {
    /// Underlying [`XChaChaKvStore`] error.
    #[error("kv error: {0}")]
    Kv(KVError),
    /// Archive-mode codec / validation error.
    #[error(transparent)]
    ArchiveMode(#[from] ArchiveModeError),
    /// CBOR / JSON codec error.
    #[error("codec error: {0}")]
    Codec(String),
}

impl From<KVError> for ScopeStateProviderError {
    fn from(e: KVError) -> Self {
        Self::Kv(e)
    }
}

impl ScopeStateProvider {
    /// Wrap an existing [`XChaChaKvStore`] handle. The store MUST
    /// already be opened with the operator's boot passphrase (or a
    /// hardware-released equivalent — see persist v9.2.0
    /// `encrypted_kv` "Hardware-key custodian boundary").
    #[must_use]
    pub fn new(kv: Arc<XChaChaKvStore>) -> Self {
        Self { kv }
    }

    /// Read the per-community [`ArchiveMode`], or `None` if no
    /// archive_mode has been configured for this community.
    ///
    /// # Errors
    ///
    /// - KV read fault → [`ScopeStateProviderError::Kv`]
    /// - Corrupt JSON value → [`ScopeStateProviderError::Codec`]
    pub async fn archive_mode_get(
        &self,
        community_id: &str,
    ) -> Result<Option<ArchiveMode>, ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_ARCHIVE_MODE);
        let raw = self.kv.get(&ns, b"v1").await?;
        match raw {
            None => Ok(None),
            Some(bytes) => {
                let parsed: ArchiveMode = serde_json::from_slice(&bytes)
                    .map_err(|e| ScopeStateProviderError::Codec(e.to_string()))?;
                Ok(Some(parsed))
            }
        }
    }

    /// Write the per-community [`ArchiveMode`]. The mode is
    /// validated ([`ArchiveMode::validate`]) before storage.
    ///
    /// # Errors
    ///
    /// - Validation fault → [`ScopeStateProviderError::ArchiveMode`]
    /// - KV write fault → [`ScopeStateProviderError::Kv`]
    pub async fn archive_mode_put(
        &self,
        community_id: &str,
        mode: ArchiveMode,
    ) -> Result<(), ScopeStateProviderError> {
        mode.validate()?;
        let ns = namespace_for(community_id, KIND_ARCHIVE_MODE);
        let bytes =
            serde_json::to_vec(&mode).map_err(|e| ScopeStateProviderError::Codec(e.to_string()))?;
        self.kv.put(&ns, b"v1", &bytes).await?;
        Ok(())
    }

    /// Read the opaque MLS group-state serialization, or `None` if
    /// no group state has been persisted for `(community_id, epoch)`.
    ///
    /// v6.0.0 ships an opaque `Vec<u8>` slot; v6.1.0's
    /// `StorageProvider` will own the codec.
    ///
    /// # Errors
    ///
    /// - KV read fault → [`ScopeStateProviderError::Kv`]
    pub async fn group_state_get(
        &self,
        community_id: &str,
        epoch: u64,
    ) -> Result<Option<Vec<u8>>, ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_GROUP_STATE);
        let key = epoch.to_be_bytes();
        let raw = self.kv.get(&ns, &key).await?;
        Ok(raw)
    }

    /// Write the opaque MLS group-state serialization for
    /// `(community_id, epoch)`. Overwrites any prior value at the
    /// same coordinates (re-persisting the same epoch after a no-op
    /// commit is allowed).
    ///
    /// # Errors
    ///
    /// - KV write fault → [`ScopeStateProviderError::Kv`]
    pub async fn group_state_put(
        &self,
        community_id: &str,
        epoch: u64,
        bytes: &[u8],
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_GROUP_STATE);
        let key = epoch.to_be_bytes();
        self.kv.put(&ns, &key, bytes).await?;
        Ok(())
    }

    /// Delete the opaque MLS group-state serialization for
    /// `(community_id, epoch)`. Used by §3.5 `rotate-forward`'s
    /// past-epoch-key prune sweep (honest-holder discipline; FSD
    /// §3.5 / §7.8).
    ///
    /// # Errors
    ///
    /// - KV delete fault → [`ScopeStateProviderError::Kv`]
    pub async fn group_state_delete(
        &self,
        community_id: &str,
        epoch: u64,
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_GROUP_STATE);
        let key = epoch.to_be_bytes();
        self.kv.delete(&ns, &key).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open_provider() -> ScopeStateProvider {
        let kv = XChaChaKvStore::open_in_memory(b"test-passphrase").unwrap();
        ScopeStateProvider::new(Arc::new(kv))
    }

    #[tokio::test]
    async fn archive_mode_roundtrip() {
        let provider = open_provider();
        assert_eq!(
            provider.archive_mode_get("community-1").await.unwrap(),
            None
        );

        let mode = ArchiveMode::RotateForward { window_days: 7 };
        provider
            .archive_mode_put("community-1", mode)
            .await
            .unwrap();
        let back = provider.archive_mode_get("community-1").await.unwrap();
        assert_eq!(back, Some(mode));
    }

    #[tokio::test]
    async fn archive_mode_per_community_isolation() {
        let provider = open_provider();
        provider
            .archive_mode_put("community-A", ArchiveMode::default())
            .await
            .unwrap();
        provider
            .archive_mode_put("community-B", ArchiveMode::Retain)
            .await
            .unwrap();
        assert_eq!(
            provider.archive_mode_get("community-A").await.unwrap(),
            Some(ArchiveMode::default())
        );
        assert_eq!(
            provider.archive_mode_get("community-B").await.unwrap(),
            Some(ArchiveMode::Retain)
        );
    }

    #[tokio::test]
    async fn archive_mode_rejects_invalid_window() {
        let provider = open_provider();
        let bad = ArchiveMode::RotateForward { window_days: 0 };
        assert!(matches!(
            provider.archive_mode_put("community-c", bad).await,
            Err(ScopeStateProviderError::ArchiveMode(
                ArchiveModeError::WindowDaysOutOfBounds(0)
            ))
        ));
    }

    #[tokio::test]
    async fn group_state_roundtrip() {
        let provider = open_provider();
        assert_eq!(provider.group_state_get("c1", 0).await.unwrap(), None);

        let payload = b"opaque mls group serialization".to_vec();
        provider.group_state_put("c1", 0, &payload).await.unwrap();
        assert_eq!(
            provider.group_state_get("c1", 0).await.unwrap(),
            Some(payload.clone())
        );

        // Distinct epoch is independent.
        assert_eq!(provider.group_state_get("c1", 1).await.unwrap(), None);

        // Delete the epoch — gone.
        provider.group_state_delete("c1", 0).await.unwrap();
        assert_eq!(provider.group_state_get("c1", 0).await.unwrap(), None);
    }

    #[tokio::test]
    async fn group_state_overwrites_per_epoch() {
        let provider = open_provider();
        provider.group_state_put("c1", 5, b"v1").await.unwrap();
        provider.group_state_put("c1", 5, b"v2").await.unwrap();
        assert_eq!(
            provider.group_state_get("c1", 5).await.unwrap(),
            Some(b"v2".to_vec())
        );
    }
}
