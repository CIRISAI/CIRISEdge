//! Substrate-tier MLS state at rest (CIRISEdge#175 v6.0.0; CIRISEdge#676
//! v32.1.0 — `FSD/MLS_STATE_AT_REST.md`).
//!
//! Backed by [`ciris_persist::encrypted_kv::XChaChaKvStore`] — persist's
//! app-layer XChaCha20-Poly1305-sealed KV. The at-rest database file is
//! **opaque** to anyone who reads it without the key (CEWP
//! `SCOPE_PRIVACY.md` §6 / §7.8 cold-state opacity).
//!
//! # How MLS state is durable here
//!
//! [`super::cohort_group`] snapshots openmls's storage map into this store
//! on every commit and restores it with `MlsGroup::load` on open. That IS
//! edge's realisation of durable MLS state: openmls 0.8.1's libcrux
//! `Provider` fixes its storage to a private in-memory map, so a
//! per-method `openmls_traits::storage::StorageProvider` over the KV would
//! need edge's own `OpenMlsProvider` for the same durability at ~60
//! synchronous KV round-trips per commit. The snapshot stays the mechanism
//! (FSD §0); the old "DEFERRED to v6.1.0" note is retired.
//!
//! # Whose key
//!
//! [`open_mls_state`] — persist's opener, run off the async worker — keys
//! the store from persist's ONE hardware-sealed seed under
//! [`ciris_persist::encrypted_kv::MLS_STATE_CONTEXT`]. No seed ⇒
//! [`MlsStateUnavailable::HardwareCustodyUnavailable`], the named degraded
//! posture: the host keeps state in memory ([`ScopeStateProvider::ephemeral`],
//! stated as such) or opens with a passphrase the OPERATOR supplies. **Edge
//! never derives a passphrase** — not from a room id, a key id or a path
//! (FSD §1; the CIRISServer#630 shape this module exists to remove).
//!
//! # Namespace conventions
//!
//! Per-room state is namespaced `mls/{community_id}/{kind}`; persist's
//! namespace isolation is cryptographic (`K_value(ns)` is HKDF-bound to the
//! namespace bytes). One store houses every room the node is in. Kinds:
//! - [`KIND_GROUP_STATE`] — the openmls storage snapshot per epoch, plus the
//!   head and ledger slots `cohort_group` keeps beside it;
//! - [`KIND_ARCHIVE_MODE`] — the §3.5 per-community archive policy;
//! - [`KIND_PENDING_JOIN`] — a published KeyPackage's private material
//!   while its Welcome is in flight (FSD §3);
//! - [`KIND_MEMBER_JOINS`] — per-member add instants, the restart signal's
//!   reference point (FSD §4.1).
//!
//! The KV has no cross-namespace listing, so the rooms this node holds are
//! indexed under [`ROOMS_INDEX_NAMESPACE`] by [`ScopeStateProvider::group_state_put`]
//! and enumerated by [`ScopeStateProvider::persisted_room_ids`] (FSD §5).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use ciris_persist::encrypted_kv::{EncryptedKVStore, KVError, MlsStateCustody, XChaChaKvStore};

use super::archive_mode::{ArchiveMode, ArchiveModeError, ARCHIVE_MODE_NAMESPACE};

/// MLS group-state kind — the openmls storage snapshot per epoch (and the
/// head / ledger slots `cohort_group` keeps at reserved epochs).
pub const KIND_GROUP_STATE: &str = "group_state";

/// Archive-mode kind — see [`ARCHIVE_MODE_NAMESPACE`].
pub const KIND_ARCHIVE_MODE: &str = ARCHIVE_MODE_NAMESPACE;

/// CIRISEdge#676 — a published KeyPackage's private material, held until
/// its Welcome arrives (one slot per room; the next `PublishKeyPackage`
/// overwrites it; a successful join deletes it).
pub const KIND_PENDING_JOIN: &str = "pending_join";

/// CIRISEdge#676 — `{member_key_id → added_at}` for the room's current
/// members, written beside every group-state snapshot.
pub const KIND_MEMBER_JOINS: &str = "member_joins";

/// CIRISEdge#676 — the index of rooms this node holds state for: one key
/// per `community_id`, value `b"1"`. Never a room's own namespace, so a
/// room id can neither collide with nor enumerate another.
pub const ROOMS_INDEX_NAMESPACE: &str = "mls/__rooms__/index";

/// Build the per-community namespace for a kind under
/// `mls/{community_id}/{kind}`.
#[must_use]
fn namespace_for(community_id: &str, kind: &str) -> String {
    format!("mls/{community_id}/{kind}")
}

/// Substrate-tier MLS state provider — the sealed-KV surface every MLS
/// group in this process persists through.
///
/// # Cloning
///
/// Holds an [`Arc<XChaChaKvStore>`]. Cheap to clone; clones share the same
/// on-disk database and key.
#[derive(Clone)]
pub struct ScopeStateProvider {
    kv: Arc<XChaChaKvStore>,
    /// Test-only failure injection: while set, `group_state_put` fails (a
    /// store double for the "ack write failed" witness, CIRISEdge#697).
    #[cfg(test)]
    pub(crate) fail_group_state_puts: Arc<std::sync::atomic::AtomicBool>,
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

/// CIRISEdge#676 — why the durable MLS-state store could not be opened.
///
/// The host reads the variant, never the string: the first is the
/// **degraded posture** (choose in-memory state or an operator passphrase,
/// FSD §1); the second is a store that must be inspected, not worked
/// around.
#[derive(Debug, thiserror::Error)]
pub enum MlsStateUnavailable {
    /// persist found no hardware-sealed seed to root the store in (no TPM /
    /// Keystore / Secure Enclave, a build without persist's `secrets`
    /// feature, `CIRIS_DATA_DIR` unset, or — for a store already in use — a
    /// seed that has gone missing). **Nothing was opened.** The only
    /// fallbacks are an explicit [`ScopeStateProvider::ephemeral`] store or
    /// a passphrase the operator supplies; edge derives none.
    #[error("MLS state store: hardware custody unavailable — {0}")]
    HardwareCustodyUnavailable(String),
    /// The store exists but refused to open under the derived key (wrong
    /// key, tampered rows, a backend fault). Do not fall back: a store that
    /// will not open is a store to look at.
    #[error("MLS state store at {path}: {source}")]
    Store {
        /// The store the host asked for.
        path: PathBuf,
        /// persist's refusal.
        source: KVError,
    },
    /// The blocking opener panicked or was cancelled.
    #[error("MLS state store: opener task failed — {0}")]
    Join(String),
}

/// CIRISEdge#676 / #694 — **open the durable MLS-state store at `path`,
/// keyed from the root persist's content master resolves to on this host**
/// (persist v50.0.0 #920, `Engine::open_mls_state`), and report which.
///
/// The root is named by the persisted `federation_content_master` row: the
/// hardware-sealed seed where the row says `hardware`, otherwise the persisted
/// SOFTWARE content master (`BLOB_ENCRYPTION_AT_REST.md` §4.3 — "a software
/// fallback that is honest about being software"). **Both are durable on
/// disk**; a TPM-less host (every CI runner) opens the store and gets
/// [`MlsStateCustodyKind::Software`] by name — a custody CLASS, never a
/// failure (CC 4.2.2.1). The kind is logged here and returned so the host can
/// report it. One store per node, every room namespaced inside it (FSD §2).
///
/// # Errors
/// [`MlsStateUnavailable::HardwareCustodyUnavailable`] is persist's §11.7
/// refusal only — the row says hardware and the seed is unreachable — and is
/// the one case a host falls back to [`ScopeStateProvider::ephemeral`].
/// Every other refusal is [`MlsStateUnavailable::Store`].
pub async fn open_mls_state(
    engine: &ciris_persist::Engine,
    path: impl AsRef<Path>,
) -> Result<(ScopeStateProvider, MlsStateCustody), MlsStateUnavailable> {
    let path = path.as_ref().to_path_buf();
    match engine.open_mls_state(&path).await {
        Ok((kv, custody)) => {
            tracing::info!(
                path = %path.display(),
                custody = custody.kind.as_str(),
                descriptor = %custody.descriptor,
                "MLS-state store opened on disk (custody `{}`)",
                custody.kind.as_str()
            );
            Ok((ScopeStateProvider::new(Arc::new(kv)), custody))
        }
        Err(KVError::HardwareCustodyUnavailable(detail)) => {
            Err(MlsStateUnavailable::HardwareCustodyUnavailable(detail))
        }
        Err(source) => Err(MlsStateUnavailable::Store { path, source }),
    }
}

impl ScopeStateProvider {
    /// Wrap an existing [`XChaChaKvStore`] handle. The store MUST already
    /// be opened under a real key: persist's sealed seed
    /// ([`open_mls_state`]) or the operator's passphrase
    /// ([`XChaChaKvStore::open`]).
    #[must_use]
    pub fn new(kv: Arc<XChaChaKvStore>) -> Self {
        Self {
            kv,
            #[cfg(test)]
            fail_group_state_puts: Arc::default(),
        }
    }

    /// CIRISEdge#676 — an **in-memory** store under a random one-shot key:
    /// the named "state does not survive this process" posture a host
    /// chooses ONLY when [`open_mls_state`] answers
    /// [`MlsStateUnavailable::HardwareCustodyUnavailable`] — persist's §11.7
    /// refusal (the row says hardware, the seed is unreachable). A host with no
    /// TPM does NOT get here: it opens on disk under the software master. Replaces every
    /// `open_in_memory(room_id)` (a room id is public; a key sealed under it
    /// is a key sealed under nothing).
    ///
    /// # Panics
    /// Never in practice: an in-memory SQLite open with a 32-byte random
    /// passphrase fails only if the allocator does.
    #[must_use]
    pub fn ephemeral() -> Self {
        let mut pass = [0u8; 32];
        pass[..16].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        pass[16..].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
        let kv = XChaChaKvStore::open_in_memory(&pass)
            .expect("an in-memory sealed KV under a random key always opens");
        Self::new(Arc::new(kv))
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

    /// Read the MLS group-state snapshot for `(community_id, epoch)`, or
    /// `None` if none has been persisted.
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

    /// Write the MLS group-state snapshot for `(community_id, epoch)`.
    /// Overwrites any prior value at the same coordinates, and records the
    /// room in the [`ROOMS_INDEX_NAMESPACE`] so a restart can find it
    /// (CIRISEdge#676; idempotent).
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
        #[cfg(test)]
        if self
            .fail_group_state_puts
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err(ScopeStateProviderError::Codec(
                "injected put failure".into(),
            ));
        }
        let ns = namespace_for(community_id, KIND_GROUP_STATE);
        let key = epoch.to_be_bytes();
        self.kv.put(&ns, &key, bytes).await?;
        self.kv
            .put(ROOMS_INDEX_NAMESPACE, community_id.as_bytes(), b"1")
            .await?;
        Ok(())
    }

    /// Delete the snapshot for `(community_id, epoch)` — the §3.5
    /// `rotate-forward` past-epoch prune. The room stays indexed; see
    /// [`Self::forget_room`] for leaving one.
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

    /// CIRISEdge#676 — every room this store holds group state for, sorted.
    /// The boot re-address walks this (FSD §5).
    ///
    /// # Errors
    ///
    /// - KV scan fault → [`ScopeStateProviderError::Kv`]
    pub async fn persisted_room_ids(&self) -> Result<Vec<String>, ScopeStateProviderError> {
        let rows = self.kv.scan(ROOMS_INDEX_NAMESPACE, b"").await?;
        let mut ids: Vec<String> = rows
            .into_iter()
            .filter_map(|p| String::from_utf8(p.0).ok())
            .collect();
        ids.sort();
        ids.dedup();
        Ok(ids)
    }

    /// CIRISEdge#676 — leave a room: delete every persisted slot for it
    /// (group state at every epoch, the ledger/head slots, the pending
    /// material, the member joins) and drop it from the index.
    ///
    /// # Errors
    ///
    /// - KV scan/delete fault → [`ScopeStateProviderError::Kv`]
    pub async fn forget_room(&self, community_id: &str) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_GROUP_STATE);
        for pair in self.kv.scan(&ns, b"").await? {
            self.kv.delete(&ns, &pair.0).await?;
        }
        self.pending_join_delete(community_id).await?;
        self.kv
            .delete(&namespace_for(community_id, KIND_MEMBER_JOINS), b"v1")
            .await?;
        self.kv
            .delete(ROOMS_INDEX_NAMESPACE, community_id.as_bytes())
            .await?;
        Ok(())
    }

    /// CIRISEdge#676 — the pending-join material for `community_id`
    /// (FSD §3), if a KeyPackage was published and no Welcome consumed yet.
    ///
    /// # Errors
    ///
    /// - KV read fault → [`ScopeStateProviderError::Kv`]
    pub async fn pending_join_get(
        &self,
        community_id: &str,
    ) -> Result<Option<Vec<u8>>, ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_PENDING_JOIN);
        Ok(self.kv.get(&ns, b"v1").await?)
    }

    /// Write the pending-join material for `community_id` (overwrites — the
    /// newest published KeyPackage is the one a Welcome will be sealed to).
    ///
    /// # Errors
    ///
    /// - KV write fault → [`ScopeStateProviderError::Kv`]
    pub async fn pending_join_put(
        &self,
        community_id: &str,
        bytes: &[u8],
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_PENDING_JOIN);
        self.kv.put(&ns, b"v1", bytes).await?;
        Ok(())
    }

    /// Delete the pending-join material for `community_id` (on a successful
    /// join, or when the room is abandoned).
    ///
    /// # Errors
    ///
    /// - KV delete fault → [`ScopeStateProviderError::Kv`]
    pub async fn pending_join_delete(
        &self,
        community_id: &str,
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_PENDING_JOIN);
        self.kv.delete(&ns, b"v1").await?;
        Ok(())
    }

    /// CIRISEdge#676 — `{member_key_id → added_at}` for `community_id`'s
    /// current members (FSD §4.1), or `None` before the first persist.
    ///
    /// # Errors
    ///
    /// - KV read fault → [`ScopeStateProviderError::Kv`]
    /// - Corrupt JSON → [`ScopeStateProviderError::Codec`]
    pub async fn member_joins_get(
        &self,
        community_id: &str,
    ) -> Result<Option<HashMap<String, DateTime<Utc>>>, ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_MEMBER_JOINS);
        match self.kv.get(&ns, b"v1").await? {
            None => Ok(None),
            Some(bytes) => serde_json::from_slice(&bytes)
                .map(Some)
                .map_err(|e| ScopeStateProviderError::Codec(e.to_string())),
        }
    }

    /// Test-only: drop a room's join map, to reproduce a store persisted
    /// before the map existed (CIRISEdge#695 upgrade witness).
    #[cfg(test)]
    pub(crate) async fn member_joins_delete(
        &self,
        community_id: &str,
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_MEMBER_JOINS);
        self.kv.delete(&ns, b"v1").await?;
        Ok(())
    }

    /// Write `{member_key_id → added_at}` for `community_id`.
    ///
    /// # Errors
    ///
    /// - KV write fault → [`ScopeStateProviderError::Kv`]
    /// - Codec fault → [`ScopeStateProviderError::Codec`]
    pub async fn member_joins_put(
        &self,
        community_id: &str,
        joins: &HashMap<String, DateTime<Utc>>,
    ) -> Result<(), ScopeStateProviderError> {
        let ns = namespace_for(community_id, KIND_MEMBER_JOINS);
        let bytes =
            serde_json::to_vec(joins).map_err(|e| ScopeStateProviderError::Codec(e.to_string()))?;
        self.kv.put(&ns, b"v1", &bytes).await?;
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

    /// FSD §5 — every room a snapshot was written for is enumerable, once,
    /// sorted; a pruned epoch keeps the room indexed; `forget_room` removes
    /// it and everything under it.
    #[tokio::test]
    async fn persisted_rooms_are_indexed_by_the_snapshot_write_and_forgotten_whole() {
        let provider = open_provider();
        assert!(provider.persisted_room_ids().await.unwrap().is_empty());
        for room in ["chat:room:v1:b", "chat:room:v1:a", "person-x"] {
            provider.group_state_put(room, 0, b"s0").await.unwrap();
            provider.group_state_put(room, 1, b"s1").await.unwrap();
        }
        assert_eq!(
            provider.persisted_room_ids().await.unwrap(),
            vec!["chat:room:v1:a", "chat:room:v1:b", "person-x"],
            "sorted, deduplicated across epochs"
        );
        // Pruning an epoch is not leaving the room.
        provider.group_state_delete("person-x", 0).await.unwrap();
        assert_eq!(provider.persisted_room_ids().await.unwrap().len(), 3);
        provider
            .pending_join_put("person-x", b"material")
            .await
            .unwrap();
        provider.forget_room("person-x").await.unwrap();
        assert_eq!(
            provider.persisted_room_ids().await.unwrap(),
            vec!["chat:room:v1:a", "chat:room:v1:b"]
        );
        assert_eq!(provider.group_state_get("person-x", 1).await.unwrap(), None);
        assert_eq!(provider.pending_join_get("person-x").await.unwrap(), None);
    }

    /// FSD §3 / §4.1 — the two new slots round-trip and are per room.
    #[tokio::test]
    async fn pending_join_and_member_joins_round_trip_per_room() {
        let provider = open_provider();
        assert_eq!(provider.pending_join_get("r").await.unwrap(), None);
        provider.pending_join_put("r", b"km-1").await.unwrap();
        provider.pending_join_put("r", b"km-2").await.unwrap();
        assert_eq!(
            provider.pending_join_get("r").await.unwrap(),
            Some(b"km-2".to_vec()),
            "the newest published KeyPackage's material wins"
        );
        assert_eq!(provider.pending_join_get("other").await.unwrap(), None);
        provider.pending_join_delete("r").await.unwrap();
        assert_eq!(provider.pending_join_get("r").await.unwrap(), None);

        let mut joins = HashMap::new();
        joins.insert(
            "node-a".to_owned(),
            DateTime::from_timestamp_millis(1_700_000_000_000).unwrap(),
        );
        provider.member_joins_put("r", &joins).await.unwrap();
        assert_eq!(provider.member_joins_get("r").await.unwrap(), Some(joins));
        assert_eq!(provider.member_joins_get("other").await.unwrap(), None);
    }

    /// FSD §7 S2 (v50, #694) — on a host with no hardware storage (every CI
    /// runner, and this one) the opener opens ON DISK under the persisted
    /// SOFTWARE content master and says so by name; a hardware host opens
    /// `Hardware`. Either way the store is durable: re-opening through the
    /// same engine reads back what was written. The degraded in-memory posture
    /// is reachable only through persist's §11.7 refusal, which this host
    /// cannot produce.
    #[tokio::test]
    async fn a_tpm_less_host_opens_the_store_on_disk_as_software() {
        use ciris_persist::encrypted_kv::MlsStateCustodyKind;
        use ciris_persist::store::backend::Backend as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mls-state.kv");
        let backend = ciris_persist::prelude::FederationDirectorySqlite::open(
            dir.path().join("persist.db").to_string_lossy().to_string(),
        )
        .await
        .expect("open substrate");
        backend.run_migrations().await.expect("migrate");
        let mut ed = ciris_keyring::Ed25519SoftwareSigner::new("mls-state-test");
        ed.import_key(&[9u8; 32]).expect("import test key");
        let signer: Arc<dyn ciris_keyring::HardwareSigner> = Arc::new(ed);
        let engine = ciris_persist::Engine::from_shared(
            ciris_persist::BackendDispatch::Sqlite(backend),
            signer,
        );
        let (p, custody) = open_mls_state(&engine, &path)
            .await
            .expect("a host without a TPM still opens a durable store");
        assert!(path.exists(), "the store is ON DISK, not in memory");
        assert!(
            matches!(
                custody.kind,
                MlsStateCustodyKind::Software | MlsStateCustodyKind::Hardware
            ),
            "the custody class is reported by name: {custody:?}"
        );
        assert!(
            !custody.descriptor.is_empty(),
            "the descriptor names the root"
        );
        p.group_state_put("r", 0, b"state").await.expect("write");
        drop(p);
        let (reopened, again) = open_mls_state(&engine, &path).await.expect("reopen");
        assert_eq!(
            again.kind, custody.kind,
            "the row wins: same custody on reopen"
        );
        assert_eq!(
            reopened
                .group_state_get("r", 0)
                .await
                .expect("read")
                .as_deref(),
            Some(&b"state"[..]),
            "durable across opens"
        );
    }

    /// FSD §7 S7 — a store opened under another key is refused, not decoded
    /// as state (persist's verifier row fails the AEAD check).
    #[tokio::test]
    async fn a_store_under_another_key_is_refused_not_decoded() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mls-state.kv");
        {
            let kv = XChaChaKvStore::open(&path, b"operator-passphrase").unwrap();
            let p = ScopeStateProvider::new(Arc::new(kv));
            p.group_state_put("r", 0, b"secret state").await.unwrap();
        }
        let refused = XChaChaKvStore::open(&path, b"a-room-id-is-not-a-passphrase");
        assert!(
            matches!(refused, Err(KVError::WrongPassphrase)),
            "another key must be refused at open"
        );
    }

    /// FSD §7 S8 — `ephemeral()` is random per open: two ephemeral stores
    /// never share a key, and nothing here passes a room id to `open`.
    #[tokio::test]
    async fn ephemeral_stores_are_independent() {
        let a = ScopeStateProvider::ephemeral();
        let b = ScopeStateProvider::ephemeral();
        a.group_state_put("r", 0, b"only in a").await.unwrap();
        assert_eq!(b.group_state_get("r", 0).await.unwrap(), None);
    }
}
