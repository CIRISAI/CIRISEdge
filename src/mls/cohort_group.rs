//! Persistent per-cohort MLS group (CIRISEdge#499, workstream E).
//!
//! The `community` / `affiliations` scopes need a **real**
//! `exporter_secret` — an RFC 9420 §8.5 epoch secret produced by an
//! actual MLS group with an actual roster — so
//! [`crate::scope_privacy`]'s `k_record_id` / `k_symbol` subkeys are
//! bound to group membership rather than to a placeholder. Unlike the
//! per-stream A/V group ([`crate::transport::realtime_av_mls`]), a
//! cohort group must **outlive the process**: a node that restarts
//! and cannot reload its cohort group has silently lost the ability
//! to read its own community's records.
//!
//! # Why a snapshot, and NOT `StorageProvider` (CIRISEdge#217)
//!
//! The obvious design is to implement openmls's
//! [`openmls_traits::storage::StorageProvider`] over the sealed KV so
//! openmls persists incrementally. We deliberately do **not**:
//!
//! - `StorageProvider` is ~45 **synchronous** methods.
//! - The sealed KV ([`ciris_persist::encrypted_kv::XChaChaKvStore`],
//!   surfaced here via [`ScopeStateProvider`]) is **async**.
//! - Bridging sync-over-async means `block_on` inside an async
//!   context, which is this repo's documented *"no reactor running"*
//!   panic class (CIRISEdge#217 — the same failure mode that held
//!   edge v1.1.9 off PyPI when persist's sqlite path did it).
//!
//! So instead: keep openmls's own in-memory storage — the
//! `MemoryStorage` inside [`openmls_libcrux_crypto::Provider`], which
//! is exactly what the A/V path already runs on — and **snapshot its
//! whole key/value map** into the blob slot the CIRISEdge#175 v6.0.0
//! scaffold already built
//! ([`ScopeStateProvider::group_state_put`]). Reload is the mirror
//! image: read the blob, restore the map into a fresh provider, and
//! let [`openmls::prelude::MlsGroup::load`] reconstruct the group
//! purely from storage reads.
//!
//! `MemoryStorage::serialize` exists upstream but is
//! `#[cfg(feature = "test-utils")]`, so it is unusable in a
//! production build. This module therefore carries its **own**
//! versioned, length-prefixed codec ([`SNAPSHOT_MAGIC`] /
//! [`SNAPSHOT_VERSION`]) — the version byte is what turns a future
//! format change into a loud [`CohortGroupError::SnapshotVersion`]
//! instead of a garbage load.
//!
//! # The ordering invariant that must not be gotten wrong
//!
//! **merge → snapshot+persist → THEN emit Commit/Welcome.**
//!
//! If we advertised an epoch before persisting it, a crash in that
//! window leaves peers at epoch N while our durable state is at
//! N-1 — and MLS has no way to re-derive N without the commit
//! secrets we just lost. The group is unloadable in the only sense
//! that matters: it can never commit again.
//!
//! This module enforces the ordering **structurally**, not by
//! convention: the Commit/Welcome bytes are returned inside a
//! [`CohortCommit`] whose fields are private and whose only
//! construction site is inside [`CohortGroupInner::persist_and_seal`]
//! — i.e. you cannot obtain emittable bytes without the durable write
//! having already succeeded. A persist failure returns `Err` and the
//! caller never sees the Commit.
//!
//! The persist step is itself crash-ordered: the epoch-N snapshot is
//! written **before** the head pointer moves to N, so a crash between
//! the two leaves the head at N-1 whose snapshot is still retained.
//!
//! # Single writer per `community_id`
//!
//! Two concurrent commits against the same group fork the epoch (both
//! committers believe they own N+1; one of them is wrong and its
//! peers will reject its subsequent messages). Every mutating method
//! here takes an async mutex, and [`CohortGroups`] hands out clones
//! of the *same* [`CohortGroup`] handle per `community_id` so two
//! independently-obtained handles share one lock rather than racing
//! two in-memory copies of the same group.
//!
//! # Relationship to `transport::realtime_av_mls`
//!
//! Same ciphersuite (`0x004D` X-Wing), same provider, same commit
//! patterns — but **different** exporter labels. This module exports
//! under CIRISVerify's scope-privacy labels
//! ([`crate::scope_privacy::DESTINATION_EXPORTER_LABEL`] and
//! [`crate::scope_privacy::RECORD_EXPORTER_LABEL`], v13.5.0); the A/V
//! module exports under `ciris-realtime-av-epoch-dek-seed-v1`. So a
//! cohort secret and an A/V DEK seed can never collide even if some
//! future deployment points both at one group. RFC 9420 makes exporter
//! derivations label-domain-separated; this module relies on that.
//!
//! Verify refused the DEK-seed label for scope-privacy inputs
//! explicitly and on the record: it protects payload confidentiality,
//! and deriving a routing identifier that appears in the clear on the
//! wire from that material would collapse two secrets §8.5 exists to
//! keep independent.
//!
//! Per the workstream file boundary this module does **not** import
//! from `crate::transport::*`. The few helpers it needs from there —
//! the ciphersuite constant, the `mint_*_key_package` shape, the
//! `export_secret` wrapper — are duplicated below (a handful of lines
//! each) rather than shared, so the transport module stays untouched.

use std::collections::HashMap;
use std::sync::{Arc, PoisonError};

use openmls::group::GroupId;
use openmls::prelude::{
    BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle,
    LeafNodeParameters, MlsGroup, MlsGroupCreateConfig, MlsMessageIn, MlsMessageOut,
    ProcessedMessageContent, ProtocolMessage,
};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider as LibcruxProvider;
use openmls_traits::types::SignatureScheme;
use openmls_traits::OpenMlsProvider;
use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};
use tokio::sync::Mutex;
use zeroize::Zeroize;

use super::scope_state::{ScopeStateProvider, ScopeStateProviderError};

/// The openmls storage type backing [`LibcruxProvider`]. Named
/// through the trait so this module does not need a direct
/// `openmls_memory_storage` dependency line in `Cargo.toml` (the
/// concrete type is `openmls_memory_storage::MemoryStorage`, whose
/// `values: RwLock<HashMap<Vec<u8>, Vec<u8>>>` field is public — that
/// public field is the whole reason the snapshot approach works).
type MemStorage = <LibcruxProvider as OpenMlsProvider>::StorageProvider;

/// The MLS ciphersuite cohort groups are pinned to: `0x004D` —
/// X-Wing (ML-KEM-768 + X25519) | ChaCha20-Poly1305 | SHA-256 |
/// Ed25519.
///
/// Same pin as `transport::realtime_av_mls::CIPHERSUITE_ID`,
/// duplicated rather than imported per the workstream file boundary.
/// If one moves the other must move with it — a cohort group and an
/// A/V group in the same deployment negotiating different suites
/// would be a silent interop break.
pub const CIPHERSUITE_ID: u16 = 0x004D;

/// The openmls enum value [`CIPHERSUITE_ID`] maps to.
const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

// The exporter labels for cohort secrets are NOT defined here. They are
// CIRISVerify's (`RECORD_EXPORTER_LABEL` / `DESTINATION_EXPORTER_LABEL`,
// v13.5.0), re-exported through `crate::scope_privacy` and used
// verbatim — a label is a cross-impl wire fact, and an edge-local one
// would put two owners on it. This module previously defined its own
// `COHORT_SECRET_LABEL`; it was retired when verify settled the family.

/// Length of a [`CohortSecret`], in bytes.
pub const COHORT_SECRET_LEN: usize = 32;

/// Magic prefix on every snapshot blob. Lets a wrong-slot read fail
/// loudly instead of being parsed as a truncated map.
pub const SNAPSHOT_MAGIC: &[u8; 8] = b"CIRISMLS";

/// Snapshot format version. Bump on any wire-breaking change to
/// [`encode_snapshot`]; [`decode_snapshot`] refuses anything it does
/// not recognise (CIRISEdge#499 — a garbage load of MLS state is
/// worse than a loud refusal, because a partially-decoded group can
/// still *appear* to work until the first commit).
pub const SNAPSHOT_VERSION: u8 = 0x01;

/// Reserved epoch slot holding the *head pointer* — the epoch number
/// whose snapshot is current.
///
/// [`ScopeStateProvider`] exposes get/put/delete keyed by
/// `(community_id, epoch)` with no list or scan, so "which epoch is
/// current?" needs a well-known slot. `u64::MAX` is that slot: a real
/// MLS group would need 2^64 commits to collide with it, and
/// [`CohortGroupInner::persist_and_seal`] refuses the collision
/// explicitly rather than trusting the arithmetic.
const HEAD_SLOT: u64 = u64::MAX;

/// Version byte on the head-pointer value (independent of
/// [`SNAPSHOT_VERSION`]: the pointer encoding can change without the
/// snapshot encoding changing, and vice versa).
const HEAD_VERSION: u8 = 0x01;

/// Default number of epochs retained in the KV.
///
/// Each commit rewrites the *whole* snapshot blob under a new epoch
/// key, so without a bound the sealed KV grows without limit — one
/// full copy of group state per commit, forever. A small window is
/// kept rather than exactly one because the crash-ordered persist
/// (snapshot-then-head) needs the previous epoch to still be there if
/// a crash lands between the two writes, and because §3.5
/// `rotate-forward` semantics want a short tail, not an instant
/// horizon.
pub const DEFAULT_RETAINED_EPOCHS: u64 = 4;

/// Hard ceiling on a decoded snapshot's entry count. Purely a
/// decode-side DoS guard: the blob comes out of our own sealed KV, so
/// a hostile value implies the KV was already compromised, but a
/// length-prefixed codec should never trust a length field to size an
/// allocation (cf. the CIRISEdge#473 reassembler byte-budget finding).
const MAX_SNAPSHOT_ENTRIES: u32 = 1 << 20;

/// Hard ceiling on any single snapshot key or value, in bytes. Same
/// rationale as [`MAX_SNAPSHOT_ENTRIES`].
const MAX_SNAPSHOT_FIELD: u32 = 1 << 26; // 64 MiB

// ─── Errors ─────────────────────────────────────────────────────────

/// Errors from the persistent cohort-group surface.
#[derive(Debug, thiserror::Error)]
pub enum CohortGroupError {
    /// Sealed-KV read/write fault, or a codec fault inside
    /// [`ScopeStateProvider`].
    #[error("cohort group state store: {0}")]
    Store(#[from] ScopeStateProviderError),
    /// The snapshot blob did not begin with [`SNAPSHOT_MAGIC`].
    #[error("cohort group snapshot: bad magic (slot does not hold an MLS snapshot)")]
    SnapshotMagic,
    /// The snapshot blob carried a version byte this build does not
    /// understand. Loud by design — see [`SNAPSHOT_VERSION`].
    #[error("cohort group snapshot: unsupported format version {0:#04x} (this build reads {SNAPSHOT_VERSION:#04x})")]
    SnapshotVersion(u8),
    /// The snapshot blob was truncated, over-long, or declared a
    /// length that exceeds the decode budget.
    #[error("cohort group snapshot: malformed ({0})")]
    SnapshotMalformed(String),
    /// The head pointer slot held something unreadable.
    #[error("cohort group head pointer: malformed ({0})")]
    HeadMalformed(String),
    /// The head pointer named an epoch whose snapshot is missing —
    /// either the retention window pruned too aggressively or the KV
    /// lost a write. Fail-closed: we do NOT silently fall back to an
    /// older epoch, because a silently-rewound group re-uses epoch
    /// numbers its peers have already seen.
    #[error("cohort group: head points at epoch {0} but no snapshot is stored for it")]
    HeadDangling(u64),
    /// [`MlsGroup::load`] returned `None` — the restored storage map
    /// did not contain a group under the expected group id.
    #[error("cohort group: snapshot restored but no MLS group found for community {0:?}")]
    GroupMissing(String),
    /// The group's own signature key pair was not recoverable from
    /// the restored storage. Without it the group can never commit
    /// again, so this is fatal rather than degraded.
    #[error("cohort group: signature key pair not recoverable from snapshot for community {0:?}")]
    SignerMissing(String),
    /// The 0x004D ciphersuite is unavailable in this openmls build.
    /// Should be impossible at 0.8.1 (X-Wing ships unconditionally);
    /// the gate exists so a future re-pin behind a feature flag has a
    /// clean failure mode.
    #[error("MLS ciphersuite 0x004D (X-Wing) is not available in this openmls build")]
    CiphersuiteNotAvailable,
    /// A `KeyPackage` offered to [`CohortGroup::add_member`] was
    /// minted under a different ciphersuite. Refused before the
    /// roster is touched.
    #[error("key package for {key_id:?} uses ciphersuite {got:#06x}, cohort groups require {CIPHERSUITE_ID:#06x}")]
    CiphersuiteMismatch {
        /// The CIRIS `key_id` the key package was offered for.
        key_id: String,
        /// The ciphersuite the offered key package actually carries.
        got: u16,
    },
    /// Group creation failed inside openmls.
    #[error("MLS cohort group creation failed: {0}")]
    CreateFailed(String),
    /// An Add commit failed.
    #[error("MLS cohort Add commit failed: {0}")]
    AddFailed(String),
    /// A Remove commit failed.
    #[error("MLS cohort Remove commit failed: {0}")]
    RemoveFailed(String),
    /// A self-update (rotate) commit failed.
    #[error("MLS cohort rotate failed: {0}")]
    RotateFailed(String),
    /// `process_message` / `merge_staged_commit` failed on a remote
    /// commit.
    #[error("MLS cohort remote commit apply failed: {0}")]
    ApplyFailed(String),
    /// Wire bytes did not decode as an MLS message.
    #[error("MLS wire decode failed: {0}")]
    WireDecodeFailed(String),
    /// The bytes handed to [`CohortGroup::apply_remote_commit`]
    /// decoded as MLS but were not a Commit.
    #[error("expected a Commit message, got a different MLS content type")]
    NotACommit,
    /// A member lookup by `key_id` found nothing.
    #[error("member not found in cohort group: {0}")]
    MemberNotFound(String),
    /// KeyPackage minting failed.
    #[error("MLS KeyPackage build failed: {0}")]
    KeyPackageBuildFailed(String),
    /// Exporter-secret derivation failed — would indicate corrupted
    /// group state.
    #[error("MLS exporter_secret derivation failed: {0}")]
    ExportFailed(String),
    /// The group reached the reserved [`HEAD_SLOT`] epoch. Refused
    /// rather than silently overwriting the head pointer with a
    /// snapshot.
    #[error(
        "cohort group reached the reserved head-pointer epoch {HEAD_SLOT}; refusing to persist"
    )]
    EpochExhausted,
    /// The bytes handed to [`CohortGroup::join`] decoded as MLS but
    /// were not a Welcome.
    #[error("expected a Welcome message, got a different MLS content type")]
    NotAWelcome,
    /// [`StagedWelcome::new_from_welcome`] refused the Welcome — most
    /// often because none of this node's `KeyPackage`s match it (the
    /// Welcome was minted for someone else, or for a KeyPackage this
    /// node has already consumed).
    ///
    /// [`StagedWelcome::new_from_welcome`]: openmls::prelude::StagedWelcome::new_from_welcome
    #[error("MLS cohort Welcome could not be staged: {0}")]
    WelcomeRejected(String),
    /// The Welcome is cryptographically valid but admits this node to
    /// a group whose id is not the one [`cohort_group_id`] derives for
    /// the community being joined.
    ///
    /// Refused BEFORE the group is constructed or persisted. Accepting
    /// it would file another community's group under this
    /// `community_id`'s namespace — and since the exporter context is
    /// the `community_id`, every secret derived afterwards would be
    /// derived under a community this group is not actually for.
    #[error(
        "cohort Welcome is for MLS group {got:?}, not the group id derived for community \
         {community_id:?} ({expected:?})"
    )]
    WelcomeForDifferentGroup {
        /// The community this join was attempted for.
        community_id: String,
        /// The group id `cohort_group_id(community_id)` derives.
        expected: Vec<u8>,
        /// The group id the Welcome actually admits to.
        got: Vec<u8>,
    },
    /// [`CohortGroup::join`] was called for a community this node
    /// already holds persisted group state for.
    ///
    /// Refused rather than overwritten: a join writes a genesis head
    /// pointer, so proceeding would displace an existing group's head
    /// and strand every snapshot it names. A node that really is being
    /// re-admitted after removal must drop the old state explicitly.
    #[error(
        "cohort group state already exists for community {0:?} at epoch {1}; \
         refusing to displace it with a join"
    )]
    AlreadyJoined(String, u64),
}

// ─── The cohort epoch secret ────────────────────────────────────────

/// The current epoch's MLS exporter secret for a cohort, derived
/// under one of CIRISVerify's scope-privacy exporter labels — see
/// [`CohortGroup::destination_secret`] and
/// [`CohortGroup::record_secret`].
///
/// This is the `exporter_secret` the `community` / `affiliations`
/// scopes were missing: 32 bytes bound to *this* group at *this*
/// epoch, from which `scope_privacy`'s `k_record_id` / `k_symbol`
/// subkeys are derived (CEWP `SCOPE_PRIVACY.md` §2.2).
///
/// Zeroized on drop; `Debug` redacts. Same shape as the A/V path's
/// `RootSecret` so downstream key-derivation code is mechanical.
pub struct CohortSecret([u8; COHORT_SECRET_LEN]);

impl CohortSecret {
    /// Borrow the raw bytes — for key derivation only. Callers MUST
    /// NOT log, persist, or transmit these bytes.
    pub fn as_bytes(&self) -> &[u8; COHORT_SECRET_LEN] {
        &self.0
    }
}

impl Drop for CohortSecret {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl std::fmt::Debug for CohortSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortSecret")
            .field("bytes", &"<redacted 32B>")
            .finish()
    }
}

// ─── Commit artifacts ───────────────────────────────────────────────

/// Wire artifacts produced by a cohort roster mutation, **after** the
/// resulting epoch is durable.
///
/// # Why the fields are private
///
/// This type is the structural enforcement of the module's ordering
/// invariant (see module docs). Its only construction site is inside
/// [`CohortGroupInner::persist_and_seal`], which runs *after* the
/// snapshot write and head-pointer update have both succeeded.
/// Because the Commit/Welcome bytes are only reachable through
/// [`Self::commit`] / [`Self::welcome`] on a value you cannot build
/// yourself, "emit before persist" is not expressible by a caller of
/// this module.
#[derive(Clone)]
#[must_use = "a CohortCommit carries the Commit/Welcome that MUST be fanned out to the cohort"]
pub struct CohortCommit {
    epoch: u64,
    commit: Vec<u8>,
    welcome: Option<Vec<u8>>,
}

impl CohortCommit {
    /// The epoch this commit advanced the group to. Already durable
    /// by the time you hold this value.
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// The serialized MLS Commit, to fan out to existing members.
    pub fn commit(&self) -> &[u8] {
        &self.commit
    }

    /// The serialized MLS Welcome, to ship to joiners. `None` when
    /// the commit contained no Add proposals (Remove-only, or a
    /// rotate).
    pub fn welcome(&self) -> Option<&[u8]> {
        self.welcome.as_deref()
    }

    /// Consume into `(epoch, commit_bytes, welcome_bytes)`.
    pub fn into_parts(self) -> (u64, Vec<u8>, Option<Vec<u8>>) {
        (self.epoch, self.commit, self.welcome)
    }
}

impl std::fmt::Debug for CohortCommit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortCommit")
            .field("epoch", &self.epoch)
            .field("commit_len", &self.commit.len())
            .field("welcome_len", &self.welcome.as_ref().map(Vec::len))
            .finish()
    }
}

// ─── Snapshot codec ─────────────────────────────────────────────────
//
// Layout (all integers big-endian):
//
//   magic[8] = "CIRISMLS"
//   version  = u8
//   count    = u32
//   count × { k_len: u32, v_len: u32, key[k_len], value[v_len] }
//
// Entries are emitted in sorted key order so the blob is a
// deterministic function of the map — which makes "did this commit
// actually change storage?" answerable by byte comparison, and keeps
// the sealed-KV write stable under HashMap iteration order.

/// Encode an openmls storage map into a versioned snapshot blob.
fn encode_snapshot(values: &HashMap<Vec<u8>, Vec<u8>>) -> Result<Vec<u8>, CohortGroupError> {
    let count = u32::try_from(values.len()).map_err(|_| {
        CohortGroupError::SnapshotMalformed(format!("entry count {} exceeds u32", values.len()))
    })?;

    let mut entries: Vec<(&Vec<u8>, &Vec<u8>)> = values.iter().collect();
    entries.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let body: usize = entries.iter().map(|(k, v)| 8 + k.len() + v.len()).sum();
    let mut out = Vec::with_capacity(8 + 1 + 4 + body);
    out.extend_from_slice(SNAPSHOT_MAGIC);
    out.push(SNAPSHOT_VERSION);
    out.extend_from_slice(&count.to_be_bytes());

    for (k, v) in entries {
        let k_len = u32::try_from(k.len()).map_err(|_| {
            CohortGroupError::SnapshotMalformed(format!("key length {} exceeds u32", k.len()))
        })?;
        let v_len = u32::try_from(v.len()).map_err(|_| {
            CohortGroupError::SnapshotMalformed(format!("value length {} exceeds u32", v.len()))
        })?;
        out.extend_from_slice(&k_len.to_be_bytes());
        out.extend_from_slice(&v_len.to_be_bytes());
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    Ok(out)
}

/// Read a big-endian `u32` from `buf` at `*pos`, advancing `*pos`.
fn take_u32(buf: &[u8], pos: &mut usize, what: &str) -> Result<u32, CohortGroupError> {
    let end = pos
        .checked_add(4)
        .ok_or_else(|| CohortGroupError::SnapshotMalformed("offset overflow".to_string()))?;
    if end > buf.len() {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "truncated reading {what}: need 4 bytes at {pos}, have {}",
            buf.len()
        )));
    }
    let mut raw = [0u8; 4];
    raw.copy_from_slice(&buf[*pos..end]);
    *pos = end;
    Ok(u32::from_be_bytes(raw))
}

/// Read `len` bytes from `buf` at `*pos`, advancing `*pos`.
fn take_bytes(
    buf: &[u8],
    pos: &mut usize,
    len: u32,
    what: &str,
) -> Result<Vec<u8>, CohortGroupError> {
    if len > MAX_SNAPSHOT_FIELD {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "{what} length {len} exceeds the {MAX_SNAPSHOT_FIELD}-byte decode budget"
        )));
    }
    let len = len as usize;
    let end = pos
        .checked_add(len)
        .ok_or_else(|| CohortGroupError::SnapshotMalformed("offset overflow".to_string()))?;
    if end > buf.len() {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "truncated reading {what}: need {len} bytes at {pos}, have {}",
            buf.len()
        )));
    }
    let out = buf[*pos..end].to_vec();
    *pos = end;
    Ok(out)
}

/// Decode a snapshot blob back into an openmls storage map.
fn decode_snapshot(blob: &[u8]) -> Result<HashMap<Vec<u8>, Vec<u8>>, CohortGroupError> {
    if blob.len() < 8 + 1 + 4 {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "blob is {} bytes, shorter than the 13-byte header",
            blob.len()
        )));
    }
    if &blob[..8] != SNAPSHOT_MAGIC {
        return Err(CohortGroupError::SnapshotMagic);
    }
    let version = blob[8];
    if version != SNAPSHOT_VERSION {
        return Err(CohortGroupError::SnapshotVersion(version));
    }

    let mut pos = 9usize;
    let count = take_u32(blob, &mut pos, "entry count")?;
    if count > MAX_SNAPSHOT_ENTRIES {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "entry count {count} exceeds the {MAX_SNAPSHOT_ENTRIES} decode budget"
        )));
    }

    let mut map = HashMap::with_capacity(count as usize);
    for i in 0..count {
        let k_len = take_u32(blob, &mut pos, "key length")?;
        let v_len = take_u32(blob, &mut pos, "value length")?;
        let key = take_bytes(blob, &mut pos, k_len, "key")?;
        let value = take_bytes(blob, &mut pos, v_len, "value")?;
        if map.insert(key, value).is_some() {
            return Err(CohortGroupError::SnapshotMalformed(format!(
                "duplicate key at entry {i}"
            )));
        }
    }
    if pos != blob.len() {
        return Err(CohortGroupError::SnapshotMalformed(format!(
            "{} trailing bytes after {count} entries",
            blob.len() - pos
        )));
    }
    Ok(map)
}

/// Encode the head pointer: `[version, epoch_be]`.
fn encode_head(epoch: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    out.push(HEAD_VERSION);
    out.extend_from_slice(&epoch.to_be_bytes());
    out
}

/// Decode the head pointer.
fn decode_head(blob: &[u8]) -> Result<u64, CohortGroupError> {
    if blob.len() != 9 {
        return Err(CohortGroupError::HeadMalformed(format!(
            "expected 9 bytes, got {}",
            blob.len()
        )));
    }
    if blob[0] != HEAD_VERSION {
        return Err(CohortGroupError::HeadMalformed(format!(
            "unsupported head version {:#04x}",
            blob[0]
        )));
    }
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&blob[1..9]);
    Ok(u64::from_be_bytes(raw))
}

// ─── Group id derivation ────────────────────────────────────────────

/// Domain-separated MLS group id for a cohort.
///
/// Deterministic from `community_id` so [`MlsGroup::load`] can find
/// the group in a restored storage map without a second lookup table,
/// and prefixed so a cohort group id can never be confused with a
/// randomly-generated per-stream A/V group id.
fn cohort_group_id(community_id: &str) -> GroupId {
    let mut raw = Vec::with_capacity(13 + community_id.len());
    raw.extend_from_slice(b"ciris-cohort:");
    raw.extend_from_slice(community_id.as_bytes());
    GroupId::from_slice(&raw)
}

// ─── Key material minting ───────────────────────────────────────────

/// A prospective cohort member's retained private MLS material.
///
/// Mirrors `transport::realtime_av_mls::JoinerKeyMaterial` (duplicated
/// per the workstream file boundary, not imported). The public
/// [`KeyPackage`] returned alongside by
/// [`mint_cohort_key_material`] is what a member publishes; this is
/// what the member keeps so it can consume the matching Welcome.
pub struct CohortKeyMaterial {
    /// The member's own provider, holding the private leaf material.
    pub provider: Arc<LibcruxProvider>,
    /// The member's MLS signature key pair.
    pub signer: SignatureKeyPair,
    /// The CIRIS `key_id` stamped into the credential.
    pub key_id: String,
}

impl std::fmt::Debug for CohortKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortKeyMaterial")
            .field("key_id", &self.key_id)
            .field("provider", &"<opaque-libcrux>")
            .field("signer", &"<redacted>")
            .finish()
    }
}

/// Mint a cohort member's KeyPackage plus the private material that
/// member retains, under the pinned [`CIPHERSUITE`].
///
/// The private leaf keys live in the returned
/// [`CohortKeyMaterial::provider`]; only the public [`KeyPackage`] is
/// meant to leave the member's node.
pub fn mint_cohort_key_material(
    key_id: &str,
) -> Result<(CohortKeyMaterial, KeyPackage), CohortGroupError> {
    let provider = Arc::new(LibcruxProvider::default());
    let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
        .map_err(|e| CohortGroupError::KeyPackageBuildFailed(format!("signature key: {e:?}")))?;
    signer.store(provider.storage()).map_err(|e| {
        CohortGroupError::KeyPackageBuildFailed(format!("store signature key: {e:?}"))
    })?;
    let cred_with_key = CredentialWithKey {
        credential: BasicCredential::new(key_id.as_bytes().to_vec()).into(),
        signature_key: signer.to_public_vec().into(),
    };
    let bundle: KeyPackageBundle = KeyPackage::builder()
        .build(CIPHERSUITE, provider.as_ref(), &signer, cred_with_key)
        .map_err(|e| CohortGroupError::KeyPackageBuildFailed(format!("{e:?}")))?;
    let key_package = bundle.key_package().clone();
    Ok((
        CohortKeyMaterial {
            provider,
            signer,
            key_id: key_id.to_string(),
        },
        key_package,
    ))
}

// ─── The group itself ───────────────────────────────────────────────

/// Guarded per-cohort MLS state. All mutation runs under
/// [`CohortGroup`]'s async mutex — see module docs § "Single writer".
struct CohortGroupInner {
    community_id: String,
    provider: Arc<LibcruxProvider>,
    signer: SignatureKeyPair,
    group: MlsGroup,
    store: ScopeStateProvider,
    retained_epochs: u64,
}

impl CohortGroupInner {
    /// Current epoch as a plain `u64`.
    fn epoch(&self) -> u64 {
        self.group.epoch().as_u64()
    }

    /// Snapshot the provider's storage map into a blob.
    fn snapshot(&self) -> Result<Vec<u8>, CohortGroupError> {
        let guard = self
            .provider
            .storage()
            .values
            .read()
            // A poisoned lock here means some other thread panicked
            // mid-write to openmls storage. The map is still a valid
            // `HashMap` (openmls writes whole entries), so we recover
            // the inner value rather than propagating a panic into an
            // async task — a panic here would abort the commit AFTER
            // the merge, which is exactly the unpersisted-epoch state
            // this module exists to prevent.
            .unwrap_or_else(PoisonError::into_inner);
        encode_snapshot(&guard)
    }

    /// Persist the current (already-merged) epoch and only then seal
    /// the wire artifacts into a [`CohortCommit`].
    ///
    /// **This is the ordering invariant** (CIRISEdge#499). Order of
    /// operations, and why:
    ///
    /// 1. snapshot the merged state → write it under epoch N.
    /// 2. move the head pointer to N. A crash between (1) and (2)
    ///    leaves the head at N-1, whose snapshot is still retained;
    ///    the group reloads at N-1 and can re-commit. A crash before
    ///    (1) is likewise safe.
    /// 3. prune outside the retention window (best-effort — see
    ///    below).
    /// 4. *Only now* construct the [`CohortCommit`] the caller will
    ///    fan out.
    ///
    /// Pruning failures are logged, not propagated: the epoch is
    /// already durable at that point, and failing the commit would
    /// leave the caller thinking the epoch did not happen when it
    /// did — the exact desync this ordering exists to prevent.
    fn persist_and_seal(
        &self,
        commit: Vec<u8>,
        welcome: Option<Vec<u8>>,
    ) -> impl std::future::Future<Output = Result<CohortCommit, CohortGroupError>> + '_ {
        let blob = self.snapshot();
        async move {
            let epoch = self.epoch();
            if epoch == HEAD_SLOT {
                return Err(CohortGroupError::EpochExhausted);
            }
            let blob = blob?;

            // (1) snapshot first.
            self.store
                .group_state_put(&self.community_id, epoch, &blob)
                .await?;
            // (2) then the head pointer.
            self.store
                .group_state_put(&self.community_id, HEAD_SLOT, &encode_head(epoch))
                .await?;
            // (3) then prune, best-effort.
            self.prune(epoch).await;

            // (4) and only now are emittable bytes constructible.
            Ok(CohortCommit {
                epoch,
                commit,
                welcome,
            })
        }
    }

    /// Drop the snapshot that just fell out of the retention window.
    ///
    /// Epochs advance by exactly one per commit, so deleting the
    /// single epoch `current - retained` on every commit keeps the
    /// window bounded. A group that was reloaded from disk resumes
    /// the same one-per-commit cadence, so no sweep loop is needed.
    async fn prune(&self, current: u64) {
        let Some(victim) = current.checked_sub(self.retained_epochs) else {
            return;
        };
        if let Err(e) = self
            .store
            .group_state_delete(&self.community_id, victim)
            .await
        {
            tracing::warn!(
                community_id = %self.community_id,
                epoch = victim,
                error = %e,
                "cohort MLS snapshot prune failed; retained epochs will exceed the window \
                 (CIRISEdge#499). The current epoch IS durable — this is a storage-growth \
                 concern, not a correctness one."
            );
        }
    }

    /// Derive this epoch's cohort secret under one of CIRISVerify's
    /// scope-privacy exporter labels (CIRISVerify#259, v13.5.0).
    ///
    /// `label` is [`crate::scope_privacy::RECORD_EXPORTER_LABEL`] or
    /// [`crate::scope_privacy::DESTINATION_EXPORTER_LABEL`] — never an
    /// edge-local string. Both the label and the context are
    /// cross-impl wire facts: two members of one cohort derive the
    /// same bytes only if they export under the same `(label,
    /// context, length)`, so verify owns all three and edge reproduces
    /// them.
    fn scope_secret(&self, label: &str) -> Result<CohortSecret, CohortGroupError> {
        let bytes = self
            .group
            .export_secret(
                self.provider.crypto(),
                label,
                // EXPORTER_CONTEXT is EMPTY, per verify: the exporter
                // already binds (group_id, epoch) via RFC 9420 §8.5, so
                // a context adds nothing and is "one less thing to
                // diverge on". This deliberately replaces edge's
                // earlier `community_id`-as-context: that was
                // belt-and-braces against a snapshot restored under the
                // wrong namespace, but a non-empty context edge chose
                // for itself would make edge derive different bytes
                // from every other implementation — trading a local
                // safety margin for a silent cross-impl split. The
                // namespace check now lives where it can be enforced
                // without touching the wire: `join` refuses a Welcome
                // whose group id is not the one derived for the
                // community (CIRISEdge#500).
                crate::scope_privacy::EXPORTER_CONTEXT,
                COHORT_SECRET_LEN,
            )
            .map_err(|e| CohortGroupError::ExportFailed(format!("{e:?}")))?;
        let raw: [u8; COHORT_SECRET_LEN] = bytes.try_into().map_err(|v: Vec<u8>| {
            CohortGroupError::ExportFailed(format!(
                "expected {COHORT_SECRET_LEN} bytes, got {}",
                v.len()
            ))
        })?;
        Ok(CohortSecret(raw))
    }

    /// Resolve a CIRIS `key_id` to its MLS leaf index.
    fn leaf_of(&self, key_id: &str) -> Result<openmls::prelude::LeafNodeIndex, CohortGroupError> {
        self.group
            .members()
            .find(|m| m.credential.serialized_content() == key_id.as_bytes())
            .map(|m| m.index)
            .ok_or_else(|| CohortGroupError::MemberNotFound(key_id.to_string()))
    }
}

/// A persistent, per-cohort MLS group (CIRISEdge#499).
///
/// Cheap to clone; **clones share one async mutex**, which is what
/// makes the single-writer invariant hold. Obtain handles through
/// [`CohortGroups::open`] so two callers naming the same
/// `community_id` get clones of the same handle rather than two
/// independent groups.
#[derive(Clone)]
pub struct CohortGroup {
    community_id: Arc<str>,
    inner: Arc<Mutex<CohortGroupInner>>,
}

impl std::fmt::Debug for CohortGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CohortGroup")
            .field("community_id", &self.community_id)
            .field("ciphersuite_id", &format_args!("0x{CIPHERSUITE_ID:04X}"))
            // How many handles share this group's writer lock. >1 is
            // normal and is the single-writer invariant working.
            .field("handles", &Arc::strong_count(&self.inner))
            .field("state", &"<locked>")
            .finish_non_exhaustive()
    }
}

impl CohortGroup {
    /// The ciphersuite cohort groups are pinned to.
    pub const fn ciphersuite_id() -> u16 {
        CIPHERSUITE_ID
    }

    /// The community this group serves.
    pub fn community_id(&self) -> &str {
        &self.community_id
    }

    /// Create a brand-new cohort group with this node as the sole
    /// initial member, and persist its epoch-0 state.
    ///
    /// The group's own [`SignatureKeyPair`] is minted **and stored in
    /// the provider** before the group is built — that `store()` call
    /// is what puts the private signing key into the storage map, and
    /// therefore into the snapshot. Skip it and the group reloads
    /// after a restart but can never commit again (CIRISEdge#499:
    /// this is the restart round-trip the tests pin).
    ///
    /// `own_key_id` is the CIRIS federation `key_id` stamped into the
    /// MLS `BasicCredential` identity, exactly as the A/V path does.
    pub async fn create(
        store: ScopeStateProvider,
        community_id: &str,
        own_key_id: &str,
        retained_epochs: u64,
    ) -> Result<Self, CohortGroupError> {
        // Ciphersuite availability gate, before anything is minted.
        if CIPHERSUITE_ID != 0x004D {
            return Err(CohortGroupError::CiphersuiteNotAvailable);
        }

        let provider = Arc::new(LibcruxProvider::default());
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519)
            .map_err(|e| CohortGroupError::CreateFailed(format!("own signature key: {e:?}")))?;
        signer
            .store(provider.storage())
            .map_err(|e| CohortGroupError::CreateFailed(format!("store signature key: {e:?}")))?;

        let cred_with_key = CredentialWithKey {
            credential: BasicCredential::new(own_key_id.as_bytes().to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };

        let create_config = MlsGroupCreateConfig::builder()
            .ciphersuite(CIPHERSUITE)
            // The ratchet-tree extension is what lets a joiner
            // reconstruct the tree from the Welcome alone; without it
            // a restored group would need an out-of-band tree copy.
            .use_ratchet_tree_extension(true)
            .build();

        let group = MlsGroup::new_with_group_id(
            provider.as_ref(),
            &signer,
            &create_config,
            cohort_group_id(community_id),
            cred_with_key,
        )
        .map_err(|e| CohortGroupError::CreateFailed(format!("MlsGroup::new: {e:?}")))?;

        let inner = CohortGroupInner {
            community_id: community_id.to_string(),
            provider,
            signer,
            group,
            store,
            retained_epochs: retained_epochs.max(1),
        };

        // Persist the genesis epoch before handing out a handle: a
        // group that exists only in RAM is the same failure the
        // ordering invariant guards against, just at epoch 0.
        let epoch = inner.epoch();
        let blob = inner.snapshot()?;
        inner
            .store
            .group_state_put(&inner.community_id, epoch, &blob)
            .await?;
        inner
            .store
            .group_state_put(&inner.community_id, HEAD_SLOT, &encode_head(epoch))
            .await?;

        Ok(Self {
            community_id: Arc::from(community_id),
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Join an existing cohort from a `Welcome` (CIRISEdge#500).
    ///
    /// The counterpart to [`Self::create`]. Until this existed the
    /// cohort bootstrap was one-directional: a founder could `create`
    /// a group and [`Self::add_member`] you — producing a Welcome —
    /// and you had no supported way to turn that Welcome into a
    /// [`CohortGroup`]. A node that cannot join a cohort cannot derive
    /// its scoped address in it (CIRISEdge#499), and that failure is
    /// silent, because an RNS destination hash nobody registered is
    /// simply never delivered to.
    ///
    /// `own_key_id` is NOT a parameter: it is
    /// [`CohortKeyMaterial::key_id`], the id already stamped into the
    /// credential whose private half decrypts this Welcome. Taking it
    /// separately would let the two disagree.
    ///
    /// # What is checked, and in what order
    ///
    /// 1. The ciphersuite gate, before anything is decrypted.
    /// 2. The bytes decode as MLS and carry a Welcome body.
    /// 3. **No group state already exists for `community_id`** — a
    ///    join writes a genesis head pointer, so proceeding would
    ///    displace an existing group's head and strand every snapshot
    ///    it names.
    /// 4. The Welcome stages against this node's key material.
    /// 5. **The group id is the one [`cohort_group_id`] derives for
    ///    `community_id`** — checked on the [`StagedWelcome`]'s group
    ///    context, so a mismatched Welcome never becomes a group at
    ///    all. Accepting one would file another community's group
    ///    under this namespace, and since the exporter context is the
    ///    `community_id`, every secret derived afterwards would be
    ///    derived under a community the group is not for.
    /// 6. Only then is the group constructed and persisted.
    ///
    /// # What is NOT checked
    ///
    /// **Welcome authenticity is not membership authorization.**
    /// openmls proves the Welcome is well-formed and that this node's
    /// key package matches it. It does not prove the sender was
    /// entitled to add this node to this community — that is a
    /// federation-tier question about the sender's standing, and the
    /// answer is not in the Welcome. Callers that need it must gate
    /// before calling; this function deliberately does not invent a
    /// rule for it.
    ///
    /// # Durable before usable
    ///
    /// The returned handle already has its snapshot and head pointer
    /// written, the same discipline that makes a [`CohortCommit`]
    /// durable before it is emittable. A crash immediately after
    /// joining reloads into the group rather than losing membership
    /// that peers have already committed to.
    ///
    /// # Errors
    /// See [`CohortGroupError::NotAWelcome`],
    /// [`CohortGroupError::WelcomeRejected`],
    /// [`CohortGroupError::WelcomeForDifferentGroup`],
    /// [`CohortGroupError::AlreadyJoined`].
    pub async fn join(
        store: ScopeStateProvider,
        community_id: &str,
        key_material: CohortKeyMaterial,
        welcome: &[u8],
        retained_epochs: u64,
    ) -> Result<Self, CohortGroupError> {
        use openmls::prelude::{MlsGroupJoinConfig, MlsMessageBodyIn, StagedWelcome};

        if CIPHERSUITE_ID != 0x004D {
            return Err(CohortGroupError::CiphersuiteNotAvailable);
        }

        let msg_in = MlsMessageIn::tls_deserialize(&mut &welcome[..])
            .map_err(|e| CohortGroupError::WireDecodeFailed(format!("{e:?}")))?;
        let MlsMessageBodyIn::Welcome(welcome_body) = msg_in.extract() else {
            return Err(CohortGroupError::NotAWelcome);
        };

        // Before consuming the key material: refuse if this node already
        // holds state for the community. `new_from_welcome` consumes the
        // matching KeyPackage's private half even when it fails, so the
        // cheap fail-closed check goes first.
        if let Some(head_raw) = store.group_state_get(community_id, HEAD_SLOT).await? {
            let epoch = decode_head(&head_raw)?;
            return Err(CohortGroupError::AlreadyJoined(
                community_id.to_string(),
                epoch,
            ));
        }

        let join_config = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let staged = StagedWelcome::new_from_welcome(
            key_material.provider.as_ref(),
            &join_config,
            welcome_body,
            None,
        )
        .map_err(|e| CohortGroupError::WelcomeRejected(format!("{e:?}")))?;

        // Check the group id on the STAGED welcome, so a Welcome for a
        // different community never becomes an MlsGroup at all.
        let expected = cohort_group_id(community_id);
        let got = staged.group_context().group_id();
        if got != &expected {
            return Err(CohortGroupError::WelcomeForDifferentGroup {
                community_id: community_id.to_string(),
                expected: expected.as_slice().to_vec(),
                got: got.as_slice().to_vec(),
            });
        }

        let group = staged
            .into_group(key_material.provider.as_ref())
            .map_err(|e| CohortGroupError::WelcomeRejected(format!("into_group: {e:?}")))?;

        let inner = CohortGroupInner {
            community_id: community_id.to_string(),
            provider: key_material.provider,
            signer: key_material.signer,
            group,
            store,
            retained_epochs: retained_epochs.max(1),
        };

        // Persist the joined epoch before handing out a handle — same
        // ordering as `create`, and for the same reason: a group that
        // exists only in RAM is membership the node loses on restart
        // while its peers still count it in the roster.
        let epoch = inner.epoch();
        if epoch == HEAD_SLOT {
            return Err(CohortGroupError::EpochExhausted);
        }
        let blob = inner.snapshot()?;
        inner
            .store
            .group_state_put(&inner.community_id, epoch, &blob)
            .await?;
        inner
            .store
            .group_state_put(&inner.community_id, HEAD_SLOT, &encode_head(epoch))
            .await?;

        Ok(Self {
            community_id: Arc::from(community_id),
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Reload a cohort group from the sealed KV, or `Ok(None)` if
    /// this node has never created/joined one for `community_id`.
    ///
    /// Reconstruction is: head pointer → snapshot blob → storage map
    /// → [`MlsGroup::load`] → [`SignatureKeyPair::read`] keyed by the
    /// group's own leaf signature key. Every step is a pure storage
    /// read; nothing is re-derived, so the reloaded group is
    /// byte-identical to the one that was snapshotted.
    ///
    /// Fail-closed throughout: a dangling head, a missing group, or
    /// an unrecoverable signer are all errors, never a silent
    /// downgrade to an older epoch or a fresh group (a silently
    /// rewound group re-uses epoch numbers its peers already
    /// consumed).
    pub async fn load(
        store: ScopeStateProvider,
        community_id: &str,
        retained_epochs: u64,
    ) -> Result<Option<Self>, CohortGroupError> {
        let Some(head_raw) = store.group_state_get(community_id, HEAD_SLOT).await? else {
            return Ok(None);
        };
        let epoch = decode_head(&head_raw)?;
        let Some(blob) = store.group_state_get(community_id, epoch).await? else {
            return Err(CohortGroupError::HeadDangling(epoch));
        };
        let map = decode_snapshot(&blob)?;

        let provider = Arc::new(LibcruxProvider::default());
        restore_storage(provider.storage(), map);

        let group_id = cohort_group_id(community_id);
        let group = MlsGroup::load(provider.storage(), &group_id)
            .map_err(|e| CohortGroupError::ApplyFailed(format!("MlsGroup::load: {e:?}")))?
            .ok_or_else(|| CohortGroupError::GroupMissing(community_id.to_string()))?;

        // The own-leaf signature key is the lookup key for the stored
        // SignatureKeyPair. It came out of the same snapshot, so if
        // the group loaded but the signer did not, the snapshot is
        // internally inconsistent — fatal, not degraded.
        let own_sig_pub = group
            .own_leaf_node()
            .ok_or_else(|| CohortGroupError::SignerMissing(community_id.to_string()))?
            .signature_key()
            .as_slice()
            .to_vec();
        let signer =
            SignatureKeyPair::read(provider.storage(), &own_sig_pub, SignatureScheme::ED25519)
                .ok_or_else(|| CohortGroupError::SignerMissing(community_id.to_string()))?;

        Ok(Some(Self {
            community_id: Arc::from(community_id),
            inner: Arc::new(Mutex::new(CohortGroupInner {
                community_id: community_id.to_string(),
                provider,
                signer,
                group,
                store,
                retained_epochs: retained_epochs.max(1),
            })),
        }))
    }

    /// The group's current epoch.
    pub async fn epoch(&self) -> u64 {
        self.inner.lock().await.epoch()
    }

    /// Number of members currently in the group (including self).
    pub async fn member_count(&self) -> usize {
        self.inner.lock().await.group.members().count()
    }

    /// The CIRIS `key_id`s of every member, in leaf order.
    pub async fn member_key_ids(&self) -> Vec<String> {
        self.inner
            .lock()
            .await
            .group
            .members()
            .map(|m| String::from_utf8_lossy(m.credential.serialized_content()).into_owned())
            .collect()
    }

    /// Whether the group is still operational (a removed member's
    /// group goes inactive per RFC 9420).
    pub async fn is_active(&self) -> bool {
        self.inner.lock().await.group.is_active()
    }

    /// The current epoch's cohort exporter secret — the
    /// `exporter_secret` the `community` / `affiliations` scopes need
    /// (CIRISEdge#499).
    ///
    /// The **destination** plane secret — the input to
    /// `k_destination` / `derive_destination`, and therefore to every
    /// scoped Reticulum address this node presents in the cohort.
    ///
    /// Derived under [`crate::scope_privacy::DESTINATION_EXPORTER_LABEL`],
    /// which is deliberately distinct from the record plane's label:
    /// the two secrets go to different subsystems, and sharing one PRK
    /// would mean a compromise yielding the record secret
    /// *retroactively deanonymizes all routing* — an adversary
    /// recomputes and links every address the node ever presented,
    /// collapsing exactly the unlinkability scope-native addressing
    /// exists to buy.
    ///
    /// # Errors
    /// [`CohortGroupError::ExportFailed`] on a corrupted group state.
    pub async fn destination_secret(&self) -> Result<CohortSecret, CohortGroupError> {
        self.inner
            .lock()
            .await
            .scope_secret(crate::scope_privacy::DESTINATION_EXPORTER_LABEL)
    }

    /// The **record** plane secret — the input to `k_record_id` /
    /// `k_symbol`, derived under
    /// [`crate::scope_privacy::RECORD_EXPORTER_LABEL`].
    ///
    /// Independent of [`Self::destination_secret`] by construction; see
    /// there for why the separation is load-bearing rather than tidy.
    ///
    /// # Errors
    /// [`CohortGroupError::ExportFailed`] on a corrupted group state.
    pub async fn record_secret(&self) -> Result<CohortSecret, CohortGroupError> {
        self.inner
            .lock()
            .await
            .scope_secret(crate::scope_privacy::RECORD_EXPORTER_LABEL)
    }

    /// Add a member from a KeyPackage that member published, advance
    /// the epoch, persist, and *then* return the wire artifacts.
    ///
    /// The KeyPackage's ciphersuite is checked **before** the roster
    /// is touched so a mismatched member cannot leave the group in a
    /// partially-advanced state.
    pub async fn add_member(
        &self,
        key_id: &str,
        key_package: KeyPackage,
    ) -> Result<CohortCommit, CohortGroupError> {
        let got = u16::from(key_package.ciphersuite());
        if got != CIPHERSUITE_ID {
            return Err(CohortGroupError::CiphersuiteMismatch {
                key_id: key_id.to_string(),
                got,
            });
        }

        let mut guard = self.inner.lock().await;
        // Reborrow through the guard so `group` / `provider` /
        // `signer` are *disjoint* field borrows. Calling
        // `guard.group.add_members(guard.provider…)` directly would
        // borrow the whole `MutexGuard` twice via `DerefMut`.
        let inner = &mut *guard;
        let (commit_msg, welcome_msg, _group_info) = inner
            .group
            .add_members(inner.provider.as_ref(), &inner.signer, &[key_package])
            .map_err(|e| CohortGroupError::AddFailed(format!("{e:?}")))?;
        inner
            .group
            .merge_pending_commit(inner.provider.as_ref())
            .map_err(|e| CohortGroupError::AddFailed(format!("merge_pending_commit: {e:?}")))?;

        let commit = serialize_mls_message(&commit_msg)?;
        let welcome = Some(serialize_mls_message(&welcome_msg)?);
        inner.persist_and_seal(commit, welcome).await
    }

    /// Remove a member by CIRIS `key_id`, advance the epoch, persist,
    /// and *then* return the wire artifacts.
    pub async fn remove_member(&self, key_id: &str) -> Result<CohortCommit, CohortGroupError> {
        let mut guard = self.inner.lock().await;
        let idx = guard.leaf_of(key_id)?;
        // Disjoint field borrows — see `add_member`.
        let inner = &mut *guard;
        let (commit_msg, welcome_msg, _group_info) = inner
            .group
            .remove_members(inner.provider.as_ref(), &inner.signer, &[idx])
            .map_err(|e| CohortGroupError::RemoveFailed(format!("{e:?}")))?;
        inner
            .group
            .merge_pending_commit(inner.provider.as_ref())
            .map_err(|e| CohortGroupError::RemoveFailed(format!("merge_pending_commit: {e:?}")))?;

        let commit = serialize_mls_message(&commit_msg)?;
        let welcome = welcome_msg.map(|m| serialize_mls_message(&m)).transpose()?;
        inner.persist_and_seal(commit, welcome).await
    }

    /// Rotate this node's own leaf (an MLS self-update commit),
    /// advancing the epoch without a roster change.
    ///
    /// This is the forward-secrecy lever for a cohort: the exporter
    /// secret changes, so records sealed under the old epoch's
    /// `k_record_id` / `k_symbol` are not readable from the new
    /// epoch's derivation, which is what §3.5 `rotate-forward` wants.
    pub async fn rotate(&self) -> Result<CohortCommit, CohortGroupError> {
        let mut guard = self.inner.lock().await;
        // Disjoint field borrows — see `add_member`.
        let inner = &mut *guard;
        let bundle = inner
            .group
            .self_update(
                inner.provider.as_ref(),
                &inner.signer,
                LeafNodeParameters::default(),
            )
            .map_err(|e| CohortGroupError::RotateFailed(format!("{e:?}")))?;
        inner
            .group
            .merge_pending_commit(inner.provider.as_ref())
            .map_err(|e| CohortGroupError::RotateFailed(format!("merge_pending_commit: {e:?}")))?;

        let commit = serialize_mls_message(bundle.commit())?;
        let welcome = bundle
            .to_welcome_msg()
            .map(|m| serialize_mls_message(&m))
            .transpose()?;
        inner.persist_and_seal(commit, welcome).await
    }

    /// Apply a Commit produced by another member, advance to its
    /// epoch, and persist before returning.
    ///
    /// Same ordering discipline, for the same reason: an applied-
    /// but-unpersisted remote commit means a restart rewinds this
    /// node behind its cohort, and MLS gives it no way to catch up
    /// without a fresh Welcome.
    ///
    /// Returns the new epoch.
    pub async fn apply_remote_commit(&self, commit: &[u8]) -> Result<u64, CohortGroupError> {
        let mut guard = self.inner.lock().await;
        // Disjoint field borrows — see `add_member`.
        let inner = &mut *guard;

        let msg_in = MlsMessageIn::tls_deserialize(&mut &*commit)
            .map_err(|e| CohortGroupError::WireDecodeFailed(format!("commit decode: {e:?}")))?;
        let proto: ProtocolMessage = msg_in.try_into_protocol_message().map_err(|e| {
            CohortGroupError::WireDecodeFailed(format!("not a protocol message: {e:?}"))
        })?;

        let processed = inner
            .group
            .process_message(inner.provider.as_ref(), proto)
            .map_err(|e| CohortGroupError::ApplyFailed(format!("{e:?}")))?;

        match processed.into_content() {
            ProcessedMessageContent::StagedCommitMessage(staged) => {
                inner
                    .group
                    .merge_staged_commit(inner.provider.as_ref(), *staged)
                    .map_err(|e| CohortGroupError::ApplyFailed(format!("merge_staged: {e:?}")))?;
            }
            _ => return Err(CohortGroupError::NotACommit),
        }

        // Merge → persist, then report the epoch. There are no wire
        // artifacts to seal here (we are the applier, not the
        // committer), so the sealed value is discarded — but the
        // persist still happens before the caller learns the epoch
        // advanced.
        let sealed = inner.persist_and_seal(Vec::new(), None).await?;
        Ok(sealed.epoch())
    }
}

/// Overwrite an openmls in-memory storage map wholesale.
///
/// `MemoryStorage::values` is a public `RwLock<HashMap<..>>`
/// (openmls_memory_storage 0.5.0), which is precisely what makes the
/// snapshot design possible without implementing the ~45-method
/// synchronous `StorageProvider` over an async KV (CIRISEdge#217 —
/// see module docs).
fn restore_storage(storage: &MemStorage, map: HashMap<Vec<u8>, Vec<u8>>) {
    let mut guard = storage
        .values
        .write()
        .unwrap_or_else(PoisonError::into_inner);
    *guard = map;
}

/// Serialize an `MlsMessageOut` to its on-wire bytes.
fn serialize_mls_message(msg: &MlsMessageOut) -> Result<Vec<u8>, CohortGroupError> {
    msg.tls_serialize_detached()
        .map_err(|e| CohortGroupError::WireDecodeFailed(format!("serialize: {e:?}")))
}

// ─── Registry ───────────────────────────────────────────────────────

/// Process-wide registry of live cohort groups, keyed by
/// `community_id`.
///
/// # Why this exists
///
/// [`CohortGroup`]'s mutex only enforces single-writer for holders of
/// the *same* handle. Two callers that each ran
/// [`CohortGroup::load`] would hold two independent in-memory copies
/// of one group and could commit concurrently — forking the epoch,
/// which is the failure the async mutex was supposed to prevent. The
/// registry closes that: [`Self::open`] is get-or-create, so every
/// caller naming a `community_id` gets a clone of one handle.
///
/// Groups stay resident once opened (bounded by the number of
/// communities the node participates in, not by traffic). A process
/// restart is a fresh registry, which is exactly the reload path
/// [`CohortGroup::load`] implements.
pub struct CohortGroups {
    store: ScopeStateProvider,
    own_key_id: String,
    retained_epochs: u64,
    live: Mutex<HashMap<String, CohortGroup>>,
}

impl std::fmt::Debug for CohortGroups {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `store` is deliberately not rendered: it is a handle on the
        // XChaCha-sealed KV and nothing about it is safe or useful to
        // print.
        f.debug_struct("CohortGroups")
            .field("own_key_id", &self.own_key_id)
            .field("retained_epochs", &self.retained_epochs)
            .field("live", &"<locked>")
            .finish_non_exhaustive()
    }
}

impl CohortGroups {
    /// Build a registry over a sealed-KV-backed
    /// [`ScopeStateProvider`]. `own_key_id` is this node's CIRIS
    /// federation `key_id`, stamped into the MLS credential of any
    /// group this registry creates.
    pub fn new(store: ScopeStateProvider, own_key_id: impl Into<String>) -> Self {
        Self::with_retention(store, own_key_id, DEFAULT_RETAINED_EPOCHS)
    }

    /// As [`Self::new`], with an explicit retention window (see
    /// [`DEFAULT_RETAINED_EPOCHS`]).
    pub fn with_retention(
        store: ScopeStateProvider,
        own_key_id: impl Into<String>,
        retained_epochs: u64,
    ) -> Self {
        Self {
            store,
            own_key_id: own_key_id.into(),
            retained_epochs: retained_epochs.max(1),
            live: Mutex::new(HashMap::new()),
        }
    }

    /// Get the live handle for `community_id`, reloading it from the
    /// sealed KV if this process has not opened it yet, and creating
    /// a fresh group if none has ever been persisted.
    ///
    /// Idempotent: repeated calls return clones of the same handle,
    /// which is what makes the single-writer invariant hold across
    /// independent call sites.
    pub async fn open(&self, community_id: &str) -> Result<CohortGroup, CohortGroupError> {
        let mut live = self.live.lock().await;
        if let Some(existing) = live.get(community_id) {
            return Ok(existing.clone());
        }
        let handle = match CohortGroup::load(self.store.clone(), community_id, self.retained_epochs)
            .await?
        {
            Some(g) => g,
            None => {
                CohortGroup::create(
                    self.store.clone(),
                    community_id,
                    &self.own_key_id,
                    self.retained_epochs,
                )
                .await?
            }
        };
        live.insert(community_id.to_string(), handle.clone());
        Ok(handle)
    }

    /// Join `community_id` from a `Welcome` and register the handle
    /// (CIRISEdge#500) — the registry-level counterpart to
    /// [`CohortGroup::join`].
    ///
    /// Use this rather than calling [`CohortGroup::join`] directly
    /// whenever a [`CohortGroups`] exists, because the whole
    /// load-or-join runs under the SAME `live` lock that [`Self::open`]
    /// holds. Without that, an `open` racing a `join` for one community
    /// would find no state, take its `create` branch, and mint a
    /// *second* group under the same `community_id` — two groups, two
    /// epoch lines, and the single-writer property gone. Holding the
    /// lock across the join makes the two calls serialize.
    ///
    /// If a handle is already live for `community_id`, that handle is
    /// returned and the Welcome is left unconsumed: rejoining a
    /// community this node is already in is a caller error, not
    /// something to resolve by displacing live state.
    ///
    /// # Errors
    /// Whatever [`CohortGroup::join`] returns — including
    /// [`CohortGroupError::AlreadyJoined`] when persisted state exists
    /// for a community with no live handle.
    pub async fn join(
        &self,
        community_id: &str,
        key_material: CohortKeyMaterial,
        welcome: &[u8],
    ) -> Result<CohortGroup, CohortGroupError> {
        let mut live = self.live.lock().await;
        if let Some(existing) = live.get(community_id) {
            return Ok(existing.clone());
        }
        let handle = CohortGroup::join(
            self.store.clone(),
            community_id,
            key_material,
            welcome,
            self.retained_epochs,
        )
        .await?;
        live.insert(community_id.to_string(), handle.clone());
        Ok(handle)
    }

    /// Drop the in-memory handle for `community_id` without touching
    /// its persisted state — the next [`Self::open`] reloads from the
    /// KV. Used by tests to simulate a process restart; also useful
    /// for shedding memory for a community the node has gone quiet
    /// on.
    pub async fn evict(&self, community_id: &str) -> bool {
        self.live.lock().await.remove(community_id).is_some()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::too_many_lines)]
mod tests {
    use super::*;
    use ciris_persist::encrypted_kv::XChaChaKvStore;

    fn open_store() -> ScopeStateProvider {
        let kv = XChaChaKvStore::open_in_memory(b"cohort-group-test-passphrase").unwrap();
        ScopeStateProvider::new(Arc::new(kv))
    }

    // ── Join (CIRISEdge#500) ────────────────────────────────────────

    /// Founder creates, adds `joiner`, and returns (founder, joiner's
    /// key material, the Welcome bytes). Two independent stores —
    /// the real deployment shape; sharing one would have both nodes
    /// clobbering the same head pointer.
    async fn founder_and_welcome(
        community: &str,
        joiner: &str,
    ) -> (CohortGroup, CohortKeyMaterial, Vec<u8>) {
        let a = CohortGroup::create(open_store(), community, "node-a", 16)
            .await
            .unwrap();
        let (material, kp) = mint_cohort_key_material(joiner).unwrap();
        let add = a.add_member(joiner, kp).await.unwrap();
        let welcome = add.welcome().expect("an Add produces a Welcome").to_vec();
        (a, material, welcome)
    }

    #[tokio::test]
    async fn a_joiner_lands_in_the_founders_group_at_the_same_epoch_and_secret() {
        let (a, material, welcome) = founder_and_welcome("c-join", "node-b").await;
        let b = CohortGroup::join(open_store(), "c-join", material, &welcome, 16)
            .await
            .expect("join");

        assert_eq!(b.community_id(), "c-join");
        assert_eq!(
            b.epoch().await,
            a.epoch().await,
            "joiner lands at the add epoch"
        );
        // The exporter is the whole point — a joiner that agreed on
        // everything except the secret would derive a different scoped
        // address and be silently unreachable (CIRISEdge#499).
        assert_eq!(
            b.destination_secret().await.unwrap().as_bytes(),
            a.destination_secret().await.unwrap().as_bytes(),
            "joiner must derive the SAME cohort secret as the founder",
        );
        let mut roster = b.member_key_ids().await;
        roster.sort();
        assert_eq!(roster, vec!["node-a".to_string(), "node-b".to_string()]);
    }

    #[tokio::test]
    async fn a_join_is_durable_before_the_handle_is_usable() {
        // The invariant. Process death is simulated by dropping the
        // handle, which discards the whole in-memory provider —
        // everything but the sealed KV.
        let (a, material, welcome) = founder_and_welcome("c-join-durable", "node-b").await;
        let store_b = open_store();

        let (epoch_at_join, secret_at_join) = {
            let b = CohortGroup::join(store_b.clone(), "c-join-durable", material, &welcome, 16)
                .await
                .unwrap();
            // At the instant the caller holds the handle, the KV must
            // ALREADY name this epoch — not after some later commit.
            let head = store_b
                .group_state_get("c-join-durable", HEAD_SLOT)
                .await
                .unwrap()
                .expect("head pointer written before join returned");
            let epoch = b.epoch().await;
            assert_eq!(decode_head(&head).unwrap(), epoch);
            assert!(
                store_b
                    .group_state_get("c-join-durable", epoch)
                    .await
                    .unwrap()
                    .is_some(),
                "the snapshot the head names must exist before join returns",
            );
            (epoch, *b.destination_secret().await.unwrap().as_bytes())
        };

        // Crash, then reload. Membership peers already committed to
        // must survive.
        let reloaded = CohortGroup::load(store_b, "c-join-durable", 16)
            .await
            .unwrap()
            .expect("a joined group reloads");
        assert_eq!(reloaded.epoch().await, epoch_at_join);
        assert_eq!(
            *reloaded.destination_secret().await.unwrap().as_bytes(),
            secret_at_join,
        );
        // And it can still take part: applying the founder's next
        // commit is what proves the signer survived the round trip.
        let rotate = a.rotate().await.unwrap();
        let new_epoch = reloaded.apply_remote_commit(rotate.commit()).await.unwrap();
        assert_eq!(new_epoch, a.epoch().await);
        assert_eq!(
            reloaded.destination_secret().await.unwrap().as_bytes(),
            a.destination_secret().await.unwrap().as_bytes(),
        );
    }

    #[tokio::test]
    async fn a_welcome_for_another_community_is_refused_and_persists_nothing() {
        let (_a, material, welcome) = founder_and_welcome("c-real", "node-b").await;
        let store_b = open_store();

        // Same cryptographically-valid Welcome, filed under the wrong
        // community. Accepting it would derive every later secret
        // under a community the group is not for (the exporter context
        // is the community_id).
        let err = CohortGroup::join(store_b.clone(), "c-imposter", material, &welcome, 16)
            .await
            .expect_err("a Welcome for another group must be refused");
        match err {
            CohortGroupError::WelcomeForDifferentGroup {
                ref community_id, ..
            } => assert_eq!(community_id, "c-imposter"),
            other => panic!("expected WelcomeForDifferentGroup, got {other:?}"),
        }
        assert!(
            store_b
                .group_state_get("c-imposter", HEAD_SLOT)
                .await
                .unwrap()
                .is_none(),
            "a refused join must leave NOTHING persisted",
        );
    }

    #[tokio::test]
    async fn join_refuses_to_displace_existing_group_state() {
        let (_a, material, welcome) = founder_and_welcome("c-existing", "node-b").await;
        // This node already has its own group for the community.
        let store_b = open_store();
        let own = CohortGroup::create(store_b.clone(), "c-existing", "node-b", 16)
            .await
            .unwrap();
        let own_epoch = own.epoch().await;
        let own_secret = *own.destination_secret().await.unwrap().as_bytes();

        let err = CohortGroup::join(store_b.clone(), "c-existing", material, &welcome, 16)
            .await
            .expect_err("join must not displace existing state");
        assert!(
            matches!(err, CohortGroupError::AlreadyJoined(ref c, e) if c == "c-existing" && e == own_epoch)
        );

        // The pre-existing group is untouched — head still names its
        // epoch, and it still derives its own secret.
        let reloaded = CohortGroup::load(store_b, "c-existing", 16)
            .await
            .unwrap()
            .expect("pre-existing group survives a refused join");
        assert_eq!(reloaded.epoch().await, own_epoch);
        assert_eq!(
            *reloaded.destination_secret().await.unwrap().as_bytes(),
            own_secret
        );
    }

    #[tokio::test]
    async fn non_welcome_bytes_are_refused_by_content_type_not_by_crash() {
        let (a, material, _welcome) = founder_and_welcome("c-notwelcome", "node-b").await;
        // A Commit is a valid MLS message and NOT a Welcome.
        let rotate = a.rotate().await.unwrap();
        let err = CohortGroup::join(open_store(), "c-notwelcome", material, rotate.commit(), 16)
            .await
            .expect_err("a Commit is not a Welcome");
        assert!(matches!(err, CohortGroupError::NotAWelcome), "got {err:?}");

        let (material2, _kp) = mint_cohort_key_material("node-c").unwrap();
        let err = CohortGroup::join(
            open_store(),
            "c-notwelcome",
            material2,
            b"not mls at all",
            16,
        )
        .await
        .expect_err("garbage is not MLS");
        assert!(
            matches!(err, CohortGroupError::WireDecodeFailed(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn registry_join_registers_one_handle_and_open_reuses_it() {
        let (_a, material, welcome) = founder_and_welcome("c-registry", "node-b").await;
        let groups = CohortGroups::with_retention(open_store(), "node-b", 16);

        let joined = groups.join("c-registry", material, &welcome).await.unwrap();
        // `open` must find the JOINED group, not take its create branch
        // and mint a second group under the same community.
        let opened = groups.open("c-registry").await.unwrap();
        assert!(
            Arc::ptr_eq(&joined.inner, &opened.inner),
            "open must return the joined handle, not create a rival group",
        );
        assert_eq!(opened.epoch().await, joined.epoch().await);

        // After eviction it reloads from the KV rather than re-creating.
        assert!(groups.evict("c-registry").await);
        let reopened = groups.open("c-registry").await.unwrap();
        assert!(!Arc::ptr_eq(&joined.inner, &reopened.inner));
        assert_eq!(reopened.epoch().await, joined.epoch().await);
        let mut roster = reopened.member_key_ids().await;
        roster.sort();
        assert_eq!(roster, vec!["node-a".to_string(), "node-b".to_string()]);
    }

    // ── Snapshot codec ──────────────────────────────────────────────

    #[test]
    fn snapshot_codec_roundtrips() {
        let mut map = HashMap::new();
        map.insert(b"alpha".to_vec(), b"one".to_vec());
        map.insert(b"beta".to_vec(), vec![0u8; 300]);
        map.insert(Vec::new(), Vec::new()); // empty key + empty value
        let blob = encode_snapshot(&map).unwrap();
        assert_eq!(decode_snapshot(&blob).unwrap(), map);
    }

    #[test]
    fn snapshot_codec_roundtrips_empty_map() {
        let map = HashMap::new();
        let blob = encode_snapshot(&map).unwrap();
        assert_eq!(decode_snapshot(&blob).unwrap(), map);
    }

    #[test]
    fn snapshot_encoding_is_deterministic() {
        // Two maps with identical content but built in different
        // insertion orders must encode to identical bytes — the
        // sorted-key emission. Keeps the sealed-KV write stable
        // instead of churning under HashMap iteration order.
        let mut a = HashMap::new();
        a.insert(b"k1".to_vec(), b"v1".to_vec());
        a.insert(b"k2".to_vec(), b"v2".to_vec());
        a.insert(b"k3".to_vec(), b"v3".to_vec());
        let mut b = HashMap::new();
        b.insert(b"k3".to_vec(), b"v3".to_vec());
        b.insert(b"k1".to_vec(), b"v1".to_vec());
        b.insert(b"k2".to_vec(), b"v2".to_vec());
        assert_eq!(encode_snapshot(&a).unwrap(), encode_snapshot(&b).unwrap());
    }

    #[test]
    fn snapshot_version_byte_is_checked() {
        // The whole point of the version byte: a future format change
        // must be *detectable*, not a garbage load (CIRISEdge#499).
        let mut map = HashMap::new();
        map.insert(b"k".to_vec(), b"v".to_vec());
        let mut blob = encode_snapshot(&map).unwrap();
        blob[8] = 0xFE;
        assert!(matches!(
            decode_snapshot(&blob),
            Err(CohortGroupError::SnapshotVersion(0xFE))
        ));
    }

    #[test]
    fn snapshot_magic_is_checked() {
        let blob = vec![0u8; 32];
        assert!(matches!(
            decode_snapshot(&blob),
            Err(CohortGroupError::SnapshotMagic)
        ));
    }

    #[test]
    fn snapshot_rejects_truncation_and_trailing_bytes() {
        let mut map = HashMap::new();
        map.insert(b"key".to_vec(), b"value".to_vec());
        let blob = encode_snapshot(&map).unwrap();

        let truncated = &blob[..blob.len() - 1];
        assert!(matches!(
            decode_snapshot(truncated),
            Err(CohortGroupError::SnapshotMalformed(_))
        ));

        let mut extended = blob.clone();
        extended.push(0xAA);
        assert!(matches!(
            decode_snapshot(&extended),
            Err(CohortGroupError::SnapshotMalformed(_))
        ));

        assert!(matches!(
            decode_snapshot(&blob[..4]),
            Err(CohortGroupError::SnapshotMalformed(_))
        ));
    }

    #[test]
    fn snapshot_rejects_absurd_declared_lengths() {
        // A declared count/length far beyond the blob must be a loud
        // refusal, never an allocation sized from the wire.
        let mut blob = Vec::new();
        blob.extend_from_slice(SNAPSHOT_MAGIC);
        blob.push(SNAPSHOT_VERSION);
        blob.extend_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            decode_snapshot(&blob),
            Err(CohortGroupError::SnapshotMalformed(_))
        ));

        let mut blob = Vec::new();
        blob.extend_from_slice(SNAPSHOT_MAGIC);
        blob.push(SNAPSHOT_VERSION);
        blob.extend_from_slice(&1u32.to_be_bytes());
        blob.extend_from_slice(&u32::MAX.to_be_bytes()); // k_len
        blob.extend_from_slice(&0u32.to_be_bytes()); // v_len
        assert!(matches!(
            decode_snapshot(&blob),
            Err(CohortGroupError::SnapshotMalformed(_))
        ));
    }

    #[test]
    fn head_pointer_codec_roundtrips_and_is_versioned() {
        for epoch in [0u64, 1, 42, u64::MAX - 1] {
            assert_eq!(decode_head(&encode_head(epoch)).unwrap(), epoch);
        }
        let mut bad = encode_head(7);
        bad[0] = 0x99;
        assert!(matches!(
            decode_head(&bad),
            Err(CohortGroupError::HeadMalformed(_))
        ));
        assert!(matches!(
            decode_head(&[0x01, 0x00]),
            Err(CohortGroupError::HeadMalformed(_))
        ));
    }

    #[test]
    fn group_id_is_domain_separated_per_community() {
        assert_ne!(cohort_group_id("a"), cohort_group_id("b"));
        assert!(cohort_group_id("a")
            .as_slice()
            .starts_with(b"ciris-cohort:"));
    }

    // ── Create / exporter ───────────────────────────────────────────

    #[tokio::test]
    async fn create_persists_genesis_epoch() {
        let store = open_store();
        let g = CohortGroup::create(store.clone(), "community-1", "node-a", 4)
            .await
            .unwrap();
        assert_eq!(g.epoch().await, 0);
        assert_eq!(g.member_count().await, 1);
        assert!(g.is_active().await);

        // Genesis state is durable the moment `create` returns.
        let head = store
            .group_state_get("community-1", HEAD_SLOT)
            .await
            .unwrap()
            .expect("head pointer written at create");
        assert_eq!(decode_head(&head).unwrap(), 0);
        assert!(store
            .group_state_get("community-1", 0)
            .await
            .unwrap()
            .is_some());
    }

    #[tokio::test]
    async fn exporter_is_stable_within_an_epoch_and_changes_across_epochs() {
        let store = open_store();
        let g = CohortGroup::create(store, "c-exp", "node-a", 4)
            .await
            .unwrap();
        let s0 = g.destination_secret().await.unwrap();
        let s0b = g.destination_secret().await.unwrap();
        assert_eq!(s0.as_bytes(), s0b.as_bytes());

        let _ = g.rotate().await.unwrap();
        let s1 = g.destination_secret().await.unwrap();
        assert_ne!(s0.as_bytes(), s1.as_bytes());
    }

    #[tokio::test]
    async fn the_two_scope_planes_derive_independent_secrets() {
        // CIRISVerify v13.5.0 gives the record plane and the
        // destination plane their OWN exporter labels, and that
        // separation is load-bearing rather than tidy: sharing one PRK
        // would mean a compromise yielding the record secret
        // retroactively deanonymizes all routing — an adversary
        // recomputes and links every address the node ever presented.
        // If these two ever came back equal, that property is gone and
        // nothing else in the stack would notice.
        let g = CohortGroup::create(open_store(), "c-planes", "node-a", 4)
            .await
            .unwrap();
        let dest = *g.destination_secret().await.unwrap().as_bytes();
        let record = *g.record_secret().await.unwrap().as_bytes();
        assert_ne!(
            dest, record,
            "record and destination planes must not share a PRK",
        );

        // Each is deterministic within an epoch...
        assert_eq!(*g.destination_secret().await.unwrap().as_bytes(), dest);
        assert_eq!(*g.record_secret().await.unwrap().as_bytes(), record);

        // ...and both move when the epoch does, or rotation would not
        // re-address the group.
        let _rotated = g.rotate().await.unwrap();
        assert_ne!(*g.destination_secret().await.unwrap().as_bytes(), dest);
        assert_ne!(*g.record_secret().await.unwrap().as_bytes(), record);
    }

    #[tokio::test]
    async fn the_exporter_context_is_verifys_empty_value_not_the_community_id() {
        // The context is a cross-impl wire fact: two members agree only
        // under the same (label, context, length). Edge previously used
        // `community_id` as the context — a local safety margin that
        // would have made edge derive different bytes from every other
        // implementation. Verify specifies EMPTY, so that is what this
        // pins, by deriving the same secret a bare export_secret call
        // under verify's constants produces.
        let g = CohortGroup::create(open_store(), "c-context", "node-a", 4)
            .await
            .unwrap();
        let via_accessor = *g.destination_secret().await.unwrap().as_bytes();

        let inner = g.inner.lock().await;
        let direct = inner
            .group
            .export_secret(
                inner.provider.crypto(),
                crate::scope_privacy::DESTINATION_EXPORTER_LABEL,
                crate::scope_privacy::EXPORTER_CONTEXT,
                COHORT_SECRET_LEN,
            )
            .unwrap();
        assert_eq!(
            via_accessor.as_slice(),
            direct.as_slice(),
            "the accessor must export under verify's exact (label, context, length)",
        );
        assert!(
            crate::scope_privacy::EXPORTER_CONTEXT.is_empty(),
            "verify specifies an EMPTY exporter context",
        );
    }

    #[tokio::test]
    async fn exporter_is_domain_separated_from_the_av_label() {
        // Neither scope-privacy label may be the A/V DEK-seed label —
        // verify refused that input explicitly. Asserted on the
        // constants (the A/V string is duplicated here rather than
        // imported — `crate::transport::*` is off-limits for this
        // workstream) and behaviourally: exporting the same group
        // under the A/V label yields different bytes.
        const AV_LABEL: &str = "ciris-realtime-av-epoch-dek-seed-v1";
        assert_ne!(crate::scope_privacy::DESTINATION_EXPORTER_LABEL, AV_LABEL);
        assert_ne!(crate::scope_privacy::RECORD_EXPORTER_LABEL, AV_LABEL);

        let store = open_store();
        let g = CohortGroup::create(store, "c-label", "node-a", 4)
            .await
            .unwrap();
        let cohort = g.destination_secret().await.unwrap();

        let inner = g.inner.lock().await;
        let av = inner
            .group
            .export_secret(inner.provider.crypto(), AV_LABEL, b"", 32)
            .unwrap();
        assert_ne!(cohort.as_bytes().as_slice(), av.as_slice());
    }

    #[test]
    fn cohort_secret_debug_redacts() {
        let s = CohortSecret([7u8; 32]);
        let rendered = format!("{s:?}");
        assert!(rendered.contains("redacted"), "{rendered}");
        assert!(
            !rendered.contains('7') || !rendered.contains("07"),
            "{rendered}"
        );
    }

    // ── THE ordering invariant ──────────────────────────────────────

    #[tokio::test]
    async fn commit_is_durable_before_it_is_emitted() {
        // merge → snapshot+persist → THEN emit. The observable
        // contract: at the instant the caller holds the Commit bytes,
        // the KV already carries that epoch's snapshot AND the head
        // pointer already names it. If persistence happened after the
        // emit, either check would fail here.
        let store = open_store();
        let g = CohortGroup::create(store.clone(), "c-order", "node-a", 8)
            .await
            .unwrap();

        let (_m, kp) = mint_cohort_key_material("node-b").unwrap();
        let artifacts = g.add_member("node-b", kp).await.unwrap();

        assert_eq!(artifacts.epoch(), 1);
        assert!(!artifacts.commit().is_empty());
        assert!(artifacts.welcome().is_some());

        let head = store
            .group_state_get("c-order", HEAD_SLOT)
            .await
            .unwrap()
            .expect("head pointer must already name the emitted epoch");
        assert_eq!(decode_head(&head).unwrap(), artifacts.epoch());
        assert!(
            store
                .group_state_get("c-order", artifacts.epoch())
                .await
                .unwrap()
                .is_some(),
            "the emitted epoch's snapshot must already be durable"
        );
    }

    #[tokio::test]
    async fn crash_after_emit_reloads_at_the_emitted_epoch() {
        // The crash this ordering exists to survive: the process dies
        // the instant after `add_member` returns. Peers are at the
        // emitted epoch; so must we be, and we must still be able to
        // commit.
        let store = open_store();
        let emitted_epoch = {
            let g = CohortGroup::create(store.clone(), "c-crash", "node-a", 8)
                .await
                .unwrap();
            let (_m, kp) = mint_cohort_key_material("node-b").unwrap();
            let artifacts = g.add_member("node-b", kp).await.unwrap();
            artifacts.epoch()
            // `g` dropped here — the whole in-memory provider goes
            // with it. Nothing but the sealed KV survives.
        };

        let reloaded = CohortGroup::load(store, "c-crash", 8)
            .await
            .unwrap()
            .expect("group must reload after the crash");
        assert_eq!(reloaded.epoch().await, emitted_epoch);
        assert_eq!(reloaded.member_count().await, 2);

        // And it can still commit — the property that would be lost
        // if the epoch had been advertised before being persisted.
        let after = reloaded.rotate().await.unwrap();
        assert_eq!(after.epoch(), emitted_epoch + 1);
    }

    // ── Restart round-trip, incl. the signature key pair ────────────

    #[tokio::test]
    async fn signature_key_pair_survives_the_restart_roundtrip() {
        // create → snapshot → drop → load → commit. The commit at the
        // end is the real assertion: `MlsGroup::commit` needs the
        // group's private signing key, so a signer that did not make
        // it into (or out of) the snapshot fails HERE and nowhere
        // earlier (CIRISEdge#499).
        let store = open_store();
        let (own_sig_pub, epoch_before) = {
            let g = CohortGroup::create(store.clone(), "c-signer", "node-a", 8)
                .await
                .unwrap();
            let inner = g.inner.lock().await;
            let pk = inner
                .group
                .own_leaf_node()
                .unwrap()
                .signature_key()
                .as_slice()
                .to_vec();
            (pk, inner.epoch())
        };

        let reloaded = CohortGroup::load(store, "c-signer", 8)
            .await
            .unwrap()
            .expect("group must reload");
        assert_eq!(reloaded.epoch().await, epoch_before);

        // Same signing identity, not a freshly minted one.
        {
            let inner = reloaded.inner.lock().await;
            assert_eq!(inner.signer.to_public_vec(), own_sig_pub);
            assert_eq!(
                inner
                    .group
                    .own_leaf_node()
                    .unwrap()
                    .signature_key()
                    .as_slice(),
                own_sig_pub.as_slice()
            );
        }

        // The load-bearing part: it can still commit.
        let artifacts = reloaded.rotate().await.unwrap();
        assert_eq!(artifacts.epoch(), epoch_before + 1);

        // …and add members after the restart.
        let (_m, kp) = mint_cohort_key_material("node-b").unwrap();
        let add = reloaded.add_member("node-b", kp).await.unwrap();
        assert_eq!(add.epoch(), epoch_before + 2);
        assert_eq!(reloaded.member_count().await, 2);
    }

    #[tokio::test]
    async fn exporter_survives_the_restart_roundtrip() {
        // The reason the whole module exists: the community scope's
        // exporter_secret must be the SAME bytes after a restart, or
        // every record sealed under it becomes unreadable.
        let store = open_store();
        let before = {
            let g = CohortGroup::create(store.clone(), "c-exp-rt", "node-a", 8)
                .await
                .unwrap();
            *g.destination_secret().await.unwrap().as_bytes()
        };
        let reloaded = CohortGroup::load(store, "c-exp-rt", 8)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            *reloaded.destination_secret().await.unwrap().as_bytes(),
            before
        );
    }

    #[tokio::test]
    async fn load_returns_none_for_an_unknown_community() {
        let store = open_store();
        assert!(CohortGroup::load(store, "never-created", 4)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn load_fails_closed_on_a_dangling_head() {
        // A head pointing at a pruned/lost epoch must NOT silently
        // rewind to an older snapshot: a rewound group re-uses epoch
        // numbers its peers already consumed.
        let store = open_store();
        let g = CohortGroup::create(store.clone(), "c-dangle", "node-a", 8)
            .await
            .unwrap();
        let _ = g.rotate().await.unwrap();
        store.group_state_delete("c-dangle", 1).await.unwrap();

        assert!(matches!(
            CohortGroup::load(store, "c-dangle", 8).await,
            Err(CohortGroupError::HeadDangling(1))
        ));
    }

    // ── Roster ops ──────────────────────────────────────────────────

    #[tokio::test]
    async fn add_then_remove_advances_and_persists_each_epoch() {
        let store = open_store();
        let g = CohortGroup::create(store.clone(), "c-roster", "node-a", 16)
            .await
            .unwrap();

        let (_m, kp) = mint_cohort_key_material("node-b").unwrap();
        assert_eq!(g.add_member("node-b", kp).await.unwrap().epoch(), 1);
        assert_eq!(g.member_count().await, 2);
        let ids = g.member_key_ids().await;
        assert!(ids.contains(&"node-a".to_string()));
        assert!(ids.contains(&"node-b".to_string()));

        let removed = g.remove_member("node-b").await.unwrap();
        assert_eq!(removed.epoch(), 2);
        assert_eq!(g.member_count().await, 1);
        assert!(removed.welcome().is_none());

        // Every epoch along the way is durable.
        for epoch in 0..=2u64 {
            assert!(
                store
                    .group_state_get("c-roster", epoch)
                    .await
                    .unwrap()
                    .is_some(),
                "epoch {epoch} snapshot missing"
            );
        }
    }

    #[tokio::test]
    async fn remove_of_an_unknown_member_leaves_the_epoch_untouched() {
        let store = open_store();
        let g = CohortGroup::create(store, "c-missing", "node-a", 4)
            .await
            .unwrap();
        assert!(matches!(
            g.remove_member("ghost").await,
            Err(CohortGroupError::MemberNotFound(_))
        ));
        assert_eq!(g.epoch().await, 0);
    }

    #[tokio::test]
    async fn add_member_refuses_a_mismatched_ciphersuite_without_advancing() {
        // Refused BEFORE the roster is touched, so a bad member
        // cannot leave the group partially advanced.
        let store = open_store();
        let g = CohortGroup::create(store, "c-suite", "node-a", 4)
            .await
            .unwrap();

        let provider = LibcruxProvider::default();
        let signer = SignatureKeyPair::new(SignatureScheme::ED25519).unwrap();
        signer.store(provider.storage()).unwrap();
        let cred = CredentialWithKey {
            credential: BasicCredential::new(b"node-classical".to_vec()).into(),
            signature_key: signer.to_public_vec().into(),
        };
        let bundle: KeyPackageBundle = KeyPackage::builder()
            .build(
                Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519,
                &provider,
                &signer,
                cred,
            )
            .unwrap();

        let err = g
            .add_member("node-classical", bundle.key_package().clone())
            .await
            .unwrap_err();
        assert!(matches!(
            err,
            CohortGroupError::CiphersuiteMismatch { got, .. } if got != CIPHERSUITE_ID
        ));
        assert_eq!(g.epoch().await, 0);
    }

    #[tokio::test]
    async fn rotate_advances_the_epoch_without_a_roster_change() {
        let store = open_store();
        let g = CohortGroup::create(store, "c-rot", "node-a", 4)
            .await
            .unwrap();
        let before = g.member_count().await;
        let r = g.rotate().await.unwrap();
        assert_eq!(r.epoch(), 1);
        assert_eq!(g.member_count().await, before);
        assert!(r.welcome().is_none());
    }

    #[tokio::test]
    async fn apply_remote_commit_rejects_non_commit_bytes() {
        let store = open_store();
        let g = CohortGroup::create(store, "c-remote", "node-a", 4)
            .await
            .unwrap();
        assert!(matches!(
            g.apply_remote_commit(&[0u8; 12]).await,
            Err(CohortGroupError::WireDecodeFailed(_))
        ));
        assert_eq!(g.epoch().await, 0);
    }

    #[tokio::test]
    async fn apply_remote_commit_persists_before_reporting_the_epoch() {
        // Second member joins via Welcome so it holds a real remote
        // group, then the first member's rotate Commit is applied by
        // the second.
        //
        // This drives the PUBLIC `join` verb (CIRISEdge#500). It used
        // to hand-assemble node-b's handle out of openmls's
        // `StagedWelcome` and a directly-constructed
        // `CohortGroupInner`, because no join verb existed — which
        // meant the test asserted the apply path over a handle no
        // production code path could ever produce.

        // Two nodes, ONE community, two independent local sealed
        // stores — the real deployment shape. (Sharing a store would
        // have both nodes clobbering the same
        // `mls/{community}/group_state` head pointer.)
        let store_a = open_store();
        let store_b = open_store();
        let a = CohortGroup::create(store_a, "c-apply", "node-a", 16)
            .await
            .unwrap();
        let (material, kp) = mint_cohort_key_material("node-b").unwrap();
        let add = a.add_member("node-b", kp).await.unwrap();

        let b = CohortGroup::join(
            store_b.clone(),
            "c-apply",
            material,
            add.welcome().expect("an Add produces a Welcome"),
            16,
        )
        .await
        .expect("join");
        assert_eq!(b.epoch().await, add.epoch());

        let rotate = a.rotate().await.unwrap();
        let new_epoch = b.apply_remote_commit(rotate.commit()).await.unwrap();
        assert_eq!(new_epoch, rotate.epoch());

        // Durable at the instant the epoch is reported.
        let head = store_b
            .group_state_get("c-apply", HEAD_SLOT)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(decode_head(&head).unwrap(), new_epoch);

        // Both sides derive the same exporter for the same epoch —
        // the property that makes a cohort secret a *shared* secret.
        let shared = *a.destination_secret().await.unwrap().as_bytes();
        assert_eq!(*b.destination_secret().await.unwrap().as_bytes(), shared);

        // …and node-b's applied epoch survives a restart, exporter
        // included. A Welcome-joined group persists exactly like a
        // created one because `mint_cohort_key_material` stored the
        // signer in the same provider the snapshot captures.
        drop(b);
        let b_reloaded = CohortGroup::load(store_b, "c-apply", 16)
            .await
            .unwrap()
            .expect("joined group must reload");
        assert_eq!(b_reloaded.epoch().await, new_epoch);
        assert_eq!(
            *b_reloaded.destination_secret().await.unwrap().as_bytes(),
            shared
        );
    }

    // ── Retention bound ─────────────────────────────────────────────

    #[tokio::test]
    async fn retained_epochs_are_bounded() {
        // The snapshot rewrites the whole blob per commit, so without
        // a bound the sealed KV grows one full copy of group state
        // per commit, forever.
        let store = open_store();
        let retain = 3u64;
        let g = CohortGroup::create(store.clone(), "c-prune", "node-a", retain)
            .await
            .unwrap();
        for _ in 0..6 {
            let _ = g.rotate().await.unwrap();
        }
        let head_epoch = g.epoch().await;
        assert_eq!(head_epoch, 6);

        for epoch in 0..=head_epoch {
            let present = store
                .group_state_get("c-prune", epoch)
                .await
                .unwrap()
                .is_some();
            if epoch + retain <= head_epoch {
                assert!(!present, "epoch {epoch} should have been pruned");
            } else {
                assert!(present, "epoch {epoch} should still be retained");
            }
        }
    }

    #[tokio::test]
    async fn retention_of_zero_is_clamped_to_one() {
        // A zero window would delete the epoch it just wrote.
        let store = open_store();
        let g = CohortGroup::create(store.clone(), "c-zero", "node-a", 0)
            .await
            .unwrap();
        let _ = g.rotate().await.unwrap();
        assert!(store
            .group_state_get("c-zero", g.epoch().await)
            .await
            .unwrap()
            .is_some());
    }

    // ── Single-writer ───────────────────────────────────────────────

    #[tokio::test]
    async fn registry_hands_out_one_handle_per_community() {
        // Two independent `open` calls must share one mutex, or
        // concurrent commits fork the epoch.
        let store = open_store();
        let groups = CohortGroups::new(store, "node-a");
        let g1 = groups.open("c-reg").await.unwrap();
        let g2 = groups.open("c-reg").await.unwrap();
        assert!(Arc::ptr_eq(&g1.inner, &g2.inner));

        let other = groups.open("c-other").await.unwrap();
        assert!(!Arc::ptr_eq(&g1.inner, &other.inner));
    }

    #[tokio::test]
    async fn concurrent_commits_serialize_instead_of_forking_the_epoch() {
        // N concurrent rotates through clones of one handle must
        // produce N distinct, contiguous epochs. A forked epoch shows
        // up as a duplicate.
        let store = open_store();
        let groups = CohortGroups::with_retention(store, "node-a", 64);
        let g = groups.open("c-race").await.unwrap();

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let handle = g.clone();
            tasks.push(tokio::spawn(async move { handle.rotate().await }));
        }
        let mut epochs = Vec::new();
        for t in tasks {
            epochs.push(t.await.unwrap().unwrap().epoch());
        }
        epochs.sort_unstable();
        assert_eq!(epochs, (1..=8u64).collect::<Vec<_>>());
        assert_eq!(g.epoch().await, 8);
    }

    #[tokio::test]
    async fn registry_reloads_after_eviction_instead_of_re_creating() {
        // Eviction models a process restart: the next `open` must
        // reload the persisted group (same epoch, same exporter), not
        // mint a fresh one.
        let store = open_store();
        let groups = CohortGroups::with_retention(store, "node-a", 8);
        let g = groups.open("c-evict").await.unwrap();
        let _ = g.rotate().await.unwrap();
        let epoch = g.epoch().await;
        let secret = *g.destination_secret().await.unwrap().as_bytes();
        drop(g);

        assert!(groups.evict("c-evict").await);
        let back = groups.open("c-evict").await.unwrap();
        assert_eq!(back.epoch().await, epoch);
        assert_eq!(*back.destination_secret().await.unwrap().as_bytes(), secret);
    }

    #[tokio::test]
    async fn per_community_state_is_isolated() {
        let store = open_store();
        let groups = CohortGroups::new(store, "node-a");
        let a = groups.open("comm-a").await.unwrap();
        let b = groups.open("comm-b").await.unwrap();
        let _ = a.rotate().await.unwrap();
        assert_eq!(a.epoch().await, 1);
        assert_eq!(b.epoch().await, 0);
        assert_ne!(
            a.destination_secret().await.unwrap().as_bytes(),
            b.destination_secret().await.unwrap().as_bytes()
        );
    }
}
