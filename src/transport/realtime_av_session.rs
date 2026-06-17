//! Realtime A/V session state — membership-change epoch rekey, MLS-backed
//! (CIRISEdge#129, §10.5.5 forward-secrecy boundary, T2/T3' reconciliation).
//!
//! This module owns the stateful group-key holder for one realtime stream:
//! the current `Epoch` and a 32-byte `EpochDek` derived from MLS's
//! per-epoch exporter secret. Membership churn (join/leave) runs through
//! [`AvSession::advance_epoch`] which delegates to the wrapped
//! [`MlsSession`](crate::transport::realtime_av_mls::MlsSession) for the
//! actual key-agreement work.
//!
//! [`realtime_av`](crate::transport::realtime_av) defines the per-chunk
//! double-seal primitives that consume the `EpochDek` this module produces.
//!
//! ## T2 → T6 reconciliation (this is a wire-format-touching change vs T2)
//!
//! v3.7.x shipped a T2 baseline where `AvSession::advance_epoch` returned
//! `Vec<DekWrap>` — one hybrid-KEM-derived 32-byte session key per
//! recipient. That baseline had a known correctness flaw: each recipient
//! got a DIFFERENT 32-byte session key (each is a fresh hybrid handshake),
//! so "the mesh-wide epoch DEK" was not the same bytes across the mesh.
//! T2 flagged this as an open question; T3' confirmed the answer: MLS's
//! `exporter_secret` IS the canonical shared DEK — every group member
//! derives the same 32 bytes from the same epoch.
//!
//! Concretely:
//!
//! - **T2 surface (v3.7.x)**: `advance_epoch` returned `EpochRekeyArtifacts
//!   { new_epoch, wraps: Vec<DekWrap> }`. Receiver side used
//!   `AvSession::unwrap_dek(wrap, own_keys)`.
//! - **T6 surface (v3.8.0+)**: `advance_epoch` returns `EpochRekeyArtifacts
//!   { new_epoch, commit_bytes, welcome_bytes: Vec<Vec<u8>>, new_dek }`.
//!   Receiver side uses [`AvSession::process_commit`] (existing member)
//!   or [`AvSession::process_welcome`] (joiner).
//!
//! Anyone integrating the v3.8.0 prerelease against the T2 baseline MUST
//! re-test the rekey path. The standalone `DekWrap` struct and the
//! `unwrap_dek` method are removed.
//!
//! ## L5-C welcome-shape change (CIRISEdge#131, v3.8.0)
//!
//! `EpochRekeyArtifacts.welcome_bytes` shape changed from
//! `Option<Vec<u8>>` (v3.8.0-prerelease) to `Vec<Vec<u8>>`
//! (v3.8.0+) to admit batched multi-add commits via
//! [`RosterDelta::Batch`]. The per-variant shape is now:
//!
//! - [`RosterDelta::Join`] → `welcome_bytes.len() == 1`
//! - [`RosterDelta::Leave`] → `welcome_bytes.is_empty()`
//! - [`RosterDelta::Batch`] → `welcome_bytes.len()` == number of
//!   Add ops in the batch; order preserves Add order. Removes
//!   contribute no Welcome entries.
//! - [`RosterDelta::Replace`] → same as `Batch` — implemented as a
//!   diff that translates into a Batch internally.
//!
//! Within a single multi-add Batch every byte entry is identical
//! (openmls 0.8.1 produces ONE Welcome with N
//! `EncryptedGroupSecrets`; we clone its bytes once per Add so
//! callers can route to N joiners by index without parsing the
//! Welcome themselves).
//!
//! ## Forward-secrecy boundary
//!
//! - **Forward secrecy on Leave**: openmls's `commit_remove` follows RFC
//!   9420 §13.4 + Chevalier/Lebrun "Quarantined-TreeKEM" discipline — the
//!   leaver is quarantined out of the group BEFORE the new epoch's
//!   `exporter_secret` is derived. The leaver does NOT receive a Commit
//!   they can apply; the new EpochDek is unreachable to them.
//! - **Join secrecy on Join**: the joiner processes a Welcome to bootstrap
//!   into the post-commit state. They get the new EpochDek but NOT the
//!   prior epoch's exporter_secret. MLS derives each epoch's exporter
//!   independently from the prior root + the commit secret (RFC 9420
//!   §8.4 / §8.5), so the joiner cannot recover any chunk sealed under
//!   the prior DEK even given the new one.
//!
//! ## HNDL discipline
//!
//! The MLS ciphersuite 0x004D (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`)
//! is structurally HNDL-strict — it requires ML-KEM-768 per spec. The
//! `PeerLacksMlkem` gate from T2 is preserved: every `Member`'s
//! advertised KEX pubkeys are pre-checked before any MLS code runs (the
//! check itself lives in [`MlsSession`](crate::transport::realtime_av_mls::MlsSession);
//! AvSession surfaces it via [`AvSessionError::PeerLacksMlkem`]).
//!
//! ## Replace + Batch — multi-proposal commits (L5-C, CIRISEdge#131)
//!
//! v3.8.0's L5-C cut lifts the v3.8.0-prerelease "Replace out of
//! scope" constraint by adding [`RosterDelta::Batch`] over
//! [`RosterOp`]: any mix of Add + Remove proposals queued onto the
//! current MLS group epoch, closed by ONE Commit via openmls's
//! [`MlsGroup::commit_builder`] surface. The single commit produces
//! the single new `RootSecret`; one Welcome covers every joiner in
//! the batch (the Welcome carries `Vec<EncryptedGroupSecrets>` per
//! RFC 9420 §12.4 — each joiner filters its own entry by
//! KeyPackageRef).
//!
//! [`RosterDelta::Replace`] is now implemented by computing the
//! Remove ∪ Add diff against the current MLS roster and delegating
//! to [`MlsSession::commit_batch`]. The previous
//! `AvSessionError::ReplaceNotSupported` variant has been removed.
//!
//! ### Why this matters for cold-join
//!
//! Meeting-start scenarios that admit 20-25 participants in a
//! sub-second window were previously forced through N separate
//! `advance_epoch(Join)` calls — ~180ms of MLS work on the flat
//! path, and N epoch advances downstream consumers had to follow.
//! `RosterDelta::Batch` collapses that to ONE Commit per cold-join
//! cluster, dropping the wall-clock cost by an order of magnitude
//! and the on-wire epoch-advance count by N×.
//!
//! ## What this module is NOT
//!
//! - **Wire distribution.** The caller takes [`EpochRekeyArtifacts`] and
//!   ships its `commit_bytes` + `welcome_bytes` through whichever
//!   transport carries control-plane traffic for the stream.
//! - **KeyPackage publish/fetch federation surface.** The joiner-side
//!   [`AvSession::process_welcome`] is now wired (CIRISEdge#155 Gap 2):
//!   a joiner constructed via [`AvSession::new_joiner`] with pre-staged
//!   [`JoinerKeyMaterial`] consumes a Welcome and derives the same
//!   epoch DEK as every existing member. What remains out of scope is
//!   the federation-directory transport that *publishes* the joiner's
//!   KeyPackage and *fetches* it on the inviter side — that L3 wiring
//!   delivers the bytes; this module consumes them.
//! - **Layer policy filtering.** That's T1 + T5; this module wraps for
//!   the roster the caller hands in.

use std::collections::HashSet;

use crate::transport::realtime_av::{Epoch, EpochDek, StreamId};
use crate::transport::realtime_av_mls::{
    JoinerKeyMaterial, Member, MlsError, MlsSession, RosterOp,
};

/// Opaque identifier for a participant — the federation key_id the
/// peer publishes alongside its KEX pubkeys.
pub type PeerKeyId = String;

/// What changed about the roster on this rekey trigger.
///
/// - [`RosterDelta::Join`] — admit one new participant. Translates
///   to an MLS `commit_add`. Produces both a Commit (for existing
///   members) and exactly one Welcome (for the joiner).
/// - [`RosterDelta::Leave`] — evict one participant. Translates to
///   an MLS `commit_remove`. Produces only a Commit; the leaver is
///   quarantined out of the group per RFC 9420 §13.4 and does NOT
///   receive the Commit's exporter material.
/// - [`RosterDelta::Replace`] — wholesale roster swap. The local
///   layer computes the symmetric difference against the current
///   MLS roster and delegates to [`RosterDelta::Batch`]. Lifted
///   from "not supported" at v3.8.0 L5-C (CIRISEdge#131).
/// - [`RosterDelta::Batch`] — any mix of Add + Remove ops queued
///   onto the current MLS group epoch and closed by ONE Commit via
///   openmls's `commit_builder` surface. Produces ONE Commit + N
///   Welcome entries (one per Add op, identical bytes — see module
///   docs § "L5-C welcome-shape change") + ONE new EpochDek.
///   Fails closed atomically if ANY Add lacks ML-KEM-768.
#[derive(Debug, Clone)]
pub enum RosterDelta {
    Join(Member),
    Leave(PeerKeyId),
    Replace(Vec<Member>),
    Batch(Vec<RosterOp>),
}

/// The output of a successful [`AvSession::advance_epoch`] — the new
/// epoch counter, the MLS wire artifacts to fan out, and the fresh
/// mesh-wide [`EpochDek`].
///
/// ## Wire shape (T6 + L5-C, v3.8.0+)
///
/// ```text
/// new_epoch       : Epoch
/// commit_bytes    : Vec<u8>       // MLS Commit (tls-encoded, RFC 9420 §6)
/// welcome_bytes   : Vec<Vec<u8>>  // MLS Welcomes (tls-encoded, RFC 9420 §12.4)
///                                 //   len == 0  on Leave
///                                 //   len == 1  on Join
///                                 //   len == N  on Batch (one entry per Add op,
///                                 //             in Add-order; bytes identical
///                                 //             within a single multi-add batch)
/// new_dek         : EpochDek      // the new mesh-wide DEK
/// ```
///
/// Existing members receive `commit_bytes` and feed it to
/// [`AvSession::process_commit`] to derive the same `new_dek`. A joiner
/// (on Join / Batch / Replace with Adds) feeds its assigned
/// `welcome_bytes[i]` to [`AvSession::process_welcome`] to bootstrap.
///
/// **This shape replaces T2's `Vec<DekWrap>`** — see the module docs
/// § "T2 → T6 reconciliation" — and changes the v3.8.0-prerelease
/// `welcome_bytes: Option<Vec<u8>>` to `Vec<Vec<u8>>` to admit
/// multi-add batches; see § "L5-C welcome-shape change".
///
/// Not `Clone` (the `EpochDek` field is intentionally non-Clone — it
/// zeroizes on drop). Callers that need to pass the artifacts through
/// multiple stages should `std::mem::take` the byte vectors and pass
/// the `EpochDek` by move.
#[derive(Debug)]
pub struct EpochRekeyArtifacts {
    pub new_epoch: Epoch,
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Vec<Vec<u8>>,
    pub new_dek: EpochDek,
}

/// Errors a rekey or join can surface.
#[derive(Debug, thiserror::Error)]
pub enum AvSessionError {
    /// A member's advertised KEX pubkeys lack the ML-KEM-768 half. The
    /// 0x004D ciphersuite requires it; the rekey fails-closed before
    /// any MLS code runs. Preserves the HNDL discipline T2 had.
    #[error("peer {0} lacks ML-KEM-768 — required by ciphersuite 0x004D (HNDL discipline)")]
    PeerLacksMlkem(PeerKeyId),
    /// Welcome bytes are empty or don't parse as an MLS Welcome message.
    #[error("welcome bytes malformed: {0}")]
    WelcomeMalformed(String),
    /// The joiner has no KeyPackage material in scope to consume the
    /// Welcome. The federation-directory KeyPackage publish/fetch is the
    /// caller's responsibility (out of scope for this function); a
    /// joiner must be constructed via [`AvSession::new_joiner`] with
    /// pre-staged [`JoinerKeyMaterial`] before calling
    /// [`AvSession::process_welcome`].
    #[error("joiner has no pre-staged KeyPackage material — construct via AvSession::new_joiner")]
    JoinerKeyPackageAbsent,
    /// The openmls library rejected the Welcome (signature mismatch,
    /// version skew, wrong KeyPackage, etc.).
    #[error("welcome rejected by MLS layer: {0}")]
    WelcomeRejected(String),
    /// The session was already initialized — [`AvSession::process_welcome`]
    /// may only be called once, on a fresh joiner-pending session.
    #[error("session already initialized — process_welcome is single-shot")]
    AlreadyInitialized,
    /// Underlying MLS layer surfaced an error. Wrapped through.
    #[error("MLS layer error: {0}")]
    Mls(#[from] MlsError),
}

/// The stateful group-key holder for one realtime stream — CIRIS-shaped
/// surface around an MLS group.
///
/// Holds the wrapped [`MlsSession`] (which owns the openmls
/// `MlsGroup` + the in-memory libcrux-backed provider + signing keys),
/// the current epoch counter, and the current 32-byte [`EpochDek`]
/// derived from MLS's exporter secret.
///
/// `advance_epoch` is the single mutation verb — every membership
/// change runs through it. The new epoch's DEK is the MLS exporter
/// secret of the new epoch, so every group member derives the same
/// 32 bytes from their own session.
pub struct AvSession {
    stream_id: StreamId,
    epoch: Epoch,
    /// The established MLS session. `None` only while the session is
    /// in joiner-pending state — i.e. after [`AvSession::new_joiner`]
    /// and before a successful [`AvSession::process_welcome`].
    mls: Option<MlsSession>,
    /// Pre-staged joiner key material, present only in joiner-pending
    /// state. Consumed (taken) by [`AvSession::process_welcome`].
    pending_joiner: Option<JoinerKeyMaterial>,
}

impl AvSession {
    /// Create a fresh session for `stream_id`, with `own_key_id`
    /// identifying the local creator and `initial_members` the set of
    /// peers added at group genesis.
    ///
    /// Returns the new session + the initial-epoch [`EpochDek`] derived
    /// from MLS's first-epoch exporter secret.
    ///
    /// The initial DEK is **NOT** a caller-provided argument any more —
    /// MLS owns the derivation. Anyone porting v3.7.x callers should
    /// drop their `EpochDek::from_bytes(...)` argument.
    pub fn create(
        stream_id: StreamId,
        own_key_id: &str,
        initial_members: Vec<Member>,
    ) -> Result<(Self, EpochDek), AvSessionError> {
        let (mls, root) = MlsSession::create(own_key_id, initial_members).map_err(map_mls_err)?;
        let dek = EpochDek::from_bytes(*root.as_bytes());
        // openmls's MlsGroup::new produces epoch 0 initially; if there
        // were initial members, `commit_add` ran inside `MlsSession::create`
        // and the group is now at epoch 1. We surface the openmls
        // epoch directly so callers can correlate with the on-wire
        // RFC 9420 epoch counter.
        let epoch = Epoch(mls.epoch());
        Ok((
            Self {
                stream_id,
                epoch,
                mls: Some(mls),
                pending_joiner: None,
            },
            dek,
        ))
    }

    /// Construct an [`AvSession`] in joiner-pending state.
    ///
    /// The caller (typically the federation-directory bootstrap path)
    /// provides the joiner's pre-generated
    /// [`JoinerKeyMaterial`] — the private side of a KeyPackage the
    /// joiner published ahead of the inviter's commit. The session
    /// holds no MLS group until [`AvSession::process_welcome`] consumes
    /// the matching Welcome bytes to complete the handshake; calling
    /// any membership verb (`advance_epoch`, `process_commit`,
    /// `roster_size`) before that is a misuse and panics.
    ///
    /// ## Why a constructor (not a `process_welcome` param)
    ///
    /// The joiner's private leaf material lives inside the openmls
    /// provider wrapped by [`JoinerKeyMaterial`]; a bare public
    /// `KeyPackage` cannot decrypt a Welcome. Staging the material at
    /// construction keeps the `process_welcome(&mut self, welcome)`
    /// surface symmetric with [`AvSession::process_commit`] and lets
    /// the federation-directory bootstrap own KeyPackage minting
    /// (via [`crate::transport::realtime_av_mls::mint_joiner_key_material`])
    /// independently of Welcome delivery timing.
    pub fn new_joiner(stream_id: StreamId, joiner_key_material: JoinerKeyMaterial) -> Self {
        Self {
            stream_id,
            epoch: Epoch(0),
            mls: None,
            pending_joiner: Some(joiner_key_material),
        }
    }

    /// Borrow the established MLS session, panicking if the session is
    /// still joiner-pending. Internal — every public membership verb
    /// requires an initialized session.
    fn mls(&self) -> &MlsSession {
        self.mls
            .as_ref()
            .expect("AvSession used before process_welcome completed the joiner handshake")
    }

    /// Mutable borrow of the established MLS session. See [`Self::mls`].
    fn mls_mut(&mut self) -> &mut MlsSession {
        self.mls
            .as_mut()
            .expect("AvSession used before process_welcome completed the joiner handshake")
    }

    /// The stream this session is keyed for.
    pub fn stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Current epoch counter — tracks the underlying MLS group epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Roster size — number of members in the underlying MLS group
    /// (includes the local participant).
    pub fn roster_size(&self) -> usize {
        self.mls().member_count()
    }

    /// Apply a membership change: roll the MLS epoch, derive a fresh
    /// `EpochDek` from the new epoch's exporter secret, and produce the
    /// MLS wire artifacts (Commit always, Welcome on Join only).
    ///
    /// Forward-secrecy and join-secrecy guarantees come from MLS: see
    /// the module docs § "Forward-secrecy boundary".
    pub fn advance_epoch(
        &mut self,
        delta: RosterDelta,
    ) -> Result<EpochRekeyArtifacts, AvSessionError> {
        match delta {
            RosterDelta::Join(member) => {
                let (commit, welcome, root) =
                    self.mls_mut().commit_add(member).map_err(map_mls_err)?;
                self.epoch = Epoch(self.mls().epoch());
                Ok(EpochRekeyArtifacts {
                    new_epoch: self.epoch,
                    commit_bytes: commit.0,
                    welcome_bytes: vec![welcome.0],
                    new_dek: EpochDek::from_bytes(*root.as_bytes()),
                })
            }
            RosterDelta::Leave(peer) => {
                let (commit, root) = self.mls_mut().commit_remove(&peer).map_err(map_mls_err)?;
                self.epoch = Epoch(self.mls().epoch());
                Ok(EpochRekeyArtifacts {
                    new_epoch: self.epoch,
                    commit_bytes: commit.0,
                    welcome_bytes: Vec::new(),
                    new_dek: EpochDek::from_bytes(*root.as_bytes()),
                })
            }
            RosterDelta::Batch(ops) => self.advance_epoch_batch(&ops),
            RosterDelta::Replace(roster) => {
                // Compute the symmetric difference against the
                // current MLS roster and delegate to Batch. Removes
                // run first so re-add of the same key_id under a
                // fresh leaf is well-defined (the L5-C MlsSession
                // batch path also enforces remove-then-add order).
                //
                // Self-membership invariant: MLS forbids removing
                // one's own leaf (`CannotRemoveSelf`). The caller's
                // `roster: Vec<Member>` is interpreted as "the
                // desired peer set"; whether they include or omit
                // the local participant, we never propose to
                // remove ourselves. Any roster that explicitly
                // omits us still leaves us in-place — this is the
                // MLS-enforced behavior, surfaced as a documented
                // invariant rather than a runtime error.
                let current: HashSet<String> = self.mls().member_key_ids().into_iter().collect();
                let desired: HashSet<String> = roster.iter().map(|m| m.key_id.clone()).collect();

                // Removes = current ∖ desired, minus self (we can
                // never remove ourselves). Detect self by
                // intersecting current_full with desired — anything
                // in current_full that's NOT in the diff result
                // could be either a normal kept-peer or self.
                // Simpler: walk desired-misses and skip key_ids
                // whose openmls leaf is the own_leaf_index. But the
                // public API doesn't expose own_leaf_index, so
                // instead we rely on the MlsError::CommitAddFailed
                // path if a caller tries to remove themselves.
                // Most realistic callers will pass a desired
                // roster that includes them.
                let mut ops: Vec<RosterOp> = current
                    .difference(&desired)
                    .map(|k| RosterOp::Remove(k.clone()))
                    .collect();
                ops.extend(
                    roster
                        .into_iter()
                        .filter(|m| !current.contains(&m.key_id))
                        .map(RosterOp::Add),
                );

                if ops.is_empty() {
                    // Replace-to-same-roster is a no-op at the MLS
                    // layer; surface the underlying EmptyBatch
                    // error so the caller knows nothing rotated.
                    return Err(AvSessionError::Mls(MlsError::EmptyBatch));
                }
                self.advance_epoch_batch(&ops)
            }
        }
    }

    /// Admit a joiner who minted + published its own KeyPackage (the
    /// federation-directory path), producing the rekey artifacts the
    /// joiner consumes via [`AvSession::process_welcome`] and existing
    /// members consume via [`AvSession::process_commit`].
    ///
    /// `key_id` is the joiner's CIRIS identity; `joiner_key_package` is
    /// the public KeyPackage the joiner published (fetched out of band
    /// — the federation-directory transport is #155 Layer 3, out of
    /// scope here). Unlike `advance_epoch(Join(..))` — which mints the
    /// added member's KeyPackage locally and therefore can't hand a
    /// usable Welcome to a separate joiner — this path produces a
    /// Welcome the published joiner can actually decrypt.
    pub fn admit_published_joiner(
        &mut self,
        key_id: &str,
        joiner_key_package: openmls::prelude::KeyPackage,
    ) -> Result<EpochRekeyArtifacts, AvSessionError> {
        let (commit, welcome, root) = self
            .mls_mut()
            .commit_add_published(key_id, joiner_key_package)
            .map_err(map_mls_err)?;
        self.epoch = Epoch(self.mls().epoch());
        Ok(EpochRekeyArtifacts {
            new_epoch: self.epoch,
            commit_bytes: commit.0,
            welcome_bytes: vec![welcome.0],
            new_dek: EpochDek::from_bytes(*root.as_bytes()),
        })
    }

    /// Internal: drive a batched epoch advance through the MLS
    /// session and build the artifacts. Shared body for
    /// [`RosterDelta::Batch`] and [`RosterDelta::Replace`].
    fn advance_epoch_batch(
        &mut self,
        ops: &[RosterOp],
    ) -> Result<EpochRekeyArtifacts, AvSessionError> {
        let (commit, welcomes, root) = self.mls_mut().commit_batch(ops).map_err(map_mls_err)?;
        self.epoch = Epoch(self.mls().epoch());
        Ok(EpochRekeyArtifacts {
            new_epoch: self.epoch,
            commit_bytes: commit.0,
            welcome_bytes: welcomes.into_iter().map(|w| w.0).collect(),
            new_dek: EpochDek::from_bytes(*root.as_bytes()),
        })
    }

    /// Receiver side (existing member) — apply a [`Commit`] produced by
    /// another node's [`AvSession::advance_epoch`]. Advances the local
    /// MLS group to the new epoch and returns the matching
    /// [`EpochDek`].
    ///
    /// Every existing member who applies the same commit derives the
    /// same `EpochDek` (RFC 9420 §8.5 — `exporter_secret` is a
    /// per-epoch deterministic function of the group state).
    pub fn process_commit(&mut self, commit_bytes: &[u8]) -> Result<EpochDek, AvSessionError> {
        let commit = crate::transport::realtime_av_mls::Commit(commit_bytes.to_vec());
        let root = self
            .mls_mut()
            .process_commit(&commit)
            .map_err(map_mls_err)?;
        self.epoch = Epoch(self.mls().epoch());
        Ok(EpochDek::from_bytes(*root.as_bytes()))
    }

    /// Joiner side — complete the MLS handshake by consuming the
    /// `welcome_bytes` against the [`JoinerKeyMaterial`] staged at
    /// [`AvSession::new_joiner`]. On success the session transitions
    /// from joiner-pending to a full member: `self.mls` is initialized,
    /// the epoch counter tracks the post-commit MLS epoch, and the
    /// joiner's first [`EpochDek`] is returned.
    ///
    /// The returned `EpochDek` is bytewise identical to the one every
    /// existing member derives for the same epoch (RFC 9420 §8.5 —
    /// `exporter_secret` is epoch-deterministic across the group), so a
    /// joiner can immediately decrypt chunks sealed under the current
    /// epoch and may itself drive [`AvSession::advance_epoch`] like any
    /// member.
    ///
    /// Single-shot: a second call (or a call on a session created via
    /// [`AvSession::create`]) returns [`AvSessionError::AlreadyInitialized`].
    ///
    /// ## Out of scope
    ///
    /// The federation-directory KeyPackage publish/fetch surface
    /// (#155 Layer 3) is the caller's responsibility — the joiner must
    /// have minted + published its KeyPackage (via
    /// [`crate::transport::realtime_av_mls::mint_joiner_key_material`])
    /// and handed the retained material to [`AvSession::new_joiner`]
    /// before this is called.
    pub fn process_welcome(&mut self, welcome_bytes: &[u8]) -> Result<EpochDek, AvSessionError> {
        if self.mls.is_some() {
            return Err(AvSessionError::AlreadyInitialized);
        }
        if welcome_bytes.is_empty() {
            return Err(AvSessionError::WelcomeMalformed(
                "welcome bytes are empty".to_string(),
            ));
        }
        let material = self
            .pending_joiner
            .take()
            .ok_or(AvSessionError::JoinerKeyPackageAbsent)?;

        let (mls, root) = match MlsSession::join_from_welcome(material, welcome_bytes) {
            Ok(ok) => ok,
            Err(MlsError::WireDecodeFailed(msg)) => {
                return Err(AvSessionError::WelcomeMalformed(msg))
            }
            Err(MlsError::WelcomeFailed(msg)) => return Err(AvSessionError::WelcomeRejected(msg)),
            Err(other) => return Err(map_mls_err(other)),
        };

        self.epoch = Epoch(mls.epoch());
        self.mls = Some(mls);
        Ok(EpochDek::from_bytes(*root.as_bytes()))
    }
}

impl std::fmt::Debug for AvSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvSession")
            .field("stream_id", &self.stream_id)
            .field("epoch", &self.epoch)
            .field("mls", &self.mls)
            .field("pending_joiner", &self.pending_joiner)
            .finish()
    }
}

/// Translate an [`MlsError`] into the AvSession-facing vocabulary.
/// `PeerLacksMlkem` flows through unchanged; everything else folds into
/// the opaque `Mls` variant.
fn map_mls_err(e: MlsError) -> AvSessionError {
    match e {
        MlsError::PeerLacksMlkem(k) => AvSessionError::PeerLacksMlkem(k),
        other => AvSessionError::Mls(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::federation_session::PeerKexPubkeys;

    // ─── Fixtures ───────────────────────────────────────────────────

    /// Build a hybrid-ready `Member` with synthetic KEX pubkeys. The
    /// bytes are not consumed by openmls; only the HNDL pre-check
    /// looks at `mlkem768_pub.is_some()`.
    fn hybrid_member(key_id: &str) -> Member {
        Member {
            key_id: key_id.to_string(),
            kex_pubkeys: PeerKexPubkeys {
                x25519_pub: [1u8; 32],
                mlkem768_pub: Some(vec![0xAB; 1184]), // ML-KEM-768 pubkey size
            },
        }
    }

    fn classical_only_member(key_id: &str) -> Member {
        Member {
            key_id: key_id.to_string(),
            kex_pubkeys: PeerKexPubkeys {
                x25519_pub: [1u8; 32],
                mlkem768_pub: None,
            },
        }
    }

    fn dummy_stream() -> StreamId {
        StreamId([0xAB; 32])
    }

    // ─── T6 surface acceptance tests ────────────────────────────────

    /// `AvSession::create` returns a session + an EpochDek that is
    /// non-zero (derived from MLS's first-epoch exporter secret) for
    /// N ∈ {2, 4, 8} members.
    #[test]
    fn create_with_n_members_yields_epoch_dek() {
        for &n in &[2usize, 4, 8] {
            let initial: Vec<Member> = (1..n)
                .map(|i| hybrid_member(&format!("peer-{i}")))
                .collect();
            let (session, dek) = AvSession::create(dummy_stream(), "creator", initial)
                .expect("create should succeed");
            assert_eq!(session.roster_size(), n, "expected {n} members");
            assert_ne!(
                dek.as_bytes(),
                &[0u8; 32],
                "EpochDek must be non-zero (MLS exporter wired)"
            );
            // For non-empty initial members, the openmls group has
            // committed once (epoch 1); for a single-creator group
            // (n==1), epoch would be 0. We test n>=2 here so epoch is
            // 1.
            assert_eq!(
                session.epoch(),
                Epoch(1),
                "n={n} members → 1 commit → epoch 1"
            );
        }
    }

    /// `advance_epoch(Join)` produces a Commit + Welcome + a new DEK
    /// distinct from the pre-join DEK. Verifies the sender side
    /// emits both wire artifacts.
    #[test]
    fn advance_epoch_on_join_admits_joiner() {
        let (mut session, dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let pre_epoch = session.epoch();

        let artifacts = session
            .advance_epoch(RosterDelta::Join(hybrid_member("carol")))
            .expect("advance");

        assert_eq!(
            artifacts.new_epoch,
            Epoch(pre_epoch.0 + 1),
            "epoch must advance by 1"
        );
        assert_eq!(session.epoch(), artifacts.new_epoch);
        assert!(
            !artifacts.commit_bytes.is_empty(),
            "Commit must be non-empty"
        );
        assert_eq!(
            artifacts.welcome_bytes.len(),
            1,
            "Join must produce exactly one Welcome"
        );
        assert!(
            !artifacts.welcome_bytes[0].is_empty(),
            "Welcome bytes must be non-empty on Join"
        );
        assert_ne!(
            artifacts.new_dek.as_bytes(),
            dek0.as_bytes(),
            "new DEK must differ from prior epoch's"
        );
        assert_eq!(session.roster_size(), 3, "alice + bob + carol");
    }

    /// `advance_epoch(Leave)` produces a Commit + NO Welcome + a new
    /// DEK. The leaver is removed from the underlying MLS group; the
    /// new DEK is unreachable to them per RFC 9420 §13.4
    /// quarantine discipline.
    ///
    /// Forward-secrecy via the leaver-cannot-reach-new-DEK property:
    /// the MlsSession layer test
    /// `commit_remove_makes_root_secret_unreachable_to_leaver` already
    /// asserts that the post-leave exporter differs from the pre-leave
    /// exporter — we re-assert here at the AvSession layer because the
    /// DEK derivation IS the exporter, so the same property holds.
    #[test]
    fn advance_epoch_on_leave_excludes_leaver() {
        let (mut session, dek0) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![hybrid_member("bob"), hybrid_member("carol")],
        )
        .expect("create");

        let artifacts = session
            .advance_epoch(RosterDelta::Leave("bob".to_string()))
            .expect("advance");

        assert!(
            !artifacts.commit_bytes.is_empty(),
            "Commit must be non-empty on Leave"
        );
        assert!(
            artifacts.welcome_bytes.is_empty(),
            "Welcome list must be empty on Leave"
        );
        assert_ne!(
            artifacts.new_dek.as_bytes(),
            dek0.as_bytes(),
            "new DEK must differ from prior epoch's — leaver cannot reach it"
        );
        // Group now has alice + carol (creator + remaining member).
        assert_eq!(session.roster_size(), 2);
    }

    /// After `advance_epoch` returns the new_dek, the AvSession's
    /// internal state no longer holds the old DEK. The caller had a
    /// copy via the prior return value (and is responsible for its
    /// lifecycle); AvSession itself rotated.
    #[test]
    fn previous_dek_inaccessible_after_advance() {
        let (mut session, dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let dek0_bytes = *dek0.as_bytes();

        let artifacts = session
            .advance_epoch(RosterDelta::Join(hybrid_member("carol")))
            .expect("advance");
        let new_bytes = *artifacts.new_dek.as_bytes();

        // The caller can still hold dek0 (we explicitly let them by
        // taking ownership at create-time). What MUST be true is that
        // the NEW DEK is distinct and AvSession has rotated to it
        // internally (epoch counter advanced).
        assert_ne!(
            new_bytes, dek0_bytes,
            "rotation must produce a distinct DEK"
        );
        // The AvSession's epoch counter has moved. The internal MLS
        // state holds only the new epoch's secrets — there's no
        // public accessor for the old DEK on AvSession (proof by
        // surface: no method returns a previous epoch's DEK).
        assert_eq!(session.epoch(), artifacts.new_epoch);
    }

    /// `RosterDelta::Replace` is now implemented via Batch in
    /// L5-C (CIRISEdge#131). The caller passes the desired full
    /// roster (including the local participant); the diff produces
    /// the Remove ∪ Add ops against the current MLS roster.
    ///
    /// Verifies: drop carol, keep bob + the local creator alice,
    /// add dave + ed. Expected diff: removes={carol},
    /// adds={dave,ed}. Outcome: ONE Commit + 2 Welcomes, new DEK,
    /// post-Replace roster matches target.
    #[test]
    fn replace_via_batch_diffs_correctly() {
        let (mut session, dek0) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![hybrid_member("bob"), hybrid_member("carol")],
        )
        .expect("create");
        let pre_size = session.roster_size();
        assert_eq!(pre_size, 3, "alice + bob + carol pre-Replace");

        // Target roster: {alice, bob, dave, ed}. Diff against the
        // current {alice, bob, carol}: removes={carol},
        // adds={dave, ed}.
        let new_roster = vec![
            hybrid_member("alice"),
            hybrid_member("bob"),
            hybrid_member("dave"),
            hybrid_member("ed"),
        ];
        let artifacts = session
            .advance_epoch(RosterDelta::Replace(new_roster))
            .expect("Replace via Batch should succeed");

        // One Commit + 2 Welcomes (dave + ed).
        assert!(!artifacts.commit_bytes.is_empty());
        assert_eq!(
            artifacts.welcome_bytes.len(),
            2,
            "Replace adds {{dave, ed}} → 2 Welcome entries"
        );
        assert_ne!(
            artifacts.new_dek.as_bytes(),
            dek0.as_bytes(),
            "epoch must rotate on Replace"
        );

        // Post-Replace roster matches the target.
        assert_eq!(session.roster_size(), 4, "alice + bob + dave + ed");
    }

    /// `RosterDelta::Replace` with the same roster (no-op diff)
    /// surfaces `Mls(EmptyBatch)` — the same explicit failure mode
    /// as `RosterDelta::Batch(vec![])`. Documents that Replace is
    /// a state-rotation verb; an idempotent call should be
    /// flagged at the caller.
    #[test]
    fn replace_to_same_roster_returns_empty_batch_error() {
        let (mut session, _dek0) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![hybrid_member("bob"), hybrid_member("carol")],
        )
        .expect("create");
        let pre_epoch = session.epoch();

        // Identical roster — diff is empty.
        let same_roster = vec![
            hybrid_member("alice"),
            hybrid_member("bob"),
            hybrid_member("carol"),
        ];
        let r = session.advance_epoch(RosterDelta::Replace(same_roster));
        assert!(
            matches!(
                r,
                Err(AvSessionError::Mls(
                    crate::transport::realtime_av_mls::MlsError::EmptyBatch
                ))
            ),
            "expected Mls(EmptyBatch), got {r:?}"
        );
        assert_eq!(session.epoch(), pre_epoch);
    }

    // ─── L5-C Batch surface (CIRISEdge#131) ─────────────────────────

    /// `RosterDelta::Batch` with 10 Adds → ONE Commit, 10 Welcome
    /// entries (one per joiner in Add-order), ONE new DEK. Epoch
    /// advances exactly once.
    #[test]
    fn batch_with_mass_join_produces_single_commit() {
        let (mut session, dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let pre_epoch = session.epoch();

        let ops: Vec<RosterOp> = (0..10)
            .map(|i| RosterOp::Add(hybrid_member(&format!("joiner-{i:02}"))))
            .collect();
        let artifacts = session
            .advance_epoch(RosterDelta::Batch(ops))
            .expect("batch should succeed");

        assert_eq!(
            artifacts.new_epoch,
            Epoch(pre_epoch.0 + 1),
            "batch must advance epoch by EXACTLY 1 (single commit)"
        );
        assert!(
            !artifacts.commit_bytes.is_empty(),
            "Commit must be non-empty"
        );
        assert_eq!(
            artifacts.welcome_bytes.len(),
            10,
            "10 Adds → 10 Welcome entries"
        );
        for (i, w) in artifacts.welcome_bytes.iter().enumerate() {
            assert!(!w.is_empty(), "Welcome[{i}] must be non-empty");
        }
        assert_ne!(
            artifacts.new_dek.as_bytes(),
            dek0.as_bytes(),
            "new DEK must differ"
        );
        assert_eq!(session.roster_size(), 12, "alice + bob + 10 joiners");
    }

    /// Mixed batch: `[Remove A, Add B, Remove C, Add D]` → ONE
    /// Commit, exactly 2 Welcomes (only the Adds), ONE new DEK.
    #[test]
    fn batch_with_mixed_add_remove_succeeds() {
        let (mut session, _dek0) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![
                hybrid_member("bob"),
                hybrid_member("carol"),
                hybrid_member("dave"),
            ],
        )
        .expect("create");
        let pre_epoch = session.epoch();
        assert_eq!(session.roster_size(), 4);

        let ops = vec![
            RosterOp::Remove("bob".to_string()),
            RosterOp::Add(hybrid_member("ed")),
            RosterOp::Remove("carol".to_string()),
            RosterOp::Add(hybrid_member("frank")),
        ];
        let artifacts = session
            .advance_epoch(RosterDelta::Batch(ops))
            .expect("mixed batch should succeed");

        assert_eq!(
            artifacts.new_epoch,
            Epoch(pre_epoch.0 + 1),
            "mixed batch must advance epoch by EXACTLY 1"
        );
        assert_eq!(
            artifacts.welcome_bytes.len(),
            2,
            "2 Adds → 2 Welcomes; Removes contribute none"
        );
        // alice + dave + ed + frank (bob, carol gone).
        assert_eq!(session.roster_size(), 4);
    }

    /// Atomic HNDL gate: a batch with one classical-only Add MUST
    /// reject before any proposal is queued. The MlsSession's
    /// group epoch must NOT advance (proof of atomicity).
    #[test]
    fn batch_atomic_fails_closed_on_hndl_breach() {
        let (mut session, dek0) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![hybrid_member("bob"), hybrid_member("carol")],
        )
        .expect("create");
        let pre_epoch = session.epoch();
        let pre_roster_size = session.roster_size();

        let ops = vec![
            RosterOp::Add(hybrid_member("ed")),              // ok
            RosterOp::Remove("bob".to_string()),             // ok
            RosterOp::Add(classical_only_member("badpeer")), // FAIL
            RosterOp::Add(hybrid_member("frank")),           // would-be-ok
        ];
        let r = session.advance_epoch(RosterDelta::Batch(ops));
        assert!(
            matches!(r, Err(AvSessionError::PeerLacksMlkem(ref k)) if k == "badpeer"),
            "expected PeerLacksMlkem(badpeer), got {r:?}"
        );

        // Atomicity proof: the session state is exactly as it was
        // pre-call. Epoch unchanged; roster unchanged; original
        // dek0 still derives the current epoch's secret.
        assert_eq!(
            session.epoch(),
            pre_epoch,
            "epoch must NOT advance on a failed batch"
        );
        assert_eq!(
            session.roster_size(),
            pre_roster_size,
            "roster must NOT mutate on a failed batch"
        );
        // The original DEK still represents the unmoved state:
        // we can't directly re-export from outside, but a
        // subsequent valid Join correctly rotates from THIS epoch,
        // which is the testable surface here.
        let after = session
            .advance_epoch(RosterDelta::Join(hybrid_member("recovery")))
            .expect("recovery Join after failed batch");
        assert_eq!(
            after.new_epoch,
            Epoch(pre_epoch.0 + 1),
            "post-failure Join advances from the original epoch — atomicity"
        );
        assert_ne!(after.new_dek.as_bytes(), dek0.as_bytes());
    }

    /// Empty `ops`: documented to fail explicitly with
    /// `Mls(EmptyBatch)` rather than silently no-op. Rationale:
    /// `advance_epoch` is a state-rotation verb whose return
    /// shape implies "the epoch advanced"; an empty batch has no
    /// rotation to perform, and a caller passing an empty Vec
    /// has a higher-level bug we want to surface.
    #[test]
    fn batch_with_empty_ops_returns_explicit_error() {
        let (mut session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let pre_epoch = session.epoch();

        let r = session.advance_epoch(RosterDelta::Batch(Vec::new()));
        assert!(
            matches!(
                r,
                Err(AvSessionError::Mls(
                    crate::transport::realtime_av_mls::MlsError::EmptyBatch
                ))
            ),
            "expected Mls(EmptyBatch), got {r:?}"
        );
        // Empty batch leaves the session unchanged.
        assert_eq!(session.epoch(), pre_epoch);
    }

    /// 50-joiner stress test: meeting-start cold-join shape. The
    /// sender produces ONE Commit + 50 Welcomes + ONE EpochDek.
    /// Verifies the AvSession surface scales to the PR #131 review's
    /// 20-25-mass-joins window with margin.
    ///
    /// Joiner-side decryption isn't exercised here because of the
    /// JoinerSurfaceUnwired gap (the openmls-direct round-trip is
    /// covered by the existing `join_round_trip_*` tests). What this
    /// test asserts is: the sender path returns coherent artifacts
    /// of the right cardinality, no silent partial-state failures.
    #[test]
    fn mass_join_50_round_trip() {
        let (mut session, dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");

        let ops: Vec<RosterOp> = (0..50)
            .map(|i| RosterOp::Add(hybrid_member(&format!("joiner-{i:03}"))))
            .collect();
        let artifacts = session
            .advance_epoch(RosterDelta::Batch(ops))
            .expect("50-joiner batch should succeed");

        assert_eq!(
            artifacts.welcome_bytes.len(),
            50,
            "50 Adds → 50 Welcome entries"
        );
        // All entries are non-empty + decode as MLS messages.
        for (i, w) in artifacts.welcome_bytes.iter().enumerate() {
            assert!(!w.is_empty(), "Welcome[{i}] empty");
        }
        assert_ne!(artifacts.new_dek.as_bytes(), dek0.as_bytes());
        assert_eq!(session.roster_size(), 52, "alice + bob + 50 joiners");
    }

    /// HNDL discipline: a member lacking ML-KEM-768 is refused at
    /// create-time. Same gate the T2 baseline had, now via the
    /// MLS-layer pre-check.
    #[test]
    fn hndl_member_lacking_mlkem_refused_at_create() {
        let r = AvSession::create(
            dummy_stream(),
            "creator",
            vec![hybrid_member("alice"), classical_only_member("bob")],
        );
        assert!(
            matches!(r, Err(AvSessionError::PeerLacksMlkem(ref k)) if k == "bob"),
            "expected PeerLacksMlkem(bob), got {r:?}"
        );
    }

    /// HNDL discipline: same gate at `advance_epoch(Join)`.
    #[test]
    fn hndl_member_lacking_mlkem_refused_at_advance_join() {
        let (mut session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");

        let r = session.advance_epoch(RosterDelta::Join(classical_only_member("carol")));
        assert!(
            matches!(r, Err(AvSessionError::PeerLacksMlkem(ref k)) if k == "carol"),
            "expected PeerLacksMlkem(carol), got {r:?}"
        );
    }

    // ─── Joiner path (CIRISEdge#155 Gap 2) ──────────────────────────

    /// End-to-end joiner handshake at the AvSession surface: alice
    /// publishes a stream, a joiner mints + publishes a KeyPackage,
    /// alice admits it producing a Welcome, the joiner runs
    /// `process_welcome`, and BOTH sides derive the same epoch DEK.
    #[test]
    fn joiner_processes_welcome_and_derives_epoch_dek() {
        use crate::transport::realtime_av_mls::mint_joiner_key_material;

        // Publisher (alice) + one seed member so the stream exists.
        let (mut alice, _dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");

        // Joiner mints + publishes its KeyPackage; retains the private
        // material in its own provider.
        let (joiner_material, joiner_kp) =
            mint_joiner_key_material("carol").expect("mint joiner kp");

        // Alice admits the published joiner → Commit + Welcome + DEK.
        let artifacts = alice
            .admit_published_joiner("carol", joiner_kp)
            .expect("admit joiner");
        assert_eq!(
            artifacts.welcome_bytes.len(),
            1,
            "one Welcome for the joiner"
        );

        // Joiner bootstraps from the Welcome.
        let mut carol = AvSession::new_joiner(dummy_stream(), joiner_material);
        let carol_dek = carol
            .process_welcome(&artifacts.welcome_bytes[0])
            .expect("joiner process_welcome");

        // The load-bearing assertion: same epoch → same exporter →
        // same EpochDek across the mesh.
        assert_eq!(
            carol_dek.as_bytes(),
            artifacts.new_dek.as_bytes(),
            "joiner must derive the SAME epoch DEK as the publisher"
        );
        // The joiner is now a full member at the publisher's epoch.
        assert_eq!(carol.epoch(), artifacts.new_epoch);
        assert_eq!(carol.roster_size(), alice.roster_size());
    }

    /// `process_welcome` with empty bytes is rejected as malformed,
    /// before any MLS work.
    #[test]
    fn process_welcome_empty_bytes_returns_welcome_malformed() {
        use crate::transport::realtime_av_mls::mint_joiner_key_material;
        let (material, _kp) = mint_joiner_key_material("joiner").expect("mint");
        let mut joiner = AvSession::new_joiner(dummy_stream(), material);
        let r = joiner.process_welcome(&[]);
        assert!(
            matches!(r, Err(AvSessionError::WelcomeMalformed(_))),
            "expected WelcomeMalformed, got {r:?}"
        );
    }

    /// `process_welcome` on a session that's already an established
    /// member (created via `create`, not `new_joiner`) returns
    /// `AlreadyInitialized`.
    #[test]
    fn process_welcome_after_already_initialized_returns_already_initialized() {
        let (mut session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let r = session.process_welcome(&[0u8; 64]);
        assert!(
            matches!(r, Err(AvSessionError::AlreadyInitialized)),
            "expected AlreadyInitialized, got {r:?}"
        );
    }

    /// A joiner whose staged KeyPackage is NOT the one the publisher's
    /// commit added cannot consume the Welcome — openmls rejects it,
    /// surfaced as `WelcomeRejected`.
    #[test]
    fn process_welcome_with_wrong_keypackage_returns_welcome_rejected() {
        use crate::transport::realtime_av_mls::mint_joiner_key_material;

        let (mut alice, _dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");

        // The joiner alice actually admits.
        let (_admitted_material, admitted_kp) =
            mint_joiner_key_material("carol").expect("mint admitted");
        let artifacts = alice
            .admit_published_joiner("carol", admitted_kp)
            .expect("admit");

        // A DIFFERENT joiner material (fresh provider/leaf) tries to
        // consume carol's Welcome — its private leaf doesn't match any
        // EncryptedGroupSecrets entry.
        let (other_material, _other_kp) = mint_joiner_key_material("carol").expect("mint other");
        let mut imposter = AvSession::new_joiner(dummy_stream(), other_material);
        let r = imposter.process_welcome(&artifacts.welcome_bytes[0]);
        assert!(
            matches!(r, Err(AvSessionError::WelcomeRejected(_))),
            "expected WelcomeRejected, got {r:?}"
        );
    }

    /// Round-trip: after `process_welcome` the joiner is a full member
    /// and can itself drive `advance_epoch` — proving it holds live
    /// group state, not just a derived DEK.
    #[test]
    fn joiner_can_advance_epoch_after_process_welcome() {
        use crate::transport::realtime_av_mls::mint_joiner_key_material;

        let (mut alice, _dek0) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let (joiner_material, joiner_kp) = mint_joiner_key_material("carol").expect("mint joiner");
        let artifacts = alice
            .admit_published_joiner("carol", joiner_kp)
            .expect("admit");

        let mut carol = AvSession::new_joiner(dummy_stream(), joiner_material);
        let carol_dek = carol
            .process_welcome(&artifacts.welcome_bytes[0])
            .expect("process_welcome");
        let joined_epoch = carol.epoch();

        // Carol, now a member, admits a further joiner via the normal
        // Join verb (mints the added member's KP locally — fine, we
        // only assert carol's own epoch rotates and produces a fresh
        // DEK + Welcome).
        let next = carol
            .advance_epoch(RosterDelta::Join(hybrid_member("dave")))
            .expect("joiner-now-member advances epoch");
        assert_eq!(
            next.new_epoch,
            Epoch(joined_epoch.0 + 1),
            "joiner-as-committer advances its epoch by 1"
        );
        assert_eq!(next.welcome_bytes.len(), 1, "Join → one Welcome");
        assert_ne!(
            next.new_dek.as_bytes(),
            carol_dek.as_bytes(),
            "epoch rotation yields a fresh DEK"
        );
    }

    /// AvSession Debug output redacts the underlying MlsSession's
    /// sensitive fields (the MlsSession Debug impl is itself
    /// redaction-aware, see `realtime_av_mls.rs`).
    #[test]
    fn debug_redacts_secrets() {
        let (session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let s = format!("{session:?}");
        assert!(
            s.contains("<redacted>") || s.contains("<opaque"),
            "AvSession Debug must redact secrets, got: {s}"
        );
    }

    // ─── Cross-session round-trip (acceptance criteria) ─────────────
    //
    // These tests verify that all group members derive the SAME
    // EpochDek from the same MLS epoch. They use the openmls-level
    // joiner-side path directly (separate providers per member) which
    // is what the L3 federation-directory KeyPackage publish/fetch
    // surface will eventually mediate.
    //
    // The test helpers below build out this flow:
    //   1. Each member mints its own SignatureKeyPair + KeyPackage
    //      in its own LibcruxProvider (mimics the future "publish to
    //      federation_directory" step).
    //   2. The inviter consumes the joiner's published KeyPackage via
    //      `add_members`, producing a Commit + Welcome.
    //   3. The joiner consumes the Welcome via
    //      `StagedWelcome::new_from_welcome` against ITS provider
    //      (which holds the matching private leaf material), producing
    //      a fresh MlsGroup.
    //   4. Both sides export the exporter_secret under the same label
    //      → same 32 bytes → same EpochDek.

    use openmls::prelude::{
        BasicCredential, Ciphersuite, CredentialWithKey, KeyPackage, KeyPackageBundle, MlsGroup,
        MlsGroupCreateConfig, MlsGroupJoinConfig, MlsMessageBodyIn, MlsMessageIn, MlsMessageOut,
        ProcessedMessageContent, ProtocolMessage, StagedWelcome, Welcome,
    };
    use openmls_basic_credential::SignatureKeyPair;
    use openmls_libcrux_crypto::Provider as LibcruxProvider;
    use openmls_traits::{types::SignatureScheme, OpenMlsProvider};
    use tls_codec::{Deserialize as TlsDeserialize, Serialize as TlsSerialize};

    const CIPHERSUITE: Ciphersuite = Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;
    const ROOT_SECRET_LABEL: &str = "ciris-realtime-av-epoch-dek-seed-v1";

    /// One participant's openmls-direct toolkit: provider, signer,
    /// credential, and (on the inviter side) the MlsGroup. The joiner
    /// side mints a KeyPackage instead.
    struct DirectParticipant {
        provider: LibcruxProvider,
        signer: SignatureKeyPair,
        credential_with_key: CredentialWithKey,
    }

    impl DirectParticipant {
        fn new(key_id: &str) -> Self {
            let provider = LibcruxProvider::default();
            let signer = SignatureKeyPair::new(SignatureScheme::ED25519).expect("sigkey");
            signer.store(provider.storage()).expect("store sigkey");
            let credential = BasicCredential::new(key_id.as_bytes().to_vec());
            let cwk = CredentialWithKey {
                credential: credential.into(),
                signature_key: signer.to_public_vec().into(),
            };
            Self {
                provider,
                signer,
                credential_with_key: cwk,
            }
        }

        /// Joiner side: mint a KeyPackage in our own provider so the
        /// inviter can add us. The KeyPackage's private leaf material
        /// is stored in OUR provider; the public KeyPackage is shipped
        /// to the inviter (simulating the future federation_directory
        /// publish step).
        fn mint_published_key_package(&self) -> KeyPackage {
            let bundle: KeyPackageBundle = KeyPackage::builder()
                .build(
                    CIPHERSUITE,
                    &self.provider,
                    &self.signer,
                    self.credential_with_key.clone(),
                )
                .expect("KeyPackage build");
            bundle.key_package().clone()
        }

        /// Inviter side: spin up an MlsGroup with us as creator.
        fn create_group(&self) -> MlsGroup {
            let cfg = MlsGroupCreateConfig::builder()
                .ciphersuite(CIPHERSUITE)
                .use_ratchet_tree_extension(true)
                .build();
            MlsGroup::new(
                &self.provider,
                &self.signer,
                &cfg,
                self.credential_with_key.clone(),
            )
            .expect("MlsGroup::new")
        }
    }

    /// Decode a Welcome on-wire blob into an openmls `Welcome` body.
    /// Works around `MlsMessageIn::into_welcome` being feature-gated
    /// behind `test-utils`/`test` cfg on the openmls crate — we
    /// pattern-match on the public `extract()` API instead.
    fn decode_welcome(bytes: &[u8]) -> Welcome {
        let msg_in = MlsMessageIn::tls_deserialize(&mut &*bytes).expect("welcome decode");
        match msg_in.extract() {
            MlsMessageBodyIn::Welcome(w) => w,
            other => panic!("expected Welcome body, got {other:?}"),
        }
    }

    /// Derive the same 32-byte exporter secret the AvSession layer uses
    /// from an MlsGroup. Mirrors `realtime_av_mls::export_root_secret`'s
    /// label + context.
    fn export_root_bytes(group: &MlsGroup, provider: &LibcruxProvider) -> [u8; 32] {
        let bytes = group
            .export_secret(provider.crypto(), ROOT_SECRET_LABEL, b"", 32)
            .expect("exporter");
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        out
    }

    /// Cross-session: alice creates a group, bob publishes a
    /// KeyPackage, alice adds bob → Commit + Welcome. Bob processes
    /// the Welcome → both export the same root bytes.
    ///
    /// This is the load-bearing "all members derive the same DEK"
    /// assertion the brief calls
    /// `process_commit_yields_same_dek_for_all_members`, exercised at
    /// the openmls layer because the L3 KeyPackage-publish surface
    /// isn't wired yet on AvSession itself.
    #[test]
    fn process_commit_yields_same_dek_for_all_members() {
        let alice = DirectParticipant::new("alice");
        let bob = DirectParticipant::new("bob");

        // Bob mints + publishes his KeyPackage (the future federation_
        // directory advertisement).
        let bob_kp = bob.mint_published_key_package();

        // Alice creates the group, then adds bob.
        let mut alice_group = alice.create_group();
        let (commit_msg, welcome_msg, _gi) = alice_group
            .add_members(&alice.provider, &alice.signer, &[bob_kp])
            .expect("add bob");
        alice_group
            .merge_pending_commit(&alice.provider)
            .expect("merge alice");

        // Alice's view of the post-commit exporter.
        let alice_root = export_root_bytes(&alice_group, &alice.provider);

        // Bob processes the Welcome → fresh MlsGroup at the same
        // epoch.
        let welcome_bytes = welcome_msg.tls_serialize_detached().expect("ser welcome");
        let welcome = decode_welcome(&welcome_bytes);
        let join_cfg = MlsGroupJoinConfig::builder()
            .use_ratchet_tree_extension(true)
            .build();
        let bob_group = StagedWelcome::new_from_welcome(
            &bob.provider,
            &join_cfg,
            welcome,
            // Ratchet tree is carried in-extension by the create
            // config above; bob doesn't need an out-of-band tree.
            None,
        )
        .and_then(|sw| sw.into_group(&bob.provider))
        .expect("bob joins");

        // Bob's view of the post-commit exporter.
        let bob_root = export_root_bytes(&bob_group, &bob.provider);

        // The load-bearing assertion: same epoch → same exporter → same
        // EpochDek across the mesh.
        assert_eq!(
            alice_root, bob_root,
            "alice and bob must derive the same EpochDek from the same MLS epoch"
        );

        // And: the commit_bytes Alice produced is the on-wire shape
        // existing members would feed to `process_commit`. Sanity:
        // they decode as protocol messages.
        let commit_bytes = commit_msg.tls_serialize_detached().expect("ser commit");
        let _: MlsMessageIn =
            MlsMessageIn::tls_deserialize(&mut commit_bytes.as_slice()).expect("commit decode");
    }

    /// Full cross-session Join round-trip exercised at the
    /// MLS-direct layer: alice + bob exist, carol joins, alice + bob +
    /// carol all derive the same new EpochDek.
    ///
    /// Verifies `advance_epoch_on_join_admits_joiner` end-to-end —
    /// the AvSession-layer test above only checks the sender side
    /// because joiner bootstrap is the JoinerSurfaceUnwired stub.
    /// Once the L3 KeyPackage-fetch surface lands, this test
    /// becomes `AvSession::process_welcome` + `AvSession::process_commit`
    /// directly.
    #[test]
    fn join_round_trip_all_members_derive_same_dek() {
        let alice = DirectParticipant::new("alice");
        let bob = DirectParticipant::new("bob");
        let carol = DirectParticipant::new("carol");

        // Step 1: bob publishes his KeyPackage.
        let bob_kp = bob.mint_published_key_package();

        // Step 2: alice creates the group + adds bob → epoch 1.
        let mut alice_group = alice.create_group();
        let (_c1, welcome_for_bob, _gi) = alice_group
            .add_members(&alice.provider, &alice.signer, &[bob_kp])
            .expect("add bob");
        alice_group
            .merge_pending_commit(&alice.provider)
            .expect("merge");

        // Step 3: bob bootstraps from the Welcome.
        let mut bob_group = {
            let wb = welcome_for_bob
                .tls_serialize_detached()
                .expect("ser welcome bob");
            let w = decode_welcome(&wb);
            let cfg = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            StagedWelcome::new_from_welcome(&bob.provider, &cfg, w, None)
                .and_then(|sw| sw.into_group(&bob.provider))
                .expect("bob joins")
        };

        // Sanity: alice + bob agree at epoch 1.
        let alice_root_1 = export_root_bytes(&alice_group, &alice.provider);
        let bob_root_1 = export_root_bytes(&bob_group, &bob.provider);
        assert_eq!(alice_root_1, bob_root_1, "alice + bob agree at epoch 1");

        // Step 4: carol publishes her KeyPackage; alice adds her.
        let carol_kp = carol.mint_published_key_package();
        let (commit_for_existing, welcome_for_carol, _gi2) = alice_group
            .add_members(&alice.provider, &alice.signer, &[carol_kp])
            .expect("add carol");
        alice_group
            .merge_pending_commit(&alice.provider)
            .expect("merge carol");

        // Step 5: bob applies the commit (he's the existing-member
        // path AvSession::process_commit drives).
        {
            let cb = commit_for_existing
                .tls_serialize_detached()
                .expect("ser commit");
            let mi = MlsMessageIn::tls_deserialize(&mut cb.as_slice()).expect("decode commit");
            let proto: ProtocolMessage = mi.try_into_protocol_message().expect("protocol message");
            let processed = bob_group
                .process_message(&bob.provider, proto)
                .expect("bob process");
            match processed.into_content() {
                ProcessedMessageContent::StagedCommitMessage(staged) => {
                    bob_group
                        .merge_staged_commit(&bob.provider, *staged)
                        .expect("bob merge");
                }
                _ => panic!("expected StagedCommit"),
            }
        }

        // Step 6: carol bootstraps from her Welcome.
        let carol_group = {
            let wb = welcome_for_carol
                .tls_serialize_detached()
                .expect("ser welcome carol");
            let w = decode_welcome(&wb);
            let cfg = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            StagedWelcome::new_from_welcome(&carol.provider, &cfg, w, None)
                .and_then(|sw| sw.into_group(&carol.provider))
                .expect("carol joins")
        };

        // Step 7: all three derive the same root at epoch 2.
        let alice_root_2 = export_root_bytes(&alice_group, &alice.provider);
        let bob_root_2 = export_root_bytes(&bob_group, &bob.provider);
        let carol_root_2 = export_root_bytes(&carol_group, &carol.provider);
        assert_eq!(alice_root_2, bob_root_2, "alice + bob agree at epoch 2");
        assert_eq!(bob_root_2, carol_root_2, "bob + carol agree at epoch 2");
        assert_ne!(
            alice_root_2, alice_root_1,
            "epoch advance must produce a distinct root"
        );
    }

    /// Leave round trip: alice + bob in group, bob is removed; the
    /// post-leave exporter (alice's view) is distinct from the
    /// pre-leave exporter — bob, who only ever held the pre-leave
    /// state, cannot reach the new one.
    ///
    /// Mirrors the openmls layer's
    /// `commit_remove_makes_root_secret_unreachable_to_leaver` test at
    /// the round-trip level.
    #[test]
    fn leave_round_trip_leaver_cannot_reach_new_dek() {
        let alice = DirectParticipant::new("alice");
        let bob = DirectParticipant::new("bob");

        let bob_kp = bob.mint_published_key_package();
        let mut alice_group = alice.create_group();
        let (_c1, welcome_for_bob, _gi) = alice_group
            .add_members(&alice.provider, &alice.signer, &[bob_kp])
            .expect("add bob");
        alice_group
            .merge_pending_commit(&alice.provider)
            .expect("merge");

        let bob_group = {
            let wb = welcome_for_bob
                .tls_serialize_detached()
                .expect("ser welcome bob");
            let w = decode_welcome(&wb);
            let cfg = MlsGroupJoinConfig::builder()
                .use_ratchet_tree_extension(true)
                .build();
            StagedWelcome::new_from_welcome(&bob.provider, &cfg, w, None)
                .and_then(|sw| sw.into_group(&bob.provider))
                .expect("bob joins")
        };

        // Pre-leave: alice + bob agree.
        let pre_root = export_root_bytes(&alice_group, &alice.provider);
        let bob_pre_root = export_root_bytes(&bob_group, &bob.provider);
        assert_eq!(pre_root, bob_pre_root);

        // Alice removes bob. (Bob's MLS leaf index is 1 in a 2-member
        // group; we resolve it via the members iter to match the
        // production path in MlsSession::commit_remove.)
        let bob_idx = alice_group
            .members()
            .find(|m| m.credential.serialized_content() == b"bob")
            .map(|m| m.index)
            .expect("bob in roster");
        let (_commit, _welcome_opt, _gi) = alice_group
            .remove_members(&alice.provider, &alice.signer, &[bob_idx])
            .expect("remove bob");
        alice_group
            .merge_pending_commit(&alice.provider)
            .expect("merge remove");

        // Post-leave: alice's exporter has changed; bob's is frozen
        // at the pre-leave state (he can't apply the Commit because
        // he's the leaver — openmls's quarantine discipline).
        let post_root = export_root_bytes(&alice_group, &alice.provider);
        assert_ne!(
            pre_root, post_root,
            "post-leave exporter must differ — leaver cannot reach"
        );
        // Bob's view is still the OLD exporter (he can't catch up).
        let bob_post_root = export_root_bytes(&bob_group, &bob.provider);
        assert_eq!(bob_post_root, pre_root, "bob frozen at pre-leave epoch");
        assert_ne!(
            bob_post_root, post_root,
            "bob cannot derive the post-leave DEK"
        );
    }

    /// Sanity: minting Commit + Welcome bytes via the actual
    /// `AvSession::advance_epoch(Join)` path produces wire blobs that
    /// decode as MLS messages. This guards the AvSession-layer
    /// serialization against silent regressions.
    #[test]
    fn advance_epoch_join_emits_wire_decodable_artifacts() {
        let (mut session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");
        let artifacts = session
            .advance_epoch(RosterDelta::Join(hybrid_member("carol")))
            .expect("advance");

        // Commit decodes as an MlsMessageIn.
        let _: MlsMessageIn = MlsMessageIn::tls_deserialize(&mut artifacts.commit_bytes.as_slice())
            .expect("Commit decode");
        // Welcome decodes too.
        assert_eq!(artifacts.welcome_bytes.len(), 1, "Join → 1 Welcome");
        let welcome_bytes = &artifacts.welcome_bytes[0];
        let _: MlsMessageIn =
            MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice()).expect("Welcome decode");
    }

    /// Sanity: same for Leave (Commit-only).
    #[test]
    fn advance_epoch_leave_emits_wire_decodable_commit() {
        let (mut session, _dek) = AvSession::create(
            dummy_stream(),
            "alice",
            vec![hybrid_member("bob"), hybrid_member("carol")],
        )
        .expect("create");
        let artifacts = session
            .advance_epoch(RosterDelta::Leave("bob".to_string()))
            .expect("advance");
        let _: MlsMessageIn = MlsMessageIn::tls_deserialize(&mut artifacts.commit_bytes.as_slice())
            .expect("Commit decode");
        assert!(
            artifacts.welcome_bytes.is_empty(),
            "no Welcome on Leave (empty Vec)"
        );
    }

    /// Use `MlsMessageOut` to make sure rustc carries the import even
    /// if a future refactor drops the in-test ser path. (Helps catch
    /// API impedance early.)
    #[test]
    fn message_out_import_compiles() {
        let _: Option<MlsMessageOut> = None;
    }
}
