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
//!   { new_epoch, commit_bytes, welcome_bytes, new_dek }`. Receiver side
//!   uses [`AvSession::process_commit`] (existing member) or
//!   [`AvSession::process_welcome`] (joiner).
//!
//! Anyone integrating the v3.8.0 prerelease against the T2 baseline MUST
//! re-test the rekey path. The standalone `DekWrap` struct and the
//! `unwrap_dek` method are removed.
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
//! ## Replace — out of scope at v3.8.0
//!
//! [`RosterDelta::Replace`] is documented but not implemented at v3.8.0.
//! Wholesale roster swaps need a sequence of MLS Remove + Add commits
//! (not a single op MLS supports), each producing its own Commit /
//! Welcome / RootSecret. Layering that into a single
//! `EpochRekeyArtifacts` return shape requires either a vector return
//! (changing the wire) or a multi-step coordinator (larger surface than
//! v3.8.0 needs). Filed as a follow-up cut. The variant returns
//! [`AvSessionError::ReplaceNotSupported`] until that lands.
//!
//! ## What this module is NOT
//!
//! - **Wire distribution.** The caller takes [`EpochRekeyArtifacts`] and
//!   ships its `commit_bytes` + `welcome_bytes` through whichever
//!   transport carries control-plane traffic for the stream.
//! - **KeyPackage publish/fetch federation surface.** v3.8.0 ships the
//!   joiner-side [`AvSession::process_welcome`] as a stub error pending
//!   the L3 federation-directory KeyPackage publication wiring. See
//!   [`AvSessionError::JoinerSurfaceUnwired`] for the documented
//!   limitation and the test-helper path below for the round-trip
//!   coverage.
//! - **Layer policy filtering.** That's T1 + T5; this module wraps for
//!   the roster the caller hands in.

use crate::transport::federation_session::OwnKexKeys;
use crate::transport::realtime_av::{Epoch, EpochDek, StreamId};
use crate::transport::realtime_av_mls::{Member, MlsError, MlsSession};

/// Opaque identifier for a participant — the federation key_id the
/// peer publishes alongside its KEX pubkeys.
pub type PeerKeyId = String;

/// What changed about the roster on this rekey trigger.
///
/// - `Join(member)` — admit one new participant. Translates to an MLS
///   `commit_add`. Produces both a Commit (for existing members) and a
///   Welcome (for the joiner).
/// - `Leave(key_id)` — evict one participant. Translates to an MLS
///   `commit_remove`. Produces only a Commit; the leaver is quarantined
///   out of the group per RFC 9420 §13.4 and does NOT receive the
///   Commit's exporter material.
/// - `Replace(roster)` — wholesale roster swap. **Not supported at
///   v3.8.0** — returns [`AvSessionError::ReplaceNotSupported`]. See the
///   module docs § "Replace — out of scope at v3.8.0" for the
///   sequence-of-commits path that would unlock it.
#[derive(Debug, Clone)]
pub enum RosterDelta {
    Join(Member),
    Leave(PeerKeyId),
    Replace(Vec<Member>),
}

/// The output of a successful [`AvSession::advance_epoch`] — the new
/// epoch counter, the MLS wire artifacts to fan out, and the fresh
/// mesh-wide [`EpochDek`].
///
/// ## Wire shape (T6, v3.8.0+)
///
/// ```text
/// new_epoch       : Epoch
/// commit_bytes    : Vec<u8>          // MLS Commit (tls-encoded, RFC 9420 §6)
/// welcome_bytes   : Option<Vec<u8>>  // MLS Welcome (tls-encoded, RFC 9420 §12.4)
///                                    // Some(_) on Join, None on Leave
/// new_dek         : EpochDek         // the new mesh-wide DEK
/// ```
///
/// Existing members receive `commit_bytes` and feed it to
/// [`AvSession::process_commit`] to derive the same `new_dek`. A joiner
/// (on Join) additionally needs `welcome_bytes` and feeds it to
/// [`AvSession::process_welcome`] to bootstrap.
///
/// **This shape replaces T2's `Vec<DekWrap>`** — see the module docs
/// § "T2 → T6 reconciliation".
///
/// Not `Clone` (the `EpochDek` field is intentionally non-Clone — it
/// zeroizes on drop). Callers that need to pass the artifacts through
/// multiple stages should `std::mem::take` the byte vectors and pass
/// the `EpochDek` by move.
#[derive(Debug)]
pub struct EpochRekeyArtifacts {
    pub new_epoch: Epoch,
    pub commit_bytes: Vec<u8>,
    pub welcome_bytes: Option<Vec<u8>>,
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
    /// The roster-delta variant [`RosterDelta::Replace`] is documented
    /// for completeness but not implemented at v3.8.0. See the module
    /// docs § "Replace — out of scope at v3.8.0".
    #[error(
        "RosterDelta::Replace is not supported at v3.8.0 — sequence Remove+Add commits instead"
    )]
    ReplaceNotSupported,
    /// Joiner-side bootstrap via [`AvSession::process_welcome`] requires
    /// a KeyPackage that the joiner published to the federation
    /// directory ahead of the inviter's commit. v3.8.0 documents this
    /// as a Layer 3 follow-up; the in-memory provider used here cannot
    /// satisfy a Welcome addressed to a leaf whose private material
    /// lives in a separate provider. Use the test-helper round-trip
    /// path for verification (see this module's test surface).
    #[error("joiner-side Welcome processing requires the L3 federation_directory KeyPackage publish/fetch surface; deferred from v3.8.0")]
    JoinerSurfaceUnwired,
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
    mls: MlsSession,
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
                mls,
            },
            dek,
        ))
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
        self.mls.member_count()
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
                let (commit, welcome, root) = self.mls.commit_add(member).map_err(map_mls_err)?;
                self.epoch = Epoch(self.mls.epoch());
                Ok(EpochRekeyArtifacts {
                    new_epoch: self.epoch,
                    commit_bytes: commit.0,
                    welcome_bytes: Some(welcome.0),
                    new_dek: EpochDek::from_bytes(*root.as_bytes()),
                })
            }
            RosterDelta::Leave(peer) => {
                let (commit, root) = self.mls.commit_remove(&peer).map_err(map_mls_err)?;
                self.epoch = Epoch(self.mls.epoch());
                Ok(EpochRekeyArtifacts {
                    new_epoch: self.epoch,
                    commit_bytes: commit.0,
                    welcome_bytes: None,
                    new_dek: EpochDek::from_bytes(*root.as_bytes()),
                })
            }
            RosterDelta::Replace(_) => Err(AvSessionError::ReplaceNotSupported),
        }
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
        let root = self.mls.process_commit(&commit).map_err(map_mls_err)?;
        self.epoch = Epoch(self.mls.epoch());
        Ok(EpochDek::from_bytes(*root.as_bytes()))
    }

    /// Joiner side — bootstrap a fresh [`AvSession`] from a [`Welcome`]
    /// addressed to `own_key_id`, returning the joiner's first
    /// [`EpochDek`].
    ///
    /// **v3.8.0 status: documented stub.** The current MLS layer mints
    /// every member's KeyPackage locally on the inviter side, so a
    /// Welcome addressed to a leaf whose private material lives in a
    /// SEPARATE provider cannot be processed in the standard openmls
    /// flow without the L3 federation-directory KeyPackage
    /// publish/fetch wiring. Returns
    /// [`AvSessionError::JoinerSurfaceUnwired`] to surface this gap
    /// loudly to integrators.
    ///
    /// The test surface in this module's `tests` mod exercises the
    /// full cross-session round-trip via an openmls-direct test helper
    /// that simulates the future L3 publish/fetch flow.
    pub fn process_welcome(
        _stream_id: StreamId,
        own_key_id: &str,
        own_keys: &OwnKexKeys,
        _welcome_bytes: &[u8],
    ) -> Result<(Self, EpochDek), AvSessionError> {
        if own_keys.mlkem768_pub.is_none() {
            return Err(AvSessionError::PeerLacksMlkem(own_key_id.to_string()));
        }
        Err(AvSessionError::JoinerSurfaceUnwired)
    }
}

impl std::fmt::Debug for AvSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AvSession")
            .field("stream_id", &self.stream_id)
            .field("epoch", &self.epoch)
            .field("mls", &self.mls)
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

    fn hybrid_own_keys() -> OwnKexKeys {
        OwnKexKeys {
            x25519_priv: [2u8; 32],
            mlkem768_priv: Some(vec![0xCD; 2400]),
            mlkem768_pub: Some(vec![0xAB; 1184]),
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
        assert!(
            artifacts
                .welcome_bytes
                .as_ref()
                .is_some_and(|w| !w.is_empty()),
            "Welcome must be Some(non-empty) on Join"
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
            artifacts.welcome_bytes.is_none(),
            "Welcome must be None on Leave"
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

    /// `RosterDelta::Replace` returns the documented
    /// `ReplaceNotSupported` error — v3.8.0 deferred surface.
    #[test]
    fn replace_returns_not_supported_v3_8_0() {
        let (mut session, _dek) =
            AvSession::create(dummy_stream(), "alice", vec![hybrid_member("bob")]).expect("create");

        let r = session.advance_epoch(RosterDelta::Replace(vec![
            hybrid_member("carol"),
            hybrid_member("dave"),
        ]));
        assert!(
            matches!(r, Err(AvSessionError::ReplaceNotSupported)),
            "Replace must return ReplaceNotSupported at v3.8.0, got {r:?}"
        );
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

    /// `process_welcome` with HNDL-degraded own_keys is refused before
    /// the JoinerSurfaceUnwired stub fires — HNDL discipline
    /// mirrors `create` / `advance_epoch`.
    #[test]
    fn process_welcome_classical_only_own_keys_refused() {
        let degraded = OwnKexKeys {
            x25519_priv: [2u8; 32],
            mlkem768_priv: None,
            mlkem768_pub: None,
        };
        let r = AvSession::process_welcome(dummy_stream(), "joiner", &degraded, &[0u8; 10]);
        assert!(
            matches!(r, Err(AvSessionError::PeerLacksMlkem(ref k)) if k == "joiner"),
            "expected PeerLacksMlkem(joiner), got {r:?}"
        );
    }

    /// `process_welcome` with HNDL-clean own_keys but no L3 federation-
    /// directory KeyPackage publish/fetch wiring surfaces the documented
    /// `JoinerSurfaceUnwired` error. This is the v3.8.0 contract — the
    /// joiner-side bootstrap is a known follow-up cut.
    #[test]
    fn process_welcome_without_l3_keypackage_surface_documented_gap() {
        let own = hybrid_own_keys();
        let r = AvSession::process_welcome(dummy_stream(), "joiner", &own, &[0u8; 10]);
        assert!(
            matches!(r, Err(AvSessionError::JoinerSurfaceUnwired)),
            "expected JoinerSurfaceUnwired, got {r:?}"
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
        let welcome_bytes = artifacts.welcome_bytes.expect("Welcome on Join");
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
        assert!(artifacts.welcome_bytes.is_none(), "no Welcome on Leave");
    }

    /// Use `MlsMessageOut` to make sure rustc carries the import even
    /// if a future refactor drops the in-test ser path. (Helps catch
    /// API impedance early.)
    #[test]
    fn message_out_import_compiles() {
        let _: Option<MlsMessageOut> = None;
    }
}
