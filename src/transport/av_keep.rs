//! CIRISEdge#847 (#805 item 2) — **one DEK per `(stream, epoch)`, two
//! distributors** (CC 5.1 rc7, CIRISConstitution#140; rc8 #169).
//!
//! For a call's live participants the per-`(stream, epoch)` DEK is derived
//! from the MLS group's epoch (CC rc8: `HKDF(MLS-Exporter("ciris-stream-dek/v1",
//! empty ctx), info = "ciris-stream-dek/v1" ‖ stream_id_utf8 ‖ epoch_be8)`);
//! this wrapper registers whatever per-`(stream, epoch)` DEK its publisher
//! yields (the AvKeySource cut makes that `stream_epoch_dek`). A stream that
//! is **kept** — `history_on_join: full`, or switched on mid-stream with
//! [`KeptAvPublisher::set_keep`] — also registers that same DEK with persist
//! (`Engine::register_stream_epoch_dek`, CIRISPersist#981), which wraps it to
//! the stream's audience as `key_grant:stream:v1` rows: a late joiner, a
//! recording's reader or any member the audience admits opens the call's
//! stored chunks through the key-grant plane, with no second key. An
//! **unkept** call registers nothing: its DEK exists only inside the live
//! MLS group, so an ordinary call keeps the forward secrecy MLS gives it and
//! leaves no durable wrap that could later open it.
//!
//! [`KeptAvPublisher`] owns the stream's [`AvPublisher`] and is the only way
//! to rekey it, so no rekey path can skip the registration: `create` (the
//! group's first epoch), [`KeptAvPublisher::admit_joiner`] and
//! [`KeptAvPublisher::advance_epoch`]
//! each register the new epoch when kept, and never when unkept. Only the
//! stream's WRITER registers (persist refuses another writer
//! `StreamNotAuthored`); subscribers and relays never hold a registrar.
//!
//! # The keep input
//!
//! [`AvKeep`] is an explicit input, default [`AvKeep::Unkept`] (fail
//! forward-secret: CC 5.1's ordinary call), and may change mid-stream (CC
//! rc8, CIRISConstitution#169): [`KeptAvPublisher::set_keep`] turning keep ON
//! registers the CURRENT epoch at once and every later one; turning it OFF
//! stops at the next epoch, forward-only (wraps already made stay). The
//! host's call API (#805 item 5) sources it; edge invents no envelope key.
//! TODO(CIRISPersist#1068): read `history_on_join` per stream at each epoch
//! through persist's door instead of the caller.
//!
//! # Refusals
//!
//! A refused registration degrades the stream to unkept for every LATER
//! epoch and the call stays live: the live group still holds every DEK. The
//! epochs registered before the refusal stay kept, so a recording is
//! PARTIAL from that point. A caller that asked for a recording learns it is
//! not happening from [`KeepOutcome::Refused`] and from the host event bus
//! ([`AV_KEEP_REFUSED_EVENT`] on `subscribe_resource_events`), never only
//! from a log line. The resource-bus event is the interim host signal: the
//! call API (#805 item 5, `FSD/AV_CALL_API.md`) surfaces
//! [`KeepRefused`] as a typed call event.
//!
//! - `StreamEpochDekExists` — Ok ONLY when this same publisher already
//!   registered that epoch (a local retry). Otherwise persist holds a DEK for
//!   the epoch that may not be this session's per-epoch DEK, and stored
//!   chunks would seal under one key while the live ones use another:
//!   refused. TODO(CIRISPersist#1069, v55.1): persist compares the DEK in
//!   constant time — the same DEK answers Ok with
//!   `RegisteredStreamEpoch.already_registered: true` (nothing written), a
//!   different one the non-retryable `StreamEpochDekConflict`. Then this
//!   same-instance rule goes: accept `already_registered` from any
//!   instance and refuse `StreamEpochDekConflict`.
//! - `StreamNotAuthored`, `InvalidArgument` (a plaintext tier, an epoch below
//!   the newest, a stream holding legacy per-chunk-keyed chunks, a stream
//!   recorded elsewhere), and any other error: refused, terminal for keeping.
//!
//! The chunk door's retryable `stream_epoch_rotation_required` /
//! `stream_epoch_dek_missing` arrive at the chunk write (#805 item 3), which
//! rotates through [`KeptAvPublisher::advance_epoch`] and so re-registers on
//! this same path. openmls refuses an empty commit batch (`EmptyBatch`); the
//! rotation without a roster change is a self-update commit, wired with
//! item 3.

use std::collections::BTreeSet;
use std::sync::Arc;

use async_trait::async_trait;
use ciris_crypto::MlDsa65Signer;
use ciris_persist::federation::BlobError;

use super::federation_session::PeerKexPubkeys;
use super::realtime_av::{ChunkLayer, ChunkSeq, Epoch, InnerSealed, StreamId};
use super::realtime_av_dispatcher::{AvSubscriberLink, PeerKeyId};
use super::realtime_av_mls::Member;
use super::realtime_av_runtime::{AvPublisher, AvRuntimeError};
use super::realtime_av_session::{EpochRekeyArtifacts, RosterDelta};

/// The `resource_kind` of the host event a refused registration emits.
pub const AV_KEEP_REFUSED_EVENT: &str = "av_keep_refused";

/// The [`KeepRefused::kind`] of a kept stream refused because keeping is
/// DEFERRED: the AV cut ships live (unkept) calls on persist v55.0.0, and kept
/// streams wait on CIRISPersist#1067 (the v2 stream-chunk AAD, #846 part 2,
/// item 3). Every way a stream can ask to be kept refuses by this name, before
/// any `register_stream_epoch_dek` call, and the stream is never quietly
/// treated as unkept. Grep for CIRISPersist#1067 when the deferral lifts.
pub const KEEP_REFUSED_DEFERRED_1067: &str = "keep_deferred_cirispersist_1067";

/// Whether a live stream is kept (CC 5.1, rc8): `history_on_join:
/// full`. Default [`Self::Unkept`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AvKeep {
    /// An ordinary call: nothing is registered, nothing is wrapped.
    #[default]
    Unkept,
    /// Recorded or `history_on_join: full`: every epoch's DEK is registered
    /// with persist and wrapped to the stream's audience.
    Kept,
}

/// The room a stream's DEK is wrapped for: persist's `(cohort_scope,
/// group_key_id)` (a community room, a family, the owner's self cohort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvKeepTarget {
    /// The stream's cohort scope.
    pub cohort_scope: String,
    /// The group the scope names (the room, the family, the owner).
    pub group_key_id: String,
}

/// Why keeping stopped: persist's refusal of one epoch's registration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "stream {stream_id} epoch {epoch}: keeping refused ({kind}) — later epochs are not kept, \
     earlier ones stay kept: {detail}"
)]
pub struct KeepRefused {
    /// persist's stream id.
    pub stream_id: String,
    /// The epoch whose registration was refused.
    pub epoch: u64,
    /// persist's kind token (`blob_stream_epoch_dek_exists`, …).
    pub kind: &'static str,
    /// persist's message.
    pub detail: String,
}

/// What one epoch's registration did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeepOutcome {
    /// The stream is unkept (asked so, or degraded by an earlier refusal):
    /// nothing was registered.
    NotKept,
    /// The epoch's DEK is registered and wrapped to the audience.
    Registered {
        /// The epoch.
        epoch: u64,
    },
    /// This publisher had already registered the epoch (a local retry).
    AlreadyRegisteredHere {
        /// The epoch.
        epoch: u64,
    },
    /// persist refused; the stream is unkept from here on.
    Refused(KeepRefused),
}

/// persist's register door, as the publisher needs it. Implemented for
/// [`ciris_persist::Engine`]; a test supplies its own.
#[async_trait]
pub trait StreamDekRegistrar: Send + Sync {
    /// Register `dek` as `(stream_id, epoch)`'s DEK for `target`'s audience.
    ///
    /// # Errors
    /// persist's refusal.
    async fn register_stream_epoch_dek(
        &self,
        target: &AvKeepTarget,
        stream_id: &str,
        epoch: u64,
        dek: &[u8; 32],
    ) -> Result<(), BlobError>;
}

/// CIRISEdge#805 item 5 — the registrar of a node with no keep door wired:
/// every registration is refused by name. A kept stream is refused before it
/// reaches any door today (CIRISPersist#1067), and an unkept one never does.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredRegistrar;

#[async_trait]
impl StreamDekRegistrar for UnwiredRegistrar {
    async fn register_stream_epoch_dek(
        &self,
        _target: &AvKeepTarget,
        stream_id: &str,
        epoch: u64,
        _dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        Err(BlobError::InvalidArgument(format!(
            "no stream-DEK registrar is wired on this node: {stream_id} epoch {epoch} cannot be \
             kept"
        )))
    }
}

/// A shared registrar (a `Call` holds its node's as `Arc<dyn …>`).
#[async_trait]
impl<T: StreamDekRegistrar + ?Sized> StreamDekRegistrar for Arc<T> {
    async fn register_stream_epoch_dek(
        &self,
        target: &AvKeepTarget,
        stream_id: &str,
        epoch: u64,
        dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        (**self)
            .register_stream_epoch_dek(target, stream_id, epoch, dek)
            .await
    }
}

#[async_trait]
impl StreamDekRegistrar for ciris_persist::Engine {
    async fn register_stream_epoch_dek(
        &self,
        target: &AvKeepTarget,
        stream_id: &str,
        epoch: u64,
        dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        ciris_persist::Engine::register_stream_epoch_dek(
            self,
            &target.cohort_scope,
            &target.group_key_id,
            stream_id,
            epoch,
            dek,
            None,
        )
        .await
        .map(|_| ())
    }
}

/// The persist stream id of a live stream: `av-` and the hex of its
/// [`StreamId`]. Never the bare 64-hex: persist reserves a SHA-256-shaped
/// stream name for the one-leaf log of the inline blob it names
/// (CIRISPersist#953), and its chunk door refuses one.
///
/// This MUST be the one stream label everywhere: CC 5.3.3.1's nonce prefix
/// and the rc8 per-stream DEK both bind `stream_id_utf8`, so the persist
/// stream, the seal and the DEK info cannot spell it differently.
/// TODO(805-5-call-key): delegate to `realtime_av::stream_label` (which
/// returns `av-{hex}`) once that branch merges, and drop this spelling.
#[must_use]
pub fn persist_stream_id(stream_id: StreamId) -> String {
    format!("av-{}", hex::encode(stream_id.0))
}

/// **A live stream's publisher that keeps what it is told to keep.** See
/// the module docs.
pub struct KeptAvPublisher<R: StreamDekRegistrar> {
    inner: AvPublisher,
    registrar: R,
    target: AvKeepTarget,
    keep: AvKeep,
    /// Set once a registration was refused: no later epoch is registered.
    refused: Option<KeepRefused>,
    /// Epochs THIS publisher registered (an `Exists` for one of them is a
    /// local retry).
    registered: BTreeSet<u64>,
    events: Option<Arc<crate::events::EventBus>>,
}

impl<R: StreamDekRegistrar> KeptAvPublisher<R> {
    /// Create the stream ([`AvPublisher::create`]) and, when kept, register
    /// epoch 0's DEK.
    ///
    /// # Errors
    /// The MLS create or the dispatcher failed ([`AvRuntimeError`]); a
    /// refused registration is a [`KeepOutcome::Refused`], never an error:
    /// the call goes live either way.
    #[allow(clippy::too_many_arguments)] // the publisher's inputs plus the keep inputs
    pub async fn create(
        stream_id: StreamId,
        own_key_id: &str,
        initial_members: Vec<Member>,
        subscribers: Vec<AvSubscriberLink>,
        keep: AvKeep,
        target: AvKeepTarget,
        registrar: R,
        events: Option<Arc<crate::events::EventBus>>,
    ) -> Result<(Self, KeepOutcome), AvRuntimeError> {
        let inner = AvPublisher::create(stream_id, own_key_id, initial_members, subscribers)?;
        let mut me = Self {
            inner,
            registrar,
            target,
            keep,
            refused: None,
            registered: BTreeSet::new(),
            events,
        };
        let outcome = me.register_current().await;
        Ok((me, outcome))
    }

    /// CIRISEdge#805 item 5 — create a ROOM-keyed stream
    /// ([`AvPublisher::from_room_key`], `FSD/AV_CALL_API.md` §3.2, §5): the
    /// epoch DEK is the room's `stream_epoch_dek`, and the keep layer runs
    /// over it exactly as over a session's. When kept, the current epoch is
    /// registered (today: refused by name, CIRISPersist#1067).
    ///
    /// # Errors
    /// The dispatcher rejected its config ([`AvRuntimeError`]).
    #[allow(clippy::too_many_arguments)] // the room publisher's inputs plus the keep inputs
    pub async fn create_room_keyed(
        stream_id: StreamId,
        community_key_id: &str,
        epoch: Epoch,
        dek: crate::transport::realtime_av::EpochDek,
        keep: AvKeep,
        target: AvKeepTarget,
        registrar: R,
        events: Option<Arc<crate::events::EventBus>>,
    ) -> Result<(Self, KeepOutcome), AvRuntimeError> {
        let inner =
            AvPublisher::from_room_key(stream_id, community_key_id, epoch, dek, Vec::new())?;
        let mut me = Self {
            inner,
            registrar,
            target,
            keep,
            refused: None,
            registered: BTreeSet::new(),
            events,
        };
        let outcome = me.register_current().await;
        Ok((me, outcome))
    }

    /// CIRISEdge#805 item 5 — the room moved to `epoch`
    /// ([`AvPublisher::roll_room_epoch`]); register the new epoch when kept.
    /// Every epoch move of a room-keyed stream passes through here, so a
    /// kept stream cannot move an epoch without registering it.
    ///
    /// # Errors
    /// The roll was refused (not room-keyed, or not forward).
    pub async fn roll_room_epoch(
        &mut self,
        epoch: Epoch,
        dek: crate::transport::realtime_av::EpochDek,
    ) -> Result<KeepOutcome, AvRuntimeError> {
        self.inner.roll_room_epoch(epoch, dek)?;
        Ok(self.register_current().await)
    }

    /// CIRISEdge#805 item 5 — the publisher's dispatcher (per-leg fan-out,
    /// layer policy, roster).
    pub(crate) fn dispatcher_mut(
        &mut self,
    ) -> &mut crate::transport::realtime_av_dispatcher::AvDispatcher {
        self.inner.dispatcher_mut()
    }

    /// Admit a published joiner ([`AvPublisher::admit_joiner`]) and register
    /// the new epoch.
    ///
    /// # Errors
    /// The MLS add failed.
    pub async fn admit_joiner(
        &mut self,
        key_id: &str,
        joiner_key_package: openmls::prelude::KeyPackage,
        invitee_kex: &PeerKexPubkeys,
        inviter_signer: &MlDsa65Signer,
        inviter_pk_id: &str,
    ) -> Result<(EpochRekeyArtifacts, KeepOutcome), AvRuntimeError> {
        let artifacts = self.inner.admit_joiner(
            key_id,
            joiner_key_package,
            invitee_kex,
            inviter_signer,
            inviter_pk_id,
        )?;
        let outcome = self.register_current().await;
        Ok((artifacts, outcome))
    }

    /// Roll the MLS epoch ([`AvPublisher::advance_epoch`]) and register the
    /// new epoch.
    ///
    /// # Errors
    /// The MLS rekey failed.
    pub async fn advance_epoch(
        &mut self,
        delta: RosterDelta,
    ) -> Result<(EpochRekeyArtifacts, KeepOutcome), AvRuntimeError> {
        let artifacts = self.inner.advance_epoch(delta)?;
        let outcome = self.register_current().await;
        Ok((artifacts, outcome))
    }

    /// CC rc8 (CIRISConstitution#169) — **change keep mid-stream.** ON
    /// registers the CURRENT epoch at once (its outcome is returned) and every
    /// later epoch; OFF stops from the next epoch, forward-only: what was
    /// registered stays wrapped. A refused stream stays refused (keeping is
    /// terminal after a refusal); turning it on again returns
    /// [`KeepOutcome::NotKept`].
    pub async fn set_keep(&mut self, keep: AvKeep) -> KeepOutcome {
        let was = self.keep;
        // CIRISPersist#1067 — turning keep ON is refused by name while kept
        // streams are deferred, and the stream STAYS unkept. Turning it off is
        // fine.
        if (was, keep) == (AvKeep::Unkept, AvKeep::Kept) {
            return self.refuse_deferred();
        }
        self.keep = keep;
        tracing::info!(
            stream_id = %persist_stream_id(self.inner.stream_id()),
            epoch = self.inner.epoch().0,
            from = ?was,
            to = ?keep,
            "AV keep: changed mid-stream (CC rc8)"
        );
        match (was, keep) {
            (AvKeep::Unkept, AvKeep::Kept) => self.register_current().await,
            _ => KeepOutcome::NotKept,
        }
    }

    /// Re-attempt the CURRENT epoch's registration (a caller retrying after
    /// a crash between the rekey and the register). An `Exists` for an epoch
    /// this publisher registered is Ok.
    pub async fn register_current(&mut self) -> KeepOutcome {
        let epoch = self.inner.epoch().0;
        // CIRISPersist#1067 — kept streams are deferred: a Kept stream (from
        // `create`, `admit_joiner` or `advance_epoch`, which all land here) is
        // refused by name BEFORE the register door, never downgraded to
        // NotKept.
        if self.keep == AvKeep::Kept {
            return self.refuse_deferred();
        }
        if self.keep == AvKeep::Unkept || self.refused.is_some() {
            return KeepOutcome::NotKept;
        }
        let stream = persist_stream_id(self.inner.stream_id());
        let dek = *self.inner.epoch_dek().as_bytes();
        match self
            .registrar
            .register_stream_epoch_dek(&self.target, &stream, epoch, &dek)
            .await
        {
            Ok(()) => {
                self.registered.insert(epoch);
                tracing::info!(
                    stream_id = %stream,
                    epoch,
                    "AV keep: this epoch's per-(stream, epoch) DEK is registered and wrapped to \
                     the audience (CIRISEdge#847)"
                );
                KeepOutcome::Registered { epoch }
            }
            // TODO(CIRISPersist#1069): replace with persist's DEK comparison
            // (`already_registered` / `StreamEpochDekConflict`).
            Err(BlobError::StreamEpochDekExists { .. }) if self.registered.contains(&epoch) => {
                tracing::info!(
                    stream_id = %stream,
                    epoch,
                    "AV keep: epoch already registered by this publisher (a retry)"
                );
                KeepOutcome::AlreadyRegisteredHere { epoch }
            }
            Err(e) => {
                let refused = KeepRefused {
                    stream_id: stream,
                    epoch,
                    kind: e.kind(),
                    detail: e.to_string(),
                };
                self.refuse(&refused);
                self.refused = Some(refused.clone());
                KeepOutcome::Refused(refused)
            }
        }
    }

    /// CIRISPersist#1067 — refuse keeping by [`KEEP_REFUSED_DEFERRED_1067`].
    /// Logged and put on the bus once per stream; every later ask returns the
    /// same named refusal. Nothing reaches the register door.
    fn refuse_deferred(&mut self) -> KeepOutcome {
        let refused = KeepRefused {
            stream_id: persist_stream_id(self.inner.stream_id()),
            epoch: self.inner.epoch().0,
            kind: KEEP_REFUSED_DEFERRED_1067,
            detail: "kept streams are deferred behind CIRISPersist#1067 (the v2 stream-chunk \
                     AAD); this call is live and unkept"
                .to_owned(),
        };
        if self.refused.is_none() {
            self.refuse(&refused);
        }
        self.refused = Some(refused.clone());
        KeepOutcome::Refused(refused)
    }

    fn refuse(&self, refused: &KeepRefused) {
        tracing::error!(
            stream_id = %refused.stream_id,
            epoch = refused.epoch,
            kind = refused.kind,
            error = %refused.detail,
            "AV keep: persist refused this epoch's DEK — the call stays live, later epochs \
             are NOT kept, earlier ones stay kept (CIRISEdge#847)"
        );
        if let Some(events) = &self.events {
            #[allow(clippy::cast_precision_loss)] // an epoch counter, reported as a measurement
            events.emit_resource(crate::events::NetworkEvent::resource(
                AV_KEEP_REFUSED_EVENT,
                refused.epoch as f64,
                "epoch",
                crate::events::EventSeverity::Error,
                refused.to_string(),
            ));
        }
    }

    /// Whether this stream's epochs are being kept now.
    #[must_use]
    pub fn is_keeping(&self) -> bool {
        self.keep == AvKeep::Kept && self.refused.is_none()
    }

    /// The refusal that stopped keeping, if any.
    #[must_use]
    pub fn refused(&self) -> Option<&KeepRefused> {
        self.refused.as_ref()
    }

    /// The epochs this publisher registered.
    #[must_use]
    pub fn registered_epochs(&self) -> Vec<u64> {
        self.registered.iter().copied().collect()
    }

    /// The publisher, read-only (its rekey methods are reachable only
    /// through this wrapper).
    #[must_use]
    pub fn publisher(&self) -> &AvPublisher {
        &self.inner
    }

    /// [`AvPublisher::publish_chunk`].
    ///
    /// # Errors
    /// As the publisher's.
    pub async fn publish_chunk(
        &mut self,
        plaintext: &[u8],
        codec_id: u8,
        layer: ChunkLayer,
    ) -> Result<ChunkSeq, AvRuntimeError> {
        self.inner.publish_chunk(plaintext, codec_id, layer).await
    }

    /// [`AvPublisher::seal_next`].
    ///
    /// # Errors
    /// As the publisher's.
    pub fn seal_next(
        &mut self,
        plaintext: &[u8],
        codec_id: u8,
        layer: ChunkLayer,
    ) -> Result<(ChunkSeq, InnerSealed), AvRuntimeError> {
        self.inner.seal_next(plaintext, codec_id, layer)
    }

    /// [`AvPublisher::dispatch_inner`].
    ///
    /// # Errors
    /// As the publisher's.
    pub async fn dispatch_inner(&mut self, inner: InnerSealed) -> Result<usize, AvRuntimeError> {
        self.inner.dispatch_inner(inner).await
    }

    /// [`AvPublisher::add_subscriber`].
    ///
    /// # Errors
    /// As the publisher's.
    pub fn add_subscriber(&mut self, link: AvSubscriberLink) -> Result<(), AvRuntimeError> {
        self.inner.add_subscriber(link)
    }

    /// [`AvPublisher::remove_subscriber`].
    pub fn remove_subscriber(&mut self, subscriber: &PeerKeyId) {
        self.inner.remove_subscriber(subscriber);
    }

    /// The stream's current epoch.
    #[must_use]
    pub fn epoch(&self) -> Epoch {
        self.inner.epoch()
    }
}

#[cfg(test)]
mod tests;
