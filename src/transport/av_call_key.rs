//! A room call's media keys — CIRISEdge#805 item 5 (`FSD/AV_CALL_API.md` §3.2).
//!
//! A call's MLS group IS its room's ([`CohortGroup`]): a room call never
//! mints a group of its own (the per-stream `AvSession` group is the
//! pre-item-5 shape). Each publisher's stream gets its OWN epoch DEK, derived
//! from the room's exporter at the room's current epoch:
//!
//! ```text
//! seed = MLS-Exporter(L, context = ∅, 32)                           (the room group)
//! dek  = HKDF-SHA256(ikm = seed, salt = ∅, info = L ‖ stream_id_utf8 ‖ u64_be(epoch))
//! ```
//!
//! `L` is [`STREAM_DEK_LABEL`]; `stream_id_utf8` is the stream label
//! (`realtime_av::stream_label`: `av-` + the lowercase hex of the 32-byte id,
//! the one spelling persist and the STREAM nonce use too). No length
//! prefixes: the fixed label, the fixed 67-byte stream label and the
//! fixed 8-byte epoch parse unambiguously.
//!
//! **Normative: CC 5.1 (rc8, CIRISConstitution#169).** One DEK per
//! `(stream_id, epoch)`: a `key_grant:stream:v1` wraps this per-stream DEK and
//! opens that one stream only; the exporter secret is never wrapped. KATs come
//! from CIRISVerify#308.
//!
//! TODO(CIRISVerify#308): when verify lands its `stream_dek` fn and vectors,
//! call it here instead of this derivation and run its KATs.
//!
//! **Why the bind is a KDF step, not the exporter context:** the room group
//! exports with an EMPTY context, deliberately and per verify (a context edge
//! chose for itself would make edge derive different bytes from every other
//! implementation).
//!
//! **No call id in the key:** the CC has no call object, and the MLS group
//! already binds the community. A call's id (`CallId`) is a signalling and API
//! handle only, never key input.
//!
//! **The current epoch only:** an MLS exporter exports the group's CURRENT
//! epoch. A DEK for any other epoch is refused ([`StreamKeyError::EpochNotCurrent`]),
//! never derived from the wrong secret.

pub use crate::mls::cohort_group::STREAM_DEK_LABEL;
use crate::mls::{CohortGroup, CohortGroupError};
use crate::transport::realtime_av::{stream_label, Epoch, EpochDek, StreamId};

/// A call's handle: `SHA-256("ciris-edge:call:v1" ‖ utf8(community_key_id))` of
/// the room the call lives in (FSD/AV_CALL_API.md §3.1; the CC has no call
/// row). A signalling and API handle, NEVER key input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CallId(pub [u8; 32]);

/// Why a stream DEK was not derived.
#[derive(Debug, thiserror::Error)]
pub enum StreamKeyError {
    /// The room group moved past (or has not reached) the epoch asked for; an
    /// MLS exporter exports only the current epoch.
    #[error("stream DEK asked for room epoch {asked}, the room group is at {current}")]
    EpochNotCurrent { asked: u64, current: u64 },
    /// The room group's exporter failed.
    #[error("room group: {0}")]
    Room(#[from] CohortGroupError),
    /// The HKDF step failed.
    #[error("stream DEK derivation: {0:?}")]
    Kdf(ciris_crypto::CryptoError),
}

/// The HKDF info of `stream_id`'s DEK at `epoch`: `L ‖ stream_id_utf8 ‖
/// u64_be(epoch)`.
#[must_use]
pub fn stream_dek_info(stream_id: StreamId, epoch: Epoch) -> Vec<u8> {
    let label = stream_label(stream_id);
    let mut info = Vec::with_capacity(STREAM_DEK_LABEL.len() + label.len() + 8);
    info.extend_from_slice(STREAM_DEK_LABEL.as_bytes());
    info.extend_from_slice(label.as_bytes());
    info.extend_from_slice(&epoch.0.to_be_bytes());
    info
}

/// The epoch DEK of `stream_id` at the room's CURRENT epoch `epoch`
/// (FSD/AV_CALL_API.md §3.2). Members of the room derive the same DEK without
/// exchanging anything; anyone outside the room's MLS group cannot.
///
/// # Errors
/// [`StreamKeyError::EpochNotCurrent`] when `epoch` is not the room group's
/// current epoch; [`StreamKeyError::Room`] / [`StreamKeyError::Kdf`] on a
/// failed export or derivation.
pub async fn stream_epoch_dek(
    room_group: &CohortGroup,
    stream_id: StreamId,
    epoch: Epoch,
) -> Result<EpochDek, StreamKeyError> {
    let (current, seed) = room_group.stream_key_seed().await?;
    if current != epoch.0 {
        return Err(StreamKeyError::EpochNotCurrent {
            asked: epoch.0,
            current,
        });
    }
    let okm = ciris_crypto::kdf::hkdf_sha256(
        seed.as_bytes(),
        &[],
        &stream_dek_info(stream_id, epoch),
        32,
    )
    .map_err(StreamKeyError::Kdf)?;
    let mut dek = [0u8; 32];
    dek.copy_from_slice(&okm);
    Ok(EpochDek::from_bytes(dek))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ciris_persist::encrypted_kv::XChaChaKvStore;

    use super::*;
    use crate::mls::cohort_group::mint_cohort_key_material;
    use crate::mls::ScopeStateProvider;

    const STREAM_A: StreamId = StreamId([0xA1; 32]);
    const STREAM_B: StreamId = StreamId([0xB2; 32]);

    fn store() -> ScopeStateProvider {
        ScopeStateProvider::new(Arc::new(
            XChaChaKvStore::open_in_memory(b"av-call-key-test").unwrap(),
        ))
    }

    /// A room founded by `node-a` with `node-b` joined from the Welcome: two
    /// members on two stores, the deployment shape.
    async fn room(community: &str) -> (CohortGroup, CohortGroup) {
        let a = CohortGroup::create(store(), community, "node-a", 16)
            .await
            .unwrap();
        let (material, kp) = mint_cohort_key_material("node-b").unwrap();
        let add = a.add_member("node-b", kp).await.unwrap();
        let b = CohortGroup::join(
            store(),
            community,
            material,
            add.welcome().expect("an Add produces a Welcome"),
            16,
        )
        .await
        .unwrap();
        (a, b)
    }

    async fn dek(g: &CohortGroup, stream: StreamId) -> [u8; 32] {
        let epoch = Epoch(g.epoch().await);
        *stream_epoch_dek(g, stream, epoch)
            .await
            .expect("dek")
            .as_bytes()
    }

    /// The info layout is `L ‖ stream_id_utf8 ‖ u64_be(epoch)`, no length
    /// prefixes, with `L` the ruled `"ciris-stream-dek/v1"`; the stream part is
    /// the stream label, `av-` + 64 lowercase hex.
    #[test]
    fn the_info_layout_is_pinned() {
        let info = stream_dek_info(STREAM_A, Epoch(0x0102_0304_0506_0708));
        let l = STREAM_DEK_LABEL.as_bytes();
        assert_eq!(l, b"ciris-stream-dek/v1", "the label CC 5.1 (rc8) rules");
        assert_eq!(info.len(), l.len() + 3 + 64 + 8);
        assert_eq!(&info[..l.len()], l);
        assert_eq!(&info[l.len()..l.len() + 3], b"av-");
        assert_eq!(&info[l.len() + 3..l.len() + 67], "a1".repeat(32).as_bytes());
        assert_eq!(&info[l.len() + 67..], &[1, 2, 3, 4, 5, 6, 7, 8]);
    }

    /// Two members of the room derive the same DEK for a stream without
    /// exchanging it; a member of ANOTHER room derives a different one.
    #[tokio::test]
    async fn room_members_agree_and_outsiders_do_not() {
        let (a, b) = room("room-call-1").await;
        assert_eq!(dek(&a, STREAM_A).await, dek(&b, STREAM_A).await);
        let (other, _) = room("room-call-2").await;
        assert_ne!(dek(&a, STREAM_A).await, dek(&other, STREAM_A).await);
    }

    /// One DEK per stream: a key grant for one publisher's stream opens no
    /// other stream (CC 5.1, rc8, CIRISConstitution#169).
    #[tokio::test]
    async fn the_dek_is_per_stream() {
        let (a, _) = room("room-call-3").await;
        assert_ne!(dek(&a, STREAM_A).await, dek(&a, STREAM_B).await);
    }

    /// A room commit rolls the key, and the old epoch's key is no longer
    /// derivable (the exporter exports the current epoch only).
    #[tokio::test]
    async fn a_room_commit_rolls_the_key_and_the_old_epoch_is_refused() {
        let (a, _) = room("room-call-4").await;
        let e0 = Epoch(a.epoch().await);
        let before = *stream_epoch_dek(&a, STREAM_A, e0).await.unwrap().as_bytes();
        let _ = a.rotate().await.unwrap();
        let e1 = Epoch(a.epoch().await);
        assert_ne!(
            before,
            *stream_epoch_dek(&a, STREAM_A, e1).await.unwrap().as_bytes()
        );
        assert!(matches!(
            stream_epoch_dek(&a, STREAM_A, e0).await,
            Err(StreamKeyError::EpochNotCurrent { asked, current }) if asked == e0.0 && current == e1.0
        ));
    }

    /// The stream key is label-separated from the room's scope-privacy secrets
    /// and from the retired per-stream A/V label.
    #[tokio::test]
    async fn the_stream_key_is_separated_from_the_rooms_other_secrets() {
        assert_ne!(
            STREAM_DEK_LABEL,
            crate::scope_privacy::RECORD_EXPORTER_LABEL
        );
        assert_ne!(
            STREAM_DEK_LABEL,
            crate::scope_privacy::DESTINATION_EXPORTER_LABEL
        );
        assert_ne!(STREAM_DEK_LABEL, "ciris-realtime-av-epoch-dek-seed-v1");
        let (a, _) = room("room-call-5").await;
        let (_, seed) = a.stream_key_seed().await.unwrap();
        assert_ne!(seed.as_bytes(), a.record_secret().await.unwrap().as_bytes());
        assert_ne!(
            seed.as_bytes(),
            a.destination_secret().await.unwrap().as_bytes()
        );
        assert_ne!(
            &dek(&a, STREAM_A).await,
            seed.as_bytes(),
            "the DEK is not the raw seed"
        );
    }
}
