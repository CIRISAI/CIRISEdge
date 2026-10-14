//! CIRISEdge#847 — the keep wrapper's decisions against a recording
//! registrar: what is registered, when, with which DEK, and what a refusal
//! does. The persist-backed witness (an audience member outside the live
//! MLS group opens a kept call's chunks) is the integration test.

use std::sync::Mutex;

use super::*;
use crate::transport::federation_session::PeerKexPubkeys;

fn hybrid_member(key_id: &str) -> Member {
    Member {
        key_id: key_id.to_string(),
        kex_pubkeys: PeerKexPubkeys {
            x25519_pub: [1u8; 32],
            mlkem768_pub: vec![0xAB; 1184],
        },
    }
}

fn target() -> AvKeepTarget {
    AvKeepTarget {
        cohort_scope: "community".into(),
        group_key_id: "room-847".into(),
    }
}

/// What the registrar answers each call, in order; `Ok` once the script
/// runs out.
#[derive(Default)]
struct Recording {
    calls: Mutex<Vec<(String, u64, [u8; 32])>>,
    script: Mutex<Vec<Result<(), BlobError>>>,
}

#[async_trait]
impl StreamDekRegistrar for Recording {
    async fn register_stream_epoch_dek(
        &self,
        _target: &AvKeepTarget,
        stream_id: &str,
        epoch: u64,
        dek: &[u8; 32],
    ) -> Result<(), BlobError> {
        self.calls
            .lock()
            .expect("calls")
            .push((stream_id.to_owned(), epoch, *dek));
        let mut script = self.script.lock().expect("script");
        if script.is_empty() {
            Ok(())
        } else {
            script.remove(0)
        }
    }
}

impl Recording {
    fn scripted(script: Vec<Result<(), BlobError>>) -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            script: Mutex::new(script),
        }
    }

    fn calls(&self) -> Vec<(String, u64, [u8; 32])> {
        self.calls.lock().expect("calls").clone()
    }
}

fn exists(epoch: u64) -> BlobError {
    BlobError::StreamEpochDekExists {
        stream_id: "s".into(),
        epoch,
    }
}

async fn publisher(
    keep: AvKeep,
    registrar: Recording,
) -> (KeptAvPublisher<Recording>, KeepOutcome) {
    KeptAvPublisher::create(
        StreamId([0x47; 32]),
        "alice",
        vec![hybrid_member("bob"), hybrid_member("carol")],
        Vec::new(),
        keep,
        target(),
        registrar,
        None,
    )
    .await
    .expect("create the stream")
}

/// **Kept: every epoch registers the publisher's own per-epoch DEK** —
/// the created epoch, then each rekey — under the stream's persist id.
/// Fails with the register skipped on any rekey path.
#[tokio::test]
#[ignore = "kept streams deferred behind CIRISPersist#1067"]
async fn a_kept_stream_registers_every_epochs_dek() {
    let (mut p, created) = publisher(AvKeep::Kept, Recording::default()).await;
    let e0 = p.epoch().0;
    assert_eq!(created, KeepOutcome::Registered { epoch: e0 });
    let (_, left) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("rekey");
    assert_eq!(left, KeepOutcome::Registered { epoch: e0 + 1 });
    let calls = p.registrar.calls();
    let stream = persist_stream_id(StreamId([0x47; 32]));
    assert_eq!(
        calls
            .iter()
            .map(|(s, e, _)| (s.clone(), *e))
            .collect::<Vec<_>>(),
        vec![(stream.clone(), e0), (stream, e0 + 1)]
    );
    assert_eq!(
        calls[1].2,
        *p.publisher().epoch_dek().as_bytes(),
        "the registered DEK is the publisher's own, no second key"
    );
    assert_ne!(calls[0].2, calls[1].2, "each epoch has its own DEK");
    assert_eq!(p.registered_epochs(), vec![e0, e0 + 1]);
    assert!(p.is_keeping());
}

/// **Unkept: the door is never called**, at create or at any rekey.
/// Fails with the register reached on the unkept path.
#[tokio::test]
async fn an_unkept_stream_never_calls_the_door() {
    let (mut p, created) = publisher(AvKeep::Unkept, Recording::default()).await;
    assert_eq!(created, KeepOutcome::NotKept);
    let (_, left) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("rekey");
    assert_eq!(left, KeepOutcome::NotKept);
    assert!(p.registrar.calls().is_empty(), "nothing registered");
    assert!(!p.is_keeping());
    assert_eq!(
        AvKeep::default(),
        AvKeep::Unkept,
        "the default is forward-secret"
    );
}

/// **`Exists`: Ok only as a local retry.** This publisher registered epoch
/// 0; asked again (a retry after a crash), persist's Exists is Ok. A FRESH
/// publisher meeting Exists at its first epoch cannot know the stored DEK is its
/// per-epoch DEK: refused, and nothing later is registered.
#[tokio::test]
#[ignore = "kept streams deferred behind CIRISPersist#1067"]
async fn exists_is_ok_only_for_an_epoch_this_publisher_registered() {
    let (mut p, created) = publisher(
        AvKeep::Kept,
        Recording::scripted(vec![Ok(()), Err(exists(0))]),
    )
    .await;
    let e0 = p.epoch().0;
    assert_eq!(created, KeepOutcome::Registered { epoch: e0 });
    assert_eq!(
        p.register_current().await,
        KeepOutcome::AlreadyRegisteredHere { epoch: e0 },
        "a same-instance retry"
    );
    assert!(p.is_keeping());

    let (mut fresh, outcome) =
        publisher(AvKeep::Kept, Recording::scripted(vec![Err(exists(0))])).await;
    let KeepOutcome::Refused(refused) = &outcome else {
        panic!("a fresh publisher at a registered epoch is refused: {outcome:?}");
    };
    assert_eq!(refused.kind, "blob_stream_epoch_dek_exists");
    assert_eq!(refused.epoch, fresh.epoch().0);
    assert!(!fresh.is_keeping());
    let (_, later) = fresh
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("the call stays live");
    assert_eq!(later, KeepOutcome::NotKept, "no later epoch is registered");
    assert_eq!(fresh.registrar.calls().len(), 1);
}

/// **A refusal degrades to unkept, the call stays live, earlier epochs
/// stay kept, and the host hears it** on the resource event bus.
#[tokio::test]
#[ignore = "kept streams deferred behind CIRISPersist#1067"]
async fn a_refusal_degrades_to_unkept_and_reaches_the_host() {
    let events = Arc::new(crate::events::EventBus::default());
    let mut rx = events.subscribe_resources();
    let (mut p, created) = KeptAvPublisher::create(
        StreamId([0x48; 32]),
        "alice",
        vec![hybrid_member("bob"), hybrid_member("carol")],
        Vec::new(),
        AvKeep::Kept,
        target(),
        Recording::scripted(vec![
            Ok(()),
            Err(BlobError::StreamNotAuthored {
                stream_id: "s".into(),
            }),
        ]),
        Some(Arc::clone(&events)),
    )
    .await
    .expect("create");
    let e0 = p.epoch().0;
    assert_eq!(created, KeepOutcome::Registered { epoch: e0 });
    let (_, refused) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("the call stays live");
    let KeepOutcome::Refused(r) = refused else {
        panic!("persist refused the rekeyed epoch: {refused:?}");
    };
    assert_eq!((r.kind, r.epoch), ("blob_stream_not_authored", e0 + 1));
    assert_eq!(
        p.registered_epochs(),
        vec![e0],
        "the first epoch stays kept"
    );
    assert_eq!(p.refused(), Some(&r));
    let event = rx.try_recv().expect("the host hears the refusal");
    assert!(
        format!("{event:?}").contains(AV_KEEP_REFUSED_EVENT),
        "{event:?}"
    );
}

/// **CC rc8 — keep switched ON mid-stream** registers the CURRENT epoch at
/// once and every later one; the epochs before the switch never are.
#[tokio::test]
#[ignore = "kept streams deferred behind CIRISPersist#1067"]
async fn keep_switched_on_mid_stream_registers_the_current_epoch_and_later() {
    let (mut p, created) = publisher(AvKeep::Unkept, Recording::default()).await;
    assert_eq!(created, KeepOutcome::NotKept);
    let e0 = p.epoch().0;
    p.advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("rekey");
    assert_eq!(
        p.set_keep(AvKeep::Kept).await,
        KeepOutcome::Registered { epoch: e0 + 1 },
        "the current epoch at once"
    );
    let (_, later) = p
        .advance_epoch(RosterDelta::Leave("bob".into()))
        .await
        .expect("rekey again");
    assert_eq!(later, KeepOutcome::Registered { epoch: e0 + 2 });
    let epochs: Vec<u64> = p.registrar.calls().iter().map(|(_, e, _)| *e).collect();
    assert_eq!(
        epochs,
        vec![e0 + 1, e0 + 2],
        "the epoch before the switch never registered"
    );
}

/// **CC rc8 — keep switched OFF mid-stream** stops from the next epoch,
/// forward-only: the epochs already registered stay as they were.
#[tokio::test]
#[ignore = "kept streams deferred behind CIRISPersist#1067"]
async fn keep_switched_off_mid_stream_stops_at_the_next_epoch() {
    let (mut p, created) = publisher(AvKeep::Kept, Recording::default()).await;
    let e0 = p.epoch().0;
    assert_eq!(created, KeepOutcome::Registered { epoch: e0 });
    assert_eq!(p.set_keep(AvKeep::Unkept).await, KeepOutcome::NotKept);
    let (_, later) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("rekey");
    assert_eq!(later, KeepOutcome::NotKept, "no later epoch is registered");
    assert_eq!(
        p.registered_epochs(),
        vec![e0],
        "the first epoch stays registered"
    );
    assert_eq!(
        p.registrar.calls().len(),
        1,
        "nothing is unregistered or re-sent"
    );
}

// ─── CIRISPersist#1067: kept streams are deferred ─────────────────────

fn deferred(outcome: &KeepOutcome) -> bool {
    matches!(outcome, KeepOutcome::Refused(r) if r.kind == KEEP_REFUSED_DEFERRED_1067)
}

/// Every way a stream asks to be kept refuses BY NAME, and nothing reaches
/// the register door: create, a joiner's admission, and an epoch roll.
#[tokio::test]
async fn a_kept_stream_is_refused_by_name_and_never_registers() {
    let (mut p, created) = publisher(AvKeep::Kept, Recording::default()).await;
    assert!(deferred(&created), "create: {created:?}");
    let (_, joiner_kp) =
        crate::transport::realtime_av_mls::mint_joiner_key_material("dave").expect("key package");
    let (_, x_pk) = ciris_crypto::x25519::generate_ephemeral_keypair().expect("x25519");
    let (_, mlkem_pk) = ciris_crypto::ml_kem::generate_keypair().expect("ml-kem");
    let inviter = ciris_crypto::MlDsa65Signer::new().expect("inviter");
    let (_, admitted) = p
        .admit_joiner(
            "dave",
            joiner_kp,
            &PeerKexPubkeys {
                x25519_pub: x_pk,
                mlkem768_pub: mlkem_pk,
            },
            &inviter,
            "inviter-1067",
        )
        .await
        .expect("admit");
    assert!(deferred(&admitted), "admit_joiner: {admitted:?}");
    let (_, rolled) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("roll");
    assert!(deferred(&rolled), "advance_epoch: {rolled:?}");
    assert!(!p.is_keeping());
    assert!(
        p.registrar.calls().is_empty(),
        "zero register calls: {:?}",
        p.registrar.calls()
    );
}

/// Turning keep on mid-stream is refused by name, and the stream stays
/// unkept: later epochs never reach the door either. Turning it off is fine.
#[tokio::test]
async fn keep_switched_on_mid_stream_is_refused_and_the_stream_stays_unkept() {
    let (mut p, _) = publisher(AvKeep::Unkept, Recording::default()).await;
    let on = p.set_keep(AvKeep::Kept).await;
    assert!(deferred(&on), "set_keep(Kept): {on:?}");
    let (_, rolled) = p
        .advance_epoch(RosterDelta::Leave("carol".into()))
        .await
        .expect("roll");
    assert_eq!(rolled, KeepOutcome::NotKept, "still unkept, not re-refused");
    assert_eq!(p.set_keep(AvKeep::Unkept).await, KeepOutcome::NotKept);
    assert!(p.registrar.calls().is_empty(), "zero register calls");
}
