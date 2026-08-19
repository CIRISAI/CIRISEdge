//! Spine acceptance — driven through REAL sessions, not mocks.
//!
//! Every call here runs a live openmls (X-Wing 0x004D) group, the real
//! `ScopePrivacyDeriver` address derivation, a real `RelayNode` over a
//! real leviculum node handle, and the real two-layer AEAD. The only
//! stub is the destination sink, and only so a registration can be made
//! to fail on demand — the one failure the transport will not produce to
//! order.

use super::*;

use std::sync::Mutex;
use std::time::Duration;

use ciris_crypto::{ml_kem, x25519, PqcSigner};

use crate::mls::welcome_wrap::FederationDirectoryEntry;
use crate::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
use crate::scope_lifecycle::ScopedDestinationSink;
use crate::transport::federation_session::OwnKexKeys;
use crate::transport::realtime_av::{open_av_chunk, EpochDek, SealedAvChunk};
use crate::transport::realtime_av_mls::mint_joiner_key_material;
use crate::transport::realtime_av_session::AvSession;

const CONVERGENCE: Duration = Duration::from_secs(300);

// ─── fixtures ───────────────────────────────────────────────────────

/// Records what the lifecycle registered and retired, and can be told to
/// refuse the next registration.
#[derive(Default)]
struct RecordingSink {
    registered: Mutex<Vec<[u8; 16]>>,
    retired: Mutex<Vec<[u8; 16]>>,
    refuse: Mutex<bool>,
}

impl RecordingSink {
    fn refuse_next(&self, refuse: bool) {
        *self.refuse.lock().unwrap() = refuse;
    }
    fn retired(&self) -> Vec<[u8; 16]> {
        self.retired.lock().unwrap().clone()
    }
    fn registered(&self) -> Vec<[u8; 16]> {
        self.registered.lock().unwrap().clone()
    }
}

impl ScopedDestinationSink for RecordingSink {
    fn register(&self, address: &MemberAddress, _scope: &CohortScope) -> Result<(), String> {
        if *self.refuse.lock().unwrap() {
            return Err("node refused to listen".to_owned());
        }
        self.registered.lock().unwrap().push(*address.as_bytes());
        Ok(())
    }
    fn retire(&self, address: &MemberAddress, _scope: &CohortScope) -> Result<(), String> {
        self.retired.lock().unwrap().push(*address.as_bytes());
        Ok(())
    }
}

/// A throwaway leviculum node. The spine's relay never drives it for
/// I/O — `forward` is pure compute — so a synthetic identity suffices.
/// Each call gets its own storage path so builders do not collide.
fn test_node() -> Arc<ReticulumNode> {
    use leviculum_core::Identity;
    use leviculum_std::driver::ReticulumNodeBuilder;
    let mut priv_bytes = [0u8; 64];
    for (i, b) in priv_bytes.iter_mut().enumerate() {
        *b = u8::try_from(i)
            .expect("index < 64")
            .wrapping_mul(31)
            .wrapping_add(7);
    }
    let identity =
        Identity::from_private_key_bytes(&priv_bytes).expect("identity from synthetic key");
    let storage =
        std::env::temp_dir().join(format!("ciris-edge-spine-test-{}", uuid::Uuid::new_v4()));
    Arc::new(
        ReticulumNodeBuilder::new()
            .identity(identity)
            .storage_path(storage)
            .build_sync()
            .expect("build spine test node"),
    )
}

/// A fresh joiner X-Wing kex pair.
#[allow(clippy::similar_names)]
fn fresh_joiner_xwing() -> (PeerKexPubkeys, OwnKexKeys) {
    let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().expect("x25519 keypair");
    let (mlkem_sk, mlkem_pk) = ml_kem::generate_keypair().expect("ml-kem keypair");
    (
        PeerKexPubkeys {
            x25519_pub: x_pk,
            mlkem768_pub: Some(mlkem_pk.clone()),
        },
        OwnKexKeys {
            x25519_priv: x_sk,
            mlkem768_priv: Some(mlkem_sk),
            mlkem768_pub: Some(mlkem_pk),
        },
    )
}

fn directory_resolving(
    pk_id: &str,
    ml_dsa_pk: Vec<u8>,
) -> impl FnMut(&str) -> Option<FederationDirectoryEntry> {
    let want = pk_id.to_owned();
    move |id: &str| {
        (id == want).then(|| FederationDirectoryEntry {
            pk_id: id.to_owned(),
            ml_dsa_pk: ml_dsa_pk.clone(),
            x_wing_pk: None,
        })
    }
}

fn scope() -> CohortScope {
    CohortScope::Cohort {
        cohort_id: "the-call".to_owned(),
    }
}

/// One node's whole A/V stack, plus the peer sessions it admitted, so a
/// test can assert on the real byte path from both ends.
struct TestCall {
    spine: AvSpine,
    sink: Arc<RecordingSink>,
    table: Arc<ScopeAddressTable>,
    inviter: MlDsa65Signer,
    inviter_pk: Vec<u8>,
    t0: Instant,
}

/// A peer this node admitted: its own MLS session (so it derives the
/// same DEKs), its transit key, and its live epoch DEK.
struct Peer {
    key_id: PeerKeyId,
    session: AvSession,
    transit_key: [u8; 32],
    dek: EpochDek,
    /// The relay's per-subscriber `link_seq` from this peer's point of
    /// view. Counts ADMITTED chunks and is NOT reset by an epoch move —
    /// which is exactly the make-before-break property under test.
    link_seq: u64,
}

impl Peer {
    /// Open a chunk the relay sealed for this peer, advancing its
    /// `link_seq` exactly as its receive loop would.
    fn open(&mut self, sealed: &SealedAvChunk) -> Vec<u8> {
        let out = open_av_chunk(
            sealed,
            &self.transit_key,
            self.key_id.as_bytes(),
            self.link_seq,
            &self.dek,
        )
        .expect("subscriber opens both AEAD layers");
        self.link_seq += 1;
        out
    }
}

impl TestCall {
    /// A call with exactly this node in it, relaying its own stream.
    fn open(stream_seed: u8) -> Self {
        Self::open_with(stream_seed, true)
    }

    fn open_with(stream_seed: u8, relays: bool) -> Self {
        let sink = Arc::new(RecordingSink::default());
        let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
        let lifecycle = Arc::new(ScopeLifecycle::new(
            Arc::clone(&table),
            Arc::clone(&sink) as Arc<dyn ScopedDestinationSink>,
            "node-self",
            CONVERGENCE,
        ));
        let stream_id = StreamId([stream_seed; 32]);
        // No initial members: every other member arrives through the
        // spine's own `join`, so each one has a REAL session built from
        // a REAL Welcome and derives the DEKs independently.
        let (session, dek) =
            AvSession::create(stream_id, "node-self", Vec::new()).expect("create session");
        let publisher =
            AvPublisher::from_session(stream_id, session, dek, Vec::new()).expect("publisher");
        let inviter = MlDsa65Signer::new().expect("inviter signer");
        let inviter_pk = inviter.public_key().expect("inviter pk");
        let spine = AvSpine::open(scope(), lifecycle, publisher, relays.then(test_node))
            .expect("spine opens");
        Self {
            spine,
            sink,
            table,
            inviter,
            inviter_pk,
            t0: Instant::now(),
        }
    }

    /// Admit a peer through the spine and stand its own session up from
    /// the Welcome, so it derives the same epoch DEK independently.
    fn join(&mut self, key_id: &str, transit_key: [u8; 32], at: Instant) -> (Peer, JoinTicket) {
        let (material, key_package) = mint_joiner_key_material(key_id).expect("mint key package");
        let (kex_pub, kex_secret) = fresh_joiner_xwing();
        let ticket = self
            .spine
            .join(
                Joiner {
                    key_id,
                    key_package,
                    kex: &kex_pub,
                    inviter_signer: &self.inviter,
                    inviter_pk_id: "node-self-fed",
                },
                at,
            )
            .expect("join succeeds");
        let mut session = AvSession::new_joiner(self.spine.stream_id(), material);
        let dek = session
            .process_welcome(
                &ticket.welcome_bytes,
                &kex_secret,
                directory_resolving("node-self-fed", self.inviter_pk.clone()),
            )
            .expect("joiner bootstraps from the Welcome");
        (
            Peer {
                key_id: key_id.to_owned(),
                session,
                transit_key,
                dek,
                link_seq: 0,
            },
            ticket,
        )
    }

    /// Try to admit a peer, surfacing the refusal.
    fn try_join(&mut self, key_id: &str, at: Instant) -> Result<JoinTicket, AvSpineError> {
        let (_material, key_package) = mint_joiner_key_material(key_id).expect("mint key package");
        let (kex_pub, _secret) = fresh_joiner_xwing();
        self.spine.join(
            Joiner {
                key_id,
                key_package,
                kex: &kex_pub,
                inviter_signer: &self.inviter,
                inviter_pk_id: "node-self-fed",
            },
            at,
        )
    }

    fn relay_address(&self) -> [u8; 16] {
        *self
            .spine
            .relay()
            .expect("this call relays")
            .address()
            .as_bytes()
    }

    fn relay_answers(&self, addr: &[u8; 16]) -> bool {
        self.spine
            .relay()
            .expect("this call relays")
            .accepts(&DestinationHash::new(*addr))
    }
}

/// Pull the sealed chunk the relay produced for `peer` out of a fan-out.
fn chunk_for<'a>(fanout: &'a Fanout, peer: &str) -> &'a SealedAvChunk {
    &fanout
        .relayed
        .iter()
        .find(|o| o.subscriber == peer)
        .unwrap_or_else(|| panic!("no relayed chunk for {peer}"))
        .sealed
}

// ─── 1. a third joins mid-stream ────────────────────────────────────

/// **The load-bearing acceptance.** A two-member call is carrying media
/// when a third joins. The epoch advances, every address moves with it,
/// and the subscriber that was already receiving KEEPS receiving across
/// the rotation — same transit key, same continuing `link_seq`, no
/// re-dial.
///
/// This is the whole point of make-before-break, asserted on the real
/// byte path rather than on a flag: the second chunk is opened by a
/// session that derived its DEK from the Commit, at a `link_seq` that
/// continued from the first chunk. A rotation that tore the link down
/// would fail the open.
// A single acceptance narrative, deliberately not split: each assertion
// only means anything in sequence after the ones above it.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_third_member_joins_mid_stream_and_the_existing_subscriber_keeps_receiving() {
    let mut call = TestCall::open(0xA1);
    let t0 = call.t0;
    // The address the call was opened at, before anyone joined.
    let addr_at_open = *call.spine.own_address().as_bytes();

    // ── two members, one carrying media ──────────────────────────────
    let (mut alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let _subscribed = call
        .spine
        .subscribe(
            &alice.key_id,
            alice.transit_key,
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect("alice subscribes");

    let addr_before = *call.spine.own_address().as_bytes();
    let relay_before = call.relay_address();
    assert_eq!(
        relay_before, addr_before,
        "the relay SENDS from this node's scoped address — one value, not two \
         conventions that can drift",
    );

    let first = call
        .spine
        .publish(b"frame-before-the-join", t0)
        .await
        .expect("publish");
    assert_eq!(first.relayed.len(), 1, "one sealed chunk for alice");
    assert_eq!(
        alice.open(chunk_for(&first, "peer-alice")),
        b"frame-before-the-join",
        "alice receives the pre-rotation chunk byte-intact",
    );

    // ── a third member joins mid-stream ──────────────────────────────
    let epoch_before = call.spine.epoch();
    let (_bob, ticket) = call.join("peer-bob", [0x22u8; 32], t0);

    assert!(
        ticket.readdressed.epoch > epoch_before.0,
        "the join must advance the MLS epoch",
    );
    assert_eq!(
        ticket.readdressed.derived, 3,
        "all three members' addresses are derived at the new epoch",
    );
    assert!(
        ticket.readdressed.relay_window_moved,
        "a relaying node's answerable window must move with the epoch",
    );
    assert_eq!(
        ticket.readdressed.relay_evicted_early,
        Some(addr_at_open),
        "two joins inside one convergence window is ordinary; the relay holds ONE \
         superseded address, so the oldest leaves the window and the outcome SAYS \
         so rather than asserting it away",
    );

    // ── the addresses MOVED ──────────────────────────────────────────
    let addr_after = *call.spine.own_address().as_bytes();
    assert_ne!(
        addr_after, addr_before,
        "an epoch bump re-derives every member's address, including ours",
    );
    assert_eq!(
        call.relay_address(),
        addr_after,
        "the relay's send address moved onto the new epoch",
    );
    assert!(
        call.sink.registered().contains(&addr_after),
        "the new address is REGISTERED with the transport — an unregistered \
         destination is never delivered to, with no error anywhere",
    );
    assert_eq!(
        ticket.dial_address.as_bytes(),
        &addr_after,
        "the ticket hands the joiner the address it must actually dial",
    );
    assert!(
        ticket.joiner_address.is_some(),
        "the joiner's own address is derived here too — we dial it",
    );

    // ── ...and nothing was broken to move them ───────────────────────
    assert!(
        call.relay_answers(&addr_before),
        "make-before-break: the relay still ANSWERS on the superseded address, so a \
         peer mid-dial is not stranded",
    );
    assert!(call.relay_answers(&addr_after));
    assert!(
        call.table.accepts_inbound(&addr_before).is_some(),
        "the table also still attributes the superseded address",
    );
    assert!(call.table.accepts_inbound(&addr_after).is_some());
    let retired = call.sink.retired();
    assert!(
        !retired.contains(&addr_before) && !retired.contains(&addr_after),
        "neither the superseded address nor the live one is retired before the \
         convergence window elapses: {retired:?}",
    );
    assert_eq!(
        retired,
        vec![addr_at_open],
        "the ONE address retired is the one the second rotation pushed out of the \
         window early — leaving it registered would keep a destination routable that \
         the table no longer attributes",
    );

    // ── the existing subscriber KEEPS receiving ──────────────────────
    // Alice applies the Commit and derives the new epoch's DEK — the
    // same 32 bytes the publisher rotated to (RFC 9420 §8.5).
    alice.dek = alice
        .session
        .process_commit(&ticket.commit_bytes)
        .expect("alice applies the Commit");

    let second = call
        .spine
        .publish(b"frame-after-the-join", t0)
        .await
        .expect("publish across the rotation");
    assert_eq!(
        second.relayed.len(),
        1,
        "alice is STILL on the relay roster after the rotation — a rotation that \
         dropped her would be a dropped live stream",
    );
    assert_eq!(
        alice.link_seq, 1,
        "alice's link_seq continued rather than resetting — the link was never \
         re-dialled, which is what 'a link is keyed by LinkId' buys",
    );
    assert_eq!(
        alice.open(chunk_for(&second, "peer-alice")),
        b"frame-after-the-join",
        "the post-rotation chunk opens on the SAME link at the CONTINUED link_seq",
    );
    assert_eq!(second.epoch.0, ticket.readdressed.epoch);
}

// ─── 2. heal ────────────────────────────────────────────────────────

/// A dropped subscriber is healed and the roster converges — each of the
/// three convergences named, never inferred.
// A single acceptance narrative, deliberately not split: each assertion
// only means anything in sequence after the ones above it.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn a_dropped_subscriber_is_healed_and_the_roster_converges() {
    let mut call = TestCall::open(0xB2);
    let t0 = call.t0;
    let (mut alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let (bob, bob_ticket) = call.join("peer-bob", [0x22u8; 32], t0);
    alice.dek = alice
        .session
        .process_commit(&bob_ticket.commit_bytes)
        .expect("alice applies bob's Commit");
    for peer in [&alice, &bob] {
        let _subscribed = call
            .spine
            .subscribe(
                &peer.key_id,
                peer.transit_key,
                ReceiverLayerPolicy::UNCAPPED,
                t0,
            )
            .expect("subscribe");
    }
    assert_eq!(call.spine.health().relay_subscribers, 2);

    // ── a recoverable drop: re-key the hop, do NOT move the epoch ────
    let epoch_before = call.spine.epoch();
    let addr_before = *call.spine.own_address().as_bytes();
    let healed = call
        .spine
        .heal(
            SubscriberDrop {
                subscriber: alice.key_id.clone(),
                cause: DropCause::LinkFailure,
                redial: Some(Redial {
                    transit_key: [0xAAu8; 32],
                    layer_policy: ReceiverLayerPolicy::UNCAPPED,
                }),
            },
            t0,
        )
        .expect("heal a link failure");
    assert_eq!(
        healed,
        HealOutcome::Readmitted {
            subscriber: "peer-alice".to_owned(),
            epoch: epoch_before,
        },
    );
    assert_eq!(
        call.spine.epoch(),
        epoch_before,
        "a flaky link must NOT churn every member's address",
    );
    assert_eq!(*call.spine.own_address().as_bytes(), addr_before);
    assert_eq!(call.spine.health().relay_subscribers, 2, "roster converged");

    // The re-dial actually took: the hop is on the NEW transit key, from
    // link_seq 0 (a re-dial is a new link).
    alice.transit_key = [0xAAu8; 32];
    alice.link_seq = 0;
    let fanout = call.spine.publish(b"post-heal", t0).await.expect("publish");
    assert_eq!(
        alice.open(chunk_for(&fanout, "peer-alice")),
        b"post-heal",
        "the re-admitted hop carries media on its fresh transit key",
    );

    // ── a departure: forward secrecy, so the epoch AND the addresses move
    let evicted = call
        .spine
        .heal(
            SubscriberDrop {
                subscriber: bob.key_id.clone(),
                cause: DropCause::Departed,
                redial: None,
            },
            t0,
        )
        .expect("heal a departure");
    let HealOutcome::Evicted {
        was_subscribed,
        readdressed,
        ..
    } = &evicted
    else {
        panic!("a departure must evict, got {evicted:?}");
    };
    assert!(was_subscribed, "bob was on the relay roster");
    assert!(
        readdressed.epoch > epoch_before.0,
        "an eviction moves the epoch",
    );
    assert!(readdressed.relay_window_moved);
    assert_ne!(
        *call.spine.own_address().as_bytes(),
        addr_before,
        "an eviction re-addresses the call exactly as a join does",
    );
    assert!(
        !call.spine.is_member("peer-bob"),
        "the departed member is out of the MLS group — it must not hold the DEK \
         that seals the next chunk",
    );
    assert_eq!(
        call.spine.health().relay_subscribers,
        1,
        "the relay roster converged with the MLS roster",
    );
    assert_eq!(readdressed.derived, 2, "two members remain to address");

    // ── a second drop of the already-departed peer: pruned, not evicted
    let again = call
        .spine
        .heal(
            SubscriberDrop {
                subscriber: bob.key_id.clone(),
                cause: DropCause::LinkFailure,
                redial: Some(Redial {
                    transit_key: [0xBBu8; 32],
                    layer_policy: ReceiverLayerPolicy::UNCAPPED,
                }),
            },
            t0,
        )
        .expect("heal a non-member");
    assert_eq!(
        again,
        HealOutcome::RosterPruned {
            subscriber: "peer-bob".to_owned(),
            reason: PruneReason::NotAMember,
        },
        "a peer with no epoch DEK must never be re-admitted to the relay roster",
    );
}

/// A recoverable drop the caller cannot re-key is pruned with its own
/// reason — never left in the roster to be silently fanned to.
#[tokio::test]
async fn a_link_failure_with_no_redial_material_is_pruned_loudly() {
    let mut call = TestCall::open(0xB3);
    let t0 = call.t0;
    let (alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let _subscribed = call
        .spine
        .subscribe(
            &alice.key_id,
            alice.transit_key,
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect("subscribe");

    let out = call
        .spine
        .heal(
            SubscriberDrop {
                subscriber: alice.key_id.clone(),
                cause: DropCause::LinkFailure,
                redial: None,
            },
            t0,
        )
        .expect("heal");
    assert_eq!(
        out,
        HealOutcome::RosterPruned {
            subscriber: "peer-alice".to_owned(),
            reason: PruneReason::NoRedialOffered,
        },
    );
    assert_eq!(call.spine.health().relay_subscribers, 0);
    assert!(
        call.spine.is_member("peer-alice"),
        "pruning a hop must not evict the member — it can re-subscribe when it \
         re-dials",
    );
}

// ─── 3. the seal cadence ────────────────────────────────────────────

/// Seal runs on cadence and retires **exactly** the superseded address —
/// on both planes, on one deadline — and never the live one.
#[tokio::test]
async fn seal_runs_on_cadence_and_retires_exactly_the_superseded_address() {
    let mut call = TestCall::open(0xC3);
    let t0 = call.t0;
    let before = *call.spine.own_address().as_bytes();
    assert_eq!(
        call.spine.seal_deadline(),
        None,
        "a call with no rotation has no deadline to wait on",
    );

    let (_alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let after = *call.spine.own_address().as_bytes();
    assert_ne!(before, after);
    assert_eq!(
        call.spine.seal_deadline(),
        Some(t0 + CONVERGENCE),
        "the rotation armed exactly one deadline, on the monotonic clock",
    );

    // ── too early: sealing now cuts off any peer that has not re-keyed
    let early = call.spine.seal_due(
        t0 + CONVERGENCE
            .checked_sub(Duration::from_secs(1))
            .expect("window > 1s"),
    );
    assert_eq!(early, SpineSeal::default(), "nothing is due yet");
    assert!(call.relay_answers(&before), "the relay still answers");
    assert!(call.table.accepts_inbound(&before).is_some());
    assert!(call.sink.retired().is_empty());

    // ── the window closes ────────────────────────────────────────────
    let sealed = call.spine.seal_due(t0 + CONVERGENCE);
    assert_eq!(
        sealed,
        SpineSeal {
            sealed: true,
            unretired: false,
            relay_retired: Some(before),
            table_refused: false,
        },
        "the seal names the ONE address it dropped",
    );
    assert_eq!(
        call.sink.retired(),
        vec![before],
        "exactly the superseded destination is retired from the transport",
    );

    // ── the live address survives, on both planes ────────────────────
    assert!(
        !call.relay_answers(&before),
        "a sealed address is no longer answered — that is what stops new probes",
    );
    assert!(
        call.relay_answers(&after),
        "the LIVE address must survive the seal",
    );
    assert_eq!(
        call.relay_address(),
        after,
        "a seal must never move the send address",
    );
    assert!(call.table.accepts_inbound(&before).is_none());
    assert!(
        call.table.accepts_inbound(&after).is_some(),
        "the table's live epoch must survive the seal",
    );

    // ── idempotent, and the deadline is disarmed ─────────────────────
    assert_eq!(call.spine.seal_deadline(), None);
    assert_eq!(
        call.spine.seal_due(t0 + CONVERGENCE * 2),
        SpineSeal::default(),
        "sealing twice must not strand the live address",
    );
    assert!(call.relay_answers(&after));
}

/// The cadence is owned by the spine, not by the caller: an ordinary
/// verb closes a window that has come due, with no timer anywhere.
#[tokio::test]
async fn an_ordinary_verb_closes_a_window_that_has_come_due() {
    let mut call = TestCall::open(0xC4);
    let t0 = call.t0;
    let before = *call.spine.own_address().as_bytes();
    let (_alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    assert!(call.spine.seal_deadline().is_some());

    // No explicit seal call anywhere — just media, at a later instant.
    let fanout = call
        .spine
        .publish(b"traffic", t0 + CONVERGENCE)
        .await
        .expect("publish");
    assert!(
        fanout.sealed.sealed,
        "publishing past the deadline closed the window: a call carrying media \
         needs no timer to converge",
    );
    assert_eq!(fanout.sealed.relay_retired, Some(before));
    assert_eq!(call.spine.seal_deadline(), None);
    assert!(!call.relay_answers(&before));
}

// ─── 4. a failed address install ────────────────────────────────────

/// An epoch advance whose address install fails must not leave the call
/// half-live.
///
/// The MLS commit cannot be undone, so the test asserts the property
/// that IS achievable: the two address planes still agree with each
/// other, the relay never starts answering (or sending) on an address
/// the table never registered, the degradation is named, and the live
/// stream is not dropped to achieve any of it.
// A single acceptance narrative, deliberately not split: each assertion
// only means anything in sequence after the ones above it.
#[allow(clippy::too_many_lines)]
#[tokio::test]
async fn an_epoch_advance_whose_address_install_fails_does_not_leave_the_call_half_live() {
    let mut call = TestCall::open(0xD4);
    let t0 = call.t0;
    let (alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let _subscribed = call
        .spine
        .subscribe(
            &alice.key_id,
            alice.transit_key,
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect("alice subscribes");

    let own_before = *call.spine.own_address().as_bytes();
    let relay_before = call.relay_address();
    let superseded_before = call
        .spine
        .relay()
        .expect("relays")
        .superseded_address()
        .map(|d| *d.as_bytes());
    let registered_before = call.sink.registered().len();

    // The transport refuses to listen on the next epoch's address.
    call.sink.refuse_next(true);
    let err = call
        .try_join("peer-bob", t0)
        .expect_err("a join whose address install fails must surface");
    let AvSpineError::AddressStranded(stranded) = &err else {
        panic!("expected AddressStranded, got {err:?}");
    };
    assert!(stranded.reason.contains("registering"), "{stranded:?}");

    // ── the relay window did NOT move ────────────────────────────────
    assert_eq!(
        call.relay_address(),
        relay_before,
        "the relay must not SEND from an address the transport never registered",
    );
    assert_eq!(
        call.spine
            .relay()
            .expect("relays")
            .superseded_address()
            .map(|d| *d.as_bytes()),
        superseded_before,
        "the relay's rotation window must be UNCHANGED — an install with no activate \
         is the state that silently loses an epoch, and an install+activate would \
         make it send from an address the transport never registered",
    );
    assert!(
        call.relay_answers(&relay_before),
        "the relay still answers where it always did",
    );
    assert_eq!(
        *call.spine.own_address().as_bytes(),
        own_before,
        "the spine's notion of its own address must not advance past what is \
         actually registered",
    );
    assert_eq!(
        call.sink.registered().len(),
        registered_before,
        "nothing new was registered",
    );

    // ── the degradation is a named state, not a log line ─────────────
    let health = call.spine.health();
    assert_eq!(health.stranded.as_ref(), Some(stranded));
    let mut expected_answers = vec![relay_before];
    expected_answers.extend(superseded_before);
    assert_eq!(
        health.relay_answers, expected_answers,
        "the relay's answerable set is exactly what it was before the failed \
         advance — the planes agree",
    );

    // ── the call refuses to GROW ─────────────────────────────────────
    let refused = call
        .spine
        .subscribe(
            &"peer-alice".to_owned(),
            [0x99u8; 32],
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect_err("a stranded call must not hand out addresses that answer nowhere");
    assert!(
        matches!(
            refused,
            AvSpineError::Stranded {
                verb: "subscribe",
                ..
            }
        ),
        "{refused:?}",
    );
    assert!(
        matches!(
            call.try_join("peer-carol", t0),
            Err(AvSpineError::Stranded { verb: "join", .. })
        ),
        "a stranded call must not admit a joiner it cannot be dialled by",
    );

    // ── ...but it does NOT drop the live stream ──────────────────────
    // Alice's link was dialled while she was legitimately in the group
    // and is keyed by LinkId; cutting it to signal an addressing fault
    // would be the one thing make-before-break exists to prevent.
    let fanout = call
        .spine
        .publish(b"still-serving", t0)
        .await
        .expect("a stranded call still serves its live links");
    assert_eq!(
        fanout.relayed.len(),
        1,
        "alice is still fanned to across the degradation",
    );
    assert_eq!(
        fanout.stranded.as_ref(),
        Some(stranded),
        "every publish carries the degradation forward — it never goes quiet",
    );
}

// ─── structural properties ──────────────────────────────────────────

/// The relay is born AT the installed scoped address. There is no window
/// in which it answers on a bootstrap address the table never installed,
/// because there is no constructor that can put it there.
#[tokio::test]
async fn a_relay_is_born_at_the_installed_scoped_address() {
    let call = TestCall::open(0xE5);
    let own = *call.spine.own_address().as_bytes();
    assert_eq!(call.relay_address(), own);
    assert!(
        call.table.accepts_inbound(&own).is_some(),
        "the address the relay answers on is one the table attributes",
    );
    assert_eq!(
        call.sink.registered(),
        vec![own],
        "and one the transport is listening on — exactly one, ours",
    );
    assert_eq!(
        call.spine.health().relay_answers,
        vec![own],
        "one answerable address outside a rotation window",
    );
}

/// A peer that is not in the MLS roster cannot become a relay
/// subscriber: it holds no epoch DEK, so every chunk sealed for it is
/// fan-out spent on ciphertext it can never open.
#[tokio::test]
async fn a_non_member_cannot_be_subscribed() {
    let mut call = TestCall::open(0xE6);
    let t0 = call.t0;
    let err = call
        .spine
        .subscribe(
            &"stranger".to_owned(),
            [0x11u8; 32],
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect_err("a stranger is not on the call");
    assert!(
        matches!(err, AvSpineError::NotAMember(ref p) if p == "stranger"),
        "{err:?}"
    );
    assert_eq!(call.spine.health().relay_subscribers, 0);
}

/// A node that publishes without relaying is a first-class shape: the
/// epoch still re-addresses, and the outcome says the relay window did
/// not move because there is no relay — not because the move was
/// forgotten.
#[tokio::test]
async fn a_non_relaying_node_still_re_addresses_and_says_so() {
    let mut call = TestCall::open_with(0xE7, false);
    let t0 = call.t0;
    assert!(call.spine.relay().is_none());
    let before = *call.spine.own_address().as_bytes();

    let (_alice, ticket) = call.join("peer-alice", [0x11u8; 32], t0);
    assert!(
        !ticket.readdressed.relay_window_moved,
        "no relay to move — reported, not silently true",
    );
    assert_ne!(*call.spine.own_address().as_bytes(), before);
    assert!(call.table.accepts_inbound(&before).is_some());

    // A relay verb on a non-relaying node is a named refusal.
    let err = call
        .spine
        .subscribe(
            &"peer-alice".to_owned(),
            [0x11u8; 32],
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect_err("no relay");
    assert!(matches!(err, AvSpineError::NoRelay(_)), "{err:?}");

    // The seal still runs, on the plane that exists.
    let sealed = call.spine.seal_due(t0 + CONVERGENCE);
    assert_eq!(
        sealed,
        SpineSeal {
            sealed: true,
            unretired: false,
            relay_retired: None,
            table_refused: false,
        },
    );
    assert!(call.table.accepts_inbound(&before).is_none());
}

/// One inner seal feeds both fan-out legs. Sealing twice would re-derive
/// the same `(stream, epoch, chunk_seq)` inner nonce for a second
/// ciphertext, so the sequence must advance once per chunk no matter how
/// many legs it rides.
#[tokio::test]
async fn one_chunk_is_inner_sealed_once_for_both_legs() {
    let mut call = TestCall::open(0xE8);
    let t0 = call.t0;
    let (alice, _) = call.join("peer-alice", [0x11u8; 32], t0);
    let _subscribed = call
        .spine
        .subscribe(
            &alice.key_id,
            alice.transit_key,
            ReceiverLayerPolicy::UNCAPPED,
            t0,
        )
        .expect("subscribe");

    let a = call.spine.publish(b"one", t0).await.expect("publish");
    let b = call.spine.publish(b"two", t0).await.expect("publish");
    assert_eq!(a.chunk_seq.0, 0);
    assert_eq!(b.chunk_seq.0, 1, "one seq per chunk, not one per leg");
    assert_eq!(a.relay.reached(), 1);
    assert_eq!(
        a.direct,
        LegOutcome::Idle,
        "this node relays rather than dialling a remote relay",
    );
    assert_eq!(a.relay_withheld, 0);
    // The relay's own sealed output is ciphertext under a DEK it does
    // not hold: the same inner ciphertext rides both legs.
    assert_ne!(
        chunk_for(&a, "peer-alice").double_sealed_ciphertext,
        chunk_for(&b, "peer-alice").double_sealed_ciphertext,
    );
}
