//! **CIRISEdge#930 — the key-plane listings are computed once and served
//! many, and a new row is never hidden by the memo.**
//!
//! Over real sqlite directories and the real bridge:
//!
//! - **equivalence** — for a store with many subjects (a revoked key, an
//!   occurrence and its `withdraws`, a carrier, held keys with nothing, and
//!   ids the store has never seen), each of the four key-plane listings
//!   returns exactly the refs the pre-#930 per-subject loop returns
//!   ([`oracle`], that loop kept verbatim), on the fill AND on the memo;
//! - **invalidation** — after a revocation arrives through the replication
//!   choke, and after a revocation, a `withdraws` and a carrier are written
//!   LOCALLY (bypassing the choke, CIRISEdge#858's shape), the next listing
//!   carries them;
//! - **cost** — under a counting directory, N peers' rounds between two
//!   writes cost one fill, and a round after the fill costs the same handful
//!   of reads whatever |Global| is.
//!
//! `cargo test --lib key_plane_memo_930`

use std::collections::BTreeSet;
use std::sync::Arc;

use ciris_persist::federation::types::SignedRevocation;
use ciris_persist::federation::FederationDirectory;

use super::counting_directory_930::CountingDirectory;
use super::key_plane_v59_tests::{round, self_revocation, NodeA};
use super::park_fresh_858_tests::{hold, substrate, Ident};
use crate::observability as obs;
use crate::replication::{
    BridgeConfig, EnvelopeKind, EnvelopeRef, FederationDirectoryReplicationBridge,
    ReplicationDirectory,
};

/// The four key-plane session planes.
const PLANES: [EnvelopeKind; 4] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::Revocation,
    EnvelopeKind::IdentityOccurrenceRevocation,
];

/// v45 (CIRISEdge#971) — the feed's probe spacing every bridge here runs
/// with: longer than any test, so "inside the spacing" is deterministic and
/// no assertion rests on a clock. A write that bypasses the choke reaches a
/// listing at once only through a door that marks the feed dirty, which is
/// how a host reports it (its kick reaches `invalidate_send_set_memos`).
const NO_TEST_OUTLIVES: std::time::Duration = std::time::Duration::from_secs(3600);

/// A bridge over `dir` whose self set and cohort are both `subjects` (so
/// `Global` = self ∪ cohort carries every subject TWICE, as production's
/// concatenation can).
fn bridge_over(
    dir: Arc<dyn FederationDirectory>,
    subjects: &[String],
    metrics: Option<obs::EdgeMetrics>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let cohort = subjects.to_vec();
    let own = subjects.to_vec();
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            dir,
            Arc::new(move || cohort.clone()),
            BridgeConfig {
                feed_probe_spacing: NO_TEST_OUTLIVES,
                ..BridgeConfig::default()
            },
        )
        .with_self_provider(Some(Arc::new(move || own.clone())))
        .with_metrics(metrics),
    )
}

/// **THE ORACLE** — the pre-#930 listing, kept verbatim: every subject of
/// the plane's set (duplicates included, as the old loop walked them), each
/// read with its per-subject read, then hashed and deduped as
/// `key_plane_refs` does. A failed read contributes nothing.
pub(super) async fn oracle(
    kind: EnvelopeKind,
    dir: &dyn FederationDirectory,
    subjects: &[String],
) -> BTreeSet<(Vec<u8>, u64)> {
    let mut rows = Vec::new();
    // Global = self ∪ cohort: the subject list twice.
    let walk: Vec<&String> = match kind {
        EnvelopeKind::Revocation | EnvelopeKind::IdentityOccurrenceRevocation => {
            subjects.iter().chain(subjects.iter()).collect()
        }
        _ => subjects.iter().collect(),
    };
    for subject in walk {
        let found = match kind {
            EnvelopeKind::Key => super::key_plane_rows::key_record_rows(dir, subject).await,
            EnvelopeKind::IdentityOccurrence => {
                super::key_plane_rows::occurrence_rows_binding(dir, subject).await
            }
            EnvelopeKind::Revocation => {
                super::key_plane_rows::revocation_rows_of(dir, subject).await
            }
            _ => super::key_plane_rows::occurrence_withdrawals_binding(dir, subject).await,
        };
        if let Ok(found) = found {
            rows.extend(found);
        }
    }
    rows.into_iter()
        .map(|row| {
            let bytes = serde_json::to_vec(&row).expect("encode");
            let hash: [u8; 32] = <sha2::Sha256 as sha2::Digest>::digest(&bytes).into();
            (
                hash.to_vec(),
                u64::try_from(row.asserted_at.timestamp_millis()).unwrap_or(0),
            )
        })
        .collect()
}

pub(super) fn as_set(refs: &[EnvelopeRef]) -> BTreeSet<(Vec<u8>, u64)> {
    let set: BTreeSet<_> = refs
        .iter()
        .map(|r| (r.envelope_hash.to_vec(), r.seq))
        .collect();
    assert_eq!(set.len(), refs.len(), "a listing never offers a hash twice");
    set
}

/// The store the witnesses share: NodeA (P's occurrence of N, with its
/// `withdraws` when `withdrawn`, K's self-revocation, a carrier revoking N's
/// occurrence K),
/// `held` more keys with nothing on any revocation plane, and `ghosts` ids
/// the store has never seen. Returns the fixture and the subject list.
async fn world(
    tag: &str,
    seed: u8,
    withdrawn: bool,
    held: usize,
    ghosts: usize,
) -> (NodeA, Vec<Ident>, Vec<String>) {
    let a = NodeA::build(tag, seed).await;
    if withdrawn {
        a.withdraw_occurrence().await;
    }
    a.carrier_revoking_node_occurrence(a.k.key_id()).await;
    let mut extra = Vec::new();
    for i in 0..held {
        let id = Ident::mint(
            &format!("held-{tag}-{i}"),
            "node",
            seed.wrapping_add(16)
                .wrapping_add(u8::try_from(i).expect("small")),
        )
        .await;
        hold(&a.dir, &id).await;
        extra.push(id);
    }
    let mut subjects: Vec<String> = [&a.p, &a.n, &a.k]
        .into_iter()
        .chain(extra.iter())
        .map(|id| id.key_id().to_owned())
        .collect();
    subjects.extend((0..ghosts).map(|i| format!("ghost-{tag}-{i}")));
    (a, extra, subjects)
}

/// **Equivalence.** Each of the four listings equals the per-subject oracle
/// — on the fill, and again when served from the memo — and none is vacuous.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn each_key_plane_listing_equals_the_per_subject_oracle_930() {
    let (a, _extra, subjects) = world("eq930", 0x11, true, 4, 24).await;
    let dir: Arc<dyn FederationDirectory> = Arc::clone(&a.dir) as _;
    let bridge = bridge_over(Arc::clone(&dir), &subjects, None);
    for kind in PLANES {
        let want = oracle(kind, &*dir, &subjects).await;
        assert!(
            !want.is_empty(),
            "{kind:?}: the fixture puts a row on every plane"
        );
        let fill = bridge.list_envelope_refs(kind).await;
        assert_eq!(as_set(&fill), want, "{kind:?}: the fill equals the oracle");
        let memo = bridge.list_envelope_refs(kind).await;
        assert_eq!(as_set(&memo), want, "{kind:?}: the memo equals the oracle");
    }
    // The occurrence-revocation plane carries BOTH shapes: the withdraws and
    // the carrier (two rows), and the Revocation plane K's one row.
    assert_eq!(
        oracle(EnvelopeKind::IdentityOccurrenceRevocation, &*dir, &subjects)
            .await
            .len(),
        2
    );
    assert_eq!(
        oracle(EnvelopeKind::Revocation, &*dir, &subjects)
            .await
            .len(),
        1
    );
}

/// **Invalidation through the choke.** S holds K's key and has listed its
/// Revocation plane (memoized: K has nothing). A's revocation of K then
/// arrives over a replication round, through S's apply choke; S's next
/// listing carries it and equals the oracle.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replicated_revocation_is_in_the_next_listing_930() {
    let a = NodeA::build("rep930", 0x21).await;
    let s_ident = Ident::mint("node-s-rep930", "node", 0x2a).await;
    let s_dir = substrate().await;
    hold(&s_dir, &s_ident).await;
    hold(&s_dir, &a.k).await;
    let subjects = vec![s_ident.key_id().to_owned(), a.k.key_id().to_owned()];
    let metrics = obs::EdgeMetrics::new();
    let s = bridge_over(
        Arc::clone(&s_dir) as Arc<dyn FederationDirectory>,
        &subjects,
        Some(metrics.clone()),
    );
    assert!(s
        .list_envelope_refs(EnvelopeKind::Revocation)
        .await
        .is_empty());
    assert!(s
        .list_envelope_refs(EnvelopeKind::Revocation)
        .await
        .is_empty());
    assert!(
        metrics
            .key_plane_sweep()
            .get(obs::KEY_PLANE_MEMO_HITS)
            .copied()
            >= Some(2),
        "precondition: the second listing was served from the memo"
    );

    let a_bridge = bridge_over(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        &[
            a.p.key_id().to_owned(),
            a.n.key_id().to_owned(),
            a.k.key_id().to_owned(),
        ],
        None,
    );
    round(
        EnvelopeKind::Revocation,
        &a_bridge,
        a.n.key_id(),
        &s,
        s_ident.key_id(),
    )
    .await;
    assert_eq!(
        s_dir
            .revocations_for(a.k.key_id())
            .await
            .expect("read")
            .len(),
        1,
        "precondition: S admitted K's revocation"
    );

    let after = s.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(after.len(), 1, "the admitted revocation is offered on");
    assert_eq!(
        as_set(&after),
        oracle(EnvelopeKind::Revocation, &*s_dir, &subjects).await
    );
}

/// **Invalidation by LOCAL writes** (the doors that bypass the choke): a
/// revocation authored through `put_revocation`, a `withdraws` and a carrier
/// written straight into the directory. After each, and the host's report of
/// it (the door its kick reaches, v45 CIRISEdge#971), the next listing of its
/// plane equals the oracle and carries the new row. The first write is also
/// listed BEFORE its report: inside the probe spacing the listing is the
/// memo's (the stated staleness bound, a key-plane offer one round late).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_local_write_is_in_the_next_listing_930() {
    let a = NodeA::build("loc930", 0x31).await;
    let e = Ident::mint("held-loc930", "node", 0x3a).await;
    hold(&a.dir, &e).await;
    let subjects: Vec<String> = [&a.p, &a.n, &a.k, &e]
        .into_iter()
        .map(|id| id.key_id().to_owned())
        .collect();
    let dir: Arc<dyn FederationDirectory> = Arc::clone(&a.dir) as _;
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_over(Arc::clone(&dir), &subjects, Some(metrics.clone()));

    // Fill both planes and serve each once from the memo.
    for kind in [
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
    ] {
        bridge.list_envelope_refs(kind).await;
        bridge.list_envelope_refs(kind).await;
    }
    let before_rev = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    let before_occ = bridge
        .list_envelope_refs(EnvelopeKind::IdentityOccurrenceRevocation)
        .await;
    assert_eq!(before_rev.len(), 1, "K's revocation only");
    assert!(before_occ.is_empty(), "nothing withdrawn yet");

    // 1. A revocation of E, authored LOCALLY.
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    let unreported = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        unreported.len(),
        1,
        "inside the spacing an unreported write is not probed for (CIRISEdge#971)"
    );
    bridge.invalidate_send_set_memos("host_kick");
    let rev = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(rev.len(), 2, "E's new revocation is offered");
    assert_eq!(
        as_set(&rev),
        oracle(EnvelopeKind::Revocation, &*dir, &subjects).await
    );

    // 2. P's `withdraws` of its occurrence of N, written into the directory.
    a.withdraw_occurrence().await;
    bridge.invalidate_send_set_memos("host_kick");
    let occ = bridge
        .list_envelope_refs(EnvelopeKind::IdentityOccurrenceRevocation)
        .await;
    assert_eq!(occ.len(), 1, "the withdraws is offered");
    assert_eq!(
        as_set(&occ),
        oracle(EnvelopeKind::IdentityOccurrenceRevocation, &*dir, &subjects).await
    );

    // 3. A carrier revoking N's occurrence K, written into the directory.
    a.carrier_revoking_node_occurrence(a.k.key_id()).await;
    bridge.invalidate_send_set_memos("host_kick");
    let occ = bridge
        .list_envelope_refs(EnvelopeKind::IdentityOccurrenceRevocation)
        .await;
    assert_eq!(occ.len(), 2, "the carrier is offered");
    assert_eq!(
        as_set(&occ),
        oracle(EnvelopeKind::IdentityOccurrenceRevocation, &*dir, &subjects).await
    );
    assert!(
        metrics
            .key_plane_sweep()
            .get(obs::KEY_PLANE_INVALIDATED)
            .copied()
            >= Some(1),
        "the memo dropped answers: {:?}",
        metrics.key_plane_sweep()
    );
}

/// The store reads of one counting window, minus the change probe.
fn subject_reads(dir: &CountingDirectory) -> usize {
    dir.total() - dir.count("list_attestations_since")
}

/// **Cost.** Under a counting directory: the first round fills each Global
/// plane (reads scale with |Global|); eight more peers' rounds between two
/// writes read NOTHING (v45, CIRISEdge#971: no subject read, and inside the
/// probe spacing no change probe either; before v45, one probe per listing),
/// whatever |Global| is; a reported `withdraws` then costs one probe and the
/// re-read of the one subject it names, not a sweep; and eight peers
/// arriving together on a fresh bridge share one fill.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[allow(clippy::too_many_lines)] // two widths, a write, and the concurrent fill
async fn n_peer_rounds_between_writes_cost_one_sweep_930() {
    let (a, _extra, subjects) = world("cost930", 0x41, false, 2, 60).await;
    let global = [
        EnvelopeKind::Revocation,
        EnvelopeKind::IdentityOccurrenceRevocation,
    ];
    let mut steady: Vec<usize> = Vec::new();
    for width in [subjects.len() / 4, subjects.len()] {
        let counting = CountingDirectory::new(Arc::clone(&a.dir) as Arc<dyn FederationDirectory>);
        let metrics = obs::EdgeMetrics::new();
        let bridge = bridge_over(
            Arc::new(counting.clone()) as Arc<dyn FederationDirectory>,
            &subjects[..width],
            Some(metrics.clone()),
        );
        for kind in global {
            bridge
                .list_envelope_refs_for_peer(kind, Some("peer-0"))
                .await;
        }
        let fill = subject_reads(&counting);
        assert!(
            fill >= 2 * width,
            "the fill reads every Global subject on both planes ({fill} reads, |Global| {width})"
        );
        counting.reset();
        for peer in 1..=8 {
            for kind in global {
                bridge
                    .list_envelope_refs_for_peer(kind, Some(&format!("peer-{peer}")))
                    .await;
            }
        }
        assert_eq!(
            subject_reads(&counting),
            0,
            "|Global| {width}: eight peers' rounds read no subject: {:?}",
            counting.counts()
        );
        assert_eq!(
            counting.count("list_attestations_since"),
            0,
            "|Global| {width}: an idle round probes nothing inside the spacing \
             (CIRISEdge#971; it was one probe per listing)"
        );
        steady.push(counting.total());
        let ledger = metrics.key_plane_sweep();
        assert_eq!(
            ledger.get(obs::KEY_PLANE_SWEEPS).copied(),
            Some(2),
            "{ledger:?}"
        );
        assert_eq!(
            ledger.get(obs::KEY_PLANE_SUBJECT_READS).copied(),
            Some(2 * u64::try_from(width).expect("small")),
            "the fill read each distinct subject once per plane (Global's \
             self ∪ cohort duplicate is read once): {ledger:?}"
        );

        // A write: P's withdraws of its occurrence of N, written locally. The
        // next round re-reads ONLY the subject it names (N), on the one plane
        // it changes.
        if width == subjects.len() {
            a.withdraw_occurrence().await;
            bridge.invalidate_send_set_memos("host_kick");
            counting.reset();
            let reads_before = metrics
                .key_plane_sweep()
                .get(obs::KEY_PLANE_SUBJECT_READS)
                .copied()
                .unwrap_or(0);
            let occ = bridge
                .list_envelope_refs_for_peer(
                    EnvelopeKind::IdentityOccurrenceRevocation,
                    Some("peer-9"),
                )
                .await;
            assert_eq!(occ.len(), 2, "the carrier and the new withdraws");
            let reads_after = metrics.key_plane_sweep()[obs::KEY_PLANE_SUBJECT_READS];
            assert_eq!(reads_after - reads_before, 1, "one subject (N) re-read");
        }
    }
    assert_eq!(
        steady[0],
        steady[1],
        "a round between writes costs the same at |Global| {} and {}",
        subjects.len() / 4,
        subjects.len()
    );

    // Eight peers at once on a fresh bridge: one fill, the rest wait for it.
    let metrics = obs::EdgeMetrics::new();
    let bridge = bridge_over(
        Arc::clone(&a.dir) as Arc<dyn FederationDirectory>,
        &subjects,
        Some(metrics.clone()),
    );
    let mut joins = Vec::new();
    for peer in 0..8 {
        let b = Arc::clone(&bridge);
        joins.push(tokio::spawn(async move {
            b.list_envelope_refs_for_peer(EnvelopeKind::Revocation, Some(&format!("peer-{peer}")))
                .await
        }));
    }
    for j in joins {
        j.await.expect("join");
    }
    let ledger = metrics.key_plane_sweep();
    assert_eq!(
        ledger.get(obs::KEY_PLANE_SWEEPS).copied(),
        Some(1),
        "{ledger:?}"
    );
    assert_eq!(
        ledger.get(obs::KEY_PLANE_SUBJECT_READS).copied(),
        Some(u64::try_from(subjects.len()).expect("small")),
        "{ledger:?}"
    );
}

/// **v45 (CIRISEdge#971) — the unreported write, at explicit instants.** A
/// write no edge door reports (the host writing to persist directly, the
/// CIRISEdge#858 shape) is the production case the probe spacing bounds:
///
/// 1. inside the spacing a listing does NOT carry it (the last drain vouches);
/// 2. once the last drain began a full spacing ago, the next listing does;
/// 3. a second unreported write, inside the new spacing, is not carried until
///    a door marks the feed dirty, and then at once.
///
/// The instants are set by ageing the feed's last drain, never by sleeping.
/// Mutants: the spacing ignored (step 1 lists the row), the dirt mark ignored
/// (step 3's last listing does not).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unreported_write_waits_out_the_spacing_and_a_mark_ends_the_wait_971() {
    let a = NodeA::build("unrep971", 0x35).await;
    let e = Ident::mint("held-unrep971", "node", 0x3c).await;
    let f = Ident::mint("held2-unrep971", "node", 0x3d).await;
    hold(&a.dir, &e).await;
    hold(&a.dir, &f).await;
    let subjects: Vec<String> = [&a.p, &a.n, &a.k, &e, &f]
        .into_iter()
        .map(|id| id.key_id().to_owned())
        .collect();
    let dir: Arc<dyn FederationDirectory> = Arc::clone(&a.dir) as _;
    let bridge = bridge_over(Arc::clone(&dir), &subjects, None);
    let before = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(before.len(), 1, "K's revocation only");

    // A revocation of E, written with no door told.
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");

    // 1. Inside the spacing.
    let inside = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        inside.len(),
        1,
        "inside the spacing an unreported write is not listed"
    );

    // 2. The last drain began a full spacing ago.
    bridge.age_feed(NO_TEST_OUTLIVES).await;
    let after = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        after.len(),
        2,
        "past the spacing the unreported write is listed"
    );
    assert_eq!(
        as_set(&after),
        oracle(EnvelopeKind::Revocation, &*dir, &subjects).await
    );

    // 3. A second unreported write, inside the spacing the probe above began.
    let revocation = self_revocation(&a.dir, &f).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    let inside = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(
        inside.len(),
        2,
        "inside the new spacing it is not listed yet"
    );
    bridge.mark_feed_dirty();
    let marked = bridge.list_envelope_refs(EnvelopeKind::Revocation).await;
    assert_eq!(marked.len(), 3, "a dirt mark lists it at once");
    assert_eq!(
        as_set(&marked),
        oracle(EnvelopeKind::Revocation, &*dir, &subjects).await
    );
}

/// A transport that answers nothing and hands every Revocation Summary it is
/// asked to send to the witness.
struct SummaryTap {
    summaries: tokio::sync::mpsc::UnboundedSender<Vec<EnvelopeRef>>,
}

#[async_trait::async_trait]
impl crate::transport::Transport for SummaryTap {
    fn id(&self) -> crate::transport::TransportId {
        crate::transport::TransportId::HTTP
    }
    async fn send(
        &self,
        _destination_key_id: &str,
        bytes: &[u8],
    ) -> Result<crate::transport::TransportSendOutcome, crate::transport::TransportError> {
        use super::protocol::ReplicationMessage;
        let msg = match super::wire_frame::try_unwrap_framed(bytes) {
            Ok(Some(framed)) => Some(framed.msg),
            _ => ReplicationMessage::from_bytes(bytes).ok(),
        };
        if let Some(ReplicationMessage::Summary(s)) = msg {
            if s.kind == EnvelopeKind::Revocation {
                let _ = self.summaries.send(s.refs);
            }
        }
        Ok(crate::transport::TransportSendOutcome::Delivered)
    }
    async fn listen(
        &self,
        _sink: tokio::sync::mpsc::Sender<crate::transport::InboundFrame>,
    ) -> Result<(), crate::transport::TransportError> {
        Ok(())
    }
}

/// **v45 (CIRISEdge#971) — a kick marks the feed dirty BEFORE the rounds it
/// fires ask.** The server reports every write with a kick of all peers
/// (`compose::kick_replication`, seventeen modules) and never with
/// `note_local_write`, so the kick is the production door. A running runtime,
/// one initiator peer on the Revocation plane, the probe spacing an hour: the
/// first round lists the store; the host writes a revocation and kicks; the
/// FIRST round the kick fires offers it, with no wait on the spacing (an hour)
/// or the memo TTL (ten minutes). With `mark_feed_dirty` removed from
/// `invalidate_send_set_memos`, or called after the scheduler's kick, the
/// kicked round's Summary lacks the row and this fails.
///
/// No sleep: each step waits on the next Summary the runtime sends. The peer
/// answers no plane, so the first-contact ladder never applies (it needs a
/// plane answered elsewhere) and no round runs between the two but the
/// kicked one (cadence an hour).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_kick_marks_the_feed_before_its_rounds_ask_971() {
    use crate::replication::runtime::{ReplicationRuntime, ReplicationRuntimeConfig};
    use crate::replication::scheduler::SchedulerConfig;
    use std::time::Duration;
    const PEER: &str = "kick971-peer";
    /// The bound on one Summary's arrival; an event wait, not a sleep.
    const ARRIVES_WITHIN: Duration = Duration::from_secs(30);

    let a = NodeA::build("kick971", 0x37).await;
    let e = Ident::mint("held-kick971", "node", 0x3e).await;
    hold(&a.dir, &e).await;
    let subjects: Vec<String> = [&a.p, &a.n, &a.k, &e]
        .into_iter()
        .map(|id| id.key_id().to_owned())
        .collect();
    let dir: Arc<dyn FederationDirectory> = Arc::clone(&a.dir) as _;
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let own = subjects.clone();
    let config = ReplicationRuntimeConfig {
        enable_bundle_bootstrap_peers: false,
        scheduler: SchedulerConfig {
            cadence: Duration::from_hours(1),
            round_timeout: Duration::from_millis(200),
            ..SchedulerConfig::default()
        },
        bridge: BridgeConfig {
            feed_probe_spacing: NO_TEST_OUTLIVES,
            ..BridgeConfig::default()
        },
        ..ReplicationRuntimeConfig::default()
    };
    let mut rt = ReplicationRuntime::start(
        Arc::clone(&dir),
        Arc::new(SummaryTap { summaries: tx }),
        vec![crate::replication::ReplicationPeer {
            peer_key_id: PEER.to_string(),
            kind: EnvelopeKind::Revocation,
        }],
        config,
        Some(Arc::new(move || own.clone())),
    )
    .await;

    // The first cadence tick fires at spawn: its listing fills the memo and
    // drains the feed.
    let first = tokio::time::timeout(ARRIVES_WITHIN, rx.recv())
        .await
        .expect("the first round's Summary")
        .expect("open");
    assert_eq!(first.len(), 1, "K's revocation only");

    // The host writes, then kicks every peer (its only report).
    let revocation = self_revocation(&a.dir, &e).await;
    a.dir
        .put_revocation(SignedRevocation { revocation })
        .await
        .expect("local revocation");
    rt.round_now_all().await.expect("kick all");

    let kicked = tokio::time::timeout(ARRIVES_WITHIN, rx.recv())
        .await
        .expect("the kicked round's Summary")
        .expect("open");
    assert_eq!(
        kicked.len(),
        2,
        "the first kicked round offers the row the kick reported"
    );
    let want = oracle(EnvelopeKind::Revocation, &*dir, &subjects).await;
    assert_eq!(as_set(&kicked), want);
    rt.shutdown().await;
}
