//! **Range fingerprints, step A: the passive receiver half over real
//! bridges** (`docs/design/RANGE_FINGERPRINTS.md` §9, §10.1 step A).
//!
//! Over real sqlite directories and the real bridge and `Session`:
//!
//! - **the mixed old/new pair**: a node with the receiver half on and a node
//!   with it off (the 45.1.9 wire) converge on the bootstrap planes exactly as
//!   two 45.1.9 nodes do, in both directions. The new node's markers are
//!   inert to the old one, and a pre-RF reader decodes the new node's
//!   Summary unchanged;
//! - **a fingerprinted Summary is answered** from the receiver's listed mirror:
//!   `list` while the mirror is empty, `match` once the sender has listed its
//!   range completely, `match` again on every idle root, and a difference the
//!   moment the sender's set gains a row the receiver lacks;
//! - **a salt that arrived over a non-confidential transport** is never used;
//! - **the compact members** (`rh`, `wh`, `xh`, `eb`) decode into the fields
//!   every consumer reads.
//!
//! `cargo test --lib rf_step_a`

use std::collections::HashSet;
use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::sqlite::SqliteBackend;

use super::key_plane_v59_tests::NodeA;
use super::park_fresh_858_tests::{hold, substrate, Ident};
use super::range_fp::{
    elem, encode_compact_body, encode_compact_hashes, encode_salt, in_prefix,
    mark_inbound_transport, node_fp, Acc, RfSummary, ALG_SALTED_SUM, RF_VERSION,
};
use crate::replication::{
    BridgeConfig, DirectoryStateAdapter, EnvelopeKind, EnvelopeRef,
    FederationDirectoryReplicationBridge, MutableDirectoryStateAdapter, ReplicationDirectory,
    ReplicationMessage, ReplicationOutcome, Session, SessionRole, SummaryMessage,
};

/// The `Summary` an old (pre-RF) build decodes: no `rf` member at all.
#[derive(serde::Deserialize)]
struct PreRfSummary {
    kind: EnvelopeKind,
    refs: Vec<EnvelopeRef>,
}

/// The `Diff` an old build decodes.
#[derive(serde::Deserialize)]
struct PreRfDiff {
    kind: EnvelopeKind,
    want: Vec<[u8; 32]>,
}

/// An old build's message enum, for the two verbs that carry `rf`.
#[derive(serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum PreRf {
    Summary(PreRfSummary),
    Diff(PreRfDiff),
}

const PLANES: [EnvelopeKind; 3] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
];

fn bridge_with(
    dir: &Arc<SqliteBackend>,
    me: &str,
    publish: Vec<String>,
    answer: bool,
) -> Arc<FederationDirectoryReplicationBridge> {
    let cohort = publish.clone();
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(dir) as Arc<dyn FederationDirectory>,
            Arc::new(move || cohort.clone()),
            BridgeConfig {
                range_fingerprints_answer: answer,
                ..BridgeConfig::default()
            },
        )
        .with_local_key_id(Some(me.to_owned()))
        .with_self_provider(Some(Arc::new(move || publish.clone()))),
    )
}

fn node_a_bridge(a: &NodeA, answer: bool) -> Arc<FederationDirectoryReplicationBridge> {
    bridge_with(
        &a.dir,
        a.n.key_id(),
        vec![
            a.p.key_id().to_owned(),
            a.n.key_id().to_owned(),
            a.k.key_id().to_owned(),
        ],
        answer,
    )
}

fn messages(outcome: ReplicationOutcome) -> Vec<ReplicationMessage> {
    match outcome {
        ReplicationOutcome::Send(msgs)
        | ReplicationOutcome::SendAndComplete { msgs, .. }
        | ReplicationOutcome::SendThenApplied { msgs, .. } => msgs,
        _ => Vec::new(),
    }
}

/// One round on `kind`, B initiating toward A, every frame through its wire
/// form (`to_bytes` / `from_bytes`, the compact decode included). Returns
/// what A sent and what B sent.
async fn round_on_the_wire(
    kind: EnvelopeKind,
    a: &Arc<FederationDirectoryReplicationBridge>,
    a_id: &str,
    b: &Arc<FederationDirectoryReplicationBridge>,
    b_id: &str,
) -> (Vec<ReplicationMessage>, Vec<ReplicationMessage>) {
    let wire =
        |m: ReplicationMessage| ReplicationMessage::from_bytes(&m.to_bytes()).expect("decodes");
    let dir_a: Arc<dyn ReplicationDirectory> = Arc::clone(a) as _;
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(b) as _;
    let prov_a = DirectoryStateAdapter::new(Arc::clone(&dir_a)).with_peer(b_id);
    let prov_b = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a_id);
    let app_a = MutableDirectoryStateAdapter::new(dir_a);
    let app_b = MutableDirectoryStateAdapter::new(dir_b);
    let mut sa = Session::new(SessionRole::Responder, kind);
    let mut sb = Session::new(SessionRole::Initiator, kind);
    let (mut from_a, mut from_b) = (Vec::new(), Vec::new());
    let mut to_a: Vec<ReplicationMessage> = messages(sb.start_round(&prov_b).await)
        .into_iter()
        .map(wire)
        .collect();
    for _ in 0..8 {
        from_b.extend(to_a.iter().cloned());
        let mut to_b = Vec::new();
        for m in to_a.drain(..) {
            to_b.extend(
                messages(sa.on_message(m, &prov_a, &app_a, Some(b_id)).await)
                    .into_iter()
                    .map(wire),
            );
        }
        if to_b.is_empty() {
            break;
        }
        from_a.extend(to_b.iter().cloned());
        for m in to_b {
            to_a.extend(
                messages(sb.on_message(m, &prov_b, &app_b, Some(a_id)).await)
                    .into_iter()
                    .map(wire),
            );
        }
        if to_a.is_empty() {
            break;
        }
    }
    (from_a, from_b)
}

fn rf_markers(msgs: &[ReplicationMessage]) -> (usize, usize, usize) {
    let (mut with, mut salted, mut total) = (0, 0, 0);
    for m in msgs {
        let rf = match m {
            ReplicationMessage::Summary(s) => {
                total += 1;
                s.rf.as_ref().map(RfSummary::is_fingerprinted)
            }
            ReplicationMessage::Diff(d) => {
                total += 1;
                d.rf.as_ref().map(|_| false)
            }
            _ => None,
        };
        if let Some(fp) = rf {
            with += 1;
            if fp {
                salted += 1;
            }
        }
    }
    (with, salted, total)
}

async fn b_holds_a(b_dir: &SqliteBackend, a: &NodeA) {
    for id in [&a.p, &a.n] {
        assert!(
            b_dir
                .lookup_public_key(id.key_id())
                .await
                .expect("lookup")
                .is_some(),
            "B holds {}'s key",
            id.key_id()
        );
    }
    assert!(
        !b_dir
            .list_signed_transport_destinations_for(a.n.key_id())
            .await
            .expect("routes")
            .is_empty(),
        "B holds N's route"
    );
}

/// **The mixed old/new pair (design §9, witness 9's step-A half).** A node
/// with the receiver half on and one with it off converge on the bootstrap
/// planes, both ways round. The new node's Summaries and Diffs carry the
/// marker and never a salt (step A sends no fingerprint); the old node's
/// carry nothing; and an old node's reader sees the new node's refs intact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_mixed_old_new_pair_converges_and_the_marker_is_inert_rf_a() {
    for new_side_is_a in [true, false] {
        let tag = if new_side_is_a {
            "rfa-new-a"
        } else {
            "rfa-new-b"
        };
        let a = NodeA::build(tag, if new_side_is_a { 0x61 } else { 0x71 }).await;
        let b_ident = Ident::mint(
            &format!("node-b-{tag}"),
            "node",
            if new_side_is_a { 0x66 } else { 0x76 },
        )
        .await;
        let b_dir = substrate().await;
        hold(&b_dir, &b_ident).await;
        let a_bridge = node_a_bridge(&a, new_side_is_a);
        let b = bridge_with(
            &b_dir,
            b_ident.key_id(),
            vec![b_ident.key_id().to_owned()],
            !new_side_is_a,
        );
        let (mut new_msgs, mut old_msgs) = (Vec::new(), Vec::new());
        for _ in 0..2 {
            for kind in PLANES {
                let (from_a, from_b) =
                    round_on_the_wire(kind, &a_bridge, a.n.key_id(), &b, b_ident.key_id()).await;
                if new_side_is_a {
                    new_msgs.extend(from_a);
                    old_msgs.extend(from_b);
                } else {
                    new_msgs.extend(from_b);
                    old_msgs.extend(from_a);
                }
            }
        }
        b_holds_a(&b_dir, &a).await;
        let (with, salted, total) = rf_markers(&new_msgs);
        assert!(
            total > 0 && with == total,
            "every new-side Summary and Diff carries the marker: {with}/{total}"
        );
        assert_eq!(salted, 0, "step A sends no fingerprint");
        let (with, _, total) = rf_markers(&old_msgs);
        assert!(total > 0);
        assert_eq!(with, 0, "the old side carries nothing");
        // An old node's reader: the new node's Summary and Diff, decoded by
        // the pre-RF shapes, keep their refs and want.
        for m in &new_msgs {
            match (m, serde_json::from_slice::<PreRf>(&m.to_bytes())) {
                (ReplicationMessage::Summary(s), Ok(PreRf::Summary(old))) => {
                    assert_eq!((old.kind, &old.refs), (s.kind, &s.refs));
                }
                (ReplicationMessage::Diff(d), Ok(PreRf::Diff(old))) => {
                    assert_eq!((old.kind, &old.want), (d.kind, &d.want));
                }
                (ReplicationMessage::Summary(_) | ReplicationMessage::Diff(_), other) => {
                    panic!(
                        "an old reader parses every new-side frame: {:?}",
                        other.err()
                    );
                }
                _ => {}
            }
        }
        // A new receiver against an old sender: its Diffs answer nothing (no
        // `sid`, no answers), they only say it answers.
        for m in &new_msgs {
            if let ReplicationMessage::Diff(d) = m {
                let rf = d.rf.as_ref().expect("the marker");
                assert!(
                    rf.sid.is_none() && rf.m.is_empty() && rf.u.is_none(),
                    "{rf:?}"
                );
                assert_eq!(rf.e, Some(1));
            }
        }
    }
}

/// **An old peer ignores `rf`** (design §6.1, decision 3: speculation is
/// harmless). A node with the receiver half off, handed a FINGERPRINTED
/// Summary, answers it exactly as it answers the same Summary without `rf`:
/// the same `want`, and no `rf` member of its own, which is the downgrade the
/// sender reads.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_old_peer_answers_a_fingerprinted_summary_as_a_plain_one_rf_a() {
    let a = NodeA::build("rfa-old-peer", 0xa1).await;
    let b_ident = Ident::mint("node-b-rfa-old-peer", "node", 0xa6).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let a_bridge = node_a_bridge(&a, false);
    let old = bridge_with(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        false,
    );
    let offer: Vec<[u8; 32]> = a_bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some(b_ident.key_id()))
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect();
    assert!(!offer.is_empty());
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(&old) as _;
    let prov = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a.n.key_id());
    let app = MutableDirectoryStateAdapter::new(Arc::clone(&dir_b));
    let mut sender = RefSender {
        salt: [0x44; 32],
        sid: 9,
    };
    let fingerprinted = sender.summary(EnvelopeKind::Key, &offer, &[""]);
    let plain = SummaryMessage {
        rf: None,
        ..fingerprinted.clone()
    };
    let mut answers = Vec::new();
    for summary in [fingerprinted, plain] {
        let mut s = Session::new(SessionRole::Responder, EnvelopeKind::Key);
        let msg = ReplicationMessage::from_bytes(&ReplicationMessage::Summary(summary).to_bytes())
            .expect("decodes");
        let diff = messages(s.on_message(msg, &prov, &app, Some(a.n.key_id())).await)
            .into_iter()
            .find_map(|m| match m {
                ReplicationMessage::Diff(d) => Some(d),
                _ => None,
            })
            .expect("a Diff");
        assert!(diff.rf.is_none(), "an old peer says nothing about rf");
        let mut want = diff.want;
        want.sort_unstable();
        answers.push(want);
    }
    assert!(!answers[0].is_empty(), "B lacks A's rows: it wants them");
    assert_eq!(answers[0], answers[1], "the fingerprints change nothing");
}

/// A reference SENDER for one plane: fingerprints over exactly `offer`
/// (filter first, R1), listing `lc` ranges completely.
struct RefSender {
    salt: [u8; 32],
    sid: u32,
}

impl RefSender {
    fn summary(&mut self, kind: EnvelopeKind, offer: &[[u8; 32]], lc: &[&str]) -> SummaryMessage {
        self.sid += 1;
        let mut acc = Acc::default();
        for x in offer {
            acc.add(&elem(&self.salt, x));
        }
        let fp = hex::encode(node_fp(kind.as_wire_str(), "", &acc));
        let mut refs = Vec::new();
        for p in lc {
            refs.extend(
                offer
                    .iter()
                    .filter(|x| in_prefix(x, p))
                    .map(|x| EnvelopeRef {
                        envelope_hash: *x,
                        seq: 0,
                    }),
            );
        }
        SummaryMessage {
            status: None,
            kind,
            refs,
            rf: Some(RfSummary {
                v: RF_VERSION,
                a: Some(ALG_SALTED_SUM),
                ep: Some("reference-sender".into()),
                salt: Some(encode_salt(&self.salt)),
                sid: Some(self.sid),
                n: vec![(String::new(), acc.count(), fp)],
                lc: lc.iter().map(|p| (*p).to_owned()).collect(),
                ..RfSummary::default()
            }),
        }
    }
}

fn rf_answer_of(msgs: &[ReplicationMessage]) -> super::range_fp::RfDiff {
    msgs.iter()
        .find_map(|m| match m {
            ReplicationMessage::Diff(d) => d.rf.clone(),
            _ => None,
        })
        .expect("the Diff carries an rf answer")
}

/// **A real bridge answers a fingerprinted Summary from its listed mirror.**
/// B first converges with A over the legacy wire, then A's Key-plane offer
/// arrives fingerprinted: `list` while B's mirror of A is empty; `match` once
/// A lists the root completely; `match` again on the idle root with no refs;
/// a difference once A's set gains a row B lacks. The answers echo `sid`, and
/// the Diff's `want` is the legacy diff, unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_real_bridge_answers_from_its_listed_mirror_rf_a() {
    let a = NodeA::build("rfa-answer", 0x81).await;
    let b_ident = Ident::mint("node-b-rfa-answer", "node", 0x86).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let a_bridge = node_a_bridge(&a, false);
    let b = bridge_with(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        true,
    );
    for _ in 0..2 {
        for kind in PLANES {
            round_on_the_wire(kind, &a_bridge, a.n.key_id(), &b, b_ident.key_id()).await;
        }
    }
    b_holds_a(&b_dir, &a).await;
    let offer: Vec<[u8; 32]> = a_bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some(b_ident.key_id()))
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect();
    assert!(!offer.is_empty(), "A offers its key rows");
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(&b) as _;
    let prov_b = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a.n.key_id());
    let app_b = MutableDirectoryStateAdapter::new(Arc::clone(&dir_b));
    let mut sender = RefSender {
        salt: [0x5a; 32],
        sid: 41,
    };
    let answer = |summary: SummaryMessage| {
        let prov_b = &prov_b;
        let app_b = &app_b;
        let a_id = a.n.key_id().to_owned();
        async move {
            let mut sb = Session::new(SessionRole::Responder, EnvelopeKind::Key);
            let msg =
                ReplicationMessage::from_bytes(&ReplicationMessage::Summary(summary).to_bytes())
                    .expect("decodes");
            messages(sb.on_message(msg, prov_b, app_b, Some(&a_id)).await)
        }
    };
    let first = sender.summary(EnvelopeKind::Key, &offer, &[]);
    let rf = rf_answer_of(&answer(first).await);
    assert_eq!(rf.sid, Some(42));
    assert!(rf.st.is_some());
    assert_eq!(rf.l, vec![String::new()], "an empty mirror lists: {rf:?}");
    let listed = sender.summary(EnvelopeKind::Key, &offer, &[""]);
    let out = answer(listed).await;
    let rf = rf_answer_of(&out);
    assert_eq!(
        rf.m,
        vec![String::new()],
        "B holds everything A listed: {rf:?}"
    );
    let want: Vec<[u8; 32]> = out
        .iter()
        .find_map(|m| match m {
            ReplicationMessage::Diff(d) => Some(d.want.clone()),
            _ => None,
        })
        .expect("a Diff");
    assert!(
        want.is_empty(),
        "the legacy want is unchanged: B lacks nothing"
    );
    for _ in 0..5 {
        let idle = sender.summary(EnvelopeKind::Key, &offer, &[]);
        assert!(idle.refs.is_empty());
        assert_eq!(
            rf_answer_of(&answer(idle).await).m,
            vec![String::new()],
            "the idle root matches"
        );
    }
    let mut grown = offer.clone();
    grown.push([0xee; 32]);
    let changed = sender.summary(EnvelopeKind::Key, &grown, &[]);
    let rf = rf_answer_of(&answer(changed).await);
    assert!(
        rf.m.is_empty(),
        "a row B lacks makes the root differ: {rf:?}"
    );
}

/// **A refusal whose backoff ends mid-window is wanted at the next compare**,
/// over a real bridge and the real `Session`: the refusal sits in the
/// bridge's own refusal memory, exactly where the apply choke records one, and
/// the receive diff, its suppression and the answer are the field's. While
/// the refusal is in backoff the row is settled provisionally and the root
/// matches; once its window has passed, the very next Summary's root differs,
/// and the next listing wants the row.
///
/// Mutation that turns it red: drop the bridge's refusal probe from
/// `still_settled` (the row would stay matched past its window).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refusal_whose_backoff_ends_is_wanted_at_the_next_compare_rf_a() {
    use crate::replication::RetryDisposition;
    use std::time::{Duration, Instant};
    let a = NodeA::build("rfa-backoff", 0xb1).await;
    let b_ident = Ident::mint("node-b-rfa-backoff", "node", 0xb6).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let a_bridge = node_a_bridge(&a, false);
    let b = bridge_with(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        true,
    );
    for _ in 0..2 {
        for kind in PLANES {
            round_on_the_wire(kind, &a_bridge, a.n.key_id(), &b, b_ident.key_id()).await;
        }
    }
    b_holds_a(&b_dir, &a).await;
    let mut offer: Vec<[u8; 32]> = a_bridge
        .list_envelope_refs_for_peer(EnvelopeKind::Key, Some(b_ident.key_id()))
        .await
        .into_iter()
        .map(|r| r.envelope_hash)
        .collect();
    // One row B does not hold, refused by B a moment ago.
    let refused = [0xd7; 32];
    offer.push(refused);
    b.refusal_backoff_for_tests().record_at(
        EnvelopeKind::Key,
        refused,
        RetryDisposition::Transient,
        Instant::now(),
    );
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(&b) as _;
    let prov_b = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a.n.key_id());
    let app_b = MutableDirectoryStateAdapter::new(Arc::clone(&dir_b));
    let mut sender = RefSender {
        salt: [0x6b; 32],
        sid: 300,
    };
    let answer = |summary: SummaryMessage| {
        let (prov_b, app_b) = (&prov_b, &app_b);
        let a_id = a.n.key_id().to_owned();
        async move {
            let mut sb = Session::new(SessionRole::Responder, EnvelopeKind::Key);
            let msg =
                ReplicationMessage::from_bytes(&ReplicationMessage::Summary(summary).to_bytes())
                    .expect("decodes");
            let diff = messages(sb.on_message(msg, prov_b, app_b, Some(&a_id)).await)
                .into_iter()
                .find_map(|m| match m {
                    ReplicationMessage::Diff(d) => Some(d),
                    _ => None,
                })
                .expect("a Diff");
            (diff.rf.expect("an answer"), diff.want)
        }
    };
    let (rf, want) = answer(sender.summary(EnvelopeKind::Key, &offer, &[""])).await;
    assert_eq!(rf.m, vec![String::new()], "in backoff: settled: {rf:?}");
    assert!(!want.contains(&refused), "and not asked for");
    let (rf, _) = answer(sender.summary(EnvelopeKind::Key, &offer, &[])).await;
    assert_eq!(rf.m, vec![String::new()], "still in backoff: still matched");
    // The window passes (the entry stays, its `retry_at` behind us).
    let memory = b.refusal_backoff_for_tests();
    let _ = memory.take(EnvelopeKind::Key, &refused);
    memory.record_at(
        EnvelopeKind::Key,
        refused,
        RetryDisposition::Transient,
        Instant::now()
            .checked_sub(Duration::from_mins(10))
            .expect("the host has been up ten minutes"),
    );
    assert!(memory.contains(EnvelopeKind::Key, &refused));
    let (rf, _) = answer(sender.summary(EnvelopeKind::Key, &offer, &[])).await;
    assert!(rf.m.is_empty(), "the next compare differs: {rf:?}");
    assert_eq!(rf.l, vec![String::new()]);
    let (_, want) = answer(sender.summary(EnvelopeKind::Key, &offer, &[""])).await;
    assert_eq!(want, vec![refused], "listed again, it is wanted");
}

/// **R6 / N7 — a salt that arrived over a non-confidential transport is never
/// used** (witness 17's inbound half). The registry marks the Summary; the
/// receiver answers `u:"transport"` and learns nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_salt_over_a_non_confidential_transport_is_refused_rf_a_17() {
    let a = NodeA::build("rfa-transport", 0x91).await;
    let b_ident = Ident::mint("node-b-rfa-transport", "node", 0x96).await;
    let b_dir = substrate().await;
    hold(&b_dir, &b_ident).await;
    let b = bridge_with(
        &b_dir,
        b_ident.key_id(),
        vec![b_ident.key_id().to_owned()],
        true,
    );
    let dir_b: Arc<dyn ReplicationDirectory> = Arc::clone(&b) as _;
    let prov_b = DirectoryStateAdapter::new(Arc::clone(&dir_b)).with_peer(a.n.key_id());
    let app_b = MutableDirectoryStateAdapter::new(Arc::clone(&dir_b));
    let mut sender = RefSender {
        salt: [0x33; 32],
        sid: 1,
    };
    let mut msg = ReplicationMessage::Summary(sender.summary(EnvelopeKind::Key, &[[1; 32]], &[""]));
    mark_inbound_transport(&mut msg, false);
    let mut sb = Session::new(SessionRole::Responder, EnvelopeKind::Key);
    let rf = rf_answer_of(&messages(
        sb.on_message(msg, &prov_b, &app_b, Some(a.n.key_id()))
            .await,
    ));
    assert_eq!(rf.u.as_deref(), Some("transport"));
    assert!(rf.m.is_empty() && rf.s.is_empty() && rf.l.is_empty());
    // Over a confidential transport the same Summary is answered.
    let mut msg = ReplicationMessage::Summary(sender.summary(EnvelopeKind::Key, &[[1; 32]], &[""]));
    mark_inbound_transport(&mut msg, true);
    let mut sb = Session::new(SessionRole::Responder, EnvelopeKind::Key);
    let rf = rf_answer_of(&messages(
        sb.on_message(msg, &prov_b, &app_b, Some(a.n.key_id()))
            .await,
    ));
    assert!(rf.u.is_none(), "{rf:?}");
}

/// **The `rf` members round-trip, nested, after `kind`** (design §2.5,
/// witness 4): a full fingerprinted `Summary.rf` and a full `Diff.rf` answer
/// survive the wire byte for byte; `kind` precedes `rf` in the frame, so the
/// lane classifier's 256-byte head still finds it; `v`, `a` and `salt` never
/// appear at top level.
#[test]
fn rf_members_round_trip_nested_after_kind_rf_a_4() {
    use super::range_fp::RfDiff;
    let summary = ReplicationMessage::Summary(SummaryMessage {
        status: None,
        kind: EnvelopeKind::IdentityOccurrence,
        refs: vec![EnvelopeRef {
            envelope_hash: [3; 32],
            seq: 9,
        }],
        rf: Some(RfSummary {
            v: RF_VERSION,
            a: Some(ALG_SALTED_SUM),
            ep: Some("AAAAAAAAAAA".into()),
            e: None,
            salt: Some(encode_salt(&[1; 32])),
            sid: Some(2_974_410_118),
            n: vec![(String::new(), 33_012, "ab".repeat(16))],
            c: vec![("3f".into(), vec![1; 16], "cd".repeat(16 * 16))],
            lc: vec!["3f2a".into()],
            pk: vec!["7c01".into()],
            transport_refused: false,
        }),
    });
    let bytes = summary.to_bytes();
    assert_eq!(ReplicationMessage::from_bytes(&bytes).unwrap(), summary);
    let text = std::str::from_utf8(&bytes).unwrap();
    assert!(text.find("\"kind\"").unwrap() < text.find("\"rf\"").unwrap());
    let top: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    for k in ["v", "a", "salt", "sid"] {
        assert!(top.get(k).is_none(), "`{k}` stays nested");
    }
    let diff = ReplicationMessage::Diff(crate::replication::DiffMessage {
        kind: EnvelopeKind::Key,
        want: vec![[4; 32]],
        withheld: Vec::new(),
        rf: Some(RfDiff {
            v: RF_VERSION,
            sid: Some(7),
            st: Some("5b816966".into()),
            m: vec![String::new()],
            s: vec!["3f".into()],
            l: vec!["3f2a".into()],
            ..RfDiff::default()
        }),
    });
    assert_eq!(
        ReplicationMessage::from_bytes(&diff.to_bytes()).unwrap(),
        diff
    );
}

/// **The compact members decode into the fields every consumer reads**
/// (design §12.3, witness 13): `rh` into a Summary's refs, `wh` / `xh` into a
/// Diff's want / withheld, `eb` into a Deliver's envelopes. A malformed member
/// decodes to nothing; a message without them is untouched.
#[test]
fn compact_members_decode_into_the_existing_fields_rf_a_13() {
    let h = |b: u8| [b; 32];
    let s = format!(
        r#"{{"type":"summary","kind":"key","refs":[],"rh":"{}"}}"#,
        encode_compact_hashes(&[h(1), h(2)])
    );
    let ReplicationMessage::Summary(sm) = ReplicationMessage::from_bytes(s.as_bytes()).unwrap()
    else {
        panic!("a Summary")
    };
    let got: HashSet<[u8; 32]> = sm.refs.iter().map(|r| r.envelope_hash).collect();
    assert_eq!(got, [h(1), h(2)].into_iter().collect());
    let d = format!(
        r#"{{"type":"diff","kind":"key","want":[],"wh":"{}","xh":"{}"}}"#,
        encode_compact_hashes(&[h(3)]),
        encode_compact_hashes(&[h(4)])
    );
    let ReplicationMessage::Diff(dm) = ReplicationMessage::from_bytes(d.as_bytes()).unwrap() else {
        panic!("a Diff")
    };
    assert_eq!((dm.want, dm.withheld), (vec![h(3)], vec![h(4)]));
    let body = br#"{"attestation":{"attestation_id":"x"}}"#;
    let e = format!(
        r#"{{"type":"deliver","kind":"key","envelopes":[],"eb":["{}"]}}"#,
        encode_compact_body(body)
    );
    let ReplicationMessage::Deliver(dl) = ReplicationMessage::from_bytes(e.as_bytes()).unwrap()
    else {
        panic!("a Deliver")
    };
    assert_eq!(dl.envelopes, vec![body.to_vec()], "byte-exact");
    // Malformed: nothing added, the message still parses.
    let bad = br#"{"type":"summary","kind":"key","refs":[],"rh":"%%%"}"#;
    let ReplicationMessage::Summary(sm) = ReplicationMessage::from_bytes(bad).unwrap() else {
        panic!("a Summary")
    };
    assert!(sm.refs.is_empty());
    // A malformed `rf` reads as no `rf`, never a failed Summary.
    let odd = br#"{"type":"summary","kind":"key","refs":[],"rf":{"v":"one"}}"#;
    let ReplicationMessage::Summary(sm) = ReplicationMessage::from_bytes(odd).unwrap() else {
        panic!("a Summary")
    };
    assert!(sm.rf.is_none());
    // No member: byte-identical round trip.
    let plain = ReplicationMessage::Summary(SummaryMessage {
        status: None,
        kind: EnvelopeKind::Key,
        refs: vec![],
        rf: None,
    });
    assert_eq!(
        std::str::from_utf8(&plain.to_bytes()).unwrap(),
        r#"{"type":"summary","kind":"key","refs":[]}"#
    );
}
