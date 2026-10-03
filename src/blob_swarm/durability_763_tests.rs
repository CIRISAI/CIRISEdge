//! **CIRISEdge#763 — durability at every tier (CC 6.1.5.3) for `self`
//! files**, on two or three real SQLite substrates (the
//! `chunk_grants_779_tests` harness, in-process): alice's laptop A writes a
//! self file, her phone B pulls it; S, where present, is a server-class node
//! she claimed.
//!
//! Every count is persist's: the audience and the deficit
//! ([`row_deficit`](super::durability::row_deficit) over
//! `content_audience` / `deficit_over`), the custody fold
//! (`device_custody_of`). Edge's part, and what each witness fails without:
//! a completed pull files `here` (`BlobPuller::report_here`); the durability
//! pass re-files a lapsing `here`, corrects a lost copy to `none` and lists
//! the repairs rarest first (`BlobPuller::durability_sweep`); a promoted DAG
//! that lost a chunk is repaired and reported whole again.

use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::custody_ack::{device_custody_of, CustodyVerdict};
use ciris_persist::federation::durability::{DeficitAudience, DurabilityMode};
use ciris_persist::federation::types::device_class;
use ciris_persist::federation::{FederationDirectory as _, SignedAttestation};

use super::chunk_grants_779_tests::{
    cross_keys_except, device, edge_of, federate, fetch_from, publish_self_file,
    publish_self_file_seeded, puller_of, two_devices, Ident, Node, Published, Withhold,
    EPOCH_CHUNKS,
};
use super::durability::row_deficit;
use super::pull::PullOutcome;

/// Hand `from`'s `custody:ack:v1` rows to `to`'s replicated door, as the
/// audience-gated replication would (the bridge-level gate is witnessed by
/// `family_files_wire_736`).
async fn carry_custody(from: &Node, to: &Node) -> usize {
    let mut carried = 0;
    for row in from.dir.list_attestations_by(&from.me).await.expect("list") {
        if ciris_persist::federation::admission::envelope_dimension(&row.attestation_envelope)
            != Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)
        {
            continue;
        }
        if to
            .dir
            .get_attestation(&row.attestation_id)
            .await
            .expect("read")
            .is_some()
        {
            continue;
        }
        to.dir
            .apply_replicated_attestation(SignedAttestation { attestation: row })
            .await
            .expect("the cohort admits the custody report");
        carried += 1;
    }
    carried
}

async fn deliver_row(file: &Published, to: &Node) {
    to.dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("the device admits the crossed row");
}

async fn verdict(on: &Node, device_key: &str, sha: &[u8; 32]) -> CustodyVerdict {
    device_custody_of(
        &*on.dir,
        device_key,
        &hex::encode(sha),
        None,
        chrono::Utc::now(),
    )
    .await
    .expect("custody fold")
    .state
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// **A self file reaches every personal device of its owner as a FULL holder,
/// and not her server-class node.** A (laptop, the author) and B (phone) are
/// alice's personal devices; S is a node she claimed as a `server`. B's pull
/// stores the DAG and files `here`; S's is refused (CC 3.3.7). A's durability
/// pass files A's own `here`; S's pass finds the file outside its audience.
/// With both reports carried, persist's deficit on A reads: audience {A, B}
/// (S absent), mode Full (two nodes < N + K), both live `here`, nothing
/// missing. Fails without the post-pull `here` (B stays `unknown` and is
/// listed missing) or without the pass (A is).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_self_file_reaches_every_personal_device_as_a_full_holder_not_a_server_763() {
    let alice = Ident::new("alice-fed", 0x11);
    let alice_phone = Ident::new("alice-phone", 0x33);
    let alice_srv = Ident::new("alice-srv", 0x44);
    let ids = [&alice, &alice_phone, &alice_srv];
    let node_a = device(
        &ids,
        &alice,
        &alice,
        Some(EPOCH_CHUNKS),
        device_class::LAPTOP,
    )
    .await;
    let node_b = device(&ids, &alice, &alice_phone, None, device_class::PHONE).await;
    let node_s = device(&ids, &alice, &alice_srv, None, device_class::SERVER).await;
    for (x, y) in [
        (&node_a, &node_b),
        (&node_b, &node_a),
        (&node_a, &node_s),
        (&node_s, &node_a),
        (&node_b, &node_s),
        (&node_s, &node_b),
    ] {
        federate(x, y).await;
    }
    let file = publish_self_file(&node_a, &alice).await;
    for to in [&node_b, &node_s] {
        deliver_row(&file, to).await;
        cross_keys_except(&node_a, to, &Withhold::none(), None).await;
    }
    let (edge_a, edge_b, edge_s) = (edge_of(&node_a), edge_of(&node_b), edge_of(&node_s));
    let (puller_a, puller_b, puller_s) = (
        puller_of(&node_a, &edge_a),
        puller_of(&node_b, &edge_b),
        puller_of(&node_s, &edge_s),
    );
    assert_eq!(
        puller_b
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::Here,
        "B's completed pull filed its `here`"
    );
    let at_s = puller_s
        .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_s))
        .await;
    assert!(
        !matches!(at_s, PullOutcome::Stored { .. }),
        "a server-class node of alice's holds none of her self file: {at_s:?}"
    );
    let sweep_a = puller_a.durability_sweep().await;
    assert_eq!(
        sweep_a.reported_here,
        vec![file.sha],
        "A holds its own file whole and reports it"
    );
    assert!(sweep_a.repairs.is_empty());
    let sweep_s = puller_s.durability_sweep().await;
    assert!(
        sweep_s.repairs.is_empty() && sweep_s.reported_here.is_empty(),
        "S is outside the audience: nothing to repair or report ({sweep_s:?})"
    );
    carry_custody(&node_b, &node_a).await;

    let d = row_deficit(&*node_a.dir, &file.row, &file.sha, chrono::Utc::now())
        .await
        .expect("deficit");
    assert_eq!(
        d.audience,
        DeficitAudience::Nodes(sorted(vec![node_a.me.clone(), node_b.me.clone()])),
        "the audience is alice's personal devices; her server is not in it"
    );
    assert_eq!(d.mode, Some(DurabilityMode::Full), "two nodes < N + K");
    assert_eq!(
        sorted(d.live_here.clone()),
        sorted(vec![node_a.me.clone(), node_b.me.clone()]),
        "every audience node is a full holder"
    );
    assert!(d.missing.is_empty(), "nothing missing: {:?}", d.missing);
}

/// **A device that lost its copy shows up in `missing`, and its repairs run
/// rarest first.** B pulled F1 and reported it `here`; F2's row and keys
/// reached B but its pull never ran (an offer dropped, a ladder spent). As
/// far as B knows, A holds F1 (A's F1 report crossed) and nobody holds F2.
/// Then B loses a chunk of F1. B's pass corrects its stale F1 `here` to
/// `none` — persist's deficit now lists B missing for both files — and
/// returns the repairs rarest first: F2 (no other live holder) before F1
/// (A). F2's repair is pulled and stored, and B is `here` for it. Fails
/// without the pass: no repair list, and B's stale `here` hides the lost
/// copy for 72 h.
///
/// F1's repair stops at persist (see
/// `a_chunk_repair_refiles_here_for_the_whole_dag_763`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_device_that_lost_its_copy_is_missing_and_repaired_rarest_first_763() {
    let (alice, node_a, node_b) = two_devices().await;
    let (edge_a, edge_b) = (edge_of(&node_a), edge_of(&node_b));
    let (puller_a, puller_b) = (puller_of(&node_a, &edge_a), puller_of(&node_b, &edge_b));
    let f1 = publish_self_file_seeded(&node_a, &alice, 0x0763).await;
    let f2 = publish_self_file_seeded(&node_a, &alice, 0x1763).await;
    for f in [&f1, &f2] {
        deliver_row(f, &node_b).await;
    }
    cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await;
    assert_eq!(
        puller_b
            .pull_dag_with(&f1.row, f1.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    // A reports both; only F1's report reaches B.
    assert_eq!(puller_a.durability_sweep().await.reported_here.len(), 2);
    let f1_hex = hex::encode(f1.sha);
    for row in node_a
        .dir
        .list_attestations_by(&node_a.me)
        .await
        .expect("list")
    {
        let is_f1_ack =
            ciris_persist::federation::admission::envelope_dimension(&row.attestation_envelope)
                == Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)
                && row
                    .attestation_envelope
                    .get("evidence_refs")
                    .and_then(|r| r.get(0))
                    .and_then(serde_json::Value::as_str)
                    == Some(f1_hex.as_str());
        if is_f1_ack {
            node_b
                .dir
                .apply_replicated_attestation(SignedAttestation { attestation: row })
                .await
                .expect("B admits A's F1 report");
        }
    }
    assert_eq!(
        verdict(&node_b, &node_b.me, &f1.sha).await,
        CustodyVerdict::Here
    );
    // The loss: one of F1's chunks, gone from B's store.
    assert!(node_b
        .dir
        .delete_blob(&f1.stream[1].2)
        .await
        .expect("delete"));

    let sweep = puller_b.durability_sweep().await;
    let order: Vec<[u8; 32]> = sweep.repairs.iter().map(|r| r.sha).collect();
    assert_eq!(
        order,
        vec![f2.sha, f1.sha],
        "rarest first: F2 has no other live holder B knows of, F1 has A"
    );
    assert!(sweep.repairs[0].live_here.is_empty());
    assert_eq!(sweep.repairs[1].live_here, vec![node_a.me.clone()]);
    assert_eq!(
        verdict(&node_b, &node_b.me, &f1.sha).await,
        CustodyVerdict::None,
        "B corrected its own report: the copy is gone"
    );
    for f in [&f1, &f2] {
        let d = row_deficit(&*node_b.dir, &f.row, &f.sha, chrono::Utc::now())
            .await
            .expect("deficit");
        assert!(
            d.missing.contains(&node_b.me),
            "the device without a copy is listed missing: {d:?}"
        );
    }
    let first = &sweep.repairs[0];
    assert_eq!(
        puller_b
            .pull_dag_with(&first.row, first.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false },
        "the rarest file is repaired"
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &f2.sha).await,
        CustodyVerdict::Here
    );
    let d = row_deficit(&*node_b.dir, &f2.row, &f2.sha, chrono::Utc::now())
        .await
        .expect("deficit");
    assert!(!d.missing.contains(&node_b.me), "repaired: {d:?}");
    let again: Vec<[u8; 32]> = puller_b
        .durability_sweep()
        .await
        .repairs
        .iter()
        .map(|r| r.sha)
        .collect();
    assert_eq!(again, vec![f1.sha], "only F1 is left to repair");
}

/// **A promoted DAG that lost a chunk is not "held": the pull goes after the
/// chunk, and no `here` is filed while any chunk is missing.** B pulled the
/// file (`here` filed), then lost chunk 1. Re-offered, the pull is no longer
/// `AlreadyHeld`: it fetches the missing chunk from A and hands it to
/// persist's adopt door. B files no `here` for a DAG it does not hold whole.
/// Fails on the pre-#763 puller, which answered `AlreadyHeld` for a promoted
/// DAG whatever it was missing.
///
/// **The repair cannot complete on this persist (8fcbeb9e):** the lost
/// chunk's stream position survives `delete_blob` (the eviction floor), and
/// `adopt_sealed_chunks` refuses re-adopting the IDENTICAL `(seq, sha)` there
/// as a seq conflict ("stream … seq 1 already exists"). Asserted here by name
/// so the day persist accepts it this test reds and the full witness below
/// is un-ignored.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_dag_missing_a_chunk_is_not_held_and_files_no_here_763() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let puller = puller_of(&node_b, &edge_b);
    let file = publish_self_file(&node_a, &alice).await;
    deliver_row(&file, &node_b).await;
    cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await;
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let reports_before = node_b
        .dir
        .list_attestations_by(&node_b.me)
        .await
        .expect("list")
        .len();
    assert!(node_b
        .dir
        .delete_blob(&file.stream[1].2)
        .await
        .expect("delete"));
    let repair = puller
        .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
        .await;
    assert!(
        matches!(&repair, PullOutcome::StoreFailed(e) if e.contains("seq 1 already exists")),
        "the pull fetched the lost chunk and persist's adopt door refused its position \
         (not AlreadyHeld): {repair:?}"
    );
    assert_eq!(
        node_b
            .dir
            .list_attestations_by(&node_b.me)
            .await
            .expect("list")
            .len(),
        reports_before,
        "no `here` for a DAG missing a chunk"
    );
    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    assert!(
        !super::durability::holds_whole(
            node_b.store.engine(),
            &*node_b.dir,
            &node_b.me,
            &file.row,
            &file.sha,
            &file_row.pointer,
        )
        .await
        .expect("holding"),
        "persist's readiness door names the lost chunk"
    );
}

/// **A chunk repair re-files `here` for the WHOLE DAG.** As above, then the
/// repair completes: `Stored`, one NEW `here` (accepted only because every
/// chunk is held again), and the file reads back byte-identical.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "persist 8fcbeb9e refuses re-adopting a lost chunk at its surviving stream position \
            (adopt_sealed_chunks: `seq N already exists`, identical sha); un-ignore when persist \
            makes that re-adopt idempotent"]
async fn a_chunk_repair_refiles_here_for_the_whole_dag_763() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let puller = puller_of(&node_b, &edge_b);
    let file = publish_self_file(&node_a, &alice).await;
    deliver_row(&file, &node_b).await;
    cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await;
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    let reports_before = node_b
        .dir
        .list_attestations_by(&node_b.me)
        .await
        .expect("list")
        .len();
    let lost = file.stream[1].2;
    assert!(node_b.dir.delete_blob(&lost).await.expect("delete"));
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false },
        "a promoted DAG missing a chunk is repaired, not AlreadyHeld"
    );
    assert!(node_b.dir.has_blob(&lost).await.expect("has_blob"));
    assert_eq!(
        node_b
            .dir
            .list_attestations_by(&node_b.me)
            .await
            .expect("list")
            .len(),
        reports_before + 1,
        "the repair filed one new `here`"
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::Here
    );
    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    let mut read = Vec::new();
    while let Some(item) = walk.next().await {
        read.extend_from_slice(&item.expect("every chunk opens"));
    }
    assert!(
        read == file.plain,
        "the repaired DAG reads the file alice wrote"
    );
    assert_eq!(
        puller
            .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::AlreadyHeld,
        "a whole DAG re-offered is held"
    );
}
