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
//! that lost a chunk, or a device that lost the whole file, is repaired and
//! reported whole again through persist's custody door (under the row's AAD);
//! a withdrawn file is not repaired.

use ciris_persist::federation::blobs::BlobStorage as _;
use ciris_persist::federation::custody_ack::{device_custody_of, CustodyVerdict};
use ciris_persist::federation::durability::{DeficitAudience, DurabilityMode};
use ciris_persist::federation::key_grant::KEY_GRANT_ATTESTATION_TYPE_PREFIX;
use ciris_persist::federation::types::device_class;
use ciris_persist::federation::{FederationDirectory as _, SignedAttestation};

use super::chunk_grants_779_tests::{
    cross_keys_except, device, edge_of, federate, fetch_from, publish_self_file,
    publish_self_file_seeded, puller_of, two_devices, Ident, Node, Published, Withhold,
    EPOCH_CHUNKS,
};
use super::durability::row_deficit;
use super::pull::{DagByteFetch as _, PullOutcome};

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
/// Then F1's lost chunk is repaired too (persist v53 re-adopts the identical
/// chunk at its kept position), and the next pass has nothing left to do.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // two files' loss, sweep and repair, in order, on purpose
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
    assert_eq!(
        puller_b
            .pull_dag_with(&f1.row, f1.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false },
        "F1's lost chunk is repaired"
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &f1.sha).await,
        CustodyVerdict::Here
    );
    assert!(
        puller_b.durability_sweep().await.repairs.is_empty(),
        "nothing left to repair"
    );
}

/// The `key_grant` sets `node` holds (every axis).
async fn key_grant_rows(node: &Node) -> usize {
    node.dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list")
        .into_iter()
        .filter(|a| {
            a.attestation
                .attestation_type
                .starts_with(KEY_GRANT_ATTESTATION_TYPE_PREFIX)
        })
        .count()
}

/// **A promoted DAG that lost a chunk is not "held": the pull goes after the
/// chunk, and no `here` is filed while any chunk is missing.** B pulled the
/// file (`here` filed), then lost chunk 1. While it is missing, persist's
/// custody door refuses B's `here` by name (`custody_ack_here_dag_incomplete`,
/// the manifest opened under the row's AAD), and a DIFFERENT chunk offered at
/// the lost chunk's kept position is refused (`already exists`) and stores
/// nothing. Re-offered, the pull is no longer `AlreadyHeld`: it fetches the
/// missing chunk from A, persist re-adopts the identical `(seq, sha)`, and
/// the DAG is `Stored` again. Fails on the pre-#763 puller, which answered
/// `AlreadyHeld` for a promoted DAG whatever it was missing, and with the
/// custody door asked without the row's AAD (the refusal is then
/// `custody_ack_here_seal_did_not_open`, not the incomplete DAG).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // every refusal before the repair, then the repair, in order, on purpose
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
    let (lost_seq, _, lost) = file.stream[1];
    assert!(node_b.dir.delete_blob(&lost).await.expect("delete"));
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
    let refused = super::durability::file_custody(
        node_b.store.engine(),
        &file.row,
        &file.sha,
        &file_row.pointer,
        ciris_persist::federation::custody_ack::CustodyState::Here,
    )
    .await;
    assert!(
        matches!(&refused, Err(e) if e.contains("custody_ack_here_dag_incomplete")),
        "persist's door refuses `here` for a DAG missing a chunk: {refused:?}"
    );

    // A different chunk at the lost chunk's kept position: refused, nothing
    // stored. Persist's adopt door, as the pull calls it.
    let (other_seq, other_size, other) = file.stream[2];
    let envelope = fetch_from(&node_a, &node_b)
        .fetch(other)
        .await
        .expect("seq 2's envelope");
    let provenance = ciris_persist::federation::BlobProvenance::from_attestation(
        &file.row,
        &file.sha,
        file_row.pointer.epoch,
        None,
    )
    .expect("provenance");
    let wrong = node_b
        .store
        .engine()
        .adopt_sealed_chunks(
            &file.stream_id,
            &[ciris_persist::federation::AdoptChunkItem {
                seq: lost_seq,
                envelope: &envelope,
                plaintext_size: other_size,
            }],
            0,
            provenance,
        )
        .await
        .expect("the door answers per item");
    assert!(
        matches!(&wrong[..], [Err(e)] if e.to_string().contains("already exists")),
        "seq {other_seq}'s chunk at seq {lost_seq}'s kept position is refused: {wrong:?}"
    );
    assert!(!node_b.dir.has_blob(&lost).await.expect("has_blob"));
    let at_lost: Vec<[u8; 32]> = node_b
        .dir
        .stream_chunks(&file.stream_id)
        .await
        .expect("stream chunks")
        .chunks
        .into_iter()
        .filter(|c| c.seq == lost_seq)
        .map(|c| c.chunk_sha)
        .collect();
    assert!(
        !at_lost.contains(&other),
        "the refused chunk was not stored at seq {lost_seq}: {at_lost:?}"
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

    let repair = puller
        .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
        .await;
    assert_eq!(
        repair,
        PullOutcome::Stored { announced: false },
        "the pull fetched the lost chunk and persist re-adopted it at its kept position \
         (not AlreadyHeld, not a seq conflict)"
    );
    assert!(node_b.dir.has_blob(&lost).await.expect("has_blob"));
}

/// **A chunk repair re-files `here` for the WHOLE DAG.** B pulled the file,
/// lost chunk 1, and B's durability pass corrected its `here` to `none` and
/// listed the file as a repair. The repair completes: `Stored`, a NEW `here`
/// (accepted by persist's door only because every chunk is held again), and
/// the file reads back byte-identical. Fails without the pass (no repair,
/// B's stale `here` stands) and with the custody door asked without the
/// row's AAD (no `here` is filed for any edge DAG).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
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
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::Here
    );
    let lost = file.stream[1].2;
    assert!(node_b.dir.delete_blob(&lost).await.expect("delete"));
    let sweep = puller.durability_sweep().await;
    let repairs: Vec<[u8; 32]> = sweep.repairs.iter().map(|r| r.sha).collect();
    assert_eq!(repairs, vec![file.sha], "the sweep lists the damaged DAG");
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::None,
        "the sweep corrected B's `here` to `none`"
    );
    let reports_before = node_b
        .dir
        .list_attestations_by(&node_b.me)
        .await
        .expect("list")
        .len();
    let repair = &sweep.repairs[0];
    assert_eq!(
        puller
            .pull_dag_with(&repair.row, repair.sha, &fetch_from(&node_a, &node_b))
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
    assert!(puller.durability_sweep().await.repairs.is_empty());
}

/// **A device that lost a WHOLE self file is repaired, and reads it with no
/// new key.** B pulled the file and reported `here`; then the whole file is
/// evicted (`delete_blob` of the manifest and every chunk, terminators
/// included). B's pass corrects its `here` to `none` and lists the file as a
/// repair, rarest first (A's report never reached B: no live holder). The
/// repair pulls the manifest and every chunk again, and the file reads whole,
/// by stream and by `open`, under the at-rest grants the eviction KEPT (CC:
/// a grant is a key-plane fact, not a holding): B holds exactly the
/// `key_grant` sets it held before. Fails without the pass (B's stale `here`
/// stands and nothing is repaired).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_whole_lost_file_is_repaired_and_reads_with_no_new_key_763() {
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
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::Here
    );
    let grants_before = key_grant_rows(&node_b).await;
    assert!(grants_before > 0, "B was granted the file's keys");

    // The whole file, gone from B's store.
    assert!(node_b.dir.delete_blob(&file.sha).await.expect("delete"));
    for (_, _, chunk) in &file.stream {
        node_b.dir.delete_blob(chunk).await.expect("delete");
    }
    assert!(!node_b.dir.has_blob(&file.sha).await.expect("has_blob"));

    let sweep = puller.durability_sweep().await;
    let repairs: Vec<[u8; 32]> = sweep.repairs.iter().map(|r| r.sha).collect();
    assert_eq!(repairs, vec![file.sha], "the lost file is a repair");
    assert!(
        sweep.repairs[0].live_here.is_empty(),
        "no live holder B knows of: rarest"
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::None,
        "B reported the lost copy `none`"
    );
    let d = row_deficit(&*node_b.dir, &file.row, &file.sha, chrono::Utc::now())
        .await
        .expect("deficit");
    assert!(d.missing.contains(&node_b.me), "B is missing: {d:?}");

    let repair = &sweep.repairs[0];
    assert_eq!(
        puller
            .pull_dag_with(&repair.row, repair.sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false },
        "the whole file is repaired"
    );
    assert_eq!(
        verdict(&node_b, &node_b.me, &file.sha).await,
        CustodyVerdict::Here
    );
    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    let whole = file_row
        .open(&node_b.store, &node_b.me)
        .await
        .expect("the repaired file opens");
    assert!(whole == file.plain, "the repaired file reads whole");
    let mut walk = file_row.chunks(&node_b.store, &node_b.me);
    let mut read = Vec::new();
    while let Some(item) = walk.next().await {
        read.extend_from_slice(&item.expect("every chunk opens"));
    }
    assert!(read == file.plain, "and by stream");
    assert_eq!(
        key_grant_rows(&node_b).await,
        grants_before,
        "no key_grant set was re-applied: the eviction kept the grants"
    );
    assert!(puller.durability_sweep().await.repairs.is_empty());
}

/// **A withdrawn self file reads `Withdrawn` for a device holding its grant,
/// and the durability pass does not repair it.** B pulled the file; alice
/// withdraws it (CC 2.3) and the `withdraws` row reaches B. A's read is
/// refused `Withdrawn`, not `NotGranted` and not a substrate fault (B's is
/// pinned below on a persist gap). Then B's copy is evicted: the pass lists
/// no repair and files no report for it (a retracted file is not
/// durability's to restore). Fails with the pass
/// listing withdrawn files (`LifecycleView::IncludeWithdrawn`): the evicted
/// file comes back as a repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withdrawn_file_reads_withdrawn_and_is_not_repaired_763() {
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
    let withdraws = crate::files::withdraw(
        &*node_a.dir,
        &file.row,
        "deleted from the drive",
        file.row.asserted_at + chrono::Duration::seconds(1),
        crate::replication::attestation_bind::Signers {
            node: &node_a.signer,
            actor: None,
        },
    )
    .await
    .expect("the author withdraws the file");
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: withdraws,
        })
        .await
        .expect("B admits the withdrawal");

    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    let at_a = file_row.open(&node_a.store, &node_a.me).await;
    assert!(
        matches!(
            &at_a,
            Err(crate::files::FileError::Unopened(
                crate::chat::UnopenedReason::Withdrawn { .. }
            ))
        ),
        "a grant-holder's read of a withdrawn file is Withdrawn: {:?}",
        at_a.as_ref().map(Vec::len)
    );

    // PERSIST GAP (reported, v53.0.0): B filed a custody `here` after its
    // pull, a federation-tier `scores` row citing the blob in
    // `evidence_refs`. Persist's tombstone fold (`binding_state` over
    // `attestations_binding_content`) counts that report as a LIVE binding of
    // the content, so on every device that reported `here` the withdrawn file
    // still reads. Pinned by name: when persist stops counting custody
    // reports as bindings this leg reds, and B's read is asserted `Withdrawn`
    // like A's.
    let bindings = node_b
        .dir
        .attestations_binding_content(&hex::encode(file.sha))
        .await
        .expect("bindings");
    assert!(
        bindings.iter().any(|r| r.attesting_key_id == node_b.me
            && ciris_persist::federation::admission::envelope_dimension(&r.attestation_envelope)
                == Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)),
        "B's own custody report is one of the blob's bindings"
    );
    assert_eq!(
        ciris_persist::federation::blob_tombstone::binding_state(&*node_b.dir, &file.sha)
            .await
            .expect("fold"),
        ciris_persist::federation::blob_tombstone::BindingState::Live,
        "persist's fold on B: the custody report keeps the withdrawn blob live"
    );
    assert!(
        file_row.open(&node_b.store, &node_b.me).await.is_ok(),
        "B (which reported `here`) still reads the withdrawn file on this persist"
    );

    assert!(node_b.dir.delete_blob(&file.sha).await.expect("delete"));
    for (_, _, chunk) in &file.stream {
        node_b.dir.delete_blob(chunk).await.expect("delete");
    }
    let sweep = puller.durability_sweep().await;
    assert!(
        !sweep.repairs.iter().any(|r| r.sha == file.sha),
        "a withdrawn file is not repaired: {:?}",
        sweep
            .repairs
            .iter()
            .map(|r| hex::encode(r.sha))
            .collect::<Vec<_>>()
    );
    assert!(!sweep.reported_here.contains(&file.sha));
}
