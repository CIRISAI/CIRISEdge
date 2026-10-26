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
    assert_eq!(
        verdict(&node_a, &node_a.me, &file.sha).await,
        CustodyVerdict::Here,
        "persist v55's write door filed A's holding claim as it stored the file (CIRISPersist#989)"
    );
    let sweep_a = puller_a.durability_sweep().await;
    assert_eq!(
        (sweep_a.reported_here.clone(), sweep_a.already_here.clone()),
        (Vec::new(), vec![file.sha]),
        "A holds its own file whole, and its report is live and fresh: nothing to re-file"
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
    // A's write door reported both (v55); only F1's report reaches B.
    assert_eq!(puller_a.durability_sweep().await.already_here.len(), 2);
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

/// The custody reports `node` has signed.
async fn custody_reports_by(node: &Node) -> usize {
    node.dir
        .list_attestations_by(&node.me)
        .await
        .expect("list")
        .iter()
        .filter(|r| {
            ciris_persist::federation::admission::envelope_dimension(&r.attestation_envelope)
                == Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)
        })
        .count()
}

/// The `key_grant` sets `node` holds (every axis).
async fn key_grant_rows(node: &Node) -> usize {
    node.dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list")
        .into_iter()
        .filter(|a| ciris_persist::federation::key_grant::is_key_grant_row(&a.attestation))
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
        matches!(&refused, Err(e) if e.to_string().contains("custody_ack_here_dag_incomplete")),
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
    // persist v55 (CIRISPersist#989): B's `here`, filed after its first pull,
    // IS its holding claim, so the repair reports the claim that exists.
    assert_eq!(
        repair,
        PullOutcome::Stored { announced: true },
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
/// refused `Withdrawn`, not `NotGranted` and not a substrate fault, and so is
/// B's even though B filed a custody `here` (persist v53.0.1: a custody
/// report never binds content). Then B's copy is evicted: the pass lists
/// no repair and files no report for it (a retracted file is not
/// durability's to restore). Fails with the pass
/// listing withdrawn files (`LifecycleView::IncludeWithdrawn`): the evicted
/// file comes back as a repair.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // one scenario: withdraw, read on both, refuse `here`, evict, sweep
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

    // B filed a custody `here` after its pull: a federation-tier `scores` row
    // citing the blob in `evidence_refs`. On persist v53.0.0 the tombstone
    // fold counted that report as a LIVE binding, so every device that
    // reported `here` kept reading the withdrawn file. Persist v53.0.1 fixed
    // the shared predicate (a `custody:` row never binds content). On B,
    // which DID report `here`, the read is now `Withdrawn` like A's, and B's
    // own report is not among the blob's bindings.
    let bindings = node_b
        .dir
        .attestations_binding_content(&hex::encode(file.sha))
        .await
        .expect("bindings");
    assert!(
        !bindings.iter().any(|r| r.attesting_key_id == node_b.me
            && ciris_persist::federation::admission::envelope_dimension(&r.attestation_envelope)
                == Some(ciris_persist::federation::custody_ack::CUSTODY_ACK_DIMENSION)),
        "B's own custody report is never a binding of the blob (persist v53.0.1)"
    );
    assert!(
        matches!(
            ciris_persist::federation::blob_tombstone::binding_state(&*node_b.dir, &file.sha)
                .await
                .expect("fold"),
            ciris_persist::federation::blob_tombstone::BindingState::Withdrawn { .. }
        ),
        "persist's fold on B: the withdrawn blob is Withdrawn despite B's custody report"
    );
    let at_b = file_row.open(&node_b.store, &node_b.me).await;
    assert!(
        matches!(
            &at_b,
            Err(crate::files::FileError::Unopened(
                crate::chat::UnopenedReason::Withdrawn { .. }
            ))
        ),
        "B (which reported `here`) reads the withdrawn file as Withdrawn: {:?}",
        at_b.as_ref().map(Vec::len)
    );

    // Edge never files `here` for a retracted file: not on a direct report
    // (the post-pull path), and not on the daily re-file.
    let reports = custody_reports_by(&node_b).await;
    let direct = super::durability::file_custody(
        node_b.store.engine(),
        &file.row,
        &file.sha,
        &file_row.pointer,
        ciris_persist::federation::custody_ack::CustodyState::Here,
    )
    .await;
    assert!(
        matches!(&direct, Err(e) if e.to_string().contains("is retracted")),
        "`here` for a withdrawn file is refused by edge: {direct:?}"
    );
    let resweep = puller.durability_sweep().await;
    assert!(!resweep.reported_here.contains(&file.sha));
    assert_eq!(
        custody_reports_by(&node_b).await,
        reports,
        "the sweep filed no new `here` for the withdrawn file"
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

/// A `tracing` writer into a shared buffer, for a witness that names a log
/// line.
#[derive(Clone, Default)]
struct Captured(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// **A withdrawn self file is refused to peers by the device that reported
/// holding it.** B pulled the file and filed its custody `here`, a row that
/// cites the file's sha in `evidence_refs`. Every row B holds goes through
/// the revocation register as the replication apply path hands it over, and
/// then alice's `withdraws` lands. The register reads `Revoked` (B's custody
/// report is a holding, not a reference), and B's serve door refuses a
/// requesting peer `Withdrawn`, logging the refusal at INFO. The refusal is
/// booked as `blob_serve_refusals["withdrawn"]`. Fails with a custody report
/// counted as a reference (`is_possession_row` without the custody arm): B's
/// own report keeps the register `Live` and B serves the withdrawn file's
/// chunks.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // the register, the serve door, its log line and its counter, in order, on purpose
async fn a_withdrawn_file_is_refused_to_peers_despite_this_devices_custody_report_763() {
    use super::revocation::{apply_observation, observe};
    use super::{BlobChunkSource as _, BytesVerdict, ChunkSourceRefusal, RevocationRegister};

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
        CustodyVerdict::Here,
        "precondition: B reported its copy"
    );

    // Every row B holds, through the register, as the apply path feeds it.
    let register = std::sync::Arc::new(RevocationRegister::default());
    for signed in node_b
        .dir
        .list_attestations_since(None, 1000)
        .await
        .expect("list")
    {
        if let Some(obs) = observe(&signed.attestation) {
            apply_observation(&register, &*node_b.dir, None, obs).await;
        }
    }
    assert_eq!(register.verdict(&file.sha), BytesVerdict::Live);

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
            attestation: withdraws.clone(),
        })
        .await
        .expect("B admits the withdrawal");
    apply_observation(
        &register,
        &*node_b.dir,
        None,
        observe(&withdraws).expect("a withdraws is observed"),
    )
    .await;
    assert_eq!(
        register.verdict(&file.sha),
        BytesVerdict::Revoked,
        "B's own custody report does not keep the withdrawn file live"
    );

    let source = super::PersistBlobChunkSource::new(node_b.store.engine().clone())
        .with_revocations(Some(std::sync::Arc::clone(&register)));
    let captured = Captured::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .finish();
    let refused = {
        let _guard = tracing::subscriber::set_default(subscriber);
        source
            .read_chunk(file.sha, file.stream[0].2, &node_a.me)
            .await
    };
    assert_eq!(
        refused,
        Err(ChunkSourceRefusal::Withdrawn),
        "B refuses the withdrawn file's chunk to a peer"
    );
    let logged = String::from_utf8(captured.0.lock().expect("capture").clone()).expect("utf8");
    assert!(
        logged.contains("INFO") && logged.contains("refusing Withdrawn"),
        "the refusal is logged at INFO: {logged:?}"
    );

    let metrics = crate::observability::EdgeMetrics::new();
    metrics.book_chunk_source_refusal(&ChunkSourceRefusal::Withdrawn);
    metrics.book_chunk_source_refusal(&ChunkSourceRefusal::PolicyDenied);
    assert_eq!(
        metrics
            .snapshot()
            .blob_serve_refusals
            .get(crate::observability::BLOB_SERVE_REFUSED_WITHDRAWN)
            .copied(),
        Some(1),
        "a Withdrawn serve refusal is booked under its tag"
    );
    assert_eq!(
        crate::observability::BLOB_SERVE_REFUSED_WITHDRAWN,
        "withdrawn"
    );
}

/// **CIRISEdge#802 review — the bounded durability pass ROLLS through a
/// room larger than its budget.** In test builds a pass reads pages of 2
/// and stops once it has read 3 files. alice's laptop holds five self
/// files: the first pass reads four (two pages) and saves its place; the
/// second resumes there and reaches the fifth, which a pass restarting at
/// the room's head every time never did (so a room past the budget had its
/// tail permanently excluded from custody refresh and repair). Fails with
/// the pass restarting each room at `None`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_durability_pass_rolls_past_its_file_budget_802() {
    let (alice, node_a, _node_b) = two_devices().await;
    let edge_a = edge_of(&node_a);
    let puller_a = puller_of(&node_a, &edge_a);
    let mut shas = Vec::new();
    for seed in 0..5u32 {
        shas.push(
            publish_self_file_seeded(&node_a, &alice, 0x0802_0000 + seed)
                .await
                .sha,
        );
    }
    // Persist v55's write door filed each file's `here` (CIRISPersist#989),
    // so a pass that reaches a file finds it live and fresh.
    let first = puller_a.durability_sweep().await;
    assert_eq!(
        first.already_here.len(),
        4,
        "the first pass stops after two pages (budget 3): {} reached",
        first.already_here.len()
    );
    let second = puller_a.durability_sweep().await;
    let mut reached: Vec<[u8; 32]> = first.already_here.clone();
    reached.extend(second.already_here.iter().copied());
    for sha in &shas {
        assert!(
            reached.contains(sha),
            "every file is reached within two passes; {} was not",
            hex::encode(sha)
        );
    }
    assert!(
        !second.already_here.is_empty(),
        "the second pass resumed past the first pass's stop, not at the room's head"
    );
}

/// Every `(device, file)` custody verdict and every file's deficit, read
/// twice on `on`: persist's own per-file fold (`row_deficit` over an empty
/// `known`, `device_custody_of`) and one CIRISEdge#817 pass index. They must
/// agree field for field, since they are the only directory-derived inputs a
/// pass's repair and report decisions read.
async fn assert_pass_index_agrees(on: &Node, files: &[&Published], devices: &[&str]) {
    let now = chrono::Utc::now();
    let mut pass = super::durability::PassCustody::new();
    for f in files {
        let per_file = row_deficit(&*on.dir, &f.row, &f.sha, now)
            .await
            .expect("persist's per-file deficit");
        let in_pass = pass
            .row_deficit(&*on.dir, &f.row, &f.sha, now)
            .await
            .expect("the pass's deficit");
        assert_eq!(
            in_pass, per_file,
            "{}: the pass's deficit is persist's per-file deficit",
            on.me
        );
        for d in devices {
            let folded = device_custody_of(&*on.dir, d, &hex::encode(f.sha), None, now)
                .await
                .expect("persist's fold");
            let indexed = pass
                .custody_of(&*on.dir, d, &hex::encode(f.sha), now)
                .await
                .expect("the pass's fold");
            assert_eq!(indexed, folded, "{}: {d}'s verdict agrees", on.me);
        }
    }
}

/// **CIRISEdge#817 item 3 — a durability pass folds each audience device's
/// custody ONCE, not once per file.** alice's laptop A and phone B (audience
/// of two) share four self files; A's pass reads all four (two pages under
/// the test budget). The pass reads two device histories, the audience, where
/// v40.0.3 read F × D + F = 12: `row_deficit` handed persist's `deficit_over`
/// an empty `known`, so every audience node was re-folded
/// (`list_attestations_by(device)`) for every file, plus one more fold per
/// file for A's own verdict. The four files' shared audience is resolved once
/// for the pass, not once per file. The decisions do not move: across states
/// covering `here` (A, then B after a pull and its pass), `unknown` (B before
/// any report) and a report the cohort never carried, the pass's deficits and
/// verdicts equal persist's per-file fold on both nodes, and the passes still
/// report and repair what they did. Fails on v40.0.3 (12 folds).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[allow(clippy::too_many_lines)] // two nodes' passes and the parity check, in order, on purpose
async fn a_durability_pass_folds_each_audience_device_once_817() {
    let (alice, node_a, node_b) = two_devices().await;
    let (edge_a, edge_b) = (edge_of(&node_a), edge_of(&node_b));
    let (puller_a, puller_b) = (puller_of(&node_a, &edge_a), puller_of(&node_b, &edge_b));
    let mut files = Vec::new();
    for seed in 0..4u32 {
        files.push(publish_self_file_seeded(&node_a, &alice, 0x0817_0000 + seed).await);
    }
    for f in &files {
        deliver_row(f, &node_b).await;
    }
    cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await;
    let refs: Vec<&Published> = files.iter().collect();
    let devices = [node_a.me.as_str(), node_b.me.as_str()];
    // Before any report: every verdict is `unknown`.
    assert_pass_index_agrees(&node_a, &refs, &devices).await;

    let sweep_a = puller_a.durability_sweep().await;
    assert_eq!(
        sweep_a.already_here.len(),
        4,
        "A holds all four, each reported by persist v55's write door"
    );
    let audience = super::durability::audience_of(
        &row_deficit(
            &*node_a.dir,
            &files[0].row,
            &files[0].sha,
            chrono::Utc::now(),
        )
        .await
        .expect("deficit"),
    )
    .expect("a self file's audience is enumerable")
    .len();
    assert_eq!(audience, 2, "the audience is alice's two personal devices");
    assert_eq!(
        puller_a.last_durability_custody_folds(),
        audience,
        "a pass over {} files folds each of the {audience} audience devices once, \
         not F x D + F = {}",
        files.len(),
        files.len() * audience + files.len()
    );
    assert_eq!(
        puller_a.last_durability_audience_reads(),
        1,
        "four self files by one author share one audience, resolved once per pass"
    );

    // B: two of A's four reports carried, one file pulled, B's own pass.
    let carried_hex: Vec<String> = files[..2].iter().map(|f| hex::encode(f.sha)).collect();
    for row in node_a
        .dir
        .list_attestations_by(&node_a.me)
        .await
        .expect("list")
    {
        let ack = ciris_persist::federation::custody_ack::parse_custody_ack(&row)
            .ok()
            .flatten();
        if ack.is_some_and(|a| carried_hex.contains(&a.blob_sha256_hex)) {
            node_b
                .dir
                .apply_replicated_attestation(SignedAttestation { attestation: row })
                .await
                .expect("B admits A's report");
        }
    }
    assert_eq!(
        puller_b
            .pull_dag_with(&files[0].row, files[0].sha, &fetch_from(&node_a, &node_b))
            .await,
        PullOutcome::Stored { announced: false }
    );
    assert_pass_index_agrees(&node_b, &refs, &devices).await;
    let sweep_b = puller_b.durability_sweep().await;
    assert_eq!(
        puller_b.last_durability_custody_folds(),
        audience,
        "B's pass folds each audience device once"
    );
    let mut repaired: Vec<[u8; 32]> = sweep_b.repairs.iter().map(|r| r.sha).collect();
    repaired.sort_unstable();
    let mut expected: Vec<[u8; 32]> = files[1..].iter().map(|f| f.sha).collect();
    expected.sort_unstable();
    assert_eq!(
        repaired, expected,
        "B repairs the three files it does not hold"
    );
    let carried = sweep_b
        .repairs
        .iter()
        .find(|r| r.sha == files[1].sha)
        .expect("F1 is a repair");
    assert_eq!(
        carried.live_here,
        vec![node_a.me.clone()],
        "a carried `here` makes A a holder B pulls from"
    );
    assert!(
        sweep_b
            .repairs
            .iter()
            .filter(|r| r.sha != files[1].sha)
            .all(|r| r.live_here.is_empty()),
        "an uncarried report is unknown to B: no live holder"
    );
    // After B's pass filed its `here`, the index still agrees on both nodes.
    assert_pass_index_agrees(&node_b, &refs, &devices).await;
    assert_pass_index_agrees(&node_a, &refs, &devices).await;
}

/// Does `node`'s holder fold, read at `at`, name `node` itself for `sha`?
async fn names_itself(node: &Node, sha: &[u8; 32], at: chrono::DateTime<chrono::Utc>) -> bool {
    ciris_persist::federation::holding_claim::live_holders(&*node.dir, sha, at)
        .await
        .expect("live_holders")
        .contains(&node.me)
}

/// **The pass still FILES a `here` whenever this node's claim is not live
/// and fresh.** Since persist v55 the write door files the holding claim as it
/// stores, so a fresh file is `already_here` on the first pass; this is the
/// pass's own filing job, which those first passes no longer reach. alice's
/// laptop A publishes a self file, and:
///
/// 1. A retracts its claim (a `none`, CC 3.1.3.3 rule 4): its holder fold
///    drops it, and the next pass files a `here` again, so the fold names A.
/// 2. Read 25 h on, the claim is live but past the daily refresh
///    (`CUSTODY_REFRESH`): the pass re-files it.
/// 3. Read 73 h on, every claim A filed has lapsed (72 h liveness): the pass
///    files a fresh one, which the fold at the real clock names.
///
/// Each filing is booked `filed_here` in `durability_custody`; the
/// fresh-claim pass is booked `already_here`. Fails with the filing arm
/// removed (nothing re-files, and a lapsed claim stays lapsed).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_pass_files_here_when_the_claim_is_retracted_stale_or_lapsed_763() {
    use crate::observability::{DURABILITY_ALREADY_HERE, DURABILITY_FILED_HERE};
    use ciris_persist::federation::custody_ack::CustodyState;
    let (alice, node_a, _node_b) = two_devices().await;
    let edge_a = edge_of(&node_a);
    let puller_a = puller_of(&node_a, &edge_a);
    let booked = |tag: &str| {
        edge_a
            .metrics()
            .snapshot()
            .durability_custody
            .get(tag)
            .copied()
            .unwrap_or(0)
    };
    let file = publish_self_file(&node_a, &alice).await;
    let now = chrono::Utc::now;
    assert!(
        names_itself(&node_a, &file.sha, now()).await,
        "the write door filed A's claim"
    );
    let first = puller_a.durability_sweep().await;
    assert_eq!(first.already_here, vec![file.sha]);
    assert_eq!(booked(DURABILITY_ALREADY_HERE), 1);
    assert_eq!(booked(DURABILITY_FILED_HERE), 0);

    // 1. Retracted.
    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    super::durability::file_custody(
        node_a.store.engine(),
        &file.row,
        &file.sha,
        &file_row.pointer,
        CustodyState::None,
    )
    .await
    .expect("A retracts its claim");
    assert!(
        !names_itself(&node_a, &file.sha, now()).await,
        "a `none` retracts A's claim"
    );
    let refiled = puller_a.durability_sweep().await;
    assert_eq!(
        refiled.reported_here,
        vec![file.sha],
        "the pass files a `here` for a retracted claim it still holds whole"
    );
    assert!(
        names_itself(&node_a, &file.sha, now()).await,
        "the fold names A again"
    );
    assert_eq!(booked(DURABILITY_FILED_HERE), 1);

    // 2. Stale: live, but past the daily refresh.
    let stale = puller_a
        .durability_sweep_at(now() + chrono::Duration::hours(25))
        .await;
    assert_eq!(
        stale.reported_here,
        vec![file.sha],
        "a claim past the refresh is re-filed"
    );
    assert_eq!(booked(DURABILITY_FILED_HERE), 2);

    // 3. Lapsed: past the 72 h liveness of every claim A filed.
    let lapsed_at = now() + chrono::Duration::hours(73);
    assert!(
        !names_itself(&node_a, &file.sha, lapsed_at).await,
        "73 h on, every claim A filed has lapsed"
    );
    let lapsed = puller_a.durability_sweep_at(lapsed_at).await;
    assert_eq!(
        lapsed.reported_here,
        vec![file.sha],
        "a lapsed claim is filed afresh"
    );
    assert_eq!(booked(DURABILITY_FILED_HERE), 3);
    assert!(
        names_itself(&node_a, &file.sha, now()).await,
        "the fresh claim is live at the real clock"
    );
    assert!(lapsed.repairs.is_empty() && refiled.repairs.is_empty());
}

/// Tombstone `sha` on `node` with a counter-notice takedown (`dmca512`: the
/// bytes stay on disk through its window, withheld), as persist's own I778
/// does: a claimant who is the signed subject of the content's establishing
/// row files a signed takedown notice, and the node records it.
///
/// persist v60.0.0 (CIRISPersist#803, #854) — the notice is a
/// `takedown_notice:{basis}:v1` ROW the claimant signs, so the claimant is a
/// lowercase federation key id, not a raw base64 pubkey; the basis is CC
/// 3.3.2's spelling (`dmca512`).
async fn take_down(node: &Node, sha: &[u8; 32]) -> String {
    use ciris_persist::federation::takedown_tombstone::{
        notice_dimension, takedown_tombstone, TakedownNotice,
    };
    use ciris_persist::federation::tier_ingest::test_support as ts;
    use ciris_persist::federation::types::attestation_type;
    use ciris_persist::federation::FederationDirectory;
    let dir: &dyn FederationDirectory = &*node.dir;
    let sha_hex = hex::encode(sha);
    let claimant_id = "takedown-claimant-a1".to_owned();
    let producer = "takedown-producer";
    for k in [producer, claimant_id.as_str()] {
        if dir.lookup_public_key(k).await.expect("lookup").is_none() {
            ts::register_hybrid_key(dir, k).await;
        }
    }
    let now = chrono::Utc::now();
    let establishing = ts::seal_row(
        producer,
        ciris_persist::federation::Attestation {
            attestation_id: uuid::Uuid::new_v4().to_string(),
            attesting_key_id: producer.into(),
            attested_key_id: producer.into(),
            attestation_type: attestation_type::SCORES.into(),
            weight: None,
            asserted_at: now,
            expires_at: None,
            attestation_envelope: serde_json::json!({
                "dimension": "content:established:v1",
                "evidence_refs": [sha_hex],
            }),
            original_content_hash: String::new(),
            scrub_signature_classical: String::new(),
            scrub_signature_pqc: None,
            scrub_key_id: producer.into(),
            scrub_timestamp: now,
            pqc_completed_at: Some(now),
            persist_row_hash: String::new(),
            subject_key_ids: vec![claimant_id.clone()],
            withdraws_admission_rule: None,
            cohort_scope: "federation".to_string(),
            tier: ciris_persist::federation::types::attestation_tier::FEDERATION.to_string(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        },
    );
    dir.put_attestation(SignedAttestation {
        attestation: establishing,
    })
    .await
    .expect("the establishing row");
    let basis = "dmca512";
    let envelope = serde_json::json!({
        "dimension": notice_dimension(basis),
        "score": -1.0,
        "confidence": 1.0,
        "subject_kind": "takedown_notice",
        "content_sha256": sha_hex,
        "claimant_key_id": claimant_id,
        "legal_basis": basis,
        "jurisdiction": "US",
        "good_faith_statement": "good faith",
        "claim_text": "claim",
    });
    let mut row = ts::bare_attestation(
        &uuid::Uuid::new_v4().to_string(),
        &claimant_id,
        &claimant_id,
        &envelope,
    );
    row.attestation_type = attestation_type::SCORES.into();
    row.weight = None;
    row.asserted_at = now;
    row.scrub_timestamp = now;
    row.expires_at = Some(now + chrono::Duration::days(30));
    let notice = TakedownNotice::of_row(&ts::seal_row(&claimant_id, row)).expect("notice row");
    let report = takedown_tombstone(dir, &notice, "takedown-node")
        .await
        .expect("the takedown");
    assert!(report.tombstoned, "tombstoned: {report:?}");
    ciris_persist::federation::steward_purge::purge_withheld(dir, sha)
        .await
        .expect("withholding")
        .expect("the bytes are withheld")
}

/// **persist v55 r3 (Codex r3 on #1065) — a durability pass leaves bytes a
/// takedown withholds alone.** alice's laptop holds a self file; a
/// counter-notice takedown tombstones it (the bytes stay on disk, withheld)
/// and the copy then loses a chunk. The pass books it `withheld`, files
/// nothing (persist would refuse a `here` as `custody_ack_here_withheld`, and
/// a `none` would be a report about withheld bytes) and queues NO repair (a
/// repair would pull taken-down content back). Fails with the withholding
/// check removed: nothing is booked `withheld`. (Without the check the pass
/// still files nothing and repairs nothing here — persist's readiness door
/// refuses a withheld manifest, so the pass stops at "holding unreadable" —
/// but silently; the check is what makes the outcome named and keeps the
/// pass from leaning on that read failing.)
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_durability_pass_leaves_withheld_bytes_alone() {
    use crate::observability::DURABILITY_WITHHELD;
    let (alice, node_a, _node_b) = two_devices().await;
    let edge_a = edge_of(&node_a);
    let puller_a = puller_of(&node_a, &edge_a);
    let file = publish_self_file(&node_a, &alice).await;
    let notice = take_down(&node_a, &file.sha).await;
    assert!(!notice.is_empty());
    // Whatever the takedown itself retracted, the pass must add nothing.
    let reports_before = node_a
        .dir
        .list_attestations_by(&node_a.me)
        .await
        .expect("list")
        .len();
    let (_, _, lost) = file.stream[1];
    let _ = node_a.dir.delete_blob(&lost).await.expect("delete");

    let sweep = puller_a.durability_sweep().await;
    assert_eq!(sweep.withheld, vec![file.sha], "booked withheld: {sweep:?}");
    assert!(
        sweep.repairs.is_empty(),
        "no repair pulls taken-down bytes back: {:?}",
        sweep.repairs.iter().map(|r| r.sha).collect::<Vec<_>>()
    );
    assert!(sweep.reported_here.is_empty() && sweep.already_here.is_empty());
    assert_eq!(
        node_a
            .dir
            .list_attestations_by(&node_a.me)
            .await
            .expect("list")
            .len(),
        reports_before,
        "no custody report was filed about withheld bytes"
    );
    assert_eq!(
        edge_a
            .metrics()
            .snapshot()
            .durability_custody
            .get(DURABILITY_WITHHELD)
            .copied(),
        Some(1),
        "booked once for the pass"
    );
}

/// **persist v55.0.0 (5ee68307) — a takedown that lands between the pass's
/// withholding guard and its custody report is booked `withheld`, not
/// `report_refused`.** The guard is bypassed: alice's laptop files `here`
/// straight through `durability::file_custody` for a self file a real
/// counter-notice takedown withholds. persist's custody door refuses it TYPED
/// (`PurgeRefused` with `steward_purge::token::BLOB_PURGED`, naming the
/// notice), and the pass's booking reads it as `withheld` (DEBUG), never a
/// refused report. Fails with the `withheld_notice` match removed from
/// `book_custody_report`: it books `report_refused`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_withheld_here_refused_by_persist_books_withheld_not_report_refused() {
    use crate::observability::{DURABILITY_REPORT_REFUSED, DURABILITY_WITHHELD};
    use ciris_persist::federation::custody_ack::CustodyState;
    let (alice, node_a, _node_b) = two_devices().await;
    let edge_a = edge_of(&node_a);
    let puller_a = puller_of(&node_a, &edge_a);
    let file = publish_self_file(&node_a, &alice).await;
    let notice = take_down(&node_a, &file.sha).await;
    let file_row = crate::files::FileRow::from_row(&file.row).expect("a file row");
    let filed = super::durability::file_custody(
        node_a.store.engine(),
        &file.row,
        &file.sha,
        &file_row.pointer,
        CustodyState::Here,
    )
    .await;
    assert_eq!(
        filed.as_ref().err().and_then(|e| e.withheld_notice()),
        Some(notice.as_str()),
        "persist refuses `here` about withheld bytes, typed, naming the notice: {filed:?}"
    );
    let mut out = super::durability::DurabilitySweep::default();
    assert!(
        puller_a.book_custody_report(
            &hex::encode(file.sha),
            file.sha,
            CustodyState::Here,
            filed,
            &mut out
        ),
        "the report's refusal says the bytes are withheld"
    );
    assert_eq!(out.withheld, vec![file.sha]);
    let booked = edge_a.metrics().snapshot().durability_custody;
    assert_eq!(
        booked.get(DURABILITY_WITHHELD).copied(),
        Some(1),
        "{booked:?}"
    );
    assert_eq!(booked.get(DURABILITY_REPORT_REFUSED), None, "{booked:?}");
}
