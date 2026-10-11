//! **A DAG chunk (or manifest) a holder answers withdrawn, purged or revoked
//! ends the pull terminally — no retry booked, no other holder asked.**
//!
//! The whole-blob scheduler has always ended on `GoneFederationWide` as
//! `PullOutcome::Refused`. The DAG fetcher stopped asking holders on the same
//! wire word, but its stop rode `DagFetchStop::Transport`, so the pull ended
//! `FetchFailed` and booked a retry: the withdrawn (and, since persist
//! v54.1.0, purged) DAG was re-asked up the retry ladder although every
//! holder is bound by the same retraction. The stop is typed now
//! (`DagFetchError::Gone`).
//!
//! The witness is the real puller over two in-memory devices (the #779
//! fixture), with a fetcher that answers one address `Gone` and serves the
//! rest from the author's store. Reverting the stop to `Transport`
//! (`fetch_verified`) turns both legs RED: the pull ends `FetchFailed` with a
//! retry booked.
//!
//! `cargo test --lib dag_gone_terminal`

use super::chunk_grants_779_tests::{
    cross_keys_except, edge_of, fetch_from, publish_self_file, puller_of, two_devices, StoreFetch,
    Withhold,
};
use super::pull::{DagByteFetch, DagFetchError, PullOutcome};
use ciris_persist::federation::{FederationDirectory as _, SignedAttestation};

/// Serves every address from the author's store but `gone`, which a holder
/// answers `MissReason::Withdrawn` (what `SwarmFetch` types as `Gone`).
struct GoneOn {
    inner: StoreFetch,
    gone: [u8; 32],
}

#[async_trait::async_trait]
impl DagByteFetch for GoneOn {
    fn holders(&self) -> &[String] {
        self.inner.holders()
    }

    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String> {
        self.fetch_typed(sha).await.map_err(|e| e.to_string())
    }

    async fn fetch_typed(&self, sha: [u8; 32]) -> Result<Vec<u8>, DagFetchError> {
        if sha == self.gone {
            return Err(DagFetchError::Gone("Withdrawn".into()));
        }
        self.inner
            .fetch(sha)
            .await
            .map_err(DagFetchError::Transport)
    }
}

fn assert_gone(outcome: &PullOutcome, what: &str) {
    match outcome {
        PullOutcome::Refused(reason) => assert!(
            reason.contains("withdrawn or revoked federation-wide"),
            "{what}: refused for the retraction, got {reason}"
        ),
        other => {
            panic!("{what}: a gone answer must end the pull Refused (terminal), got {other:?}")
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_gone_manifest_or_chunk_ends_the_dag_pull_with_no_retry() {
    let (alice, node_a, node_b) = two_devices().await;
    let edge_b = edge_of(&node_b);
    let file = publish_self_file(&node_a, &alice).await;
    node_b
        .dir
        .apply_replicated_attestation(SignedAttestation {
            attestation: file.row.clone(),
        })
        .await
        .expect("B admits the crossed row");
    assert!(cross_keys_except(&node_a, &node_b, &Withhold::none(), None).await > 0);
    let puller = puller_of(&node_b, &edge_b);

    // 1. The manifest is answered gone.
    let manifest_gone = puller
        .pull_dag_with(
            &file.row,
            file.sha,
            &GoneOn {
                inner: fetch_from(&node_a, &node_b),
                gone: file.sha,
            },
        )
        .await;
    assert_gone(&manifest_gone, "manifest");
    assert!(
        !puller.retry_booked(file.sha),
        "a gone manifest books no retry: every holder is bound by the same retraction"
    );

    // 2. The manifest arrives; a data chunk is answered gone.
    let chunk_gone = puller
        .pull_dag_with(
            &file.row,
            file.sha,
            &GoneOn {
                inner: fetch_from(&node_a, &node_b),
                gone: file.chunks[0],
            },
        )
        .await;
    assert_gone(&chunk_gone, "chunk");
    assert!(
        !puller.retry_booked(file.sha),
        "a gone chunk books no retry (it used to ride Transport onto the retry ladder)"
    );

    // Control: the same pull with nothing gone completes, so the retraction
    // was the only thing that stopped it.
    assert!(
        matches!(
            puller
                .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
                .await,
            PullOutcome::Stored { .. }
        ),
        "with nothing gone the DAG pulls"
    );
}
