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

/// Serves from the author's store, but names `holders` as who it fetches from.
struct NamedHolders {
    inner: StoreFetch,
    holders: Vec<String>,
}

#[async_trait::async_trait]
impl DagByteFetch for NamedHolders {
    fn holders(&self) -> &[String] {
        &self.holders
    }

    async fn fetch(&self, sha: [u8; 32]) -> Result<Vec<u8>, String> {
        self.inner.fetch(sha).await
    }
}

/// **The mirror image: a store-gate refusal on axis 1 or 2 is NOT terminal.**
///
/// Those axes read directory facts that can still land on this node — the
/// holder's owner binding, the room roster, a widening — so the pull books a
/// retry like any fetch that may clear. The first cut ended them `Refused`
/// with nothing booked, and a joiner whose first pull ran before its room's
/// standing converged never asked again (the linux↔android pair room,
/// CIRISServer live chat: `axis 1: SenderNotApprovedForTier`, one attempt).
/// Reverting `gate_refused` to `Refused` turns this RED.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_axis_one_refusal_books_a_retry() {
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

    // A holder this node cannot place in the owner's self-collective (yet).
    let refused = puller
        .pull_dag_with(
            &file.row,
            file.sha,
            &NamedHolders {
                inner: fetch_from(&node_a, &node_b),
                holders: vec!["a-key-this-node-has-not-met".to_owned()],
            },
        )
        .await;
    match &refused {
        PullOutcome::FetchFailed { reason, retrying } => {
            assert!(reason.starts_with("axis 1"), "axis 1 refused: {reason}");
            assert!(*retrying, "the refusal is booked for retry");
        }
        other => panic!("an axis-1 refusal is retried, not terminal: {other:?}"),
    }
    assert!(puller.retry_booked(file.sha), "the retry is on the ledger");

    // Control: from the owner's real node the same pull completes.
    assert!(
        matches!(
            puller
                .pull_dag_with(&file.row, file.sha, &fetch_from(&node_a, &node_b))
                .await,
            PullOutcome::Stored { .. }
        ),
        "from a holder with standing the DAG pulls"
    );
}

/// **The puller's "me" is the node, even when a caller hands it the actor.**
///
/// CIRISServer passed `signer_key_id()` on a split home (`use_node_identity`):
/// the gate resolved the actor's principal, found no room, and refused every
/// room blob `VerifiedOnly`. `wire_self` corrects exactly that id to the
/// node's and leaves every other choice to the caller.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_split_homes_actor_id_is_corrected_to_the_node() {
    use ciris_persist::federation::FederationDirectory;
    let (_alice, node_a, _node_b) = two_devices().await;
    let split = |advertised: Option<&str>| {
        let mut config = crate::EdgeConfig::default();
        config.advertised_key_id = advertised.map(str::to_owned);
        crate::Edge::builder()
            .directory(node_a.dir.clone() as std::sync::Arc<dyn crate::verify::VerifyDirectory>)
            .federation_directory(node_a.dir.clone() as std::sync::Arc<dyn FederationDirectory>)
            .queue(node_a.dir.clone())
            .signer(node_a.signer.clone())
            .transport(std::sync::Arc::new(super::chunk_grants_779_tests::NoWire)
                as std::sync::Arc<dyn crate::transport::Transport>)
            .config(config)
            .build()
            .expect("build edge")
    };
    let actor = node_a.signer.key_id.clone();

    let home = split(Some("the-node-key"));
    assert_eq!(
        super::pull::wire_self(&home, actor.clone()),
        "the-node-key",
        "the actor's id is the node's on a split home"
    );
    assert_eq!(
        super::pull::wire_self(&home, "another-key".to_owned()),
        "another-key",
        "any other id is the caller's to choose"
    );
    let unsplit = split(None);
    assert_eq!(
        super::pull::wire_self(&unsplit, actor.clone()),
        actor,
        "when the two coincide nothing changes"
    );
}
