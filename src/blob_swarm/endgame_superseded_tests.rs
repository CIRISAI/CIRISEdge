//! 45.1.1 — a chunk is asked of one holder at a time, and a wait another fetch
//! takes is not the holder's failure.
//!
//! Field (CIRISServer 0.5.247 `big_room`, nroom3b, Carol): a one-chunk blob
//! with two routable holders went into endgame at once (`endgame_threshold`
//! 2), the duplicate to the second holder replaced the first holder's wait
//! (the edge holds one waiter per `(blob, chunk)`), each closed wait was an
//! error strike, and the re-dispatch closed the other's wait in turn: both
//! holders were struck out within 45 ms, logged as "channel closed before
//! response".

use std::sync::Arc;
use std::time::Duration;

use super::{ChunkManifestLite, ChunkVerifyError, SwarmConfig, SwarmScheduler};
use crate::blob_swarm::BlobChunkVerifier;
use crate::{ChunkResult, Edge, EdgeBuilder, EdgeConfig};

struct HashVerifier;

impl BlobChunkVerifier for HashVerifier {
    fn verify_and_store(
        &self,
        _blob_sha256: [u8; 32],
        chunk_sha256: [u8; 32],
        bytes: &[u8],
        _disposition: super::StoreDisposition,
    ) -> Result<(), ChunkVerifyError> {
        use sha2::Digest;
        let got: [u8; 32] = sha2::Sha256::digest(bytes).into();
        if got == chunk_sha256 {
            Ok(())
        } else {
            Err(ChunkVerifyError::Mismatch {
                chunk_sha: hex::encode(chunk_sha256),
            })
        }
    }
}

async fn edge(label: &str) -> (Arc<Edge>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let seeds = tmp.path().join("seeds");
    std::fs::create_dir_all(&seeds).expect("seed dir");
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = u8::try_from(i).expect("in range") ^ 0x3c;
    }
    std::fs::write(seeds.join("ed25519.seed"), seed).expect("write seed");
    let mut pqc_seed = seed;
    pqc_seed[0] ^= 0x55;
    std::fs::write(seeds.join("ml_dsa_65.seed"), pqc_seed).expect("write pqc seed");
    let edge = EdgeBuilder::from_keyring_seed_dir(label, seeds, tmp.path().join("edge.sqlite"))
        .await
        .expect("builder")
        .transport(Arc::new(crate::transport::NullTransport))
        .config(EdgeConfig {
            cohort_scope_enforcement: crate::CohortScopeEnforcement::Off,
            ..EdgeConfig::default()
        })
        .build()
        .expect("build edge");
    (Arc::new(edge), tmp)
}

fn one_chunk_blob() -> ([u8; 32], ChunkManifestLite, Vec<u8>) {
    use sha2::Digest;
    let bytes = b"one chunk, two holders".to_vec();
    let sha: [u8; 32] = sha2::Sha256::digest(&bytes).into();
    let manifest = ChunkManifestLite {
        chunks: vec![(sha, bytes.len())],
        total_size: bytes.len() as u64,
    };
    (sha, manifest, bytes)
}

async fn until(deadline: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + deadline;
    while tokio::time::Instant::now() < end {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    ready()
}

/// Two routable holders, one chunk: the chunk is asked ONCE and the blob
/// lands. Red at v45.1.0: the endgame duplicate to the second holder replaced
/// the first wait, and the two re-dispatches kept replacing each other until
/// both holders were struck out (many registrations for one chunk).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_chunk_with_two_holders_is_asked_once_and_lands() {
    let (edge, _tmp) = edge("swarm-endgame-two-holders").await;
    let (sha, manifest, bytes) = one_chunk_blob();
    let scheduler = SwarmScheduler::new(
        Arc::clone(&edge),
        Arc::new(HashVerifier),
        SwarmConfig {
            per_request_timeout: Duration::from_secs(10),
            ..SwarmConfig::default()
        },
    );
    let holders = vec!["holder-alice".to_owned(), "holder-bob".to_owned()];
    let fetch = tokio::spawn(async move { scheduler.fetch_blob(sha, manifest, holders).await });

    assert!(
        until(Duration::from_secs(5), || edge.chunk_wait_registrations()
            >= 1)
        .await,
        "the chunk was never asked for"
    );
    // Let any duplicate the scheduler would send go out before answering.
    tokio::time::sleep(Duration::from_millis(200)).await;
    let asked = edge.chunk_wait_registrations();
    assert!(
        edge.complete_pending_chunk_fetch_for_test(sha, sha, ChunkResult::Bytes(bytes.clone())),
        "a wait for the chunk is open"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .expect("the fetch ends")
        .expect("the fetch task")
        .expect("the blob lands");
    assert_eq!(got, bytes);
    assert_eq!(
        asked, 1,
        "one chunk with two holders is asked of one holder at a time, not raced \
         against a single waiter"
    );
}

/// One holder, a strike limit of one, and another fetch that takes the
/// scheduler's wait: the scheduler asks again and the blob lands. Red at
/// v45.1.0: the taken wait was an error strike, the only holder was retired,
/// and the fetch ended `ChunkUnreachable`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wait_another_fetch_takes_is_not_a_strike() {
    let (edge, _tmp) = edge("swarm-superseded-wait").await;
    let (sha, manifest, bytes) = one_chunk_blob();
    let scheduler = SwarmScheduler::new(
        Arc::clone(&edge),
        Arc::new(HashVerifier),
        SwarmConfig {
            per_request_timeout: Duration::from_secs(10),
            error_strike_limit: 1,
            ..SwarmConfig::default()
        },
    );
    let holders = vec!["holder-only".to_owned()];
    let fetch = tokio::spawn(async move { scheduler.fetch_blob(sha, manifest, holders).await });

    assert!(
        until(Duration::from_secs(5), || edge.chunk_wait_registrations()
            >= 1)
        .await,
        "the chunk was never asked for"
    );
    // A competing fetch of the same chunk takes the scheduler's wait.
    let _competitor = edge.register_chunk_wait_for_test((sha, sha));
    // The scheduler asks again (a third registration) rather than retiring
    // its only holder.
    let asked_again = until(Duration::from_secs(5), || {
        edge.chunk_wait_registrations() >= 3
    })
    .await;
    assert!(
        edge.complete_pending_chunk_fetch_for_test(sha, sha, ChunkResult::Bytes(bytes.clone())),
        "a wait for the chunk is open"
    );
    let got = tokio::time::timeout(Duration::from_secs(10), fetch)
        .await
        .expect("the fetch ends")
        .expect("the fetch task");
    assert!(
        asked_again,
        "the scheduler asked again after its wait was taken"
    );
    assert_eq!(
        got.expect("the blob lands: a taken wait does not retire the holder"),
        bytes
    );
}
