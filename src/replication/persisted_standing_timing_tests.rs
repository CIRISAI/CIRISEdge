//! **The persisted-standing pass, timed at the production row count.**
//!
//! 18,060 live routes in a real sqlite store. The "before" is the pre-fix pass
//! kept verbatim as a loop over the same store, so the two numbers share a
//! disk. It is sqlite, not the production postgres: a read here is a local
//! file, so the reads are printed too; multiply by a real round trip.
//!
//! `cargo test --lib persisted_standing_timing -- --ignored --nocapture`

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ciris_persist::federation::self_at_login::BindingProvenance;
use ciris_persist::federation::FederationDirectory;
use ciris_persist::store::SqliteBackend;
use leviculum_core::Identity;

use super::park_fresh_858_tests::substrate;
use crate::transport::persisted_standing::{StandingRefresh, UNPROVEN_TTL};
use crate::verify::{
    BindingChanges, BindingCursors, HybridPolicy, LiveTransportBinding, ProvenanceChain,
    RootingDirectory, RootingRejection, RootingVerdict,
};

const ROWS: usize = 18_060;

/// The store, counting the reads a pass makes. `proven`: every row proves
/// `owns_key` (a real read, a true answer), so each reaches the table: the
/// costlier shape, since a proven row is what the fold and the revocations are
/// read for.
struct Measured {
    store: Arc<SqliteBackend>,
    proven: bool,
    reads: AtomicUsize,
}

impl Measured {
    fn take(&self) -> usize {
        self.reads.swap(0, Ordering::SeqCst)
    }
    fn hit(&self) {
        self.reads.fetch_add(1, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl RootingDirectory for Measured {
    async fn root_binding(&self, key_id: &str, claimed: &str) -> RootingVerdict {
        self.hit();
        self.store.root_binding(key_id, claimed).await
    }
    async fn provenance_chain(&self, key_id: &str) -> Result<ProvenanceChain, RootingRejection> {
        self.store.provenance_chain(key_id).await
    }
    async fn hybrid_transport_binding_exists(&self, key_id: &str, dest_hash: [u8; 16]) -> bool {
        self.hit();
        let read = RootingDirectory::hybrid_transport_binding_exists(
            self.store.as_ref(),
            key_id,
            dest_hash,
        )
        .await;
        read || self.proven
    }
    async fn live_binding_rows(&self) -> Result<Vec<LiveTransportBinding>, String> {
        self.hit();
        RootingDirectory::live_binding_rows(self.store.as_ref()).await
    }
    async fn live_bindings_of(&self, key_id: &str) -> Result<Vec<LiveTransportBinding>, String> {
        self.hit();
        RootingDirectory::live_bindings_of(self.store.as_ref(), key_id).await
    }
    async fn binding_stands(&self, row: &LiveTransportBinding) -> bool {
        self.reads.fetch_add(2, Ordering::SeqCst);
        RootingDirectory::binding_stands(self.store.as_ref(), row).await
    }
    async fn binding_changes(
        &self,
        cursors: &mut BindingCursors,
        page: u32,
    ) -> Result<BindingChanges, String> {
        self.reads.fetch_add(2, Ordering::SeqCst);
        RootingDirectory::binding_changes(self.store.as_ref(), cursors, page).await
    }
}

async fn seed(store: &SqliteBackend) {
    for i in 0..ROWS {
        let mut seed = [0u8; 64];
        seed[..8].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        seed[32..40].copy_from_slice(&(i as u64 + 1).to_le_bytes());
        let pubkey = Identity::from_private_key_bytes(&seed)
            .expect("an identity")
            .public_key_bytes();
        let dest = crate::transport::reticulum::named_dest_for_test(&pubkey);
        RootingDirectory::persist_transport_binding(
            store,
            &format!("timed-key-{i}"),
            dest,
            pubkey,
            BindingProvenance::Advisory,
            1,
        )
        .await;
    }
}

/// The pass this cut replaced, as it read: the fold, every key's revocations,
/// and every failed row walked again.
async fn the_old_pass(dir: &Measured) -> usize {
    let rows = FederationDirectory::list_all_transport_destinations(dir.store.as_ref())
        .await
        .expect("the rows read");
    let mut reads = 1 + rows.len();
    let now = chrono::Utc::now();
    let mut kept = 0usize;
    for row in &rows {
        let revoked =
            FederationDirectory::revocations_for(dir.store.as_ref(), &row.occurrence_key_id)
                .await
                .map_or(true, |r| r.iter().any(|r| r.effective_at <= now));
        reads += 1;
        if revoked {
            continue;
        }
        let dest = hex::decode(&row.destination).expect("hex");
        let dest: [u8; 16] = dest.try_into().expect("16 bytes");
        reads += 1;
        if dir
            .hybrid_transport_binding_exists(&row.occurrence_key_id, dest)
            .await
        {
            kept += 1;
        }
    }
    let _ = (kept, dir.take());
    reads
}

async fn timed<T>(
    what: &str,
    reads: &Measured,
    work: impl std::future::Future<Output = T>,
) -> Duration {
    reads.take();
    let began = Instant::now();
    work.await;
    let took = began.elapsed();
    eprintln!("{what}: {took:?}, {} reads", reads.take());
    took
}

#[ignore = "seeds 18,060 rows; run by hand for the pass time"]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn persisted_standing_timing_at_the_production_row_count() {
    let store = substrate().await;
    let began = Instant::now();
    seed(&store).await;
    eprintln!("seeded {ROWS} rows in {:?}", began.elapsed());
    let policy = HybridPolicy::Ed25519Fallback;

    for proven in [false, true] {
        eprintln!(
            "--- every row {}",
            if proven { "proven" } else { "unproven" }
        );
        let dir = Arc::new(Measured {
            store: Arc::clone(&store),
            proven,
            reads: AtomicUsize::new(0),
        });
        let old = Instant::now();
        let reads = the_old_pass(&dir).await;
        eprintln!("the old pass: {:?}, {reads} reads", old.elapsed());

        let rooting: Arc<dyn RootingDirectory> = dir.clone();
        let refresh = Arc::new(StandingRefresh::default());
        timed(
            "boot sweep",
            &dir,
            Arc::clone(&refresh).boot(Arc::clone(&rooting), policy, None),
        )
        .await;
        let idle = timed(
            "a tick with no change",
            &dir,
            Arc::clone(&refresh).pass(Arc::clone(&rooting), policy, None),
        )
        .await;
        assert!(idle < Duration::from_secs(1), "an idle tick took {idle:?}");
        refresh.force_sweep_for_test().await;
        timed(
            "a later sweep",
            &dir,
            Arc::clone(&refresh).boot(Arc::clone(&rooting), policy, None),
        )
        .await;
        eprintln!("(failures memoised for {UNPROVEN_TTL:?})");
    }
}
