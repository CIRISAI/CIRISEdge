//! v5.2.0 (CIRISEdge#143) — production adapter exercises the
//! [`FountainEvictHardDelete`] surface end-to-end.
//!
//! The substrate-tier `swarm_rarity` tests already prove the trait
//! dispatches correctly; this integration test verifies the v5.2.0
//! adapter shape — [`PersistFountainEvictHardDelete`] is a thin
//! passthrough that the production caller wires over its persist
//! `Engine` handle. Until persist v9.x exposes the eviction API on
//! `Arc<dyn FederationDirectory>`, the test stops at the adapter
//! boundary; the adapter is exercised against an in-tree recorder
//! that stands in for the persist-side concrete.

use std::sync::{Arc, Mutex};

use ciris_edge::holonomic::swarm_rarity::{FountainEvictError, FountainEvictHardDelete};
use ciris_edge::swarm::PersistFountainEvictHardDelete;

#[derive(Default)]
struct Recorder {
    calls: Mutex<Vec<(String, String)>>,
}
impl FountainEvictHardDelete for Recorder {
    fn evict_fountain_content_hard_delete(
        &self,
        content_id: &str,
        corpus_kind: &str,
    ) -> Result<(), FountainEvictError> {
        self.calls
            .lock()
            .unwrap()
            .push((content_id.to_string(), corpus_kind.to_string()));
        Ok(())
    }
}

#[test]
fn production_adapter_calls_through_to_inner_evictor() {
    let rec: Arc<Recorder> = Arc::new(Recorder::default());
    let adapter = PersistFountainEvictHardDelete::new(rec.clone());

    // Three distinct hard-delete invocations.
    adapter
        .evict_fountain_content_hard_delete("revoked-A", "fountain-corpus")
        .expect("hard-delete succeeds");
    adapter
        .evict_fountain_content_hard_delete("revoked-B", "fountain-corpus")
        .expect("hard-delete succeeds");
    adapter
        .evict_fountain_content_hard_delete("revoked-C", "different-corpus")
        .expect("hard-delete succeeds");

    let calls = rec.calls.lock().unwrap().clone();
    assert_eq!(
        calls,
        vec![
            ("revoked-A".to_string(), "fountain-corpus".to_string()),
            ("revoked-B".to_string(), "fountain-corpus".to_string()),
            ("revoked-C".to_string(), "different-corpus".to_string()),
        ],
        "production adapter must passthrough every call to the inner evictor",
    );
}

#[test]
fn production_adapter_surfaces_inner_failure() {
    struct Failing;
    impl FountainEvictHardDelete for Failing {
        fn evict_fountain_content_hard_delete(
            &self,
            _: &str,
            _: &str,
        ) -> Result<(), FountainEvictError> {
            Err(FountainEvictError::HardDeleteFailed(
                "persist-backend-down".into(),
            ))
        }
    }
    let adapter = PersistFountainEvictHardDelete::new(Arc::new(Failing));
    let err = adapter
        .evict_fountain_content_hard_delete("c1", "fountain-corpus")
        .expect_err("must surface inner failure");
    match err {
        FountainEvictError::HardDeleteFailed(msg) => {
            assert!(
                msg.contains("persist-backend-down"),
                "error message must propagate: {msg}"
            );
        }
    }
}
