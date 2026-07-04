//! CC 6.1.5.2 §Q `storage-contention` — edge's consumption of the canonical
//! signed shapes, plus the B5 consumption accounting.
//!
//! # The signed shapes are verify's now (CIRISEdge#269 / CIRISVerify#170)
//!
//! The two §Q signed wire shapes — [`StorageBudgetV1`] (owner per-`cohort_scope`
//! budget + `pinned_class`) and [`CorpusWantV1`] (want/have + `size_cap`) — live
//! in [`ciris_verify_core::holonomic::storage_contention`], the canonical home
//! for every §19/§Q signed shape, on verify's shared `Preimage` builder +
//! bound-hybrid gate (verify v8.7.0). Edge **re-exports** them here so the
//! replication layer keeps one import path, and adds the B5 consumption
//! accounting below.
//!
//! Edge previously carried a standalone reimplementation (v8.5.0 / CIRISEdge#258
//! Cut 1) — its own preimage discipline, `bound_hybrid_sign`/`verify`, and
//! domain constants. That forked the canonical bytes; #269 dropped it in favor
//! of verify's. The domain separators are byte-identical (`CIRIS-STG-BUDGET`,
//! `CIRIS-WANT-HAVE\0`), so any already-signed shape verifies unchanged, and
//! the shared #57 freeze-gate goldens
//! (`ciris-verify-core .../holonomic_v19_7/{storage_budget,corpus_want}`) are
//! now the single source of truth for both sides.
//!
//! Verify-at-ingest uses [`verify_storage_budget_v1`] / [`verify_corpus_want_v1`]
//! (structure validate + bound-hybrid Ed25519 + ML-DSA-65). Edge keeps only the
//! **replication logic** — how budgets/wants are used and, here, B5 consumption
//! accounting.

use std::collections::BTreeMap;

use ciris_persist::fountain::FountainHeldMeta;

// ── the canonical §Q signed shapes + verify gates (verify-owned) ──────
pub use ciris_verify_core::holonomic::preimage::{DOMAIN_CORPUS_WANT, DOMAIN_STORAGE_BUDGET};
pub use ciris_verify_core::holonomic::storage_contention::{
    verify_corpus_want_v1, verify_storage_budget_v1, CorpusWantV1, ScopeBudget, StorageBudgetV1,
    StorageContentionError, StorageContentionVerification,
};

// ── B5 consumption accounting (edge-internal) ─────────────────────────

/// CC 6.1.5.2 §Q **B5 consumption accounting** — sum the durable bytes
/// actually held, grouped by `cohort_scope`, recomputed **edge-internally**
/// from what persist holds. Consumption is NEVER trusted from the wire; it
/// is reconciled against real bytes so a forged [`StorageBudgetV1`] cannot
/// become a force-evict channel (B5 consumption-challengeability).
///
/// Input is persist's [`FountainHeldMeta`] rows
/// (`FederationDirectory::list_held_fountain_content`, enriched with
/// `content_bytes` + `cohort_scope` as of CIRISPersist v12.1.0 / #349).
/// Content whose signed envelope declares no scope (`cohort_scope: None`)
/// rolls up under the `None` key — **unattributed budget** (CIRISEdge#260).
///
/// Producers of edge-published fountain content that should draw from a
/// scope's budget MUST set the `cohort_scope` key in the content's signed
/// envelope; persist round-trips it verbatim (it does not infer scope), and
/// unscoped content lands as `None` here.
#[must_use]
pub fn consumption_by_scope(held: &[FountainHeldMeta]) -> BTreeMap<Option<String>, u64> {
    let mut acc: BTreeMap<Option<String>, u64> = BTreeMap::new();
    for meta in held {
        let bucket = acc.entry(meta.cohort_scope.clone()).or_default();
        *bucket = bucket.saturating_add(meta.content_bytes);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(scope: Option<&str>, content_bytes: u64) -> FountainHeldMeta {
        FountainHeldMeta {
            content_id: "cid".into(),
            corpus_kind: "corpus.text".into(),
            pqc_key_id: "pub".into(),
            original_content_length: content_bytes,
            n_source: 10,
            k_repair: 5,
            min_viable_symbols: 10,
            symbol_size: 100,
            held_symbols: 10,
            content_bytes,
            cohort_scope: scope.map(String::from),
            recoverable: true,
            admitted_at: "2026-07-04T00:00:00Z".into(),
        }
    }

    #[test]
    fn consumption_sums_content_bytes_by_scope() {
        let rows = vec![
            held(Some("community"), 100),
            held(Some("community"), 250),
            held(Some("affiliations"), 40),
            held(None, 7), // unscoped envelope → unattributed budget
        ];
        let by = consumption_by_scope(&rows);
        assert_eq!(by.get(&Some("community".to_string())), Some(&350));
        assert_eq!(by.get(&Some("affiliations".to_string())), Some(&40));
        assert_eq!(by.get(&None), Some(&7));
        assert_eq!(by.len(), 3);
        assert!(consumption_by_scope(&[]).is_empty());
    }

    /// CIRISEdge#269 — the §Q shapes now resolve to verify's canonical types.
    /// A compile-level assertion that the re-exports wire up and the fields
    /// edge's replication logic depends on (`pinned_class`, `pin_reserve_bytes`)
    /// are present on verify's shapes.
    #[test]
    fn q_shapes_resolve_to_verify_canonical() {
        let budget = StorageBudgetV1 {
            node_id: "node-a".into(),
            epoch_id: "epoch-1".into(),
            revision: 1,
            scopes: vec![ScopeBudget {
                cohort_scope: "community".into(),
                budget_bytes: 1_000,
                pin_reserve_bytes: 500,
            }],
            pinned_class: vec!["corpus.text".into()],
        };
        assert!(budget.validate().is_ok());
        assert_eq!(budget.scopes[0].pin_reserve_bytes, 500);
        assert_eq!(budget.pinned_class, vec!["corpus.text".to_string()]);

        let want = CorpusWantV1 {
            node_id: "node-b".into(),
            epoch_id: "epoch-1".into(),
            cohort_scope: "community".into(),
            size_cap_bytes: 4_096,
            remaining_budget_bytes: 1_000,
            want: vec!["cid-aaa".into()],
        };
        assert!(want.admits("cid-aaa", 4_096));
        assert!(!want.admits("cid-aaa", 4_097));
    }
}
