//! v0.18.0 (CIRISEdge#33 background pruner) — lifecycle hook gate.
//!
//! Exercises three invariants of the new background pruner:
//! 1. `EdgeConfig::blackhole_prune_interval_seconds = 0` short-circuits
//!    the loop entry (no panic, immediate return).
//! 2. With a non-zero interval, the loop calls
//!    `BlackholeRules::blackhole_prune_expired` at the configured
//!    cadence — an expired rule added before the loop starts is gone
//!    after one tick.
//! 3. The spawn site on `Edge::run` gates on
//!    `reticulum_transport.blackhole_rules_handle()` returning `Some`;
//!    when the transport has no backend wired (test fixture posture),
//!    the spawn is skipped. This invariant is asserted via the
//!    accessor surface (a `None` return means the gate would fire).
//!
//! Requires the Reticulum feature flag so the
//! `blackhole_rules_handle` accessor is in scope:
//! `cargo test --features "transport-reticulum" --test pruner_lifecycle`

#![cfg(feature = "_reticulum-module")]

use std::sync::Arc;
use std::time::Duration;

use ciris_edge::{run_blackhole_pruner, EdgeConfig, DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS};
use ciris_persist::federation::BlackholeRules;
use ciris_persist::prelude::FederationDirectorySqlite;
use ciris_persist::store::sqlite::SqliteBackend;

async fn fresh_backend() -> Arc<SqliteBackend> {
    FederationDirectorySqlite::open(":memory:")
        .await
        .expect("open in-memory persist")
}

fn fixed_hash(byte: u8) -> Vec<u8> {
    // Reticulum identity hashes are 16 bytes; persist validates that
    // length at `blackhole_upsert` entry.
    vec![byte; 16]
}

// ─── #1 interval = 0 disables the background task ───────────────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruner_zero_interval_disables_background_task() {
    // The `run_blackhole_pruner` helper short-circuits when called
    // with `interval_seconds = 0` — the production `Edge::run` spawn
    // site never reaches the helper in that case (the `if interval >
    // 0` gate is the v0.18.0 production guard), but the helper's
    // defensive zero-handling protects against a refactor regression.
    let backend = fresh_backend().await;
    let rules: Arc<dyn BlackholeRules> = backend.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // The helper must return promptly (within a millisecond);
    // there's no tokio interval to wait on. Wrap in a tight timeout
    // so a regression that would hang the loop fails loudly.
    let handle = tokio::spawn(async move {
        run_blackhole_pruner(rules, 0, shutdown_rx).await;
    });
    let outcome = tokio::time::timeout(Duration::from_millis(500), handle).await;
    assert!(
        outcome.is_ok(),
        "pruner with interval=0 returns immediately, not hanging",
    );
    drop(shutdown_tx);
}

// ─── #2 the loop actually prunes at the configured interval ─────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruner_calls_prune_expired_at_interval() {
    let backend = fresh_backend().await;
    let rules: Arc<dyn BlackholeRules> = backend.clone();

    // Seed an EXPIRED rule. `until = now - 1h` — the next prune tick
    // must drop it. Plus a PERMANENT rule (`until = None`) we expect
    // to survive (the persist contract: NULL never prunes).
    let expired_hash = fixed_hash(0xEE);
    let permanent_hash = fixed_hash(0xCC);
    let expired_until = chrono::Utc::now() - chrono::Duration::hours(1);
    rules
        .blackhole_upsert(&expired_hash, Some(expired_until), Some("expired-test"))
        .await
        .expect("upsert expired");
    rules
        .blackhole_upsert(&permanent_hash, None, Some("permanent-test"))
        .await
        .expect("upsert permanent");

    // Verify both are live before the prune.
    let pre = rules.blackhole_list().await.expect("list pre");
    assert_eq!(pre.len(), 2, "two rules seeded");

    // Spawn the pruner with a 1s interval. The first tick fires at
    // 0s (tokio::time::interval default behavior), so we wait ~250ms
    // for the prune to land and check.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let pruner_rules = Arc::clone(&rules);
    let handle = tokio::spawn(async move {
        run_blackhole_pruner(pruner_rules, 1, shutdown_rx).await;
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    // The expired rule should be gone; the permanent rule survives.
    let post = rules.blackhole_list().await.expect("list post");
    let post_hashes: Vec<&Vec<u8>> = post.iter().map(|r| &r.identity_hash).collect();
    assert!(
        !post_hashes.contains(&&expired_hash),
        "expired rule pruned after first tick",
    );
    assert!(
        post_hashes.contains(&&permanent_hash),
        "permanent rule survives prune",
    );

    // Clean shutdown.
    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
}

// ─── #3 spawn is skipped when no blackhole backend is wired ─────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn pruner_skips_when_no_blackhole_rules_wired() {
    // The production `Edge::run` spawn site gates on
    // `reticulum_transport.blackhole_rules_handle()` returning `Some`.
    // When the transport was built WITHOUT a `Arc<dyn BlackholeRules>`
    // (test fixture posture — the v0.16.1 `ReticulumAuth.blackhole_rules`
    // field defaults to `None`), the spawn must be skipped. We can't
    // observe a spawn-not-happening directly, but we can observe the
    // accessor surface: a transport built without the backend returns
    // `None` from `blackhole_rules_handle`, and the conditional spawn
    // site (`if let Some(rules) = ...`) is by construction skipped.
    //
    // Build a `ReticulumTransport` with `ReticulumAuth::default()`
    // (all fields `None`) and assert the accessor returns `None`.
    use ciris_edge::transport::reticulum::{
        ReticulumAuth, ReticulumTransport, ReticulumTransportConfig,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let identity_path = tmp.path().join("test-identity");
    let config = ReticulumTransportConfig::new(identity_path, "test-key".to_string());
    let auth = ReticulumAuth::default();
    let transport = ReticulumTransport::new(config, auth)
        .await
        .expect("build transport");

    assert!(
        transport.blackhole_rules_handle().is_none(),
        "transport built without BlackholeRules accessor returns None — \
         the Edge::run spawn site's `if let Some(rules)` gate fires and \
         skips the spawn",
    );
}

// ─── #4 default interval matches the spec-pinned constant ───────────

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn default_blackhole_prune_interval_is_one_hour() {
    let config = EdgeConfig::default();
    assert_eq!(
        config.blackhole_prune_interval_seconds, DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS,
        "default interval = 1 hour per the v0.18.0 spec",
    );
    assert_eq!(
        DEFAULT_BLACKHOLE_PRUNE_INTERVAL_SECONDS, 3600,
        "spec-pinned constant = 3600 seconds (1 hour)",
    );
}
