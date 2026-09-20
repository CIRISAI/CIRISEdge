//! `ReplicationRuntime` — the operator-facing entry point that
//! bundles bridge + registry + scheduler + cohort callback into a
//! single managed runtime.
//!
//! Closes the orchestration concern raised in CIRISEdge#65's
//! FSD §3.7. Per the FSD:
//!
//! > `init_edge_runtime` gains [replication parameters]. Each entry
//! > constructs a `ReplicationCoordinator` (Initiator role, because
//! > the operator chose to peer with this remote for this kind),
//! > registers it with the application-side `ReplicationRegistry`
//! > (for inbound dispatch), and adds it to the
//! > `ReplicationScheduler`'s Initiator set.
//!
//! This module is the small bit of glue that does all of that
//! cohesively + exposes a runtime handle the caller can hold for
//! the lifetime of their application.
//!
//! ## Shape
//!
//! - [`ReplicationRuntime::start`] constructs the bridge, builds
//!   coordinators for each peer/kind in the configured set,
//!   registers them with a shared [`ReplicationRegistry`], hands
//!   the Initiator set to a [`ReplicationScheduler`], and spawns
//!   the scheduler's run loop on the current tokio runtime.
//! - [`ReplicationRuntime::register_peer`] hot-adds a new
//!   `(peer_key_id, kind)` after start.
//! - [`ReplicationRuntime::registry`] returns a shared
//!   `Arc<ReplicationRegistry>` the application's `Transport::listen`
//!   loop calls `route_inbound_bytes` on. The listen-loop integration
//!   itself is operator code — when bytes arrive identifying a
//!   source peer, the operator calls `registry.route_inbound_bytes(
//!   peer_key_id, bytes)` and that's it.
//! - [`ReplicationRuntime::shutdown`] flips the scheduler's cancel
//!   watch to true and awaits the scheduler's run-loop task to
//!   completion.
//!
//! ## Why no auto-routing into transport.listen()
//!
//! Edge's `Transport::listen` already runs in the application's
//! existing dispatch loop. Wiring the registry's `route_inbound_bytes`
//! INTO that loop is operator code (a one-line addition to the
//! application's listen-handler), not edge's job. This keeps the
//! v1 cut clean: the runtime exposes the registry; the operator
//! wires it. A v1.7 follow-up may add an opt-in
//! `Edge::install_replication_routing(runtime)` helper.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use ciris_persist::federation::FederationDirectory;
use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinHandle;

use super::bridge::{BridgeConfig, CohortProvider, FederationDirectoryReplicationBridge};
use super::coordinator::{DriveStep, ReplicationCoordinator};
use super::directory::{DirectoryStateAdapter, MutableDirectoryStateAdapter, ReplicationDirectory};
use super::mesh_config::MeshConfigReader;
use super::protocol::EnvelopeKind;
use super::registry::ReplicationRegistry;
use super::scheduler::{
    ReplicationScheduler, RoundEvent, SchedulerCommandError, SchedulerConfig, SchedulerHandle,
};
use super::session::SessionRole;
use super::summary::{StateApplier, StateProvider};
use crate::transport::Transport;

/// CIRISEdge#373 — outer bound on a single responder reply send inside the drive
/// loop, so a stalled reply can't park the inbound drain forever. Sized to sit
/// just ABOVE the reverse-path progress-aware hard cap (`REVERSE_PATH_MAX_TRANSFER`
/// = 45 s, v13.6.1) plus dial margin, so it never severs a LIVE, progressing
/// large-resource transfer — that would re-open the exact live-link cut v13.6.1
/// fixes. A DEAD link now fast-fails at the reverse-path no-progress window (~6 s),
/// so this bound only bites a genuinely pathological send; a progressing transfer
/// is delivering the trace, so letting it run is correct.
const RESPONDER_REPLY_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// CIRISEdge#348 — drive a factory-created **Responder** coordinator.
///
/// The registry only STORES a coordinator; the [`ReplicationScheduler`] drives
/// **Initiators** only (`add_initiator`). A Responder spun up on-demand for an
/// inbound round from a non-consent-pull peer (the #312 responder factory) has
/// no other driver — so this task IS its round engine: pull each inbound
/// replication message, step the round, and emit every reply on the transport.
///
/// Without it, `route_inbound_bytes` queues the round-open into the
/// responder's inbox and it is NEVER processed — the responder never
/// replies, the initiator times out forever, and (the seam that cost the mesh
/// weeks — #348) NOTHING logs. This was the missing half of #312: it spun up +
/// registered the Responder but never ran the drive loop. Spawned ONCE per
/// (peer, kind) — the registry invokes the factory only on first insert into
/// its RESPONDERS table (CIRISEdge#634: a responder's slot is never the
/// initiator's). Every terminal / error path logs; there is no silent discard.
/// CIRISEdge#397 — bring persist's `signed_wire_index` (V111) current so the
/// content-hash point-read fetch resolves pre-existing rows. Run ONCE at
/// startup: idempotent, and fail-soft — a backend that doesn't implement the
/// rebuild errors (fine; that backend's fetch stays on the local cache path),
/// and every subsequent signed put keeps the index current via persist's
/// per-write hook.
async fn rebuild_signed_wire_index_fail_soft(directory: &Arc<dyn FederationDirectory>) {
    if let Ok(n) = directory.rebuild_signed_wire_index().await {
        tracing::info!(indexed = n, "rebuilt signed_wire_index (CIRISEdge#397)");
    }
}

/// **The self-publish set — what this node advertises ABOUT ITSELF.**
///
/// Hand this to [`ReplicationRuntime::start`]'s `self_provider`. It is the set
/// of identities this node speaks for, and it gates the `SelfOwn` planes:
/// `Key`, `IdentityOccurrence`, and `TransportDestination`.
///
/// `TransportDestination` is the one that surprises people. It is the node's
/// TRANSPORT HINT — the `(peer, dest)` binding a peer needs to satisfy
/// CIRISEdge#393 item 2 — so a node that does not publish it has its frames
/// DROPPED at every peer's attribution gate, reported as "item 1 PASSED
/// (Rooted ∧ owns_key) but item 2 FAILED". The row exists on its author the
/// whole time; nothing offers it.
///
/// Include every identity the node holds, not just the node key. An agent and
/// its owner are separate identities (three keys minimum: human, node, agent),
/// and their rows must reach peers for `resolve(agentID) -> owner -> nodes` to
/// walk anywhere.
///
/// ```ignore
/// let runtime = ReplicationRuntime::start(
///     directory, transport, peers, config,
///     Some(self_publish_set([&node_key_id, &agent_key_id, &owner_key_id])),
/// ).await;
/// ```
#[must_use]
pub fn self_publish_set<I, S>(identities: I) -> CohortProvider
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let set: Vec<String> = identities
        .into_iter()
        .map(|s| s.as_ref().to_owned())
        .collect();
    Arc::new(move || set.clone())
}

/// Assemble the production bridge from the runtime config. Extracted from
/// [`ReplicationRuntime::start`] so the builder chain reads as one thing (and so
/// `start` stays under the clippy line ceiling).
///
/// CIRISEdge#433 — `.with_metrics` is the wiring that makes the withhold ledger +
/// the replication-plane served counter live: the bridge writes to the SAME
/// `EdgeMetrics` handle the rest of the edge reports from. This is the ONE
/// production bridge construction — every coordinator (the initiator set AND the
/// #312 responder factory) shares this instance, so wiring it here covers both
/// roles. `config.metrics` is `None` only when the operator started the runtime
/// without a metrics handle, which also disables the #370 round-outcome counter;
/// the ledger degrades the same way (every increment becomes a no-op).
fn build_bridge(
    directory: &Arc<dyn FederationDirectory>,
    cohort: CohortProvider,
    config: &ReplicationRuntimeConfig,
    self_provider: Option<CohortProvider>,
    mesh_config: Option<Arc<MeshConfigReader>>,
    convergence: Arc<super::convergence::ConvergenceSignal>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let bridge_config = resolve_sweep_permits(config.bridge);
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(directory),
            cohort,
            bridge_config,
        )
        .with_self_provider(self_provider)
        .with_convergence(Some(convergence))
        .with_local_key_id(config.local_key_id.clone())
        .with_engine(config.sealed_content.as_ref().map(|w| w.engine.clone()))
        .with_revocations(
            config
                .sealed_content
                .as_ref()
                .and_then(|w| w.revocations.clone()),
        )
        .with_pull_sink(
            config
                .sealed_content
                .as_ref()
                .and_then(|w| w.pull_sink.clone()),
        )
        .with_serve_tier_subject(config.serve_tier_subject_key_id.clone())
        // ROLE_MATRIX Axis 3 — the production serve-tier resolver: canonical
        // legs live (leg A ∧ leg B against this node's own trust base), the
        // owner-conferred rung fail-closed pending CIRISPersist#788. Installed
        // iff a local identity exists, because leg B and the cache subject are
        // both keyed on it; without one the tier stays fail-closed `None`.
        .with_serve_tier_resolver(
            config
                .serve_tier_subject_key_id
                .clone()
                .or_else(|| config.local_key_id.clone())
                .map(|local| {
                    std::sync::Arc::new(
                        crate::replication::serve_tier::DirectoryServeTierResolver::new(
                            Arc::clone(directory),
                            local,
                        ),
                    )
                        as std::sync::Arc<dyn crate::replication::serve_tier::ServeTierResolver>
                }),
        )
        .with_metrics(config.metrics.clone())
        .with_mesh_config(mesh_config)
        // Workstream F — installed iff the operator turned enforcement ON. See
        // `ReplicationRuntimeConfig::accord_relay_enforced`: `false` keeps
        // `accord:*` carriage on the projection row alone (pre-workstream
        // behavior) and `true` enforces the fail-closed relay predicate on both
        // the advertise sweep and its direct-fetch twin. CIRISPersist#731 — no
        // root is passed: each object names its own, in its signed bytes.
        .with_accord_relay_gate(config.accord_relay_enforced.then(|| {
            Arc::new(crate::replication::accord_relay_gate::AccordRelayGate::new(
                Arc::clone(directory),
                config.local_key_id.clone(),
            ))
        })),
    )
}

/// CIRISEdge#531 — apply the [`BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV`]
/// override, if the operator set one, to the runtime's bridge config.
///
/// This is the ONE production assembly point every downstream reaches
/// (`ReplicationRuntime::start` → [`build_bridge`]), including the ones —
/// CIRISServer — that never construct a [`BridgeConfig`] of their own and so
/// cannot reach the field. Deliberately NOT in `BridgeConfig::default()`: an
/// env read inside `Default` would make every test construction in the repo
/// environment-sensitive, which is how a green suite starts lying.
///
/// A missing var leaves the configured value (the default, 2) alone. An
/// unparseable one WARNS and leaves it alone too — a typo in an env var must
/// not be able to change the node's memory posture, in either direction.
fn resolve_sweep_permits(mut config: BridgeConfig) -> BridgeConfig {
    config = resolve_sweep_page_rows(config);
    let Ok(raw) = std::env::var(BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV) else {
        return config;
    };
    match raw.trim().parse::<usize>() {
        // CIRISEdge#531 (review finding) — a value that PARSES but exceeds
        // `Semaphore::MAX_PERMITS` (`usize::MAX >> 3`) used to sail past this
        // check and panic inside `Semaphore::new`, taking the node down at boot
        // on an operator typo — in the one knob whose whole purpose is keeping a
        // wedged box alive. It is now refused like any other bad value, and
        // `SweepGate::new` clamps as the belt under this brace.
        Ok(n) if n > tokio::sync::Semaphore::MAX_PERMITS => tracing::warn!(
            raw = %raw,
            max = tokio::sync::Semaphore::MAX_PERMITS,
            env = BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV,
            keeping = config.advertise_sweep_permits,
            "advertise-sweep width bound override exceeds the semaphore maximum \
             — IGNORED, keeping the configured value (CIRISEdge#531)"
        ),
        Ok(n) => {
            tracing::info!(
                permits = n,
                configured = config.advertise_sweep_permits,
                env = BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV,
                "advertise-sweep width bound overridden from the environment \
                 (0 = unbounded, the pre-CIRISEdge#531 behaviour)"
            );
            config.advertise_sweep_permits = n;
        }
        Err(e) => tracing::warn!(
            error = %e,
            raw = %raw,
            env = BridgeConfig::ADVERTISE_SWEEP_PERMITS_ENV,
            keeping = config.advertise_sweep_permits,
            "advertise-sweep width bound override is not a usize — IGNORED, \
             keeping the configured value (CIRISEdge#531)"
        ),
    }
    config
}

/// CIRISEdge#531 DEPTH — apply the [`BridgeConfig::SWEEP_PAGE_ROWS_ENV`]
/// override. Same contract as [`resolve_sweep_permits`]: missing or
/// unparseable leaves the configured value alone, `0` is the documented escape
/// hatch back to one whole-table read per sweep.
///
/// This is the knob that makes the memory FLAT rather than merely bounded, so
/// it deserves the same out-of-band lever: the deployment this was filed for
/// (CIRISServer) never constructs a [`BridgeConfig`] and so cannot reach the
/// field on a box that is already wedged.
fn resolve_sweep_page_rows(mut config: BridgeConfig) -> BridgeConfig {
    let Ok(raw) = std::env::var(BridgeConfig::SWEEP_PAGE_ROWS_ENV) else {
        return config;
    };
    match raw.trim().parse::<u32>() {
        Ok(n) => {
            tracing::info!(
                rows = n,
                configured = config.sweep_page_rows,
                env = BridgeConfig::SWEEP_PAGE_ROWS_ENV,
                "sweep page size overridden from the environment (0 = one \
                 whole-table read per sweep, the pre-DEPTH behaviour)"
            );
            config.sweep_page_rows = n;
        }
        Err(e) => tracing::warn!(
            error = %e,
            raw = %raw,
            env = BridgeConfig::SWEEP_PAGE_ROWS_ENV,
            keeping = config.sweep_page_rows,
            "sweep page size override is not a u32 — IGNORED, keeping the \
             configured value (CIRISEdge#531)"
        ),
    }
    config
}

/// CIRISEdge#440 — the ONE resolved mesh-config reader, shared by the bridge
/// (page limit + trace pause), the scheduler (cadence), and — via
/// [`ReplicationRuntime::mesh_config_reader`] — any host-wired A/V transit
/// gate. Built iff there is a `local_key_id`: the fold is about a node's OWN
/// subscription + consent baseline, and without an identity there is no node
/// to resolve for (the same structural condition that fail-closes the #386
/// serve gate). The baseline pins the node's ACTUAL configured cadence + page
/// limit, so an empty plane resolves to exactly what the node already runs —
/// relief, never a gate.
fn build_mesh_config_reader(
    directory: &Arc<dyn FederationDirectory>,
    config: &ReplicationRuntimeConfig,
) -> Option<Arc<MeshConfigReader>> {
    config.local_key_id.as_ref().map(|local| {
        Arc::new(MeshConfigReader::new(
            Arc::clone(directory),
            local.clone(),
            MeshConfigReader::baseline_for(
                config.scheduler.cadence,
                config.bridge.operational_page_limit,
            ),
        ))
    })
}

/// CIRISEdge#370 — spawn the scheduler's run loop. With a live metrics handle,
/// route each round's [`RoundEvent`] through a purpose-built `event_sink` into
/// a consumer task that folds it into the `EdgeMetrics` round-outcome counter
/// (the field instrument for the transport concurrency ceiling, leviculum#29);
/// without one, keep the zero-overhead `run_until_cancelled` path — no
/// channel, no consumer task. The scheduler tolerates a closed sink, and the
/// consumer's `recv()` returns `None` when the scheduler task ends and drops
/// the sender, so the consumer winds down without its own cancel. (Extracted
/// from [`ReplicationRuntime::start`] verbatim for the clippy line ceiling.)
/// CIRISEdge#640 — the start line says which doors this runtime has, as
/// edge's own truth (the host logs its intent; this is what it got).
fn log_started(config: &ReplicationRuntimeConfig, peers: usize, proactive_publish: bool) {
    tracing::info!(
        peers,
        local_key_id = ?config.local_key_id,
        sealed_content = ?config.sealed_content,
        proactive_publish,
        "replication runtime STARTED — sealed_content: None means this node neither pulls \
         nor opens sealed content; a puller or a revocation register cannot exist without \
         the engine (SealedContentWiring, CIRISEdge#640)"
    );
}

fn spawn_scheduler_task(
    scheduler: ReplicationScheduler,
    handle: &SchedulerHandle,
    cancel_rx: watch::Receiver<bool>,
    config: &ReplicationRuntimeConfig,
) -> JoinHandle<()> {
    let metrics = config.metrics.clone();
    let handle = handle.clone();
    // The round-event sink always runs: it feeds the outcome counters when
    // metrics are configured AND (CIRISEdge#636) turns every round that admitted
    // rows into a propagation kick toward the other peers on that plane.
    let (evt_tx, mut evt_rx) = mpsc::channel::<(String, RoundEvent)>(256);
    tokio::spawn(async move {
        // Debounce per plane: a burst of admitting rounds on one plane fires
        // ONE fan-out per window; the kicks coalesce per coordinator anyway,
        // this just keeps the command channel quiet under a flood.
        const PROPAGATE_DEBOUNCE: std::time::Duration = std::time::Duration::from_millis(500);
        let mut last_propagate: HashMap<EnvelopeKind, std::time::Instant> = HashMap::new();
        while let Some((peer, event)) = evt_rx.recv().await {
            if let Some(m) = &metrics {
                m.inc_round_outcome(round_outcome_of(&event));
            }
            if let RoundEvent::Completed(report) = &event {
                if report.admitted > 0 {
                    let due = last_propagate
                        .get(&report.kind)
                        .map_or(true, |at| at.elapsed() >= PROPAGATE_DEBOUNCE);
                    if due {
                        last_propagate.insert(report.kind, std::time::Instant::now());
                        if handle.propagate(&peer, report.kind).await.is_err() {
                            break; // the scheduler is gone; so is this sink's job
                        }
                    }
                }
            }
        }
    });
    tokio::spawn(async move {
        scheduler.run_with_events(cancel_rx, Some(evt_tx)).await;
    })
}

fn spawn_responder_drive(coord: Arc<ReplicationCoordinator>) {
    tokio::spawn(async move {
        let peer = coord.peer_key_id().to_string();
        let kind = coord.kind();
        tracing::debug!(peer = %peer, ?kind, "responder driver started (CIRISEdge#348)");
        loop {
            // Channel closed ⇒ the coordinator was dropped; end the driver.
            // CIRISEdge#634 — take the frame WITH its round metadata so the
            // step can rebind (a new round resets a stuck session) and the
            // replies below echo the round; a legacy frame (`meta: None`)
            // gets a legacy reply.
            let Some(inbound) = coord.recv_inbound_framed().await else {
                tracing::debug!(peer = %peer, ?kind, "responder driver ending (channel closed)");
                break;
            };
            match coord.drive_round_step_framed(Some(inbound)).await {
                Ok(DriveStep::SendThenWait(msgs)) => {
                    for m in &msgs {
                        // CIRISEdge#373 — BOUND the reply send. This loop is the
                        // responder's only inbound drain; a reply that blocks here
                        // (a reverse-path stall to a churning NAT'd peer + the
                        // NAT-blocked dial fallback = up to ~130 s) parks the drain
                        // while the peer keeps pushing frames, overflowing the
                        // capacity-8 inbound channel and silently dropping 100% of
                        // the trace. Cap it well under the round cadence so a stalled
                        // reply yields the drain; the abandoned send is safe (its
                        // awaits — resource wait, dial — are cancellation-tolerant,
                        // and the anti-entropy protocol is idempotent + retried).
                        match tokio::time::timeout(
                            RESPONDER_REPLY_SEND_TIMEOUT,
                            coord.send_message(m),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(e)) => {
                                tracing::warn!(
                                    peer = %peer, ?kind, error = %e,
                                    "responder reply send failed — round will not complete (CIRISEdge#348)"
                                );
                                break;
                            }
                            Err(_elapsed) => {
                                tracing::warn!(
                                    peer = %peer, ?kind,
                                    timeout_secs = RESPONDER_REPLY_SEND_TIMEOUT.as_secs(),
                                    "responder reply send TIMED OUT — abandoning it so the inbound \
                                     drain resumes and the peer's trace is not dropped (CIRISEdge#373); \
                                     the next round rides the peer's fresh link"
                                );
                                break;
                            }
                        }
                    }
                }
                // CIRISEdge#380 — defensive: `SendThenComplete` is initiator-only
                // (`start_round` emits it; responders never start rounds). If it
                // ever appears here, honor its semantics: send, then done.
                Ok(DriveStep::SendThenComplete(msgs, report)) => {
                    for m in &msgs {
                        if let Err(e) = coord.send_message(m).await {
                            tracing::warn!(
                                peer = %peer, ?kind, error = %e,
                                "responder SendThenComplete send failed (CIRISEdge#380)"
                            );
                            break;
                        }
                    }
                    tracing::debug!(
                        peer = %peer, ?kind, ?report,
                        "responder round complete (initiator-final path, CIRISEdge#380)"
                    );
                }
                Ok(DriveStep::Complete(report)) => {
                    tracing::debug!(
                        peer = %peer, ?kind, ?report,
                        "responder served an anti-entropy round to completion (CIRISEdge#348)"
                    );
                }
                Ok(DriveStep::Refused) => {
                    tracing::warn!(
                        peer = %peer, ?kind,
                        "responder REFUSED an inbound replication message (unexpected role/phase) \
                         — dropped, NOT silently (CIRISEdge#348)"
                    );
                }
                Err(e) => {
                    tracing::warn!(
                        peer = %peer, ?kind, error = %e,
                        "responder drive_round_step failed; ending driver (CIRISEdge#348)"
                    );
                    break;
                }
            }
        }
    });
}

/// CIRISEdge#370 — project a scheduler [`RoundEvent`] onto the
/// metrics-facing [`crate::observability::RoundOutcome`] label. The
/// `Completed` report payload and the `Error` string are intentionally
/// dropped here — high-cardinality per-round detail rides the round's
/// tracing span, not the counter key.
fn round_outcome_of(event: &RoundEvent) -> crate::observability::RoundOutcome {
    use crate::observability::RoundOutcome;
    match event {
        RoundEvent::Completed(_) => RoundOutcome::Completed,
        RoundEvent::Refused => RoundOutcome::Refused,
        RoundEvent::TimedOut => RoundOutcome::TimedOut,
        RoundEvent::Error(_) => RoundOutcome::Error,
    }
}

/// A `(peer_key_id, kind)` pair the runtime should anti-entropy with
/// as the Initiator side. Each pair gets one [`ReplicationCoordinator`]
/// in the Initiator role.
#[derive(Debug, Clone)]
pub struct ReplicationPeer {
    pub peer_key_id: String,
    pub kind: EnvelopeKind,
}

/// CIRISEdge#640 — the sealed-content door, as one value.
///
/// The engine's job is to project the wraps a `key_grant` row carries into
/// grants for THIS node's occurrences (`Engine::apply_replicated_key_grant`,
/// CIRISPersist#848). The only node that ever needs a projected wrap is one
/// that will OPEN sealed bytes it did not seal — and sealed bytes arrive only
/// through the puller; withdrawals of the sets it projects arrive only
/// through the revocation register. So `pull_sink ⇒ engine` and
/// `revocations ⇒ engine`, and this struct is that rule spelled as a type:
/// there is no way to hold a puller or a register without the engine they
/// depend on. The receive-side twin of `BlobChunkSource::answers_scope`.
///
/// Build the engine with `Engine::from_shared_with_local` over the same
/// substrate (`PersistGroupContentStore::from_shared_hybrid` builds it); the
/// sink with `blob_swarm::BlobPuller::spawn`; hand the same
/// [`RevocationRegister`](crate::blob_swarm::RevocationRegister) to the blob
/// chunk source and the swarm converger. A node that SEALS for a room must
/// also be able to open what the room sends back: install this wherever you
/// install the puller.
#[derive(Clone)]
pub struct SealedContentWiring {
    /// CIRISPersist#848 / CIRISEdge#601 — the key-grant door. A `key_grant:*`
    /// attestation row arriving on the Attestation cursor is routed to
    /// `Engine::apply_replicated_key_grant`, which admits the carrier AND
    /// projects the wraps addressed to this node's occurrences.
    pub engine: super::bridge::BridgeEngine,
    /// CIRISEdge#601 — the pull sink. An admitted attestation that references
    /// a blob is offered here; the `BlobPuller` behind it projects the
    /// meaning, runs the store gate and fetches. `None` = rows arrive and
    /// bytes never do; every non-author member reads `NotFetched`.
    pub pull_sink: Option<crate::blob_swarm::PullSink>,
    /// CIRISEdge#606 — CC 2.3 at the bytes plane. `Some` ARMS the withdraws
    /// observer on the apply path (see
    /// [`RevocationWiring`](super::bridge::RevocationWiring)).
    pub revocations: Option<super::bridge::RevocationWiring>,
}

impl std::fmt::Debug for SealedContentWiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedContentWiring")
            .field("engine", &true)
            .field("pull_sink", &self.pull_sink.is_some())
            .field("revocations", &self.revocations.is_some())
            .finish()
    }
}

/// Configuration for [`ReplicationRuntime::start`].
#[derive(Debug, Clone, Default)]
pub struct ReplicationRuntimeConfig {
    /// Cadence + round-timeout for the scheduler. Defaults to
    /// [`SchedulerConfig::default`] (30 s cadence, 10 s round timeout).
    pub scheduler: SchedulerConfig,
    /// Cache + paging tuning for the bridge. Defaults to
    /// [`BridgeConfig::default`].
    pub bridge: BridgeConfig,
    /// CIRISEdge#370 — optional live metrics handle. When `Some`,
    /// [`ReplicationRuntime::start`] wires the scheduler's `event_sink`
    /// to a consumer task that folds each round's
    /// [`RoundEvent`](crate::replication::scheduler::RoundEvent) into
    /// the [`EdgeMetrics::inc_round_outcome`](crate::observability::EdgeMetrics::inc_round_outcome)
    /// counter — the field instrument for the transport concurrency
    /// ceiling. `None` (the default) preserves the pre-#370
    /// `run_until_cancelled` path with no event-sink overhead. This is a
    /// live shared handle (its counters are `Arc`-backed), not tuning —
    /// it rides on the config only because `start` already threads the
    /// config through to the scheduler-spawn site.
    pub metrics: Option<crate::observability::EdgeMetrics>,
    /// CIRISEdge#386 — this node's OWN federation key_id. Required for the
    /// `trace:*` serve gate: it is the `user` half of the trust-root walk
    /// ("does the recipient's `infra:serve` root to a root I trust?"). `None`
    /// fail-closes that gate (and only that gate — every other plane is
    /// unaffected), logging a WARN, because a node with no local identity
    /// cannot evaluate its own trust. The server supplies the same
    /// `node_key_id` it already threads into consent-peer resolution.
    pub local_key_id: Option<String>,
    /// CIRISEdge#541/#552 — the subject whose SERVING TIER is resolved.
    ///
    /// Distinct from `local_key_id` on purpose. `local_key_id` is the truster
    /// for the E3 trace gate's leg B and the subject of the own-record Pull
    /// arm; the tier is a property of the identity peers REGISTERED and
    /// conferred against, which under `use_node_identity` is the node, not the
    /// actor. Redefining `local_key_id` would have moved a security path's
    /// truster identity as a side effect.
    ///
    /// Falls back to `local_key_id` when unset — correct for every deployment
    /// where the two identities coincide.
    pub serve_tier_subject_key_id: Option<String>,
    /// CIRISEdge#640 — everything a node needs to OPEN sealed content it did
    /// not seal, wired as ONE value (see [`SealedContentWiring`]): the engine
    /// that projects key-grant wraps into grants for this node's occurrences,
    /// with the puller and the revocation register that only make sense
    /// beside it. `None` is a node that neither pulls nor opens sealed
    /// content (pre-v24.1.0 behaviour: a `key_grant:*` row is admitted as a
    /// carrier and LOGS AN ERROR naming this field). The half-wired states —
    /// a puller with no engine (bytes arrive that nobody can open: every
    /// member reads `NotGranted` with the row present, 0.5.207–0.5.213's
    /// shape), a register with no engine — are not constructible.
    pub sealed_content: Option<SealedContentWiring>,
    /// Workstream F — does this node ENFORCE the `accord:*` relay predicate?
    /// `true` installs the
    /// [`AccordRelayGate`](crate::replication::accord_relay_gate::AccordRelayGate)
    /// on the bridge (fail-closed carriage: persist's `may_relay_accord_object`
    /// — seated signer AND a live `delegates_to(self → root)`); `false` (the
    /// default) leaves `accord:*` carriage exactly as the `Global` projection
    /// row alone decides it, i.e. byte-identical pre-workstream behavior.
    ///
    /// # A bool, because the root is NOT the operator's to name (CIRISPersist#731)
    ///
    /// This was an `Option<String>` — the accord root every `accord:*` object
    /// was judged against. That is the defect #731 reports: a host that names
    /// the wrong root gets a confidently wrong answer *in the permissive
    /// direction*, because an object belonging to a different accord is checked
    /// against a roster that may well seat its signer, and the predicate cannot
    /// notice — it was never given the object. CC 4.2.3 does make the accord an
    /// INSTANCE parameter (*"another instantiation of this form names its own
    /// three"*), but the instance is named by each OBJECT, in its
    /// signature-covered bytes, and reading it there is the fix.
    ///
    /// So the only thing left for an operator to decide is whether to enforce
    /// at all. Turning it on remains a dated fleet-floor event (the AV-42
    /// `RequireTransportBinding` shape), never a silent default: a fleet whose
    /// family records have not converged goes dark on the accord plane the
    /// moment it flips, and *"cannot judge"* is a REFUSAL by design.
    ///
    /// Requires [`Self::local_key_id`]: with no "I" there is no
    /// `delegates_to(self → root)` to evaluate, and the gate holds fully closed.
    pub accord_relay_enforced: bool,
}

/// Live replication runtime — bridge + registry + scheduler task +
/// shutdown handle. Construct via [`Self::start`]; hold the returned
/// handle for the lifetime of the application; call
/// [`Self::shutdown`] to stop the background scheduler.
pub struct ReplicationRuntime {
    transport: Arc<dyn Transport>,
    registry: Arc<ReplicationRegistry>,
    bridge: Arc<FederationDirectoryReplicationBridge>,
    /// CIRISEdge#370 — THE applier: one shared `Arc<dyn StateApplier>`
    /// (stateless adapter over the bridge) handed to every coordinator this
    /// runtime builds — initial initiators, the #312 responder factory, and
    /// hot-adds — with NO wrapping mutex. `apply_envelope` is `&self`, so
    /// per-peer rounds apply concurrently down to the store's own
    /// serialization; the old per-coordinator `Arc<Mutex<_>>` hold-across-
    /// the-whole-message critical section (with `block_on` DB I/O inside)
    /// is gone.
    applier: Arc<dyn StateApplier>,
    /// Bumped once per ADMITTED envelope. The thing that lets a caller AWAIT a
    /// row's arrival rather than poll for it — see [`Self::await_convergence`]
    /// and [`Self::pull_and_await`].
    convergence: Arc<super::convergence::ConvergenceSignal>,
    cancel_tx: watch::Sender<bool>,
    scheduler_task: Option<JoinHandle<()>>,
    config: ReplicationRuntimeConfig,
    /// Runtime control channel for the scheduler (CIRISEdge#173,
    /// v5.1.0). Used by [`Self::register_initiator_peer`] /
    /// [`Self::remove_peer`] / [`Self::set_peers`] to mutate the
    /// scheduler's Initiator set without restart.
    scheduler_handle: SchedulerHandle,
    /// Current Initiator set, kept in sync with the scheduler's
    /// live coordinator tasks. Drives [`Self::set_peers`]'s diff.
    /// Pre-v5.1 entries (passed to `start`) populate this on init.
    current_initiators: Arc<Mutex<HashSet<(String, EnvelopeKind)>>>,
    /// CIRISEdge#927 — whether this node's Initiator rounds proactively deliver
    /// their publish set (set iff `start` got a `self_provider`). Applied to
    /// every Initiator coordinator this runtime builds, including hot-adds.
    proactive_publish: bool,
    /// CIRISEdge#440 — the shared mesh-config reader (`Some` iff
    /// `local_key_id` was configured); see [`Self::mesh_config_reader`].
    mesh_config: Option<Arc<MeshConfigReader>>,
}

/// Failure modes for the v5.1.0 runtime peer-mutation API
/// (CIRISEdge#173).
#[derive(Debug, thiserror::Error)]
pub enum ReplicationRuntimeError {
    /// The scheduler has stopped (e.g. [`ReplicationRuntime::shutdown`]
    /// was called) — runtime control is no longer possible. Subsequent
    /// calls will keep failing.
    #[error("replication runtime has shut down; peer mutation is no longer accepted")]
    SchedulerStopped,
    /// CIRISEdge#462 — one or more subject-`Pull` sends failed to reach the peer.
    /// The scheduled Initiator was still installed (ordinary anti-entropy runs),
    /// but anti-entropy CANNOT carry the `SelfOwn` plane a Pull recovers, so the
    /// caller MUST treat the pull as not-dispatched for the named kinds and retry
    /// — never a silent `Ok`. Carries `"<Kind>: <error>; …"`.
    #[error("subject Pull dispatch failed: {0}")]
    PullDispatch(String),
}

impl From<SchedulerCommandError> for ReplicationRuntimeError {
    fn from(_: SchedulerCommandError) -> Self {
        Self::SchedulerStopped
    }
}

impl ReplicationRuntime {
    /// Start the runtime with the given set of Initiator peers.
    ///
    /// `directory` is the persist federation directory (typically
    /// extracted from a cohabitating `PyEngine` via the
    /// [`crate::ffi::pyo3::extract_capsule`] helper, or passed as an
    /// `Arc<dyn FederationDirectory>` from the host code path).
    ///
    /// `transport` is the canonical transport for the peer set
    /// (Reticulum per MISSION §1.4; HTTPS in fallback deployments).
    /// One transport instance is shared across all coordinators —
    /// each coordinator addresses its peer by `peer_key_id`.
    ///
    /// `peers` is the initial Initiator set. Each entry constructs
    /// one [`ReplicationCoordinator`] in Initiator role, registers
    /// it with the registry, and hands it to the scheduler.
    pub async fn start(
        directory: Arc<dyn FederationDirectory>,
        transport: Arc<dyn Transport>,
        peers: Vec<ReplicationPeer>,
        config: ReplicationRuntimeConfig,
        // CIRISEdge#311 — the SELF-plane publish set (collapses the #257
        // key_selector + #305 occurrence_selector into one). `Some` yields the
        // node's OWN + held anchored key_ids (KERI publish-own); the unified
        // engine advertises them across every `SelfOwn` kind (Key,
        // IdentityOccurrence — which carries the content-tier `encryption_pubkeys`
        // for KEX — and TransportDestination). `None` preserves the pre-selector
        // cohort projection. The server computes this set (it holds the anchor
        // knowledge) and hands it to edge alongside the consent-derived cohort —
        // edge only provides the hook.
        self_provider: Option<CohortProvider>,
    ) -> Self {
        // Cohort callback: yields the set of peer_key_ids we
        // anti-entropy with, snapshotted at construction. Hot-adds
        // via [`Self::register_peer`] don't update the snapshot —
        // the FSD §3.6 cohort is operator-configured + serves the
        // bridge's list_envelope_refs path, which can re-read on
        // each tick. We accept the snapshot model here because v1
        // hot-add is uncommon; a follow-up patch can swap in a
        // shared Arc<RwLock<Vec<String>>> if dynamism becomes the
        // common path.
        let cohort_snapshot: Vec<String> = peers.iter().map(|p| p.peer_key_id.clone()).collect();
        let cohort: CohortProvider = Arc::new(move || cohort_snapshot.clone());

        // CIRISEdge#927 — a node started with a self-publish set (`self_provider`
        // / `key_publish_set`) is one whose Initiator rounds should proactively
        // DELIVER that set (initiator-first, so a carrier-NAT'd peer's round can
        // complete without a return-path Diff). Capture before `self_provider` is
        // moved into the bridge.
        let proactive_publish = self_provider.is_some();

        // A node with NO self-publish set advertises none of its own rows on the
        // `SelfOwn` planes — and those are the planes carrying its `Key`, its
        // `IdentityOccurrence`, and its `TransportDestination`.
        //
        // That last one is the node's TRANSPORT HINT: the `(peer, dest)` binding
        // a peer needs to satisfy CIRISEdge#393 item 2. Without it every frame
        // this node sends is dropped at the peer's attribution gate with
        // "item 1 PASSED (Rooted ∧ owns_key) but item 2 FAILED", which reads
        // like a transport fault and is a configuration one. Edge's own mesh
        // harness lost several runs to exactly this.
        //
        // `None` is legitimate for a pure consumer that publishes nothing about
        // itself, so this warns rather than refuses — but it is the wrong
        // default for any node that expects to be reachable.
        if self_provider.is_none() {
            tracing::warn!(
                local_key_id = ?config.local_key_id,
                "replication started with NO self-publish set: this node will advertise                  none of its own Key / IdentityOccurrence / TransportDestination rows, so                  peers cannot satisfy CIRISEdge#393 item 2 for it and will DROP its                  frames unattributed. Pass `Some(self_publish_set(..))` unless this node                  is deliberately publishing nothing about itself"
            );
        }

        // CIRISEdge#397 — bring persist's signed_wire_index current for the
        // content-hash point-read fetch (once, idempotent, fail-soft).
        rebuild_signed_wire_index_fail_soft(&directory).await;

        let mesh_config = build_mesh_config_reader(&directory, &config);

        // The ONE production bridge — shared by every coordinator below AND by the
        // #312 responder factory. See [`build_bridge`] for the #433 metrics wiring.
        let convergence = super::convergence::ConvergenceSignal::shared();
        let bridge = build_bridge(
            &directory,
            cohort,
            &config,
            self_provider,
            mesh_config.clone(),
            Arc::clone(&convergence),
        );

        let registry = Arc::new(ReplicationRegistry::for_config(&config));

        // CIRISEdge#370 — ONE shared applier for every coordinator (initial
        // initiators, the #312 responder factory, hot-adds). The adapter is a
        // stateless `&self` wrapper over the bridge, so nothing needs a mutex;
        // applies from different peers' rounds run concurrently and serialize
        // only in the store.
        let shared_applier: Arc<dyn StateApplier> = Arc::new(MutableDirectoryStateAdapter::new(
            Arc::clone(&bridge) as Arc<dyn ReplicationDirectory>,
        ));

        // CIRISEdge#312 — install the responder factory so an inbound round
        // from an admitted-but-uncoordinated peer (a #301 advisory source we
        // don't consent-pull from, hence never built an Initiator for)
        // auto-registers a `Responder` and is served rather than dropped at
        // `NoCoordinatorRegistered`. Captures the shared transport + bridge;
        // mirrors `build_coordinator` in `Responder` role.
        {
            let factory_transport = Arc::clone(&transport);
            let factory_bridge = Arc::clone(&bridge);
            // CIRISEdge#370 — the factory hands every responder the ONE shared
            // no-mutex applier.
            let factory_applier = Arc::clone(&shared_applier);
            // CIRISEdge#441 — the responder coordinators fold peer Summaries
            // into the removal-receipt ledger; same handle the bridge uses.
            let factory_metrics = config.metrics.clone();
            registry.set_responder_factory(Arc::new(move |peer_key_id: &str, kind| {
                let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&factory_bridge) as _;
                // CIRISEdge#379 — peer-bound provider: the observer-capability
                // gate on the trace attestation plane applies per recipient.
                let provider: Arc<dyn StateProvider> =
                    Arc::new(DirectoryStateAdapter::new(bridge_dir).with_peer(peer_key_id));
                let applier = Arc::clone(&factory_applier);
                let coord = Arc::new(
                    ReplicationCoordinator::new(
                        Arc::clone(&factory_transport),
                        peer_key_id.to_string(),
                        kind,
                        SessionRole::Responder,
                        provider,
                        applier,
                    )
                    .with_metrics(factory_metrics.clone()),
                );
                // CIRISEdge#348 — DRIVE the responder. The registry only stores
                // the coordinator; the scheduler drives INITIATORS only. Without
                // a driver here the round-open is queued into the responder's
                // inbox and NEVER processed — the responder never
                // replies, the initiator times out forever, and (the seam that
                // cost weeks) NOTHING logs. This was the missing half of the #312
                // responder factory: it spun up + registered the Responder but
                // never ran the recv_inbound → drive_round_step → send_message
                // loop. Spawned ONCE per (peer, kind) — `get_or_register_with`
                // calls the factory only on first insert.
                spawn_responder_drive(Arc::clone(&coord));
                coord
            }));
        }

        // Build coordinators + scheduler. Coordinators share one
        // bridge instance; the provider is per-peer (#379 observer gate),
        // the applier is the ONE shared no-mutex `Arc<dyn StateApplier>`
        // (#370 — apply is `&self`; the store owns serialization). The
        // scheduler carries the mesh-config reader so a #440 cadence relief
        // takes effect on the next round.
        let mut scheduler =
            ReplicationScheduler::new(config.scheduler).with_mesh_config(mesh_config.clone());
        let scheduler_handle = scheduler.install_control_channel();
        let coords: Vec<Arc<ReplicationCoordinator>> = peers
            .iter()
            .map(|peer| {
                let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&bridge) as _;
                // CIRISEdge#379 — peer-bound provider (observer gate, see above).
                let provider: Arc<dyn StateProvider> =
                    Arc::new(DirectoryStateAdapter::new(bridge_dir).with_peer(&peer.peer_key_id));
                let applier = Arc::clone(&shared_applier);
                Arc::new(
                    ReplicationCoordinator::new(
                        Arc::clone(&transport),
                        &peer.peer_key_id,
                        peer.kind,
                        SessionRole::Initiator,
                        provider,
                        applier,
                    )
                    .with_metrics(config.metrics.clone())
                    .with_proactive_publish(proactive_publish),
                )
            })
            .collect();

        let mut initial_initiator_set: HashSet<(String, EnvelopeKind)> = HashSet::new();
        for (peer, coord) in peers.iter().zip(coords.iter()) {
            scheduler.add_initiator(Arc::clone(coord));
            initial_initiator_set.insert((peer.peer_key_id.clone(), peer.kind));
            // Register so the operator's listen loop can route
            // inbound replies (the Initiator side receives Summary
            // / Diff / Deliver back from the peer). Inline await
            // because `start` is async.
            registry
                .register(peer.peer_key_id.clone(), peer.kind, Arc::clone(coord))
                .await;
        }

        let (cancel_tx, cancel_rx) = watch::channel(false);
        // CIRISEdge#370/#636 — see [`spawn_scheduler_task`] for the event sink.
        let scheduler_task = spawn_scheduler_task(scheduler, &scheduler_handle, cancel_rx, &config);

        // `directory` was cloned into the bridge above; the local binding ends
        // with this scope.
        log_started(&config, peers.len(), proactive_publish);

        Self {
            transport,
            registry,
            bridge,
            applier: shared_applier,
            convergence,
            cancel_tx,
            scheduler_task: Some(scheduler_task),
            config,
            scheduler_handle,
            current_initiators: Arc::new(Mutex::new(initial_initiator_set)),
            proactive_publish,
            mesh_config,
        }
    }

    /// CIRISEdge#440 — the shared resolved mesh-config reader, when this
    /// runtime has one (`local_key_id` was configured). The host hands this to
    /// [`crate::transport::realtime_av_alm::TransitGate::with_mesh_config`] so
    /// the `feature.av_streams` toggle gates ALM admission from the SAME
    /// snapshot the replication plane runs under.
    #[must_use]
    pub fn mesh_config_reader(&self) -> Option<Arc<MeshConfigReader>> {
        self.mesh_config.clone()
    }

    /// Hot-add a `(peer_key_id, kind)` peer this node actively replicates
    /// with — routes inbound AND drives periodic anti-entropy rounds.
    ///
    /// v13.7.0 — this is now the ONE hot-add, and it does the unsurprising
    /// thing (active replication). It previously defaulted to a passive
    /// **Responder** (routed inbound but never pulled) — a footgun: it read
    /// like "register this peer" but silently did no rounds, and it duplicated
    /// the #312 responder factory, which already auto-registers a Responder on
    /// the first inbound round from any uncoordinated peer. So **serve-only
    /// peers need no call at all** — the factory handles them; callers who mean
    /// "replicate with this peer" get exactly that.
    ///
    /// Delegates to [`Self::register_initiator_peer`] (the CIRISEdge#173 control
    /// plane); returns its error if the scheduler has stopped.
    pub async fn register_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        self.register_initiator_peer(peer_key_id, kind).await
    }

    /// Hot-add a `(peer_key_id, kind)` **Initiator** coordinator —
    /// CIRISEdge#173, v5.1.0.
    ///
    /// v13.7.0 — [`Self::register_peer`] now does exactly this, so this method
    /// is a redundant alias kept for back-compat; prefer `register_peer`.
    ///
    /// Builds a coordinator in [`SessionRole::Initiator`], registers
    /// it with the registry (so inbound replies route correctly),
    /// AND tells the scheduler's runtime control plane to spawn a
    /// task that fires periodic anti-entropy rounds at the configured
    /// cadence. Idempotent — re-adding an active `(peer, kind)` is a
    /// no-op.
    ///
    /// Use this from CEG-driven reconcilers when `consent:replication`
    /// objects materialize at runtime: the new peer begins active
    /// pull immediately, no restart.
    pub async fn register_initiator_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        let peer_key_id = peer_key_id.into();
        let key = (peer_key_id.clone(), kind);

        {
            let mut active = self.current_initiators.lock().await;
            if active.contains(&key) {
                return Ok(());
            }
            active.insert(key);
        }

        let coord = self.build_coordinator(&peer_key_id, kind, SessionRole::Initiator);
        // Register first so the inbound listen loop can route replies
        // by the time the scheduler picks up the command.
        self.registry
            .register(peer_key_id, kind, Arc::clone(&coord))
            .await;
        self.scheduler_handle.add_initiator(coord).await?;
        Ok(())
    }

    /// CIRISEdge#462 — INITIATE a subject-scoped RECEIVE-axis pull: recover
    /// `subject_key_id`'s own testimony (and testimony ABOUT it) from
    /// `peer_key_id`. For each subject-pullable kind (the five replicated planes)
    /// this ensures a scheduled Initiator coordinator exists — so the reply's
    /// drive loop is live — then sends a `Pull`. The peer answers with the
    /// subject's refs (projection-gated + G2-carved by its `subject_holdings`),
    /// and the node pulls the gap through the ordinary Diff/Deliver flow.
    ///
    /// This is the mechanism the observation in #462 needs: a fedID that claimed
    /// a fresh node cannot otherwise obtain its own keys / occurrences / routes /
    /// occurrence-revocations, nor the attestations about-or-by it (so a
    /// moderation duty conferred on it becomes exercisable) — anti-entropy's
    /// advertise projection never offers the `SelfOwn` plane, and the graph
    /// already holds the answer, just on another node.
    ///
    /// A failed `Pull` send is NOT swallowed. The scheduled Initiator installed
    /// here runs ordinary anti-entropy, but anti-entropy is advertise-based and
    /// CANNOT carry the `SelfOwn` plane a Pull recovers — so a dropped Pull would
    /// silently lose that kind's subject recovery while the caller believed it was
    /// dispatched. We attempt every kind (so partial progress lands and register
    /// stays idempotent for a clean retry), then return [`PullDispatch`] naming
    /// the kinds whose send failed. `register_initiator_peer` failing (scheduler
    /// stopped) is a hard error that aborts immediately.
    ///
    /// [`PullDispatch`]: ReplicationRuntimeError::PullDispatch
    /// Subscribe to this node's convergence signal.
    ///
    /// Subscribe BEFORE dispatching the work you intend to wait on: a waiter
    /// created afterwards can miss an admission that landed in between.
    /// [`Self::pull_and_await`] does this for you and is what most callers
    /// want.
    #[must_use]
    pub fn convergence(&self) -> super::convergence::ConvergenceWaiter {
        self.convergence.subscribe()
    }

    /// **Pull, then WAIT for the answer.** The one helper every caller that
    /// needs a row from the mesh should use.
    ///
    /// [`Self::pull_subject_testimony`] is fire-and-forget by design — it
    /// returns once the sends are queued, because the rows arrive later through
    /// the ordinary Diff/Deliver flow. That leaves any caller who actually
    /// needs the answer to invent a poll loop, which is how four near-identical
    /// loops appeared in the harness and how a downstream consumer would write
    /// a fifth.
    ///
    /// This subscribes FIRST, then dispatches, then waits — so a row admitted
    /// between the send and the wait is never missed. It wakes on admission
    /// rather than on a timer, so the common case returns as soon as the row
    /// lands.
    ///
    /// `is_present` is YOUR question about observable state — "does the
    /// directory know this key", "does this fedID own a node I can reach" — not
    /// "did a message arrive". Keep it cheap; it runs once before any waiting
    /// and again on every wakeup.
    ///
    /// Returns the dispatch error only when the Pull could not be SENT. A sent
    /// Pull that never converges is a [`Converged::TimedOut`], not an error:
    /// the peer may simply not hold what you asked for, and that is an answer.
    ///
    /// ```ignore
    /// // "Search for a fedID" — resolve a contact, waiting for the directory.
    /// let outcome = runtime
    ///     .pull_and_await(&peer, &fed_id, Duration::from_secs(10), || async {
    ///         contact::resolve(&lens, &fed_id).await.is_ok()
    ///     })
    ///     .await?;
    /// if outcome.is_converged() { /* contact found */ }
    /// ```
    ///
    /// [`Converged::TimedOut`]: super::convergence::Converged::TimedOut
    pub async fn pull_and_await<F, Fut>(
        &self,
        peer_key_id: &str,
        subject_key_id: &str,
        budget: std::time::Duration,
        is_present: F,
    ) -> Result<super::convergence::Converged, ReplicationRuntimeError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        // Subscribe BEFORE the send. Reversing these two lines reintroduces the
        // race the signal exists to close: the row can be admitted between the
        // Pull leaving and the waiter parking.
        let mut waiter = self.convergence();
        self.pull_subject_testimony(peer_key_id, subject_key_id)
            .await?;
        let outcome = waiter.await_until(budget, is_present).await;
        tracing::debug!(
            peer = %peer_key_id,
            subject = %subject_key_id,
            converged = outcome.is_converged(),
            waited_ms = outcome.waited().as_millis(),
            checks = outcome.checks(),
            "pull_and_await"
        );
        Ok(outcome)
    }

    /// v19.0.0 — fire an anti-entropy round toward `peer_key_id` NOW on every
    /// plane this node initiates with it, instead of at the next cadence
    /// tick. Fire-and-forget; [`Self::sync_and_await`] is what most callers
    /// want.
    ///
    /// # Errors
    /// The scheduler has shut down.
    pub async fn round_now(&self, peer_key_id: &str) -> Result<(), ReplicationRuntimeError> {
        self.scheduler_handle.round_now(Some(peer_key_id)).await?;
        Ok(())
    }

    /// CIRISEdge#636 (production speed) — fire a round NOW toward EVERY peer on
    /// every plane this node initiates. The publish-side kick: a caller that
    /// just authored rows (an owner-binding, a consent grant, a KeyPackage)
    /// calls this instead of waiting for the 30 s cadence, so the rows cross on
    /// the next round-trip rather than the next tick. Idempotent and cheap —
    /// the scheduler coalesces kicks per coordinator (`Notify`) and a kicked
    /// round pushes the next scheduled one a full cadence out, so a burst of
    /// kicks is at most one round per (peer, kind).
    ///
    /// # Errors
    ///
    /// The scheduler's run loop has exited.
    pub async fn round_now_all(&self) -> Result<(), ReplicationRuntimeError> {
        self.scheduler_handle.round_now(None).await?;
        Ok(())
    }

    /// **Sync with a peer, then WAIT for the answer** — the anti-entropy twin
    /// of [`Self::pull_and_await`], for rows a subject Pull cannot ask for by
    /// identifier: another person's owner binding, the rows they placed in a
    /// room you share, a KeyPackage they published for you. Those reach this
    /// node through the ordinary per-peer advertise, whose gates decide what
    /// you are in the audience of — this helper only decides WHEN the round
    /// runs.
    ///
    /// Subscribes to the convergence signal first, kicks a round toward the
    /// peer, and waits; on every wake-up where `is_present` is still false it
    /// kicks again, so a walk that needs several dependent rounds (the Key
    /// plane, then attribution, then the Attestation plane) runs them back to
    /// back instead of one per cadence tick. Bounded by `budget`; a peer that
    /// does not hold what you asked for is a [`Converged::TimedOut`], not an
    /// error.
    ///
    /// # Errors
    /// The scheduler has shut down.
    ///
    /// [`Converged::TimedOut`]: super::convergence::Converged::TimedOut
    pub async fn sync_and_await<F, Fut>(
        &self,
        peer_key_id: &str,
        budget: std::time::Duration,
        mut is_present: F,
    ) -> Result<super::convergence::Converged, ReplicationRuntimeError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = bool>,
    {
        use super::convergence::Converged;
        /// One kicked round's grace before the next kick: long enough for a
        /// round's wire time, short enough that a dependent walk never idles.
        const KICK_SLICE: std::time::Duration = std::time::Duration::from_millis(1500);
        let start = std::time::Instant::now();
        let mut waiter = self.convergence();
        let mut checks = 0u32;
        let mut kicks = 0u32;
        loop {
            self.round_now(peer_key_id).await?;
            kicks += 1;
            let remaining = budget.saturating_sub(start.elapsed());
            if remaining.is_zero() {
                break;
            }
            let outcome = waiter
                .await_until(remaining.min(KICK_SLICE), &mut is_present)
                .await;
            checks += outcome.checks();
            if outcome.is_converged() {
                tracing::debug!(
                    peer = %peer_key_id,
                    waited_ms = start.elapsed().as_millis(),
                    kicks,
                    checks,
                    "sync_and_await converged"
                );
                return Ok(Converged::Yes {
                    waited: start.elapsed(),
                    checks,
                });
            }
        }
        tracing::debug!(
            peer = %peer_key_id,
            waited_ms = start.elapsed().as_millis(),
            kicks,
            checks,
            "sync_and_await timed out"
        );
        Ok(Converged::TimedOut {
            waited: start.elapsed(),
            checks,
        })
    }

    pub async fn pull_subject_testimony(
        &self,
        peer_key_id: &str,
        subject_key_id: &str,
    ) -> Result<(), ReplicationRuntimeError> {
        let mut failures: Vec<String> = Vec::new();
        for kind in EnvelopeKind::subject_pullable() {
            // Idempotent — installs (or reuses) the scheduled drive loop that
            // consumes the Pull's Summary reply.
            self.register_initiator_peer(peer_key_id, kind).await?;
            if let Some(coord) = self.registry.get_initiator(peer_key_id, kind).await {
                if let Err(e) = coord.start_pull(subject_key_id).await {
                    tracing::warn!(
                        peer = %peer_key_id,
                        subject = %subject_key_id,
                        kind = ?kind,
                        error = %e,
                        "subject Pull send failed — surfacing to the caller for retry (#462)"
                    );
                    failures.push(format!("{kind:?}: {e}"));
                }
            } else {
                // SECURITY/correctness (v16 review): register_initiator_peer just
                // installed this coordinator, so a None means a concurrent
                // deregister/reconcile raced it away before we could send. That is a
                // NOT-SENT Pull for this kind — record it, never a silent Ok (the
                // PullDispatch contract; anti-entropy cannot carry SelfOwn, so a
                // swallowed Pull is silent subject-recovery loss).
                tracing::warn!(
                    peer = %peer_key_id,
                    subject = %subject_key_id,
                    kind = ?kind,
                    "subject Pull coordinator absent immediately after register \
                     (raced by a concurrent deregister) — surfacing, not swallowing"
                );
                failures.push(format!(
                    "{kind:?}: coordinator absent after register (raced)"
                ));
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(ReplicationRuntimeError::PullDispatch(failures.join("; ")))
        }
    }

    /// Hot-remove a `(peer_key_id, kind)` peer — CIRISEdge#173,
    /// v5.1.0.
    ///
    /// Stops the matching Initiator coordinator's scheduled rounds
    /// (if active) AND deregisters from the registry so inbound
    /// routing for the peer ceases. Idempotent: removing a peer that
    /// was never added is a no-op.
    pub async fn remove_peer(
        &self,
        peer_key_id: impl Into<String>,
        kind: EnvelopeKind,
    ) -> Result<(), ReplicationRuntimeError> {
        let peer_key_id = peer_key_id.into();
        let key = (peer_key_id.clone(), kind);

        let was_initiator = {
            let mut active = self.current_initiators.lock().await;
            active.remove(&key)
        };
        if was_initiator {
            self.scheduler_handle
                .remove_initiator(peer_key_id.clone(), kind)
                .await?;
        }
        self.registry.deregister(&peer_key_id, kind).await;
        Ok(())
    }

    /// Diff-and-converge the live Initiator set against `desired` —
    /// CIRISEdge#173, v5.1.0.
    ///
    /// For each `(peer_key_id, kind)` in `desired` not currently
    /// active, calls [`Self::register_initiator_peer`]. For each
    /// currently-active pair NOT in `desired`, calls
    /// [`Self::remove_peer`]. Net effect: after this call returns,
    /// the runtime's Initiator coordinators exactly match `desired`.
    ///
    /// Atomic per individual add/remove only — partial progress is
    /// possible if a mid-call command fails (the failed pair is
    /// reflected by the returned error; pairs processed before the
    /// failure stay applied). Intended driver for CEG-reconcilers:
    /// call on every consent-object delta.
    pub async fn set_peers(
        &self,
        desired: Vec<ReplicationPeer>,
    ) -> Result<(), ReplicationRuntimeError> {
        let desired_set: HashSet<(String, EnvelopeKind)> = desired
            .iter()
            .map(|p| (p.peer_key_id.clone(), p.kind))
            .collect();
        let current_set: HashSet<(String, EnvelopeKind)> = {
            let active = self.current_initiators.lock().await;
            active.iter().cloned().collect()
        };

        // Adds first; the new peers begin active pull before the
        // departing peers' rounds stop — minimizes the convergence
        // window during a swap.
        for (peer_key_id, kind) in desired_set.difference(&current_set) {
            self.register_initiator_peer(peer_key_id.clone(), *kind)
                .await?;
        }
        for (peer_key_id, kind) in current_set.difference(&desired_set) {
            self.remove_peer(peer_key_id.clone(), *kind).await?;
        }
        Ok(())
    }

    /// Build a [`ReplicationCoordinator`] in the requested role with
    /// the runtime's shared transport + bridge-backed provider/applier.
    /// Internal helper for register_peer / register_initiator_peer.
    fn build_coordinator(
        &self,
        peer_key_id: &str,
        kind: EnvelopeKind,
        role: SessionRole,
    ) -> Arc<ReplicationCoordinator> {
        let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(&self.bridge) as _;
        // CIRISEdge#379 — peer-bound provider (observer gate).
        let provider: Arc<dyn StateProvider> =
            Arc::new(DirectoryStateAdapter::new(bridge_dir).with_peer(peer_key_id));
        // CIRISEdge#370 — hot-adds share the runtime's ONE no-mutex applier.
        let applier = Arc::clone(&self.applier);
        // CIRISEdge#927 — hot-added Initiators inherit the runtime's proactive-
        // publish posture. Harmless for Responders (they never `start_round`).
        Arc::new(
            ReplicationCoordinator::new(
                Arc::clone(&self.transport),
                peer_key_id.to_string(),
                kind,
                role,
                provider,
                applier,
            )
            .with_proactive_publish(self.proactive_publish),
        )
    }

    /// Shared registry handle. The operator's `Transport::listen`
    /// loop calls [`ReplicationRegistry::route_inbound_bytes`] on
    /// this when bytes arrive from an identified source peer.
    pub fn registry(&self) -> Arc<ReplicationRegistry> {
        Arc::clone(&self.registry)
    }

    /// The runtime's bridge. Useful for telemetry or tests that
    /// want to inspect cache state.
    pub fn bridge(&self) -> Arc<FederationDirectoryReplicationBridge> {
        Arc::clone(&self.bridge)
    }

    /// Returns the active runtime configuration.
    pub fn config(&self) -> &ReplicationRuntimeConfig {
        &self.config
    }

    /// Signal the scheduler to stop and await its run loop to exit
    /// cleanly. Idempotent — repeated calls return immediately
    /// after the first stop completes.
    pub async fn shutdown(&mut self) {
        let _ = self.cancel_tx.send(true);
        if let Some(task) = self.scheduler_task.take() {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::store::MemoryBackend;
    use std::sync::Arc;

    use crate::transport::{InboundFrame, TransportError, TransportId, TransportSendOutcome};
    use async_trait::async_trait;

    struct NoopTransport;
    #[async_trait]
    impl Transport for NoopTransport {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            _destination_key_id: &str,
            _envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            unimplemented!("runtime tests don't drive listen")
        }
    }

    /// Captured `(destination_key_id, bytes)` sends.
    type SentLog = Arc<tokio::sync::Mutex<Vec<(String, Vec<u8>)>>>;

    /// A transport that RECORDS every `send` so a test can assert the responder
    /// actually replied (CIRISEdge#348).
    struct RecordingTransport {
        sent: SentLog,
    }
    #[async_trait]
    impl Transport for RecordingTransport {
        fn id(&self) -> TransportId {
            TransportId::HTTP
        }
        async fn send(
            &self,
            destination_key_id: &str,
            envelope_bytes: &[u8],
        ) -> Result<TransportSendOutcome, TransportError> {
            self.sent
                .lock()
                .await
                .push((destination_key_id.to_string(), envelope_bytes.to_vec()));
            Ok(TransportSendOutcome::Delivered)
        }
        async fn listen(
            &self,
            _sink: tokio::sync::mpsc::Sender<InboundFrame>,
        ) -> Result<(), TransportError> {
            Ok(())
        }
    }

    /// CIRISEdge#348 — a factory-spun **Responder** is DRIVEN: an inbound
    /// round-open routed through the registry causes the responder to process it
    /// and REPLY on the transport — with NO Initiator, NO scheduler entry, and NO
    /// manual drive. Before the fix the #312 factory registered the coordinator
    /// but never ran its `recv_inbound → drive_round_step → send_message` loop, so
    /// the routed Summary sat in its inbox and was never processed: the
    /// responder never replied and the initiator timed out forever (the #348
    /// silent stall). This asserts a reply is emitted back to the initiator.
    // multi_thread: `DirectoryStateAdapter` uses `block_in_place` (directory.rs),
    // which requires a multi-threaded runtime — the shape the real edge runtime
    // always has.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn factory_responder_is_driven_and_replies_to_a_round_open() {
        use super::super::protocol::{ReplicationMessage, SummaryMessage};
        use super::super::registry::RouteOutcome;

        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let sent = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let transport: Arc<dyn Transport> = Arc::new(RecordingTransport {
            sent: Arc::clone(&sent),
        });
        // No Initiator peers — a PURE responder node (the canonical's shape: the
        // agent pulls from it). The ONLY way it serves a round is the #312
        // factory spinning up a Responder AND the #348 drive running it.
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;

        let round_open =
            super::super::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
                kind: EnvelopeKind::Key,
                refs: vec![],
            }));
        let outcome = rt
            .registry()
            .route_inbound_bytes("agent-alice", &round_open)
            .await
            .expect("route_inbound_bytes");
        assert!(
            matches!(outcome, RouteOutcome::RoutedToResponder { built: true, .. }),
            "the factory must spin up + route to a Responder, got {outcome:?}",
        );

        // The drive is a spawned task; poll (bounded) for the reply.
        let replied = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if !sent.lock().await.is_empty() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await;
        assert!(
            replied.is_ok(),
            "the factory-spun Responder MUST reply to the round-open (CIRISEdge#348) — \
             nothing was sent, so the responder was registered but never driven",
        );
        assert_eq!(
            sent.lock().await[0].0,
            "agent-alice",
            "the reply must go back to the initiating peer",
        );

        rt.shutdown().await;
    }

    /// `start` with an empty peer list builds the runtime + spawns
    /// the scheduler task; `shutdown` exits cleanly.
    #[tokio::test]
    async fn empty_peer_set_starts_and_shuts_down_cleanly() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        assert!(rt.registry().is_empty().await);
        rt.shutdown().await;
    }

    /// `start` with one Initiator peer registers it + holds the
    /// registry handle the listen loop would use.
    #[tokio::test]
    async fn one_initiator_peer_registered_at_start() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let peers = vec![ReplicationPeer {
            peer_key_id: "agent-alice".to_string(),
            kind: EnvelopeKind::Key,
        }];
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            peers,
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        let registry = rt.registry();
        assert_eq!(registry.len().await, 1);
        let coord = registry
            .get_initiator("agent-alice", EnvelopeKind::Key)
            .await;
        assert!(coord.is_some());
        rt.shutdown().await;
    }

    /// `register_peer` hot-adds an ACTIVE (Initiator) peer — routes AND
    /// drives — and the registry reflects the add immediately (v13.7.0: it
    /// no longer defaults to a passive Responder).
    #[tokio::test]
    async fn register_peer_hot_adds() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_peer("agent-bob", EnvelopeKind::Attestation)
            .await
            .expect("register_peer succeeds on a live runtime");
        assert_eq!(rt.registry().len().await, 1);
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `register_initiator_peer` hot-adds an
    /// Initiator coordinator (not just Responder) and bumps the
    /// registry. Distinct from `register_peer` (Responder-only).
    #[tokio::test]
    async fn register_initiator_peer_hot_adds_initiator_role() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_initiator_peer("agent-carol", EnvelopeKind::Key)
            .await
            .expect("hot-add succeeds while runtime is live");
        assert_eq!(rt.registry().len().await, 1);
        let coord = rt
            .registry()
            .get_initiator("agent-carol", EnvelopeKind::Key)
            .await;
        assert!(coord.is_some());
        assert_eq!(coord.unwrap().role(), SessionRole::Initiator);
        // Idempotent: re-add is a no-op.
        rt.register_initiator_peer("agent-carol", EnvelopeKind::Key)
            .await
            .expect("idempotent re-add");
        assert_eq!(rt.registry().len().await, 1);
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `remove_peer` stops the matching
    /// coordinator's scheduled rounds AND deregisters from the
    /// registry. Idempotent.
    #[tokio::test]
    async fn remove_peer_drops_initiator_and_deregisters() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.register_initiator_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .unwrap();
        assert_eq!(rt.registry().len().await, 1);
        rt.remove_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .expect("hot-remove succeeds while runtime is live");
        assert!(rt.registry().is_empty().await);
        // Idempotent: removing again is a no-op.
        rt.remove_peer("agent-dave", EnvelopeKind::Attestation)
            .await
            .expect("idempotent re-remove");
        rt.shutdown().await;
    }

    /// CIRISEdge#173 / v5.1.0 — `set_peers` converges the live
    /// Initiator set against the desired set. Verifies that adds
    /// and removes both apply in one call, including starting from
    /// a non-empty pre-existing set.
    #[tokio::test]
    async fn set_peers_diff_converges() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let initial = vec![
            ReplicationPeer {
                peer_key_id: "peer-keep".to_string(),
                kind: EnvelopeKind::Key,
            },
            ReplicationPeer {
                peer_key_id: "peer-drop".to_string(),
                kind: EnvelopeKind::Key,
            },
        ];
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            initial,
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        assert_eq!(rt.registry().len().await, 2);

        let desired = vec![
            ReplicationPeer {
                peer_key_id: "peer-keep".to_string(),
                kind: EnvelopeKind::Key,
            },
            ReplicationPeer {
                peer_key_id: "peer-new".to_string(),
                kind: EnvelopeKind::Attestation,
            },
        ];
        rt.set_peers(desired).await.expect("converge succeeds");

        assert_eq!(rt.registry().len().await, 2);
        assert!(rt
            .registry()
            .get_initiator("peer-keep", EnvelopeKind::Key)
            .await
            .is_some());
        assert!(rt
            .registry()
            .get_initiator("peer-new", EnvelopeKind::Attestation)
            .await
            .is_some());
        assert!(rt
            .registry()
            .get_initiator("peer-drop", EnvelopeKind::Key)
            .await
            .is_none());
        rt.shutdown().await;
    }

    /// `shutdown` is idempotent.
    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let backend = Arc::new(MemoryBackend::new());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt = ReplicationRuntime::start(
            directory,
            transport,
            Vec::new(),
            ReplicationRuntimeConfig::default(),
            None,
        )
        .await;
        rt.shutdown().await;
        rt.shutdown().await; // no panic, no hang
    }

    // ── CIRISEdge#634 — the reproduction at runtime level ─────────────────
    //
    // Two runtimes, each an INITIATOR toward the other for the same kind (the
    // mesh norm: mutual peers). Pre-#634 every round-open from one side landed
    // in the other side's initiator channel, undrained between rounds; the
    // responder factory never ran; rounds timed out. Post-#634 both sides'
    // rounds COMPLETE, both sides route both directions, and nothing is
    // dropped as a stale reply or back-pressure.
    mod mutual_initiators_634 {
        use super::*;
        use crate::observability::{EdgeMetrics, RoundOutcome};
        use crate::replication::registry::{ReplicationRegistry, RouteOutcome};
        use std::collections::HashMap;
        use std::sync::Mutex as StdMutex;

        type Registries = Arc<StdMutex<HashMap<String, Arc<ReplicationRegistry>>>>;
        type Ledger = Arc<StdMutex<Vec<(String, String)>>>; // (receiver, outcome label)

        /// `send(dest, bytes)` becomes `dest_registry.route_inbound_bytes(me, bytes)`
        /// on a spawned task — the shape of the real listen loop, minus the
        /// transport. Every route outcome is recorded per receiver.
        struct Loopback {
            me: String,
            registries: Registries,
            ledger: Ledger,
        }
        #[async_trait]
        impl Transport for Loopback {
            fn id(&self) -> TransportId {
                TransportId::HTTP
            }
            async fn send(
                &self,
                destination_key_id: &str,
                envelope_bytes: &[u8],
            ) -> Result<TransportSendOutcome, TransportError> {
                let dest = self
                    .registries
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .get(destination_key_id)
                    .cloned();
                let Some(dest) = dest else {
                    return Err(TransportError::Io(format!(
                        "no such node {destination_key_id}"
                    )));
                };
                let me = self.me.clone();
                let ledger = Arc::clone(&self.ledger);
                let bytes = envelope_bytes.to_vec();
                let receiver = destination_key_id.to_string();
                tokio::spawn(async move {
                    let label = match dest.route_inbound_bytes(&me, &bytes).await {
                        Ok(RouteOutcome::RoutedToResponder { .. }) => "to_responder".to_string(),
                        Ok(RouteOutcome::RoutedToInitiator { .. }) => "to_initiator".to_string(),
                        Ok(other) => format!("other:{other:?}"),
                        Err(e) => format!("err:{e}"),
                    };
                    ledger
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .push((receiver, label));
                });
                Ok(TransportSendOutcome::Delivered)
            }
            async fn listen(
                &self,
                _sink: tokio::sync::mpsc::Sender<InboundFrame>,
            ) -> Result<(), TransportError> {
                Ok(())
            }
        }

        async fn node(
            name: &str,
            peer: &str,
            registries: &Registries,
            ledger: &Ledger,
        ) -> (ReplicationRuntime, EdgeMetrics) {
            let backend = Arc::new(MemoryBackend::new());
            let directory: Arc<dyn FederationDirectory> = backend;
            let transport: Arc<dyn Transport> = Arc::new(Loopback {
                me: name.to_string(),
                registries: Arc::clone(registries),
                ledger: Arc::clone(ledger),
            });
            let metrics = EdgeMetrics::new();
            let config = ReplicationRuntimeConfig {
                scheduler: SchedulerConfig {
                    cadence: std::time::Duration::from_secs(3600),
                    round_timeout: std::time::Duration::from_secs(5),
                },
                metrics: Some(metrics.clone()),
                local_key_id: Some(name.to_string()),
                ..ReplicationRuntimeConfig::default()
            };
            let rt = ReplicationRuntime::start(
                directory,
                transport,
                vec![ReplicationPeer {
                    peer_key_id: peer.to_string(),
                    kind: EnvelopeKind::Key,
                }],
                config,
                None,
            )
            .await;
            registries
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(name.to_string(), rt.registry());
            (rt, metrics)
        }

        fn completed(m: &EdgeMetrics) -> u64 {
            m.replication_round_outcomes_total
                .read()
                .get(&RoundOutcome::Completed)
                .copied()
                .unwrap_or(0)
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
        async fn mutual_initiators_both_complete_rounds_634() {
            let registries: Registries = Arc::new(StdMutex::new(HashMap::new()));
            let ledger: Ledger = Arc::new(StdMutex::new(Vec::new()));
            let (mut alice, alice_m) = node("alice", "bob", &registries, &ledger).await;
            let (mut bob, bob_m) = node("bob", "alice", &registries, &ledger).await;

            // Both sides are initiators toward each other; neither has a
            // responder yet.
            assert!(alice
                .registry()
                .get_initiator("bob", EnvelopeKind::Key)
                .await
                .is_some());
            assert!(alice
                .registry()
                .get_responder("bob", EnvelopeKind::Key)
                .await
                .is_none());
            assert!(bob
                .registry()
                .get_initiator("alice", EnvelopeKind::Key)
                .await
                .is_some());

            let alice_before = completed(&alice_m);
            let bob_before = completed(&bob_m);

            // The #634 shape: ONE side opens a round while the other side's
            // initiator toward it is IDLE. Pre-#634 the round-open queued into
            // that idle initiator's channel and the opener timed out (verified
            // against v25.4.0: `alice={TimedOut: 1}`). Now bob's responder is
            // built on first contact and alice's round completes.
            alice.round_now("bob").await.expect("kick alice");
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if completed(&alice_m) > alice_before {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "alice's round toward an idle-initiator peer must COMPLETE: alice={:?} \
                     bob={:?} ledger={:?}",
                    alice_m.replication_round_outcomes_total.read(),
                    bob_m.replication_round_outcomes_total.read(),
                    ledger.lock().unwrap()
                )
            });

            // The mirror image.
            bob.round_now("alice").await.expect("kick bob");
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if completed(&bob_m) > bob_before {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("bob's round toward alice completes too");

            // Both at once — the simultaneous case, which the direction bit
            // keeps apart from the replies now in flight on both sides.
            let (a2, b2) = (completed(&alice_m), completed(&bob_m));
            alice.round_now("bob").await.expect("kick alice 2");
            bob.round_now("alice").await.expect("kick bob 2");
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                loop {
                    if completed(&alice_m) > a2 && completed(&bob_m) > b2 {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
            })
            .await
            .expect("simultaneous rounds complete on both sides");

            // Both sides built a responder for the other, and both directions
            // were routed on both sides. Nothing was dropped or back-pressured.
            assert!(alice
                .registry()
                .get_responder("bob", EnvelopeKind::Key)
                .await
                .is_some());
            assert!(bob
                .registry()
                .get_responder("alice", EnvelopeKind::Key)
                .await
                .is_some());
            let entries = ledger.lock().unwrap().clone();
            for who in ["alice", "bob"] {
                let mine: Vec<&str> = entries
                    .iter()
                    .filter(|(r, _)| r == who)
                    .map(|(_, l)| l.as_str())
                    .collect();
                assert!(mine.contains(&"to_responder"), "{who}: {mine:?}");
                assert!(mine.contains(&"to_initiator"), "{who}: {mine:?}");
                assert!(
                    mine.iter()
                        .all(|l| *l == "to_responder" || *l == "to_initiator"),
                    "{who} saw a drop or an error: {mine:?}"
                );
            }
            for m in [&alice_m, &bob_m] {
                let outcomes = m.replication_round_outcomes_total.read().clone();
                assert!(
                    !outcomes.contains_key(&RoundOutcome::TimedOut)
                        && !outcomes.contains_key(&RoundOutcome::Error),
                    "{outcomes:?}"
                );
            }
            alice.shutdown().await;
            bob.shutdown().await;
        }
    }
}
