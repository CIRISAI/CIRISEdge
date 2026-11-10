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
    key_grant_wake: Option<Arc<tokio::sync::Notify>>,
) -> Arc<FederationDirectoryReplicationBridge> {
    let bridge_config = resolve_sweep_permits(config.bridge);
    Arc::new(
        FederationDirectoryReplicationBridge::with_config(
            Arc::clone(directory),
            cohort,
            bridge_config,
        )
        .with_self_provider(self_provider)
        .with_kind_publish_selector(config.kind_publish_selector.clone())
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
        .with_consent_subjects(config.consent_subject_key_ids.clone())
        .with_recognised_seats(config.recognised_seats.clone())
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
        .with_membership_widener(config.membership_widener.clone())
        .with_key_grant_wake(key_grant_wake)
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

/// CIRISEdge#768 — ONE pending-KeyGrant emitter per sealed-content engine,
/// stopped with the runtime (it watches the runtime's cancel channel). Its
/// backstop is the scheduler cadence. `None` when this node seals nothing.
fn spawn_key_grant_emitter_for(
    config: &ReplicationRuntimeConfig,
    wake: Option<Arc<tokio::sync::Notify>>,
    cancel_rx: &watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    use super::key_grant_emitter::{spawn_key_grant_emitter, KeyGrantEmitterConfig};
    let (wiring, wake) = (config.sealed_content.as_ref()?, wake?);
    Some(spawn_key_grant_emitter(
        wiring.engine.clone(),
        wake,
        cancel_rx.clone(),
        KeyGrantEmitterConfig {
            debounce: KeyGrantEmitterConfig::DEFAULT_DEBOUNCE,
            backstop: config.scheduler.cadence,
        },
    ))
}

/// CIRISEdge#776 — hand the bridge the scheduler its release kick fires
/// through, and pass the handle on.
fn with_release_kick(
    bridge: &FederationDirectoryReplicationBridge,
    handle: SchedulerHandle,
) -> SchedulerHandle {
    bridge.install_release_kick(handle.clone());
    handle
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
    config = resolve_holdings_index(config);
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
             — IGNORED, keeping the configured value (history: CIRISEdge#531)"
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
             keeping the configured value (history: CIRISEdge#531)"
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
             configured value (history: CIRISEdge#531)"
        ),
    }
    config
}

/// CIRISEdge#971 — apply the holdings-index lever
/// ([`BridgeConfig::HOLDINGS_INDEX_ENV`]) and audit cadence
/// ([`BridgeConfig::HOLDINGS_AUDIT_EVERY_ENV`]) overrides. Same contract as
/// [`resolve_sweep_page_rows`]: missing leaves the configured value; a value
/// that does not parse WARNS and leaves it too. The lever only turns OFF
/// from the environment (`0`, `off`, `false`): the server pulls it on a box
/// where the index misbehaves, without a release.
fn resolve_holdings_index(mut config: BridgeConfig) -> BridgeConfig {
    if let Ok(raw) = std::env::var(BridgeConfig::HOLDINGS_INDEX_ENV) {
        let off = matches!(
            raw.trim().to_ascii_lowercase().as_str(),
            "0" | "off" | "false"
        );
        if off {
            tracing::info!(
                env = BridgeConfig::HOLDINGS_INDEX_ENV,
                "holdings index turned OFF from the environment: every Summary \
                 drains persist's content-hash index, the pre-v45 behaviour \
                 (CIRISEdge#971)"
            );
            config.holdings_index = false;
        }
    }
    if let Ok(raw) = std::env::var(BridgeConfig::HOLDINGS_AUDIT_EVERY_ENV) {
        match raw.trim().parse::<u64>() {
            Ok(secs) if secs > 0 => {
                tracing::info!(
                    secs,
                    env = BridgeConfig::HOLDINGS_AUDIT_EVERY_ENV,
                    "holdings index audit cadence overridden from the environment \
                     (CIRISEdge#971)"
                );
                config.holdings_audit_every = std::time::Duration::from_secs(secs);
            }
            _ => tracing::warn!(
                raw = %raw,
                env = BridgeConfig::HOLDINGS_AUDIT_EVERY_ENV,
                keeping_secs = config.holdings_audit_every.as_secs(),
                "holdings index audit cadence is not a positive whole number of \
                 seconds: IGNORED, keeping the configured value (tracked: \
                 CIRISEdge#971)"
            ),
        }
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
/// The runtime's registry ([`ReplicationRegistry::for_config`]) with the
/// CIRISEdge#727 owner-binding rung's receiver gate installed
/// (`FSD/FIRST_CONTACT.md` §2.1.1): an owner-binding whose attester is THIS
/// node's own owner is admitted on an un-attributed link, through the
/// bridge's apply door (so the #682 owner memo invalidates on admit). Needs a
/// local key — with no "I" there is no "my owner"; without one nothing is
/// installed and every such frame drops as before.
///
/// The gate also ANSWERS a newly admitted sibling with this node's own binding
/// on the frame's reply path (rule 2, second clause): the initiator direction
/// does not always dial (#531 link reuse), so the dial-path push alone leaves
/// the exchange one-way.
fn registry_for(
    config: &ReplicationRuntimeConfig,
    directory: &Arc<dyn FederationDirectory>,
    bridge: &Arc<FederationDirectoryReplicationBridge>,
    transport: &Arc<dyn Transport>,
) -> Arc<ReplicationRegistry> {
    let registry = Arc::new(ReplicationRegistry::for_config(config));
    let Some(local) = config.local_key_id.as_deref() else {
        return registry;
    };
    registry.install_owner_binding_carve_out(Arc::new(
        crate::first_contact::OwnerBindingCarveOut::new(
            local,
            Arc::clone(directory),
            Some(Arc::clone(bridge) as Arc<dyn ReplicationDirectory>),
            config.metrics.clone(),
        )
        .with_answer(
            Arc::clone(transport),
            Arc::new(crate::first_contact::DirectoryOwnerBinding::new(
                Arc::clone(directory),
                local,
            )),
        ),
    ));
    registry
}

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

/// CIRISEdge#794 — feed the transport's per-peer reachability evidence (a path
/// learned, a link identified) into the scheduler's no-route backoff. A
/// transport with no such events spawns nothing.
pub(crate) fn spawn_reachability_forwarder(
    transport: &Arc<dyn Transport>,
    handle: &SchedulerHandle,
    cancel_rx: &watch::Receiver<bool>,
) {
    use tokio::sync::broadcast::error::RecvError;
    let Some(mut events) = transport.subscribe_reachability() else {
        return;
    };
    let handle = handle.clone();
    let mut cancel = cancel_rx.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        return;
                    }
                }
                event = events.recv() => match event {
                    Ok(seen) => handle.note_reachable(&seen.peer_key_id, seen.evidence),
                    // Evidence lost to lag only delays a clear; the backoff
                    // still expires on its own schedule.
                    Err(RecvError::Lagged(missed)) => tracing::debug!(
                        missed,
                        "reachability evidence lagged (CIRISEdge#794)"
                    ),
                    Err(RecvError::Closed) => return,
                },
            }
        }
    });
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
                if matches!(event, RoundEvent::Completed(_)) {
                    m.telemetry.note_round_completed();
                }
            }
            if let RoundEvent::Completed(report) = &event {
                if report.admitted > 0 {
                    let due = last_propagate
                        .get(&report.kind)
                        .is_none_or(|at| at.elapsed() >= PROPAGATE_DEBOUNCE);
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

/// CIRISEdge#853 (Codex round two on #854) — when the round the responder is
/// serving began, for its completion line's `duration_ms`. The clock starts at
/// a round's first inbound frame and RESTARTS when a frame names a different
/// round id (the initiator abandoned a round and opened a new one, and the
/// coordinator rebinds to it): a replacement round's duration must not include
/// the time spent in the abandoned one. A legacy frame (round 0) never moves
/// it.
fn responder_round_clock(
    began: &mut Option<std::time::Instant>,
    timed_round: &mut u64,
    incoming_round: u64,
    now: std::time::Instant,
) -> std::time::Instant {
    if incoming_round != 0 && incoming_round != *timed_round {
        *timed_round = incoming_round;
        *began = Some(now);
    }
    *began.get_or_insert(now)
}

// One driver loop with a lifecycle line and counter per arm (CIRISEdge#853);
// splitting the arms out would separate each log line from the step it reports.
#[allow(clippy::too_many_lines)]
pub(crate) fn spawn_responder_drive(
    coord: Arc<ReplicationCoordinator>,
    reply_budget: Arc<crate::replication::reply_lane::ReplyBudget>,
) {
    use crate::replication::coordinator::DriverPhase;
    use crate::replication::reply_lane::{self, Finish, ReplyLane};
    tokio::spawn(async move {
        use crate::observability as obs;
        let peer = coord.peer_key_id().to_string();
        let kind = coord.kind();
        // CIRISEdge#853 — the responder's round lifecycle at INFO, counted in
        // `responder_rounds_total{kind, outcome}`: without it the canonical
        // cannot tell a link that served a round and closed from one opened
        // and closed empty.
        let count = |outcome: &'static str| {
            if let Some(m) = coord.metrics() {
                m.inc_responder_round(kind, outcome);
            }
        };
        tracing::info!(
            peer = %peer, ?kind, link = %coord.last_inbound_link_hex(),
            "responder driver started (CIRISEdge#348)"
        );
        count(obs::RESPONDER_ROUND_STARTED);
        // When the round being served began: its first inbound frame.
        let mut round_began: Option<std::time::Instant> = None;
        // The round id the timer is anchored to (0: none / legacy).
        let mut timed_round: u64 = 0;
        // CIRISEdge#943 — this loop steps, the lane sends: a reply the reverse
        // path is holding never holds the frames behind it. See `reply_lane`.
        let lane = ReplyLane::spawn(Arc::clone(&coord), reply_budget);
        loop {
            // CIRISEdge#662 — the phase gauge: this loop is the responder's ONE
            // drain, and when its inbox fills the drop site reads which of the
            // two awaits below it was parked in, and for how long.
            coord.set_driver_phase(DriverPhase::Idle);
            // Channel closed ⇒ the coordinator was dropped; end the driver.
            // CIRISEdge#634 — take the frame WITH its round metadata so the
            // step can rebind (a new round resets a stuck session) and the
            // replies below echo the round; a legacy frame (`meta: None`)
            // gets a legacy reply.
            let Some(inbound) = coord.recv_inbound_framed().await else {
                tracing::debug!(peer = %peer, ?kind, "responder driver ending (channel closed)");
                break;
            };
            if let Some(m) = coord.metrics() {
                m.telemetry
                    .observe_inbound_wait(kind, inbound.queued_at.elapsed());
            }
            if lane.take_send_failed() {
                round_began = None;
            }
            // The park here used to bound what a frame that wants an answer
            // could cost; a full lane is that bound now, before the step.
            if reply_lane::wants_reply(&inbound.msg) && !lane.has_room_for(&inbound.msg) {
                let what = if lane.has_room() { "node" } else { "frame" };
                lane.shed(&coord, what);
                continue;
            }
            let began = responder_round_clock(
                &mut round_began,
                &mut timed_round,
                inbound.meta.map_or(0, |m| m.round),
                std::time::Instant::now(),
            );
            coord.set_driver_phase(DriverPhase::Stepping);
            match coord.drive_round_step_framed(Some(inbound)).await {
                Ok(DriveStep::SendThenWait(msgs)) => {
                    if !msgs.is_empty() {
                        lane.enqueue(&coord, msgs, coord.current_round(), None);
                    }
                }
                // CIRISEdge#380 — defensive: `SendThenComplete` is initiator-only
                // (`start_round` emits it; responders never start rounds). If it
                // ever appears here, honor its semantics: send, then done.
                Ok(DriveStep::SendThenComplete(msgs, report)) => {
                    round_began = None;
                    let finish = Finish { report, began };
                    lane.enqueue(&coord, msgs, coord.current_round(), Some(finish));
                }
                Ok(DriveStep::Complete(report)) => {
                    round_began = None;
                    count(obs::RESPONDER_ROUND_COMPLETED_RESPONDER_FINAL);
                    tracing::info!(
                        peer = %peer, ?kind, ?report,
                        link = %coord.last_inbound_link_hex(),
                        duration_ms = u64::try_from(began.elapsed().as_millis()).unwrap_or(u64::MAX),
                        "responder served an anti-entropy round to completion (CIRISEdge#348)"
                    );
                }
                Ok(DriveStep::Refused) => {
                    tracing::warn!(
                        peer = %peer, ?kind,
                        "responder REFUSED an inbound replication message (unexpected role/phase) \
                         — dropped, NOT silently (history: CIRISEdge#348)"
                    );
                }
                // CIRISEdge#662 — a step error ends the ROUND, never the driver.
                // The responder's slot stays registered for as long as the peer
                // keeps sending, so a driver that ended here left an inbox nobody
                // drained: eight frames, then "inbox full" for every frame after,
                // forever. (`drive_round_step_framed` cannot return `Err` today —
                // this arm is defensive — but the trap is structural.)
                Err(e) => {
                    tracing::warn!(
                        peer = %peer, ?kind, error = %e,
                        "responder drive_round_step failed; the frame is dropped and the \
                         driver keeps draining (history: CIRISEdge#348 / history: CIRISEdge#662)"
                    );
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
    event.outcome()
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
    /// Cadence + round-timeout + round bound for the scheduler. Defaults to
    /// [`SchedulerConfig::default`] (30 s cadence, 10 s round timeout, at
    /// most [`SchedulerConfig::DEFAULT_MAX_CONCURRENT_ROUNDS`] rounds in
    /// flight — CIRISEdge#740: a kick on a 130-peer node runs 16 rounds at a
    /// time, not 1,800; see [`SchedulerConfig::max_concurrent_rounds`]).
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
    /// CIRISEdge#881 — the baked bundle's seated serve nodes round with this
    /// node as initiator peers on the bootstrap planes
    /// ([`BOOTSTRAP_ROUND_PLANES`]), so an unclaimed node (no consent-derived
    /// peers) rounds with the canonicals the bundle seeds, on planes that
    /// already have everyone-reach for announced nodes (#682) and admit
    /// unattributed receipt (#402): its route row (its transit pair) reaches
    /// the seat, and its owner's announced route row reaches it, with no
    /// host-side Pull.
    ///
    /// **On by default since edge v45** (CIRISEdge#971, Eric's ruling). It
    /// shipped opt-in in v43.2.0 and no host ever set it: from v43.2.0 to
    /// v44.1.2 an unclaimed device that consent named to no seat opened no
    /// round to anyone, and the seat held it Advisory and pairless for good.
    /// `true` opts a node out (pyo3: `start_replication(bundle_bootstrap_peers=False)`).
    /// On, a device asks each bundle seat for the required set by subject
    /// Pull ([`BUNDLE_PULL_PLANES`], bundle-seat mode), never a whole-plane
    /// diff, and keeps an ordinary round on [`BUNDLE_ROUND_PLANES`] only.
    ///
    /// What keeps a runtime that is not on the production mesh (tests,
    /// harnesses, a node over a scratch directory) from rounding with a
    /// production canonical is NOT this flag: a serve node is added only when
    /// THIS runtime's directory holds its key record
    /// ([`bundle_bootstrap_peers_held`]), and only persist's Engine boot seed
    /// writes those records, which it skips under a test trust root. A bare
    /// directory never holds them. Never applied under a test trust root
    /// (`test_trust_root_override_active`) either way.
    pub disable_bundle_bootstrap_peers: bool,
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
    /// Whose consent the attestation send set reads: the union of
    /// `consent_peers_by_principals(k)` over these keys.
    ///
    /// Distinct from `local_key_id` on purpose, like
    /// [`Self::serve_tier_subject_key_id`]. Consent is the agent's: the
    /// owner's `consent:replication` grant names the AGENT (`for_key_id`),
    /// while on a split home `local_key_id` is the node's wire identity, whose
    /// consent set is empty. Read by the node, the send set was empty and no
    /// `trace:*` row ever shipped.
    ///
    /// Empty (the default) falls back to `local_key_id`: correct wherever the
    /// agent and the node are one key.
    pub consent_subject_key_ids: Vec<String>,
    /// CC 5.2 — the recognised serve seats (`Edge::recognised_seats`), which
    /// the active roster starts from: only two seats walk the commons.
    pub recognised_seats: Option<Arc<std::sync::RwLock<std::collections::HashSet<String>>>>,
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
    /// CIRISEdge#678 (CIRISServer#148 limb b) — the per-kind publish set for
    /// the `SelfOwn` planes. `start`'s `self_provider` hands `Key`,
    /// `IdentityOccurrence` and `TransportDestination` ONE set; a host that
    /// relays a third party's anchored key record but not that party's
    /// occurrences or routes (their grant carries no onward-flow principle)
    /// answers per kind here. A kind the selector answers `None` for stays on
    /// `self_provider`. `None` (the default) is exactly the single-set
    /// behaviour. See
    /// [`FederationDirectoryReplicationBridge::with_kind_publish_selector`].
    pub kind_publish_selector: Option<super::bridge::KindPublishSelector>,
    /// persist v52.0.0 (CIRISPersist#955, CIRISConstitution#133) — the roster
    /// keys this node widens for on an admitted acceptance of a proposal they
    /// issued (see [`crate::membership`]). `None` (the default): acceptances
    /// are stored and nothing is widened by this node.
    pub membership_widener: Option<crate::membership::MembershipWidener>,
}

/// Live replication runtime — bridge + registry + scheduler task +
/// shutdown handle. Construct via [`Self::start`]; hold the returned
/// handle for the lifetime of the application; call
/// [`Self::shutdown`] to stop the background scheduler.
/// CIRISEdge#881 — the planes an unclaimed node rounds with the bundle's
/// seated serve nodes on: the bootstrap kinds and their revocations. All have
/// everyone-reach for announced nodes (#682) and admit unattributed receipt
/// (#402); nothing new is exposed by rounding on them without consent.
pub const BOOTSTRAP_ROUND_PLANES: [EnvelopeKind; 5] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
    EnvelopeKind::Revocation,
    EnvelopeKind::IdentityOccurrenceRevocation,
];

/// persist v60.0.0 / v61 (CIRISPersist#991) — drop every `(peer, kind)` on a
/// [retired plane](EnvelopeKind::is_retired_plane). A host that still names one
/// (the framed `Community` / `Family` / membership planes, the member listing,
/// the framed `KeyGrant`, the operational trio) would otherwise get a
/// coordinator per pair that lists nothing and refuses everything it is
/// offered — a round of transport spent on a plane persist retired. Their rows
/// ride the Attestation plane. Each dropped pair is logged once
/// ([`note_retired_plane_skipped`]).
fn without_retired_planes(peers: Vec<ReplicationPeer>) -> Vec<ReplicationPeer> {
    peers
        .into_iter()
        .filter(|p| {
            let retired = p.kind.is_retired_plane();
            if retired {
                note_retired_plane_skipped(&p.peer_key_id, p.kind);
            }
            !retired
        })
        .collect()
}

/// The one log line a skipped retired-plane peer gets.
fn note_retired_plane_skipped(peer_key_id: &str, kind: EnvelopeKind) {
    tracing::info!(
        peer = peer_key_id,
        kind = kind.as_wire_str(),
        "replication peer on a RETIRED plane not scheduled: persist retired its framed \
         carriage and its rows ride the Attestation plane (history: CIRISPersist#991)"
    );
}

/// Why a bundle serve node is not one of this runtime's bootstrap peers
/// (CIRISEdge#971), named on the start-up line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BundleSkip {
    /// The host opted out (`disable_bundle_bootstrap_peers`).
    OptedOut,
    /// A test trust root is active (persist skips the bundle under it too).
    TestTrustRoot,
    /// This runtime's directory holds no key record for it: the bundle was
    /// never seeded here, so no round with it could be dialled.
    NotInDirectory,
    /// It is this node.
    IsSelf,
    /// The directory read failed; skipped this start, never fatal.
    ReadFailed,
}

impl BundleSkip {
    /// A stable token for the start-up line.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OptedOut => "opted_out",
            Self::TestTrustRoot => "test_trust_root",
            Self::NotInDirectory => "not_in_directory",
            Self::IsSelf => "self",
            Self::ReadFailed => "read_failed",
        }
    }
}

/// **CIRISEdge#971 — the bundle's serve nodes this runtime may round with**,
/// and why each other one is skipped. A serve node becomes a bootstrap peer
/// (on every [`BOOTSTRAP_ROUND_PLANES`] plane, [`bundle_bootstrap_peers`])
/// only when no test trust root is active, the host has not opted out, it is
/// not this node, and `directory` holds its key record. A read error skips
/// that node and says so; it never fails the caller. [`ReplicationRuntime::start`]
/// calls this with the baked ids and `test_trust_root_override_active()`.
pub async fn bundle_bootstrap_peers_held(
    serve_nodes: &[String],
    directory: &dyn FederationDirectory,
    local: Option<&str>,
    disabled: bool,
    test_trust_root: bool,
) -> (Vec<ReplicationPeer>, Vec<(String, BundleSkip)>) {
    let mut held = Vec::new();
    let mut skipped = Vec::new();
    for id in serve_nodes {
        if test_trust_root {
            skipped.push((id.clone(), BundleSkip::TestTrustRoot));
            continue;
        }
        if disabled {
            skipped.push((id.clone(), BundleSkip::OptedOut));
            continue;
        }
        if Some(id.as_str()) == local {
            skipped.push((id.clone(), BundleSkip::IsSelf));
            continue;
        }
        match directory.lookup_public_key(id).await {
            Ok(Some(_)) => held.push(id.clone()),
            Ok(None) => skipped.push((id.clone(), BundleSkip::NotInDirectory)),
            Err(e) => {
                tracing::warn!(
                    serve_node = %id,
                    error = %e,
                    "bundle serve node skipped as a bootstrap peer: its key record could not \
                     be read; this start rounds without it (tracked: CIRISEdge#971)"
                );
                skipped.push((id.clone(), BundleSkip::ReadFailed));
            }
        }
    }
    (bundle_bootstrap_peers(&held, local), skipped)
}

/// **CIRISEdge#971 — the late-arrival re-check, latched.** Of `skipped`, only
/// the serve nodes skipped for want of a record (`NotInDirectory`) or for a
/// read that failed (`ReadFailed`) are read again; an opt-out, a test trust
/// root and self never change for a runtime's life and are never re-read. A
/// serve node found now is returned as peers; one held is never in `skipped`
/// again, so once every serve node is held or fixed-skipped this reads
/// NOTHING. A held serve node stays held for the runtime's life, as the
/// start-time check holds it.
pub async fn recheck_bundle_peers(
    skipped: &[(String, BundleSkip)],
    directory: &dyn FederationDirectory,
    local: Option<&str>,
) -> (Vec<ReplicationPeer>, Vec<(String, BundleSkip)>) {
    let (pending, fixed): (Vec<_>, Vec<_>) = skipped
        .iter()
        .cloned()
        .partition(|(_, why)| matches!(why, BundleSkip::NotInDirectory | BundleSkip::ReadFailed));
    if pending.is_empty() {
        return (Vec::new(), fixed);
    }
    let ids: Vec<String> = pending.into_iter().map(|(id, _)| id).collect();
    let (added, mut still) =
        bundle_bootstrap_peers_held(&ids, directory, local, false, false).await;
    still.extend(fixed);
    (added, still)
}

/// **CIRISEdge#971 (d) — the planes a device asks a bundle seat by subject
/// Pull**, never by a Summary: the four public bootstrap planes a subject Pull
/// answers (`is_subject_pullable`). A Summary there would make the seat build
/// its whole offer (every announced device's key and occurrence, about 2,690
/// refs measured on canonical-1) every cadence; CC 5.2 has a seat offer a
/// person's node only what is required, and an automatic diff is not a request.
pub const BUNDLE_PULL_PLANES: [EnvelopeKind; 4] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::TransportDestination,
    EnvelopeKind::IdentityOccurrenceRevocation,
];

/// CIRISEdge#971 (d) — the planes a device asks a bundle seat about its owner
/// on: not the route plane, whose rows are keyed by node (an owner subject
/// returns nothing there by construction), and an owned node's route comes
/// from its owner, not a seat (CC CLM-route-handed-by-owner, CIRISEdge#972).
pub const BUNDLE_OWNER_PLANES: [EnvelopeKind; 3] = [
    EnvelopeKind::Key,
    EnvelopeKind::IdentityOccurrence,
    EnvelopeKind::IdentityOccurrenceRevocation,
];

/// CIRISEdge#971 (d) — the bootstrap plane a device keeps an ordinary round on
/// with a bundle seat: key-level revocations have no subject index
/// (`is_subject_pullable` is false). The seat's offer there is
/// `Projection::Global` (its own set and its cohort), so the BYTES on the
/// wire are small, not the corpus. The seat-side walk is not: each responder
/// round builds the Global subject set and walks it per key
/// (bridge.rs `list_revocation_rows` → `key_plane_listing`), O(every key the
/// seat holds) even when the offer is empty. The #930 memo removes the
/// per-subject store read, not the walk. That cost is measured in the #971
/// idle-cost witness and belongs to the read-fix branch (withhold-rate).
pub const BUNDLE_ROUND_PLANES: [EnvelopeKind; 1] = [EnvelopeKind::Revocation];

/// **CIRISEdge#971 (d) — how often a device asks each bundle seat for the
/// required set by subject Pull.** Not the 30 s cadence: the owner subject is a
/// third-party lookup the seat charges against the device's per-requester
/// budget (60 per minute, 600 per hour, 2,000 per day; bridge.rs
/// `IDENTIFIER_LOOKUPS_*`), which the person's own contact lookups share. One
/// owner charge per 10 min is 144 a day, 7% of it. The device's own rows and
/// the seat's are answered uncharged (the subject and own-record arms). Only
/// the timer asks about the owner: a local write on a Pull plane runs the
/// self-subject offering Pull on that plane alone, and a host kick
/// (`round_now`) the self and seat legs, each [`BUNDLE_PULL_MIN_SPACING`]
/// apart. Each device draws its timer from half to one and a half of this
/// ([`bundle_pull_delay`]).
pub const BUNDLE_PULL_INTERVAL: std::time::Duration = std::time::Duration::from_secs(600);

/// CIRISEdge#971 (d) — kicked cycles are at least this far apart, so a burst
/// of local writes costs one cycle, not one per write; also the spacing of the
/// first-contact cycles.
pub const BUNDLE_PULL_MIN_SPACING: std::time::Duration = std::time::Duration::from_secs(30);

/// CIRISEdge#881 / #971 — the scheduled initiator peers the bundle's seated
/// serve nodes add: each on [`BUNDLE_ROUND_PLANES`], never this node itself.
/// The other bootstrap planes ride [`BUNDLE_PULL_PLANES`]'s subject Pulls.
#[must_use]
pub fn bundle_bootstrap_peers(serve_nodes: &[String], local: Option<&str>) -> Vec<ReplicationPeer> {
    serve_nodes
        .iter()
        .filter(|id| Some(id.as_str()) != local)
        .flat_map(|id| {
            BUNDLE_ROUND_PLANES.iter().map(move |kind| ReplicationPeer {
                peer_key_id: id.clone(),
                kind: *kind,
            })
        })
        .collect()
}

/// The peer key ids in `peers`.
fn peer_keys(peers: &[ReplicationPeer]) -> HashSet<String> {
    peers.iter().map(|p| p.peer_key_id.clone()).collect()
}

/// The distinct peer key ids in `peers`.
fn distinct_peers(peers: &[ReplicationPeer]) -> u64 {
    let ids: HashSet<&str> = peers.iter().map(|p| p.peer_key_id.as_str()).collect();
    u64::try_from(ids.len()).unwrap_or(u64::MAX)
}

/// CIRISEdge#971 — set the `initiator_peers` gauge: distinct peers by source.
fn note_initiator_peers(
    metrics: Option<&crate::observability::EdgeMetrics>,
    host: u64,
    bundle: &[ReplicationPeer],
    homed: u64,
) {
    use crate::observability::{
        INITIATOR_PEERS_BUNDLE, INITIATOR_PEERS_HOMED, INITIATOR_PEERS_HOST,
    };
    if let Some(m) = metrics {
        m.set_initiator_peers(INITIATOR_PEERS_HOST, host);
        m.set_initiator_peers(INITIATOR_PEERS_BUNDLE, distinct_peers(bundle));
        m.set_initiator_peers(INITIATOR_PEERS_HOMED, homed);
    }
}

/// CIRISEdge#881 — `peers` plus every `extra` not already in it, order kept.
#[must_use]
pub fn merge_peers(
    mut peers: Vec<ReplicationPeer>,
    extra: &[ReplicationPeer],
) -> Vec<ReplicationPeer> {
    let mut seen: HashSet<(String, EnvelopeKind)> = peers
        .iter()
        .map(|p| (p.peer_key_id.clone(), p.kind))
        .collect();
    for p in extra {
        if seen.insert((p.peer_key_id.clone(), p.kind)) {
            peers.push(p.clone());
        }
    }
    peers
}

/// CC 5.4.3 referrals — what a homed node's rounds are built from: a peer
/// refused at a bound homes on a referred node, and its first contact and
/// consent only flow there if something rounds with it. The transport says who;
/// this registers it on the bootstrap planes, as a bundle peer is, and every
/// later [`ReplicationRuntime::set_peers`] keeps it.
#[derive(Clone)]
struct HomedPeers {
    transport: Arc<dyn Transport>,
    registry: Arc<ReplicationRegistry>,
    bridge: Arc<FederationDirectoryReplicationBridge>,
    applier: Arc<dyn StateApplier>,
    scheduler_handle: SchedulerHandle,
    current_initiators: Arc<Mutex<HashSet<(String, EnvelopeKind)>>>,
    proactive_publish: bool,
    /// Held across peer sets ([`ReplicationRuntime::set_peers`]).
    peers: Arc<Mutex<Vec<ReplicationPeer>>>,
}

impl HomedPeers {
    async fn register(&self, node: &str) {
        for kind in BOOTSTRAP_ROUND_PLANES {
            self.peers.lock().await.push(ReplicationPeer {
                peer_key_id: node.to_owned(),
                kind,
            });
            if !self
                .current_initiators
                .lock()
                .await
                .insert((node.to_owned(), kind))
            {
                continue;
            }
            let coord = build_peer_coordinator(
                &self.transport,
                &self.bridge,
                &self.applier,
                self.proactive_publish,
                node,
                kind,
                SessionRole::Initiator,
            );
            self.registry
                .register(node.to_owned(), kind, Arc::clone(&coord))
                .await;
            if let Err(e) = self.scheduler_handle.add_initiator(coord).await {
                tracing::warn!(error = %e, node, "a homed node's rounds did not start");
                return;
            }
        }
        tracing::info!(
            node,
            planes = ?BOOTSTRAP_ROUND_PLANES,
            "replication rounds with the node this one homed on after a refusal, on the \
             bootstrap planes (CC 5.4.3)"
        );
    }
}

/// CC 5.4.3 referrals — register each node the transport homes on. A
/// transport with no such events spawns nothing.
/// **CIRISEdge#971 (d) — bundle-seat mode: the required set by subject Pull.**
///
/// Toward a bundle seat this node has no consent relationship with (a seat the
/// host's peer set does not name), the four [`BUNDLE_PULL_PLANES`] carry no
/// Summary round. Each cycle asks, per plane, by subject Pull:
///
/// - about THIS node, offering: the seat answers with what it holds about us,
///   and only our own rows it lacks are Delivered
///   ([`ReplicationCoordinator::pull_exchange_offering`]). In sync, nothing
///   goes up;
/// - about the SEAT: we fetch what of the seat's own rows we lack;
/// - about our OWNER, once claimed: the owner's key and occurrences.
///
/// The seat never builds its offer for us. A v44 seat serves all of it: the
/// subject and own-record arms answer without a trust root or a charge, the
/// owner Pull is one charge per cycle, and our Deliver is an unsolicited
/// Deliver a seat admits on a bootstrap plane. [`BUNDLE_ROUND_PLANES`] keep an
/// ordinary round. The Pull coordinators are registered for their replies but
/// never scheduled, so `set_peers` (which converges only scheduled
/// initiators) cannot remove them.
struct BundlePull {
    transport: Arc<dyn Transport>,
    registry: Arc<ReplicationRegistry>,
    bridge: Arc<FederationDirectoryReplicationBridge>,
    applier: Arc<dyn StateApplier>,
    scheduler_handle: SchedulerHandle,
    current_initiators: Arc<Mutex<HashSet<(String, EnvelopeKind)>>>,
    metrics: Option<crate::observability::EdgeMetrics>,
    proactive_publish: bool,
    local: Option<String>,
    round_timeout: std::time::Duration,
    /// The bundle seats this node holds.
    seats: std::sync::Mutex<Vec<String>>,
    /// The peers the host named (`start`, `set_peers`): a seat named here is
    /// a consent peer and rounds as one, untouched.
    host: std::sync::Mutex<HashSet<String>>,
    /// Seats that hold our own key AND route (the offering Key and TD Pulls'
    /// answers listed them), so they attribute our frames. Only these get the
    /// IOR legs and the [`BUNDLE_ROUND_PLANES`] round: before attribution a
    /// seat drops those frames (`routing_source` admits an unattributed frame
    /// on `is_bootstrap()` kinds only, replication/mod.rs; IOR and Revocation
    /// are not among them).
    attributed: std::sync::Mutex<HashSet<String>>,
    /// Kicks not yet run.
    pending: std::sync::Mutex<PendingKicks>,
    kick: tokio::sync::Notify,
    /// Pulls sent, for the witnesses: all, and by [`BUNDLE_PULL_PLANES`] slot.
    pulls: std::sync::atomic::AtomicU64,
    pulls_on: [std::sync::atomic::AtomicU64; 4],
}

/// CIRISEdge#971 (d) — the kicks a [`BundlePull`] has not yet run, merged.
#[derive(Debug, Default)]
struct PendingKicks {
    /// The seat set changed: first contact again.
    contact: bool,
    /// The host asked for a round now (`round_now`, `round_now_all`).
    host: bool,
    /// Pull planes this node wrote a row of its own on.
    wrote: Vec<EnvelopeKind>,
}

/// Why a [`BundlePull`] cycle runs, and so which legs it runs.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CycleCause {
    /// A seat new to this runtime, or one not yet holding our key and route:
    /// this node's and the seat's legs, so each can seal to and address the
    /// other.
    FirstContact,
    /// The jittered timer: every leg, the owner's included (the only charged
    /// one).
    Timer,
    /// A host kick: this node's and the seat's legs, never the owner's.
    HostKick,
    /// A local write: the self-subject offering Pull on these planes only.
    Wrote(Vec<EnvelopeKind>),
}

/// CIRISEdge#971 (d) — how many quick first-contact cycles a seat gets before
/// it waits for the timer: [`BUNDLE_PULL_MIN_SPACING`] apart.
const BUNDLE_FIRST_CONTACT_TRIES: u32 = 6;

impl BundlePull {
    fn note(&self, label: &'static str) {
        if let Some(m) = &self.metrics {
            m.inc_bundle_pull(label);
        }
    }

    fn targets(&self) -> Vec<String> {
        let host = self
            .host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        self.seats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|s| !host.contains(*s))
            .cloned()
            .collect()
    }

    fn set_seats(&self, seats: Vec<String>) {
        self.bridge.set_bundle_seats(seats.iter().cloned());
        *self
            .seats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = seats;
    }

    fn set_host(&self, host: HashSet<String>) {
        *self
            .host
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = host;
    }

    fn kick_with(&self, f: impl FnOnce(&mut PendingKicks)) {
        f(&mut self
            .pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner));
        self.kick.notify_one();
    }

    fn kick_contact(&self) {
        self.kick_with(|p| p.contact = true);
    }

    fn kick_host(&self) {
        self.kick_with(|p| p.host = true);
    }

    /// A row of this node's own landed on `kind`: a Pull plane asks the seat
    /// about us on it; any other plane is not this path's.
    fn kick_wrote(&self, kind: EnvelopeKind) {
        if !BUNDLE_PULL_PLANES.contains(&kind) {
            return;
        }
        self.kick_with(|p| {
            if !p.wrote.contains(&kind) {
                p.wrote.push(kind);
            }
        });
    }

    fn take_pending(&self) -> PendingKicks {
        std::mem::take(
            &mut *self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }

    fn is_attributed(&self, seat: &str) -> bool {
        self.attributed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(seat)
    }

    /// The [`BUNDLE_ROUND_PLANES`] peers of the attributed seats: what
    /// `set_peers` merges (an unattributed seat's round would only drop).
    fn round_peers(&self) -> Vec<ReplicationPeer> {
        let ready: Vec<String> = self
            .targets()
            .into_iter()
            .filter(|s| self.is_attributed(s))
            .collect();
        bundle_bootstrap_peers(&ready, self.local.as_deref())
    }

    /// The coordinator a Pull to `seat` on `kind` rides: whatever the registry
    /// already routes that pair's replies to, else a fresh unscheduled one.
    async fn coordinator(&self, seat: &str, kind: EnvelopeKind) -> Arc<ReplicationCoordinator> {
        if let Some(c) = self.registry.get_initiator(seat, kind).await {
            return c;
        }
        let c = build_peer_coordinator(
            &self.transport,
            &self.bridge,
            &self.applier,
            self.proactive_publish,
            seat,
            kind,
            SessionRole::Initiator,
        );
        self.registry
            .register(seat.to_owned(), kind, Arc::clone(&c))
            .await;
        c
    }

    /// A seat now holds our key and route: from here on it gets the IOR legs
    /// and its [`BUNDLE_ROUND_PLANES`] round (scheduled like any initiator).
    async fn note_attributed(&self, seat: &str) {
        let first = self
            .attributed
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(seat.to_owned());
        if !first {
            return;
        }
        tracing::info!(
            seat,
            "bundle seat holds this node's key and route: its revocation round starts \
             (CIRISEdge#971)"
        );
        for p in bundle_bootstrap_peers(&[seat.to_owned()], self.local.as_deref()) {
            let key = (p.peer_key_id.clone(), p.kind);
            if !self.current_initiators.lock().await.insert(key) {
                continue;
            }
            let coord = build_peer_coordinator(
                &self.transport,
                &self.bridge,
                &self.applier,
                self.proactive_publish,
                &p.peer_key_id,
                p.kind,
                SessionRole::Initiator,
            );
            self.registry
                .register(p.peer_key_id.clone(), p.kind, Arc::clone(&coord))
                .await;
            let _ = self.scheduler_handle.add_initiator(coord).await;
        }
    }

    /// One Pull leg; counted, never fatal.
    async fn leg(
        &self,
        coord: &Arc<ReplicationCoordinator>,
        slot: usize,
        subject: &str,
        offer: bool,
        label: &'static str,
    ) {
        self.pulls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.pulls_on[slot].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.note(label);
        match coord
            .pull_exchange_offering(subject, self.round_timeout, offer)
            .await
        {
            Ok(crate::replication::coordinator::PullDispatched::Throttled { .. }) => {
                self.note(crate::observability::BUNDLE_PULL_HELD_BACK);
            }
            Ok(_) => {}
            Err(e) => tracing::debug!(
                kind = ?coord.kind(),
                subject,
                error = %e,
                "bundle-seat Pull not sent; the next cycle asks again (CIRISEdge#971)"
            ),
        }
    }

    /// One cycle; its cause picks the legs (see [`CycleCause`]). Returns
    /// whether every target seat holds our key and route.
    async fn cycle(&self, cause: &CycleCause) -> bool {
        let Some(local) = self.local.clone() else {
            return true;
        };
        let targets = self.targets();
        if targets.is_empty() {
            return true;
        }
        self.note(match cause {
            CycleCause::FirstContact => crate::observability::BUNDLE_PULL_CYCLE_FIRST_CONTACT,
            CycleCause::Timer => crate::observability::BUNDLE_PULL_CYCLE_TIMER,
            CycleCause::HostKick => crate::observability::BUNDLE_PULL_CYCLE_KICK,
            CycleCause::Wrote(_) => crate::observability::BUNDLE_PULL_CYCLE_WRITE,
        });
        let owner = if *cause == CycleCause::Timer {
            let owner = self.bridge.owner_of_node(&local).await;
            self.bridge.note_local_owner(owner.clone());
            owner
        } else {
            None
        };
        let mut all = true;
        for seat in targets {
            let attributed = self.is_attributed(&seat);
            for (slot, kind) in BUNDLE_PULL_PLANES.into_iter().enumerate() {
                // IOR is not a bootstrap kind: before the seat attributes us
                // its frames drop there, so the leg waits.
                if kind == EnvelopeKind::IdentityOccurrenceRevocation && !attributed {
                    continue;
                }
                if let CycleCause::Wrote(planes) = cause {
                    if !planes.contains(&kind) {
                        continue;
                    }
                }
                let coord = self.coordinator(&seat, kind).await;
                self.leg(
                    &coord,
                    slot,
                    &local,
                    true,
                    crate::observability::BUNDLE_PULL_SELF,
                )
                .await;
                if matches!(cause, CycleCause::Wrote(_)) {
                    continue;
                }
                self.leg(
                    &coord,
                    slot,
                    &seat,
                    false,
                    crate::observability::BUNDLE_PULL_SEAT,
                )
                .await;
                if let Some(o) = owner.as_deref() {
                    if BUNDLE_OWNER_PLANES.contains(&kind) {
                        self.leg(
                            &coord,
                            slot,
                            o,
                            false,
                            crate::observability::BUNDLE_PULL_OWNER,
                        )
                        .await;
                    }
                }
            }
            // The offering Key and TD Pulls of an EARLIER cycle may have shown
            // the seat holds our key and route.
            if !attributed {
                let key = self.coordinator(&seat, EnvelopeKind::Key).await;
                let td = self
                    .coordinator(&seat, EnvelopeKind::TransportDestination)
                    .await;
                if key.peer_holds_offered() && td.peer_holds_offered() {
                    self.note_attributed(&seat).await;
                } else {
                    all = false;
                }
            }
        }
        all
    }
}

/// CIRISEdge#971 (d) — the next timer cycle: [`BUNDLE_PULL_INTERVAL`] drawn
/// from half to one and a half of itself, per device, so a fleet re-linked in
/// one second by a seat restart does not stay in phase. The ordinary round
/// tick carries no jitter to reuse (scheduler.rs); this is the shape of its
/// one draw, `redial_delay` after a failed dial.
fn bundle_pull_delay() -> std::time::Duration {
    jittered(BUNDLE_PULL_INTERVAL, &mut rand::thread_rng())
}

/// CIRISEdge#971 (d) — the next first-contact retry:
/// [`BUNDLE_PULL_MIN_SPACING`] drawn the same way, so a fleet that a seat
/// restart re-links in one second does not retry in step for three minutes.
fn first_contact_delay() -> std::time::Duration {
    jittered(BUNDLE_PULL_MIN_SPACING, &mut rand::thread_rng())
}

/// `base` drawn uniformly from half to one and a half of itself.
fn jittered(base: std::time::Duration, rng: &mut impl rand::Rng) -> std::time::Duration {
    let ms = u64::try_from(base.as_millis()).unwrap_or(u64::MAX / 2);
    std::time::Duration::from_millis(rng.gen_range(ms / 2..=ms.saturating_mul(3) / 2))
}

/// CIRISEdge#971 (d) — one WARN per process when first contact gives up.
static FIRST_CONTACT_GAVE_UP_WARNED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// CIRISEdge#971 (d) — first contact ran out of quick tries with a seat that
/// still does not hold our key and route: from here the ordinary jittered
/// timer asks, counted, and one WARN per process says so.
fn note_first_contact_gave_up(pull: &BundlePull) {
    pull.note(crate::observability::BUNDLE_PULL_FIRST_CONTACT_GAVE_UP);
    if !FIRST_CONTACT_GAVE_UP_WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            tries = BUNDLE_FIRST_CONTACT_TRIES,
            "a bundle seat does not yet hold this node's key and route after the quick \
             first-contact tries; it is asked on the ordinary 5-15 min timer from now on, \
             and its revocation round waits until it does (tracked: CIRISEdge#971)"
        );
    }
}

/// CIRISEdge#971 (d) — run [`BundlePull`]'s cycles. First contact at once and
/// then every [`first_contact_delay`] (30 s, jittered) until every seat holds
/// our key and route, at most [`BUNDLE_FIRST_CONTACT_TRIES`]; then the
/// jittered timer ([`note_first_contact_gave_up`] if the tries ran out). A
/// kick runs no sooner than [`BUNDLE_PULL_MIN_SPACING`] after the last cycle;
/// kicks that land meanwhile merge into one cycle.
fn spawn_bundle_pull(pull: Arc<BundlePull>, cancel_rx: &watch::Receiver<bool>) {
    let mut cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let mut tries = 0u32;
        let mut settled = false;
        let mut last: Option<tokio::time::Instant> = None;
        let mut next = tokio::time::Instant::now();
        loop {
            let timer = tokio::select! {
                res = cancel.changed() => {
                    if res.is_err() || *cancel.borrow() {
                        return;
                    }
                    continue;
                }
                () = tokio::time::sleep_until(next) => true,
                () = pull.kick.notified() => false,
            };
            if !timer {
                if let Some(l) = last {
                    tokio::time::sleep_until(l + BUNDLE_PULL_MIN_SPACING).await;
                }
            }
            let kicks = pull.take_pending();
            if kicks.contact {
                settled = false;
                tries = 0;
            }
            let cause = if timer || kicks.contact {
                if settled {
                    CycleCause::Timer
                } else {
                    CycleCause::FirstContact
                }
            } else if kicks.host {
                CycleCause::HostKick
            } else if !kicks.wrote.is_empty() {
                CycleCause::Wrote(kicks.wrote)
            } else {
                continue;
            };
            let now = tokio::time::Instant::now();
            last = Some(now);
            let all_attributed = pull.cycle(&cause).await;
            if matches!(cause, CycleCause::FirstContact | CycleCause::Timer) {
                tries = tries.saturating_add(1);
                if !settled && all_attributed {
                    settled = true;
                } else if !settled && tries >= BUNDLE_FIRST_CONTACT_TRIES {
                    settled = true;
                    note_first_contact_gave_up(&pull);
                }
                next = if settled {
                    now + bundle_pull_delay()
                } else {
                    now + first_contact_delay()
                };
            }
        }
    });
}

fn spawn_homed_forwarder(homed: HomedPeers, cancel_rx: &watch::Receiver<bool>) {
    use tokio::sync::broadcast::error::RecvError;
    let Some(mut events) = homed.transport.subscribe_homed() else {
        return;
    };
    let mut cancel = cancel_rx.clone();
    tokio::spawn(async move {
        // Subscribed first: one homed before this runtime came up is still used.
        for node in homed.transport.homed_peers() {
            homed.register(&node).await;
        }
        loop {
            tokio::select! {
                _ = cancel.changed() => {
                    if *cancel.borrow() {
                        return;
                    }
                }
                event = events.recv() => match event {
                    Ok(node) => homed.register(&node).await,
                    Err(RecvError::Lagged(_)) => {
                        for node in homed.transport.homed_peers() {
                            homed.register(&node).await;
                        }
                    }
                    Err(RecvError::Closed) => return,
                },
            }
        }
    });
}

/// A coordinator in `role` over the runtime's shared parts.
fn build_peer_coordinator(
    transport: &Arc<dyn Transport>,
    bridge: &Arc<FederationDirectoryReplicationBridge>,
    applier: &Arc<dyn StateApplier>,
    proactive_publish: bool,
    peer_key_id: &str,
    kind: EnvelopeKind,
    role: SessionRole,
) -> Arc<ReplicationCoordinator> {
    let bridge_dir: Arc<dyn ReplicationDirectory> = Arc::clone(bridge) as _;
    // CIRISEdge#379 — peer-bound provider (observer gate).
    let provider: Arc<dyn StateProvider> =
        Arc::new(DirectoryStateAdapter::new(bridge_dir).with_peer(peer_key_id));
    // CIRISEdge#370 — hot-adds share the runtime's ONE no-mutex applier.
    let applier = Arc::clone(applier);
    // CIRISEdge#927 — hot-added Initiators inherit the runtime's proactive-
    // publish posture. Harmless for Responders (they never `start_round`).
    Arc::new(
        ReplicationCoordinator::new(
            Arc::clone(transport),
            peer_key_id.to_string(),
            kind,
            role,
            provider,
            applier,
        )
        .with_proactive_publish(proactive_publish),
    )
}

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
    /// the-whole-message critical section is gone, and so (CIRISEdge#740) is
    /// the `block_in_place` + `block_on` bridge the adapter used to carry —
    /// the apply is awaited end to end.
    applier: Arc<dyn StateApplier>,
    /// Bumped once per ADMITTED envelope. The thing that lets a caller AWAIT a
    /// row's arrival rather than poll for it — see [`Self::await_convergence`]
    /// and [`Self::pull_and_await`].
    convergence: Arc<super::convergence::ConvergenceSignal>,
    cancel_tx: watch::Sender<bool>,
    scheduler_task: Option<JoinHandle<()>>,
    /// CIRISEdge#768 — the pending-KeyGrant emitter
    /// ([`super::key_grant_emitter`]); `Some` iff `sealed_content` was set.
    key_grant_emitter: Option<JoinHandle<()>>,
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
    /// CIRISEdge#881 — the bundle-seeded bootstrap peers merged into every
    /// peer set this runtime is given (`start`, `set_peers`).
    /// CIRISEdge#971 — grows only: a serve node whose record lands after
    /// start joins at the next `set_peers` ([`recheck_bundle_peers`]).
    bundle_peers: std::sync::Mutex<Vec<ReplicationPeer>>,
    /// CIRISEdge#971 — the directory the bundle re-check reads.
    bundle_directory: Arc<dyn FederationDirectory>,
    /// CIRISEdge#971 (d) — bundle-seat mode.
    bundle_pull: Arc<BundlePull>,
    /// CC 5.4.3 referrals — the nodes homed on, merged the same way.
    homed_peers: Arc<Mutex<Vec<ReplicationPeer>>>,
    /// CIRISEdge#971 — each bundle serve node not taken as a bootstrap peer,
    /// with why ([`Self::bundle_skipped`]).
    bundle_skipped: std::sync::Mutex<Vec<(String, BundleSkip)>>,
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
    // The assembly reads as one sequence (bridge → registry → applier →
    // coordinators → scheduler → the #768 KeyGrant emitter); splitting it to
    // dodge the line ceiling would scatter the ONE production wiring.
    #[allow(clippy::too_many_lines)]
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
        // CIRISEdge#881 — the bundle's seated serve nodes round with this node
        // on the bootstrap planes whether or not consent names any peer.
        let serve_nodes = crate::edge::baked_canonical_genesis_ids();
        let bundle_directory = Arc::clone(&directory);
        let (bundle_peers, bundle_skipped) = bundle_bootstrap_peers_held(
            &serve_nodes,
            &*directory,
            config.local_key_id.as_deref(),
            config.disable_bundle_bootstrap_peers,
            crate::edge::test_trust_root_override_active(),
        )
        .await;
        let host_peers = distinct_peers(&peers);
        let host_keys: HashSet<String> = peer_keys(&peers);
        // CIRISEdge#971 (d) — the bundle seats' revocation round starts once a
        // seat holds our route (`BundlePull::note_attributed`); their other
        // planes are subject Pulls.
        let peers = without_retired_planes(peers);
        note_initiator_peers(config.metrics.as_ref(), host_peers, &bundle_peers, 0);
        if peers.is_empty() && bundle_peers.is_empty() {
            // CIRISEdge#971 — a node with nobody to round with is silent
            // about it otherwise: from v43.2.0 to v44.1.2 every unclaimed
            // device was this node, and nothing said so.
            tracing::warn!(
                skipped = ?bundle_skipped
                    .iter()
                    .map(|(id, why)| format!("{id}:{}", why.as_str()))
                    .collect::<Vec<_>>(),
                "this node will open NO replication round to any seat or peer: no consent \
                 peer names one and every bundle serve node was skipped (named with why). It \
                 is served only by rounds others open to it, until consent names a peer \
                 (tracked: CIRISEdge#971)"
            );
        } else {
            for (id, why) in &bundle_skipped {
                tracing::debug!(
                    serve_node = %id,
                    reason = why.as_str(),
                    "bundle serve node not a bootstrap peer (CIRISEdge#971)"
                );
            }
        }
        if !bundle_peers.is_empty() {
            tracing::info!(
                serve_nodes = bundle_peers.len() / BUNDLE_ROUND_PLANES.len(),
                planes = ?BUNDLE_ROUND_PLANES,
                pull_planes = ?BUNDLE_PULL_PLANES,
                "the bundle's seated serve nodes are asked by subject Pull, consent or not; \
                 their revocation round starts once a seat holds this node's route \
                 (CIRISEdge#881, CIRISEdge#971)"
            );
        }
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
                "replication started with NO self-publish set: this node will advertise                  none of its own Key / IdentityOccurrence / TransportDestination rows, so                  peers cannot satisfy history: CIRISEdge#393 item 2 for it and will DROP its                  frames unattributed. Pass `Some(self_publish_set(..))` unless this node                  is deliberately publishing nothing about itself"
            );
        }

        // CIRISEdge#397 — bring persist's signed_wire_index current for the
        // content-hash point-read fetch (once, idempotent, fail-soft).
        rebuild_signed_wire_index_fail_soft(&directory).await;

        let mesh_config = build_mesh_config_reader(&directory, &config);

        // The ONE production bridge — shared by every coordinator below AND by the
        // #312 responder factory. See [`build_bridge`] for the #433 metrics wiring.
        let convergence = super::convergence::ConvergenceSignal::shared();
        // CIRISEdge#768 — the pending-KeyGrant emitter's wake (iff this node seals).
        let key_grant_wake = config.sealed_content.as_ref().map(|_| Arc::default());
        let bridge = build_bridge(
            &directory,
            cohort,
            &config,
            self_provider,
            mesh_config.clone(),
            Arc::clone(&convergence),
            key_grant_wake.clone(),
        );
        // CIRISEdge#971 — the holdings index warms in the background (its walk
        // of the served log and its boot drain), never inline in a peer's ask:
        // a round before it is Ready takes the pre-v45 drain.
        {
            let bridge = Arc::clone(&bridge);
            tokio::spawn(async move { bridge.warm_holdings_index().await });
        }

        // CIRISEdge#727 — the registry carries the owner-binding rung's
        // receiver gate (see [`registry_for`]).
        let registry = registry_for(&config, &directory, &bridge, &transport);

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
            // One per node: every responder's reply lane draws on it.
            let reply_budget = Arc::<crate::replication::reply_lane::ReplyBudget>::default();
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
                spawn_responder_drive(Arc::clone(&coord), Arc::clone(&reply_budget));
                coord
            }));
        }

        // Build coordinators + scheduler. Coordinators share one
        // bridge instance; the provider is per-peer (#379 observer gate),
        // the applier is the ONE shared no-mutex `Arc<dyn StateApplier>`
        // (#370 — apply is `&self`; the store owns serialization). The
        // scheduler carries the mesh-config reader so a #440 cadence relief
        // takes effect on the next round.
        let mut scheduler = ReplicationScheduler::new(config.scheduler)
            .with_mesh_config(mesh_config.clone())
            .with_metrics(config.metrics.clone());
        let scheduler_handle = with_release_kick(&bridge, scheduler.install_control_channel());
        // CIRISEdge#794 — inbound frames clear their sender's no-route backoff.
        registry.install_no_route_backoff(&scheduler_handle);
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
        let key_grant_emitter = spawn_key_grant_emitter_for(&config, key_grant_wake, &cancel_rx);
        spawn_reachability_forwarder(&transport, &scheduler_handle, &cancel_rx);
        let current_initiators = Arc::new(Mutex::new(initial_initiator_set));
        let homed_peers = Arc::new(Mutex::new(Vec::new()));
        spawn_homed_forwarder(
            HomedPeers {
                transport: Arc::clone(&transport),
                registry: Arc::clone(&registry),
                bridge: Arc::clone(&bridge),
                applier: Arc::clone(&shared_applier),
                scheduler_handle: scheduler_handle.clone(),
                current_initiators: Arc::clone(&current_initiators),
                proactive_publish,
                peers: Arc::clone(&homed_peers),
            },
            &cancel_rx,
        );
        // CIRISEdge#971 — the host's consent peers, for the no-consent seat
        // rule (`names_only_required_subjects`).
        bridge.set_consent_peers(host_keys.iter().cloned());
        // CIRISEdge#971 (d) — the bundle seats' required set, by subject Pull.
        let bundle_pull = Arc::new(BundlePull {
            transport: Arc::clone(&transport),
            registry: Arc::clone(&registry),
            bridge: Arc::clone(&bridge),
            applier: Arc::clone(&shared_applier),
            scheduler_handle: scheduler_handle.clone(),
            current_initiators: Arc::clone(&current_initiators),
            metrics: config.metrics.clone(),
            proactive_publish,
            local: config.local_key_id.clone(),
            round_timeout: config.scheduler.round_timeout,
            seats: std::sync::Mutex::new(Vec::new()),
            host: std::sync::Mutex::new(host_keys),
            attributed: std::sync::Mutex::new(HashSet::new()),
            pending: std::sync::Mutex::default(),
            kick: tokio::sync::Notify::new(),
            pulls: std::sync::atomic::AtomicU64::new(0),
            pulls_on: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
        });
        bundle_pull.set_seats(peer_keys(&bundle_peers).into_iter().collect());
        spawn_bundle_pull(Arc::clone(&bundle_pull), &cancel_rx);
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
            key_grant_emitter,
            config,
            scheduler_handle,
            current_initiators,
            bundle_peers: std::sync::Mutex::new(bundle_peers),
            bundle_skipped: std::sync::Mutex::new(bundle_skipped),
            bundle_directory,
            bundle_pull,
            homed_peers,
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
        // persist v61 — a retired plane carries nothing; it is never scheduled.
        // Debug: a host's reconcile can name one on every pass.
        if kind.is_retired_plane() {
            tracing::debug!(
                peer = %peer_key_id,
                kind = kind.as_wire_str(),
                "replication peer on a RETIRED plane not scheduled"
            );
            return Ok(());
        }
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
    /// peer is known to the scheduler — then runs a Pull on an exchange of its
    /// own ([`ReplicationCoordinator::pull_exchange`](super::coordinator::ReplicationCoordinator::pull_exchange)).
    /// The peer answers with the subject's refs (projection-gated + G2-carved by
    /// its `subject_holdings`), and the gap is fetched and applied in that
    /// exchange, on the frames' own time and never on a round's. A plane the
    /// peer throttled sends nothing until its hint runs out
    /// ([`Self::subject_pull_retry_after`]).
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
    ///
    /// CIRISEdge#968 — a kick is the host reporting a local write, so it drops
    /// the send-set memos first ([`FederationDirectoryReplicationBridge::invalidate_send_set_memos`]):
    /// the round it fires reads the consent grant it was fired for.
    pub async fn round_now(&self, peer_key_id: &str) -> Result<(), ReplicationRuntimeError> {
        self.bridge.invalidate_send_set_memos("host_kick");
        self.bundle_pull.kick_host();
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
        // CIRISEdge#968 — see [`Self::round_now`].
        self.bridge.invalidate_send_set_memos("host_kick");
        self.bundle_pull.kick_host();
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
        // CIRISEdge#968 — once, not per re-kick: the host may have just
        // written what this sync is for; the re-kicks below wait on the peer.
        self.bridge.invalidate_send_set_memos("host_sync");
        loop {
            self.scheduler_handle.round_now(Some(peer_key_id)).await?;
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

    /// CIRISEdge#937 — seconds left before `peer_key_id` will answer a subject
    /// Pull again, on the plane it throttled longest; `None` when no plane is.
    /// What a host reads to say "looking…" instead of "not found".
    pub async fn subject_pull_retry_after(&self, peer_key_id: &str) -> Option<u64> {
        let mut longest = None;
        for kind in EnvelopeKind::subject_pullable() {
            if let Some(coord) = self.registry.get_initiator(peer_key_id, kind).await {
                longest = longest.max(coord.pull_retry_after_secs());
            }
        }
        longest
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
                if let Err(e) = coord
                    .pull_exchange(subject_key_id, self.config.scheduler.round_timeout)
                    .await
                {
                    tracing::warn!(
                        peer = %peer_key_id,
                        subject = %subject_key_id,
                        kind = ?kind,
                        error = %e,
                        "subject Pull send failed — surfacing to the caller for retry (history: CIRISEdge#462)"
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
        let host = distinct_peers(&desired);
        let homed = self.homed_peers.lock().await.clone();
        let bundle = self.recheck_bundle().await;
        // CIRISEdge#971 (d) — the host's peers round as consent peers; the
        // other bundle seats are asked by Pull. A seat new to the set is asked
        // now.
        let before = self.bundle_pull.targets();
        self.bridge.set_consent_peers(peer_keys(&desired));
        self.bundle_pull.set_host(peer_keys(&desired));
        self.bundle_pull
            .set_seats(peer_keys(&bundle).into_iter().collect());
        if self.bundle_pull.targets() != before {
            self.bundle_pull.kick_contact();
        }
        note_initiator_peers(
            self.config.metrics.as_ref(),
            host,
            &bundle,
            distinct_peers(&homed),
        );
        // CIRISEdge#881 / #971 (d) — the bundle seats that hold our route keep
        // their revocation round across every peer set.
        let desired = merge_peers(desired, &self.bundle_pull.round_peers());
        let desired = merge_peers(desired, &homed);
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
        build_peer_coordinator(
            &self.transport,
            &self.bridge,
            &self.applier,
            self.proactive_publish,
            peer_key_id,
            kind,
            role,
        )
    }

    /// Shared registry handle. The operator's `Transport::listen`
    /// loop calls [`ReplicationRegistry::route_inbound_bytes`] on
    /// this when bytes arrive from an identified source peer.
    pub fn registry(&self) -> Arc<ReplicationRegistry> {
        Arc::clone(&self.registry)
    }

    /// CIRISEdge#794 — every peer backed off for having no route, with its
    /// next-attempt time and current window.
    #[must_use]
    pub fn no_route_backoff(&self) -> Vec<super::no_route_backoff::NoRouteBackoffEntry> {
        self.scheduler_handle.no_route_backoff()
    }

    /// CIRISEdge#794 — set the no-route backoff's window ceiling (default
    /// [`DEFAULT_NO_ROUTE_BACKOFF_CAP`](super::no_route_backoff::DEFAULT_NO_ROUTE_BACKOFF_CAP),
    /// 15 min). Takes effect at each backed-off peer's next window.
    pub fn set_no_route_backoff_cap(&self, cap: std::time::Duration) {
        self.scheduler_handle.set_no_route_backoff_cap(cap);
    }

    /// CIRISEdge#740 — the scheduler's round bound and its counters: the
    /// bound, rounds in flight now, the peak, and how many rounds have waited
    /// behind the gate since start.
    #[must_use]
    pub fn round_bound(&self) -> super::scheduler::RoundBoundStats {
        self.scheduler_handle.round_bound()
    }

    /// CIRISEdge#858 — the host's release hook: release every row this node
    /// parked on `key_id` and ask the peers that offered them again now. Call
    /// it after ANY local key registration and after an owner-binding write
    /// (a claim): those bypass the apply choke that would otherwise release
    /// the park, and the rows would wait out their terminal window. See
    /// [`FederationDirectoryReplicationBridge::release_signer`].
    pub fn release_signer(&self, key_id: &str) -> usize {
        // CIRISEdge#968 — a local key registration or claim: what moves to a
        // peer may have changed with it.
        self.bridge.invalidate_send_set_memos("release_signer");
        self.bridge.release_signer(key_id)
    }

    /// CIRISEdge#858 — [`Self::release_signer`] for a row written locally,
    /// given as its wire bytes: releases the signer the row binds and the key
    /// that signed it. One call after `apply_signed_owner_binding` covers a
    /// claim. See
    /// [`FederationDirectoryReplicationBridge::release_bound_signer`].
    pub fn release_bound_signer(&self, kind: EnvelopeKind, envelope_bytes: &[u8]) -> usize {
        // CIRISEdge#968 — the owner-binding a claim wrote moves the owner and
        // send-set memos; no apply event announces it.
        self.bridge
            .invalidate_send_set_memos("release_bound_signer");
        self.bundle_pull.kick_wrote(kind);
        self.bridge.release_bound_signer(kind, envelope_bytes)
    }

    /// v44 (CIRISConstitution#198 §5) — a receiver of every later
    /// decision-relevant-row event ([`crate::decision_rows`]). Nothing fires
    /// while the node is suspended; rebuild from the last cursor with
    /// [`crate::decision_rows::decision_rows_since`] on resume.
    #[must_use]
    pub fn subscribe_decision_rows(
        &self,
    ) -> tokio::sync::broadcast::Receiver<crate::decision_rows::DecisionRowRef> {
        self.bridge.subscribe_decision_rows()
    }

    /// v44 — the host wrote `row` locally: emit its decision-row event and
    /// carry it to every peer now. `written_after` is an instant taken
    /// before the write. See
    /// [`FederationDirectoryReplicationBridge::note_local_write`].
    pub async fn note_local_write(
        &self,
        row: &ciris_persist::federation::Attestation,
        written_after: chrono::DateTime<chrono::Utc>,
    ) -> Option<crate::decision_rows::DecisionRowRef> {
        // CIRISEdge#971 (d) — an Attestation-plane row: no bundle Pull plane
        // moved, so no bundle-seat cycle.
        self.bridge.note_local_write(row, written_after).await
    }

    /// v44 — the host wrote rows persist minted (a `put_*` roster door):
    /// emit an event for every decision-relevant row served since
    /// `written_after`, and carry them now. See
    /// [`FederationDirectoryReplicationBridge::note_local_writes_since`].
    ///
    /// # Errors
    /// persist's read failure.
    pub async fn note_local_writes_since(
        &self,
        written_after: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<crate::decision_rows::DecisionRowRef>, ciris_persist::federation::Error> {
        // CIRISEdge#971 (d) — Attestation-plane rows only, as above.
        self.bridge
            .note_local_writes_since(written_after, None)
            .await
    }

    /// CIRISEdge#971 — the bundle serve nodes this runtime rounds with on the
    /// bootstrap planes, and those it skipped with why.
    #[must_use]
    pub fn bundle_peers(&self) -> (Vec<ReplicationPeer>, Vec<(String, BundleSkip)>) {
        (
            self.bundle_peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            self.bundle_skipped
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
    }

    /// CIRISEdge#971 (d) — subject Pulls sent to bundle seats so far.
    #[must_use]
    pub fn bundle_pulls_sent(&self) -> u64 {
        self.bundle_pull
            .pulls
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// CIRISEdge#971 (d) — subject Pulls sent to bundle seats on `kind` so
    /// far (0 for a plane not in [`BUNDLE_PULL_PLANES`]).
    #[must_use]
    pub fn bundle_pulls_sent_on(&self, kind: EnvelopeKind) -> u64 {
        BUNDLE_PULL_PLANES
            .iter()
            .position(|k| *k == kind)
            .map_or(0, |slot| {
                self.bundle_pull.pulls_on[slot].load(std::sync::atomic::Ordering::Relaxed)
            })
    }

    /// CIRISEdge#971 — the scheduled initiator pairs, sorted: what produces
    /// this node's round frames.
    #[doc(hidden)]
    pub async fn initiator_set_for_test(&self) -> Vec<(String, EnvelopeKind)> {
        let mut v: Vec<_> = self
            .current_initiators
            .lock()
            .await
            .iter()
            .cloned()
            .collect();
        v.sort_by(|a, b| (&a.0, a.1.as_wire_str()).cmp(&(&b.0, b.1.as_wire_str())));
        v
    }

    /// CIRISEdge#971 (d) — run one timer cycle now, without its spacing.
    pub async fn bundle_pull_now(&self) {
        let _ = self.bundle_pull.cycle(&CycleCause::Timer).await;
    }

    /// CIRISEdge#971 (d) — a host kick's cycle, now, without its spacing.
    #[doc(hidden)]
    pub async fn bundle_pull_host_kick_now_for_test(&self) {
        let _ = self.bundle_pull.cycle(&CycleCause::HostKick).await;
    }

    /// CIRISEdge#971 (d) — a local write's cycle on `kind`, now, without its
    /// spacing.
    #[doc(hidden)]
    pub async fn bundle_pull_wrote_now_for_test(&self, kind: EnvelopeKind) {
        let _ = self.bundle_pull.cycle(&CycleCause::Wrote(vec![kind])).await;
    }

    /// CIRISEdge#971 test seam — treat `seat` as a bundle serve node this
    /// runtime holds, as `start` would for a baked one: its
    /// [`BUNDLE_ROUND_PLANES`] round, and Pulls on [`BUNDLE_PULL_PLANES`]
    /// unless the host names it. Honours the opt-out.
    ///
    /// # Errors
    /// The scheduler has shut down.
    #[doc(hidden)]
    pub async fn adopt_bundle_seat_for_test(
        &self,
        seat: &str,
    ) -> Result<(), ReplicationRuntimeError> {
        if self.config.disable_bundle_bootstrap_peers {
            return Ok(());
        }
        let added = bundle_bootstrap_peers(&[seat.to_owned()], self.config.local_key_id.as_deref());
        if added.is_empty() {
            return Ok(());
        }
        {
            let mut peers = self
                .bundle_peers
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            peers.extend(added.iter().cloned());
            self.bundle_pull
                .set_seats(peer_keys(&peers).into_iter().collect());
        }
        self.bundle_pull.kick_contact();
        Ok(())
    }

    /// CIRISEdge#971 test seam — stand in for the baked bundle: the serve
    /// nodes this runtime has skipped, as `start` would have recorded them.
    #[cfg(test)]
    pub(crate) fn seed_bundle_skipped_for_test(&self, skipped: Vec<(String, BundleSkip)>) {
        *self
            .bundle_skipped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = skipped;
    }

    /// CIRISEdge#971 — the bundle's serve nodes as they stand now: re-check
    /// the ones not yet held ([`recheck_bundle_peers`]) and take any that
    /// landed. Zero reads once every serve node is held or fixed-skipped.
    async fn recheck_bundle(&self) -> Vec<ReplicationPeer> {
        let skipped = self
            .bundle_skipped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let (added, still) = recheck_bundle_peers(
            &skipped,
            &*self.bundle_directory,
            self.config.local_key_id.as_deref(),
        )
        .await;
        if !added.is_empty() {
            tracing::info!(
                serve_nodes = distinct_peers(&added),
                planes = ?BUNDLE_ROUND_PLANES,
                "a bundle serve node's record landed after start: it is a bootstrap peer from \
                 now on (CIRISEdge#971)"
            );
        }
        *self
            .bundle_skipped
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = still;
        let mut peers = self
            .bundle_peers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        peers.extend(added);
        peers.clone()
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
        if let Some(task) = self.key_grant_emitter.take() {
            let _ = task.await;
        }
    }
}

#[cfg(test)]
mod tests {
    /// CIRISEdge#881 — the unit runtimes assert their exact peer sets; the
    /// bundle's canonicals are opt-in and stay out of them.
    fn unit_config() -> ReplicationRuntimeConfig {
        ReplicationRuntimeConfig {
            disable_bundle_bootstrap_peers: true,
            ..ReplicationRuntimeConfig::default()
        }
    }

    /// CIRISEdge#881 — the bundle's serve nodes join every peer set on the
    /// bootstrap planes only, never this node itself, never twice.
    #[test]
    fn bundle_serve_nodes_round_on_the_bootstrap_planes_only() {
        use super::{bundle_bootstrap_peers, merge_peers, ReplicationPeer, BUNDLE_ROUND_PLANES};
        let serve = vec![
            "canon-a".to_string(),
            "me".to_string(),
            "canon-b".to_string(),
        ];
        let extra = bundle_bootstrap_peers(&serve, Some("me"));
        assert_eq!(extra.len(), 2 * BUNDLE_ROUND_PLANES.len());
        assert!(extra.iter().all(|p| p.peer_key_id != "me"));
        assert!(extra.iter().all(|p| BUNDLE_ROUND_PLANES.contains(&p.kind)));
        assert!(
            !extra
                .iter()
                .any(|p| p.kind == super::EnvelopeKind::Attestation),
            "no content plane"
        );
        let host = vec![
            ReplicationPeer {
                peer_key_id: "canon-a".into(),
                kind: super::EnvelopeKind::Key,
            },
            ReplicationPeer {
                peer_key_id: "friend".into(),
                kind: super::EnvelopeKind::Attestation,
            },
        ];
        let merged = merge_peers(host.clone(), &extra);
        assert_eq!(
            merged.len(),
            host.len() + extra.len() - 1,
            "the duplicate (canon-a, Key) once"
        );
        assert_eq!(merged[0].peer_key_id, "canon-a", "host order kept");
        assert_eq!(merged[1].peer_key_id, "friend");
        assert!(bundle_bootstrap_peers(&[], None).is_empty());
    }

    use super::*;
    use std::sync::Arc;

    /// CIRISEdge#853 (Codex round two on #854) — a frame naming a NEW round
    /// restarts the responder's round clock; frames of the same round and
    /// legacy frames do not.
    #[test]
    fn the_round_clock_restarts_when_the_responder_rebinds_854() {
        let t0 = std::time::Instant::now();
        let t1 = t0 + std::time::Duration::from_secs(40);
        let t2 = t1 + std::time::Duration::from_secs(5);
        let (mut began, mut round) = (None, 0u64);
        assert_eq!(responder_round_clock(&mut began, &mut round, 7, t0), t0);
        assert_eq!(
            responder_round_clock(&mut began, &mut round, 7, t1),
            t0,
            "the same round keeps its start"
        );
        assert_eq!(
            responder_round_clock(&mut began, &mut round, 0, t1),
            t0,
            "a legacy frame does not move it"
        );
        assert_eq!(
            responder_round_clock(&mut began, &mut round, 8, t2),
            t2,
            "a new round id: the abandoned round's 45 s are not this round's"
        );
    }

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

    // ── CIRISEdge#971 — the bundle path, on by default, behind ONE rule ──

    /// A directory that holds a key record for each of `held`.
    async fn directory_holding(held: &[&str]) -> Arc<dyn FederationDirectory> {
        use ciris_persist::federation::types::identity_type;
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let keys: Vec<(&str, &str)> = held.iter().map(|k| (*k, identity_type::NODE)).collect();
        crate::replication::bridge::tests::register_fixture_keys(&backend, &keys).await;
        backend
    }

    fn planes_of(peers: &[ReplicationPeer], who: &str) -> Vec<EnvelopeKind> {
        let mut kinds: Vec<EnvelopeKind> = peers
            .iter()
            .filter(|p| p.peer_key_id == who)
            .map(|p| p.kind)
            .collect();
        kinds.sort_by_key(|k| k.as_wire_str());
        kinds
    }

    /// (a) A serve node this runtime's directory holds is a bootstrap peer on
    /// the bootstrap planes and nothing else; one it does not hold is skipped
    /// by name. Mutation: drop the directory check, `seat-b` is a peer.
    #[tokio::test]
    async fn a_held_serve_node_is_a_bootstrap_peer_on_the_bootstrap_planes_only_971() {
        let dir = directory_holding(&["seat-a"]).await;
        let ids = vec!["seat-a".to_owned(), "seat-b".to_owned()];
        let (peers, skipped) =
            bundle_bootstrap_peers_held(&ids, &*dir, Some("device"), false, false).await;
        let mut want = BUNDLE_ROUND_PLANES.to_vec();
        want.sort_by_key(|k| k.as_wire_str());
        assert_eq!(planes_of(&peers, "seat-a"), want);
        assert!(
            planes_of(&peers, "seat-b").is_empty(),
            "not held: not a peer"
        );
        assert_eq!(
            skipped,
            vec![("seat-b".to_owned(), BundleSkip::NotInDirectory)]
        );
    }

    /// (b) Under a test trust root no serve node is a peer, held or not.
    #[tokio::test]
    async fn under_a_test_trust_root_no_serve_node_is_a_peer_971() {
        let dir = directory_holding(&["seat-a"]).await;
        let ids = vec!["seat-a".to_owned()];
        let (peers, skipped) =
            bundle_bootstrap_peers_held(&ids, &*dir, Some("device"), false, true).await;
        assert!(peers.is_empty());
        assert_eq!(
            skipped,
            vec![("seat-a".to_owned(), BundleSkip::TestTrustRoot)]
        );
    }

    /// (c) The host's opt-out: no serve node is a peer.
    #[tokio::test]
    async fn the_opt_out_takes_no_serve_node_971() {
        let dir = directory_holding(&["seat-a"]).await;
        let ids = vec!["seat-a".to_owned()];
        let (peers, skipped) =
            bundle_bootstrap_peers_held(&ids, &*dir, Some("device"), true, false).await;
        assert!(peers.is_empty());
        assert_eq!(skipped, vec![("seat-a".to_owned(), BundleSkip::OptedOut)]);
    }

    /// (d) A serve node does not round with itself, though it holds its own
    /// record; the other seats it holds are its peers.
    #[tokio::test]
    async fn a_serve_node_does_not_add_itself_971() {
        let dir = directory_holding(&["seat-a", "seat-b"]).await;
        let ids = vec!["seat-a".to_owned(), "seat-b".to_owned()];
        let (peers, skipped) =
            bundle_bootstrap_peers_held(&ids, &*dir, Some("seat-a"), false, false).await;
        assert!(planes_of(&peers, "seat-a").is_empty());
        assert_eq!(planes_of(&peers, "seat-b").len(), BUNDLE_ROUND_PLANES.len());
        assert_eq!(skipped, vec![("seat-a".to_owned(), BundleSkip::IsSelf)]);
    }

    /// (4-i) **A record that lands after start.** The serve node joins at the
    /// next `set_peers`: a bundle Pull target from then on, its revocation
    /// round held until it holds our route (never, over a no-op transport).
    /// Mutation: drop the re-check from `set_peers`, and it never joins.
    #[tokio::test]
    async fn a_serve_node_recorded_after_start_joins_at_the_next_set_peers_971() {
        use ciris_persist::federation::types::identity_type;
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend.clone();
        let mut rt = ReplicationRuntime::start(
            directory,
            Arc::new(NoopTransport),
            Vec::new(),
            ReplicationRuntimeConfig {
                local_key_id: Some("device-971-late".to_owned()),
                ..ReplicationRuntimeConfig::default()
            },
            None,
        )
        .await;
        rt.seed_bundle_skipped_for_test(vec![("seat-late".to_owned(), BundleSkip::NotInDirectory)]);
        rt.set_peers(Vec::new()).await.expect("set_peers");
        assert!(rt.bundle_peers().0.is_empty(), "no record yet: not a peer");
        crate::replication::bridge::tests::register_fixture_keys(
            &backend,
            &[("seat-late", identity_type::NODE)],
        )
        .await;
        rt.set_peers(Vec::new()).await.expect("set_peers");
        let (peers, skipped) = rt.bundle_peers();
        assert_eq!(
            planes_of(&peers, "seat-late").len(),
            BUNDLE_ROUND_PLANES.len()
        );
        assert!(skipped.is_empty(), "held now: {skipped:?}");
        assert_eq!(rt.bundle_pull.targets(), vec!["seat-late".to_owned()]);
        let active = rt.current_initiators.lock().await.clone();
        for kind in BUNDLE_ROUND_PLANES {
            assert!(
                !active.contains(&("seat-late".to_owned(), kind)),
                "{kind:?}: no round before the seat holds our route"
            );
        }
        rt.shutdown().await;
    }

    /// (4-ii) **The latch.** Once every serve node is held (or skipped for a
    /// reason that never changes), the re-check reads NOTHING. Mutation:
    /// re-read fixed skips too, and the counts are non-zero.
    #[tokio::test]
    async fn the_recheck_reads_nothing_once_every_serve_node_is_held_971() {
        use crate::replication::counting_directory_930::CountingDirectory;
        let held = directory_holding(&["seat-a"]).await;
        let counting = CountingDirectory::new(held);
        let (peers, still) = recheck_bundle_peers(
            &[("seat-a".to_owned(), BundleSkip::NotInDirectory)],
            &counting,
            Some("device"),
        )
        .await;
        assert_eq!(planes_of(&peers, "seat-a").len(), BUNDLE_ROUND_PLANES.len());
        assert!(still.is_empty());
        assert_eq!(counting.total(), 1, "one read to find it");
        counting.reset();
        let fixed = vec![
            ("seat-b".to_owned(), BundleSkip::OptedOut),
            ("seat-c".to_owned(), BundleSkip::IsSelf),
            ("seat-d".to_owned(), BundleSkip::TestTrustRoot),
        ];
        let (peers, still) = recheck_bundle_peers(&fixed, &counting, Some("device")).await;
        assert!(peers.is_empty());
        assert_eq!(still, fixed);
        assert_eq!(counting.total(), 0, "steady state: zero reads");
    }

    /// (4-iii) **The opt-out wins after a late arrival.** Mutation: let the
    /// re-check read opted-out serve nodes, and the peer appears.
    #[tokio::test]
    async fn the_opt_out_still_wins_after_a_late_arrival_971() {
        let dir = directory_holding(&["seat-a"]).await;
        let (peers, still) = recheck_bundle_peers(
            &[("seat-a".to_owned(), BundleSkip::OptedOut)],
            &*dir,
            Some("device"),
        )
        .await;
        assert!(peers.is_empty());
        assert_eq!(still, vec![("seat-a".to_owned(), BundleSkip::OptedOut)]);
    }

    /// (d) **The bundle-Pull cadence fits the seat's limiter, v44 and v45
    /// alike** (the limiter is unchanged since #936/#937): the one charged
    /// subject (the owner) costs one charge per cycle, a tenth or less of the
    /// daily and hourly ceilings, leaving the rest for the person's own contact
    /// lookups; the self and seat subjects are uncharged. Mutation: set the
    /// interval to the 30 s cadence, and the daily budget is overrun.
    #[test]
    fn the_bundle_pull_cadence_fits_the_seats_lookup_budget_971() {
        use crate::replication::bridge::FederationDirectoryReplicationBridge as B;
        let per_day = 86_400 / BUNDLE_PULL_INTERVAL.as_secs();
        let per_hour = 3_600 / BUNDLE_PULL_INTERVAL.as_secs();
        assert!(
            per_day * 10 <= u64::from(B::IDENTIFIER_LOOKUPS_PER_DAY),
            "{per_day}/day"
        );
        assert!(
            per_hour * 10 <= u64::from(B::IDENTIFIER_LOOKUPS_PER_HOUR),
            "{per_hour}/h"
        );
        assert!(BUNDLE_PULL_MIN_SPACING.as_secs() >= B::IDENTIFIER_LOOKUP_WINDOW_SECS / 2);
    }

    /// (B) **Per-device jitter, retries included.** 256 devices re-linked in
    /// the same instant by a seat restart, each with its own seeded draw (one
    /// process, no mesh): every first-contact retry and the first timer cycle
    /// fall inside half to one and a half of their base, and at each step the
    /// fleet is spread, not in step. Mutation: return either base unjittered,
    /// and that step's spread is zero.
    #[test]
    fn devices_linked_together_spread_their_retries_and_second_cycle_971() {
        use rand::SeedableRng as _;
        let mut devices: Vec<rand::rngs::StdRng> =
            (0..256u64).map(rand::rngs::StdRng::seed_from_u64).collect();
        let mut at: Vec<std::time::Duration> = vec![std::time::Duration::ZERO; devices.len()];
        let steps = (0..BUNDLE_FIRST_CONTACT_TRIES - 1)
            .map(|_| BUNDLE_PULL_MIN_SPACING)
            .chain(std::iter::once(BUNDLE_PULL_INTERVAL));
        for (step, base) in steps.enumerate() {
            let draws: Vec<std::time::Duration> =
                devices.iter_mut().map(|r| jittered(base, r)).collect();
            assert!(
                draws.iter().all(|d| *d >= base / 2 && *d <= base * 3 / 2),
                "step {step}: in [B/2, 3B/2]"
            );
            let min = draws.iter().min().copied().unwrap_or_default();
            let max = draws.iter().max().copied().unwrap_or_default();
            assert!(
                max - min >= base / 2,
                "step {step}: spread {min:?}..{max:?}"
            );
            // No tenth of the window holds more than a quarter of the fleet.
            let bucket = (base / 10).as_millis().max(1);
            let mut counts = std::collections::HashMap::new();
            for d in &draws {
                *counts
                    .entry((*d - base / 2).as_millis() / bucket)
                    .or_insert(0u32) += 1;
            }
            assert!(counts.values().all(|c| *c <= 64), "step {step}: {counts:?}");
            for (t, d) in at.iter_mut().zip(&draws) {
                *t += *d;
            }
        }
        // The instants each device's cycles land at are spread too, not only
        // the gaps.
        let min = at.iter().min().copied().unwrap_or_default();
        let max = at.iter().max().copied().unwrap_or_default();
        assert!(max - min >= BUNDLE_PULL_INTERVAL / 2, "{min:?}..{max:?}");
        // The production draws are the same function.
        let d = bundle_pull_delay();
        assert!(d >= BUNDLE_PULL_INTERVAL / 2 && d <= BUNDLE_PULL_INTERVAL * 3 / 2);
        let d = first_contact_delay();
        assert!(d >= BUNDLE_PULL_MIN_SPACING / 2 && d <= BUNDLE_PULL_MIN_SPACING * 3 / 2);
    }

    /// (e) **The v43.2 leak guard, through `start` itself.** A DEFAULT-config
    /// runtime (the bundle path on) over a bare directory, with the REAL baked
    /// serve ids, rounds with none of them: the directory never ran persist's
    /// Engine seed, so it holds no serve node's record. Mutation: drop the
    /// directory check in `bundle_bootstrap_peers_held`, and this runtime
    /// takes the production canonical as a peer.
    #[tokio::test]
    async fn a_default_runtime_over_a_bare_directory_rounds_with_no_production_seat_971() {
        let baked = crate::edge::baked_canonical_genesis_ids();
        assert!(!baked.is_empty(), "the pinned bundle names a serve node");
        let directory = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = directory;
        let mut rt = ReplicationRuntime::start(
            directory,
            Arc::new(NoopTransport),
            Vec::new(),
            ReplicationRuntimeConfig {
                local_key_id: Some("device-971".to_owned()),
                ..ReplicationRuntimeConfig::default()
            },
            None,
        )
        .await;
        let (peers, skipped) = rt.bundle_peers();
        assert!(peers.is_empty(), "no production seat: {peers:?}");
        let expected = if crate::edge::test_trust_root_override_active() {
            BundleSkip::TestTrustRoot
        } else {
            BundleSkip::NotInDirectory
        };
        assert_eq!(
            skipped
                .iter()
                .map(|(id, why)| (id.clone(), *why))
                .collect::<Vec<_>>(),
            baked
                .iter()
                .map(|id| (id.clone(), expected))
                .collect::<Vec<_>>()
        );
        rt.shutdown().await;
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
    // multi_thread: the shape the real edge runtime always has. (Until
    // CIRISEdge#740 this was REQUIRED — `DirectoryStateAdapter` bridged with
    // `block_in_place`, which panics on a current-thread runtime; the
    // adapter is a plain async forwarder now and the flavor is a choice.)
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn factory_responder_is_driven_and_replies_to_a_round_open() {
        use super::super::protocol::{ReplicationMessage, SummaryMessage};
        use super::super::registry::RouteOutcome;

        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let sent = Arc::new(tokio::sync::Mutex::new(Vec::new()));
        let transport: Arc<dyn Transport> = Arc::new(RecordingTransport {
            sent: Arc::clone(&sent),
        });
        // No Initiator peers — a PURE responder node (the canonical's shape: the
        // agent pulls from it). The ONLY way it serves a round is the #312
        // factory spinning up a Responder AND the #348 drive running it.
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;

        let round_open =
            super::super::wire_frame::wrap(&ReplicationMessage::Summary(SummaryMessage {
                status: None,
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;
        assert!(rt.registry().is_empty().await);
        rt.shutdown().await;
    }

    /// `start` with one Initiator peer registers it + holds the
    /// registry handle the listen loop would use.
    #[tokio::test]
    async fn one_initiator_peer_registered_at_start() {
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let peers = vec![ReplicationPeer {
            peer_key_id: "agent-alice".to_string(),
            kind: EnvelopeKind::Key,
        }];
        let mut rt =
            ReplicationRuntime::start(directory, transport, peers, unit_config(), None).await;
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
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
        let mut rt =
            ReplicationRuntime::start(directory, transport, initial, unit_config(), None).await;
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
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let directory: Arc<dyn FederationDirectory> = backend;
        let transport: Arc<dyn Transport> = Arc::new(NoopTransport);
        let mut rt =
            ReplicationRuntime::start(directory, transport, Vec::new(), unit_config(), None).await;
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
                // Each runtime's first round fires the moment it starts, so
                // alice's start-up round can reach the transport before bob's
                // node has registered (a host under load builds bob slowly).
                // The peer EXISTS in this fixture; wait for it, as a real
                // transport would reach a listener that is still coming up,
                // rather than failing the round with "no such node" — the
                // `{Completed: 2, Error: 1}` this test once reported.
                let mut dest = None;
                for _ in 0..250 {
                    dest = self
                        .registries
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .get(destination_key_id)
                        .cloned();
                    if dest.is_some() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                }
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
            let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
            let directory: Arc<dyn FederationDirectory> = backend;
            let transport: Arc<dyn Transport> = Arc::new(Loopback {
                me: name.to_string(),
                registries: Arc::clone(registries),
                ledger: Arc::clone(ledger),
            });
            let metrics = EdgeMetrics::new();
            let config = ReplicationRuntimeConfig {
                disable_bundle_bootstrap_peers: true,
                scheduler: SchedulerConfig {
                    cadence: std::time::Duration::from_hours(1),
                    round_timeout: std::time::Duration::from_secs(5),
                    ..SchedulerConfig::default()
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
            // Bob comes up after alice's start-up round has already fired
            // toward him: the ordering a loaded host produced at random.
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            // Read before bob exists: his own start-up round can reach alice
            // as soon as he does, and a responder there is the case under test.
            assert!(alice
                .registry()
                .get_responder("bob", EnvelopeKind::Key)
                .await
                .is_none());
            let (mut bob, bob_m) = node("bob", "alice", &registries, &ledger).await;

            // Both sides are initiators toward each other.
            assert!(alice
                .registry()
                .get_initiator("bob", EnvelopeKind::Key)
                .await
                .is_some());
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
