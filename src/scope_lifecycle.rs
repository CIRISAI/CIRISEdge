//! The scope-address lifecycle (CIRISEdge#499).
//!
//! Everything else in the scope-native stack is a mechanism: verify
//! derives the bytes, [`ScopeAddressTable`] holds them, the MLS layer
//! produces the epoch secret, and the transport registers destinations.
//! This module is the thing that *drives* them, and it exists because
//! those mechanisms only compose safely in one order.
//!
//! # The two halves must not drift
//!
//! A scoped address is real only if BOTH are true: edge's table admits
//! it (so an arriving frame attributes to a group), and the leviculum
//! node has it registered (so the frame arrives at all). Two separate
//! call sites keeping those in step by convention is exactly the shape
//! that fails silently — an RNS destination nobody registered is never
//! delivered to, with no error anywhere, and a destination registered
//! with nothing behind it accepts links it cannot attribute.
//!
//! So the lifecycle owns both, and every transition goes through it.
//!
//! # We register our OWN address, never a peer's
//!
//! Each `(scope, group, epoch, member)` has its own address. This node
//! *listens* on exactly one of them per group-epoch — its own — and
//! *dials* the rest. Registering a peer's derived address would put two
//! endpoints under one RNS routing entry, which is unicast-ambiguous;
//! leviculum v0.19 added a `register_destination` displacement warning
//! for precisely that. The distinction is not a convention here: the
//! lifecycle resolves the address to register through its own
//! `own_key_id` and offers no way to name a different member.
//!
//! # Make-before-break
//!
//! MLS epochs advance per-member at slightly different wall-clock
//! moments, so an epoch bump is never a cutover:
//!
//! ```text
//! joined         install + register own address
//! epoch advanced install_next + activate + register the NEW own address
//!                (the superseded one stays registered and accepted)
//! seal due       drop the superseded epoch + retire its destination
//! ```
//!
//! Seal is time-driven rather than event-driven because there is no
//! event that means "every peer has advanced" — the convergence window
//! is a deliberate operator parameter, not something to infer.
//!
//! # Retirement, and what it does and does not cut
//!
//! Sealing removes the superseded epoch from the table AND retires its
//! destination from the node, so a peer that still holds a path and
//! dials the old address finds nobody home. Both halves are needed: the
//! table half stops attribution, the transport half stops the probe.
//!
//! This was the one thing the lifecycle could not do at first —
//! `leviculum-std`'s driver forwarded `register_destination` but not its
//! inverse, so a sealed address stayed routable and an observer who
//! learned it could keep re-confirming this node. Closed by
//! **leviculum#54** in v0.20.0+ciris.1, whose contract edge relies on
//! rather than infers: retirement is **idempotent** (so a timing-driven
//! seal may fire twice) and **leaves established links running** (a link
//! is keyed by `LinkId`, not by the destination it was dialled through).
//!
//! Edge deliberately does not follow retirement with a `close_link`
//! sweep. A peer holding an established link dialled it while
//! legitimately in the group; cutting it would drop a live stream, which
//! is precisely what the make-before-break window exists to prevent. The
//! unlinkability concern is about *new* probes, and retirement is what
//! stops those. Cutting live links remains available and is a separate,
//! deliberate act.
//!
//! [`SealOutcome::unretired`] therefore reports zero in a healthy
//! deployment. It is kept — rather than removed now that the verb
//! exists — because a non-zero value is the alarm for a transport that
//! cannot retire, and silence is a worse way to learn that than a
//! counter.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::cohort_scope::CohortScope;
use crate::scope_addressing::{MemberAddress, ScopeAddressError, ScopeAddressTable};

/// How long a superseded epoch stays reachable after being superseded.
///
/// Not a tuning knob so much as a statement about the slowest peer a
/// deployment is willing to keep: seal earlier and a straggler that has
/// not re-keyed is cut off; seal later and a retired address stays live.
pub const DEFAULT_CONVERGENCE_WINDOW: Duration = Duration::from_secs(300);

/// Where the lifecycle installs and retires listening destinations.
///
/// Implemented by the transport. It is a trait rather than a direct
/// dependency so the lifecycle can be tested without standing up a
/// leviculum node, and so the sealed-but-unretired gap (leviculum#54)
/// is visible at one seam instead of spread through the module.
pub trait ScopedDestinationSink: Send + Sync {
    /// Begin listening on `address` under `scope`, and record the scope
    /// with the announce-suppression policy. Implementations MUST
    /// refuse a `Public` scope for a derived address.
    ///
    /// # Errors
    /// Implementation-defined; any error means the address is NOT live.
    fn register(&self, address: &MemberAddress, scope: &CohortScope) -> Result<(), String>;

    /// Stop listening on `address`. Idempotent.
    ///
    /// # Errors
    /// Returns `Err` when the underlying transport cannot retire a
    /// destination. The lifecycle treats that as loud-but-non-fatal:
    /// there is no alternative action available, and pretending it
    /// succeeded would hide a reachability disclosure. The Reticulum
    /// transport has been able to retire since leviculum#54, so this
    /// arm is an alarm rather than an expected path.
    fn retire(&self, address: &MemberAddress, scope: &CohortScope) -> Result<(), String>;
}

/// What a transition did, so the caller can log or assert on it rather
/// than infer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionOutcome {
    /// Addresses derived and stored for this group-epoch (all members).
    pub derived: usize,
    /// The epoch now live for sending.
    pub epoch: u64,
    /// This node's own address at `epoch` — the one now registered.
    pub own_address: MemberAddress,
}

/// The result of a seal pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SealOutcome {
    /// Groups whose superseded epoch was dropped from the table.
    pub sealed: usize,
    /// Sealed epochs whose destination could NOT be retired from the
    /// transport. **Zero in a healthy deployment** since leviculum#54
    /// (v0.20.0+ciris.1). Non-zero means those addresses remain routable
    /// despite being sealed — a live reachability disclosure, and the
    /// value to alert on.
    pub unretired: usize,
}

/// Why a lifecycle transition failed.
#[derive(Debug, thiserror::Error)]
pub enum ScopeLifecycleError {
    /// The address table refused the transition.
    #[error("scope address table: {0}")]
    Table(#[from] ScopeAddressError),
    /// The table accepted the install but holds no address for THIS
    /// node — meaning `own_key_id` was not in the roster handed in.
    /// Refused rather than skipped: a node that installs a group it is
    /// not a member of would dial peers on addresses it can never be
    /// answered at.
    #[error("this node ({own_key_id}) is not in the roster for group {group_id:?}")]
    SelfNotInRoster {
        /// This node's federation key id.
        own_key_id: String,
        /// The group whose roster omitted it.
        group_id: String,
    },
    /// The transport refused to start listening. The table install is
    /// rolled back, because a group whose own address is not registered
    /// is worse than one that was never installed: it would look live.
    #[error("registering the scoped destination failed: {0}")]
    Register(String),
}

/// Drives scope-address transitions and keeps the table and the
/// transport in step.
pub struct ScopeLifecycle {
    table: std::sync::Arc<ScopeAddressTable>,
    sink: std::sync::Arc<dyn ScopedDestinationSink>,
    own_key_id: String,
    convergence: Duration,
    /// `(scope, group_id) → the instant its superseded epoch may be
    /// sealed`, plus the address to retire when it is.
    pending: Mutex<HashMap<(CohortScope, String), PendingSeal>>,
}

#[derive(Debug, Clone)]
struct PendingSeal {
    due: Instant,
    retiring: MemberAddress,
}

impl ScopeLifecycle {
    /// Build a lifecycle over `table`, installing destinations through
    /// `sink`, for the node identified by `own_key_id`.
    #[must_use]
    pub fn new(
        table: std::sync::Arc<ScopeAddressTable>,
        sink: std::sync::Arc<dyn ScopedDestinationSink>,
        own_key_id: impl Into<String>,
        convergence: Duration,
    ) -> Self {
        Self {
            table,
            sink,
            own_key_id: own_key_id.into(),
            convergence,
            pending: Mutex::new(HashMap::new()),
        }
    }

    /// This node's federation key id — the member whose address is the
    /// one registered.
    #[must_use]
    pub fn own_key_id(&self) -> &str {
        &self.own_key_id
    }

    /// A group became ours: derive every member's address for its
    /// current epoch and start listening on our own.
    ///
    /// # Errors
    /// See [`ScopeLifecycleError`]. On a registration failure the table
    /// install is rolled back so the group is not left half-live.
    pub fn joined(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
        exporter_secret: &[u8; 32],
        members: &[impl AsRef<str>],
    ) -> Result<TransitionOutcome, ScopeLifecycleError> {
        let derived = self
            .table
            .install_group(scope, group_id, epoch, exporter_secret, members)?;
        let own = self.own_address_or_rollback(scope, group_id, epoch)?;
        if let Err(e) = self.sink.register(&own, scope) {
            self.table.remove_group(scope, group_id);
            return Err(ScopeLifecycleError::Register(e));
        }
        Ok(TransitionOutcome {
            derived,
            epoch,
            own_address: own,
        })
    }

    /// The group advanced to a new epoch: derive the new addresses,
    /// make them the ones we send on, and start listening on our new
    /// own address — while the superseded epoch stays live for receive
    /// until [`Self::seal_due`] retires it.
    ///
    /// # Errors
    /// See [`ScopeLifecycleError`].
    pub fn epoch_advanced(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
        exporter_secret: &[u8; 32],
        members: &[impl AsRef<str>],
        now: Instant,
    ) -> Result<TransitionOutcome, ScopeLifecycleError> {
        // Capture the address we are about to supersede BEFORE the
        // rotation moves it — after `activate_next` the table's notion
        // of "current" has already changed, and the outgoing address is
        // the one we will owe a retirement for.
        let outgoing = self.table.live_epochs(scope, group_id).and_then(|live| {
            self.table
                .address_at(scope, group_id, live.current, &self.own_key_id)
        });

        let derived = self
            .table
            .install_next(scope, group_id, epoch, exporter_secret, members)?;
        self.table.activate_next(scope, group_id)?;

        let own = self.own_address_or_rollback(scope, group_id, epoch)?;
        if let Err(e) = self.sink.register(&own, scope) {
            // Do NOT roll the rotation back: the group is still live at
            // the superseded epoch, and unwinding an activate would
            // leave us sending on an epoch peers have already left.
            // Surfacing the failure is the honest move.
            return Err(ScopeLifecycleError::Register(e));
        }

        if let Some(retiring) = outgoing {
            self.pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(
                    (scope.clone(), group_id.to_owned()),
                    PendingSeal {
                        due: now + self.convergence,
                        retiring,
                    },
                );
        }

        Ok(TransitionOutcome {
            derived,
            epoch,
            own_address: own,
        })
    }

    /// Seal every rotation whose convergence window has elapsed.
    ///
    /// Call on a timer. Idempotent, and cheap when nothing is due.
    pub fn seal_due(&self, now: Instant) -> SealOutcome {
        let ready: Vec<((CohortScope, String), PendingSeal)> = {
            let mut pending = self
                .pending
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let keys: Vec<_> = pending
                .iter()
                .filter(|(_, p)| now >= p.due)
                .map(|(k, _)| k.clone())
                .collect();
            keys.into_iter()
                .filter_map(|k| pending.remove(&k).map(|p| (k, p)))
                .collect()
        };

        let mut out = SealOutcome::default();
        for ((scope, group_id), seal) in ready {
            match self.table.seal_rotation(&scope, &group_id) {
                Ok(Some(_) | None) => out.sealed += 1,
                Err(e) => {
                    tracing::warn!(
                        group = %group_id,
                        error = %e,
                        "scope address seal FAILED — the superseded epoch stays live \
                         (CIRISEdge#499)"
                    );
                    continue;
                }
            }
            if let Err(e) = self.sink.retire(&seal.retiring, &scope) {
                out.unretired += 1;
                tracing::warn!(
                    group = %group_id,
                    error = %e,
                    "scope address SEALED but NOT retired from the transport — the node \
                     keeps routing on a rotated-away address, so an observer that learned \
                     it can still confirm this node is reachable (leviculum#54)"
                );
            }
        }
        out
    }

    /// Number of rotations awaiting their convergence window.
    #[must_use]
    pub fn pending_seals(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Resolve THIS node's address at `epoch`, rolling the install back
    /// if the roster did not include us.
    fn own_address_or_rollback(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
    ) -> Result<MemberAddress, ScopeLifecycleError> {
        if let Some(a) = self
            .table
            .address_at(scope, group_id, epoch, &self.own_key_id)
        {
            return Ok(a);
        }
        self.table.remove_group(scope, group_id);
        Err(ScopeLifecycleError::SelfNotInRoster {
            own_key_id: self.own_key_id.clone(),
            group_id: group_id.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope_addressing::StubDeriver;
    use std::sync::Arc;

    /// Records what was registered and retired, and can be made to fail.
    #[derive(Default)]
    struct RecordingSink {
        registered: Mutex<Vec<([u8; 16], CohortScope)>>,
        retired: Mutex<Vec<[u8; 16]>>,
        register_fails: Mutex<bool>,
        /// Models the leviculum#54 gap.
        retire_unsupported: Mutex<bool>,
    }

    impl RecordingSink {
        fn registered_hashes(&self) -> Vec<[u8; 16]> {
            self.registered
                .lock()
                .unwrap()
                .iter()
                .map(|(h, _)| *h)
                .collect()
        }
    }

    impl ScopedDestinationSink for RecordingSink {
        fn register(&self, address: &MemberAddress, scope: &CohortScope) -> Result<(), String> {
            if *self.register_fails.lock().unwrap() {
                return Err("node refused".to_owned());
            }
            self.registered
                .lock()
                .unwrap()
                .push((*address.as_bytes(), scope.clone()));
            Ok(())
        }
        fn retire(&self, address: &MemberAddress, _scope: &CohortScope) -> Result<(), String> {
            if *self.retire_unsupported.lock().unwrap() {
                return Err("leviculum-std exposes no unregister_destination".to_owned());
            }
            self.retired.lock().unwrap().push(*address.as_bytes());
            Ok(())
        }
    }

    fn scope() -> CohortScope {
        CohortScope::Family
    }

    fn fixture() -> (ScopeLifecycle, Arc<ScopeAddressTable>, Arc<RecordingSink>) {
        let table = Arc::new(ScopeAddressTable::new(Arc::new(StubDeriver)));
        let sink = Arc::new(RecordingSink::default());
        let life = ScopeLifecycle::new(
            Arc::clone(&table),
            Arc::clone(&sink) as Arc<dyn ScopedDestinationSink>,
            "node-self",
            Duration::from_secs(300),
        );
        (life, table, sink)
    }

    #[test]
    fn joining_registers_our_own_address_and_only_ours() {
        // The property that keeps RNS unicast unambiguous: three members
        // are derived, exactly ONE destination is registered, and it is
        // this node's.
        let (life, table, sink) = fixture();
        let out = life
            .joined(
                &scope(),
                "g",
                1,
                &[7u8; 32],
                &["node-self", "peer-a", "peer-b"],
            )
            .expect("join");
        assert_eq!(out.derived, 3, "all members are derived (we dial them)");

        let registered = sink.registered_hashes();
        assert_eq!(registered.len(), 1, "we listen on exactly one address");
        assert_eq!(registered[0], *out.own_address.as_bytes());
        assert_eq!(
            registered[0],
            *table
                .send_address(&scope(), "g", "node-self")
                .unwrap()
                .as_bytes(),
            "the registered address is OURS, not a peer's",
        );
        for peer in ["peer-a", "peer-b"] {
            let peer_addr = *table.send_address(&scope(), "g", peer).unwrap().as_bytes();
            assert!(
                !registered.contains(&peer_addr),
                "{peer}'s address must never be registered locally",
            );
        }
    }

    #[test]
    fn a_group_we_are_not_in_is_refused_and_rolled_back() {
        // Installing a group whose roster omits us would leave the node
        // dialing peers on addresses it can never be answered at.
        let (life, table, sink) = fixture();
        let err = life
            .joined(&scope(), "g", 1, &[7u8; 32], &["peer-a", "peer-b"])
            .expect_err("a roster without us must be refused");
        assert!(matches!(err, ScopeLifecycleError::SelfNotInRoster { .. }));
        assert!(
            table.send_address(&scope(), "g", "peer-a").is_none(),
            "the install must be rolled back, not left half-present",
        );
        assert!(sink.registered_hashes().is_empty());
    }

    #[test]
    fn a_failed_registration_rolls_the_join_back() {
        // A group in the table whose own address is not registered is
        // WORSE than one never installed: it looks live.
        let (life, table, sink) = fixture();
        *sink.register_fails.lock().unwrap() = true;
        let err = life
            .joined(&scope(), "g", 1, &[7u8; 32], &["node-self"])
            .expect_err("registration failure must surface");
        assert!(matches!(err, ScopeLifecycleError::Register(_)));
        assert!(
            table.send_address(&scope(), "g", "node-self").is_none(),
            "a group we cannot listen for must not stay installed",
        );
    }

    #[test]
    fn an_advance_registers_the_new_address_before_the_old_is_retired() {
        let (life, table, sink) = fixture();
        let first = life
            .joined(&scope(), "g", 1, &[7u8; 32], &["node-self", "peer-a"])
            .unwrap();
        let t0 = Instant::now();
        let second = life
            .epoch_advanced(&scope(), "g", 2, &[9u8; 32], &["node-self", "peer-a"], t0)
            .unwrap();

        assert_ne!(
            first.own_address.as_bytes(),
            second.own_address.as_bytes(),
            "an epoch bump must move our address",
        );
        // Make-before-break: both registered, nothing retired yet.
        let registered = sink.registered_hashes();
        assert!(registered.contains(first.own_address.as_bytes()));
        assert!(registered.contains(second.own_address.as_bytes()));
        assert!(
            sink.retired.lock().unwrap().is_empty(),
            "nothing is retired before the convergence window elapses",
        );
        // ...and both still answer.
        assert!(table
            .accepts_inbound(first.own_address.as_bytes())
            .is_some());
        assert!(table
            .accepts_inbound(second.own_address.as_bytes())
            .is_some());
        assert_eq!(life.pending_seals(), 1);
    }

    #[test]
    fn seal_waits_for_the_window_then_retires_exactly_the_superseded_address() {
        let (life, table, sink) = fixture();
        let first = life
            .joined(&scope(), "g", 1, &[7u8; 32], &["node-self"])
            .unwrap();
        let t0 = Instant::now();
        let second = life
            .epoch_advanced(&scope(), "g", 2, &[9u8; 32], &["node-self"], t0)
            .unwrap();

        // Too early: sealing now would cut off any peer that has not
        // re-keyed yet.
        let early = life.seal_due(t0 + Duration::from_secs(299));
        assert_eq!(
            early,
            SealOutcome {
                sealed: 0,
                unretired: 0
            }
        );
        assert!(table
            .accepts_inbound(first.own_address.as_bytes())
            .is_some());

        let done = life.seal_due(t0 + Duration::from_secs(300));
        assert_eq!(
            done,
            SealOutcome {
                sealed: 1,
                unretired: 0
            }
        );
        assert_eq!(
            *sink.retired.lock().unwrap(),
            vec![*first.own_address.as_bytes()],
            "exactly the superseded address is retired — never the live one",
        );
        assert!(
            table
                .accepts_inbound(first.own_address.as_bytes())
                .is_none(),
            "a sealed address is no longer ours",
        );
        assert!(
            table
                .accepts_inbound(second.own_address.as_bytes())
                .is_some(),
            "the live address must survive the seal",
        );
        assert_eq!(life.pending_seals(), 0);
        // Idempotent.
        assert_eq!(
            life.seal_due(t0 + Duration::from_secs(600)),
            SealOutcome::default(),
        );
    }

    #[test]
    fn an_unretirable_destination_is_counted_not_swallowed() {
        // leviculum#54: until the driver forwards unregister_destination,
        // a sealed address stays routable. That is a real disclosure, so
        // it must reach the caller as a number rather than a log line
        // nobody reads.
        let (life, table, sink) = fixture();
        *sink.retire_unsupported.lock().unwrap() = true;
        let first = life
            .joined(&scope(), "g", 1, &[7u8; 32], &["node-self"])
            .unwrap();
        let t0 = Instant::now();
        life.epoch_advanced(&scope(), "g", 2, &[9u8; 32], &["node-self"], t0)
            .unwrap();

        let out = life.seal_due(t0 + Duration::from_secs(300));
        assert_eq!(
            out,
            SealOutcome {
                sealed: 1,
                unretired: 1
            },
            "a seal whose retirement failed must report BOTH, so the residual \
             reachability is visible rather than implied by silence",
        );
        // Edge's own admission is still closed even though RNS is not.
        assert!(table
            .accepts_inbound(first.own_address.as_bytes())
            .is_none());
    }

    #[test]
    fn scopes_are_tracked_independently() {
        // The lifecycle must not confuse two groups that share a group
        // id across different scopes — the table keys on (scope, group).
        let (life, _table, _sink) = fixture();
        let family = CohortScope::Family;
        let cohort = CohortScope::Cohort {
            cohort_id: "c-1".to_owned(),
        };
        // Real MLS groups never share an exporter secret, so the two
        // secrets differ — that is what makes the addresses differ.
        let a = life
            .joined(&family, "shared", 1, &[7u8; 32], &["node-self"])
            .unwrap();
        let b = life
            .joined(&cohort, "shared", 1, &[8u8; 32], &["node-self"])
            .unwrap();
        assert_ne!(
            a.own_address.as_bytes(),
            b.own_address.as_bytes(),
            "same group id in two scopes must not collide",
        );

        let t0 = Instant::now();
        life.epoch_advanced(&family, "shared", 2, &[9u8; 32], &["node-self"], t0)
            .unwrap();
        assert_eq!(life.pending_seals(), 1, "only the family group rotated");
    }

    #[test]
    fn reusing_one_exporter_secret_across_groups_is_refused() {
        // The derivation binds (secret, member) only — deliberately, since
        // an MLS exporter ALREADY binds (group, epoch), so re-parameterising
        // by group would be inventing a convention the KDF already provides.
        //
        // The consequence is that handing two groups the same secret is a
        // key-reuse error, not merely an addressing one, and it surfaces
        // here as a collision rather than as two groups silently sharing one
        // RNS routing entry. Found by writing this test wrong: it originally
        // passed `[7u8; 32]` to both groups and the table refused it.
        let (life, _table, _sink) = fixture();
        life.joined(&CohortScope::Family, "g-one", 1, &[7u8; 32], &["node-self"])
            .expect("first install");
        let err = life
            .joined(
                &CohortScope::Cohort {
                    cohort_id: "c-1".to_owned(),
                },
                "g-two",
                1,
                &[7u8; 32],
                &["node-self"],
            )
            .expect_err("reusing an exporter secret must be refused");
        assert!(
            matches!(
                err,
                ScopeLifecycleError::Table(ScopeAddressError::AddressCollision { .. })
            ),
            "expected an AddressCollision, got {err:?}",
        );
    }
}
