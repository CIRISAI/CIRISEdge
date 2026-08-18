//! Scope-native derived-address table (CIRISEdge#499, workstream B).
//!
//! # Why this module exists
//!
//! Scope-native addressing gives every member of every scoped group its
//! own Reticulum destination, derived from the group's MLS
//! `exporter_secret`. Two facts make a table — rather than an on-demand
//! derivation — the only defensible shape:
//!
//! 1. **Derivation is a KDF, the packet path is not a KDF budget.**
//!    Deriving on every send (or, worse, on every inbound packet, to
//!    test "is this mine?") puts an HKDF/HMAC per packet on the
//!    transport hot path. The address set only changes on membership
//!    change or epoch bump — both cold paths. Derive there, once; the
//!    hot path is then a single hash-map read.
//! 2. **An epoch bump must never silently deafen a group.** MLS epochs
//!    advance per-member at slightly different wall-clock moments. If
//!    the receive side accepted only the epoch it is currently *sending*
//!    on, every rotation would open a window where a peer that advanced
//!    first (or last) is talking to an address nobody is listening on —
//!    and the failure is silent, because in RNS an unregistered
//!    destination hash is simply not delivered. There is no error to
//!    log. The three-phase rotation below (mirroring the IFAC rotation
//!    edge already ships, CIRISEdge#492) makes the accept-set a
//!    superset of the send-set for the whole convergence window.
//!
//! # Per-member, never per-group
//!
//! Each `(scope, group, epoch, member)` tuple gets its OWN 16-byte
//! address. A single shared per-group hash is tempting (one
//! registration, one announce) and wrong twice over:
//!
//! - It is unicast-ambiguous in RNS: a destination hash names ONE
//!   endpoint. Two members registering the same hash are two endpoints
//!   claiming one address, and delivery becomes whichever one the path
//!   table learned last.
//! - Leviculum makes that concrete. `NodeCore::register_destination`
//!   (leviculum v0.19.0+ciris.1, `leviculum-core/src/node/mod.rs`) is
//!   last-wins on hash collision and logs
//!   `"register_destination replaces a different destination under
//!   <hash> (explicit-hash collision or misuse; last registration
//!   wins)"`. A shared group hash would trip that warning by
//!   construction on every member registration.
//!
//! So the API has no way to *say* "the group's address": every address
//! this table stores, returns, or reverse-resolves names a member. The
//! forward lookup requires a `member_key_id`; the reverse lookup yields
//! one ([`InboundAddress::member_key_id`]). And [`MemberAddress`] has no
//! public constructor — the only way to obtain one is from a derivation
//! this table performed against a member key id.
//!
//! # The derivation seam
//!
//! [`DestinationDeriver`] is deliberately the only crypto in this file,
//! and it is a trait, not an implementation. The real derivation is
//! **CIRISVerify#259** (`k_destination` + `derive_destination`,
//! §2.2/§2.4-shaped, alongside the `k_record_id` / `k_symbol` /
//! `derive_record_id` family this crate already re-exports from
//! `crate::scope_privacy`). Verify is the first conformant impl per FSD
//! §9; edge reproduces its bytes, it does not invent them.
//!
//! **A destination hash is a cross-impl wire fact.** Two members of one
//! group find each other only if both compute the same 16 bytes.
//! Shipping edge-local "good enough" bytes would give that wire fact two
//! owners, and the divergence is invisible until a real group silently
//! fails to converge in the field. So the only [`DestinationDeriver`]
//! impl in this crate is [`StubDeriver`], and it is `#[cfg(test)]` —
//! not feature-gated, `#[cfg(test)]`. There is no build flag that puts
//! it in a wheel; a release build that wanted it would not compile.
//! [`ScopeAddressTable::new`] takes the deriver as a parameter for
//! exactly that reason: production must supply verify's.
//!
//! # Locking
//!
//! One `parking_lot::RwLock` over the whole table. Every method here is
//! **synchronous** — no `async fn`, no `.await` anywhere in this module
//! — so a guard cannot be held across a suspension point even by
//! accident. That is not a stylistic preference: holding a lock across
//! an `.await` on a transport path is what produced the real hangs in
//! CIRISEdge#217. Structural impossibility beats a review checklist.
//!
//! The table also never retains an `exporter_secret`. Secrets are
//! borrowed for the duration of an install call and dropped; what
//! persists is only the 16-byte public addresses derived from them.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;

use crate::cohort_scope::CohortScope;

// ─── The derivation seam (CIRISVerify#259) ──────────────────────────

/// Derives a member's 16-byte Reticulum destination hash from the
/// group's MLS `exporter_secret`.
///
/// The signature carries no scope / group / epoch on purpose: an MLS
/// `exporter_secret` is ALREADY per-`(group, epoch)`. That is what makes
/// "two different groups yield unrelated addresses" and "an epoch bump
/// re-addresses the whole group" fall out of the KDF rather than out of
/// a convention this crate would have to police. It also means a caller
/// that reuses a secret across epochs is committing a key-reuse error,
/// not merely an addressing one — [`ScopeAddressTable`] catches that at
/// install time (see [`ScopeAddressError::AddressCollision`]).
///
/// The production impl is CIRISVerify#259's `k_destination` +
/// `derive_destination` pair. Edge holds the trait, verify holds the
/// bytes. See the module docs for why edge must not hold both.
pub trait DestinationDeriver: Send + Sync {
    /// Derive `member_key_id`'s destination hash under this group-epoch
    /// secret. MUST be deterministic: the same inputs must produce the
    /// same 16 bytes on every node and every impl, forever.
    fn derive(&self, exporter_secret: &[u8; 32], member_key_id: &str) -> [u8; 16];
}

// ─── Value types ────────────────────────────────────────────────────

/// A member's derived Reticulum destination hash.
///
/// Newtype rather than a bare `[u8; 16]` so the type system carries the
/// per-member provenance: the only way to obtain one is from a
/// [`ScopeAddressTable`] derivation keyed by a `member_key_id`. There is
/// no constructor that takes 16 bytes, which is what makes "the group's
/// shared address" unrepresentable rather than merely discouraged.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct MemberAddress([u8; 16]);

impl MemberAddress {
    /// The 16 wire bytes, for handing to a Reticulum `Destination`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    /// The 16 wire bytes by value.
    #[must_use]
    pub fn into_bytes(self) -> [u8; 16] {
        self.0
    }
}

/// The identity of a scoped group: its cohort scope plus its opaque
/// group id. Edge does not interpret `group_id` — it is the MLS group's
/// identifier as the scope-privacy layer names it.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ScopeGroup {
    scope: CohortScope,
    group_id: String,
}

impl ScopeGroup {
    /// The cohort scope this group lives in.
    #[must_use]
    pub fn scope(&self) -> &CohortScope {
        &self.scope
    }

    /// The opaque group identifier.
    #[must_use]
    pub fn group_id(&self) -> &str {
        &self.group_id
    }
}

/// Which rotation slot an epoch currently occupies.
///
/// The send path uses [`EpochRole::Current`] only; the receive path
/// accepts all three. That asymmetry IS the make-before-break property.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EpochRole {
    /// Installed and accepted for receive, but not yet the send epoch.
    /// A peer that advanced before us lands here.
    Next,
    /// The primary epoch: what we send on.
    Current,
    /// Superseded but still accepted for receive. A straggler that has
    /// not yet advanced lands here, and we still address it here.
    /// Dropped by [`ScopeAddressTable::seal_rotation`].
    Previous,
}

/// A resolved inbound address: the answer to "is this destination hash
/// mine, and if so whose?"
///
/// Cloning this out of the table costs three refcount bumps and two
/// `Copy` field moves — no heap allocation on the packet path. That is
/// why the group identity is behind an `Arc` shared with the forward
/// index rather than owned per-entry.
#[derive(Clone, Debug)]
pub struct InboundAddress {
    group: Arc<ScopeGroup>,
    member_key_id: Arc<str>,
    epoch: u64,
    role: EpochRole,
}

impl InboundAddress {
    /// The scoped group this address belongs to.
    #[must_use]
    pub fn group(&self) -> &ScopeGroup {
        &self.group
    }

    /// The member whose address this is. Never absent: an address in
    /// this table always names exactly one member.
    #[must_use]
    pub fn member_key_id(&self) -> &str {
        &self.member_key_id
    }

    /// The group epoch this address was derived under.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Whether this epoch is the send epoch, an installed-but-not-yet
    /// primary epoch, or a still-accepted superseded one.
    #[must_use]
    pub fn role(&self) -> EpochRole {
        self.role
    }
}

/// Snapshot of a group's three-phase rotation state. Operator /
/// telemetry surface — `Copy`, no allocation.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct LiveEpochs {
    /// Superseded epoch still accepted for receive, if a rotation is
    /// past [`ScopeAddressTable::activate_next`] but not yet sealed.
    pub previous: Option<u64>,
    /// The epoch we send on.
    pub current: u64,
    /// Installed-but-not-yet-primary epoch, if a rotation is past
    /// [`ScopeAddressTable::install_next`] but not yet activated.
    pub next: Option<u64>,
}

/// What [`ScopeAddressTable::activate_next`] did.
///
/// `evicted` is `Some` when a previous rotation was never sealed and
/// activating shifted its epoch out of the accept window. That is a
/// real (if rare) loss of receive coverage, so it is reported rather
/// than performed silently — the caller should be logging it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EpochTransition {
    /// The epoch we were sending on before this call.
    pub from: u64,
    /// The epoch we send on now.
    pub to: u64,
    /// An unsealed older epoch that this activation dropped, if any.
    pub evicted: Option<u64>,
}

/// Errors from the install / rotation surface. All are programming or
/// sequencing errors on a cold path — nothing here is a packet-path
/// outcome.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ScopeAddressError {
    /// No addresses installed for this `(scope, group_id)`.
    #[error("scope_addressing: unknown group '{group_id}' in scope '{scope_kind}'")]
    UnknownGroup {
        /// [`CohortScope::kind_token`] of the requested scope.
        scope_kind: &'static str,
        /// The requested group id.
        group_id: String,
    },
    /// [`ScopeAddressTable::install_group`] on a group that already has
    /// state. Re-seeding would drop the live accept window; rotate with
    /// [`ScopeAddressTable::install_next`] instead, or
    /// [`ScopeAddressTable::remove_group`] first.
    #[error("scope_addressing: group '{group_id}' already installed at epoch {epoch}")]
    GroupAlreadyInstalled {
        /// The group id that already has state.
        group_id: String,
        /// The epoch currently primary for that group.
        epoch: u64,
    },
    /// [`ScopeAddressTable::install_next`] while an installed-but-not-
    /// activated epoch is already pending. Refused rather than
    /// overwritten: the pending epoch may already be receiving traffic
    /// from peers that advanced first, and silently dropping its
    /// addresses is precisely the deafness this module exists to
    /// prevent. Activate (or seal) first.
    #[error("scope_addressing: rotation already in progress, epoch {pending} pending activation")]
    RotationInProgress {
        /// The pending epoch that must be activated or removed first.
        pending: u64,
    },
    /// The requested epoch is not strictly greater than the current
    /// one. Epochs are monotonic; installing backwards would make
    /// "previous" and "next" meaningless.
    #[error("scope_addressing: epoch {requested} does not advance current epoch {current}")]
    EpochNotAdvancing {
        /// The group's current (primary) epoch.
        current: u64,
        /// The epoch the caller asked to install.
        requested: u64,
    },
    /// [`ScopeAddressTable::activate_next`] with nothing installed.
    #[error("scope_addressing: no pending epoch to activate")]
    NoPendingEpoch,
    /// An install with an empty member list. An epoch with no addresses
    /// is a group nobody can reach — refused loudly rather than
    /// installed as a silent black hole.
    #[error("scope_addressing: refusing to install epoch {epoch} with no members")]
    EmptyMembership {
        /// The epoch the caller asked to install.
        epoch: u64,
    },
    /// The same member key id appeared twice in one install. Ambiguous
    /// intent — the caller's membership set is malformed.
    #[error("scope_addressing: member '{member_key_id}' listed twice in one install")]
    DuplicateMember {
        /// The repeated member key id.
        member_key_id: String,
    },
    /// Two distinct members derived to the same 16 bytes.
    ///
    /// With a sound deriver and distinct inputs this is a
    /// ~2^-64 accident. In practice it fires for the one realistic
    /// misuse: installing a new epoch with a REUSED `exporter_secret`,
    /// which re-derives the existing epoch's addresses byte-for-byte.
    /// Catching it here turns a key-reuse bug into a loud install-time
    /// error instead of a leviculum `register_destination` displacement
    /// warning and a half-deaf group.
    #[error("scope_addressing: address collision on member '{member_key_id}' (epoch {epoch}) — reused exporter_secret?")]
    AddressCollision {
        /// The member whose derived address collided.
        member_key_id: String,
        /// The epoch being installed when the collision was found.
        epoch: u64,
    },
}

// ─── Internal state ─────────────────────────────────────────────────

/// One epoch's worth of member addresses.
struct EpochSlot {
    epoch: u64,
    /// `member_key_id -> address`. `Arc<str>` keys so the reverse index
    /// shares the same allocation; `Arc<str>: Borrow<str>` keeps lookup
    /// by `&str` allocation-free.
    members: HashMap<Arc<str>, MemberAddress>,
}

/// A group's three rotation slots.
struct GroupEpochs {
    group: Arc<ScopeGroup>,
    current: EpochSlot,
    next: Option<EpochSlot>,
    previous: Option<EpochSlot>,
}

impl GroupEpochs {
    /// The slot holding `epoch`, whichever phase it is in.
    fn slot_at(&self, epoch: u64) -> Option<&EpochSlot> {
        [
            Some(&self.current),
            self.next.as_ref(),
            self.previous.as_ref(),
        ]
        .into_iter()
        .flatten()
        .find(|slot| slot.epoch == epoch)
    }

    /// Every live slot, in no particular order.
    fn slots_mut(&mut self) -> impl Iterator<Item = &mut EpochSlot> {
        [
            Some(&mut self.current),
            self.next.as_mut(),
            self.previous.as_mut(),
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(Default)]
struct Inner {
    /// Forward index (SEND path): scope -> group_id -> epochs.
    /// Two-level so both levels can be probed with borrowed keys —
    /// a flat `(CohortScope, String, u64)` key would force a `String`
    /// allocation on every lookup.
    groups: HashMap<CohortScope, HashMap<String, GroupEpochs>>,
    /// Reverse index (RECEIVE path): destination hash -> who/which
    /// epoch. Covers every live slot, which is what makes the accept
    /// set a superset of the send set.
    reverse: HashMap<[u8; 16], InboundAddress>,
}

// ─── The table ──────────────────────────────────────────────────────

/// `(scope, group_id, epoch, member)` → 16-byte Reticulum destination
/// hash, with three-phase epoch rotation.
///
/// See the module docs for the design rationale (CIRISEdge#499). The
/// short version: derive on membership/epoch change, never on a packet;
/// accept a superset of what you send so an epoch bump cannot deafen a
/// group; one address per member, never per group.
pub struct ScopeAddressTable {
    deriver: Arc<dyn DestinationDeriver>,
    inner: RwLock<Inner>,
}

impl ScopeAddressTable {
    /// Construct an empty table over `deriver`.
    ///
    /// There is no `Default` / no-argument constructor on purpose: the
    /// deriver is the cross-impl wire authority (CIRISVerify#259), so
    /// every call site has to name the one it is trusting. The only
    /// impl in this crate is `#[cfg(test)]`.
    #[must_use]
    pub fn new(deriver: Arc<dyn DestinationDeriver>) -> Self {
        Self {
            deriver,
            inner: RwLock::new(Inner::default()),
        }
    }

    // ── Cold path: install + rotate ──────────────────────────────────

    /// Seed a group's first epoch. Derives one address per member and
    /// makes `epoch` immediately primary (there is nothing to make
    /// before breaking).
    ///
    /// Returns the number of addresses installed.
    pub fn install_group(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
        exporter_secret: &[u8; 32],
        members: &[impl AsRef<str>],
    ) -> Result<usize, ScopeAddressError> {
        let mut guard = self.inner.write();
        let inner = &mut *guard;

        if let Some(existing) = lookup_group(&inner.groups, scope, group_id) {
            return Err(ScopeAddressError::GroupAlreadyInstalled {
                group_id: group_id.to_owned(),
                epoch: existing.current.epoch,
            });
        }

        let group = Arc::new(ScopeGroup {
            scope: scope.clone(),
            group_id: group_id.to_owned(),
        });
        let slot = self.build_slot(&inner.reverse, epoch, exporter_secret, members)?;
        let count = slot.members.len();

        commit_slot(&mut inner.reverse, &group, &slot, EpochRole::Current);
        inner.groups.entry(scope.clone()).or_default().insert(
            group_id.to_owned(),
            GroupEpochs {
                group,
                current: slot,
                next: None,
                previous: None,
            },
        );

        Ok(count)
    }

    /// Phase 1 — derive and register the NEXT epoch's addresses while
    /// the current epoch stays primary (make-before-break, mirroring
    /// `ReticulumTransport::ifac_install_next`, CIRISEdge#492).
    ///
    /// After this call the group ACCEPTS both epochs and SENDS on the
    /// old one. A peer that bumped its MLS epoch before us and is
    /// already addressing our new-epoch destination therefore lands
    /// from the first instant the new epoch exists anywhere.
    ///
    /// Returns the number of addresses installed.
    pub fn install_next(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
        exporter_secret: &[u8; 32],
        members: &[impl AsRef<str>],
    ) -> Result<usize, ScopeAddressError> {
        let mut guard = self.inner.write();
        // Disjoint field borrows: the group state is mutated while the
        // reverse index is read (validation) and then written (commit),
        // so the whole install is one uninterruptible critical section
        // with no window where the two indexes disagree.
        let Inner { groups, reverse } = &mut *guard;

        let group_state = lookup_group_mut(groups, scope, group_id)
            .ok_or_else(|| unknown_group(scope, group_id))?;

        if let Some(pending) = group_state.next.as_ref().map(|s| s.epoch) {
            return Err(ScopeAddressError::RotationInProgress { pending });
        }
        if epoch <= group_state.current.epoch {
            return Err(ScopeAddressError::EpochNotAdvancing {
                current: group_state.current.epoch,
                requested: epoch,
            });
        }

        let slot = self.build_slot(reverse, epoch, exporter_secret, members)?;
        let count = slot.members.len();

        commit_slot(reverse, &group_state.group, &slot, EpochRole::Next);
        group_state.next = Some(slot);

        Ok(count)
    }

    /// Phase 2 — the installed epoch becomes primary for SENDING; the
    /// epoch it supersedes stays accepted for RECEIVE (mirroring
    /// `ifac_activate_next`, CIRISEdge#492).
    ///
    /// A straggler that has not yet advanced keeps landing, and we keep
    /// addressing it on the old epoch via [`Self::address_at`] — it is
    /// excluded only at [`Self::seal_rotation`].
    pub fn activate_next(
        &self,
        scope: &CohortScope,
        group_id: &str,
    ) -> Result<EpochTransition, ScopeAddressError> {
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let reverse = &mut inner.reverse;

        let group_state = lookup_group_mut(&mut inner.groups, scope, group_id)
            .ok_or_else(|| unknown_group(scope, group_id))?;

        let next = group_state
            .next
            .take()
            .ok_or(ScopeAddressError::NoPendingEpoch)?;

        // An unsealed older epoch shifts out of the accept window here.
        // Reported in the outcome, never silent.
        let evicted = group_state.previous.take().map(|stale| {
            retract_slot(reverse, &stale);
            stale.epoch
        });

        let from = group_state.current.epoch;
        let to = next.epoch;
        let superseded = std::mem::replace(&mut group_state.current, next);

        set_role(reverse, &superseded, EpochRole::Previous);
        set_role(reverse, &group_state.current, EpochRole::Current);
        group_state.previous = Some(superseded);

        Ok(EpochTransition { from, to, evicted })
    }

    /// Phase 3 — SEAL: drop the superseded epoch (mirroring
    /// `ifac_seal_rotation`, CIRISEdge#492). Any member that never
    /// re-keyed is now unreachable and can no longer reach us;
    /// readmission means a fresh install at the live epoch.
    ///
    /// Call only after the convergence window. Idempotent: `Ok(None)`
    /// when there is nothing to seal.
    pub fn seal_rotation(
        &self,
        scope: &CohortScope,
        group_id: &str,
    ) -> Result<Option<u64>, ScopeAddressError> {
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let reverse = &mut inner.reverse;

        let group_state = lookup_group_mut(&mut inner.groups, scope, group_id)
            .ok_or_else(|| unknown_group(scope, group_id))?;

        Ok(group_state.previous.take().map(|sealed| {
            retract_slot(reverse, &sealed);
            sealed.epoch
        }))
    }

    /// Forget a group entirely — every epoch, every member, both
    /// indexes. Returns the number of addresses removed.
    pub fn remove_group(&self, scope: &CohortScope, group_id: &str) -> usize {
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let reverse = &mut inner.reverse;

        let Some(by_group) = inner.groups.get_mut(scope) else {
            return 0;
        };
        let Some(mut group_state) = by_group.remove(group_id) else {
            return 0;
        };
        if by_group.is_empty() {
            inner.groups.remove(scope);
        }

        let mut removed = 0;
        for slot in group_state.slots_mut() {
            removed += slot.members.len();
            retract_slot(reverse, slot);
        }
        removed
    }

    /// Drop one member's addresses across every live epoch of a group
    /// (a member leaving mid-rotation). Returns the number of addresses
    /// removed — up to one per live epoch.
    pub fn remove_member(&self, scope: &CohortScope, group_id: &str, member_key_id: &str) -> usize {
        let mut guard = self.inner.write();
        let inner = &mut *guard;
        let reverse = &mut inner.reverse;

        let Some(group_state) = lookup_group_mut(&mut inner.groups, scope, group_id) else {
            return 0;
        };

        let mut removed = 0;
        for slot in group_state.slots_mut() {
            if let Some(addr) = slot.members.remove(member_key_id) {
                reverse.remove(&addr.0);
                removed += 1;
            }
        }
        removed
    }

    // ── Hot path: lookup ─────────────────────────────────────────────

    /// SEND path: the address to send to `member_key_id` on right now —
    /// the group's primary (current) epoch.
    ///
    /// One hash-map probe per level, borrowed keys throughout, no
    /// allocation and no derivation. The deriver is NEVER called here.
    #[must_use]
    pub fn send_address(
        &self,
        scope: &CohortScope,
        group_id: &str,
        member_key_id: &str,
    ) -> Option<MemberAddress> {
        let guard = self.inner.read();
        let group_state = lookup_group(&guard.groups, scope, group_id)?;
        group_state.current.members.get(member_key_id).copied()
    }

    /// SEND path, explicit epoch: the address a member holds at `epoch`,
    /// whichever rotation slot that epoch occupies.
    ///
    /// This is the straggler case. Once we have activated a new epoch, a
    /// peer still on the old one is addressed here — and keeps being
    /// addressable until [`Self::seal_rotation`] drops that epoch, at
    /// which point this returns `None` and the exclusion is explicit.
    #[must_use]
    pub fn address_at(
        &self,
        scope: &CohortScope,
        group_id: &str,
        epoch: u64,
        member_key_id: &str,
    ) -> Option<MemberAddress> {
        let guard = self.inner.read();
        let group_state = lookup_group(&guard.groups, scope, group_id)?;
        group_state
            .slot_at(epoch)?
            .members
            .get(member_key_id)
            .copied()
    }

    /// RECEIVE path: is this inbound destination hash one of ours, and
    /// if so whose and at which epoch?
    ///
    /// Accepts EVERY live epoch — next, current and previous — which is
    /// the whole point: the accept set is a superset of the send set for
    /// the duration of a rotation. One hash-map probe; the returned
    /// clone is refcount bumps only, no allocation, no derivation.
    #[must_use]
    pub fn accepts_inbound(&self, dest_hash: &[u8; 16]) -> Option<InboundAddress> {
        self.inner.read().reverse.get(dest_hash).cloned()
    }

    // ── Introspection ────────────────────────────────────────────────

    /// The group's three-phase rotation state, or `None` if the group
    /// has no addresses installed.
    #[must_use]
    pub fn live_epochs(&self, scope: &CohortScope, group_id: &str) -> Option<LiveEpochs> {
        let guard = self.inner.read();
        let group_state = lookup_group(&guard.groups, scope, group_id)?;
        Some(LiveEpochs {
            previous: group_state.previous.as_ref().map(|s| s.epoch),
            current: group_state.current.epoch,
            next: group_state.next.as_ref().map(|s| s.epoch),
        })
    }

    /// Total number of live addresses across every group and epoch —
    /// i.e. the size of the receive accept set.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.read().reverse.len()
    }

    /// `true` iff no addresses are installed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.read().reverse.is_empty()
    }

    // ── Internals ────────────────────────────────────────────────────

    /// Derive a whole epoch's addresses and validate them BEFORE any
    /// mutation, so a rejected install leaves the table exactly as it
    /// was. A half-installed epoch would be a group that is reachable
    /// for some members and deaf for others — the worst of the failure
    /// modes this module exists to prevent.
    fn build_slot(
        &self,
        reverse: &HashMap<[u8; 16], InboundAddress>,
        epoch: u64,
        exporter_secret: &[u8; 32],
        members: &[impl AsRef<str>],
    ) -> Result<EpochSlot, ScopeAddressError> {
        if members.is_empty() {
            return Err(ScopeAddressError::EmptyMembership { epoch });
        }

        let mut slot = EpochSlot {
            epoch,
            members: HashMap::with_capacity(members.len()),
        };
        let mut seen: HashSet<[u8; 16]> = HashSet::with_capacity(members.len());

        for member in members {
            let member_key_id = member.as_ref();
            if slot.members.contains_key(member_key_id) {
                return Err(ScopeAddressError::DuplicateMember {
                    member_key_id: member_key_id.to_owned(),
                });
            }

            let raw = self.deriver.derive(exporter_secret, member_key_id);
            // Collision against this batch OR against any address
            // already live in the table. Either way two endpoints would
            // claim one RNS destination hash.
            if !seen.insert(raw) || reverse.contains_key(&raw) {
                return Err(ScopeAddressError::AddressCollision {
                    member_key_id: member_key_id.to_owned(),
                    epoch,
                });
            }

            slot.members
                .insert(Arc::from(member_key_id), MemberAddress(raw));
        }

        Ok(slot)
    }
}

// ─── Free helpers (borrow-splitting friendly) ───────────────────────

fn unknown_group(scope: &CohortScope, group_id: &str) -> ScopeAddressError {
    ScopeAddressError::UnknownGroup {
        scope_kind: scope.kind_token(),
        group_id: group_id.to_owned(),
    }
}

fn lookup_group<'a>(
    groups: &'a HashMap<CohortScope, HashMap<String, GroupEpochs>>,
    scope: &CohortScope,
    group_id: &str,
) -> Option<&'a GroupEpochs> {
    groups.get(scope)?.get(group_id)
}

fn lookup_group_mut<'a>(
    groups: &'a mut HashMap<CohortScope, HashMap<String, GroupEpochs>>,
    scope: &CohortScope,
    group_id: &str,
) -> Option<&'a mut GroupEpochs> {
    groups.get_mut(scope)?.get_mut(group_id)
}

/// Publish a slot's addresses into the receive accept set.
fn commit_slot(
    reverse: &mut HashMap<[u8; 16], InboundAddress>,
    group: &Arc<ScopeGroup>,
    slot: &EpochSlot,
    role: EpochRole,
) {
    for (member_key_id, addr) in &slot.members {
        reverse.insert(
            addr.0,
            InboundAddress {
                group: Arc::clone(group),
                member_key_id: Arc::clone(member_key_id),
                epoch: slot.epoch,
                role,
            },
        );
    }
}

/// Withdraw a slot's addresses from the receive accept set.
fn retract_slot(reverse: &mut HashMap<[u8; 16], InboundAddress>, slot: &EpochSlot) {
    for addr in slot.members.values() {
        reverse.remove(&addr.0);
    }
}

/// Re-label a slot's accept-set entries after a phase transition. The
/// role lives on the reverse entry (rather than being recomputed per
/// packet) so the receive path stays one probe; relabelling is a cold
/// path touching only one group's members.
fn set_role(reverse: &mut HashMap<[u8; 16], InboundAddress>, slot: &EpochSlot, role: EpochRole) {
    for addr in slot.members.values() {
        if let Some(entry) = reverse.get_mut(&addr.0) {
            entry.role = role;
        }
    }
}

// ─── Test-only deriver ──────────────────────────────────────────────

/// **TEST ONLY.** A non-cryptographic stand-in for CIRISVerify#259's
/// `k_destination` + `derive_destination`.
///
/// `#[cfg(test)]`, deliberately NOT a Cargo feature: a feature can be
/// switched on by accident (feature unification pulls flags in from
/// dependents — see the `test-anchor` note in `Cargo.toml` for how
/// carefully that has to be reasoned about). `#[cfg(test)]` cannot
/// appear in a wheel at all.
///
/// A destination hash is a **cross-impl wire fact**: two members of one
/// group find each other only if every implementation computes the same
/// 16 bytes. Shipping these bytes would hand that fact a second owner,
/// and the divergence would be invisible — an RNS destination nobody
/// registered is simply never delivered to, with no error anywhere.
/// This mixer is an FNV variant with no security properties whatsoever;
/// it exists only so the table's structure can be tested without
/// blocking on verify.
#[cfg(test)]
pub struct StubDeriver;

#[cfg(test)]
impl DestinationDeriver for StubDeriver {
    fn derive(&self, exporter_secret: &[u8; 32], member_key_id: &str) -> [u8; 16] {
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        fn mix(seed: u64, bytes: &[u8]) -> u64 {
            let mut h = seed;
            for b in bytes {
                h ^= u64::from(*b);
                h = h.wrapping_mul(PRIME);
            }
            h
        }

        // Two independently-seeded passes in opposite input order, so
        // both halves depend on both inputs.
        let lo = mix(
            mix(0xcbf2_9ce4_8422_2325, exporter_secret),
            member_key_id.as_bytes(),
        );
        let hi = mix(
            mix(0x9e37_79b9_7f4a_7c15, member_key_id.as_bytes()),
            exporter_secret,
        );

        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&lo.to_be_bytes());
        out[8..].copy_from_slice(&hi.to_be_bytes());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Wraps [`StubDeriver`] and counts calls, so tests can assert the
    /// load-bearing property directly: lookups never derive.
    struct CountingDeriver {
        calls: AtomicUsize,
    }

    impl CountingDeriver {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                calls: AtomicUsize::new(0),
            })
        }

        fn count(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl DestinationDeriver for CountingDeriver {
        fn derive(&self, exporter_secret: &[u8; 32], member_key_id: &str) -> [u8; 16] {
            self.calls.fetch_add(1, Ordering::SeqCst);
            StubDeriver.derive(exporter_secret, member_key_id)
        }
    }

    fn table() -> ScopeAddressTable {
        ScopeAddressTable::new(Arc::new(StubDeriver))
    }

    fn family() -> CohortScope {
        CohortScope::Family
    }

    fn secret(tag: u8) -> [u8; 32] {
        [tag; 32]
    }

    const MEMBERS: [&str; 3] = ["ed25519:alice", "ed25519:bob", "ed25519:carol"];

    /// Seed a group at epoch 7 with the three canonical members.
    fn seeded() -> ScopeAddressTable {
        let t = table();
        t.install_group(&family(), "g-1", 7, &secret(0xA1), &MEMBERS)
            .expect("seed install");
        t
    }

    // ── lookup purity ────────────────────────────────────────────────

    #[test]
    fn lookup_never_calls_the_deriver() {
        let deriver = CountingDeriver::new();
        let t = ScopeAddressTable::new(Arc::clone(&deriver) as Arc<dyn DestinationDeriver>);
        t.install_group(&family(), "g-1", 7, &secret(0xA1), &MEMBERS)
            .expect("install");

        let after_install = deriver.count();
        assert_eq!(after_install, MEMBERS.len(), "one derivation per member");

        for _ in 0..64 {
            let addr = t
                .send_address(&family(), "g-1", "ed25519:bob")
                .expect("bob has a current-epoch address");
            assert!(t.accepts_inbound(addr.as_bytes()).is_some());
            assert!(t.address_at(&family(), "g-1", 7, "ed25519:bob").is_some());
        }

        assert_eq!(
            deriver.count(),
            after_install,
            "the packet path must never derive — that is the whole reason this table exists"
        );
    }

    #[test]
    fn lookup_misses_are_none_not_errors() {
        let t = seeded();
        assert!(t
            .send_address(&family(), "g-1", "ed25519:mallory")
            .is_none());
        assert!(t.send_address(&family(), "g-nope", "ed25519:bob").is_none());
        assert!(t
            .send_address(&CohortScope::Public, "g-1", "ed25519:bob")
            .is_none());
        assert!(t.accepts_inbound(&[0xEE; 16]).is_none());
    }

    // ── per-member distinctness ──────────────────────────────────────

    #[test]
    fn every_member_gets_its_own_address() {
        let t = seeded();
        let mut seen = std::collections::HashSet::new();
        for m in MEMBERS {
            let addr = t.send_address(&family(), "g-1", m).expect("member address");
            assert!(
                seen.insert(addr.into_bytes()),
                "a shared per-group hash is unicast-ambiguous in RNS and trips \
                 leviculum's register_destination displacement warning"
            );
        }
        assert_eq!(seen.len(), MEMBERS.len());
        assert_eq!(t.len(), MEMBERS.len());
    }

    #[test]
    fn inbound_resolution_always_names_a_member() {
        let t = seeded();
        for m in MEMBERS {
            let addr = t.send_address(&family(), "g-1", m).expect("member address");
            let bound = t.accepts_inbound(addr.as_bytes()).expect("accepted");
            assert_eq!(bound.member_key_id(), m);
            assert_eq!(bound.group().group_id(), "g-1");
            assert_eq!(bound.group().scope(), &family());
            assert_eq!(bound.epoch(), 7);
            assert_eq!(bound.role(), EpochRole::Current);
        }
    }

    #[test]
    fn two_groups_yield_unrelated_addresses() {
        let t = table();
        t.install_group(&family(), "g-1", 7, &secret(0xA1), &MEMBERS)
            .expect("group one");
        t.install_group(&family(), "g-2", 7, &secret(0xB2), &MEMBERS)
            .expect("group two");

        for m in MEMBERS {
            let one = t.send_address(&family(), "g-1", m).expect("g-1 address");
            let two = t.send_address(&family(), "g-2", m).expect("g-2 address");
            assert_ne!(
                one, two,
                "same member, different group exporter_secret => unrelated address"
            );
        }
        assert_eq!(t.len(), MEMBERS.len() * 2);
    }

    #[test]
    fn same_group_id_in_two_scopes_is_two_groups() {
        let t = table();
        t.install_group(&family(), "g-1", 7, &secret(0xA1), &MEMBERS)
            .expect("family group");
        t.install_group(&CohortScope::SelfOnly, "g-1", 7, &secret(0xC3), &MEMBERS)
            .expect("self group");

        let fam = t
            .send_address(&family(), "g-1", MEMBERS[0])
            .expect("family");
        let own = t
            .send_address(&CohortScope::SelfOnly, "g-1", MEMBERS[0])
            .expect("self");
        assert_ne!(fam, own);
    }

    // ── phase 1: install_next ────────────────────────────────────────

    #[test]
    fn install_next_keeps_the_old_epoch_primary_for_sending() {
        let t = seeded();
        let before = t
            .send_address(&family(), "g-1", MEMBERS[0])
            .expect("before");

        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install next");

        assert_eq!(
            t.send_address(&family(), "g-1", MEMBERS[0]),
            Some(before),
            "make-before-break: installing does not move the send epoch"
        );
        assert_eq!(
            t.live_epochs(&family(), "g-1"),
            Some(LiveEpochs {
                previous: None,
                current: 7,
                next: Some(8),
            })
        );
    }

    #[test]
    fn install_next_accepts_the_new_epoch_immediately() {
        let t = seeded();
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install next");

        let next_addr = t
            .address_at(&family(), "g-1", 8, MEMBERS[0])
            .expect("next-epoch address exists before activation");
        let bound = t
            .accepts_inbound(next_addr.as_bytes())
            .expect("a peer that advanced first must not be talking to a dead address");
        assert_eq!(bound.epoch(), 8);
        assert_eq!(bound.role(), EpochRole::Next);
        assert_eq!(t.len(), MEMBERS.len() * 2, "both epochs are accepted");
    }

    #[test]
    fn install_next_over_a_pending_epoch_is_refused() {
        let t = seeded();
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("first install");
        let err = t
            .install_next(&family(), "g-1", 9, &secret(0xC3), &MEMBERS)
            .expect_err("second install must be refused, not silently overwrite");
        assert_eq!(err, ScopeAddressError::RotationInProgress { pending: 8 });
        assert_eq!(
            t.live_epochs(&family(), "g-1").map(|e| e.next),
            Some(Some(8)),
            "the refused install left the pending epoch untouched"
        );
    }

    #[test]
    fn epochs_must_advance() {
        let t = seeded();
        let err = t
            .install_next(&family(), "g-1", 7, &secret(0xB2), &MEMBERS)
            .expect_err("same epoch");
        assert_eq!(
            err,
            ScopeAddressError::EpochNotAdvancing {
                current: 7,
                requested: 7
            }
        );
        assert!(t
            .install_next(&family(), "g-1", 6, &secret(0xB2), &MEMBERS)
            .is_err());
    }

    // ── phase 2: activate_next ───────────────────────────────────────

    #[test]
    fn activate_next_flips_the_send_epoch_and_keeps_the_old_for_receive() {
        let t = seeded();
        let old = t.send_address(&family(), "g-1", MEMBERS[0]).expect("old");
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");

        let step = t.activate_next(&family(), "g-1").expect("activate");
        assert_eq!(
            step,
            EpochTransition {
                from: 7,
                to: 8,
                evicted: None
            }
        );

        let new = t.send_address(&family(), "g-1", MEMBERS[0]).expect("new");
        assert_ne!(new, old, "sending now happens on the new epoch");
        assert_eq!(new, t.address_at(&family(), "g-1", 8, MEMBERS[0]).unwrap());

        let bound = t
            .accepts_inbound(old.as_bytes())
            .expect("the superseded epoch is still accepted for receive");
        assert_eq!(bound.epoch(), 7);
        assert_eq!(bound.role(), EpochRole::Previous);
        assert_eq!(
            t.accepts_inbound(new.as_bytes()).map(|b| b.role()),
            Some(EpochRole::Current)
        );
        assert_eq!(
            t.live_epochs(&family(), "g-1"),
            Some(LiveEpochs {
                previous: Some(7),
                current: 8,
                next: None,
            })
        );
    }

    #[test]
    fn activate_without_a_pending_epoch_is_refused() {
        let t = seeded();
        assert_eq!(
            t.activate_next(&family(), "g-1")
                .expect_err("nothing pending"),
            ScopeAddressError::NoPendingEpoch
        );
    }

    #[test]
    fn activating_over_an_unsealed_previous_reports_the_eviction() {
        let t = seeded();
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install 8");
        t.activate_next(&family(), "g-1").expect("activate 8");
        // Deliberately skip seal_rotation, then rotate again.
        t.install_next(&family(), "g-1", 9, &secret(0xC3), &MEMBERS)
            .expect("install 9");
        let step = t.activate_next(&family(), "g-1").expect("activate 9");

        assert_eq!(
            step,
            EpochTransition {
                from: 8,
                to: 9,
                evicted: Some(7)
            },
            "shifting an unsealed epoch out of the accept window is reported, never silent"
        );
        assert_eq!(t.len(), MEMBERS.len() * 2, "epoch 7 left the accept set");
    }

    // ── phase 3: seal_rotation ───────────────────────────────────────

    #[test]
    fn seal_rotation_drops_the_previous_epoch() {
        let t = seeded();
        let old = t.send_address(&family(), "g-1", MEMBERS[0]).expect("old");
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");
        t.activate_next(&family(), "g-1").expect("activate");

        assert_eq!(t.seal_rotation(&family(), "g-1"), Ok(Some(7)));
        assert!(
            t.accepts_inbound(old.as_bytes()).is_none(),
            "a member that never re-keyed is excluded at seal, not before"
        );
        assert_eq!(
            t.live_epochs(&family(), "g-1"),
            Some(LiveEpochs {
                previous: None,
                current: 8,
                next: None,
            })
        );
        assert_eq!(t.len(), MEMBERS.len());
    }

    #[test]
    fn seal_rotation_is_idempotent() {
        let t = seeded();
        assert_eq!(t.seal_rotation(&family(), "g-1"), Ok(None));
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");
        t.activate_next(&family(), "g-1").expect("activate");
        assert_eq!(t.seal_rotation(&family(), "g-1"), Ok(Some(7)));
        assert_eq!(t.seal_rotation(&family(), "g-1"), Ok(None));
    }

    // ── straggler semantics (the invariant) ──────────────────────────

    #[test]
    fn straggler_outbound_lands_during_the_accept_window_and_only_stops_at_seal() {
        let t = seeded();
        let straggler_addr = t
            .address_at(&family(), "g-1", 7, "ed25519:carol")
            .expect("carol's epoch-7 address");

        // Phase 1 — we installed the new epoch; carol has not moved.
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");
        assert_eq!(
            t.address_at(&family(), "g-1", 7, "ed25519:carol"),
            Some(straggler_addr),
            "we can still address the straggler"
        );

        // Phase 2 — we send on epoch 8 now; carol still on 7.
        t.activate_next(&family(), "g-1").expect("activate");
        assert_eq!(
            t.address_at(&family(), "g-1", 7, "ed25519:carol"),
            Some(straggler_addr),
            "outbound to a straggler must still resolve during the accept-old window"
        );
        // ...and carol's inbound to her own old-epoch address still lands.
        assert_eq!(
            t.accepts_inbound(straggler_addr.as_bytes())
                .map(|b| b.epoch()),
            Some(7)
        );

        // Phase 3 — convergence window over.
        t.seal_rotation(&family(), "g-1").expect("seal");
        assert_eq!(
            t.address_at(&family(), "g-1", 7, "ed25519:carol"),
            None,
            "exclusion happens exactly at seal — explicitly, not by silent deafness"
        );
        assert!(t.accepts_inbound(straggler_addr.as_bytes()).is_none());
        assert!(
            t.send_address(&family(), "g-1", "ed25519:carol").is_some(),
            "carol is still a member — only her old epoch went away"
        );
    }

    #[test]
    fn an_epoch_bump_never_leaves_a_gap_in_the_accept_set() {
        // Walk a full rotation and assert that at every step BOTH the
        // pre-rotation and post-rotation addresses of every member are
        // accepted, except after the seal.
        let t = seeded();
        let before: Vec<_> = MEMBERS
            .iter()
            .map(|m| t.send_address(&family(), "g-1", m).expect("before"))
            .collect();

        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");
        let after: Vec<_> = MEMBERS
            .iter()
            .map(|m| t.address_at(&family(), "g-1", 8, m).expect("after"))
            .collect();

        for (old, new) in before.iter().zip(after.iter()) {
            assert!(t.accepts_inbound(old.as_bytes()).is_some());
            assert!(t.accepts_inbound(new.as_bytes()).is_some());
        }
        t.activate_next(&family(), "g-1").expect("activate");
        for (old, new) in before.iter().zip(after.iter()) {
            assert!(t.accepts_inbound(old.as_bytes()).is_some());
            assert!(t.accepts_inbound(new.as_bytes()).is_some());
        }
        t.seal_rotation(&family(), "g-1").expect("seal");
        for (old, new) in before.iter().zip(after.iter()) {
            assert!(t.accepts_inbound(old.as_bytes()).is_none());
            assert!(t.accepts_inbound(new.as_bytes()).is_some());
        }
    }

    // ── install validation ───────────────────────────────────────────

    #[test]
    fn reusing_an_exporter_secret_across_epochs_is_caught_at_install() {
        let t = seeded();
        let err = t
            .install_next(&family(), "g-1", 8, &secret(0xA1), &MEMBERS)
            .expect_err("same secret re-derives the live epoch's addresses");
        assert!(matches!(
            err,
            ScopeAddressError::AddressCollision { epoch: 8, .. }
        ));
        assert_eq!(
            t.live_epochs(&family(), "g-1").map(|e| e.next),
            Some(None),
            "the rejected install must leave no partial epoch behind"
        );
        assert_eq!(t.len(), MEMBERS.len());
    }

    #[test]
    fn empty_membership_is_refused() {
        let t = table();
        let none: [&str; 0] = [];
        assert_eq!(
            t.install_group(&family(), "g-1", 7, &secret(0xA1), &none)
                .expect_err("empty install"),
            ScopeAddressError::EmptyMembership { epoch: 7 }
        );
        assert!(t.is_empty());
    }

    #[test]
    fn duplicate_member_is_refused() {
        let t = table();
        let dupes = ["ed25519:alice", "ed25519:alice"];
        assert_eq!(
            t.install_group(&family(), "g-1", 7, &secret(0xA1), &dupes)
                .expect_err("duplicate member"),
            ScopeAddressError::DuplicateMember {
                member_key_id: "ed25519:alice".to_owned()
            }
        );
        assert!(t.is_empty(), "rejected install commits nothing");
    }

    #[test]
    fn reinstalling_a_live_group_is_refused() {
        let t = seeded();
        assert_eq!(
            t.install_group(&family(), "g-1", 9, &secret(0xB2), &MEMBERS)
                .expect_err("group already installed"),
            ScopeAddressError::GroupAlreadyInstalled {
                group_id: "g-1".to_owned(),
                epoch: 7
            }
        );
    }

    #[test]
    fn rotation_on_an_unknown_group_errors_on_every_phase() {
        let t = table();
        let expected = ScopeAddressError::UnknownGroup {
            scope_kind: "family",
            group_id: "ghost".to_owned(),
        };
        assert_eq!(
            t.install_next(&family(), "ghost", 1, &secret(0xA1), &MEMBERS)
                .expect_err("install_next"),
            expected
        );
        assert_eq!(
            t.activate_next(&family(), "ghost").expect_err("activate"),
            expected
        );
        assert_eq!(
            t.seal_rotation(&family(), "ghost").expect_err("seal"),
            expected
        );
    }

    // ── removal ──────────────────────────────────────────────────────

    #[test]
    fn remove_group_clears_both_indexes() {
        let t = seeded();
        let addr = t.send_address(&family(), "g-1", MEMBERS[0]).expect("addr");
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");

        assert_eq!(t.remove_group(&family(), "g-1"), MEMBERS.len() * 2);
        assert!(t.is_empty());
        assert!(t.accepts_inbound(addr.as_bytes()).is_none());
        assert!(t.live_epochs(&family(), "g-1").is_none());
        assert_eq!(t.remove_group(&family(), "g-1"), 0, "idempotent");
    }

    #[test]
    fn remove_member_clears_every_live_epoch() {
        let t = seeded();
        t.install_next(&family(), "g-1", 8, &secret(0xB2), &MEMBERS)
            .expect("install");
        t.activate_next(&family(), "g-1").expect("activate");

        assert_eq!(t.remove_member(&family(), "g-1", "ed25519:bob"), 2);
        assert!(t.send_address(&family(), "g-1", "ed25519:bob").is_none());
        assert!(t.address_at(&family(), "g-1", 7, "ed25519:bob").is_none());
        assert_eq!(t.len(), (MEMBERS.len() - 1) * 2);
        assert_eq!(t.remove_member(&family(), "g-1", "ed25519:bob"), 0);
        assert_eq!(t.remove_member(&family(), "g-1", "ed25519:nobody"), 0);
    }

    // ── stub-deriver sanity (structure only, never wire bytes) ───────

    #[test]
    fn stub_deriver_is_deterministic_and_input_sensitive() {
        let s = secret(0x11);
        assert_eq!(
            StubDeriver.derive(&s, "ed25519:alice"),
            StubDeriver.derive(&s, "ed25519:alice")
        );
        assert_ne!(
            StubDeriver.derive(&s, "ed25519:alice"),
            StubDeriver.derive(&s, "ed25519:bob")
        );
        assert_ne!(
            StubDeriver.derive(&s, "ed25519:alice"),
            StubDeriver.derive(&secret(0x22), "ed25519:alice")
        );
    }
}
