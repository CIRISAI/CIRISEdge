//! **What this node owes a peer, read at decision time** (`FSD/CIRIS_MESH.md`
//! §7.1 and §7.2, `FSD/PRIVACY_MODES.md` §6.12): the read behind every shed
//! lever on a shaped slot.
//!
//! §7.2 names the peers a tier leaves alone: Stretch falls on rounds to peers
//! "that are not the owner, own devices or the send set", and L-A2 and L-A3
//! say why. §6.12 adds the `seat` link. So:
//!
//! - **The owner and the owner's devices:** the principals of this node
//!   (persist `principals_of`) and each one's nodes (persist `nodes_owned_by`).
//!   Not `send_set_for(self)`: since CIRISPersist#963 that set drops a device
//!   outside the owner's allow list, and it is still the owner's device.
//! - **The seats:** the active canonical roster, [`holds_active_seat`].
//! - **The send set:** the bridge's resolved set, the one door rows go through.
//!
//! **Nothing is baked.** A seat is read per peer from the directory and the
//! tombstones when the lever acts, so a retired canonical stops being protected
//! on the next read and a newly conferred one starts. L-R3 asks that the
//! ladder's own decisions be no load: the owner's devices sit behind a memo no
//! older than the consent memo, a seat costs two point reads on a decision that
//! already cost a link and a key exchange, and a stalled read costs one budget
//! and then answers [`PeerObligation::Unresolved`] for a backoff, so nothing
//! queues on the directory under load.
//!
//! **`seat` class reads the same roster on a cadence** ([`active_seat_roster`]):
//! a class offer and the bound are sync reads on hot paths, so they read a set
//! the transport refreshes every [`SEAT_ROSTER_REFRESH`], and no offer waits
//! on the directory. The one difference is proof: a seat there is the signed
//! bundle or the conferred role. Operator config protects a peer from a shed,
//! which is the safe direction, and proves no seat.
//!
//! **Which way it fails.** A read that errors, times out or was narrower than
//! the truth answers `Unresolved`, and nothing is shed on that: a wrong refusal
//! hurts quietly, a missed shed costs a little load and shows in the count.

use std::collections::HashSet;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use ciris_persist::federation::FederationDirectory;

use crate::load_ladder::{PeerObligation, PeerObligations};

/// How old the owner's devices may be when a lever reads them: the consent
/// memo's bound, the staleness the send set already lives with.
pub const OBLIGATION_MEMO_TTL: Duration = Duration::from_secs(10);
/// How long one read may take before it answers `Unresolved`.
pub const OBLIGATION_READ_BUDGET: Duration = Duration::from_secs(1);
/// How long a read that ran out of budget keeps answering `Unresolved`
/// without trying again.
pub const OBLIGATION_READ_BACKOFF: Duration = Duration::from_secs(5);

/// **Whether `peer` holds a seat on the active canonical roster now**: it
/// carries the `canonical` role in the directory, or this node recognises it
/// from the signed bundle or operator config, and no #377 tombstone names it. A
/// tombstone subtracts whatever the provenance
/// (`Edge::refresh_canonical_retirements`): neither the baked base nor config
/// outvotes a quorum. A recognised id with no directory row stays: absence of
/// corroboration is not retirement.
///
/// # Errors
/// The directory's.
pub async fn holds_active_seat<S: std::hash::BuildHasher + Sync>(
    directory: &dyn FederationDirectory,
    recognised: &HashSet<String, S>,
    peer: &str,
) -> Result<bool, ciris_persist::federation::Error> {
    if directory.lookup_canonical_withdrawal(peer).await?.is_some() {
        return Ok(false);
    }
    Ok(recognised.contains(peer)
        || ciris_persist::federation::admission::is_canonical(directory, peer).await?)
}

/// How often the transport reads the active seats.
pub const SEAT_ROSTER_REFRESH: Duration = Duration::from_secs(30);

/// The spellings of the conferred role. Persist stores a set as a joined string
/// (`canonical,node` in the bundle) and `list_keys_by_identity_type` matches it
/// exactly; the set-aware `list_canonical_servers` is not on the trait.
const CANONICAL_SPELLINGS: [&str; 3] = ["canonical", "canonical,node", "node,canonical"];

/// **The active seats**: the signed bundle's serve nodes and every key conferred
/// the role since, less every #377 tombstone. With an empty directory that is
/// the bundle: absence of a row is not retirement.
///
/// # Errors
/// The directory's.
pub async fn active_seat_roster<S: std::hash::BuildHasher + Sync>(
    directory: &dyn FederationDirectory,
    bundle: &HashSet<String, S>,
) -> Result<HashSet<String>, ciris_persist::federation::Error> {
    let mut roster: HashSet<String> = bundle.iter().cloned().collect();
    for spelling in CANONICAL_SPELLINGS {
        match directory.list_keys_by_identity_type(spelling).await {
            Ok(keys) => roster.extend(keys.into_iter().map(|r| r.key_id)),
            // A PyO3 host's directory capsule routes this read for the accord
            // set only. The bundle still stands, and withdrawals below still
            // apply: a conferral since genesis is what such a host can't see.
            Err(ciris_persist::federation::Error::Unsupported { .. }) => break,
            Err(e) => return Err(e),
        }
    }
    for withdrawn in directory.list_canonical_withdrawals().await? {
        roster.remove(&withdrawn.key_id);
    }
    Ok(roster)
}

/// The send set, as a lever reads it.
#[async_trait::async_trait]
pub trait SendSetRead: Send + Sync {
    /// Whether `peer` is in `local`'s resolved send set. `None` when that
    /// cannot be said: no set resolved, or a `false` from a set narrower than
    /// the truth.
    async fn reaches(&self, local: &str, peer: &str) -> Option<bool>;
}

#[async_trait::async_trait]
impl SendSetRead for crate::replication::FederationDirectoryReplicationBridge {
    async fn reaches(&self, local: &str, peer: &str) -> Option<bool> {
        self.send_set_reaches(local, peer).await
    }
}

/// The owner's devices, `None` when the read failed.
type OwnDevices = Option<Arc<HashSet<String>>>;

/// The production [`PeerObligations`].
pub struct LivePeerObligations {
    directory: Arc<dyn FederationDirectory>,
    local: String,
    recognised: Arc<RwLock<HashSet<String>>>,
    bundle_seats: HashSet<String>,
    send_set: Arc<dyn SendSetRead>,
    /// When the owner's devices were read, and what came back.
    memo: tokio::sync::Mutex<Option<(Instant, OwnDevices)>>,
    backoff_until: std::sync::Mutex<Option<Instant>>,
}

impl std::fmt::Debug for LivePeerObligations {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LivePeerObligations")
            .field("local", &self.local)
            .finish_non_exhaustive()
    }
}

impl LivePeerObligations {
    /// `recognised` is the live recognition set, `Edge::canonical_peers`. The
    /// base of the seat roster is the signed bundle.
    #[must_use]
    pub fn new(
        directory: Arc<dyn FederationDirectory>,
        local: impl Into<String>,
        recognised: Arc<RwLock<HashSet<String>>>,
        send_set: Arc<dyn SendSetRead>,
    ) -> Self {
        Self {
            directory,
            local: local.into(),
            recognised,
            bundle_seats: ciris_persist::federation::genesis::canonical_genesis_bundle()
                .serve_nodes
                .iter()
                .map(|sr| sr.record.key_id.clone())
                .collect(),
            send_set,
            memo: tokio::sync::Mutex::new(None),
            backoff_until: std::sync::Mutex::new(None),
        }
    }

    /// The owner, and each of the owner's nodes.
    async fn own_devices(&self) -> Result<HashSet<String>, ciris_persist::federation::Error> {
        use ciris_persist::federation::{admission, self_collective};
        let dir = &*self.directory;
        let principals = self_collective::principals_of(dir, &self.local).await?;
        let mut own: HashSet<String> = principals.iter().cloned().collect();
        for person in &principals {
            own.extend(admission::nodes_owned_by(dir, person).await?);
        }
        own.remove(&self.local);
        Ok(own)
    }

    /// The memo, read again once it is older than [`OBLIGATION_MEMO_TTL`].
    async fn own_devices_now(&self) -> OwnDevices {
        let mut memo = self.memo.lock().await;
        if let Some((at, own)) = memo.as_ref() {
            if at.elapsed() < OBLIGATION_MEMO_TTL {
                return own.clone();
            }
        }
        let own = match self.own_devices().await {
            Ok(own) => Some(Arc::new(own)),
            Err(e) => {
                tracing::debug!(error = %e, "the owner's devices did not read; nothing is shed");
                None
            }
        };
        *memo = Some((Instant::now(), own.clone()));
        own
    }

    async fn read(&self, peer: &str) -> PeerObligation {
        let own = self.own_devices_now().await;
        if own.as_ref().is_some_and(|o| o.contains(peer)) {
            return PeerObligation::OwnDevice;
        }
        let recognised: HashSet<String> = self
            .recognised
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let seat = holds_active_seat(&*self.directory, &recognised, peer).await;
        match &seat {
            Ok(true) => return PeerObligation::Seat,
            // Recognised, and the tombstone read failed: retirement takes
            // positive evidence.
            Err(_) if recognised.contains(peer) => return PeerObligation::Seat,
            Ok(false) | Err(_) => {}
        }
        match self.send_set.reaches(&self.local, peer).await {
            Some(true) => PeerObligation::SendSet,
            Some(false) if own.is_some() && seat.is_ok() => PeerObligation::Ordinary,
            _ => PeerObligation::Unresolved,
        }
    }
}

#[async_trait::async_trait]
impl PeerObligations for LivePeerObligations {
    async fn active_seats(&self) -> Option<crate::load_ladder::ActiveSeats> {
        let read = active_seat_roster(&*self.directory, &self.bundle_seats);
        match tokio::time::timeout(OBLIGATION_READ_BUDGET, read).await {
            Ok(Ok(seats)) => Some(crate::load_ladder::ActiveSeats {
                own: seats.contains(&self.local),
                seats,
            }),
            Ok(Err(e)) => {
                tracing::warn!(error = %e, "the seat roster did not read; the last one stands");
                None
            }
            Err(_) => {
                tracing::warn!("the seat roster ran out of budget; the last one stands");
                None
            }
        }
    }

    async fn obligation_of(&self, peer: &str) -> PeerObligation {
        let backing_off = self
            .backoff_until
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some_and(|until| Instant::now() < until);
        if backing_off {
            return PeerObligation::Unresolved;
        }
        if let Ok(answer) = tokio::time::timeout(OBLIGATION_READ_BUDGET, self.read(peer)).await {
            answer
        } else {
            *self
                .backoff_until
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(Instant::now() + OBLIGATION_READ_BACKOFF);
            tracing::warn!(
                budget_ms = OBLIGATION_READ_BUDGET.as_millis(),
                "the obligation read ran out of budget; nothing is shed until it answers"
            );
            PeerObligation::Unresolved
        }
    }
}

#[cfg(test)]
mod tests {
    use super::active_seat_roster;
    use ciris_persist::federation::directory_double::FaultInjectingDirectory;
    use ciris_persist::federation::FederationDirectory;
    use std::collections::HashSet;
    use std::sync::Arc;

    /// A PyO3 host's directory capsule refuses `list_keys_by_identity_type`
    /// for anything but the accord set. The roster still reads: the bundle's
    /// seats stand, instead of the whole read failing and no seat ever being
    /// known.
    #[tokio::test]
    async fn a_host_whose_directory_lists_no_roles_still_has_the_bundle_seats() {
        let backend = Arc::new(ciris_persist::store::test_backend::test_backend());
        let inner: Arc<dyn FederationDirectory> = backend;
        let capsule_like: Arc<dyn FederationDirectory> =
            Arc::new(FaultInjectingDirectory::new(inner).unsupported("list_keys_by_identity_type"));
        let bundle: HashSet<String> = ["seat-a", "seat-b"].map(str::to_owned).into();
        let roster = active_seat_roster(&*capsule_like, &bundle)
            .await
            .expect("an unsupported role listing is not a failed roster");
        assert_eq!(roster, bundle);
    }
}
