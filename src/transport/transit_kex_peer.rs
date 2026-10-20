//! CIRISEdge#805 (CC 3.3.6.2) — resolve a PEER's transit KEX pair, the static
//! `{x25519, ml_kem_768}` a dialler runs `transit_kex::initiate` against.
//!
//! The only source is persist's per-peer resolver `transit_kex_pair_for`,
//! reached through [`RootingDirectory::transit_kex_pair_for`] (the handle
//! the transport holds; its one real implementation forwards to persist): the
//! pair from a live `Rooted` signed `transport_destination` binding, `None`
//! when there is none, when two live Rooted bindings disagree, or when the
//! pair reuses any key on the node's current occurrence. Never the raw
//! `SignedTransportDestination::transit_kex_pair` (it skips the provenance
//! and cross-row reuse checks) and never a bare announce (a routing hint is
//! not a hop key).
//!
//! `None` means the peer cannot relay (CC 3.3.6.2).

use std::collections::HashSet;
use std::sync::Mutex;

use ciris_persist::federation::self_at_login::TransitKexPair;

use crate::verify::RootingDirectory;

/// Per-peer transit pair resolution with a say-once log for peers that
/// cannot relay. Holds no pair: every call re-reads the directory, so a
/// re-signed or retired binding is seen on the next dial.
#[derive(Debug, Default)]
pub struct PeerTransitResolver {
    /// Peers already logged as "cannot relay" (debug, once each).
    logged_no_pair: Mutex<HashSet<String>>,
    /// Peers whose refused dial (`link_seal_refused_no_pair`) has been said
    /// at INFO since their pair last resolved ([`Self::note_no_pair_refusal`]).
    said_no_pair_refusal: Mutex<HashSet<String>>,
}

impl PeerTransitResolver {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The transit pair to key a hop to `occurrence_key_id`, or `None` when
    /// that peer cannot relay.
    ///
    /// # Errors
    ///
    /// The directory's: a backend read error, a stored binding whose pair
    /// does not parse (a corrupted row; it passed admission), or no
    /// directory at all.
    pub async fn resolve<D: RootingDirectory + ?Sized>(
        &self,
        dir: &D,
        occurrence_key_id: &str,
    ) -> Result<Option<TransitKexPair>, String> {
        let pair = dir.transit_kex_pair_for(occurrence_key_id).await?;
        if pair.is_some() {
            self.rearm(occurrence_key_id);
        } else {
            let first = self
                .logged_no_pair
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .insert(occurrence_key_id.to_owned());
            if first {
                // persist's `None` does not say which of its three cases
                // applied, so neither does this line.
                tracing::debug!(
                    peer = %occurrence_key_id,
                    "CIRISEdge#805: peer has no usable transit KEX pair and cannot relay \
                     (no live Rooted binding carrying one, two live Rooted bindings \
                     carrying different pairs, or the pair reuses one of its keys; \
                     persist does not say which)"
                );
            }
        }
        Ok(pair)
    }

    /// A dial to `peer` was refused for want of its pair. `true` the first
    /// time since the pair last resolved: during bootstrap a peer's pair
    /// arrives only after its route does, so the refusal repeats on every
    /// round until then and is said once (INFO), its repeats at DEBUG
    /// ([`no_pair_refusal_level`]).
    pub fn note_no_pair_refusal(&self, peer: &str) -> bool {
        self.said_no_pair_refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(peer.to_owned())
    }

    /// `peer`'s pair resolved: a later loss of it is said again, at both
    /// say-once points.
    fn rearm(&self, peer: &str) {
        self.said_no_pair_refusal
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(peer);
        self.logged_no_pair
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(peer);
    }
}

/// The level a `link_seal_refused_no_pair` dial refusal is logged at: INFO
/// the first time per peer (`first`, from
/// [`PeerTransitResolver::note_no_pair_refusal`]), DEBUG after. Never WARN:
/// a peer whose pair has not arrived yet is the normal bootstrap state, not
/// a fault.
#[must_use]
pub fn no_pair_refusal_level(first: bool) -> tracing::Level {
    if first {
        tracing::Level::INFO
    } else {
        tracing::Level::DEBUG
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_no_pair_refusal_is_said_once_per_peer_and_rearmed_when_the_pair_resolves() {
        let r = PeerTransitResolver::new();
        assert!(r.note_no_pair_refusal("bob"), "said the first time");
        for _ in 0..17 {
            assert!(!r.note_no_pair_refusal("bob"), "repeats are quiet");
        }
        assert!(r.note_no_pair_refusal("carol"), "per peer");
        r.rearm("bob");
        assert!(
            r.note_no_pair_refusal("bob"),
            "said again once the pair was had and lost"
        );
        assert_eq!(no_pair_refusal_level(true), tracing::Level::INFO);
        assert_eq!(no_pair_refusal_level(false), tracing::Level::DEBUG);
        for first in [true, false] {
            assert_ne!(
                no_pair_refusal_level(first),
                tracing::Level::WARN,
                "never WARN"
            );
        }
    }
}
