//! CIRISEdge#805 (CC 3.3.6.2) — resolve a PEER's transit KEX pair, the static
//! `{x25519, ml_kem_768}` a dialler runs `transit_kex::initiate` against.
//!
//! The only source is persist's per-peer resolver
//! [`transit_kex_pair_for`]: the pair from a live `Rooted` signed
//! `transport_destination` binding, `None` when there is none, when two live
//! Rooted bindings disagree, or when the pair reuses any key on the node's
//! current occurrence. Never the raw `SignedTransportDestination::
//! transit_kex_pair` (it skips the provenance and cross-row reuse checks) and
//! never a bare announce (a routing hint is not a hop key).
//!
//! `None` means the peer cannot relay (CC 3.3.6.2).

use std::collections::HashSet;
use std::sync::Mutex;

use ciris_persist::federation::self_at_login::{transit_kex_pair_for, TransitKexPair};
use ciris_persist::federation::FederationDirectory;

/// Per-peer transit pair resolution with a say-once log for peers that
/// cannot relay. Holds no pair: every call re-reads the directory, so a
/// re-signed or retired binding is seen on the next dial.
#[derive(Debug, Default)]
pub struct PeerTransitResolver {
    /// Peers already logged as "cannot relay" (debug, once each).
    logged_no_pair: Mutex<HashSet<String>>,
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
    /// persist's: a backend read error, or a stored binding whose pair does
    /// not parse (a corrupted row; it passed admission).
    pub async fn resolve<D: FederationDirectory + ?Sized>(
        &self,
        dir: &D,
        occurrence_key_id: &str,
    ) -> Result<Option<TransitKexPair>, ciris_persist::federation::Error> {
        let pair = transit_kex_pair_for(dir, occurrence_key_id).await?;
        if pair.is_none() {
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
}
