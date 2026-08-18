//! A/V session → scoped-address wiring (CIRISEdge#499).
//!
//! The twin of [`crate::cohort_addressing`], for the other kind of MLS
//! group edge holds. Cohorts make a *community* addressable; this makes
//! a *call inside it* addressable, and the two are deliberately separate
//! groups with separate secrets:
//!
//! ```text
//! CohortGroup   community membership   → who is in the community, and where
//! AvSession     one stream's media     → who is on THIS call, and where
//! ```
//!
//! Both derive through the same [`ScopeAddressTable`] and the same
//! [`ScopeLifecycle`], so a community call and a community message get
//! their addresses from one mechanism with one set of rotation rules.
//! What differs is only which group's exporter feeds it.
//!
//! # Why a call needs its own addresses at all
//!
//! Without this, a call inside a community is reachable at the
//! community's addresses, which means **being on the call is
//! observable to the whole community** — the roster of a specific
//! conversation leaks to everyone entitled to the room. Contextual
//! integrity treats that as a distinct flow: the community is the
//! context for "is a member", the call is the context for "is talking
//! to whom, now". Per-session derivation keeps the second from being a
//! side effect of the first.
//!
//! An observer with the community secret still cannot enumerate call
//! participants, because the session's exporter is a different secret
//! under a different group.
//!
//! # The relay
//!
//! [`RelayNode`](crate::transport::realtime_av_relay::RelayNode) holds
//! current+next across a rotation for the same reason the table does —
//! MLS epochs advance per-member at different moments, and a
//! `DestinationHash` is used to dial and listen, never per chunk, so a
//! rotation must never strand a subscriber mid-dial. [`advance_av_addresses`]
//! moves both together, so the relay's answerable set and the table's
//! accept-set cannot disagree.

use crate::scope_lifecycle::{ScopeGroupSnapshot, TransitionOutcome};
use crate::transport::realtime_av_session::{AvSession, AvSessionError};

/// Why a session's addresses could not be installed.
#[derive(Debug, thiserror::Error)]
pub enum AvAddressError {
    /// The session's destination secret could not be derived.
    #[error("A/V session exporter: {0}")]
    Exporter(#[from] AvSessionError),
}

/// The table group id for a session: its [`StreamId`], hex-encoded.
///
/// Distinct by construction from any community id, so a session and the
/// community it runs inside can never collide in the table even under
/// the same scope.
///
/// [`StreamId`]: crate::transport::realtime_av::StreamId
#[must_use]
pub fn session_group_id(session: &AvSession) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(70);
    out.push_str("av-stream:");
    for b in session.stream_id().0 {
        write!(out, "{b:02x}").expect("write to String is infallible");
    }
    out
}

/// **The adapter.** Reduce a session to the one shape the lifecycle
/// takes.
///
/// Identical in form to [`crate::cohort_addressing::snapshot`] — that
/// is the point. Downstream writes the same two lines whether it is
/// standing up a community or a call inside one:
///
/// ```ignore
/// let snap = av_addressing::snapshot(&call)?;
/// lifecycle.install(&community_scope, &snap)?;
/// ```
///
/// # Errors
/// [`AvAddressError::Exporter`] on corrupted group state.
pub fn snapshot(session: &AvSession) -> Result<ScopeGroupSnapshot, AvAddressError> {
    Ok(ScopeGroupSnapshot {
        group_id: session_group_id(session),
        epoch: session.epoch().0,
        members: session.member_key_ids(),
        // The DESTINATION plane specifically — never the DEK seed.
        destination_secret: session.destination_secret()?,
    })
}

/// Move the relay's answerable window onto the epoch the lifecycle just
/// activated.
///
/// Call immediately after [`ScopeLifecycle::advance`] when this node is
/// the relay for the stream. Kept separate from the advance rather than
/// folded into it because not every node running a session relays it,
/// and a verb that silently did nothing on non-relays would be the kind
/// of quiet no-op this codebase keeps paying for.
///
/// The relay answers on current+next for the same reason the table
/// does: a `DestinationHash` is used to dial and listen, never per
/// chunk, so a rotation must not strand a subscriber mid-dial.
pub fn advance_relay_window(
    relay: &mut crate::transport::realtime_av_relay::RelayNode,
    activated: &TransitionOutcome,
) {
    let displaced = relay.install_next_address(leviculum_core::DestinationHash::new(
        *activated.own_address.as_bytes(),
    ));
    debug_assert!(
        displaced.is_none(),
        "a relay rotation was installed without an intervening seal",
    );
    relay.activate_next_address();
}
