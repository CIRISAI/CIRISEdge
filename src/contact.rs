//! CIRISEdge#552/#554 — the contact ladder: **announce → discover → request →
//! consent → chat**.
//!
//! # Why this module exists at all
//!
//! Every rung of this ladder already existed as a primitive, and none of it was
//! reachable without knowing five subsystems. Discovery meant resolving a
//! `TransportDestination` yourself; a contact meant hand-building a
//! `consent:replication:v1` grant; a chat room meant knowing it is really a
//! 2-member `Community`. That is not a DX problem in the cosmetic sense — it is
//! why the ladder had never been walked end to end, and why nobody could say
//! which rung was broken.
//!
//! So the surface here takes a **fedID and nothing else**. `discover(fed_id)`,
//! `request_contact(fed_id)`, `accept_contact(fed_id)`, `open_chat(fed_id)`.
//! Anything a caller must look up first is a rung they can get wrong.
//!
//! # Multi-hop is free, and that is load-bearing
//!
//! A node publishes its RNS transport key on the `TransportDestination` plane.
//! Once discovery yields that, **Reticulum routes to it across however many hops
//! separate the two nodes** — edge does not implement relaying, path discovery,
//! or a DHT to make contact work at range.
//!
//! This is why the hash-first directory (#552) does not need multi-hop hash
//! propagation to deliver contact: what has to travel is the *destination*, and
//! the transport already carries it. A node one hop from a body-holder can
//! discover anyone that holder knows, and then reach them directly at any
//! distance.
//!
//! # Every rung logs, and says what to do
//!
//! The ladder is diagnosed from logs, because its failures are distributed: the
//! rung that breaks is usually not on the node you are looking at. So each rung
//! emits a structured event with the same shape — step, subject, outcome — and a
//! failure names the ACTIONABLE cause, not the mechanical one. "no transport
//! destination for X: it has not announced, or this node has not admitted its
//! announce" beats "lookup returned None".

use std::fmt;

/// A rung of the ladder. Stable strings — an operator greps these, and a
/// dashboard groups by them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rung {
    /// This node published its own identity and transport key.
    Announce,
    /// Resolve a fedID to something reachable.
    Discover,
    /// Ask a peer to be a contact. Point-to-point; leaves no federation trace.
    RequestContact,
    /// Grant replication consent — the contact becomes real and replicable.
    Consent,
    /// Open or find the 2-member community that carries the conversation.
    OpenChat,
    /// Put a message in it.
    SendMessage,
}

impl Rung {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Announce => "announce",
            Self::Discover => "discover",
            Self::RequestContact => "request_contact",
            Self::Consent => "consent",
            Self::OpenChat => "open_chat",
            Self::SendMessage => "send_message",
        }
    }

    /// The rung before this one. A failure is nearly always the previous rung
    /// not having completed, so the diagnostic can say where to look.
    #[must_use]
    pub const fn previous(self) -> Option<Self> {
        match self {
            Self::Announce => None,
            Self::Discover => Some(Self::Announce),
            Self::RequestContact => Some(Self::Discover),
            Self::Consent => Some(Self::RequestContact),
            Self::OpenChat => Some(Self::Consent),
            Self::SendMessage => Some(Self::OpenChat),
        }
    }
}

impl fmt::Display for Rung {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a rung did not complete — in terms of what an operator can do about it.
///
/// Deliberately NOT a wrapper over the underlying error types. A caller that
/// needs the mechanical cause has the log; this is the axis a human acts on, and
/// keeping it small is what makes it usable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LadderStall {
    /// The subject has not announced, or this node has not admitted its
    /// announce yet. Resolves itself as replication converges.
    NotYetDiscovered { fed_id: String },
    /// Discovered, but nothing answered. The peer may be offline; RNS will route
    /// when it returns.
    Unreachable { fed_id: String },
    /// The peer has not consented. Not an error — the ladder is waiting on a
    /// human, and no amount of retrying changes that.
    AwaitingConsent { fed_id: String },
    /// This node has not consented to the peer. The reciprocal of the above.
    ConsentNotGranted { fed_id: String },
    /// The rung before this one has not completed.
    PriorRungIncomplete { rung: Rung, prior: Rung },
}

impl LadderStall {
    /// What an operator should do. Every arm answers it — a stall with no
    /// remedy is a bug report, not a diagnostic.
    #[must_use]
    pub fn remedy(&self) -> String {
        match self {
            Self::NotYetDiscovered { fed_id } => format!(
                "no transport destination for {fed_id}: either it has not announced, \
                 or this node has not admitted its announce yet. Check that the peer \
                 is running and that a replication round with it has completed."
            ),
            Self::Unreachable { fed_id } => format!(
                "{fed_id} is discoverable but did not answer. It is probably offline; \
                 Reticulum will route to it across the mesh when it returns. No action \
                 needed unless it stays unreachable while known to be up."
            ),
            Self::AwaitingConsent { fed_id } => format!(
                "waiting for {fed_id} to accept the contact request. This is a person, \
                 not a timeout — retrying does not help and re-sending is spam."
            ),
            Self::ConsentNotGranted { fed_id } => format!(
                "this node has not granted replication consent to {fed_id}. Accept the \
                 contact request to make the conversation replicable in both directions."
            ),
            Self::PriorRungIncomplete { rung, prior } => format!(
                "{rung} cannot proceed because {prior} has not completed. Look at the \
                 {prior} rung on this node first — a ladder failure is nearly always \
                 the rung before it."
            ),
        }
    }

    /// Is this a stall the ladder resolves on its own?
    ///
    /// The distinction that matters operationally: a `false` here means the
    /// ladder is waiting on a HUMAN, and an operator watching a dashboard should
    /// not treat it as a fault to escalate.
    #[must_use]
    pub const fn self_resolving(&self) -> bool {
        match self {
            Self::NotYetDiscovered { .. } | Self::Unreachable { .. } => true,
            Self::AwaitingConsent { .. }
            | Self::ConsentNotGranted { .. }
            | Self::PriorRungIncomplete { .. } => false,
        }
    }
}

/// Emit the one structured line a rung produces.
///
/// One shape for every rung, so `step=` is greppable and a dashboard can group
/// without parsing prose. Success is INFO because walking the ladder is a rare,
/// meaningful event — not a hot path — and the first question after "it did not
/// work" is always which rungs DID.
pub fn log_rung(rung: Rung, fed_id: &str, stall: Option<&LadderStall>) {
    match stall {
        None => tracing::info!(
            step = rung.as_str(),
            fed_id,
            outcome = "ok",
            "contact ladder: {rung} completed for {fed_id}"
        ),
        Some(s) if s.self_resolving() => tracing::info!(
            step = rung.as_str(),
            fed_id,
            outcome = "waiting",
            remedy = %s.remedy(),
            "contact ladder: {rung} is waiting — this resolves itself"
        ),
        Some(s) => tracing::warn!(
            step = rung.as_str(),
            fed_id,
            outcome = "stalled",
            remedy = %s.remedy(),
            "contact ladder: {rung} stalled and needs someone to act"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{LadderStall, Rung};

    /// The ladder is ordered, and the order is the diagnostic. A failure is
    /// nearly always the previous rung, so every rung must be able to name it.
    #[test]
    fn every_rung_but_the_first_names_its_predecessor() {
        assert_eq!(Rung::Announce.previous(), None, "announce is the base");
        for rung in [
            Rung::Discover,
            Rung::RequestContact,
            Rung::Consent,
            Rung::OpenChat,
            Rung::SendMessage,
        ] {
            assert!(
                rung.previous().is_some(),
                "{rung} must name the rung to look at first"
            );
        }
    }

    /// Waiting on a PERSON is not a fault. An operator dashboard that escalates
    /// "awaiting consent" trains people to ignore it, and then they ignore the
    /// real ones too.
    #[test]
    fn waiting_on_a_human_is_not_self_resolving() {
        let awaiting = LadderStall::AwaitingConsent {
            fed_id: "fed_abc".into(),
        };
        assert!(!awaiting.self_resolving());

        let converging = LadderStall::NotYetDiscovered {
            fed_id: "fed_abc".into(),
        };
        assert!(
            converging.self_resolving(),
            "an unconverged directory fixes itself and must not page anyone"
        );
    }

    /// Every stall answers "what do I do". A diagnostic that names a condition
    /// and no action is a bug report addressed to the wrong person.
    #[test]
    fn every_stall_states_a_remedy_naming_its_subject() {
        let id = "fed_7f3a9c21e4b8";
        let stalls = [
            LadderStall::NotYetDiscovered { fed_id: id.into() },
            LadderStall::Unreachable { fed_id: id.into() },
            LadderStall::AwaitingConsent { fed_id: id.into() },
            LadderStall::ConsentNotGranted { fed_id: id.into() },
        ];
        for s in stalls {
            let r = s.remedy();
            assert!(r.len() > 40, "a remedy must actually say something: {r}");
            assert!(
                r.contains(id),
                "a remedy must name its subject so a log line is actionable alone: {r}"
            );
        }
        // The structural one names rungs rather than a fedID.
        let prior = LadderStall::PriorRungIncomplete {
            rung: Rung::OpenChat,
            prior: Rung::Consent,
        };
        let r = prior.remedy();
        assert!(r.contains("open_chat") && r.contains("consent"), "{r}");
    }

    /// The rung strings are an operator interface: they are grepped and grouped.
    #[test]
    fn rung_names_are_stable_and_distinct() {
        let names: Vec<&str> = [
            Rung::Announce,
            Rung::Discover,
            Rung::RequestContact,
            Rung::Consent,
            Rung::OpenChat,
            Rung::SendMessage,
        ]
        .iter()
        .map(|r| r.as_str())
        .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), names.len(), "rung names must be distinct");
        assert!(names.contains(&"request_contact"));
    }
}
