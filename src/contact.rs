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

/// What a `key_id` names.
///
/// Three identifier types reach this surface — a fedID, a nodeID, an agentID —
/// and a caller usually holds one without knowing which. `key_id` is
/// `"<label>-<fingerprint>"` and the label is operator-chosen, so it is NOT a
/// reliable discriminator: `frank-laptop-a3k…` could be anything. The directory
/// is the authority, via `identity_type`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityKind {
    /// A person. The party that CONSENTS.
    Person,
    /// A node. The party you actually reach over the wire.
    Node,
    /// An agent. Owned by a person, and cannot consent on their behalf.
    Agent,
    /// Something else in the directory — steward, accord holder, partner.
    Other(String),
}

impl IdentityKind {
    #[must_use]
    pub fn from_identity_type(t: &str) -> Self {
        match t {
            "user" => Self::Person,
            "node" => Self::Node,
            "agent" => Self::Agent,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// Who you are talking to, and what you actually contact.
///
/// The two are DIFFERENT and the split is the footgun this type exists to
/// remove. A person consents; a node is reachable. Collapsing them lets a caller
/// send a consent request to a node (nobody is there to accept it) or try to
/// open a link to a person (they have no transport key), and both fail in ways
/// that look like the network.
///
/// Whatever identifier you started from — fedID, nodeID, agentID — you end up
/// here, so the rest of the ladder is written once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    /// The person. Who consents, and who a conversation is *with*.
    pub fed_id: String,
    /// Their nodes. What a contact request is actually delivered to, and where
    /// Reticulum routes — across as many hops as separate you.
    pub nodes: Vec<String>,
    /// Which identifier the caller supplied, so a log line can say how it got
    /// here. A stall on a nodeID and the same stall on its owner's fedID are
    /// different situations to an operator.
    pub resolved_from: IdentityKind,
}

/// The directory reads resolution needs. A trait so the ladder is testable
/// without standing up persist — the resolution rules are the part that gets
/// this wrong, not the SQL.
#[async_trait::async_trait]
pub trait DirectoryLens: Send + Sync {
    /// `identity_type` for a key, or `None` if the directory has never seen it.
    async fn identity_type_of(&self, key_id: &str) -> Option<String>;
    /// The person who owns this node or agent.
    async fn owner_of(&self, key_id: &str) -> Option<String>;
    /// Every node that person owns.
    async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String>;
}

/// Resolve any identifier to the person and the nodes that reach them.
///
/// The rule is one sentence: **whatever you hand me, I find the person, then
/// their nodes.** A nodeID and an agentID resolve through their owner; a fedID
/// is already the person.
///
/// A stall here is nearly always `NotYetDiscovered`, which is the honest reading
/// of "the directory has not converged on this key yet" — it is not an error and
/// it fixes itself.
///
/// # Errors
/// [`LadderStall::NotYetDiscovered`] when the directory does not yet know the
/// key, its owner, or any node to reach.
pub async fn resolve(lens: &dyn DirectoryLens, any_id: &str) -> Result<Subject, LadderStall> {
    let stall = || LadderStall::NotYetDiscovered {
        fed_id: any_id.to_owned(),
    };
    let kind = IdentityKind::from_identity_type(
        lens.identity_type_of(any_id)
            .await
            .ok_or_else(stall)?
            .as_str(),
    );

    let fed_id = match &kind {
        IdentityKind::Person => any_id.to_owned(),
        // A node or agent cannot consent; its OWNER does. Resolving through the
        // owner is what makes "add frank-laptop as a contact" mean "add Frank".
        IdentityKind::Node | IdentityKind::Agent => {
            lens.owner_of(any_id).await.ok_or_else(stall)?
        }
        // A steward or accord holder is not a contactable person. TERMINAL, not
        // `NotYetDiscovered`: the latter self-resolves, so a caller would retry
        // forever against something that will never become contactable — and the
        // remedy ("wait for convergence") would be advice that never comes true.
        IdentityKind::Other(t) => {
            return Err(LadderStall::NotContactable {
                key_id: any_id.to_owned(),
                identity_type: t.clone(),
            })
        }
    };

    let nodes = lens.nodes_owned_by(&fed_id).await;
    if nodes.is_empty() {
        // Known person, nothing to reach. Distinct from "unknown key", and the
        // remedy is the same: wait for their announce to replicate.
        return Err(LadderStall::NotYetDiscovered { fed_id });
    }
    Ok(Subject {
        fed_id,
        nodes,
        resolved_from: kind,
    })
}

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
    /// The key resolves, but not to anything a person can be contacted through
    /// — a steward, an accord holder, a partner record. TERMINAL: no amount of
    /// convergence turns one of these into a contactable person, so a caller
    /// that retries is retrying forever.
    NotContactable {
        key_id: String,
        identity_type: String,
    },
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
            Self::NotContactable {
                key_id,
                identity_type,
            } => format!(
                "{key_id} is registered as identity_type={identity_type}, which is \
                 not a person and cannot hold a conversation. Contact its OWNER \
                 instead, or check that the identifier is the one you meant — this \
                 will not resolve by waiting."
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
            | Self::PriorRungIncomplete { .. }
            // Terminal by nature: a steward does not become a person.
            | Self::NotContactable { .. } => false,
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

/// The [`DirectoryLens`] over a real persist directory.
///
/// Thin on purpose: every rule that can be got wrong lives in [`resolve`] and is
/// tested without a database. This adapter only says which persist call answers
/// which question.
pub struct PersistLens<'a> {
    directory: &'a dyn ciris_persist::federation::FederationDirectory,
}

impl<'a> PersistLens<'a> {
    #[must_use]
    pub fn new(directory: &'a dyn ciris_persist::federation::FederationDirectory) -> Self {
        Self { directory }
    }
}

#[async_trait::async_trait]
impl DirectoryLens for PersistLens<'_> {
    async fn identity_type_of(&self, key_id: &str) -> Option<String> {
        // An error and an absence are the SAME answer here on purpose: both mean
        // "this node cannot say what that key is yet", and the ladder's stall for
        // that is `NotYetDiscovered`, which self-resolves. Distinguishing them
        // would produce a second diagnostic with the same remedy.
        self.directory
            .lookup_public_key(key_id)
            .await
            .ok()
            .flatten()
            .map(|record| record.identity_type)
    }

    async fn owner_of(&self, key_id: &str) -> Option<String> {
        ciris_persist::federation::admission::owner_of(self.directory, key_id)
            .await
            .ok()
            .flatten()
    }

    async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
        ciris_persist::federation::admission::nodes_owned_by(self.directory, fed_id)
            .await
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{LadderStall, Rung};

    /// A fake directory. The resolution RULES are what get this wrong, not the
    /// SQL, so the tests exercise the rules directly.
    struct FakeLens {
        types: std::collections::HashMap<String, String>,
        owners: std::collections::HashMap<String, String>,
        nodes: std::collections::HashMap<String, Vec<String>>,
    }

    #[async_trait::async_trait]
    impl super::DirectoryLens for FakeLens {
        async fn identity_type_of(&self, key_id: &str) -> Option<String> {
            self.types.get(key_id).cloned()
        }
        async fn owner_of(&self, key_id: &str) -> Option<String> {
            self.owners.get(key_id).cloned()
        }
        async fn nodes_owned_by(&self, fed_id: &str) -> Vec<String> {
            self.nodes.get(fed_id).cloned().unwrap_or_default()
        }
    }

    fn frank() -> FakeLens {
        let mut types = std::collections::HashMap::new();
        types.insert("frank-fed-aaa".into(), "user".into());
        types.insert("frank-laptop-bbb".into(), "node".into());
        types.insert("frank-agent-ccc".into(), "agent".into());
        types.insert("some-steward-ddd".into(), "steward".into());
        let mut owners = std::collections::HashMap::new();
        owners.insert("frank-laptop-bbb".into(), "frank-fed-aaa".into());
        owners.insert("frank-agent-ccc".into(), "frank-fed-aaa".into());
        let mut nodes = std::collections::HashMap::new();
        nodes.insert(
            "frank-fed-aaa".into(),
            vec!["frank-laptop-bbb".into(), "frank-phone-eee".into()],
        );
        FakeLens {
            types,
            owners,
            nodes,
        }
    }

    /// The headline DX property: all three identifier types land on the same
    /// person and the same reachable nodes. A caller holding "a Frank
    /// identifier" does not have to know which one it is.
    #[tokio::test]
    async fn any_identifier_resolves_to_the_same_person_and_nodes() {
        let lens = frank();
        for id in ["frank-fed-aaa", "frank-laptop-bbb", "frank-agent-ccc"] {
            let s = super::resolve(&lens, id).await.expect("{id} must resolve");
            assert_eq!(s.fed_id, "frank-fed-aaa", "{id} must resolve to the PERSON");
            assert_eq!(
                s.nodes.len(),
                2,
                "{id} must yield every node that reaches him"
            );
        }
    }

    /// And it records HOW it got there — a stall on a nodeID and the same stall
    /// on its owner's fedID are different situations to whoever is debugging.
    #[tokio::test]
    async fn the_subject_remembers_which_identifier_it_came_from() {
        let lens = frank();
        let from_node = super::resolve(&lens, "frank-laptop-bbb").await.unwrap();
        assert_eq!(from_node.resolved_from, super::IdentityKind::Node);
        let from_person = super::resolve(&lens, "frank-fed-aaa").await.unwrap();
        assert_eq!(from_person.resolved_from, super::IdentityKind::Person);
    }

    /// An agent cannot consent on its owner's behalf, so addressing one must
    /// resolve to the PERSON. Returning the agent would send a consent request
    /// to something that cannot accept it — and it would look like the peer
    /// simply never answered.
    #[tokio::test]
    async fn an_agent_resolves_to_its_owner_not_itself() {
        let lens = frank();
        let s = super::resolve(&lens, "frank-agent-ccc").await.unwrap();
        assert_eq!(s.fed_id, "frank-fed-aaa");
        assert!(!s.nodes.contains(&"frank-agent-ccc".to_string()));
    }

    /// A steward or accord holder is not a contactable person. Refusing beats
    /// resolving to something that looks addressable and is not.
    #[tokio::test]
    async fn a_non_contactable_identity_type_stalls_rather_than_resolving() {
        let lens = frank();
        let Err(stall) = super::resolve(&lens, "some-steward-ddd").await else {
            panic!("a steward is not a contactable person");
        };
        assert!(
            !stall.self_resolving(),
            "a steward never becomes contactable — a self-resolving stall would \
             make the caller retry forever"
        );
        assert!(stall.remedy().contains("steward"), "{}", stall.remedy());
    }

    /// A key the directory has never seen is NOT an error the operator caused —
    /// it is an unconverged directory, and it fixes itself.
    #[tokio::test]
    async fn an_unknown_key_stalls_as_not_yet_discovered_and_self_resolves() {
        let lens = frank();
        let Err(stall) = super::resolve(&lens, "stranger-zzz").await else {
            panic!("an unknown key cannot resolve");
        };
        assert!(
            stall.self_resolving(),
            "an unconverged directory must not page anyone"
        );
    }

    /// A known person with no reachable node is its own case: the remedy names
    /// THEM, not the identifier the caller happened to type.
    #[tokio::test]
    async fn a_person_with_no_nodes_stalls_naming_the_person() {
        let mut lens = frank();
        lens.nodes.clear();
        let Err(stall) = super::resolve(&lens, "frank-laptop-bbb").await else {
            panic!("no reachable node means no contact");
        };
        assert!(
            stall.remedy().contains("frank-fed-aaa"),
            "the remedy must name the person we could not reach: {}",
            stall.remedy()
        );
    }

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
