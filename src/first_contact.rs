//! CIRISEdge#683 — first contact on the opaque plane.
//!
//! The contract is `FSD/FIRST_CONTACT.md` §2.2. A device this node has never
//! seen sends an `OpaqueRequest` signed by a key this node does not hold, so
//! the verify would answer `UnknownKey` and drop it. The request may therefore
//! carry the sender's own self-signed key record, and this module decides
//! whether that record is admitted, **before** the envelope verify runs. The
//! verify records the nonce in the replay window before it checks the
//! signature, so a verify that failed and was re-run after admission would
//! read as a replay.
//!
//! The order is the contract:
//!
//! 1. shape: the record names the envelope's signer and is self-signed;
//! 2. rate: per sender, per link, node-wide, before any cryptography;
//! 3. proof of possession: persist's `verify_key_registration`;
//! 4. admission through the replicated Key door (the #402 door).
//!
//! The requester's half is here too: the key records and attestations a
//! first-contact answer carries ([`Introductions`]) are admitted only from a
//! solicited answer, through the same doors replication uses.
//!
//! Admission grants no trust and serves nothing. A key row is what every
//! verifier needs; Attributed still needs a transport binding and Rooted still
//! needs an acceptance.

use std::sync::Arc;

use ciris_persist::federation::attestation_apply::ReplicatedAttestationOutcome as AttestationOutcome;
use ciris_persist::federation::{FederationDirectory, SignedAttestation, SignedKeyRecord};

use crate::messages::{
    EdgeEnvelope, Introductions, MessageType, OpaqueRequestWire, OpaqueResponse, OpaqueResponseWire,
};
use crate::rate_limit::{Decision, DenyReason, Policy, Quota, RateLimiter, Ts};
use crate::replication::{EnvelopeKind, ReplicationDirectory};

/// What a first-contact opaque handler is told about the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpaqueRequestContext {
    /// The verified signer of the request.
    pub sender_key_id: String,
    /// The app-owned request discriminator.
    pub kind: u32,
    /// The opaque request payload, byte-for-byte.
    pub payload: Vec<u8>,
    /// `true` iff this request introduced its sender's key: the key was
    /// unknown here until the request's own record was admitted
    /// (`FIRST_CONTACT.md` §2.2). The host decides what a first contact may
    /// be answered with; edge only says that it is one.
    pub first_contact: bool,
}

/// A handler's answer: the response, plus the records the requester needs.
///
/// On a first-contact answer edge adds this node's own key record to
/// `introductions.keys`, so the requester can verify the answer. The host
/// adds the owner's binding to this node and, once it has minted it, the
/// owner's binding to the requester (I14).
#[derive(Debug, Clone)]
pub struct OpaqueAnswer {
    /// The response edge ships back.
    pub response: OpaqueResponse,
    /// Records the requester admits from a solicited answer.
    pub introductions: Introductions,
}

impl From<OpaqueResponse> for OpaqueAnswer {
    fn from(response: OpaqueResponse) -> Self {
        Self {
            response,
            introductions: Introductions::default(),
        }
    }
}

/// What [`crate::Edge::send_opaque_request_introducing`] returns: the response
/// and what the requester admitted from the answer's introductions.
#[derive(Debug, Clone)]
pub struct OpaqueExchange {
    /// The responder's answer.
    pub response: OpaqueResponse,
    /// What the answer's introductions did to local state.
    pub introductions: IntroductionReport,
}

/// The requester's ledger of an answer's introductions. Every carried row
/// lands in exactly one list.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IntroductionReport {
    /// Key ids newly admitted.
    pub keys_admitted: Vec<String>,
    /// Key ids already held (no work done).
    pub keys_held: Vec<String>,
    /// Attestation ids newly admitted.
    pub attestations_admitted: Vec<String>,
    /// Attestation ids already held.
    pub attestations_held: Vec<String>,
    /// `(id, reason)` for every row refused or dropped over the cap.
    pub refused: Vec<(String, String)>,
}

/// Why a first-contact request was refused. Operator-facing and never sent
/// back: a refused request gets no answer (#554 D3, a refusal that explains
/// itself is a tuning oracle).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FirstContactRefusal {
    /// The record is not the envelope signer's.
    RecordNamesOtherKey,
    /// The record is not self-signed (`scrub_key_id != key_id`).
    RecordNotSelfSigned,
    /// The sender spent its budget.
    SenderBudgetSpent,
    /// The link the request arrived on spent its budget.
    LinkBudgetSpent,
    /// The node-wide first-contact ceiling was reached.
    NodeBudgetSpent,
    /// The gate tracks as many senders or links as it will hold.
    AtCapacity,
    /// Persist's proof-of-possession gate refused the record.
    ProofOfPossessionFailed,
    /// The Key door refused the record after proof of possession.
    KeyRefused,
    /// The directory could not say whether the key is known.
    DirectoryUnreadable,
    /// No federation directory is wired, so no key can be admitted.
    NoDirectory,
}

impl FirstContactRefusal {
    /// Stable ledger label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RecordNamesOtherKey => "first_contact_record_names_other_key",
            Self::RecordNotSelfSigned => "first_contact_record_not_self_signed",
            Self::SenderBudgetSpent => "first_contact_sender_budget_spent",
            Self::LinkBudgetSpent => "first_contact_link_budget_spent",
            Self::NodeBudgetSpent => "first_contact_node_budget_spent",
            Self::AtCapacity => "first_contact_at_capacity",
            Self::ProofOfPossessionFailed => "first_contact_proof_of_possession_failed",
            Self::KeyRefused => "first_contact_key_refused",
            Self::DirectoryUnreadable => "first_contact_directory_unreadable",
            Self::NoDirectory => "first_contact_no_directory",
        }
    }
}

/// The first-contact door's verdict on one inbound frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirstContactOutcome {
    /// Not a key-carrying `OpaqueRequest`: the ordinary path, untouched.
    NotApplicable,
    /// The signer is already known; the carried record is ignored.
    KnownKey,
    /// The signer's key was admitted by this request.
    Admitted { sender_key_id: String },
    /// Refused: the frame is dropped.
    Refused(FirstContactRefusal),
}

impl FirstContactOutcome {
    /// Whether the frame is dropped. A node with no federation directory
    /// cannot admit a key, but it can still verify one it holds, so a closed
    /// door is counted and the frame goes on to the verify, which drops an
    /// unknown key as it always did.
    pub(crate) fn drops(&self) -> bool {
        matches!(self, Self::Refused(r) if *r != FirstContactRefusal::NoDirectory)
    }

    /// Ledger label, or `None` for a frame the door never looked at.
    pub(crate) fn label(&self) -> Option<&'static str> {
        match self {
            Self::NotApplicable => None,
            Self::KnownKey => Some("first_contact_known_key"),
            Self::Admitted { .. } => Some("first_contact_admitted"),
            Self::Refused(r) => Some(r.as_str()),
        }
    }
}

/// The three first-contact budgets (`FIRST_CONTACT.md` §2.2 step 2), one
/// instance per node. A thin face over [`RateLimiter`], like
/// [`crate::invite_gate::InviteGate`].
///
/// A per-sender budget alone fails under identity rotation (every request a
/// fresh key), which is the shape a flood of first contacts takes; the
/// node-wide ceiling is the bound that holds there, and it is what caps the
/// key rows a stranger can make this node write.
#[derive(Debug)]
pub struct FirstContactGate {
    sender: RateLimiter,
    link: RateLimiter,
    node: RateLimiter,
}

impl FirstContactGate {
    /// A new device retries while a person decides; three tries per ten
    /// minutes covers that and nothing more.
    pub const SENDER_BUDGET: Quota = Quota::new(3, 600);
    /// The slow-drain ceiling for one sender.
    pub const SENDER_DAILY: Quota = Quota::new(12, 86_400);
    /// One link carries one device's retries, with room for a second.
    pub const LINK_BUDGET: Quota = Quota::new(6, 600);
    /// Node-wide: how many strangers' keys this node admits per hour.
    pub const NODE_BUDGET: Quota = Quota::new(32, 3_600);
    /// How many senders and links each budget tracks.
    pub const TRACKED_CAP: usize = 4_096;

    const NODE_KEY: &'static str = "node";

    #[must_use]
    pub fn new() -> Self {
        let sender = Policy::quota(
            Self::SENDER_BUDGET.permits,
            Self::SENDER_BUDGET.window_secs,
            Self::TRACKED_CAP,
        )
        .with_long_windows([Some(Self::SENDER_DAILY), None]);
        Self {
            sender: RateLimiter::new(sender),
            link: RateLimiter::new(Policy::quota(
                Self::LINK_BUDGET.permits,
                Self::LINK_BUDGET.window_secs,
                Self::TRACKED_CAP,
            )),
            node: RateLimiter::new(Policy::quota(
                Self::NODE_BUDGET.permits,
                Self::NODE_BUDGET.window_secs,
                1,
            )),
        }
    }

    /// Spend one first contact from `sender` on `link`. Checked sender, then
    /// link, then node, so a sender or link over its own budget never draws
    /// down the node-wide one.
    ///
    /// # Errors
    ///
    /// The budget that refused.
    pub fn admit(&mut self, sender: &str, link: &str, now: Ts) -> Result<(), FirstContactRefusal> {
        fn refusal(d: &Decision, spent: FirstContactRefusal) -> Option<FirstContactRefusal> {
            match d {
                Decision::Allow { .. } => None,
                Decision::Deny {
                    reason: DenyReason::AtCapacity,
                } => Some(FirstContactRefusal::AtCapacity),
                Decision::Deny { .. } => Some(spent),
            }
        }
        let d = self
            .sender
            .check_from(&sender.to_owned(), Some(sender), now);
        if let Some(r) = refusal(&d, FirstContactRefusal::SenderBudgetSpent) {
            return Err(r);
        }
        let d = self.link.check_from(&link.to_owned(), Some(link), now);
        if let Some(r) = refusal(&d, FirstContactRefusal::LinkBudgetSpent) {
            return Err(r);
        }
        let d = self.node.check(&Self::NODE_KEY.to_owned(), now);
        if let Some(r) = refusal(&d, FirstContactRefusal::NodeBudgetSpent) {
            return Err(r);
        }
        Ok(())
    }
}

impl Default for FirstContactGate {
    fn default() -> Self {
        Self::new()
    }
}

/// At most this many key records are admitted from one answer.
pub const MAX_INTRODUCED_KEYS: usize = 8;
/// At most this many attestations are admitted from one answer.
pub const MAX_INTRODUCED_ATTESTATIONS: usize = 16;

/// The persist doors a first contact is admitted through.
///
/// `replication` is the replication bridge when a runtime is installed: the
/// SAME apply door replication uses, so the bridge's memos (the owner memo the
/// §2.1 announce gate reads) are invalidated on admit. Without a runtime there
/// is no bridge and no memo, and the directory is called directly with the
/// same persist entry points the bridge would call.
#[derive(Clone)]
pub(crate) struct AdmissionDoors {
    pub(crate) directory: Arc<dyn FederationDirectory>,
    pub(crate) replication: Option<Arc<dyn ReplicationDirectory>>,
}

/// A key the Key door accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeyAdmit {
    /// A new row.
    Admitted,
    /// The row was already held.
    Held,
}

impl AdmissionDoors {
    async fn is_known(&self, key_id: &str) -> Result<bool, FirstContactRefusal> {
        self.directory
            .lookup_public_key(key_id)
            .await
            .map(|row| row.is_some())
            .map_err(|e| {
                tracing::warn!(
                    key_id,
                    error = %e,
                    "first contact: key lookup failed (CIRISEdge#683)"
                );
                FirstContactRefusal::DirectoryUnreadable
            })
    }

    /// Proof of possession, then the replicated Key door.
    pub(crate) async fn admit_key(
        &self,
        record: &SignedKeyRecord,
    ) -> Result<KeyAdmit, FirstContactRefusal> {
        if let Err(e) = ciris_persist::federation::verify_key_registration(
            self.directory.as_ref(),
            &record.record,
        )
        .await
        {
            tracing::warn!(
                key_id = %record.record.key_id,
                error = %e,
                "first contact: proof of possession refused (CIRISEdge#683)"
            );
            return Err(FirstContactRefusal::ProofOfPossessionFailed);
        }
        if let Some(bridge) = &self.replication {
            let bytes = serde_json::to_vec(record).map_err(|_| FirstContactRefusal::KeyRefused)?;
            let outcome = bridge
                .apply_envelope_bytes(EnvelopeKind::Key, &bytes, None)
                .await;
            return match outcome {
                crate::replication::summary::ApplyOutcome::Admitted => Ok(KeyAdmit::Admitted),
                crate::replication::summary::ApplyOutcome::Duplicate => Ok(KeyAdmit::Held),
                other => {
                    tracing::warn!(
                        key_id = %record.record.key_id,
                        outcome = ?other,
                        "first contact: the Key door refused a proven record (CIRISEdge#683)"
                    );
                    Err(FirstContactRefusal::KeyRefused)
                }
            };
        }
        // One mapping with the bridge door above: a persist outcome variant
        // added later (v54's `ScrubsRehydrated`) lands in the bridge's
        // exhaustive match, not in this arm's catch-all as a refusal.
        let result = self
            .directory
            .apply_replicated_key_record(record.clone())
            .await;
        match crate::replication::bridge::key_outcome_to_apply(result, "first-contact").0 {
            crate::replication::summary::ApplyOutcome::Admitted => Ok(KeyAdmit::Admitted),
            crate::replication::summary::ApplyOutcome::Duplicate => Ok(KeyAdmit::Held),
            other => {
                tracing::warn!(
                    key_id = %record.record.key_id,
                    outcome = ?other,
                    "first contact: the Key door refused a proven record (CIRISEdge#683)"
                );
                Err(FirstContactRefusal::KeyRefused)
            }
        }
    }

    /// The attestation apply door, unattributed (the stranger door). `Ok(true)`
    /// for a new row, `Ok(false)` for one already held.
    pub(crate) async fn admit_attestation(&self, att: &SignedAttestation) -> Result<bool, String> {
        if let Some(bridge) = &self.replication {
            let bytes = serde_json::to_vec(att).map_err(|e| format!("serialize: {e}"))?;
            return match bridge
                .apply_envelope_bytes(EnvelopeKind::Attestation, &bytes, None)
                .await
            {
                crate::replication::summary::ApplyOutcome::Admitted => Ok(true),
                crate::replication::summary::ApplyOutcome::Duplicate => Ok(false),
                other => Err(format!("{other:?}")),
            };
        }
        match self
            .directory
            .apply_replicated_attestation(att.clone())
            .await
        {
            Ok(AttestationOutcome::Inserted) => Ok(true),
            Ok(AttestationOutcome::Unchanged | AttestationOutcome::Deduplicated) => Ok(false),
            Ok(other) => Err(format!("{other:?}")),
            Err(e) => Err(e.to_string()),
        }
    }
}

// ── CIRISEdge#727 — the owner-binding rung (`FSD/FIRST_CONTACT.md` §2.1.1) ──

/// The most owner-binding rows one push may carry. A node pushes exactly ONE
/// (its own); the cap bounds what a stranger's push costs before it is refused
/// by name, and is small on purpose.
pub const MAX_OWNER_BINDING_PUSH: usize = 4;

/// Why an owner-binding push (or one row of it) was refused. Operator-facing,
/// counted under `first_contact_outcomes`, never answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerBindingRefusal {
    /// More than [`MAX_OWNER_BINDING_PUSH`] rows; nothing is read.
    DeliverOversized,
    /// This node's own owner could not be resolved (a read error, or an
    /// ambiguous owner — CC 3.2 cardinality ≠ 1 fails closed).
    OwnerUnresolved,
    /// This node has no owner, so no binding is self-authenticating to it.
    ReceiverUnowned,
    /// The row's attester is not this node's owner: a stranger's household.
    /// Decided before any cryptography.
    NotOwnOwner,
    /// The attester IS this node's owner, but the signature does not verify
    /// against the owner key this node holds.
    SignatureInvalid,
    /// A row that passed the shape check could not be deserialized as a row.
    Malformed,
    /// Persist's replicated-attestation door refused it (its own gates: the
    /// single-owner rule, quota, tier ingest).
    DoorRefused,
}

impl OwnerBindingRefusal {
    /// Stable ledger label.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DeliverOversized => "owner_binding_deliver_oversized",
            Self::OwnerUnresolved => "owner_binding_owner_unresolved",
            Self::ReceiverUnowned => "owner_binding_receiver_unowned",
            Self::NotOwnOwner => "owner_binding_not_own_owner",
            Self::SignatureInvalid => "owner_binding_signature_invalid",
            Self::Malformed => "owner_binding_malformed",
            Self::DoorRefused => "owner_binding_door_refused",
        }
    }
}

/// Ledger label for a row the door admitted as new.
pub const OWNER_BINDING_ADMITTED: &str = "owner_binding_admitted";
/// Ledger label for a row this node already held.
pub const OWNER_BINDING_HELD: &str = "owner_binding_held";
/// Ledger label (sender side) for a binding pushed complete on a dialed link.
pub const OWNER_BINDING_PUSHED: &str = "owner_binding_pushed";
/// Ledger label (sender side) for a push the link Channel did not complete.
pub const OWNER_BINDING_PUSH_INCOMPLETE: &str = "owner_binding_push_incomplete";

/// Ledger label (receiver side) for this node's own binding sent back on the
/// reply path of a link a sibling's binding was NEWLY admitted on.
pub const OWNER_BINDING_ANSWERED: &str = "owner_binding_answered";
/// Ledger label (receiver side) for an answer the transport could not send.
pub const OWNER_BINDING_ANSWER_FAILED: &str = "owner_binding_answer_failed";

/// The rung's verdict on one inbound frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwnerBindingOutcome {
    /// Not an un-attributed owner-binding push: the ordinary path, untouched.
    NotApplicable,
    /// The frame was this rung's and is consumed here, whatever each row's
    /// fate. `refused` lists every row (or the frame) refused, by name;
    /// `subjects` the `attested_key_id` of every row admitted as NEW.
    Consumed {
        admitted: usize,
        held: usize,
        refused: Vec<OwnerBindingRefusal>,
        subjects: Vec<String>,
    },
}

/// What the receiver needs to ANSWER a sibling (§2.1.1 rule 2, second
/// clause): the transport whose reply path the frame names, and this node's
/// own binding.
struct OwnerBindingAnswer {
    transport: Arc<dyn crate::transport::Transport>,
    own: Arc<dyn OwnOwnerBindingSource>,
}

/// **The receiver's half of the owner-binding rung** (§2.1.1 rule 1).
///
/// An owner-binding `O → X` arriving on an un-attributed link is admitted
/// iff its attester is THIS node's own owner (`owner_of(local)`, persist's
/// single-valued resolver — never a sorted `.next()`) and its signature
/// verifies against the owner key this node holds
/// ([`verify_row_hybrid_signature`](ciris_persist::federation::verify_row_hybrid_signature),
/// which resolves the attester's REGISTERED keys). It then goes through the
/// same apply door #683's introductions use — the replication bridge's
/// unattributed `apply_envelope_bytes`, so the #682 owner memo is invalidated
/// on admit — or, with no runtime, persist's `apply_replicated_attestation`
/// directly. Every persist admission gate stays in front of the write.
///
/// A row whose attester is not this node's owner is refused BEFORE any
/// cryptography (`owner_binding_not_own_owner`): a stranger's push costs one
/// memoised owner read and a string compare. Nothing is stored, nothing is
/// answered, and the refusal names itself in `first_contact_outcomes`.
///
/// This gate reads the frame's bytes only; it never consults the link's
/// identity. The row is self-authenticating to its receiver or it is not.
pub struct OwnerBindingCarveOut {
    local_key_id: String,
    doors: AdmissionDoors,
    metrics: Option<crate::observability::EdgeMetrics>,
    answer: Option<OwnerBindingAnswer>,
}

impl std::fmt::Debug for OwnerBindingCarveOut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerBindingCarveOut")
            .field("local_key_id", &self.local_key_id)
            .field("bridge", &self.doors.replication.is_some())
            .field("answers", &self.answer.is_some())
            .finish_non_exhaustive()
    }
}

impl OwnerBindingCarveOut {
    /// `replication` is the runtime's bridge when one is installed (the memo
    /// invalidation lives there); `None` calls persist directly.
    #[must_use]
    pub fn new(
        local_key_id: impl Into<String>,
        directory: Arc<dyn FederationDirectory>,
        replication: Option<Arc<dyn ReplicationDirectory>>,
        metrics: Option<crate::observability::EdgeMetrics>,
    ) -> Self {
        Self {
            local_key_id: local_key_id.into(),
            doors: AdmissionDoors {
                directory,
                replication,
            },
            metrics,
            answer: None,
        }
    }

    /// **The answer** (§2.1.1 rule 2, second clause). Having NEWLY admitted a
    /// sibling's binding on a link, this node sends its own binding back on
    /// that link's reply path ([`Transport::send_on_reply_path`], the #683
    /// answer shape). The recipient is proven to be its owner's node — a
    /// stronger warrant than a dial. Answered only on `admitted`, never on
    /// `held`, so two siblings exchange exactly one binding each and stop.
    ///
    /// Why it is needed at all: the initiator direction does not always dial.
    /// A node whose sends ride the link its sibling opened (#531 link reuse)
    /// never reaches the dial-path push, so without the answer the exchange
    /// is one-way and the sibling withholds its route forever.
    ///
    /// [`Transport::send_on_reply_path`]: crate::transport::Transport::send_on_reply_path
    #[must_use]
    pub fn with_answer(
        mut self,
        transport: Arc<dyn crate::transport::Transport>,
        own: Arc<dyn OwnOwnerBindingSource>,
    ) -> Self {
        self.answer = Some(OwnerBindingAnswer { transport, own });
        self
    }

    /// This node's key id — the `self` whose owner decides admission.
    #[must_use]
    pub fn local_key_id(&self) -> &str {
        &self.local_key_id
    }

    fn count(&self, label: &'static str) {
        if let Some(m) = &self.metrics {
            m.inc_first_contact(label);
        }
    }

    /// Judge one inbound frame. Applies only to an **un-attributed** CRPL
    /// `Deliver` of the owner-binding push shape
    /// ([`DeliverMessage::is_owner_binding_push`]); an attributed frame takes
    /// the ordinary path whatever it carries (rule 1 admits it there too, on
    /// the sync door).
    pub async fn admit_frame(&self, frame: &crate::transport::InboundFrame) -> OwnerBindingOutcome {
        if frame.source_key_id.is_some() {
            return OwnerBindingOutcome::NotApplicable;
        }
        let Ok(Some(crate::replication::ReplicationMessage::Deliver(deliver))) =
            crate::replication::wire_frame::try_unwrap(&frame.envelope_bytes)
        else {
            return OwnerBindingOutcome::NotApplicable;
        };
        let outcome = self.admit_deliver(&deliver).await;
        if let OwnerBindingOutcome::Consumed { .. } = &outcome {
            // CIRISEdge#853 — the owner-binding stage of this link's link-up.
            if let (Some(m), Some(path)) = (&self.metrics, frame.reply_path.as_ref()) {
                if path.transport() == crate::transport::TransportId::RETICULUM_RS {
                    m.responder_link_up_stage(
                        path.token(),
                        crate::observability::LINK_UP_STAGE_OWNER_BINDING,
                    );
                }
            }
        }
        if let OwnerBindingOutcome::Consumed { subjects, .. } = &outcome {
            // The answer rides only a NEW admission (never `held`), and only
            // the reply path the frame names — never a by-key dial of our
            // own, which the transport's fallback would attempt for a path
            // that is gone. `subjects[0]` is the sibling that pushed (a node
            // pushes only its own binding); the id is the transport's
            // by-key fallback target and nothing else.
            if let (Some(answer), Some(path), Some(sibling)) = (
                self.answer.as_ref(),
                frame.reply_path.as_ref(),
                subjects.first(),
            ) {
                self.answer_on(answer, path, sibling).await;
            }
        }
        outcome
    }

    async fn answer_on(
        &self,
        answer: &OwnerBindingAnswer,
        path: &crate::transport::ReplyPath,
        sibling: &str,
    ) {
        let Some(frame) = answer.own.own_owner_binding_frame().await else {
            return; // unowned or ambiguous: nothing of ours to say
        };
        match answer
            .transport
            .send_on_reply_path(sibling, path, &frame)
            .await
        {
            Ok(_) => {
                self.count(OWNER_BINDING_ANSWERED);
                tracing::debug!(
                    local = %self.local_key_id,
                    sibling,
                    "own owner-binding ANSWERED on the sibling's reply path (CIRISEdge#727)"
                );
            }
            Err(e) => {
                self.count(OWNER_BINDING_ANSWER_FAILED);
                tracing::warn!(
                    local = %self.local_key_id,
                    sibling,
                    error = %e,
                    "own owner-binding answer failed — the sibling re-pushes on its next dial \
                     (CIRISEdge#727)"
                );
            }
        }
    }

    /// Judge one Deliver as if it arrived un-attributed. The frame-level door
    /// above calls this; tests call it directly.
    pub async fn admit_deliver(
        &self,
        deliver: &crate::replication::DeliverMessage,
    ) -> OwnerBindingOutcome {
        use ciris_persist::federation::admission::owner_of;

        if !deliver.is_owner_binding_push() {
            return OwnerBindingOutcome::NotApplicable;
        }
        let mut refused = Vec::new();
        let refuse_frame = |this: &Self, r: OwnerBindingRefusal, detail: &str| {
            this.count(r.as_str());
            tracing::warn!(
                local = %this.local_key_id,
                refusal = r.as_str(),
                detail,
                envelopes = deliver.envelopes.len(),
                "owner-binding push REFUSED — nothing stored (CIRISEdge#727)"
            );
            OwnerBindingOutcome::Consumed {
                admitted: 0,
                held: 0,
                refused: vec![r],
                subjects: Vec::new(),
            }
        };
        if deliver.envelopes.len() > MAX_OWNER_BINDING_PUSH {
            return refuse_frame(
                self,
                OwnerBindingRefusal::DeliverOversized,
                "more rows than one node's own binding could be",
            );
        }
        let owner = match owner_of(self.doors.directory.as_ref(), &self.local_key_id).await {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                return refuse_frame(
                    self,
                    OwnerBindingRefusal::ReceiverUnowned,
                    "this node has no owner, so no binding is self-authenticating to it",
                );
            }
            Err(e) => {
                return refuse_frame(self, OwnerBindingRefusal::OwnerUnresolved, &e.to_string());
            }
        };
        let mut admitted = 0usize;
        let mut held = 0usize;
        let mut subjects: Vec<String> = Vec::new();
        for bytes in &deliver.envelopes {
            match self.admit_row(&owner, bytes).await {
                Ok(RowAdmit::Admitted(subject)) => {
                    admitted += 1;
                    subjects.push(subject);
                }
                Ok(RowAdmit::Held) => held += 1,
                Err(r) => {
                    self.count(r.as_str());
                    refused.push(r);
                }
            }
        }
        OwnerBindingOutcome::Consumed {
            admitted,
            held,
            refused,
            subjects,
        }
    }

    /// One row of a push, against `owner` (= `owner_of(local)`, already
    /// resolved). The order is the rule: attester field first (the privacy
    /// bound — no cryptography for a stranger's row), then the signature
    /// against the held owner key, then persist's door.
    async fn admit_row(&self, owner: &str, bytes: &[u8]) -> Result<RowAdmit, OwnerBindingRefusal> {
        let signed = serde_json::from_slice::<SignedAttestation>(bytes)
            .map_err(|_| OwnerBindingRefusal::Malformed)?;
        let row = &signed.attestation;
        // The privacy bound (rule 3): decided on the attester field alone,
        // before a single signature is checked.
        if row.attesting_key_id != owner {
            tracing::debug!(
                local = %self.local_key_id,
                attester = %row.attesting_key_id,
                subject = %row.attested_key_id,
                "owner-binding push refused: not this node's owner (CIRISEdge#727)"
            );
            return Err(OwnerBindingRefusal::NotOwnOwner);
        }
        // Rule 1's cryptographic half: against the owner key THIS node holds
        // (persist resolves the attester's registered keys; an attester it
        // does not hold is a refusal, never a pass).
        if let Err(e) = ciris_persist::federation::verify_row_hybrid_signature(
            self.doors.directory.as_ref(),
            row,
        )
        .await
        {
            tracing::warn!(
                local = %self.local_key_id,
                attestation_id = %row.attestation_id,
                error = %e,
                "owner-binding push refused: the signature does not verify against the held \
                 owner key (CIRISEdge#727)"
            );
            return Err(OwnerBindingRefusal::SignatureInvalid);
        }
        match self.doors.admit_attestation(&signed).await {
            Ok(true) => {
                self.count(OWNER_BINDING_ADMITTED);
                tracing::info!(
                    local = %self.local_key_id,
                    attestation_id = %row.attestation_id,
                    subject = %row.attested_key_id,
                    "owner-binding ADMITTED on the owner-binding rung — the announce memo is \
                     invalidated; the next round serves this owner's node (CIRISEdge#727)"
                );
                Ok(RowAdmit::Admitted(row.attested_key_id.clone()))
            }
            Ok(false) => {
                self.count(OWNER_BINDING_HELD);
                Ok(RowAdmit::Held)
            }
            Err(reason) => {
                tracing::warn!(
                    local = %self.local_key_id,
                    attestation_id = %row.attestation_id,
                    reason,
                    "owner-binding push refused by persist's door (CIRISEdge#727)"
                );
                Err(OwnerBindingRefusal::DoorRefused)
            }
        }
    }
}

/// One row's fate on the rung (the refusals are the `Err` arm).
enum RowAdmit {
    /// A new row; carries its `attested_key_id` (the sibling that pushed).
    Admitted(String),
    /// Already held.
    Held,
}

/// **The sender's half of the owner-binding rung** (§2.1.1 rule 2): the
/// frame a transport pushes on a link this node DIALED, right after the
/// announce and bundle. `None` means push nothing — the node is unowned, its
/// owner is ambiguous (fail-closed), or it holds no live binding about itself.
///
/// The transport asks on every dial and never caches: the binding is
/// directory state (a claim, an announce, a withdrawal all move it).
#[async_trait::async_trait]
pub trait OwnOwnerBindingSource: Send + Sync {
    /// The CRPL `Deliver` (kind `Attestation`, exactly one envelope: this
    /// node's own live owner-binding), or `None`.
    async fn own_owner_binding_frame(&self) -> Option<Vec<u8>>;
}

/// The production [`OwnOwnerBindingSource`]: this node's live owner-binding
/// read from its federation directory. "Live" is judged the way the bridge's
/// #682 announce walk judges it: not retired by an admitted `withdraws` /
/// `recants` (persist's `precedence::retired_ids`), not expired; the attester
/// must be `owner_of(local)` (persist's single-valued resolver) and the
/// subject this node. Among several live rows the latest `asserted_at` wins.
pub struct DirectoryOwnerBinding {
    directory: Arc<dyn FederationDirectory>,
    local_key_id: String,
}

impl DirectoryOwnerBinding {
    #[must_use]
    pub fn new(directory: Arc<dyn FederationDirectory>, local_key_id: impl Into<String>) -> Self {
        Self {
            directory,
            local_key_id: local_key_id.into(),
        }
    }

    /// The row itself (the frame builder's input), for callers that want to
    /// inspect what would be pushed.
    pub async fn own_owner_binding(&self) -> Option<ciris_persist::federation::Attestation> {
        use ciris_persist::federation::admission::{is_owner_binding_envelope, owner_of};
        use ciris_persist::federation::types::attestation_type;

        let owner = match owner_of(self.directory.as_ref(), &self.local_key_id).await {
            Ok(Some(o)) => o,
            Ok(None) => return None,
            Err(e) => {
                tracing::debug!(
                    local = %self.local_key_id,
                    error = %e,
                    "own owner-binding: owner unresolved — nothing pushed (CIRISEdge#727)"
                );
                return None;
            }
        };
        let rows = match self
            .directory
            .list_attestations_for(&self.local_key_id)
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::debug!(
                    local = %self.local_key_id,
                    error = %e,
                    "own owner-binding: directory unreadable — nothing pushed (CIRISEdge#727)"
                );
                return None;
            }
        };
        let refs: Vec<&ciris_persist::federation::Attestation> = rows.iter().collect();
        let retired = ciris_persist::federation::precedence::retired_ids(&refs);
        let now = chrono::Utc::now();
        rows.iter()
            .filter(|r| {
                r.attestation_type == attestation_type::DELEGATES_TO
                    && r.attesting_key_id == owner
                    && r.attested_key_id == self.local_key_id
                    && is_owner_binding_envelope(&r.attestation_envelope)
                    && !retired.contains(r.attestation_id.as_str())
                    && !r.expires_at.is_some_and(|exp| exp <= now)
            })
            .max_by_key(|r| r.asserted_at)
            .cloned()
    }
}

#[async_trait::async_trait]
impl OwnOwnerBindingSource for DirectoryOwnerBinding {
    async fn own_owner_binding_frame(&self) -> Option<Vec<u8>> {
        let row = self.own_owner_binding().await?;
        let bytes = serde_json::to_vec(&SignedAttestation { attestation: row }).ok()?;
        Some(crate::replication::wire_frame::wrap_for_kind(
            &crate::replication::ReplicationMessage::Deliver(crate::replication::DeliverMessage {
                kind: EnvelopeKind::Attestation,
                envelopes: vec![bytes],
            }),
        ))
    }
}

/// Find `needle` in `hay` — the cheap prefilter that keeps the door off every
/// frame that does not name the field it reads.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    memchr::memmem::find(hay, needle).is_some()
}

/// The envelope and the key record a first-contact `OpaqueRequest` carries, or
/// `None` for every other frame.
pub(crate) fn carried_key_record(bytes: &[u8]) -> Option<(EdgeEnvelope, SignedKeyRecord)> {
    if !contains(bytes, b"\"key_record\"") {
        return None;
    }
    let envelope: EdgeEnvelope = serde_json::from_slice(bytes).ok()?;
    if envelope.message_type != MessageType::OpaqueRequest {
        return None;
    }
    let body: OpaqueRequestWire = serde_json::from_str(envelope.body.get()).ok()?;
    let record = body.key_record?;
    Some((envelope, record))
}

/// The envelope and the introductions an `OpaqueResponse` carries, or `None`.
pub(crate) fn carried_introductions(bytes: &[u8]) -> Option<(EdgeEnvelope, Introductions)> {
    if !contains(bytes, b"\"introductions\"") {
        return None;
    }
    let envelope: EdgeEnvelope = serde_json::from_slice(bytes).ok()?;
    if envelope.message_type != MessageType::OpaqueResponse {
        return None;
    }
    let body: OpaqueResponseWire = serde_json::from_str(envelope.body.get()).ok()?;
    if body.introductions.is_empty() {
        return None;
    }
    Some((envelope, body.introductions))
}

/// The receiver's door (`FIRST_CONTACT.md` §2.2 steps 0–4), run before the
/// envelope verify. `link` names the budget bucket of the path the frame
/// arrived on.
pub(crate) async fn admit_first_contact(
    bytes: &[u8],
    link: &str,
    doors: Option<&AdmissionDoors>,
    gate: &std::sync::Mutex<FirstContactGate>,
    now: Ts,
) -> FirstContactOutcome {
    let Some((envelope, record)) = carried_key_record(bytes) else {
        return FirstContactOutcome::NotApplicable;
    };
    let Some(doors) = doors else {
        return FirstContactOutcome::Refused(FirstContactRefusal::NoDirectory);
    };
    let sender = envelope.signing_key_id;
    match doors.is_known(&sender).await {
        Ok(true) => return FirstContactOutcome::KnownKey,
        Ok(false) => {}
        Err(r) => return FirstContactOutcome::Refused(r),
    }
    if record.record.key_id != sender {
        return FirstContactOutcome::Refused(FirstContactRefusal::RecordNamesOtherKey);
    }
    if record.record.scrub_key_id != record.record.key_id {
        return FirstContactOutcome::Refused(FirstContactRefusal::RecordNotSelfSigned);
    }
    if let Err(r) = gate
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .admit(&sender, link, now)
    {
        return FirstContactOutcome::Refused(r);
    }
    match doors.admit_key(&record).await {
        // `Held` here is a lost race with another path admitting the same key
        // between the lookup and the door: the key is known either way.
        Ok(KeyAdmit::Admitted | KeyAdmit::Held) => FirstContactOutcome::Admitted {
            sender_key_id: sender,
        },
        Err(r) => FirstContactOutcome::Refused(r),
    }
}

/// The requester's key half (§2.2 requester step 1): each carried key, known
/// ones skipped, unknown ones proven and admitted. Runs before the answer is
/// verified. Capped at [`MAX_INTRODUCED_KEYS`].
pub(crate) async fn admit_introduced_keys(
    doors: &AdmissionDoors,
    keys: &[SignedKeyRecord],
    report: &mut IntroductionReport,
) {
    for (i, record) in keys.iter().enumerate() {
        let key_id = record.record.key_id.clone();
        if i >= MAX_INTRODUCED_KEYS {
            report.refused.push((key_id, "over_key_cap".to_string()));
            continue;
        }
        match doors.is_known(&key_id).await {
            Ok(true) => {
                report.keys_held.push(key_id);
                continue;
            }
            Ok(false) => {}
            Err(r) => {
                report.refused.push((key_id, r.as_str().to_string()));
                continue;
            }
        }
        match doors.admit_key(record).await {
            Ok(KeyAdmit::Admitted) => report.keys_admitted.push(key_id),
            Ok(KeyAdmit::Held) => report.keys_held.push(key_id),
            Err(r) => report.refused.push((key_id, r.as_str().to_string())),
        }
    }
}

/// The requester's attestation half (§2.2 requester step 3), after the answer
/// is verified. Capped at [`MAX_INTRODUCED_ATTESTATIONS`].
pub(crate) async fn admit_introduced_attestations(
    doors: &AdmissionDoors,
    attestations: &[SignedAttestation],
    report: &mut IntroductionReport,
) {
    for (i, att) in attestations.iter().enumerate() {
        let id = att.attestation.attestation_id.clone();
        if i >= MAX_INTRODUCED_ATTESTATIONS {
            report
                .refused
                .push((id, "over_attestation_cap".to_string()));
            continue;
        }
        match doors.admit_attestation(att).await {
            Ok(true) => report.attestations_admitted.push(id),
            Ok(false) => report.attestations_held.push(id),
            Err(reason) => {
                tracing::warn!(
                    attestation_id = %id,
                    reason = %reason,
                    "first contact: an introduced attestation was refused (CIRISEdge#683)"
                );
                report.refused.push((id, reason));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sender_gets_three_tries_per_window_683() {
        let mut g = FirstContactGate::new();
        for i in 0..3 {
            assert_eq!(g.admit("s", &format!("l{i}"), 0), Ok(()));
        }
        assert_eq!(
            g.admit("s", "l9", 0),
            Err(FirstContactRefusal::SenderBudgetSpent)
        );
        assert_eq!(g.admit("s", "l9", 601), Ok(()), "the window refills");
    }

    #[test]
    fn one_link_cannot_carry_a_rotating_flood_683() {
        let mut g = FirstContactGate::new();
        for i in 0..6 {
            assert_eq!(g.admit(&format!("s{i}"), "link", 0), Ok(()));
        }
        assert_eq!(
            g.admit("s-fresh", "link", 0),
            Err(FirstContactRefusal::LinkBudgetSpent),
            "fresh keys on one link are still one link"
        );
    }

    #[test]
    fn the_node_ceiling_holds_under_identity_and_link_rotation_683() {
        let mut g = FirstContactGate::new();
        for i in 0..32 {
            assert_eq!(g.admit(&format!("s{i}"), &format!("l{i}"), 0), Ok(()));
        }
        assert_eq!(
            g.admit("s-new", "l-new", 0),
            Err(FirstContactRefusal::NodeBudgetSpent),
            "every sender and link fresh, and the node still stops"
        );
    }

    #[test]
    fn a_refused_sender_does_not_draw_down_the_node_budget_683() {
        let mut g = FirstContactGate::new();
        for _ in 0..3 {
            g.admit("s", "l", 0).unwrap();
        }
        for _ in 0..100 {
            let _ = g.admit("s", "l", 0);
        }
        for i in 0..29 {
            assert_eq!(
                g.admit(&format!("o{i}"), &format!("m{i}"), 0),
                Ok(()),
                "the flooding sender's refusals cost the node nothing"
            );
        }
    }

    #[test]
    fn refusal_labels_are_stable_683() {
        assert_eq!(
            FirstContactRefusal::ProofOfPossessionFailed.as_str(),
            "first_contact_proof_of_possession_failed"
        );
        assert_eq!(
            FirstContactOutcome::Admitted {
                sender_key_id: "x".into()
            }
            .label(),
            Some("first_contact_admitted")
        );
        assert_eq!(FirstContactOutcome::NotApplicable.label(), None);
    }

    #[test]
    fn only_a_key_carrying_opaque_request_opens_the_door_683() {
        assert!(carried_key_record(b"{\"message_type\":\"opaque_event\"}").is_none());
        assert!(carried_key_record(b"not json \"key_record\"").is_none());
    }
}
