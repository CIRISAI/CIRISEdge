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
use ciris_persist::federation::register::ReplicatedKeyOutcome as KeyOutcome;
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
        match self
            .directory
            .apply_replicated_key_record(record.clone())
            .await
        {
            Ok(KeyOutcome::Inserted | KeyOutcome::Upgraded | KeyOutcome::Rebound) => {
                Ok(KeyAdmit::Admitted)
            }
            Ok(KeyOutcome::Unchanged) => Ok(KeyAdmit::Held),
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
