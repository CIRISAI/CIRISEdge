//! **Decision-relevant rows: which ones landed, and from where to rebuild**
//! (CIRISEdge v44; CIRISConstitution#198 §5; `FSD/QUORUM_AND_PENDING_DECISIONS.md` §3).
//!
//! The pending-decision queue is CIRISServer's, built over persist's folds.
//! Edge only tells the host **which rows to re-read**:
//!
//! - an **event** ([`DecisionRowRef`] on [`DecisionRowSignal`]) when a
//!   decision-relevant row is admitted through the replication choke, when
//!   the bridge's own widener writes a widening, or when the host reports a
//!   local write (`note_local_write`): local writes bypass the choke;
//! - a **cursor** ([`DecisionCursor`], persist's `(admitted_at,
//!   attestation_id)` serve position) and [`decision_rows_since`], so the host
//!   rebuilds after a suspend, a restart or a lagged receiver with the same
//!   rows the events would have named.
//!
//! Edge evaluates nothing here: no standing, no tally, no window. A row is on
//! this node because persist's audience gate admitted it (CC 5.2); whether
//! this person has standing on it is a persist fold the host asks for.

use ciris_persist::federation::{Attestation, FederationDirectory};
use serde::{Deserialize, Serialize};

/// What a decision-relevant row is, by the namespace family it belongs to.
/// The list is closed and documented: every variant names its prefixes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionRowKind {
    /// `membership:proposal:` — an invitation (or a standing proposal).
    MembershipProposal,
    /// `membership:acceptance:` / `membership:decline:` — the invitee's
    /// answer: the second voice on an admission.
    MembershipReply,
    /// `objection:` — a two-path proposal, assent or raised objection (CC
    /// 3.1.9.2).
    Objection,
    /// `group:roster:`, `membership:widening:`, `membership:removal:`,
    /// `membership:resignation:` — a roster event that LANDED (persist
    /// admitted it).
    RosterLanded,
    /// `moderation:` — a moderation act (CC 4.5.5 / 4.5.13).
    ModerationAction,
    /// attestation type or dimension `accord:invoke:` — an accord halt,
    /// notify or drill (CC 4.2.1.1).
    AccordHalt,
    /// `consent:replication:` — a contact grant (a contact request when it
    /// names this node's person and is not reciprocated: the server's fold).
    ContactRequest,
    /// `cosign:pending:` — a widening or removal HELD for cosignatures (persist
    /// 61.3.0, CIRISPersist#1252; CC 3.3.4, CC 3.1.3 `cosign:{state}`): the
    /// event its primary signed, short of its room's protocol. A decision the
    /// group's members may answer by cosigning. Its `attestation_id` is the
    /// quorum key; `scope_id` is the group.
    CosignPending,
    /// `cosign:signature:` — one member's cosignature on a held event, by
    /// itself. `proposal_id` names the held event (its quorum key), so the
    /// host refreshes that decision's tally.
    CosignSignature,
}

impl DecisionRowKind {
    /// Every kind with the prefixes it maps (the documented list).
    pub const PREFIXES: [(Self, &'static [&'static str]); 9] = [
        (Self::MembershipProposal, &["membership:proposal:"]),
        (
            Self::MembershipReply,
            &["membership:acceptance:", "membership:decline:"],
        ),
        (Self::Objection, &["objection:"]),
        (
            Self::RosterLanded,
            &[
                "group:roster:",
                "membership:widening:",
                "membership:removal:",
                "membership:resignation:",
            ],
        ),
        (Self::ModerationAction, &["moderation:"]),
        (Self::AccordHalt, &["accord:invoke:"]),
        (Self::ContactRequest, &["consent:replication:"]),
        (Self::CosignPending, &["cosign:pending:"]),
        (Self::CosignSignature, &["cosign:signature:"]),
    ];

    /// The stable token (the serde spelling).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MembershipProposal => "membership_proposal",
            Self::MembershipReply => "membership_reply",
            Self::Objection => "objection",
            Self::RosterLanded => "roster_landed",
            Self::ModerationAction => "moderation_action",
            Self::AccordHalt => "accord_halt",
            Self::ContactRequest => "contact_request",
            Self::CosignPending => "cosign_pending",
            Self::CosignSignature => "cosign_signature",
        }
    }

    /// The kind of `row`, by its signed `dimension` or (for the accord's
    /// typed rows) its `attestation_type`; `None` for any other row.
    #[must_use]
    pub fn of_row(row: &Attestation) -> Option<Self> {
        let dimension = row
            .attestation_envelope
            .get("dimension")
            .and_then(serde_json::Value::as_str);
        let names = [dimension, Some(row.attestation_type.as_str())];
        Self::PREFIXES.iter().find_map(|(kind, prefixes)| {
            names
                .iter()
                .flatten()
                .any(|n| prefixes.iter().any(|p| n.starts_with(p)))
                .then_some(*kind)
        })
    }
}

/// persist's serve position on the Attestation plane: the `(admitted_at,
/// attestation_id)` resume pair of `list_attestations_since`. Text form
/// `"{rfc3339-ms}|{attestation_id}"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DecisionCursor {
    /// The serve instant (persist's `admitted_at`).
    pub admitted_at: chrono::DateTime<chrono::Utc>,
    /// The tie-break within one instant.
    pub attestation_id: String,
}

/// How far below "now" an event's cursor is set, so it is at or before the
/// row's serve position whatever clock persist's backend stamps with.
pub const EVENT_CURSOR_MARGIN_SECS: i64 = 5;

impl DecisionCursor {
    /// A cursor at or before every row admitted at or after `instant`.
    #[must_use]
    pub fn at_or_before(instant: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            admitted_at: instant - chrono::Duration::seconds(EVENT_CURSOR_MARGIN_SECS),
            attestation_id: String::new(),
        }
    }

    fn pair(&self) -> (chrono::DateTime<chrono::Utc>, String) {
        (self.admitted_at, self.attestation_id.clone())
    }
}

impl std::fmt::Display for DecisionCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}|{}",
            self.admitted_at
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            self.attestation_id
        )
    }
}

impl std::str::FromStr for DecisionCursor {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (at, id) = s
            .split_once('|')
            .ok_or_else(|| format!("decision cursor {s:?}: expected `rfc3339|id`"))?;
        let admitted_at = chrono::DateTime::parse_from_rfc3339(at)
            .map_err(|e| format!("decision cursor {s:?}: {e}"))?
            .with_timezone(&chrono::Utc);
        Ok(Self {
            admitted_at,
            attestation_id: id.to_owned(),
        })
    }
}

impl Serialize for DecisionCursor {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DecisionCursor {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// One decision-relevant row: what the host re-reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionRowRef {
    /// The row.
    pub attestation_id: String,
    /// Its kind.
    pub kind: DecisionRowKind,
    /// The row's `cohort_scope` (`self`, `family`, `community`,
    /// `affiliations`, `federation`).
    pub cohort_scope: String,
    /// The group it is placed at (`community_key_id` / `family_key_id`);
    /// `None` at `self` / `federation`.
    pub scope_id: Option<String>,
    /// The proposal this row answers or completes, when the row names one: a
    /// reply's `references_attestation_id`, an objection's
    /// `objects_to_attestation_id`, or (on a widening the bridge's widener
    /// wrote) the proposal whose acceptance it seated. Set on a widening, it
    /// marks the proposal/acceptance pair COMPLETE.
    pub proposal_id: Option<String>,
    /// A resume point that INCLUDES this row: `decision_rows_since(cursor)`
    /// returns it (and possibly rows already seen; dedup by id).
    pub cursor: DecisionCursor,
}

fn env_str<'a>(row: &'a Attestation, key: &str) -> Option<&'a str> {
    row.attestation_envelope
        .get(key)
        .and_then(serde_json::Value::as_str)
}

impl DecisionRowRef {
    /// The reference for `row` at `cursor`, or `None` when the row is not
    /// decision-relevant.
    #[must_use]
    pub fn of_row(row: &Attestation, cursor: DecisionCursor) -> Option<Self> {
        let kind = DecisionRowKind::of_row(row)?;
        // A cosign row carries its event (and so its group) inside its own
        // member, not at the envelope's top: persist reads it back.
        let cosign = matches!(
            kind,
            DecisionRowKind::CosignPending | DecisionRowKind::CosignSignature
        )
        .then(|| {
            ciris_persist::federation::cosign::read_row(row)
                .ok()
                .flatten()
        })
        .flatten();
        let scope_id = match &cosign {
            Some(read) => Some(read.event.group_key_id().to_owned()),
            None => ["community_key_id", "family_key_id"]
                .iter()
                .find_map(|k| env_str(row, k))
                .map(str::to_owned),
        };
        let proposal_id = match kind {
            DecisionRowKind::MembershipReply => {
                env_str(row, "references_attestation_id").map(str::to_owned)
            }
            DecisionRowKind::Objection => {
                env_str(row, "objects_to_attestation_id").map(str::to_owned)
            }
            DecisionRowKind::CosignSignature => cosign.as_ref().map(|r| r.quorum_key.clone()),
            _ => None,
        };
        Some(Self {
            attestation_id: row.attestation_id.clone(),
            kind,
            cohort_scope: row.cohort_scope.clone(),
            scope_id,
            proposal_id,
            cursor,
        })
    }
}

/// **Rebuild from a cursor**: the decision-relevant rows persist serves
/// after `since` (every row from the start when `None`), scanning at most
/// `limit` rows, and the cursor to resume from (the last position scanned;
/// `since` itself when nothing was). Call it until it returns no rows.
///
/// # Errors
/// persist's read failure.
pub async fn decision_rows_since(
    directory: &dyn FederationDirectory,
    since: Option<DecisionCursor>,
    limit: u32,
) -> Result<(Vec<DecisionRowRef>, Option<DecisionCursor>), ciris_persist::federation::Error> {
    let page = directory
        .list_attestations_since(since.as_ref().map(DecisionCursor::pair), limit.max(1))
        .await?;
    let next = page
        .last()
        .map(|s| {
            let (admitted_at, attestation_id) = s.resume_pair();
            DecisionCursor {
                admitted_at,
                attestation_id,
            }
        })
        .or(since);
    let rows = page
        .iter()
        .filter_map(|s| {
            let (admitted_at, attestation_id) = s.resume_pair();
            DecisionRowRef::of_row(
                &s.attestation,
                DecisionCursor {
                    admitted_at,
                    attestation_id,
                },
            )
        })
        .collect();
    Ok((rows, next))
}

/// Capacity of the decision-row broadcast (a lagged receiver rebuilds from
/// its last cursor with [`decision_rows_since`]).
pub const DECISION_ROW_CHANNEL_CAPACITY: usize = 1024;

/// The decision-row event stream. Cheap to clone; emission never blocks.
#[derive(Debug, Clone)]
pub struct DecisionRowSignal {
    tx: tokio::sync::broadcast::Sender<DecisionRowRef>,
    telemetry: std::sync::Arc<std::sync::OnceLock<std::sync::Arc<crate::telemetry::EdgeTelemetry>>>,
}

impl Default for DecisionRowSignal {
    fn default() -> Self {
        Self::new()
    }
}

impl DecisionRowSignal {
    /// A signal with [`DECISION_ROW_CHANNEL_CAPACITY`].
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx: tokio::sync::broadcast::channel(DECISION_ROW_CHANNEL_CAPACITY).0,
            telemetry: std::sync::Arc::default(),
        }
    }

    /// Count unheard rows into `telemetry`, and let it read the subscribers.
    pub fn attach_telemetry(&self, telemetry: &std::sync::Arc<crate::telemetry::EdgeTelemetry>) {
        telemetry.watch_decision_rows(self.tx.clone());
        let _ = self.telemetry.set(std::sync::Arc::clone(telemetry));
    }

    fn send(&self, r: DecisionRowRef) -> usize {
        let kind = r.kind;
        let heard = self.tx.send(r).unwrap_or(0);
        if heard == 0 {
            if let Some(t) = self.telemetry.get() {
                t.note_decision_row_unheard(kind);
            }
        }
        heard
    }

    /// Receivers listening now. Zero means every row since is unheard here
    /// and rests on [`decision_rows_since`] for whoever asks.
    #[must_use]
    pub fn subscribers(&self) -> usize {
        self.tx.receiver_count()
    }

    /// A new receiver of every later event.
    #[must_use]
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<DecisionRowRef> {
        self.tx.subscribe()
    }

    /// Emit a reference already built (a rebuild scan's). Returns how many
    /// receivers it reached.
    pub fn emit(&self, r: DecisionRowRef) -> usize {
        self.send(r)
    }

    /// Emit `row` if it is decision-relevant (its cursor is a lower bound
    /// taken just before it was admitted: `admitted_before`). Returns the
    /// reference emitted. Nobody listening is not an error.
    pub fn observe(
        &self,
        row: &Attestation,
        admitted_before: chrono::DateTime<chrono::Utc>,
        proposal_id: Option<&str>,
    ) -> Option<DecisionRowRef> {
        let mut r = DecisionRowRef::of_row(row, DecisionCursor::at_or_before(admitted_before))?;
        if let Some(p) = proposal_id {
            r.proposal_id = Some(p.to_owned());
        }
        self.send(r.clone());
        Some(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(dimension: &str, attestation_type: &str, extra: &serde_json::Value) -> Attestation {
        let mut envelope = serde_json::json!({ "dimension": dimension });
        if let (Some(o), Some(e)) = (envelope.as_object_mut(), extra.as_object()) {
            for (k, v) in e {
                o.insert(k.clone(), v.clone());
            }
        }
        let t = chrono::Utc::now();
        serde_json::from_value(serde_json::json!({
            "attestation_id": format!("id-{dimension}"),
            "attesting_key_id": "k",
            "attested_key_id": "k",
            "attestation_type": attestation_type,
            "asserted_at": t,
            "attestation_envelope": envelope,
            "original_content_hash": "",
            "scrub_signature_classical": "",
            "scrub_key_id": "k",
            "scrub_timestamp": t,
            "persist_row_hash": "",
            "cohort_scope": "community",
        }))
        .expect("a minimal attestation decodes")
    }

    /// **Every documented prefix classifies to its kind, and nothing else
    /// does.** The table is the contract the server codes against.
    #[test]
    fn every_documented_prefix_classifies_and_others_do_not() {
        for (kind, prefixes) in DecisionRowKind::PREFIXES {
            for p in prefixes {
                let r = row(&format!("{p}v1"), "scores", &serde_json::json!({}));
                assert_eq!(DecisionRowKind::of_row(&r), Some(kind), "{p}");
            }
        }
        let halt = row(
            "",
            "accord:invoke:constitutional:h1:v1",
            &serde_json::json!({}),
        );
        assert_eq!(
            DecisionRowKind::of_row(&halt),
            Some(DecisionRowKind::AccordHalt)
        );
        for other in ["chat:message:v1", "consent:state:granted:v1", "member:x"] {
            assert_eq!(
                DecisionRowKind::of_row(&row(other, "scores", &serde_json::json!({}))),
                None,
                "{other}"
            );
        }
    }

    /// The reply names its proposal; the room is the scope id.
    #[test]
    fn a_reply_names_its_proposal_and_room() {
        let r = row(
            "membership:acceptance:v1",
            "scores",
            &serde_json::json!({ "references_attestation_id": "p1", "community_key_id": "room" }),
        );
        let at = chrono::Utc::now();
        let d = DecisionRowRef::of_row(&r, DecisionCursor::at_or_before(at)).expect("relevant");
        assert_eq!(d.kind, DecisionRowKind::MembershipReply);
        assert_eq!(d.proposal_id.as_deref(), Some("p1"));
        assert_eq!(d.scope_id.as_deref(), Some("room"));
        assert!(
            d.cursor.admitted_at < at,
            "the event cursor is a lower bound"
        );
    }

    /// The cursor's text form round-trips (the host stores it as a string).
    #[test]
    fn the_cursor_round_trips_through_text() {
        let c = DecisionCursor {
            admitted_at: crate::replication::attestation_bind::truncate_to_substrate_resolution(
                chrono::Utc::now(),
            ),
            attestation_id: "a|b".into(),
        };
        let back: DecisionCursor = c.to_string().parse().expect("parse");
        assert_eq!(back, c);
        let json = serde_json::to_string(&c).expect("json");
        assert_eq!(
            serde_json::from_str::<DecisionCursor>(&json).expect("de"),
            c
        );
    }
}

#[cfg(test)]
mod telemetry_tests {
    use super::*;
    use crate::observability::EdgeMetrics;

    fn proposal() -> DecisionRowRef {
        DecisionRowRef {
            attestation_id: "a".to_owned(),
            kind: DecisionRowKind::Objection,
            cohort_scope: "community".to_owned(),
            scope_id: None,
            proposal_id: None,
            cursor: DecisionCursor::at_or_before(chrono::Utc::now()),
        }
    }

    /// The direction a host cares about: a row nobody heard is counted, a row
    /// someone heard is not, and the gauge says which it was.
    #[test]
    fn a_row_with_no_receiver_is_unheard_and_one_with_a_receiver_is_not() {
        let m = EdgeMetrics::new();
        let signal = DecisionRowSignal::new();
        signal.attach_telemetry(&m.telemetry);
        assert_eq!(m.snapshot().decision_row_subscribers, 0);
        assert_eq!(signal.emit(proposal()), 0);
        assert_eq!(m.snapshot().decision_row_unheard_total["objection"], 1);

        let rx = signal.subscribe();
        assert_eq!(m.snapshot().decision_row_subscribers, 1);
        assert_eq!(signal.emit(proposal()), 1);
        assert_eq!(m.snapshot().decision_row_unheard_total["objection"], 1);

        drop(rx);
        assert_eq!(
            m.snapshot().decision_row_subscribers,
            0,
            "read from the channel, not remembered"
        );
    }
}
