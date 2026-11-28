//! 45.3 (CC review) — **which egress class an identity-plane replication
//! message rides**, from its row family and plane.
//!
//! FIRST class is never held by the egress budget (charged and counted like
//! call control): call control and proofs, link setup, a halt and the
//! accord's carriage, any revocation and key row, any removal, roster or
//! epoch row of a room, stream bindings and parts. BULK waits on the budget
//! (within the guaranteed floor): every other replication row, chat and
//! receipts, file transfer.
//!
//! **A family edge cannot place is FIRST, never bulk.** A misfiled bulk row
//! costs bandwidth; a misfiled removal costs exposure. So this is written
//! the safe way round: a message is BULK only when every row in it is
//! positively known to be bulk, and an envelope that does not parse, a
//! dimension with no prefix here, or a kind this build predates, is FIRST.
//!
//! Membership, roster and epoch rows are FIRST for every room, not only the
//! rooms this node is in a call of: telling the two apart needs the call
//! registry at the replication send, and the conservative side of the
//! difference costs only those (small, rare) rows' bandwidth.

use super::protocol::{EnvelopeKind, ReplicationMessage};
use crate::transport::egress_budget::SendClass;

/// Dimension prefixes whose rows are FIRST class: the accord (its halts and
/// carriage), membership (removal, roster, widening, the room's epoch keys),
/// call sessions, consent and moderation (who may see what), and any
/// revocation or recant.
pub const FIRST_PREFIXES: &[&str] = &[
    "accord:",
    "membership:",
    "key_grant:",
    "key:",
    "session:",
    "consent:",
    "moderation:",
    "revocation:",
    "recants",
    // 45.3 (constitution ruling): a withdrawal, a duty and an ownership row
    // change who holds or answers for what; they do not wait behind media.
    "withdraws",
    "duty:",
    "ownership:",
];

/// 45.3 — the `av_plane` label FIRST bytes are counted under, per
/// [`FIRST_PREFIXES`] entry (the prefix only, never a row's content).
pub const FIRST_FAMILIES: &[(&str, &str)] = &[
    ("accord:", crate::observability::AV_FIRST_BYTES_ACCORD),
    (
        "membership:",
        crate::observability::AV_FIRST_BYTES_MEMBERSHIP,
    ),
    ("key_grant:", crate::observability::AV_FIRST_BYTES_KEY_GRANT),
    ("key:", crate::observability::AV_FIRST_BYTES_KEY),
    ("session:", crate::observability::AV_FIRST_BYTES_SESSION),
    ("consent:", crate::observability::AV_FIRST_BYTES_CONSENT),
    (
        "moderation:",
        crate::observability::AV_FIRST_BYTES_MODERATION,
    ),
    (
        "revocation:",
        crate::observability::AV_FIRST_BYTES_REVOCATION,
    ),
    ("recants", crate::observability::AV_FIRST_BYTES_RECANTS),
    ("withdraws", crate::observability::AV_FIRST_BYTES_WITHDRAWS),
    ("duty:", crate::observability::AV_FIRST_BYTES_DUTY),
    ("ownership:", crate::observability::AV_FIRST_BYTES_OWNERSHIP),
];

/// Dimension prefixes positively known to be BULK: conversation and its
/// history, file holdings, and the scoring, capacity and health planes.
pub const BULK_PREFIXES: &[&str] = &[
    "chat:",
    "file:",
    "supersedes",
    "scores:",
    "trust:",
    "capacity:",
    "content_class:",
    "substrate_health:",
    "provenance:build_manifest:",
    "trace:",
    "objection:",
];

/// The class of one Attestation row's dimension.
#[must_use]
pub fn class_of_dimension(dimension: &str) -> SendClass {
    if FIRST_PREFIXES.iter().any(|p| dimension.starts_with(p)) {
        return SendClass::First;
    }
    if BULK_PREFIXES.iter().any(|p| dimension.starts_with(p)) {
        return SendClass::Bulk;
    }
    SendClass::First
}

/// The class a message about `kind` rides when its rows are not read: the
/// key, revocation, accord and membership planes are FIRST, the directory
/// planes (identity occurrences, organisations, locations, transport
/// destinations, partner records) BULK, and `Attestation` BULK (a Deliver of
/// it is read row by row in [`class_of`]).
#[must_use]
pub fn class_of_kind(kind: EnvelopeKind) -> SendClass {
    match kind {
        EnvelopeKind::IdentityOccurrence
        | EnvelopeKind::LocationProof
        | EnvelopeKind::Organization
        | EnvelopeKind::OrgMembership
        | EnvelopeKind::PartnerRecord
        | EnvelopeKind::TransportDestination
        | EnvelopeKind::Attestation => SendClass::Bulk,
        // Key, Revocation and the membership revocations, the accord's
        // quorum evidence, key grants, and family/community rosters and
        // their widenings and listings, and any kind this build predates.
        _ => SendClass::First,
    }
}

#[derive(serde::Deserialize)]
struct RowDimension {
    attestation_envelope: Option<EnvelopeDimension>,
}

#[derive(serde::Deserialize)]
struct EnvelopeDimension {
    dimension: Option<String>,
}

/// The class `msg` rides. A Deliver of Attestation rows is BULK only when
/// every row's dimension is positively bulk; one row that is FIRST, does not
/// parse, or names no dimension makes the whole message FIRST.
#[must_use]
pub fn class_of(msg: &ReplicationMessage) -> SendClass {
    match msg {
        ReplicationMessage::Deliver(d) if d.kind == EnvelopeKind::Attestation => {
            let all_bulk = d.envelopes.iter().all(|e| {
                serde_json::from_slice::<RowDimension>(e)
                    .ok()
                    .and_then(|r| r.attestation_envelope)
                    .and_then(|a| a.dimension)
                    .is_some_and(|dim| class_of_dimension(&dim) == SendClass::Bulk)
            });
            if all_bulk {
                SendClass::Bulk
            } else {
                SendClass::First
            }
        }
        other => class_of_kind(other.kind()),
    }
}

/// 45.3 — the `av_plane` label a FIRST message's bytes are counted under:
/// the family prefix of its first FIRST row (an Attestation Deliver), or
/// `first_bytes:unknown_dimension` for a row edge cannot place, or
/// `first_bytes:other_kind` for a non-Attestation kind. Prefix labels only.
#[must_use]
pub fn family_of(msg: &ReplicationMessage) -> &'static str {
    match msg {
        ReplicationMessage::Deliver(d) if d.kind == EnvelopeKind::Attestation => {
            for e in &d.envelopes {
                let dim = serde_json::from_slice::<RowDimension>(e)
                    .ok()
                    .and_then(|r| r.attestation_envelope)
                    .and_then(|a| a.dimension);
                let Some(dim) = dim else {
                    return crate::observability::AV_FIRST_BYTES_UNKNOWN_DIMENSION;
                };
                if let Some((_, label)) = FIRST_FAMILIES.iter().find(|(p, _)| dim.starts_with(p)) {
                    return label;
                }
                if !BULK_PREFIXES.iter().any(|p| dim.starts_with(p)) {
                    return crate::observability::AV_FIRST_BYTES_UNKNOWN_DIMENSION;
                }
            }
            crate::observability::AV_FIRST_BYTES_UNKNOWN_DIMENSION
        }
        _ => crate::observability::AV_FIRST_BYTES_OTHER_KIND,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::replication::protocol::DeliverMessage;

    fn row(dimension: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "attestation_id": "a",
            "attestation_type": "scores",
            "attestation_envelope": {"dimension": dimension},
        }))
        .expect("row")
    }

    fn deliver(rows: &[&str]) -> ReplicationMessage {
        ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: rows.iter().map(|d| row(d)).collect(),
        })
    }

    /// A removal, roster, epoch, accord or call-session row is FIRST; a
    /// chat or score row is BULK; one FIRST row makes the message FIRST.
    #[test]
    fn a_removal_rides_first_and_a_chat_row_bulk() {
        assert_eq!(
            class_of(&deliver(&["membership:removal:v1"])),
            SendClass::First
        );
        assert_eq!(
            class_of(&deliver(&["key_grant:epoch:v1"])),
            SendClass::First
        );
        assert_eq!(class_of(&deliver(&["accord:halt:v1"])), SendClass::First);
        assert_eq!(class_of(&deliver(&["chat:message:v1"])), SendClass::Bulk);
        assert_eq!(
            class_of(&deliver(&[
                "chat:message:v1",
                "scores:x",
                "file:holding:v1"
            ])),
            SendClass::Bulk
        );
        assert_eq!(
            class_of(&deliver(&["chat:message:v1", "membership:removal:v1"])),
            SendClass::First
        );
    }

    /// What edge cannot place is FIRST, never bulk: an unknown dimension, a
    /// row with no dimension, bytes that do not parse.
    #[test]
    fn what_edge_cannot_place_rides_first() {
        assert_eq!(class_of(&deliver(&["zzz:new_family:v1"])), SendClass::First);
        let no_dim = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![b"{\"attestation_id\":\"a\"}".to_vec(), b"not json".to_vec()],
        });
        assert_eq!(class_of(&no_dim), SendClass::First);
        assert_eq!(class_of_kind(EnvelopeKind::Key), SendClass::First);
        assert_eq!(class_of_kind(EnvelopeKind::Revocation), SendClass::First);
        assert_eq!(class_of_kind(EnvelopeKind::KeyGrant), SendClass::First);
        assert_eq!(class_of_kind(EnvelopeKind::LocationProof), SendClass::Bulk);
    }

    /// 45.3 (constitution ruling) — withdraws, duty and ownership rows ride
    /// FIRST (they were BULK).
    #[test]
    fn withdraws_duty_and_ownership_ride_first() {
        for dim in ["withdraws:v1", "duty:serve:v1", "ownership:claim:v1"] {
            assert_eq!(class_of(&deliver(&[dim])), SendClass::First, "{dim}");
            assert_eq!(class_of_dimension(dim), SendClass::First, "{dim}");
        }
        assert_eq!(class_of(&deliver(&["supersedes:v1"])), SendClass::Bulk);
    }

    /// FIRST bytes are labelled by family prefix only; every FIRST prefix
    /// has a label, and every label is a registered `av_plane` key.
    #[test]
    fn first_bytes_are_labelled_by_family_prefix() {
        assert_eq!(FIRST_FAMILIES.len(), FIRST_PREFIXES.len());
        for p in FIRST_PREFIXES {
            assert!(FIRST_FAMILIES.iter().any(|(q, _)| q == p), "{p} labelled");
        }
        for (_, l) in FIRST_FAMILIES {
            assert!(crate::observability::AV_PLANE_LABELS.contains(l), "{l}");
        }
        assert_eq!(
            family_of(&deliver(&["chat:message:v1", "membership:removal:v1"])),
            crate::observability::AV_FIRST_BYTES_MEMBERSHIP
        );
        assert_eq!(
            family_of(&deliver(&["zzz:new_family:v1"])),
            crate::observability::AV_FIRST_BYTES_UNKNOWN_DIMENSION
        );
        assert_eq!(
            family_of(&ReplicationMessage::Deliver(DeliverMessage {
                kind: EnvelopeKind::Key,
                envelopes: vec![],
            })),
            crate::observability::AV_FIRST_BYTES_OTHER_KIND
        );
    }
}
