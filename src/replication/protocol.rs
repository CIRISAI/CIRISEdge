//! Wire-stable message types for the anti-entropy protocol.
//!
//! Four messages, exchanged pairwise between region peers:
//!
//! ```text
//!  A → B   Summary  { kind, refs: [(envelope_hash, seq)] }
//!  A ← B   Diff     { kind, want: [envelope_hash] }     // B asks for what A has that B doesn't
//!  A → B   Deliver  { kind, envelopes: [signed_bytes] }
//!
//!  (and vice versa — both sides initiate Summary in the same round
//!   so the diff is bidirectional)
//! ```
//!
//! A [`FetchMessage`] is the explicit "I want these envelopes by hash"
//! shape, used when a peer learns of envelope hashes via a third
//! channel (e.g. a downstream consumer that needs to chase an unknown
//! reference). The [`SummaryMessage`] / [`DiffMessage`] flow is the
//! steady-state anti-entropy path; [`FetchMessage`] is the on-demand
//! path.
//!
//! ## Wire codec
//!
//! Messages serialize via `serde_json` for the v1 protocol. Future
//! versions may upgrade to CBOR or persist's canonical-bytes shape,
//! but JSON keeps the v1 implementation simple and debuggable; the
//! anti-entropy traffic is low-frequency (sync rounds every N seconds
//! per peer-pair, not per-envelope) so the codec efficiency is not
//! a hot path.
//!
//! ## Wire stability
//!
//! Every variant is `#[serde(tag = "type")]` so adding a new
//! `ReplicationMessage` variant doesn't break v1 receivers — they
//! see an unknown tag and refuse the message at the deserializer.
//! Adding a NEW field to an existing message is a non-break (serde
//! defaults the absent field on the receiver side) provided the
//! field is annotated `#[serde(default)]`. Removing or renaming a
//! field IS a break and requires bumping the protocol version (a
//! follow-up adds `protocol_version` to the [`SummaryMessage`]
//! envelope; v1 is implicit version `1`).

use serde::{Deserialize, Serialize};

/// The kinds of envelope the anti-entropy protocol replicates. Each
/// kind corresponds to a separate sync stream so partitions on one
/// kind don't gate convergence on others. Extending this enum is
/// additive (new variant); the receiver gracefully unknowns variants
/// it doesn't recognize via serde's untagged-fallback behavior. New
/// variants MUST be appended (not inserted) to preserve serialized
/// wire order for the explicit JSON-name representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeKind {
    /// `federation_keys` table — newly-published key registrations.
    Key,
    /// `federation_attestations` table — `trust_grant` / `holds_bytes`
    /// / consent / etc.
    Attestation,
    /// `federation_revocations` table — anti-rollback per CIRISPersist
    /// V058.
    Revocation,
    /// `federation_communities` (CEG 0.8) once shipped — placeholder
    /// reserved here so the kind enum doesn't have to change when the
    /// substrate lands.
    Community,
}

/// A reference to a single envelope in a peer's local state. The
/// `envelope_hash` is `sha256(canonical_bytes(envelope))` — same shape
/// persist uses for `original_content_hash`. The `seq` is monotonic
/// per (kind, signer) and lets the receiver detect anti-rollback
/// attempts locally before round-tripping to persist's R1/Q1 merge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeRef {
    /// 32-byte sha256 of the canonical-bytes form of the envelope.
    pub envelope_hash: [u8; 32],
    /// Per-(kind, signer) monotonic counter. v1 is best-effort —
    /// persist's R1/Q1 merge is the canonical anti-rollback oracle;
    /// this field is a hint for receivers to short-circuit obvious
    /// stale data without paying the merge round-trip.
    pub seq: u64,
}

/// "Here are the envelope hashes I have for `kind`." First message
/// of an anti-entropy round.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryMessage {
    pub kind: EnvelopeKind,
    pub refs: Vec<EnvelopeRef>,
}

/// "I want these envelopes." Receiver's response to a `SummaryMessage`
/// — the list of `envelope_hash`es present in the sender's summary
/// but absent from the receiver's local state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffMessage {
    pub kind: EnvelopeKind,
    pub want: Vec<[u8; 32]>,
}

/// "I want these envelopes by hash." Used for on-demand fetch (a
/// consumer learns of a hash via a third channel and asks edge to
/// chase it). The receiver of a `Fetch` MUST NOT speculatively
/// deliver envelopes the requester didn't ask for — anti-entropy
/// uses the Summary/Diff flow for unsolicited convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FetchMessage {
    pub kind: EnvelopeKind,
    pub want: Vec<[u8; 32]>,
}

/// "Here are the bytes." Wraps the requested envelopes' raw signed-
/// bytes form (the same shape `put_*` admits expect on the receiver's
/// persist side). Order is unspecified; the receiver MUST validate
/// each envelope's signature + canonical-bytes hash before applying.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliverMessage {
    pub kind: EnvelopeKind,
    /// Each entry is the byte-exact signed envelope as it would have
    /// been admitted by the original signer's local `put_*` call.
    pub envelopes: Vec<Vec<u8>>,
}

/// The protocol's top-level message type — what flows on the wire
/// between region peers. `#[serde(tag = "type")]` so a future variant
/// is transparent to v1 receivers (they refuse on unknown tag, NOT
/// silent ignore).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplicationMessage {
    Summary(SummaryMessage),
    Diff(DiffMessage),
    Fetch(FetchMessage),
    Deliver(DeliverMessage),
}

impl ReplicationMessage {
    /// Serialize to JSON bytes for transport. Returns the bytes ready
    /// to hand to `Transport::send`.
    pub fn to_bytes(&self) -> Vec<u8> {
        // serde_json::to_vec on an enum it knows the shape of cannot
        // fail; unwrap is safe.
        serde_json::to_vec(self).expect("ReplicationMessage serialization cannot fail")
    }

    /// Parse from on-wire JSON bytes. Returns `Err` on JSON parse
    /// failure or unknown tag.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProtocolError> {
        serde_json::from_slice(bytes).map_err(|e| ProtocolError::Decode(e.to_string()))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("replication message decode failed: {0}")]
    Decode(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_hash(seed: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        for (i, b) in h.iter_mut().enumerate() {
            *b = u8::try_from(i & 0xFF).unwrap().wrapping_mul(seed.max(1));
        }
        h
    }

    /// Round-trip — JSON-encoded then parsed yields the same value.
    #[test]
    fn summary_round_trips_via_json() {
        let m = ReplicationMessage::Summary(SummaryMessage {
            kind: EnvelopeKind::Attestation,
            refs: vec![
                EnvelopeRef {
                    envelope_hash: fake_hash(1),
                    seq: 100,
                },
                EnvelopeRef {
                    envelope_hash: fake_hash(2),
                    seq: 101,
                },
            ],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn diff_round_trips() {
        let m = ReplicationMessage::Diff(DiffMessage {
            kind: EnvelopeKind::Revocation,
            want: vec![fake_hash(3)],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn fetch_round_trips() {
        let m = ReplicationMessage::Fetch(FetchMessage {
            kind: EnvelopeKind::Key,
            want: vec![fake_hash(4), fake_hash(5)],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    #[test]
    fn deliver_round_trips() {
        let m = ReplicationMessage::Deliver(DeliverMessage {
            kind: EnvelopeKind::Attestation,
            envelopes: vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD]],
        });
        let bytes = m.to_bytes();
        let parsed = ReplicationMessage::from_bytes(&bytes).expect("parse");
        assert_eq!(parsed, m);
    }

    /// Unknown tag refused — wire-stability guarantee.
    #[test]
    fn unknown_tag_refused() {
        let raw = br#"{"type":"hostile_takeover","payload":42}"#;
        let r = ReplicationMessage::from_bytes(raw);
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// Malformed JSON refused.
    #[test]
    fn malformed_json_refused() {
        let r = ReplicationMessage::from_bytes(b"{not json");
        assert!(matches!(r, Err(ProtocolError::Decode(_))));
    }

    /// All four `EnvelopeKind` variants round-trip via JSON — kind
    /// values are wire-load-bearing.
    #[test]
    fn envelope_kind_wire_values_are_stable() {
        let cases = [
            (EnvelopeKind::Key, "key"),
            (EnvelopeKind::Attestation, "attestation"),
            (EnvelopeKind::Revocation, "revocation"),
            (EnvelopeKind::Community, "community"),
        ];
        for (kind, wire) in cases {
            let m = ReplicationMessage::Summary(SummaryMessage { kind, refs: vec![] });
            let bytes = m.to_bytes();
            let s = std::str::from_utf8(&bytes).unwrap();
            assert!(s.contains(wire), "expected `{wire}` in {s}");
            assert_eq!(ReplicationMessage::from_bytes(&bytes).unwrap(), m);
        }
    }
}
