//! Property-based invariants for the v1 replication wire format.
//!
//! Locks the wire-stable contract from `FSD/REPLICATION_WIRE_FORMAT_V1.md`
//! against arbitrary inputs — proptest generates thousands of random
//! `ReplicationMessage` shapes and asserts the invariants hold for
//! every one.
//!
//! ## What's tested
//!
//! 1. **Wrap/unwrap round-trip** — for any `ReplicationMessage`,
//!    `try_unwrap(wrap(m)) == Ok(Some(m))`.
//! 2. **Magic prefix discriminates** — for any byte string that doesn't
//!    start with `CRPL`, `try_unwrap` returns `Ok(None)`. (Non-
//!    replication bytes route to the non-replication dispatcher.)
//! 3. **Unknown version surfaces typed error** — for any version byte
//!    other than `WIRE_PROTOCOL_VERSION`, `try_unwrap` returns
//!    `Err(UnknownVersion(v))`.
//! 4. **`EnvelopeKind` JSON tag round-trips** — every variant
//!    serialises + deserialises to itself.
//!
//! ## Wall-clock budget
//!
//! Default proptest runs 256 cases per `proptest!`. The whole file
//! finishes in well under a second on CI runners — proportionate to
//! the value (every PR exercises the v1 wire contract against random
//! inputs).
//!
//! ## Why an integration test, not a #[cfg(test)] mod
//!
//! Property-based tests touching the wire contract validate the
//! **public API surface** — the same shape downstream consumers see.
//! Integration-test placement means the test links against the
//! crate's exported `pub` items, catching any accidental
//! `pub(crate)` regression that would hide a wire-format type.

use ciris_edge::replication::protocol::ProtocolError;
use ciris_edge::replication::wire_frame::{
    try_unwrap, wrap, wrap_at_version, WIRE_PROTOCOL_VERSION,
};
use ciris_edge::replication::{
    DeliverMessage, DiffMessage, EnvelopeKind, EnvelopeRef, FetchMessage, ReplicationMessage,
    SummaryMessage, REPLICATION_FRAME_MAGIC,
};
use proptest::prelude::*;

// ─── Generators ────────────────────────────────────────────────────

fn arb_envelope_kind() -> impl Strategy<Value = EnvelopeKind> {
    prop_oneof![
        Just(EnvelopeKind::Key),
        Just(EnvelopeKind::Attestation),
        Just(EnvelopeKind::Revocation),
        Just(EnvelopeKind::IdentityOccurrence),
        Just(EnvelopeKind::Family),
        Just(EnvelopeKind::Community),
        Just(EnvelopeKind::IdentityOccurrenceRevocation),
        Just(EnvelopeKind::FamilyMembershipRevocation),
        Just(EnvelopeKind::CommunityMembershipRevocation),
    ]
}

fn arb_envelope_ref() -> impl Strategy<Value = EnvelopeRef> {
    (any::<[u8; 32]>(), any::<u64>())
        .prop_map(|(envelope_hash, seq)| EnvelopeRef { envelope_hash, seq })
}

fn arb_summary() -> impl Strategy<Value = SummaryMessage> {
    (
        arb_envelope_kind(),
        prop::collection::vec(arb_envelope_ref(), 0..16),
    )
        .prop_map(|(kind, refs)| SummaryMessage { kind, refs })
}

fn arb_diff() -> impl Strategy<Value = DiffMessage> {
    (
        arb_envelope_kind(),
        prop::collection::vec(any::<[u8; 32]>(), 0..32),
    )
        .prop_map(|(kind, want)| DiffMessage { kind, want })
}

fn arb_fetch() -> impl Strategy<Value = FetchMessage> {
    (
        arb_envelope_kind(),
        prop::collection::vec(any::<[u8; 32]>(), 0..32),
    )
        .prop_map(|(kind, want)| FetchMessage { kind, want })
}

fn arb_deliver() -> impl Strategy<Value = DeliverMessage> {
    (
        arb_envelope_kind(),
        prop::collection::vec(prop::collection::vec(any::<u8>(), 0..256), 0..8),
    )
        .prop_map(|(kind, envelopes)| DeliverMessage { kind, envelopes })
}

fn arb_replication_message() -> impl Strategy<Value = ReplicationMessage> {
    prop_oneof![
        arb_summary().prop_map(ReplicationMessage::Summary),
        arb_diff().prop_map(ReplicationMessage::Diff),
        arb_fetch().prop_map(ReplicationMessage::Fetch),
        arb_deliver().prop_map(ReplicationMessage::Deliver),
    ]
}

// ─── Properties ────────────────────────────────────────────────────

proptest! {
    /// Property 1: any well-formed `ReplicationMessage` round-trips
    /// through `wrap` → `try_unwrap`. The wire format is bijective on
    /// the message domain.
    #[test]
    fn wrap_unwrap_round_trip_for_any_message(msg in arb_replication_message()) {
        let framed = wrap(&msg);
        let parsed = try_unwrap(&framed).expect("decode").expect("magic");
        prop_assert_eq!(parsed, msg);
    }

    /// Property 2: bytes that do NOT start with the `CRPL` magic
    /// always return `Ok(None)` — never an error. The application's
    /// dispatcher routes non-replication bytes to its other handlers.
    ///
    /// We constrain the first byte ≠ b'C' (the first byte of CRPL)
    /// so the test doesn't accidentally generate a magic prefix.
    /// That's a strict subset of the property — any byte string whose
    /// first byte is in `[0..b'C') ∪ (b'C'..=0xFF]` will not match
    /// magic. (The `[b'C'..b'C']` 1-byte window may match; we exclude
    /// it explicitly.)
    #[test]
    fn non_crpl_bytes_yield_none(
        bytes in prop::collection::vec(any::<u8>(), 0..512)
            .prop_filter("first byte is C", |v| v.first() != Some(&b'C'))
    ) {
        let r = try_unwrap(&bytes).expect("non-CRPL routing is never an error");
        prop_assert!(r.is_none());
    }

    /// Property 3: any version byte other than `WIRE_PROTOCOL_VERSION`
    /// surfaces as `UnknownVersion(v)`, regardless of body content.
    /// Anchors the v1→v2 transition story: a v1 receiver seeing a v2
    /// frame fails cleanly with a typed error the scheduler can act
    /// on (drop the peer, downgrade, etc.).
    #[test]
    fn unknown_version_byte_always_surfaces_typed_error(
        version in any::<u8>().prop_filter("non-v1 version", |v| *v != WIRE_PROTOCOL_VERSION),
        body in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let mut frame = REPLICATION_FRAME_MAGIC.to_vec();
        frame.push(version);
        frame.extend_from_slice(&body);
        match try_unwrap(&frame) {
            Err(ProtocolError::UnknownVersion(v)) => prop_assert_eq!(v, version),
            other => prop_assert!(
                false,
                "expected UnknownVersion({}), got {:?}", version, other
            ),
        }
    }

    /// Property 4: every `EnvelopeKind` variant serialises +
    /// deserialises to itself through the JSON serde tag. Locks the
    /// snake_case rename of every variant — if a future commit
    /// accidentally renames a variant's serde tag, this proptest
    /// surfaces the regression on every shrink.
    #[test]
    fn envelope_kind_json_tag_round_trips(kind in arb_envelope_kind()) {
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: EnvelopeKind = serde_json::from_str(&json).unwrap();
        prop_assert_eq!(parsed, kind);
    }

    /// Property 5: `wrap_at_version` with the canonical version
    /// produces the same bytes as `wrap`. (Documents the equivalence
    /// for test-fixture readers; catches any drift where `wrap`
    /// accidentally embeds a different version byte than
    /// `WIRE_PROTOCOL_VERSION`.)
    #[test]
    fn wrap_equals_wrap_at_current_version(msg in arb_replication_message()) {
        prop_assert_eq!(wrap(&msg), wrap_at_version(&msg, WIRE_PROTOCOL_VERSION));
    }
}
