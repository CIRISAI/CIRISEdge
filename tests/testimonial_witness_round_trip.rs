//! CIRISEdge#37 (v0.16.0) — `testimonial_witness` wire-form round-trip
//! tests per FSD-002 §3.6.3 v1.4 + §5.14.
//!
//! The witness is a **preservation primitive**: edge propagates the
//! value verbatim and signs over it as part of canonical envelope
//! bytes; the `payload` is opaque to edge (joint-correlation tier owns
//! interpretation). The tests below pin:
//!
//! 1. v0.15.x envelopes (no witness field) round-trip BYTE-EQUAL to
//!    their v0.15.x JSON shape — the load-bearing backward-compat
//!    invariant.
//! 2. v0.16.0 envelopes with a witness round-trip and the witness
//!    rides through canonical-bytes derivation (which the verify path
//!    uses to compute the signed-over bytes).
//! 3. Arbitrary JSON in `payload` survives a round trip byte-equal —
//!    confirming the opaque-payload contract.
//! 4. Multiple witnesses across a sequence of envelopes preserve order
//!    and content (the wire spec at v0.16.0 carries ONE witness per
//!    envelope; a sequence-of-envelopes test pins that intent).

use chrono::{DateTime, Utc};
use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion, TestimonialWitness};
use serde_json::value::RawValue;

/// Build a v0.15.x-shaped envelope (witness/scope absent) — the
/// shared fixture every backward-compat test uses.
fn v015_envelope() -> EdgeEnvelope {
    let body: Box<RawValue> =
        RawValue::from_string(r#"{"text":"hello"}"#.to_string()).expect("raw value");
    EdgeEnvelope {
        edge_schema_version: SchemaVersion::V2_0_0,
        signing_key_id: "edge-key-aaaa".to_string(),
        destination_key_id: "edge-key-bbbb".to_string(),
        message_type: MessageType::OpaqueEvent,
        sent_at: DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        nonce: [0x42; 16],
        body,
        signature: "ZmFrZS1lZDI1NTE5LXNpZ25hdHVyZQ==".to_string(),
        signature_pqc: None,
        in_reply_to: None,
        testimonial_witness: None,
        key_boundary_scope: None,
        cohort_scope: None,
    }
}

/// v0.15.x backward-compat — an envelope with `testimonial_witness =
/// None` serializes to a JSON shape that does NOT contain the
/// `testimonial_witness` key at all. That is the load-bearing
/// invariant: pre-v0.16.0 envelopes round-trip byte-equal, and
/// pre-v0.16.0 consumers (which lack the field on their struct) keep
/// deserializing unchanged.
#[test]
fn envelope_without_witness_round_trips_unchanged() {
    let env = v015_envelope();
    let json = serde_json::to_string(&env).expect("serialize");

    // The field must be ABSENT from the wire when None — this is the
    // byte-equal-to-v0.15.x guarantee.
    assert!(
        !json.contains("testimonial_witness"),
        "v0.15.x backward-compat: testimonial_witness must NOT appear in JSON when None; got: {json}"
    );
    assert!(
        !json.contains("key_boundary_scope"),
        "v0.15.x backward-compat: key_boundary_scope must NOT appear in JSON when None; got: {json}"
    );
    assert!(
        !json.contains("cohort_scope"),
        "v0.19.0 backward-compat: cohort_scope must NOT appear in JSON when None; got: {json}"
    );

    // Round-trip through deserialize → re-serialize → byte-equal.
    let back: EdgeEnvelope = serde_json::from_str(&json).expect("deserialize");
    let again = serde_json::to_string(&back).expect("re-serialize");
    assert_eq!(json, again, "v0.15.x envelope must round-trip byte-equal");
    assert!(back.testimonial_witness.is_none());
    assert!(back.key_boundary_scope.is_none());
    assert!(back.cohort_scope.is_none());
}

/// v0.16.0 — a witness-bearing envelope round-trips through
/// JSON byte-equal (Serialize → Deserialize → Serialize). This is the
/// witness-aware path; the body's signed bytes will include the
/// witness when the originator runs `canonicalize_envelope_for_signing`
/// (which persist's substrate owns — see `src/verify.rs`).
#[test]
fn envelope_with_witness_round_trips_and_signs() {
    let mut env = v015_envelope();
    env.testimonial_witness = Some(TestimonialWitness {
        kind: "ratchet-conscience".to_string(),
        payload: serde_json::json!({
            "ratchet_stage": "stage-7",
            "alignment_score": 0.92,
            "verdict": "advance"
        }),
        issuer_key_id: "lens-detector-eu-01".to_string(),
        issued_at: DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
    });

    let json = serde_json::to_string(&env).expect("serialize");
    // Witness is part of the wire — sanity-check the key surfaces.
    assert!(json.contains("\"testimonial_witness\""));
    assert!(json.contains("\"ratchet-conscience\""));
    assert!(json.contains("\"lens-detector-eu-01\""));

    let back: EdgeEnvelope = serde_json::from_str(&json).expect("deserialize");
    let again = serde_json::to_string(&back).expect("re-serialize");
    assert_eq!(
        json, again,
        "v0.16.0 witness envelope must round-trip byte-equal"
    );
    assert_eq!(
        env.testimonial_witness, back.testimonial_witness,
        "TestimonialWitness must round-trip equal"
    );

    // Canonical bytes derivation — confirm the witness is part of the
    // signed-over bytes when present. Persist's
    // `canonicalize_envelope_for_signing` operates on the JSON-derived
    // serde_json::Value; the field appears in the value iff it
    // appeared in the wire.
    let env_value = serde_json::to_value(&env).expect("envelope to_value");
    let canonical_with = ciris_persist::prelude::canonicalize_envelope_for_signing(&env_value)
        .expect("canonicalize");

    // Compare against a witness-stripped sibling — canonical bytes
    // MUST differ when the witness is present vs absent. This is the
    // "signs over the witness" pin.
    let mut sibling = env.clone();
    sibling.testimonial_witness = None;
    let sibling_value = serde_json::to_value(&sibling).expect("sibling to_value");
    let canonical_without =
        ciris_persist::prelude::canonicalize_envelope_for_signing(&sibling_value)
            .expect("canonicalize sibling");

    assert_ne!(
        canonical_with, canonical_without,
        "canonical bytes MUST differ when testimonial_witness is present vs absent — \
         that is the 'edge signs over the witness' invariant per FSD-002 §3.6.3 v1.4"
    );
}

/// Witness payload is opaque to edge — arbitrary JSON (nested
/// objects, arrays, numbers, booleans, null) must round-trip byte-equal.
#[test]
fn witness_payload_opaque_to_edge() {
    // Exercise every JSON type kind: object, array, string, number,
    // boolean, null. Edge must NOT interpret, must NOT reorder, must
    // NOT drop.
    let payloads = vec![
        serde_json::json!(null),
        serde_json::json!(42),
        serde_json::json!("plain-string"),
        serde_json::json!(true),
        serde_json::json!([1, 2, 3, "four", null, false]),
        serde_json::json!({
            "nested": {
                "deeper": {
                    // Use sentinel float values not approximating PI
                    // (clippy::approx_constant); we're testing JSON
                    // preservation, the specific number is incidental.
                    "deepest": [1.5, -2.0, 9.81],
                    "flag": false
                }
            },
            "list": [{"a": 1}, {"b": 2}]
        }),
    ];

    for payload in payloads {
        let mut env = v015_envelope();
        env.testimonial_witness = Some(TestimonialWitness {
            kind: "lens-detector".to_string(),
            payload: payload.clone(),
            issuer_key_id: "kind-test-issuer".to_string(),
            issued_at: Utc::now(),
        });

        let json = serde_json::to_string(&env).expect("serialize");
        let back: EdgeEnvelope = serde_json::from_str(&json).expect("deserialize");

        let back_payload = back
            .testimonial_witness
            .as_ref()
            .expect("witness present")
            .payload
            .clone();
        assert_eq!(
            payload, back_payload,
            "opaque payload must round-trip exactly equal — edge MUST NOT interpret"
        );
    }
}

/// A sequence of envelopes each carrying its own witness preserves
/// per-envelope content and order. The v0.16.0 wire spec is "one
/// witness per envelope" (a `Option<TestimonialWitness>` on the
/// `EdgeEnvelope`, NOT a `Vec`); this test pins that intent and
/// validates the sequence-level preservation contract that
/// federation-forwarding traffic relies on.
#[test]
fn multiple_witnesses_in_sequence_preserved() {
    let kinds = [
        "ratchet-conscience",
        "lens-detector",
        "registry-attest",
        "joint-correlation-tier-2",
    ];

    let mut envelopes: Vec<EdgeEnvelope> = Vec::new();
    for (i, kind) in kinds.iter().enumerate() {
        let mut env = v015_envelope();
        env.signing_key_id = format!("edge-key-{i:04x}");
        env.testimonial_witness = Some(TestimonialWitness {
            kind: (*kind).to_string(),
            payload: serde_json::json!({"sequence_index": i, "kind_tag": kind}),
            issuer_key_id: format!("issuer-{i}"),
            issued_at: Utc::now(),
        });
        envelopes.push(env);
    }

    // Serialize the whole sequence to a JSON array — the
    // federation-forwarding shape edge produces in a multi-recipient
    // fan-out.
    let json_seq = serde_json::to_string(&envelopes).expect("serialize sequence");
    let back_seq: Vec<EdgeEnvelope> =
        serde_json::from_str(&json_seq).expect("deserialize sequence");

    assert_eq!(envelopes.len(), back_seq.len());
    for (i, (orig, back)) in envelopes.iter().zip(back_seq.iter()).enumerate() {
        let orig_w = orig.testimonial_witness.as_ref().expect("orig witness");
        let back_w = back.testimonial_witness.as_ref().expect("back witness");
        assert_eq!(orig_w.kind, back_w.kind, "kind preserved at index {i}");
        assert_eq!(
            orig_w.payload, back_w.payload,
            "payload preserved at index {i}"
        );
        assert_eq!(
            orig_w.issuer_key_id, back_w.issuer_key_id,
            "issuer preserved at index {i}"
        );
        assert_eq!(
            orig.signing_key_id, back.signing_key_id,
            "envelope identity preserved at index {i}"
        );
    }
}

/// Witness presence is observable at the JSON layer — the field
/// either rides as a discrete key or is omitted. This pins the
/// `skip_serializing_if = "Option::is_none"` contract so a
/// `serde(default)` mismatch on a downstream consumer cannot silently
/// substitute a default value.
#[test]
fn witness_field_omitted_when_none_present_when_some() {
    let env_none = v015_envelope();
    let json_none = serde_json::to_string(&env_none).expect("serialize none");
    assert!(!json_none.contains("testimonial_witness"));

    let mut env_some = v015_envelope();
    env_some.testimonial_witness = Some(TestimonialWitness {
        kind: "anything".to_string(),
        payload: serde_json::json!(null),
        issuer_key_id: "x".to_string(),
        issued_at: Utc::now(),
    });
    let json_some = serde_json::to_string(&env_some).expect("serialize some");
    assert!(json_some.contains("\"testimonial_witness\""));
}
