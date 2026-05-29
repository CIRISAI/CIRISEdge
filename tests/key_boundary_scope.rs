//! CIRISEdge#38 (v0.16.0) — `key_boundary:{scope}` wire-form
//! round-trip tests per FSD-002 §3.4 + IEEE Ch6 (D26).
//!
//! v0.16.0 lands the WIRE-FORM PRIMITIVE only — Rust types, wire-string
//! codec, backward-compat parse. Enforcement (binding signatures to a
//! scope, refusing cross-scope verify) is v0.16.1+. See
//! `src/key_boundary.rs` and `docs/THREAT_MODEL.md` §AV-17 for the
//! invariant context (AV-17 is process-wide — the scope slot expresses
//! finer per-tenant / per-channel / per-cohort / per-data-class
//! isolation contracts the v0.16.1+ verifier will check).

use ciris_edge::key_boundary::{
    decode_scope_id, encode_scope_id, KeyBoundaryParseError, KeyBoundaryScope,
    LEGACY_NO_SEED_IN_HEAP,
};

/// Each variant of `KeyBoundaryScope` round-trips through
/// `as_wire_string` ↔ `from_wire_string` losslessly.
#[test]
fn scope_wire_string_round_trip_each_variant() {
    let cases = vec![
        KeyBoundaryScope::Process,
        KeyBoundaryScope::Tenant {
            tenant_id: "acme-corp".to_string(),
        },
        KeyBoundaryScope::Channel {
            channel_id: "ops-emergency".to_string(),
        },
        KeyBoundaryScope::Cohort {
            cohort_id: "cohort-zh-east".to_string(),
        },
        KeyBoundaryScope::DataClass {
            class: "phi-hipaa".to_string(),
        },
    ];
    for scope in cases {
        let wire = scope.as_wire_string();
        let back = KeyBoundaryScope::from_wire_string(&wire)
            .unwrap_or_else(|e| panic!("round-trip failed for {scope:?}: wire={wire}, err={e}"));
        assert_eq!(scope, back, "round-trip mismatch for {scope:?}");
        // Wire form must start/end with the canonical prefix/suffix.
        assert!(
            wire.starts_with("key_boundary:"),
            "wire form must use 'key_boundary:' prefix; got {wire}"
        );
        assert!(
            wire.ends_with(":no_seed_in_heap"),
            "wire form must use ':no_seed_in_heap' suffix; got {wire}"
        );
    }
}

/// Backward-compat: the v0.15.x wire string `key_boundary:no_seed_in_heap`
/// (no scope segment between prefix and suffix) parses as
/// `KeyBoundaryScope::Process`. Pre-v0.16.0 traffic continues to verify.
#[test]
fn legacy_no_seed_in_heap_string_parses_as_process() {
    let parsed =
        KeyBoundaryScope::from_wire_string(LEGACY_NO_SEED_IN_HEAP).expect("legacy form must parse");
    assert_eq!(parsed, KeyBoundaryScope::Process);

    // And the modern explicit form is also Process.
    let explicit = KeyBoundaryScope::from_wire_string("key_boundary:process:no_seed_in_heap")
        .expect("explicit process form must parse");
    assert_eq!(explicit, KeyBoundaryScope::Process);
}

/// Scope IDs may contain `:`, `/`, whitespace, and backslashes — the
/// wire-string codec escapes them and decodes them back. This is the
/// load-bearing test for the encoder: an unescaped `:` in a scope-id
/// would be misparsed as the kind separator and break the wire-form
/// round-trip.
#[test]
fn scope_with_special_chars_quoted_correctly() {
    let tricky = vec![
        // Colons embedded in the scope-id.
        "tenant-with:colon",
        "tenant:multi:colons:here",
        // Backslashes.
        r"tenant\with\backslash",
        r"tenant\\double\\backslash",
        // Slashes and whitespace.
        "tenant/with/slash",
        "tenant with spaces",
        "tenant\twith\ttabs",
        // Combinations.
        r"weird\:tenant: with all/the\\chars",
    ];

    for id in tricky {
        let scope = KeyBoundaryScope::Tenant {
            tenant_id: id.to_string(),
        };
        let wire = scope.as_wire_string();
        let back = KeyBoundaryScope::from_wire_string(&wire).unwrap_or_else(|e| {
            panic!("round-trip failed for tenant_id={id:?}, wire={wire:?}, err={e}")
        });
        assert_eq!(scope, back, "round-trip mismatch for tenant_id={id:?}");
    }
}

/// The codec primitives (`encode_scope_id` / `decode_scope_id`)
/// round-trip every input losslessly — the property test on the
/// per-character escape rules. Includes 0-length and pathological
/// escape-sequence inputs.
#[test]
fn scope_id_codec_round_trip() {
    let inputs = vec![
        String::new(),
        "plain".to_string(),
        ":".to_string(),
        "\\".to_string(),
        "::".to_string(),
        "\\\\".to_string(),
        "\\:".to_string(),
        ":\\".to_string(),
        // ASCII 0x21..=0x7E.
        (0x21u8..=0x7Eu8).map(|b| b as char).collect::<String>(),
    ];
    for s in inputs {
        let encoded = encode_scope_id(&s);
        let decoded = decode_scope_id(&encoded).expect("decode");
        assert_eq!(s, decoded, "codec round-trip failed for {s:?}");
    }
}

/// Error cases — malformed wire strings yield typed errors.
#[test]
fn malformed_wire_strings_yield_typed_errors() {
    // Missing prefix.
    let r = KeyBoundaryScope::from_wire_string("xxx:tenant:abc:no_seed_in_heap");
    assert!(matches!(r, Err(KeyBoundaryParseError::MissingPrefix)));

    // Missing suffix.
    let r = KeyBoundaryScope::from_wire_string("key_boundary:tenant:abc:wrong_suffix");
    assert!(matches!(r, Err(KeyBoundaryParseError::MissingSuffix)));

    // Unknown kind.
    let r = KeyBoundaryScope::from_wire_string("key_boundary:nonsense:foo:no_seed_in_heap");
    match r {
        Err(KeyBoundaryParseError::UnknownKind { kind }) => assert_eq!(kind, "nonsense"),
        other => panic!("expected UnknownKind, got {other:?}"),
    }

    // Missing scope-id for a kind that requires one.
    let r = KeyBoundaryScope::from_wire_string("key_boundary:tenant:no_seed_in_heap");
    // The parser splits on first raw `:` so the body `tenant` will
    // produce MissingScopeId because rest is None. Note the string
    // `key_boundary:tenant:no_seed_in_heap` — strip_prefix leaves
    // `tenant:no_seed_in_heap`, strip_suffix leaves `tenant`,
    // split_kind returns ("tenant", None) → MissingScopeId.
    match r {
        Err(KeyBoundaryParseError::MissingScopeId { kind }) => assert_eq!(kind, "tenant"),
        other => panic!("expected MissingScopeId, got {other:?}"),
    }

    // Process variant with a phantom scope-id rejected.
    let r = KeyBoundaryScope::from_wire_string("key_boundary:process:phantom:no_seed_in_heap");
    assert!(matches!(r, Err(KeyBoundaryParseError::UnknownKind { .. })));

    // Dangling backslash escape in the scope-id.
    let raw = decode_scope_id(r"trailing\");
    assert!(matches!(raw, Err(KeyBoundaryParseError::DanglingEscape)));
}

/// Pin the canonical wire-string shape for each variant — golden
/// strings the federation cross-repo contract MUST not drift on. This
/// is the FSD-002 §3.4 wire-locked surface.
#[test]
fn canonical_wire_strings_pinned() {
    assert_eq!(
        KeyBoundaryScope::Process.as_wire_string(),
        "key_boundary:process:no_seed_in_heap"
    );
    assert_eq!(
        KeyBoundaryScope::Tenant {
            tenant_id: "acme".to_string()
        }
        .as_wire_string(),
        "key_boundary:tenant:acme:no_seed_in_heap"
    );
    assert_eq!(
        KeyBoundaryScope::Channel {
            channel_id: "ops".to_string()
        }
        .as_wire_string(),
        "key_boundary:channel:ops:no_seed_in_heap"
    );
    assert_eq!(
        KeyBoundaryScope::Cohort {
            cohort_id: "eu-east".to_string()
        }
        .as_wire_string(),
        "key_boundary:cohort:eu-east:no_seed_in_heap"
    );
    assert_eq!(
        KeyBoundaryScope::DataClass {
            class: "phi".to_string()
        }
        .as_wire_string(),
        "key_boundary:data_class:phi:no_seed_in_heap"
    );
}

/// `KeyBoundaryScope` serializes via serde to a typed JSON
/// representation (tagged variant via the `kind` discriminator). Pin
/// the shape so a `key_boundary_scope` field on an `EdgeEnvelope`
/// matches what consumers across the federation expect.
#[test]
fn serde_json_shape_matches_tagged_kind() {
    let process_json = serde_json::to_string(&KeyBoundaryScope::Process).unwrap();
    assert_eq!(process_json, r#"{"kind":"process"}"#);

    let tenant_json = serde_json::to_string(&KeyBoundaryScope::Tenant {
        tenant_id: "acme".to_string(),
    })
    .unwrap();
    assert_eq!(tenant_json, r#"{"kind":"tenant","tenant_id":"acme"}"#);

    let class_json = serde_json::to_string(&KeyBoundaryScope::DataClass {
        class: "phi-hipaa".to_string(),
    })
    .unwrap();
    assert_eq!(class_json, r#"{"kind":"data_class","class":"phi-hipaa"}"#);

    // And round-trip.
    let back: KeyBoundaryScope = serde_json::from_str(&tenant_json).unwrap();
    assert_eq!(
        back,
        KeyBoundaryScope::Tenant {
            tenant_id: "acme".to_string()
        }
    );
}

/// The envelope-level `key_boundary_scope` field rides on
/// `EdgeEnvelope` exactly the way the brief specifies: optional, skipped
/// when None (backward-compat byte-equal), present when Some. This
/// test bridges the wire-string codec to the envelope serde shape.
#[test]
fn envelope_carries_scope_when_set() {
    use chrono::{DateTime, Utc};
    use ciris_edge::messages::{EdgeEnvelope, MessageType, SchemaVersion};
    use serde_json::value::RawValue;

    let body: Box<RawValue> =
        RawValue::from_string(r#"{"text":"x"}"#.to_string()).expect("raw value");
    let env = EdgeEnvelope {
        edge_schema_version: SchemaVersion::V1_0_0,
        signing_key_id: "k1".to_string(),
        destination_key_id: "k2".to_string(),
        message_type: MessageType::InlineText,
        sent_at: DateTime::parse_from_rfc3339("2026-05-29T00:00:00.000Z")
            .unwrap()
            .with_timezone(&Utc),
        nonce: [0u8; 16],
        body,
        signature: "x".to_string(),
        signature_pqc: None,
        in_reply_to: None,
        testimonial_witness: None,
        key_boundary_scope: Some(KeyBoundaryScope::Tenant {
            tenant_id: "acme".to_string(),
        }),
    };

    let json = serde_json::to_string(&env).expect("serialize");
    assert!(json.contains("\"key_boundary_scope\""));
    assert!(json.contains("\"tenant\""));
    assert!(json.contains("\"acme\""));

    let back: EdgeEnvelope = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(env.key_boundary_scope, back.key_boundary_scope);
}
