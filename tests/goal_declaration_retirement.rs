//! Acceptance gate for CIRISEdge#41 — `GoalDeclaration` + `GoalRetirement`
//! federation wire transport for the typed `Goal` primitive landed in
//! CIRISPersist#114 (persist v2.10.0). v0.11.1.
//!
//! Wire-shape pins:
//!
//! 1. Round-trip — declare a Goal, encode + verify the envelope, decode
//!    back and confirm every field (including `m1_rationale` carried on
//!    `meta_goal_alignment.rationale`) is preserved.
//! 2. Canonical-bytes determinism — same Goal must produce identical
//!    canonical bytes across runs (the F-3 detector pivot on
//!    `(goal_id, declared_by_key_id, m1_rationale, ...)` requires byte
//!    stability).
//! 3. Single-signer retirement round-trip — the
//!    `(goal_id, retired_at, retired_by_key_id, reason)` shape survives
//!    encode + envelope-level signature + decode.
//! 4. Delivery-class pins — both wire types MUST declare
//!    `Delivery::Durable` (per #41 §"Delivery posture").
//! 5. Regression guard — the m1 rationale's bytes MUST appear in the
//!    canonical-bytes output (changing the rationale changes the
//!    canonical bytes — the load-bearing anti-route-around invariant
//!    against attractor capture).
//! 6. Wire-shape sanity — `MessageType::GoalDeclaration` is distinct
//!    from `MessageType::StewardDirective` (post-CIRISEdge#20 merge).

use std::fmt::Write as _;

use ciris_edge::handler::Delivery;
use ciris_edge::{
    GoalDeclaration, GoalRetirement, Message, MessageType, GOAL_DECLARATION_DOMAIN,
    GOAL_RETIREMENT_DOMAIN,
};
use ciris_persist::federation::goal::{
    DeliberationRef, Goal, GoalScope, M1Dimension, MetaGoalAlignment,
};

// ─── Fixtures ───────────────────────────────────────────────────────

const FIXTURE_RATIONALE: &str = "preserves cohort heterogeneity across pilot sites";

fn fixture_goal() -> Goal {
    let declared_at = chrono::DateTime::parse_from_rfc3339("2026-05-28T12:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);
    Goal::new(
        // Deterministic UUID — pins canonical-bytes determinism.
        uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        "lens-steward".into(),
        declared_at,
        "publish quarterly federation health report".into(),
        GoalScope::Cohort {
            cohort_id: "stewards".into(),
        },
        MetaGoalAlignment::new(
            M1Dimension::Plurality,
            FIXTURE_RATIONALE.into(),
            Some(DeliberationRef {
                artifact_type: "pdma".into(),
                artifact_id: "pdma-2026-05".into(),
            }),
        ),
    )
}

fn fixture_retirement() -> GoalRetirement {
    GoalRetirement {
        goal_id: uuid::Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
        retired_at: chrono::DateTime::parse_from_rfc3339("2026-09-01T12:00:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc),
        retired_by_key_id: "lens-steward".into(),
        reason: Some("supplanted by 2026-Q4 cycle goal".into()),
    }
}

// ─── Tests ──────────────────────────────────────────────────────────

/// Round-trip — a fully-populated `Goal` (including the optional
/// `DeliberationRef`) survives the wire-body JSON encode + decode. Pins
/// CIRISEdge#41's "Goal fields preserved including m1_rationale" ask.
#[test]
fn goal_declaration_round_trip() {
    let goal = fixture_goal();
    let declaration = GoalDeclaration(goal.clone());

    // `#[serde(transparent)]` newtype — the wire body IS the inner Goal.
    let wire = serde_json::to_string(&declaration).expect("serialize");
    let back: GoalDeclaration = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back.0.goal_id, goal.goal_id);
    assert_eq!(back.0.declared_by_key_id, goal.declared_by_key_id);
    assert_eq!(back.0.declared_at, goal.declared_at);
    assert_eq!(back.0.goal_text, goal.goal_text);
    assert_eq!(back.0.scope, goal.scope);
    // M-1 alignment — the load-bearing structural invariant.
    assert_eq!(back.0.meta_goal_alignment.dimension, M1Dimension::Plurality);
    assert_eq!(
        back.0.meta_goal_alignment.rationale, FIXTURE_RATIONALE,
        "m1_rationale (meta_goal_alignment.rationale) MUST survive round-trip — \
         it is the F-3 detector input per CIRISEdge#41"
    );
    assert_eq!(
        back.0.meta_goal_alignment.deliberation_ref,
        goal.meta_goal_alignment.deliberation_ref
    );

    // Canonical-bytes domain prefix is the LOCKED wire constant.
    let cb = declaration.canonical_bytes();
    assert!(
        cb.starts_with(GOAL_DECLARATION_DOMAIN),
        "canonical bytes must be domain-separated with GOAL_DECLARATION_DOMAIN"
    );
}

/// Canonical-bytes determinism — the same Goal must produce identical
/// canonical bytes across runs (the F-3 detector relies on byte-stable
/// hashing of the canonical form for cross-peer aggregation).
#[test]
fn goal_declaration_canonical_bytes_deterministic() {
    let a = GoalDeclaration(fixture_goal()).canonical_bytes();
    let b = GoalDeclaration(fixture_goal()).canonical_bytes();
    assert_eq!(
        a, b,
        "canonical bytes MUST be deterministic across runs — \
         F-3 aggregation pivots on byte-stable hashing"
    );

    // Sanity — two GENUINELY different goals must produce DIFFERENT
    // canonical bytes (the encoding is injective per the length-prefix
    // discipline mirrored from DeliveryAttestation).
    let mut other = fixture_goal();
    other.declared_by_key_id = "different-steward".into();
    let c = GoalDeclaration(other).canonical_bytes();
    assert_ne!(
        a, c,
        "distinct goals must produce distinct canonical bytes (injective encoding)"
    );
}

/// `SignedGoalRetirement`-equivalent round-trip. Per CIRISEdge#41 §"Out
/// of scope", persist's `retire_goal` API is `(goal_id, retired_at)`
/// only — the wire body carries declarer attribution + reason on top so
/// the receiver can route the call and audit the retirement; the
/// envelope's hybrid signature IS the proof-of-authority (no
/// body-internal signature at v0.11.1).
#[test]
fn goal_retirement_round_trip() {
    let r = fixture_retirement();
    let wire = serde_json::to_string(&r).expect("serialize");
    let back: GoalRetirement = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back, r);

    // Optional reason — None should serialize away.
    let mut no_reason = fixture_retirement();
    no_reason.reason = None;
    let wire = serde_json::to_string(&no_reason).expect("serialize");
    assert!(
        !wire.contains("\"reason\""),
        "None reason must elide via skip_serializing_if; got: {wire}"
    );
    let back: GoalRetirement = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back, no_reason);

    let cb = GoalRetirement::canonical_bytes(&r);
    assert!(
        cb.starts_with(GOAL_RETIREMENT_DOMAIN),
        "canonical bytes must be domain-separated with GOAL_RETIREMENT_DOMAIN"
    );
}

/// Delivery-class pin for `GoalDeclaration` — `Delivery::Durable` per
/// CIRISEdge#41 §"Delivery posture" (federation evidence, NOT
/// best-effort; must reach every interested peer for F-3 aggregation).
/// A regression that demotes this to `Ephemeral` would silently drop
/// goals on transient network blips.
#[test]
fn goal_declaration_delivery_class_is_durable() {
    match <GoalDeclaration as Message>::DELIVERY {
        Delivery::Durable {
            requires_ack,
            max_attempts,
            ttl_seconds,
            ack_timeout_seconds,
        } => {
            assert!(
                requires_ack,
                "GoalDeclaration must declare requires_ack=true — \
                 the GoalDeclarationResponse IS the observable accept/reject"
            );
            assert!(
                max_attempts >= 20,
                "long-haul durable shape; max_attempts {max_attempts} too low for federation evidence"
            );
            assert!(
                ttl_seconds >= 24 * 60 * 60,
                "long-haul durable shape; ttl_seconds {ttl_seconds} too short for federation evidence"
            );
            assert!(ack_timeout_seconds.is_some());
        }
        other => panic!("GoalDeclaration::DELIVERY must be Durable; got {other:?}"),
    }
    assert_eq!(GoalDeclaration::TYPE, MessageType::GoalDeclaration);
}

/// Delivery-class pin for `GoalRetirement` — same `Delivery::Durable`
/// shape as `GoalDeclaration`. An unrecorded retirement looks the same
/// as a live goal to F-3 (the false-positive failure mode CIRISEdge#41
/// §"Delivery posture" calls out).
#[test]
fn goal_retirement_delivery_class_is_durable() {
    match <GoalRetirement as Message>::DELIVERY {
        Delivery::Durable { requires_ack, .. } => {
            assert!(
                requires_ack,
                "GoalRetirement must declare requires_ack=true — \
                 an unrecorded retirement looks the same as a live goal to F-3"
            );
        }
        other => panic!("GoalRetirement::DELIVERY must be Durable; got {other:?}"),
    }
    assert_eq!(GoalRetirement::TYPE, MessageType::GoalRetirement);
}

/// **Regression guard.** The m1_rationale field's content MUST appear
/// in `GoalDeclaration::canonical_bytes()`. This is the load-bearing
/// anti-route-around invariant: if the canonical bytes omit the
/// rationale, a declarer can hold the same canonical-bytes hash while
/// mutating the rationale — exactly the attractor-capture failure mode
/// MISSION.md §1 names + CIRISEdge#41 calls out structurally.
#[test]
fn goal_declaration_m1_rationale_in_canonical_bytes() {
    let goal = fixture_goal();
    let declaration = GoalDeclaration(goal);
    let cb = declaration.canonical_bytes();

    // Hex-encode the canonical bytes; grep the rationale.
    let hex = cb.iter().fold(String::new(), |mut acc, b| {
        let _ = write!(acc, "{b:02x}");
        acc
    });
    let needle_hex = FIXTURE_RATIONALE
        .as_bytes()
        .iter()
        .fold(String::new(), |mut acc, b| {
            let _ = write!(acc, "{b:02x}");
            acc
        });
    assert!(
        hex.contains(&needle_hex),
        "canonical bytes MUST contain the m1_rationale field's content — \
         the F-3 attractor-capture defense. Rationale '{FIXTURE_RATIONALE}' \
         was not found in canonical bytes (hex: {hex})"
    );

    // Mutating ONLY the rationale must change the canonical bytes
    // (the field IS load-bearing, not vestigial).
    let mut mutated = fixture_goal();
    mutated.meta_goal_alignment.rationale = "completely different rationale".into();
    let cb_mutated = GoalDeclaration(mutated).canonical_bytes();
    assert_ne!(
        cb, cb_mutated,
        "mutating the m1_rationale MUST change the canonical bytes — \
         otherwise a declarer routes around F-3 by varying rationale"
    );
}

/// Wire-shape sanity post-CIRISEdge#20 merge — the new
/// `MessageType::GoalDeclaration` variant is distinct from
/// `MessageType::StewardDirective` (the most recent prior addition,
/// v0.10.0). Pin so a future merge accident that aliases two variants
/// is caught at the wire layer.
#[test]
fn goal_declaration_message_type_distinct_from_steward_directive() {
    assert_ne!(
        MessageType::GoalDeclaration,
        MessageType::StewardDirective,
        "GoalDeclaration and StewardDirective MUST be distinct wire-type \
         variants (post-CIRISEdge#20 v0.10.0 + CIRISEdge#41 v0.11.1)"
    );
    assert_ne!(MessageType::GoalDeclaration, MessageType::GoalRetirement);
    assert_ne!(MessageType::GoalRetirement, MessageType::StewardDirective);

    // serde-wire-shape pin: the new variants serialize to their
    // PascalCase names (matching the existing MessageType convention —
    // no `rename_all` on the enum).
    assert_eq!(
        serde_json::to_string(&MessageType::GoalDeclaration).unwrap(),
        r#""GoalDeclaration""#
    );
    assert_eq!(
        serde_json::to_string(&MessageType::GoalRetirement).unwrap(),
        r#""GoalRetirement""#
    );
}
