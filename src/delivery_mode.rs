//! CIRISEdge#411 §1 — the `delivery_mode` field processor.
//!
//! `delivery_mode` became a **typed `EnvelopeCore` field** in persist v21.9.0
//! (hoisted out of the untyped `extra` bag, byte-invariant under JCS). The
//! `field_processor_matrix` tags `delivery_mode` `owner_component: edge` with the
//! processor `reachability.rs#ReachabilityTracker::snapshot_all` — edge is the
//! component that must READ the field (typed, never from `extra`) and let its
//! VALUE drive delivery-path selection.
//!
//! This module is the value-semantics processor: it reads the typed field via
//! persist's [`EnvelopeCore::from_value`] (so a producer that hoisted the field
//! and a legacy producer that left it in `extra` both resolve identically, and a
//! presence-only scan of `extra` can never be fooled), classifies the delivery
//! requirement, and — fail-secure — refuses to treat an envelope the producer
//! marked `mandatory` as best-effort-droppable when no path is reachable.
//!
//! It does NOT own the transport selection itself (that is the scheduler /
//! `ReachabilityTracker`); it owns the *rule* the selection must honor, expressed
//! as a pure decision so it is exhaustively testable without the runtime.

use ciris_persist::federation::envelope::EnvelopeCore;

/// The wire token that marks an envelope's delivery as mandatory. Matches
/// persist's canonical value (`envelope.rs` witnesses `Some("mandatory")`); any
/// other value (including absent) is best-effort. Kept as the single source so a
/// value comparison, not a presence check, is what every caller performs.
pub const DELIVERY_MODE_MANDATORY: &str = "mandatory";

/// The delivery requirement an envelope's `delivery_mode` VALUE imposes on edge's
/// path selection. Derived from the value, never from field presence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRequirement {
    /// No `delivery_mode`, or a value other than [`DELIVERY_MODE_MANDATORY`] —
    /// best-effort; a no-reachable-path outcome may drop.
    BestEffort,
    /// `delivery_mode == "mandatory"` — the producer requires delivery. Edge must
    /// select a durable/reachable path and, if none exists, surface the miss
    /// (fail-loud, MISSION §3 anti-pattern 6), never silently drop.
    Mandatory,
}

/// Read the **typed** `delivery_mode` off a CEG envelope value via persist's
/// [`EnvelopeCore`] parser — the hoisted field, NOT `extra["delivery_mode"]`.
/// `None` when the envelope does not parse as an `EnvelopeCore` or carries no
/// `delivery_mode`. Reading through `EnvelopeCore::from_value` is what makes this
/// byte-invariant with persist (a hoisted producer and a legacy `extra` producer
/// resolve to the same typed value).
#[must_use]
pub fn delivery_mode_of(envelope: &serde_json::Value) -> Option<String> {
    EnvelopeCore::from_value(envelope.clone())
        .ok()
        .and_then(|core| core.delivery_mode)
}

/// The delivery requirement the envelope's `delivery_mode` VALUE imposes.
#[must_use]
pub fn requirement_of(envelope: &serde_json::Value) -> DeliveryRequirement {
    match delivery_mode_of(envelope).as_deref() {
        Some(DELIVERY_MODE_MANDATORY) => DeliveryRequirement::Mandatory,
        _ => DeliveryRequirement::BestEffort,
    }
}

/// The fail-secure path decision: given the envelope's delivery requirement and
/// whether ANY transport path to the destination is currently reachable (the
/// caller derives `path_reachable` from [`crate::reachability::ReachabilityTracker`]
/// `snapshot_all`/`snapshot`), decide what edge must do.
///
/// The load-bearing case is `(Mandatory, false)` → [`DeliveryDecision::FailLoudNoPath`]:
/// a producer-mandated envelope with no reachable path must NOT be silently
/// dropped. Best-effort with no path is a plain drop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryDecision {
    /// A reachable path exists — deliver.
    Deliver,
    /// Best-effort and no path — a permissible drop.
    DropBestEffort,
    /// Mandatory and no path — surface the miss; never a silent drop.
    FailLoudNoPath,
}

/// Resolve the delivery decision from the envelope's requirement + reachability.
#[must_use]
pub fn decide(envelope: &serde_json::Value, path_reachable: bool) -> DeliveryDecision {
    match (requirement_of(envelope), path_reachable) {
        (_, true) => DeliveryDecision::Deliver,
        (DeliveryRequirement::Mandatory, false) => DeliveryDecision::FailLoudNoPath,
        (DeliveryRequirement::BestEffort, false) => DeliveryDecision::DropBestEffort,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The typed read resolves the HOISTED field, and — the value-semantics
    /// guard — a legacy producer that left `delivery_mode` in the flattened body
    /// resolves identically (persist's `EnvelopeCore` flattens `extra`). A
    /// presence scan of `extra` alone could be fooled; reading the typed value
    /// cannot. Mirrors persist's `hoisted_fields_are_canonicalization_byte_invariant`.
    #[test]
    fn reads_the_typed_field_by_value() {
        let env = json!({
            "attesting_key_id": "agent-1",
            "attested_key_id": "agent-1",
            "attestation_type": "scores",
            "delivery_mode": "mandatory",
        });
        assert_eq!(delivery_mode_of(&env).as_deref(), Some("mandatory"));
        assert_eq!(requirement_of(&env), DeliveryRequirement::Mandatory);
    }

    /// Absent `delivery_mode` → best-effort (never defaulted to mandatory).
    #[test]
    fn absent_is_best_effort() {
        let env = json!({
            "attesting_key_id": "agent-1",
            "attested_key_id": "agent-1",
            "attestation_type": "scores",
        });
        assert_eq!(delivery_mode_of(&env), None);
        assert_eq!(requirement_of(&env), DeliveryRequirement::BestEffort);
    }

    /// A non-`mandatory` value is best-effort — the check is on the VALUE, not on
    /// the field being present.
    #[test]
    fn other_value_is_best_effort() {
        let env = json!({
            "attesting_key_id": "a", "attested_key_id": "a",
            "attestation_type": "scores", "delivery_mode": "best_effort",
        });
        assert_eq!(requirement_of(&env), DeliveryRequirement::BestEffort);
    }

    /// The fail-secure truth table: the ONE case that must never silently drop is
    /// (mandatory, no path).
    #[test]
    fn decide_is_fail_secure_for_mandatory() {
        let mandatory = json!({
            "attesting_key_id": "a", "attested_key_id": "a",
            "attestation_type": "scores", "delivery_mode": "mandatory",
        });
        let best_effort = json!({
            "attesting_key_id": "a", "attested_key_id": "a",
            "attestation_type": "scores",
        });
        assert_eq!(decide(&mandatory, true), DeliveryDecision::Deliver);
        assert_eq!(decide(&mandatory, false), DeliveryDecision::FailLoudNoPath);
        assert_eq!(decide(&best_effort, true), DeliveryDecision::Deliver);
        assert_eq!(
            decide(&best_effort, false),
            DeliveryDecision::DropBestEffort
        );
    }

    /// A non-object envelope does not parse as `EnvelopeCore` → best-effort, never
    /// a panic.
    #[test]
    fn non_object_envelope_is_best_effort() {
        assert_eq!(delivery_mode_of(&json!("not an object")), None);
        assert_eq!(requirement_of(&json!(42)), DeliveryRequirement::BestEffort);
    }
}
