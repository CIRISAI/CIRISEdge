//! CIRISEdge#411 §5 — the manifest-driven field-conformance harness.
//!
//! The keystone of the #519 program: the SAME `field_processor_matrix` that tags
//! a field `owner_component ⊇ edge` GENERATES edge's conformance obligation for
//! it. A field tagged to edge that edge neither processes (with a value-semantics
//! check) nor explicitly defers (with a reason) is a **completeness gap the build
//! must catch** — the `#315` carried-but-unprocessed dead-plane class the whole
//! program exists to kill.
//!
//! Mirrors persist's own `namespace::conformance` exemplar (its
//! `persist_field_conformance()` FFI): every owned field is EITHER an
//! [`EDGE_FIELD_CONFORMANCE`] row with a `check` that verifies the field's
//! VALUE/behaviour, OR a [`DEFERRED_PENDING_PLANE`] row whose reason names the
//! upstream plane/entrypoint that must land before edge can soundly process it.
//! [`every_edge_tagged_field_is_accounted_for`] cross-checks the union against
//! persist's live matrix, so a NEW edge-tagged row persist ships fails edge's
//! build until edge categorizes it.

/// One edge-owned field's conformance obligation — a value/behaviour property and
/// a pure check that proves edge's processor honors it. Mirrors persist's
/// `FieldConformance` (a `fn() -> Result<(), String>`, so the whole table runs
/// without async / a live directory — the checks assert the pure, value-semantics
/// invariants, never presence).
pub struct FieldConformance {
    /// The manifest field string (EXACT — matched against `field_processor_matrix`).
    pub field: &'static str,
    /// The value/behaviour property this check proves.
    pub property: &'static str,
    /// The check — `Ok(())` conformant, `Err(reason)` a violation.
    pub check: fn() -> Result<(), String>,
    /// CIRISEdge#410 Ask 3 — the Constitution CC section this routing processor
    /// serves (the `CC-<section>` the `evidence/CIRISEdge.cc_impl.tsv` row keys on).
    pub cc: &'static str,
    /// The `CLM-nsproc-*` claim name this row resolves (CIRISEdge#410 §3).
    pub clm: &'static str,
    /// The `path#symbol` evidence anchor — the LIVE processor the check exercises,
    /// so the evidence registry is generated from the tested code, never a
    /// hand-maintained string that can drift from it.
    pub evidence: &'static str,
}

/// Every edge-tagged field edge PROCESSES, with a check that verifies the value
/// semantics (not presence). The `restrictions[].op=recipient_capability` row is
/// here — the manifest still marks it `proposed:`, but edge shipped the processor
/// (`recipient_capability_withholds`) in v14.1; this table is the truth.
pub const EDGE_FIELD_CONFORMANCE: &[FieldConformance] = &[
    FieldConformance {
        field: "delivery_mode",
        property: "the typed value drives a fail-secure path decision (mandatory + no path ⇒ never a silent drop)",
        check: check_delivery_mode,
        cc: "5.3.3",
        clm: "CLM-nsproc-delivery-mode",
        evidence: "src/delivery_mode.rs#decide",
    },
    FieldConformance {
        field: "cohort_scope",
        property: "projection is a total function of the cohort_scope VALUE (offer/projection filter)",
        check: check_cohort_scope_projection,
        cc: "3.3.6",
        clm: "CLM-nsproc-cohort-scope",
        evidence: "src/replication/bridge.rs#attestation_is_advertised",
    },
    FieldConformance {
        field: "dimension",
        property: "the record's projection authority is resolved from the dimension VALUE (per-record projection)",
        check: check_dimension_projection,
        cc: "3.1",
        clm: "CLM-nsproc-dimension",
        evidence: "src/replication/bridge.rs#attestation_is_advertised",
    },
    FieldConformance {
        field: "key_boundary_scope",
        property: "every scope variant round-trips through its wire form (typed discriminator, opaque id)",
        check: check_key_boundary_scope,
        cc: "3.4",
        clm: "CLM-nsproc-key-boundary-scope",
        evidence: "src/key_boundary.rs#KeyBoundaryScope",
    },
    FieldConformance {
        field: "recipient_serve_capability",
        property: "the serve gate keys on persist's INFRA_SERVE const, never a hand-rolled token (the #379 value-provenance lock)",
        check: check_recipient_serve_capability_token,
        cc: "5.3.3.5",
        clm: "CLM-nsproc-recipient-serve-capability",
        evidence: "src/replication/bridge.rs#peer_has_serve_capability",
    },
    FieldConformance {
        field: "restrictions[].op=recipient_capability",
        property: "a recipient_capability restriction is honored as a WITHHOLD, never routed through the strip pipeline",
        check: check_recipient_capability_is_withhold_not_strip,
        cc: "5.3.2.4",
        clm: "CLM-nsproc-recipient-capability",
        evidence: "src/replication/bridge.rs#recipient_capability_withholds",
    },
    FieldConformance {
        field: "attestation_prefixes",
        property: "a grant's prefix gates a dimension by str::starts_with (covers), the exact predicate the serve gate applies",
        check: check_attestation_prefixes_covers,
        cc: "5.3.2.4",
        clm: "CLM-nsproc-attestation-prefixes",
        evidence: "src/replication/bridge.rs#recipient_capability_withholds",
    },
];

/// Every edge-tagged field edge does NOT process with a runtime value-check —
/// each with the concrete upstream reason. Deferring is NOT skipping: the field
/// is still ACCOUNTED FOR (the completeness test asserts it), and the reason names
/// exactly what must land first. Mirrors persist's `AHEAD_OF_MATRIX` exemption
/// discipline, inverted (BEHIND, pending a plane).
pub const DEFERRED_PENDING_PLANE: &[(&str, &str)] = &[
    // ── The projection-time strips (§1/§3). Unsound on edge's wire, not skipped. ──
    (
        "evidence_disclosure",
        "serve-time strip is UNSOUND on edge's content-addressed signed wire (#397): the \
      recipient fetches by content_hash and re-verifies the hybrid signature at \
      put_attestation, so stripping a field breaks both. persist applies StripField at \
      PROMOTION before signing (promote_attestation_with_transforms, v21.7.0) and \
      explicitly scoped general serve-layer transforms as a follow-up — this is \
      persist-owned, not an edge processor.",
    ),
    (
        "raw_probe_payloads",
        "same content-addressed-wire unsoundness; the strip is a persist PROMOTION-side \
      transform, not an edge serve-time op.",
    ),
    (
        "raw_observation_refs",
        "same content-addressed-wire unsoundness; persist promotion-side.",
    ),
    // ── Emit-side conventions / planes not yet landed. ──
    (
        "builder_id",
        "an emit-side OMISSION convention (a producer chooses not to emit builder_id), not \
      a runtime processor; no wire plane to check.",
    ),
    (
        "cell-vs-federation scope-boundary check",
        "a producer convention (proposed:); no edge runtime plane.",
    ),
    (
        "class (auto-fire vs route-to-moderator at match time)",
        "the safety/watchlist plane is not landed (persist marks the watchlist row \
      proposed:/unassigned); no edge processor to check against a non-existent plane.",
    ),
    (
        "mode (AlertOnly vs Enforce)",
        "the hash-match enforcement plane is not landed (proposed:src/safety/hash_match.rs); \
      no plane to process.",
    ),
    (
        "manifest.content_hash",
        "no manifest-retrieval path exists yet (persist marks proposed:); nothing to verify.",
    ),
    (
        "trigger_excerpt_hash",
        "the ContentFetch caller-gate (Tier B) is not landed; no plane to process.",
    ),
    (
        "federation_keys.consent_role",
        "the ProbePatternObserver consent-role plane is proposed:; no runtime edge processor.",
    ),
    // ── Shared fields whose VALUE semantics are owned by persist/verify. ──
    (
        "score",
        "the score VALUE semantics (BooleanMin, scores.rs#value_of) are persist-owned; edge \
      routes score attestations via the Attestation projection (checked under \
      cohort_scope/dimension), it computes no score value.",
    ),
    (
        "evidence_refs",
        "verify-owned (ciris-verify-core holds_bytes.rs#verify_holds_bytes); edge CONSUMES \
      holds_bytes via the content-fetch path, it runs no evidence_refs value processor.",
    ),
    // ── REAL edge processors whose behaviour lives in async serve/relay paths, ──
    // ── covered by module-level integration tests rather than a sync pure check. ──
    (
        "withdrawal_reason",
        "processed by edge.rs#emit_withdraws (ContentMiss → withdraws); the behaviour is an \
      async relay path covered by its own integration test, not a sync pure check.",
    ),
    (
        "delivery durability",
        "processed by messages GoalDeclaration::DELIVERY / GoalRetirement::DELIVERY; covered \
      by the messages module tests.",
    ),
    (
        "holder staleness/TTL + ContentMiss->withdraws",
        "processed by transport/reticulum.rs#filter_holders_with_policy; covered by the \
      reticulum holder-policy tests, an async path.",
    ),
];

/// CIRISEdge#410 §3 — emit edge's routing-processor evidence rows in the
/// `CIRISEdge.cc_impl.tsv` format the Constitution's `check_evidence.py` vendors
/// (`<cc>\t<clm>\tCIRISEdge\t<path#symbol>\tciris-edge@v<version>`). Generated
/// from [`EDGE_FIELD_CONFORMANCE`] — the SAME table the completeness witness
/// checks — so every published evidence row anchors a LIVE, tested processor and
/// can never drift from the code. The vendored `evidence/CIRISEdge.cc_impl.tsv`
/// is regenerated from this and kept in sync by `evidence_tsv_matches_emitted`.
#[must_use]
pub fn edge_evidence_rows() -> Vec<String> {
    // CIRISEdge#442 — the HEADER ROW is load-bearing: the Constitution's
    // check_claims.py strips `#` comments and hands the remainder to
    // csv.DictReader, which consumes the first non-comment line as the
    // header. Without it the first DATA row became the header and every
    // other row was silently skipped — the file vendored as zero coverage
    // and failed nothing ("silence reads as coverage",
    // CIRISConstitution#54). Column names mirror persist's evidence file
    // verbatim.
    std::iter::once("decimal_id\tclaim_id\trepo\tpath#symbol\tcrate@version".to_string())
        .chain(EDGE_FIELD_CONFORMANCE.iter().map(|c| {
            format!(
                "{}\t{}\tCIRISEdge\t{}\tciris-edge@v{}",
                c.cc,
                c.clm,
                c.evidence,
                env!("CARGO_PKG_VERSION"),
            )
        }))
        .collect()
}

/// Run the harness: `Ok(())` iff every [`EDGE_FIELD_CONFORMANCE`] check passes.
/// The FFI (`edge_field_conformance()`) returns the violation list; empty = pass.
///
/// # Errors
/// Returns the `"{field}: {reason}"` violation strings when a check fails.
pub fn run_edge_field_conformance() -> Result<(), Vec<String>> {
    let mut violations = Vec::new();
    for c in EDGE_FIELD_CONFORMANCE {
        if let Err(reason) = (c.check)() {
            violations.push(format!("{}: {reason}", c.field));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── the pure value-semantics checks ────────────────────────────────────────

fn check_delivery_mode() -> Result<(), String> {
    use crate::delivery_mode::{decide, DeliveryDecision};
    let mandatory = serde_json::json!({
        "attesting_key_id": "a", "attested_key_id": "a",
        "attestation_type": "scores", "delivery_mode": "mandatory",
    });
    let best_effort = serde_json::json!({
        "attesting_key_id": "a", "attested_key_id": "a", "attestation_type": "scores",
    });
    if decide(&mandatory, false) != DeliveryDecision::FailLoudNoPath {
        return Err("mandatory + no reachable path must FailLoudNoPath, never drop".into());
    }
    if decide(&best_effort, false) != DeliveryDecision::DropBestEffort {
        return Err("best-effort + no path must be a permissible drop".into());
    }
    if decide(&mandatory, true) != DeliveryDecision::Deliver {
        return Err("any mode with a reachable path delivers".into());
    }
    Ok(())
}

fn check_cohort_scope_projection() -> Result<(), String> {
    use ciris_persist::federation::namespace::Projection;
    use ciris_persist::federation::namespace::{
        projection_for, registry::authority_for, tombstone_ceiling, ObjectClass,
    };
    use ciris_persist::federation::types::cohort_scope;
    // CIRISPersist#713 / v35.0.0 — the projection is per-PLANE. It must be TOTAL
    // over (plane × the 7 closed cohort scopes) — edge's offer/projection filter
    // is a function of this value, so an unhandled cell would be a routing hole.
    // `authority_for` on a benign dimension gives a concrete AuthorityClass.
    let authority = authority_for("trust:example:v1").class;
    for plane in [
        ObjectClass::Attestation,
        ObjectClass::KeyRecord,
        ObjectClass::TransportDestination,
        ObjectClass::FountainContent,
        ObjectClass::HardCaseEvent,
    ] {
        for scope in [
            cohort_scope::SELF,
            cohort_scope::FAMILY,
            cohort_scope::COMMUNITY,
            cohort_scope::AFFILIATIONS,
            cohort_scope::SPECIES,
            cohort_scope::BIOSPHERE,
            cohort_scope::FEDERATION,
        ] {
            // Both tombstone polarities — total over the value domain.
            let _ = projection_for(plane, scope, authority, false);
            let _ = projection_for(plane, scope, authority, true);
        }
    }
    // Value-semantics witnesses. Structural invisibility holds on every plane:
    if projection_for(ObjectClass::KeyRecord, cohort_scope::SELF, authority, false)
        != Projection::SelfOwn
    {
        return Err("cohort_scope=self must project SelfOwn (structural invisibility)".into());
    }
    // #713 — the per-plane CEILING replaces unconditional tombstone-Global.
    // Key-plane tombstones stay Global (verify-relevance is unbounded)…
    if projection_for(ObjectClass::KeyRecord, cohort_scope::SELF, authority, true)
        != Projection::Global
    {
        return Err("a KeyRecord tombstone must project Global (anti-rollback)".into());
    }
    // …while a non-root reachability tombstone projects at the plane ceiling
    // (Cohort), NOT Global — widening a tombstone would disclose more than the
    // original fact ("this route was withdrawn" reveals the route existed).
    // This is the limb-(b) close: reachability no longer inherits the key
    // plane's audience (CIRISEdge#311 / CIRISPersist#713).
    if !authority.is_trust_root()
        && projection_for(
            ObjectClass::TransportDestination,
            cohort_scope::SELF,
            authority,
            true,
        ) != Projection::Cohort
    {
        return Err(
            "a non-root reachability tombstone must project at the plane ceiling \
             (Cohort), not Global (contextual integrity, CIRISPersist#713)"
                .into(),
        );
    }
    // The ceiling identity the resolver documents: tombstone projection equals
    // tombstone_ceiling(plane, authority) by construction.
    if projection_for(
        ObjectClass::TransportDestination,
        cohort_scope::FEDERATION,
        authority,
        true,
    ) != tombstone_ceiling(ObjectClass::TransportDestination, authority)
    {
        return Err("tombstone projection must equal tombstone_ceiling(plane, authority)".into());
    }
    Ok(())
}

fn check_dimension_projection() -> Result<(), String> {
    use ciris_persist::federation::namespace::{projection_for, registry::authority_for};
    // Per-record projection resolves the authority CLASS from the dimension VALUE,
    // then feeds it to `projection_for`. The value-semantics property: the same
    // dimension resolves DETERMINISTICALLY to the same per-record projection (edge
    // routes each record by its actual dimension, not by presence). A
    // non-deterministic or panicking resolution would be a routing hole.
    use ciris_persist::federation::namespace::ObjectClass;
    let dimension = "trust:example:v1";
    let a = projection_for(
        ObjectClass::Attestation,
        "federation",
        authority_for(dimension).class,
        false,
    );
    let b = projection_for(
        ObjectClass::Attestation,
        "federation",
        authority_for(dimension).class,
        false,
    );
    if a != b {
        return Err(format!(
            "per-record projection for {dimension:?} is non-deterministic ({a:?} vs {b:?})"
        ));
    }
    Ok(())
}

fn check_key_boundary_scope() -> Result<(), String> {
    use crate::key_boundary::KeyBoundaryScope;
    for scope in [
        KeyBoundaryScope::Process,
        KeyBoundaryScope::Tenant {
            tenant_id: "t".into(),
        },
        KeyBoundaryScope::Channel {
            channel_id: "c".into(),
        },
        KeyBoundaryScope::Cohort {
            cohort_id: "co".into(),
        },
        KeyBoundaryScope::DataClass { class: "d".into() },
    ] {
        let wire = scope.as_wire_string();
        match KeyBoundaryScope::from_wire_string(&wire) {
            Ok(rt) if rt == scope => {}
            Ok(other) => return Err(format!("{scope:?} round-tripped to {other:?} via {wire:?}")),
            Err(e) => {
                return Err(format!(
                    "{scope:?} wire form {wire:?} failed to parse: {e:?}"
                ))
            }
        }
    }
    Ok(())
}

fn check_recipient_serve_capability_token() -> Result<(), String> {
    use ciris_persist::federation::types::delegation_scope;
    // The #379 value-provenance lock: the serve gate's capability token IS
    // persist's `delegation_scope::INFRA_SERVE` const, NOT a hand-rolled string.
    // (The v13.10.0 bug keyed on a bare `"observer"` literal, fail-closing the
    // plane; a hardcoded token can silently drift from the authority's vocabulary.)
    if crate::replication::bridge::FederationDirectoryReplicationBridge::SERVE_CAPABILITY
        != delegation_scope::INFRA_SERVE
    {
        return Err("edge's SERVE_CAPABILITY drifted from persist's INFRA_SERVE const".into());
    }
    Ok(())
}

fn check_recipient_capability_is_withhold_not_strip() -> Result<(), String> {
    use ciris_persist::federation::consent_grammar::{to_transform_ops, RestrictionOp};
    // A `recipient_capability` restriction must NOT be routed through the strip
    // pipeline (that would be an unsound serve-time byte mutation, #397); persist's
    // `to_transform_ops` maps it to nothing, and edge honors it as a WITHHOLD
    // (`recipient_capability_withholds`). This proves edge's handler matches the
    // grammar's own routing.
    let ops = to_transform_ops(&[RestrictionOp::RecipientCapability {
        capability: "trace:read".into(),
    }]);
    if !ops.is_empty() {
        return Err(
            "recipient_capability must not produce a transform op (it is a withhold)".into(),
        );
    }
    // A strip_field restriction DOES produce a strip op (applied at persist promotion).
    let strip = to_transform_ops(&[RestrictionOp::StripField {
        path: "/trace/llm_calls/*/prompt".into(),
    }]);
    if strip.len() != 1 {
        return Err("a strip_field restriction must map to exactly one StripField op".into());
    }
    Ok(())
}

fn check_attestation_prefixes_covers() -> Result<(), String> {
    use ciris_persist::federation::consent_grammar::covers;
    // The grant-prefix gate the serve path applies is str::starts_with (covers),
    // trailing-colon significant: `trace:` gates `trace:complete:v1` but NOT
    // `trace_summary:v1`. Value semantics, not presence.
    let prefixes = vec!["trace:".to_string()];
    if !covers(&prefixes, "trace:complete:v1") {
        return Err("`trace:` must cover `trace:complete:v1`".into());
    }
    if covers(&prefixes, "trace_summary:v1") {
        return Err(
            "`trace:` must NOT cover `trace_summary:v1` (trailing colon significant)".into(),
        );
    }
    if covers(&prefixes, "capacity:audit:v1") {
        return Err("`trace:` must not cover an unrelated dimension".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_persist::federation::namespace::supersets::field_processor_matrix;
    use std::collections::HashSet;

    /// Every check passes.
    #[test]
    fn edge_field_conformance_passes() {
        if let Err(v) = run_edge_field_conformance() {
            panic!("edge field conformance violations: {v:#?}");
        }
    }

    /// THE KEYSTONE (CIRISEdge#411 §5): every field persist's live
    /// `field_processor_matrix` tags `owner_component ⊇ edge` is ACCOUNTED FOR —
    /// either an [`EDGE_FIELD_CONFORMANCE`] check or a [`DEFERRED_PENDING_PLANE`]
    /// row. A new edge-tagged field persist ships that edge has not categorized
    /// fails THIS test — the carried-but-unprocessed dead-plane (#315) is a build
    /// failure, exactly as #411 §5 requires.
    #[test]
    fn every_edge_tagged_field_is_accounted_for() {
        let accounted: HashSet<&str> = EDGE_FIELD_CONFORMANCE
            .iter()
            .map(|c| c.field)
            .chain(DEFERRED_PENDING_PLANE.iter().map(|(f, _)| *f))
            .collect();

        let mut gaps = Vec::new();
        for row in field_processor_matrix() {
            let edge_owned = row.owner_component.split('/').any(|c| c == "edge");
            if edge_owned && !accounted.contains(row.field.as_str()) {
                gaps.push(row.field.clone());
            }
        }
        assert!(
            gaps.is_empty(),
            "edge-tagged manifest fields with NO conformance check and NO deferral \
             (carried-but-unprocessed, #315) — add each to EDGE_FIELD_CONFORMANCE or \
             DEFERRED_PENDING_PLANE with a reason: {gaps:#?}"
        );
    }

    /// CIRISEdge#410 §3 — the vendored `evidence/CIRISEdge.cc_impl.tsv` (what the
    /// Constitution's `check_evidence.py` consumes) is EXACTLY what the live code
    /// emits from `EDGE_FIELD_CONFORMANCE`. A processor rename, a version bump, or
    /// a hand-edit to the TSV that diverges from the tested table is a BUILD
    /// failure — the evidence registry can never drift from the code it attests.
    #[test]
    fn evidence_tsv_matches_emitted() {
        let vendored: Vec<&str> = include_str!("../evidence/CIRISEdge.cc_impl.tsv")
            .lines()
            .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
            .collect();
        let emitted = edge_evidence_rows();
        assert_eq!(
            vendored,
            emitted.iter().map(String::as_str).collect::<Vec<_>>(),
            "evidence/CIRISEdge.cc_impl.tsv drifted from EDGE_FIELD_CONFORMANCE — \
             regenerate it from field_conformance::edge_evidence_rows() (CIRISEdge#410 §3)"
        );
    }

    /// CIRISEdge#410 §4 — the serve-gate/routing completeness witness: the five CI
    /// routing axes #410 enumerates each resolve to a LIVE edge processor evidence
    /// row (not merely present — anchored to a `path#symbol` the checks exercise).
    #[test]
    fn every_routing_axis_has_a_live_processor_evidence_row() {
        for axis in [
            "cohort_scope",                           // recipient_see
            "delivery_mode",                          // recipient_receive
            "restrictions[].op=recipient_capability", // information-type restriction
            "attestation_prefixes",                   // transmission principle (grant grammar)
            "recipient_serve_capability",             // serve gate
        ] {
            let row = EDGE_FIELD_CONFORMANCE
                .iter()
                .find(|c| c.field == axis)
                .unwrap_or_else(|| {
                    panic!("routing axis {axis:?} has no live processor row (#410)")
                });
            assert!(
                !row.evidence.is_empty() && row.evidence.contains('#'),
                "routing axis {axis:?} carries no path#symbol evidence anchor"
            );
        }
    }

    /// No stale entries: every field edge claims to process/defer is STILL an
    /// edge-owned row in persist's matrix (so a persist rename/removal surfaces
    /// here, not as a silently-dead edge check).
    #[test]
    fn no_conformance_entry_is_stale() {
        let edge_owned: HashSet<&str> = field_processor_matrix()
            .iter()
            .filter(|r| r.owner_component.split('/').any(|c| c == "edge"))
            .map(|r| r.field.as_str())
            .collect();
        let mut stale = Vec::new();
        for f in EDGE_FIELD_CONFORMANCE
            .iter()
            .map(|c| c.field)
            .chain(DEFERRED_PENDING_PLANE.iter().map(|(f, _)| *f))
        {
            if !edge_owned.contains(f) {
                stale.push(f);
            }
        }
        assert!(
            stale.is_empty(),
            "conformance entries no longer edge-owned in persist's matrix (rename/removal?): {stale:#?}"
        );
    }
}
