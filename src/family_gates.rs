//! Which edge gates apply to an Attestation family — total, by
//! construction (CIRISPersist#742 / CIRISEdge#499).
//!
//! # The recurrence this exists to end
//!
//! Edge conditions serve-path behaviour on the Attestation *family* in
//! more than one place: the E3 trace gate keys on
//! [`AttestationFamily::Trace`], the CC 4.2.1 relay gate keys on
//! [`AttestationFamily::Accord`]. Each fold onto persist's classifier
//! was correct in isolation and each lived at its own call site, so
//! "which gates apply to family F" was never written down anywhere —
//! it was the union of two independent `matches!` expressions a reader
//! had to find.
//!
//! That shape has now bitten twice in one week, once in each repo:
//!
//! - persist's `FAMILY_DIMS` claimed one representative per decided
//!   family and was missing the three newest, so its dominance
//!   invariant swept a corpus that read as total while never seeing
//!   `accord:*`, `moderation:*`, or `provenance:build_manifest:*`.
//! - edge's projection sweep fanned the Attestation plane across
//!   exactly ONE dimension (`trust:example:v1`) while claiming to be
//!   total over the plane — the same defect, one layer out.
//!
//! Both are the same class: **a check that could not observe the thing
//! it ruled out.** The fix is not another assertion. It is to make the
//! mapping a single total function whose *unknown* case is loud and
//! restrictive rather than silent and permissive.
//!
//! # Why edge cannot use persist's guard
//!
//! Persist closed its version with a compile error — an exhaustive
//! `match` over [`AttestationFamily`] with no wildcard, so adding a
//! family fails the build until someone names its representative. That
//! guard is real and it **does not transfer downstream**:
//!
//! - [`AttestationFamily`] is `#[non_exhaustive]`, so a match in any
//!   other crate MUST carry a wildcard arm and can never be exhaustive.
//! - `FAMILY_DIMS` and `all_planes()` live inside persist's own
//!   `#[cfg(test)]` module, so there is nothing for edge to reuse.
//!
//! So edge cannot be *told at compile time* that persist grew a family.
//! What edge can do is decide what happens when it meets one, and make
//! that the safe direction — which is what [`gates_for`] does.
//!
//! # The wildcard is the whole design
//!
//! An unknown family gets **every gate applied** and sets
//! [`FamilyGates::unknown_family`]. A row edge cannot classify is
//! therefore withheld rather than served, and says so. That inverts the
//! failure mode: the old shape let a newly-decided family route
//! *ungated* until someone noticed, and the new shape makes it
//! *over-gated* and noisy until someone teaches edge about it.
//!
//! Over-gating is a visible, reversible bug — someone reports that a
//! family will not replicate. Under-gating is an invisible,
//! unrecoverable one: rows that should not have been carried already
//! were. Given the two, edge takes the loud one.
//!
//! This module holds **no projection rules**. Which cohort tiers a
//! family reaches is persist's (`projection_for`, CIRISPersist#713),
//! and edge reads it per-row with the row's real dimension, so routing
//! was always total on that axis. What is edge's own — and what is
//! written down here — is which of *edge's* gates each family passes
//! through.

use ciris_persist::federation::namespace::{attestation_family, AttestationFamily};

/// The edge-side gates that apply to one Attestation family.
///
/// Every field is "does this gate run", never "what does it decide" —
/// the decisions stay at the gates. This type answers only *which*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FamilyGates {
    /// The E3 trace gate: the row is only served to a peer holding the
    /// serve capability, and is withheld entirely while trace is
    /// paused. Keys on [`AttestationFamily::Trace`].
    pub requires_serve_capability: bool,
    /// The CC 4.2.1 relay gate (CIRISPersist#731/#733): carriage is
    /// narrowed to the accord's own roster. Keys on
    /// [`AttestationFamily::Accord`].
    pub accord_relay_gated: bool,
    /// **This build could not classify the dimension's family.**
    ///
    /// Set only by the wildcard arm, which means persist has decided a
    /// family this edge build predates. Every other field is `true`
    /// alongside it: the row is maximally gated and will in practice be
    /// withheld. Callers should log it once per dimension rather than
    /// per row — it is a "this build is behind" signal, not a per-row
    /// fault.
    pub unknown_family: bool,
}

impl FamilyGates {
    /// Every gate on. The wildcard's value, and the safe default.
    const MAXIMAL_UNKNOWN: Self = Self {
        requires_serve_capability: true,
        accord_relay_gated: true,
        unknown_family: true,
    };

    /// No family-conditioned gate. Note this is not "ungated" — the
    /// projection filter, the consent gate, and the author-quarantine
    /// gate apply to every row regardless of family and are not
    /// represented here.
    const NONE: Self = Self {
        requires_serve_capability: false,
        accord_relay_gated: false,
        unknown_family: false,
    };
}

/// Which edge gates apply to `dimension`'s family.
///
/// Total over every possible input: an unrecognised or malformed
/// dimension classifies through persist's [`attestation_family`] like
/// any other, and anything this build does not know reaches the
/// wildcard and is maximally gated.
#[must_use]
pub fn gates_for(dimension: &str) -> FamilyGates {
    match attestation_family(dimension) {
        // The E3 capability gate. `trace:*` is the one family whose
        // rows are withheld wholesale while trace is paused.
        AttestationFamily::Trace => FamilyGates {
            requires_serve_capability: true,
            ..FamilyGates::NONE
        },
        // CC 4.2.1 — a node that never trusted the accord "is simply
        // not reached". Projection says who may HOLD; this gate says
        // who may CARRY.
        AttestationFamily::Accord => FamilyGates {
            accord_relay_gated: true,
            ..FamilyGates::NONE
        },
        // Families edge carries under the common gates only. Named
        // individually rather than folded into the wildcard, because
        // the wildcard means "this build does not know" and these are
        // known.
        AttestationFamily::Consent
        | AttestationFamily::Scores
        | AttestationFamily::Capacity
        | AttestationFamily::ContentClass
        | AttestationFamily::SubstrateHealth => FamilyGates::NONE,
        // FORCED by `#[non_exhaustive]`, and deliberately the
        // restrictive arm. See the module docs: over-gating is visible
        // and reversible, under-gating is neither.
        _ => FamilyGates::MAXIMAL_UNKNOWN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One representative per family edge knows about. Kept beside the
    /// match so the two drift together or not at all.
    const REPRESENTATIVES: &[(&str, &str)] = &[
        ("trace:reasoning:v1", "Trace"),
        ("accord:human_dignity:v1", "Accord"),
        ("consent:share:v1", "Consent"),
        ("scores:alignment:v1", "Scores"),
        ("capacity:relay_delivery:v1", "Capacity"),
        ("content_class:nsfw:v1", "ContentClass"),
        ("transport:reachability:v1", "SubstrateHealth"),
    ];

    #[test]
    fn every_known_representative_classifies_and_is_not_the_unknown_arm() {
        // Catches the drift edge CAN see: persist renaming a stem, or a
        // representative that stops classifying, would silently fall
        // into the wildcard and start being maximally gated. That is
        // safe but wrong, and it should be loud rather than mysterious.
        for (dimension, family) in REPRESENTATIVES {
            let gates = gates_for(dimension);
            assert!(
                !gates.unknown_family,
                "{dimension} (expected family {family}) fell through to the unknown \
                 arm — persist likely renamed the stem, and edge is now maximally \
                 gating a family it used to know",
            );
        }
    }

    #[test]
    fn the_two_family_conditioned_gates_land_on_exactly_their_families() {
        assert_eq!(
            gates_for("trace:reasoning:v1"),
            FamilyGates {
                requires_serve_capability: true,
                accord_relay_gated: false,
                unknown_family: false,
            },
        );
        assert_eq!(
            gates_for("accord:human_dignity:v1"),
            FamilyGates {
                requires_serve_capability: false,
                accord_relay_gated: true,
                unknown_family: false,
            },
        );
        // ...and on nothing else. A gate that quietly widened to a
        // second family would change carriage for that family with no
        // other signal.
        for (dimension, _) in REPRESENTATIVES {
            let gates = gates_for(dimension);
            if !dimension.starts_with("trace:") {
                assert!(
                    !gates.requires_serve_capability,
                    "{dimension} is not E3-gated"
                );
            }
            if !dimension.starts_with("accord:") {
                assert!(!gates.accord_relay_gated, "{dimension} is not relay-gated");
            }
        }
    }

    #[test]
    fn an_unclassifiable_dimension_is_maximally_gated_not_ungated() {
        // THE property. A family this build predates, or a malformed
        // dimension, must end up withheld rather than served. The old
        // shape — two independent `matches!` at two call sites — gave
        // the opposite: an unknown family matched NEITHER, so every
        // family-conditioned gate was skipped and the row went out
        // ungated.
        for dimension in [
            "",
            "not-a-namespace",
            "someday:persist:decides:this:v1",
            "accordion:not:accord:v1",
        ] {
            let gates = gates_for(dimension);
            assert_eq!(
                gates,
                FamilyGates::MAXIMAL_UNKNOWN,
                "{dimension:?} must be maximally gated, not silently ungated",
            );
            assert!(gates.unknown_family, "and must SAY it could not classify");
        }
    }

    #[test]
    fn a_near_miss_prefix_does_not_inherit_a_families_gates() {
        // `accordion:` starts with `accord` as a string but is not the
        // `accord:` family. Edge must not hand-roll prefix matching —
        // this pins that `gates_for` goes through persist's classifier,
        // where the stem boundary is defined.
        assert!(gates_for("accordion:not:accord:v1").unknown_family);
        assert_ne!(
            gates_for("accordion:not:accord:v1"),
            gates_for("accord:human_dignity:v1"),
        );
    }
}
