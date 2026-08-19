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
//! # What this changes today: NOTHING. The protection is latent.
//!
//! Stated plainly because the first version of this module claimed
//! otherwise. Every `AttestationFamily` variant that exists at this pin
//! is named in [`gates_for`] — including `Unknown`, which persist
//! returns for any dimension with no family and which is emphatically
//! NOT the unknown-family case. So no constructible input reaches the
//! wildcard, and `gates_for` is **behaviourally identical** to the two
//! inline `matches!` expressions it replaced.
//!
//! The value is entirely in the future: when persist decides family
//! number ten, an inline `matches!` silently returns `false` and routes
//! it ungated, while this fold routes it through the wildcard and
//! withholds it loudly. Wiring it now is what puts the protection in
//! the path *before* it is needed, not a behaviour change.
//!
//! **The wildcard arm therefore has no test, and cannot have one.** No
//! constructible input reaches it, and asserting on
//! `FamilyGates::MAXIMAL_UNKNOWN` directly is a compile-time constant
//! that proves nothing at run time — clippy says so, and it is right.
//! A test asserting a constant would manufacture the appearance of
//! coverage over the one arm that has none, which is worse than the
//! honest gap. The arm is held by review and by this paragraph.
//!
//! Two corrections are baked into that paragraph, both found by wiring
//! this module rather than by testing it:
//!
//! - It sat with **zero callers** while its own docs and commit message
//!   said it had replaced the inline checks. Mutation-verified tests on
//!   a unit nothing calls is a green board over a dead protection.
//! - It conflated `Unknown` with unknown-family, which maximally gated
//!   `trust:*` and every other unclassified dimension. That reddened 13
//!   unrelated tests the moment it was wired — and would have withheld
//!   most of the corpus had it shipped inert-but-wired.
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
// The arms are grouped by MEANING, not by value. `Unknown` shares
// `FamilyGates::NONE` with the plain families, but the two say different
// things — "persist maps this to no family" versus "a decided family with no
// edge-side gate" — and the comments on each are the record of a bug that
// came from conflating exactly those. Merging them to satisfy the lint would
// delete that distinction, which is the one this module got wrong once.
#[allow(clippy::match_same_arms)]
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
        | AttestationFamily::SubstrateHealth
        | AttestationFamily::Moderation
        | AttestationFamily::ProvenanceBuildManifest => FamilyGates::NONE,

        // `Unknown` is NOT the unknown-family case, and conflating the two
        // was a real bug in this module — invisible for as long as it had no
        // callers, and it maximally-gated 13 test paths the moment it was
        // wired.
        //
        // Persist returns `Unknown` for any dimension its registry maps to no
        // family at all: `trust:*`, `objection:*`, and every ordinary
        // dimension outside the nine decided families. Those are not
        // mysteries — they are simply not family-gated, and gating them would
        // withhold most of the corpus.
        //
        // The case this module exists for is a variant added by a persist
        // NEWER than this build, which `#[non_exhaustive]` makes reachable
        // and which no name here can match. That is the wildcard below, and
        // separating it from `Unknown` is what makes the wildcard mean what
        // its doc says.
        AttestationFamily::Unknown => FamilyGates::NONE,
        // FORCED by `#[non_exhaustive]`, and now genuinely reserved for a
        // family decided by a persist newer than this build — every family
        // this build knows about, INCLUDING `Unknown`, is named above.
        // Deliberately the restrictive arm: over-gating is visible and
        // reversible, under-gating is neither.
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

    /// The test that would have caught this module being DEAD CODE.
    ///
    /// Every other test here calls `gates_for` directly, so all four stayed
    /// green — and mutation-verified — while the serve path still used its own
    /// inline `matches!` and nothing called this module at all. A
    /// mutation-verified unit with no callers is a green board over a dead
    /// protection, and it is the exact trap this repo keeps hitting.
    ///
    /// So this asserts through the CALL SITES instead: the predicates that
    /// consult this fold must agree with `gates_for`, including on the
    /// unknown case. Re-inlining a `matches!` at a site reds this.
    ///
    /// NB (CIRISEdge#505 / v37.1.0): `dimension_half_is_gated` is no longer
    /// the accord CARRIAGE pre-filter — that is persist's `is_accord_family`,
    /// over BOTH namespaces, consumed by the bridge's `attestation_is_accord`
    /// (source-asserted there). What this pins is the accord HALF of the fold
    /// itself, so the wiring cannot drift while it still has readers.
    #[test]
    fn the_serve_paths_predicates_read_this_module_and_not_a_local_matches() {
        use crate::replication::accord_relay_gate::AccordRelayGate;

        for dimension in [
            "accord:human_dignity:v1",
            "trace:reasoning:v1",
            "consent:share:v1",
            "trust:example:v1",
            "objection:halt:v1",
        ] {
            let expected = gates_for(dimension);
            assert_eq!(
                AccordRelayGate::dimension_half_is_gated(dimension),
                expected.accord_relay_gated,
                "the dimension half-test must read gates_for for {dimension:?} \
                 — an inline matches! returns false on an unknown family and CARRIES it",
            );
        }

        // HONEST LIMIT: with `Unknown` correctly mapped to NONE, `gates_for`
        // and the inline `matches!` it replaced are behaviourally IDENTICAL
        // at this pin — every existing variant is named, so they cannot
        // disagree on any constructible input. This test therefore guards the
        // WIRING (that the serve path reads one shared fold) and cannot, by
        // construction, detect a re-inline by behaviour alone. The protection
        // is latent: it bites when persist adds a family, not today.
    }

    #[test]
    fn a_dimension_with_no_family_is_not_family_gated() {
        // REGRESSION TEST for a real bug in this module, which was invisible
        // for as long as it had no callers.
        //
        // Persist returns `AttestationFamily::Unknown` for any dimension its
        // registry maps to no family — `trust:*`, `objection:*`, and most of
        // the corpus. The first version of `gates_for` let `Unknown` fall to
        // the wildcard and be MAXIMALLY gated, conflating "no family" with
        // "a family I have never heard of". Wiring the module turned 13
        // unrelated tests red, which is what surfaced it.
        //
        // Those dimensions are not mysteries. They are simply not
        // family-gated, and gating them would withhold most of what this node
        // carries.
        for dimension in [
            "trust:example:v1",
            "objection:halt:v1",
            "",
            "not-a-namespace",
        ] {
            let gates = gates_for(dimension);
            assert!(
                !gates.unknown_family,
                "{dimension:?} classifies as Unknown, which is a KNOWN answer",
            );
            assert_eq!(
                gates,
                FamilyGates::NONE,
                "{dimension:?} has no family, so no family-conditioned gate applies",
            );
        }
    }

    #[test]
    fn a_near_miss_prefix_does_not_inherit_a_families_gates() {
        // `accordion:` starts with `accord` as a string but is not the
        // `accord:` family. Pins that `gates_for` goes through persist's
        // classifier, where the stem boundary is defined, rather than
        // hand-rolling a prefix match.
        assert_ne!(
            gates_for("accordion:not:accord:v1"),
            gates_for("accord:human_dignity:v1"),
        );
        assert!(!gates_for("accordion:not:accord:v1").accord_relay_gated);
    }
}
