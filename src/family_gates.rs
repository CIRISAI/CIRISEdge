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
        //
        // `Chat` (persist v38.2.0, CIRISPersist#757) joins them by persist's
        // OWN registry row, not by taste. Read from `projection_for`: the
        // `chat:*` arm answers `SelfOwn` at `self`/`family` and `Cohort` at
        // every cohort tier (`community | affiliations` — the Community
        // tier — and the commons `species | biosphere | federation`), with
        // NO `authority` branch — "a trust
        // root is not a party to someone else's conversation". There is no
        // `Projection::Capability` cell anywhere in the row, which is the
        // shape that would have implied edge's E3 serve-capability gate
        // (`trace:*` is the only family carrying one), and `chat:` is not
        // `accord:`, so the CC 4.2.1 relay gate does not key on it either.
        // Persist's row therefore decides NO family-conditioned edge gate —
        // the Cohort ceiling is enforced by the projection filter edge
        // already applies per-row, which is a COMMON gate, not one of these.
        AttestationFamily::Consent
        | AttestationFamily::Scores
        | AttestationFamily::Capacity
        | AttestationFamily::ContentClass
        | AttestationFamily::SubstrateHealth
        | AttestationFamily::Moderation
        | AttestationFamily::ProvenanceBuildManifest
        | AttestationFamily::Chat
        // CIRISEdge#706 — found by the registry-coverage test: persist decided
        // `session:*` (v38.7.0, #782) and `duty:*` (v42.0.0, #814) and this fold
        // never named them, so both fell to the wildcard and were MAXIMALLY
        // gated — withheld from every peer lacking `infra:serve`. Persist's rows
        // for both (`projection_for`) are the Chat shape: `SelfOwn` at
        // self/family, `Cohort` at every other tier, no `Projection::Capability`
        // cell and no `authority` branch — so neither of edge's two
        // family-conditioned gates keys on them.
        | AttestationFamily::SessionClaim
        | AttestationFamily::Duty => FamilyGates::NONE,

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
    ///
    /// **This list must name EVERY family [`gates_for`] names**, and for a
    /// cut it did not: the match named nine and this named seven, so
    /// `Moderation` and `ProvenanceBuildManifest` were unpinned — a persist
    /// rename of either stem would have dropped them into the wildcard and
    /// started maximally gating them, silently, with every test here still
    /// green. That is the same defect this module's own header describes
    /// (persist's `FAMILY_DIMS` missing its three newest families), reproduced
    /// one layer out in the drift test written to catch it. Repaired in
    /// v18.4.0 alongside the `Chat` adoption; adding a family to `gates_for`
    /// without adding its representative here re-opens it.
    const REPRESENTATIVES: &[(&str, &str)] = &[
        ("trace:reasoning:v1", "Trace"),
        ("accord:human_dignity:v1", "Accord"),
        // CIRISEdge#706 — rc5 closes `consent:{kind}`; stand on a catalogued leaf.
        ("consent:state:granted:v1", "Consent"),
        ("scores:alignment:v1", "Scores"),
        ("capacity:relay_delivery:v1", "Capacity"),
        ("content_class:nsfw:v1", "ContentClass"),
        ("transport:reachability:v1", "SubstrateHealth"),
        ("moderation:allegation:v1", "Moderation"),
        (
            "provenance:build_manifest:release:v1",
            "ProvenanceBuildManifest",
        ),
        // persist v38.2.0 (CIRISPersist#757) — the whole `chat:` prefix is
        // one family, so the representative is a plain message dimension
        // (persist's own `FAMILY_DIMS` representative is `chat:message:v1`).
        ("chat:message:v1", "Chat"),
        // CIRISEdge#706 — persist's own `FAMILY_DIMS` representatives.
        ("session:claim:v1", "SessionClaim"),
        ("duty:attribute:v1", "Duty"),
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
            "consent:state:granted:v1",
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

    /// persist v38.2.0 (CIRISPersist#757) — the `chat:*` adoption, pinned
    /// against the REASON rather than the value.
    ///
    /// Without the arm, `chat:message:v1` reaches the wildcard and is
    /// `MAXIMAL_UNKNOWN` — withheld from every peer lacking `infra:serve`,
    /// which is the module working exactly as designed and still wrong to
    /// ship. The arm's VALUE is persist's registry row: `projection_for`'s
    /// `Chat` arm is `SelfOwn` at self/family and `Cohort` at every commons
    /// tier with no `authority` branch and no `Projection::Capability` cell
    /// anywhere — so neither of edge's two family-conditioned gates keys on
    /// it. The Cohort ceiling is real, and it is enforced by the per-row
    /// projection filter (a COMMON gate), not here.
    #[test]
    fn chat_is_a_known_family_carrying_no_family_conditioned_gate() {
        for dimension in ["chat:message:v1", "chat:reaction:v1", "chat:receipt:v1"] {
            let gates = gates_for(dimension);
            assert!(
                !gates.unknown_family,
                "{dimension} must be a KNOWN family — the wildcard would withhold every \
                 chat row from any peer without `infra:serve`",
            );
            assert_eq!(
                gates,
                FamilyGates::NONE,
                "persist's `chat:*` registry row decides no family-conditioned edge gate",
            );
        }
        // ...and the stem boundary is persist's, not a prefix match here.
        assert!(!gates_for("chat:").unknown_family);
        assert_eq!(gates_for("chatter:not:chat:v1"), FamilyGates::NONE);
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

    // ── CIRISEdge#706 item 2 — every family helper against the CC registry ──
    //
    // The `trace:`/`accord:` loop above checks the two family-conditioned
    // gates over the eleven REPRESENTATIVES only. These two tests generalise it
    // to the Constitution's own registry (vendored, `crate::cc_namespace`), in
    // both directions: a helper for a family the registry does not carry fails,
    // and a family the registry carries that the gate fold does not cover — or
    // gates on the wrong family — fails.

    /// Stems edge (or the persist classifier it reads) keys on that rc5 carries
    /// no registry row for. Each is OPEN vocabulary under the CC reference
    /// (family `None`, refusal `None`), so a dimension under it is admitted —
    /// but a family helper keyed on it names a family the Constitution does
    /// not. Listed with its reason rather than skipped; the test below fails
    /// if an entry goes stale in either direction.
    const HELPER_STEMS_WITHOUT_A_REGISTRY_ROW: &[(&str, &str)] = &[(
        "scores:",
        "persist's AttestationFamily::Scores keys the `scores:` stem; rc5 carries no \
         `scores:*` row (`scores` is an attestation_type, and `scores:` dimensions are open \
         vocabulary) — persist's taxonomy, raised at the v33.0.0 adopt (CIRISEdge#702)",
    )];

    /// Every family helper edge keys on names a stem the CC registry carries.
    #[test]
    fn every_family_helper_names_a_family_the_cc_registry_carries() {
        use crate::cc_namespace::{registry_prefixes, stem};
        let registry_stems: std::collections::BTreeSet<String> = registry_prefixes()
            .iter()
            .map(|p| stem(p).to_owned())
            .collect();
        // The helpers: one stem per family `gates_for` names (its
        // representative), plus the prefix constants edge's producers key on.
        let mut helpers: Vec<(String, &str)> = REPRESENTATIVES
            .iter()
            .map(|(d, family)| (stem(d).to_owned(), *family))
            .collect();
        helpers.push((
            crate::chat::CHAT_ATTESTATION_PREFIX.to_owned(),
            "chat::CHAT_ATTESTATION_PREFIX",
        ));
        helpers.push((
            crate::key_boundary::KEY_BOUNDARY_PREFIX.to_owned(),
            "key_boundary::KEY_BOUNDARY_PREFIX",
        ));
        for (helper_stem, helper) in &helpers {
            let exempt = HELPER_STEMS_WITHOUT_A_REGISTRY_ROW
                .iter()
                .any(|(s, _)| s == helper_stem);
            assert!(
                registry_stems.contains(helper_stem) || exempt,
                "{helper} keys the `{helper_stem}` stem, which the CC registry does not \
                 carry — a helper for a family the Constitution has no row for"
            );
        }
        // …and the exemptions stay honest: each is still a helper, and still
        // absent from the registry.
        for (exempt_stem, why) in HELPER_STEMS_WITHOUT_A_REGISTRY_ROW {
            assert!(
                helpers.iter().any(|(s, _)| s == exempt_stem),
                "stale exemption `{exempt_stem}`: no helper keys it any more ({why})"
            );
            assert!(
                !registry_stems.contains(*exempt_stem),
                "stale exemption `{exempt_stem}`: the registry now carries it — drop the \
                 exemption ({why})"
            );
        }
    }

    /// Every family the CC registry carries is covered by the gate fold: an
    /// admitted sample of it classifies (never the unknown wildcard), the E3
    /// capability gate lands on exactly the `trace:` rows, and the CC 4.2.1
    /// relay gate on exactly the `accord:` rows.
    #[test]
    fn every_cc_registry_family_is_covered_by_the_gate_fold() {
        use crate::cc_namespace::{stem, vectors, REGISTRY_JSON};
        let root: serde_json::Value = serde_json::from_str(REGISTRY_JSON).unwrap();
        let mut sample: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for v in vectors() {
            if v.refusal.is_none() {
                if let Some(f) = v.family {
                    sample.entry(f).or_insert(v.dimension);
                }
            }
        }
        for fam in root["families"].as_array().unwrap() {
            let prefix = fam["prefix"].as_str().unwrap();
            let Some(dimension) = sample.get(prefix) else {
                // A parent closed in its leaves admits nothing of its own —
                // every leaf is a row, sampled under that row.
                assert_eq!(
                    fam["leaves_closed"].as_bool(),
                    Some(true),
                    "registry family `{prefix}` has no admitted vector and is not closed in \
                     its leaves — nothing exercises it"
                );
                continue;
            };
            let gates = gates_for(dimension);
            assert!(
                !gates.unknown_family,
                "`{dimension}` (registry family `{prefix}`) reached the unknown wildcard — \
                 a family the Constitution carries that edge's gate fold does not cover"
            );
            assert_eq!(
                gates.requires_serve_capability,
                stem(prefix) == "trace:",
                "E3 serve-capability gate on `{dimension}` (family `{prefix}`): it keys on \
                 exactly the `trace:` rows"
            );
            assert_eq!(
                gates.accord_relay_gated,
                stem(prefix) == "accord:",
                "CC 4.2.1 relay gate on `{dimension}` (family `{prefix}`): it keys on \
                 exactly the `accord:` rows"
            );
        }
    }
}
