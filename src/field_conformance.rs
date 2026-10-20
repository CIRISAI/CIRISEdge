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

/// CIRISEdge#718 — a Constitution claim edge resolves OUTSIDE persist's
/// field-processor matrix: the claim is on a TRANSPORT rule (CC 5.4.6), not
/// on a manifest field, so it cannot ride [`EDGE_FIELD_CONFORMANCE`] (whose
/// rows are cross-checked against `field_processor_matrix` by
/// `no_conformance_entry_is_stale`). Same discipline otherwise: a pure check
/// that exercises the LIVE decision the evidence anchor names, emitted into
/// the same `CIRISEdge.cc_impl.tsv` by [`edge_evidence_rows`].
pub struct ClaimConformance {
    /// The CC section the claim lives in.
    pub cc: &'static str,
    /// The `CLM-*` claim id, exactly as `constitution/claims.tsv` names it.
    pub clm: &'static str,
    /// The property the check proves.
    pub property: &'static str,
    /// The check — `Ok(())` conformant, `Err(reason)` a violation.
    pub check: fn() -> Result<(), String>,
    /// The `path#symbol` evidence anchor.
    pub evidence: &'static str,
}

/// The transport-rule claims edge carries evidence for (CIRISEdge#718).
///
/// CIRISEdge#872 — the rows the CIRISServer manifest used to host for edge
/// at an old version, published here against the live symbol. Withheld from
/// that list, each because edge does not meet the section yet: `CLM-holder`
/// (5.3.2.1 — edge still emits `Withdraws` on `ContentMiss`),
/// `CLM-consent-counter` (3.4.7.2 — no OQ-3 review window) and
/// `CLM-transport-edge` (5.3.3.5 — E1's CIR2 sentence is open as
/// CIRISConstitution#172). `CLM-registry-wire` was withheld until
/// CIRISConstitution#173 withdrew the 48-byte compatibility read.
pub const EDGE_CC_CLAIM_CONFORMANCE: &[ClaimConformance] = &[
    ClaimConformance {
        cc: "5.4.6",
        clm: "CLM-scoped-body-identity-link",
        property:
            "a scoped body rides the derived address at one hop and the identity-plane link only \
               beyond it, chosen once from the path table; an in-link discriminator is admitted \
               against the same ScopeAddressTable and only for an address this node holds; a \
               discriminator on a derived-address arrival is a mismatch",
        check: check_scoped_body_identity_link,
        evidence: "src/blob_swarm/scope.rs#choose_scoped_carrier",
    },
    ClaimConformance {
        cc: "5.3.3.2.1",
        clm: "CLM-namespace-realtime",
        property: "codec_id carries the ratified byte per codec and sits with the ChunkLayer at \
                   offset 48..52 outside both AEADs: a relay can read and rewrite it without \
                   touching the seal",
        check: check_namespace_realtime,
        evidence: "src/transport/realtime_av.rs#CODEC_AV1_SVC",
    },
    ClaimConformance {
        cc: "5.3.3.2.3",
        clm: "CLM-registry-wire",
        property: "to_bytes lays out stream_id(32) | epoch u64 BE | chunk_seq u64 BE | codec_id | \
                   spatial | temporal | quality | ciphertext and from_bytes reads it back; a wire \
                   shorter than the 52-byte header, or whose ciphertext cannot carry the outer \
                   and inner AEAD tags, is refused at parse; a relay refuses an inner ciphertext \
                   too short for its tag at the outer open; a tag-less ciphertext never opens",
        check: check_registry_wire,
        evidence: "src/transport/realtime_av.rs#SealedAvChunk::to_bytes",
    },
    ClaimConformance {
        cc: "5.3.3.2.4",
        clm: "CLM-chunklayer",
        property: "admits is the per-axis test spatial <= max_spatial AND temporal <= \
                   max_temporal AND quality <= max_quality; BLINKING_DOT admits only the base \
                   cell, UNCAPPED admits every cell, and every policy admits the base cell an \
                   opaque chunk carries",
        check: check_chunklayer,
        evidence: "src/transport/realtime_av.rs#ReceiverLayerPolicy::admits",
    },
    ClaimConformance {
        cc: "5.3.3.4",
        clm: "CLM-liveness",
        property: "fan_out = entitled ∩ reachable: a reachable peer outside the entitled set is \
                   never added, an entitled peer with no reachability history or a failing one \
                   is left out, and the plan reads the node-local tracker without writing to it",
        check: check_liveness,
        evidence: "src/transport/realtime_av.rs#RealtimeFanout::plan_layered",
    },
    ClaimConformance {
        cc: "5.4.4",
        clm: "CLM-welcome-wrap",
        property: "a Welcome is opened only after an ML-DSA-65 signature over x25519_eph || \
                   u32_be(len(ct)) || ct verifies against the directory-resolved inviter key; \
                   a directory miss or a bad signature refuses before HPKE open_base runs",
        check: check_welcome_wrap,
        evidence: "src/mls/welcome_wrap.rs#unwrap_welcome",
    },
    ClaimConformance {
        cc: "5.4.6",
        clm: "CLM-announce-suppress",
        property: "the announce policy installed on the node suppresses every self, family and \
                   community destination, lets a federation destination announce, and \
                   suppresses a destination it has no scope for",
        check: check_announce_suppress,
        evidence: "src/announce_suppression.rs#ScopePrivacyAnnouncePolicy::decide",
    },
    ClaimConformance {
        cc: "6.1.5.1",
        clm: "CLM-registry-replication",
        property: "the producer-silent policy is (N=20, K=6, min_viable=5, target_holders=30) \
                   with min_viable >= 1; its distinct-symbol survival is the section's \
                   0.995039 at q=0.90 and 0.957288 at q=0.85; the planner follows a different \
                   tuple when one is in force",
        check: check_registry_replication,
        evidence: "src/holonomic/fountain_defaults.rs#recommended_policy",
    },
    ClaimConformance {
        cc: "6.1.6",
        clm: "CLM-deterministic-alm",
        property: "byte-equal inputs give byte-equal topology under any permutation of ads, \
                   grants and observations; an unverified capacity ad never enters scoring; a \
                   self-asserted uplink above the cap does not outscore one at the cap",
        check: check_deterministic_alm,
        evidence: "src/holonomic/deterministic_topology.rs#compute_alm_topology_verified",
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
      the WIDENING before signing (widen_audience's strip → differs_in, v39.0.0) and \
      explicitly scoped general serve-layer transforms as a follow-up — this is \
      persist-owned, not an edge processor.",
    ),
    (
        "raw_probe_payloads",
        "same content-addressed-wire unsoundness; the strip is a persist WIDENING-side \
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
        // CIRISEdge#718 — the transport-rule claims, same row shape.
        .chain(EDGE_CC_CLAIM_CONFORMANCE.iter().map(|c| {
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
    for c in EDGE_CC_CLAIM_CONFORMANCE {
        if let Err(reason) = (c.check)() {
            violations.push(format!("{}: {reason}", c.clm));
        }
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

// ─── the pure value-semantics checks ────────────────────────────────────────

/// CIRISEdge#718 — `CLM-scoped-body-identity-link` (CC 5.4.6 at `4fd2e9e`,
/// CIRISConstitution#132), against the LIVE decision and admission functions.
fn check_scoped_body_identity_link() -> Result<(), String> {
    const OWN: &str = "ed25519:own-node";
    const PEER: &str = "ed25519:peer-node";
    use crate::blob_swarm::{
        choose_scoped_carrier, BlobScopeRouter, ScopedCarrier, ScopedPathShape, ServeRefusal,
    };
    use crate::cohort_scope::CohortScope;
    use crate::scope_addressing::{ScopeAddressTable, ScopePrivacyDeriver};
    use std::sync::Arc;

    // The send-side choice, on the exact shapes the path table produces.
    if choose_scoped_carrier(ScopedPathShape::Direct { hops: 1 }).carrier
        != ScopedCarrier::DerivedAddress
    {
        return Err("a one-hop path must ride the derived address (MUST prefer it)".into());
    }
    if choose_scoped_carrier(ScopedPathShape::Forwarded {
        hops: 2,
        next_hop: [0xC0; 16],
    })
    .carrier
        != ScopedCarrier::IdentityLink
    {
        return Err("a forwarded-only path must ride the identity-plane link".into());
    }
    if choose_scoped_carrier(ScopedPathShape::Unknown).carrier != ScopedCarrier::DerivedAddress {
        return Err("no path must never choose a forwarder on a guess".into());
    }

    // The admission, against a real table (the production deriver).
    let table = Arc::new(ScopeAddressTable::new(Arc::new(ScopePrivacyDeriver)));
    table
        .install_group(
            &CohortScope::Family,
            "fam-718",
            1,
            &[0x7E; 32],
            &[OWN, PEER],
        )
        .map_err(|e| format!("install: {e}"))?;
    let router = BlobScopeRouter::new(Some(Arc::clone(&table)));
    let own = table
        .send_address(&CohortScope::Family, "fam-718", OWN)
        .ok_or("own address")?;
    let peers = table
        .send_address(&CohortScope::Family, "fam-718", PEER)
        .ok_or("peer address")?;
    match router.scoped_arrival(None, Some(own.as_bytes()), OWN) {
        Ok(Some(a)) if a.member_key_id() == OWN && a.group().group_id() == "fam-718" => {}
        other => return Err(format!("own address must stamp the arrival, got {other:?}")),
    }
    if !matches!(
        router.scoped_arrival(None, Some(peers.as_bytes()), OWN),
        Err(ServeRefusal::DiscriminatorUnheld)
    ) {
        return Err("another member's address is not held by this node — must refuse".into());
    }
    if !matches!(
        router.scoped_arrival(None, Some(&[0x11; 16]), OWN),
        Err(ServeRefusal::DiscriminatorUnheld)
    ) {
        return Err("unknown bytes must refuse by name".into());
    }
    let arrived = table
        .accepts_inbound(own.as_bytes())
        .ok_or("reverse index")?;
    if !matches!(
        router.scoped_arrival(Some(arrived), Some(own.as_bytes()), OWN),
        Err(ServeRefusal::DiscriminatorOnDerivedAddress)
    ) {
        return Err("a discriminator on a derived-address arrival is a mismatch".into());
    }
    if !matches!(
        BlobScopeRouter::new(None).scoped_arrival(None, Some(own.as_bytes()), OWN),
        Err(ServeRefusal::DiscriminatorUnheld)
    ) {
        return Err("a legacy node holds no derived address — must refuse".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-namespace-realtime` (CC 5.3.3.2.1): the ratified
/// `codec_id` bytes, and the codec+layer block as clear metadata at 48..52.
fn check_namespace_realtime() -> Result<(), String> {
    use crate::transport::realtime_av::{
        open_av_chunk, seal_av_chunk, ChunkLayer, ChunkSeq, Epoch, EpochDek, SealedAvChunk,
        StreamId, CODEC_AV1_SVC, CODEC_JPEG_XS, CODEC_MDC, CODEC_OPAQUE,
    };

    if [CODEC_AV1_SVC, CODEC_JPEG_XS, CODEC_MDC, CODEC_OPAQUE] != [0x01, 0x02, 0x03, 0xFF] {
        return Err("codec_id bytes differ from the ratified table".into());
    }
    let dek = EpochDek::from_bytes([0x5A; 32]);
    let transit = [0xA5; 32];
    let layer = ChunkLayer {
        spatial: 2,
        temporal: 1,
        quality: 3,
    };
    let sealed = seal_av_chunk(
        b"frame",
        &transit,
        b"link-872",
        7,
        &dek,
        StreamId([0x01; 32]),
        Epoch(2),
        ChunkSeq(3),
        CODEC_AV1_SVC,
        layer,
    )
    .map_err(|e| format!("seal: {e}"))?;
    let mut wire = sealed.to_bytes();
    if wire.get(48..52) != Some(&[CODEC_AV1_SVC, 2, 1, 3][..]) {
        return Err(format!(
            "codec_id + ChunkLayer must sit at offset 48..52, got {:?}",
            wire.get(48..52)
        ));
    }
    // A relay rewriting the block (the drop-without-decrypt case) must not
    // break the seal: the block is outside both AEADs.
    wire[48..52].copy_from_slice(&[CODEC_OPAQUE, 0, 0, 0]);
    let rewritten = SealedAvChunk::from_bytes(&wire).map_err(|e| format!("parse: {e}"))?;
    if rewritten.codec_id != CODEC_OPAQUE || rewritten.layer != ChunkLayer::BASE {
        return Err("the rewritten codec+layer block must read back as written".into());
    }
    match open_av_chunk(&rewritten, &transit, b"link-872", 7, &dek) {
        Ok(p) if p == b"frame" => Ok(()),
        other => Err(format!(
            "codec_id + ChunkLayer must be clear metadata outside both AEADs; rewriting them \
             changed the open: {other:?}"
        )),
    }
}

/// CIRISEdge#872 / CIRISConstitution#173 — `CLM-registry-wire` (CC 5.3.3.2.3
/// at `acacce4`): the 52-byte header is always present.
///
/// Each refusal is checked at its own layer: the header and the two AEAD tags
/// at parse, a tag-less inner ciphertext at the relay's outer open, and the
/// AEAD for a truncated ciphertext that never went through the parser.
fn check_registry_wire() -> Result<(), String> {
    use crate::transport::realtime_av::{
        inner_sealed_from_parts, open_av_chunk, open_av_outer, seal_av_chunk, seal_av_outer,
        ChunkLayer, ChunkSeq, Epoch, EpochDek, RealtimeAvError, SealedAvChunk, StreamId,
        AEAD_TAG_LEN, CHUNK_CODEC_LAYER_LEN, CHUNK_HEADER_LEN, CODEC_AV1_SVC,
        MIN_DOUBLE_SEALED_LEN,
    };

    if (CHUNK_HEADER_LEN, CHUNK_CODEC_LAYER_LEN) != (48, 4) {
        return Err("the header is 48 bytes plus the 4-byte codec+layer block".into());
    }
    let dek = EpochDek::from_bytes([0x3C; 32]);
    let transit = [0xC3; 32];
    let stream = [0x11; 32];
    let layer = ChunkLayer {
        spatial: 1,
        temporal: 2,
        quality: 3,
    };
    let sealed = seal_av_chunk(
        b"chunk",
        &transit,
        b"link-173",
        9,
        &dek,
        StreamId(stream),
        Epoch(0x0102_0304_0506_0708),
        ChunkSeq(0x1112_1314_1516_1718),
        CODEC_AV1_SVC,
        layer,
    )
    .map_err(|e| format!("seal: {e}"))?;
    let wire = sealed.to_bytes();

    let mut want = stream.to_vec();
    want.extend_from_slice(&0x0102_0304_0506_0708u64.to_be_bytes());
    want.extend_from_slice(&0x1112_1314_1516_1718u64.to_be_bytes());
    want.extend_from_slice(&[CODEC_AV1_SVC, 1, 2, 3]);
    want.extend_from_slice(&sealed.double_sealed_ciphertext);
    if wire != want {
        return Err("to_bytes must lay the chunk out exactly as the section's table".into());
    }
    let back = SealedAvChunk::from_bytes(&wire).map_err(|e| format!("parse: {e}"))?;
    if back.to_bytes() != wire
        || back.stream_id != StreamId(stream)
        || back.codec_id != CODEC_AV1_SVC
        || back.layer != layer
    {
        return Err("from_bytes must read back what to_bytes wrote".into());
    }

    // Shorter than the 52-byte header: malformed, refused at parse.
    for len in [0, 1, 47, 48, 51] {
        if SealedAvChunk::from_bytes(&wire[..len]).is_ok() {
            return Err(format!(
                "a {len}-byte wire is shorter than the 52-byte header and must be refused"
            ));
        }
    }
    // A ciphertext too short for the outer + inner tags is malformed:
    // refused at parse (CIRISConstitution#173), not left to the AEAD.
    for extra in [0, 1, AEAD_TAG_LEN - 1, MIN_DOUBLE_SEALED_LEN - 1] {
        if !matches!(
            SealedAvChunk::from_bytes(&wire[..52 + extra]),
            Err(RealtimeAvError::WireTooShort { .. })
        ) {
            return Err(format!(
                "a wire with {extra} ciphertext bytes cannot carry both AEAD tags and must be \
                 refused at parse"
            ));
        }
        // Built in-process, past the parser, it still never opens — at the
        // subscriber or at a relay — even under the right keys and counter.
        let short = SealedAvChunk {
            double_sealed_ciphertext: sealed.double_sealed_ciphertext[..extra].to_vec(),
            ..sealed.clone()
        };
        if open_av_chunk(&short, &transit, b"link-173", 9, &dek).is_ok()
            || open_av_outer(&short, &transit, b"link-173", 9).is_ok()
        {
            return Err(format!(
                "a ciphertext of {extra} bytes carries no complete seal and must not open"
            ));
        }
    }
    // A relay's outer open refuses an inner ciphertext shorter than its tag,
    // so a tag-less inner chunk is never forwarded.
    let tagless = inner_sealed_from_parts(
        StreamId(stream),
        Epoch(1),
        ChunkSeq(1),
        CODEC_AV1_SVC,
        layer,
        vec![0u8; AEAD_TAG_LEN - 1],
    );
    let outer = seal_av_outer(&tagless, &transit, b"link-173", 10).map_err(|e| e.to_string())?;
    if !matches!(
        open_av_outer(&outer, &transit, b"link-173", 10),
        Err(RealtimeAvError::InnerTooShort { .. })
    ) {
        return Err("a relay must refuse an inner ciphertext too short for its tag".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-chunklayer` (CC 5.3.3.2.4): `admits` is the per-axis
/// prefix test, over every cell of a small grid rather than a few samples.
fn check_chunklayer() -> Result<(), String> {
    use crate::transport::realtime_av::{ChunkLayer, ReceiverLayerPolicy};

    let dot = ReceiverLayerPolicy::BLINKING_DOT;
    let all = ReceiverLayerPolicy::UNCAPPED;
    if (dot.max_spatial, dot.max_temporal, dot.max_quality) != (0, 0, 0)
        || (all.max_spatial, all.max_temporal, all.max_quality) != (255, 255, 255)
    {
        return Err("BLINKING_DOT must be {0,0,0} and UNCAPPED {255,255,255}".into());
    }
    let capped = ReceiverLayerPolicy {
        max_spatial: 1,
        max_temporal: 2,
        max_quality: 0,
    };
    for policy in [capped, dot, all] {
        for spatial in 0..=3u8 {
            for temporal in 0..=3u8 {
                for quality in 0..=3u8 {
                    let cell = ChunkLayer {
                        spatial,
                        temporal,
                        quality,
                    };
                    let want = spatial <= policy.max_spatial
                        && temporal <= policy.max_temporal
                        && quality <= policy.max_quality;
                    if policy.admits(cell) != want {
                        return Err(format!(
                            "{policy:?}.admits({cell:?}) must be {want} (per-axis test)"
                        ));
                    }
                }
            }
        }
    }
    // An opaque chunk carries the base cell; every policy must admit it.
    if !all.admits(ChunkLayer {
        spatial: 255,
        temporal: 255,
        quality: 255,
    }) || ![capped, dot, all]
        .iter()
        .all(|p| p.admits(ChunkLayer::BASE))
    {
        return Err("UNCAPPED admits every cell, and every policy admits the base cell".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-liveness` (CC 5.3.3.4): fan-out is the intersection
/// of the entitled roster the caller passes and the node-local reachable set,
/// and planning it records nothing.
fn check_liveness() -> Result<(), String> {
    use crate::reachability::{AttemptOutcome, ReachabilityTracker};
    use crate::transport::realtime_av::{
        ChunkLayer, MeshParticipant, RealtimeFanout, REALTIME_MIN_RATIO,
    };
    use crate::transport::TransportId;

    let medium = TransportId("reticulum");
    let tracker = ReachabilityTracker::new(60);
    for _ in 0..4 {
        tracker.record_attempt("alice", medium, AttemptOutcome::SendSuccess);
        // Reachable but not entitled: must never be added.
        tracker.record_attempt("outsider", medium, AttemptOutcome::SendSuccess);
        tracker.record_attempt(
            "bob",
            medium,
            AttemptOutcome::SendFailure {
                error_class: "Timeout".into(),
            },
        );
    }
    // carol is entitled but has never been reached.
    let entitled = [
        MeshParticipant::new("alice".into(), b"link-a".to_vec()),
        MeshParticipant::new("bob".into(), b"link-b".to_vec()),
        MeshParticipant::new("carol".into(), b"link-c".to_vec()),
    ];
    let attempts = |t: &ReachabilityTracker| {
        t.snapshot_all()
            .iter()
            .map(|m| (m.peer_key_id.clone(), m.attempts))
            .collect::<std::collections::BTreeMap<_, _>>()
    };
    let before = attempts(&tracker);
    let plan = RealtimeFanout::plan_layered(
        &entitled,
        ChunkLayer::BASE,
        &tracker,
        medium,
        REALTIME_MIN_RATIO,
    );
    let planned: Vec<&str> = plan.iter().map(|p| p.peer_key_id.as_str()).collect();
    if planned != ["alice"] {
        return Err(format!(
            "fan_out must be entitled ∩ reachable = [alice] (no outsider, no unreachable bob, no \
             never-reached carol), got {planned:?}"
        ));
    }
    if attempts(&tracker) != before {
        return Err("planning a fan-out must not write to the presence tracker".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-welcome-wrap` (CC 5.4.4): ML-DSA-65 over the section's
/// encapsulation bytes, verified against the directory BEFORE HPKE open.
#[allow(clippy::similar_names)]
fn check_welcome_wrap() -> Result<(), String> {
    use crate::mls::{unwrap_welcome, wrap_welcome, FederationDirectoryEntry, WelcomeWrapError};
    use ciris_crypto::hpke::{XWingRecipientPublic, XWingRecipientSecret, HPKE_SUITE_ID};
    use ciris_crypto::{ml_kem, x25519, MlDsa65Signer, MlDsa65Verifier, PqcSigner, PqcVerifier};

    if HPKE_SUITE_ID != b"HPKE-xwing-hkdf-sha256-aes256gcm-v1" {
        return Err("HPKE_SUITE_ID must be the section's byte literal".into());
    }
    let crypto = |e: ciris_crypto::CryptoError| format!("crypto: {e}");
    let (x_sk, x_pk) = x25519::generate_ephemeral_keypair().map_err(crypto)?;
    let (k_sk, k_pk) = ml_kem::generate_keypair().map_err(crypto)?;
    let invitee_pk = XWingRecipientPublic {
        x25519_pub: x_pk,
        mlkem768_pub: k_pk.clone(),
    };
    let invitee_sk = XWingRecipientSecret {
        x25519_priv: x_sk,
        mlkem768_priv: k_sk,
        mlkem768_pub: k_pk,
    };
    let inviter = MlDsa65Signer::new().map_err(crypto)?;
    let inviter_pk = inviter.public_key().map_err(crypto)?;
    let directory = |pk: Vec<u8>| {
        move |id: &str| {
            Some(FederationDirectoryEntry {
                pk_id: id.to_string(),
                ml_dsa_pk: pk.clone(),
                x_wing_pk: None,
            })
        }
    };
    let wrapped = wrap_welcome(&inviter, "inviter-872", &invitee_pk, b"welcome", b"grp")
        .map_err(|e| format!("wrap: {e}"))?;

    // The signature covers x25519_eph || u32_be(len(ct)) || ct, built here
    // from the section rather than from the helper the wrap calls.
    let enc = &wrapped.hpke_sealed.encapsulation;
    let ct_len = u32::try_from(enc.mlkem768_ciphertext.len()).map_err(|e| e.to_string())?;
    let mut spec = enc.x25519_ephemeral_pub.to_vec();
    spec.extend_from_slice(&ct_len.to_be_bytes());
    spec.extend_from_slice(&enc.mlkem768_ciphertext);
    if !MlDsa65Verifier::new()
        .verify(&inviter_pk, &spec, &wrapped.inviter_signature)
        .map_err(crypto)?
    {
        return Err(
            "the inviter's ML-DSA-65 signature must cover the section's encap bytes".into(),
        );
    }

    match unwrap_welcome(&invitee_sk, &wrapped, b"grp", directory(inviter_pk.clone())) {
        Ok(w) if w == b"welcome" => {}
        other => return Err(format!("a well-signed Welcome must open, got {other:?}")),
    }
    if !matches!(
        unwrap_welcome(&invitee_sk, &wrapped, b"grp", |_: &str| None),
        Err(WelcomeWrapError::InviterUnknown(_))
    ) {
        return Err("an inviter the directory cannot resolve must be refused".into());
    }
    // Verification is the precondition: a forged signature under the WRONG
    // aad must be refused as a signature, i.e. before HPKE open ever runs.
    let mut forged = wrapped.clone();
    forged.inviter_signature[0] ^= 0x01;
    if !matches!(
        unwrap_welcome(&invitee_sk, &forged, b"not-grp", directory(inviter_pk)),
        Err(WelcomeWrapError::SignatureRejected)
    ) {
        return Err("signature verification must precede HPKE open_base".into());
    }
    let bystander = MlDsa65Signer::new().map_err(crypto)?;
    if !matches!(
        unwrap_welcome(
            &invitee_sk,
            &wrapped,
            b"grp",
            directory(bystander.public_key().map_err(crypto)?)
        ),
        Err(WelcomeWrapError::SignatureRejected)
    ) {
        return Err("a signature that does not verify under the directory key must refuse".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-announce-suppress` (CC 5.4.6), against the policy the
/// node installs as its `AnnounceControl` (the free `should_suppress_announce`
/// has no production caller; it must agree).
fn check_announce_suppress() -> Result<(), String> {
    use crate::announce_suppression::{should_suppress_announce, ScopePrivacyAnnouncePolicy};
    use crate::cohort_scope::CohortScope;

    let policy = ScopePrivacyAnnouncePolicy::new();
    let cases = [
        ([0x10; 16], CohortScope::SelfOnly, true),
        ([0x20; 16], CohortScope::Family, true),
        (
            [0x30; 16],
            CohortScope::Cohort {
                cohort_id: "community-872".into(),
            },
            true,
        ),
        ([0x40; 16], CohortScope::Public, false),
    ];
    for (hash, scope, suppress) in &cases {
        policy.register_destination_scope(*hash, scope.clone());
        if policy.decide(hash) != *suppress {
            return Err(format!(
                "a {} destination: suppress must be {suppress}",
                scope.kind_token()
            ));
        }
        if should_suppress_announce(scope) != *suppress {
            return Err(format!(
                "the scope rule and the installed policy disagree on {}",
                scope.kind_token()
            ));
        }
    }
    if !policy.decide(&[0xEE; 16]) {
        return Err("a destination with no known scope must fail toward suppression".into());
    }
    // Narrowing a destination's scope takes effect on the next decision.
    policy.register_destination_scope([0x40; 16], CohortScope::Family);
    if !policy.decide(&[0x40; 16]) {
        return Err("a destination re-scoped to family must stop announcing".into());
    }
    Ok(())
}

/// CIRISEdge#872 — `CLM-registry-replication` (CC 6.1.5.1 §R-policy).
fn check_registry_replication() -> Result<(), String> {
    use crate::holonomic::fountain_defaults::{
        recommended_policy, recommended_reconstruction_probability, FountainPolicy,
    };
    use crate::holonomic::swarm_rarity::{
        should_eject_above_target, ConsentState, EjectionVerdict, RarityScore,
    };

    let policy = recommended_policy();
    let pinned = FountainPolicy {
        n_source: 20,
        k_repair: 6,
        min_viable_symbols: 5,
        target_holders: 30,
    };
    if policy != pinned {
        return Err(format!(
            "the producer-silent tuple must be {pinned:?}, got {policy:?}"
        ));
    }
    if policy.min_viable_symbols == 0 {
        return Err("min_viable_symbols must be >= 1".into());
    }
    // The section's distinct-symbol law, not the naive Bin(30, q).
    for (q, want) in [(0.90, 0.995_039), (0.85, 0.957_288)] {
        let got = recommended_reconstruction_probability(q);
        if (got - want).abs() > 5e-7 {
            return Err(format!(
                "survival at q={q} must be the section's {want}, got {got}"
            ));
        }
    }
    // The converger reads the tuple in force, never a hard-coded one.
    let narrow = FountainPolicy {
        target_holders: 10,
        ..policy
    };
    let common = RarityScore(u32::MAX);
    if should_eject_above_target(12, &policy, ConsentState::Active, common) != EjectionVerdict::Keep
        || should_eject_above_target(12, &narrow, ConsentState::Active, common)
            != EjectionVerdict::EjectToTier
    {
        return Err(
            "the ejection verdict must follow the target_holders of the tuple in force".into(),
        );
    }
    Ok(())
}

/// One capacity ad for [`check_deterministic_alm`]. The planner is
/// signature-blind by design; the verification state is the input.
fn alm_ad(
    peer: &str,
    mbps: f32,
    verification: crate::holonomic::deterministic_topology::CapacityVerification,
) -> crate::holonomic::deterministic_topology::VerifiedCapacityAd {
    use crate::holonomic::deterministic_topology::{SignedRelayCapacity, VerifiedCapacityAd};
    use crate::transport::realtime_av::{Epoch, ReceiverLayerPolicy, StreamId};
    use crate::transport::realtime_av_alm::capacity::RelayCapacity;

    VerifiedCapacityAd {
        ad: SignedRelayCapacity {
            advertiser_key_id: peer.to_string(),
            capacity: RelayCapacity::new(
                mbps,
                4,
                16,
                ReceiverLayerPolicy::UNCAPPED,
                1_700_000_000_000,
            ),
            stream_id: StreamId([0; 32]),
            epoch: Epoch(1),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        },
        verification,
    }
}

/// A fully-trusted, mutually-reachable locality for
/// [`check_deterministic_alm`], with distinct RTTs per directed pair.
fn alm_full_mesh(
    peers: &[&str],
) -> (
    Vec<crate::holonomic::deterministic_topology::TrustGrant>,
    Vec<crate::holonomic::deterministic_topology::ReachabilityObservation>,
) {
    use crate::holonomic::deterministic_topology::{ReachabilityObservation, TrustGrant};

    let mut grants = Vec::new();
    let mut reach = Vec::new();
    for (i, from) in peers.iter().enumerate() {
        for (j, to) in peers.iter().enumerate() {
            if i == j {
                continue;
            }
            grants.push(TrustGrant {
                granter_peer_id: (*from).to_string(),
                grantee_peer_id: (*to).to_string(),
                granted_at_unix_ms: 1_700_000_000_000,
                chain_depth: 0,
                weight: TrustGrant::DEFAULT_WEIGHT,
            });
            reach.push(ReachabilityObservation {
                from_peer_id: (*from).to_string(),
                to_peer_id: (*to).to_string(),
                observed_rtt_ms: 40 + u32::try_from(i * 7 + j).unwrap_or(0),
                observed_at_unix_ms: 1_700_000_000_000,
            });
        }
    }
    (grants, reach)
}

/// CIRISEdge#872 — `CLM-deterministic-alm` (CC 6.1.6 §T / N8).
fn check_deterministic_alm() -> Result<(), String> {
    use crate::holonomic::deterministic_topology::{
        compute_alm_topology_verified,
        CapacityVerification::{HybridSignatureValid as Valid, Unverified},
        ReachabilityObservation, TrustGrant, VerifiedCapacityAd, VerifiedTopologyInputSnapshot,
        MAX_SELF_ASSERTED_UPLINK_MBPS,
    };

    let (grants, reach) = alm_full_mesh(&["p-a", "p-b", "p-c", "p-z"]);
    let topology = |ads: Vec<VerifiedCapacityAd>,
                    grants: Vec<TrustGrant>,
                    reach: Vec<ReachabilityObservation>| {
        let t = compute_alm_topology_verified(&VerifiedTopologyInputSnapshot {
            capacity_ads: ads,
            trust_grants: grants,
            reachability_observations: reach,
            locality_id: "loc-872".into(),
            snapshot_epoch_id: 7,
        });
        serde_json::to_vec(&t)
            .map(|b| (t, b))
            .map_err(|e| e.to_string())
    };

    // Determinism under permutation of every input list.
    let ads = vec![
        alm_ad("p-a", 80.0, Valid),
        alm_ad("p-b", 40.0, Valid),
        alm_ad("p-c", 10.0, Valid),
        alm_ad("p-z", 20.0, Valid),
    ];
    let (base, base_bytes) = topology(ads.clone(), grants.clone(), reach.clone())?;
    if base.tree.is_empty() {
        return Err("a fully-trusted, reachable locality must root a tree".into());
    }
    let (mut a, mut g, mut r) = (ads.clone(), grants.clone(), reach.clone());
    a.reverse();
    g.reverse();
    r.rotate_left(5);
    if topology(a, g, r)?.1 != base_bytes {
        return Err("a permutation of byte-equal inputs must give byte-equal output".into());
    }

    // N8 filter: an unverified ad never enters scoring, however large.
    let with_liar = |v| {
        vec![
            alm_ad("p-b", 10.0, Valid),
            alm_ad("p-c", 10.0, Valid),
            alm_ad("p-z", 1.0e6, v),
        ]
    };
    let (verified_liar, _) = topology(with_liar(Valid), grants.clone(), reach.clone())?;
    if !verified_liar.tree.iter().any(|e| e.parent_peer_id == "p-z") {
        return Err("a verified high-capacity ad must be able to win a parent slot".into());
    }
    let (unverified_liar, _) = topology(with_liar(Unverified), grants.clone(), reach.clone())?;
    if unverified_liar
        .tree
        .iter()
        .any(|e| e.parent_peer_id == "p-z" || e.child_peer_id == "p-z")
    {
        return Err("an unverified capacity ad must never enter scoring".into());
    }

    // N8 cap: a self-asserted uplink above the cap scores as the cap, so it
    // cannot beat an honest peer AT the cap (lex-min p-a wins that tie).
    let capped = |liar_mbps| {
        vec![
            alm_ad("p-a", MAX_SELF_ASSERTED_UPLINK_MBPS, Valid),
            alm_ad("p-b", 10.0, Valid),
            alm_ad("p-c", 10.0, Valid),
            alm_ad("p-z", liar_mbps, Valid),
        ]
    };
    let at_cap = topology(
        capped(MAX_SELF_ASSERTED_UPLINK_MBPS),
        grants.clone(),
        reach.clone(),
    )?
    .1;
    if topology(capped(1.0e6), grants, reach)?.1 != at_cap {
        return Err("self-asserted uplink above the cap must not outscore the cap".into());
    }
    Ok(())
}

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
        projection_for, registry::authority_for, tombstone_ceiling, Plane,
    };
    use ciris_persist::federation::types::cohort_scope;
    // CIRISPersist#713 / v35.0.0 — the projection is per-PLANE. It must be TOTAL
    // over (plane × the 7 closed cohort scopes) — edge's offer/projection filter
    // is a function of this value, so an unhandled cell would be a routing hole.
    // `authority_for` on a benign dimension gives a concrete AuthorityClass.
    let authority = authority_for("trust:example:v1").class;
    // CIRISPersist#742 — the Attestation plane's projection varies by
    // FAMILY, so sweeping it at one dimension is not sweeping the plane.
    // Persist found exactly this in its own corpus (`FAMILY_DIMS` claimed
    // "one representative per decided family" and was missing the three
    // newest, so its dominance invariant read as total while never seeing
    // them). Edge had the sharper version: ONE dimension, `trust:example:v1`,
    // standing in for every family edge actually routes.
    //
    // Persist's fix was a compile error — an exhaustive match over
    // `AttestationFamily` with no wildcard, so a new family fails the build
    // until someone names its representative. **That guard does not transfer
    // to edge.** `AttestationFamily` is `#[non_exhaustive]`, so a downstream
    // match MUST carry a wildcard arm and can never be exhaustive; and
    // `FAMILY_DIMS` / `all_planes()` live inside persist's own
    // `#[cfg(test)]` module, so there is nothing to reuse. Edge's fallback is
    // this list plus `family_representatives_still_classify_as_intended`
    // below, which catches the drift edge CAN see (a representative that
    // stops classifying) even though it cannot catch a family edge has never
    // heard of.
    for plane in [
        Plane::Attestation {
            dimension: "trust:example:v1",
        },
        Plane::Attestation {
            dimension: "accord:human_dignity:v1",
        },
        Plane::Attestation {
            dimension: "moderation:allegation:v1",
        },
        Plane::Attestation {
            dimension: "provenance:build_manifest:linux-x86_64:v1",
        },
        // CIRISEdge#706 — `consent:{kind}` is closed in its leaves (rc5), so the
        // reference refuses `consent:share:v1` as `namespace_family_unregistered`;
        // the Consent family stands on a catalogued leaf.
        Plane::Attestation {
            dimension: "consent:state:granted:v1",
        },
        Plane::Attestation {
            dimension: "trace:reasoning:v1",
        },
        Plane::Attestation {
            dimension: "scores:alignment:v1",
        },
        Plane::Attestation {
            dimension: "capacity:relay_delivery:v1",
        },
        Plane::KeyRecord,
        Plane::TransportDestination,
        Plane::FountainContent,
        Plane::HardCaseEvent,
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
    if projection_for(Plane::KeyRecord, cohort_scope::SELF, authority, false) != Projection::SelfOwn
    {
        return Err("cohort_scope=self must project SelfOwn (structural invisibility)".into());
    }
    // #713 — the per-plane CEILING replaces unconditional tombstone-Global.
    // Key-plane tombstones stay Global (verify-relevance is unbounded)…
    if projection_for(Plane::KeyRecord, cohort_scope::SELF, authority, true) != Projection::Global {
        return Err("a KeyRecord tombstone must project Global (anti-rollback)".into());
    }
    // …while a non-root reachability tombstone projects at the plane ceiling
    // (Cohort), NOT Global — widening a tombstone would disclose more than the
    // original fact ("this route was withdrawn" reveals the route existed).
    // This is the limb-(b) close: reachability no longer inherits the key
    // plane's audience (CIRISEdge#311 / CIRISPersist#713).
    if !authority.is_trust_root()
        && projection_for(
            Plane::TransportDestination,
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
        Plane::TransportDestination,
        cohort_scope::FEDERATION,
        authority,
        true,
    ) != tombstone_ceiling(Plane::TransportDestination, authority)
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
    use ciris_persist::federation::namespace::Plane;
    let dimension = "trust:example:v1";
    let a = projection_for(
        Plane::Attestation { dimension },
        "federation",
        authority_for(dimension).class,
        false,
    );
    let b = projection_for(
        Plane::Attestation { dimension },
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
    // `trace_summary:sample:v1`. Value semantics, not presence.
    let prefixes = vec!["trace:".to_string()];
    if !covers(&prefixes, "trace:complete:v1") {
        return Err("`trace:` must cover `trace:complete:v1`".into());
    }
    if covers(&prefixes, "trace_summary:sample:v1") {
        return Err(
            "`trace:` must NOT cover `trace_summary:sample:v1` (trailing colon significant)".into(),
        );
    }
    if covers(&prefixes, "capacity:integrity:v1") {
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

    /// CIRISEdge#706 item 1 — **replay the CC vectors against edge's matcher.**
    ///
    /// All 1147 published `(dimension, family, refusal)` triples (CC rc8.1), exact: a
    /// matcher that answers differently from the reference on any one fails
    /// the build, every mismatch named. Edge's matcher is persist's — the
    /// full-match, refusal-bearing `namespace::matcher::match_family` of
    /// persist v50.0.0 (CIRISPersist#924), wired in [`edge_namespace_match`]
    /// at the v33.0.0 adopt (CIRISEdge#702).
    #[test]
    fn cc_namespace_match_vectors_replay() {
        let vs = crate::cc_namespace::vectors();
        assert_eq!(vs.len(), crate::cc_namespace::VENDORED_N_VECTORS);
        let mut bad = Vec::new();
        for v in &vs {
            let (family, refusal) = edge_namespace_match(&v.dimension);
            if family != v.family || refusal != v.refusal {
                bad.push(format!(
                    "{:?}: reference ({:?}, {:?}) edge ({family:?}, {refusal:?})",
                    v.dimension, v.family, v.refusal
                ));
            }
        }
        assert!(
            bad.is_empty(),
            "{} divergence(s) from the CC reference matcher over {} vectors:\n{}",
            bad.len(),
            vs.len(),
            bad.join("\n")
        );
    }

    /// The function edge classifies a dimension through, as the vectors'
    /// `(family, refusal)` pair: persist v50's full-match, refusal-bearing
    /// `namespace::matcher::match_family` (CIRISPersist#924) — edge's matcher
    /// is persist's, never a second spelling.
    fn edge_namespace_match(dimension: &str) -> (Option<String>, Option<String>) {
        let m = ciris_persist::federation::namespace::matcher::match_family(dimension);
        (
            m.family.map(str::to_owned),
            m.refusal.map(|r| r.as_str().to_owned()),
        )
    }

    /// CIRISConstitution#129 (landed at `651140a`, vendored by persist v51) —
    /// edge's PRODUCTION A/V relay-delivery score dimension is a registered,
    /// edge-owned leaf under `capacity:`. Persist v50's rc5 registry refused it
    /// (`namespace_family_unregistered`); this pins that the registry edge ships
    /// against admits it, through the matcher persist's admission gate runs,
    /// AND that the CC reference agrees on the same bytes.
    #[test]
    fn the_production_relay_delivery_dimension_admits() {
        let dim = crate::transport::realtime_av_alm::CAPACITY_RELAY_DELIVERY_DIMENSION;
        assert_eq!(dim, "capacity:relay_delivery:v1");
        let (family, refusal) = edge_namespace_match(dim);
        assert_eq!(
            refusal, None,
            "{dim} must admit under the vendored registry"
        );
        assert_eq!(family.as_deref(), Some("capacity:relay_delivery"));
        let reference = crate::cc_namespace::vectors()
            .into_iter()
            .find(|v| v.dimension == dim)
            .expect("the CC vectors carry edge's registered row");
        assert_eq!(reference.refusal, None);
    }

    /// CIRISEdge#706 item 3 — every dimension this module's fixtures stand on
    /// that the CC vectors name must be ADMITTED by the reference. A fixture
    /// that the Constitution refuses (as `consent:share:v1` became when rc5
    /// closed `consent:{kind}`) tests a shape no conformant producer emits.
    #[test]
    fn this_modules_fixture_dimensions_are_admitted_by_the_cc_reference() {
        let admitted: std::collections::HashMap<String, Option<String>> =
            crate::cc_namespace::vectors()
                .into_iter()
                .map(|v| (v.dimension, v.refusal))
                .collect();
        // The Consent family's representative is a catalogued sample.
        assert_eq!(
            admitted.get("consent:state:granted:v1"),
            Some(&None),
            "the Consent fixture must be a leaf the rc5 reference admits"
        );
        assert!(
            !admitted.contains_key("consent:share:v1") || admitted["consent:share:v1"].is_some(),
            "consent:share:v1 is refused by rc5 — it must not come back as a fixture"
        );
    }
}
