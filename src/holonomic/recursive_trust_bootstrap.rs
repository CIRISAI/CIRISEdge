//! Recursive trust bootstrap — v3.10.0 holonomic Part 4
//! (CIRISEdge#137).
//!
//! A new peer is admitted if its signed claim chains (via witness
//! chain) to a trust root in our trust graph. No special first-peer
//! assumption. The federation can re-establish itself from any
//! sufficient fragment — including a single peer with a single
//! signed witness chain.
//!
//! Composes with:
//!
//! - #135 `WholenessWitness` — the witness chain is composed of
//!   `WholenessWitness` entries + signed claims.
//! - #134 swarm rarity — admitted peer immediately participates in
//!   rarity computation.
//! - #136 deterministic ALM — admitted peer arrives at the same
//!   topology as the existing federation.
//!
//! # Trust+serve vs. membership (CEG N1/N2)
//!
//! A successful witness-chain walk authenticates that a peer can be
//! **served** — rarity-counted (#134), topology-included (#136) — but
//! it does **NOT** make the peer a member of any community. This is
//! the F-1 fix for CIRISEdge#143: the old single-verdict
//! `recursive_trust_bootstrap` laundered membership out of pure
//! witness-chain reachability, so one depth-1 peer could feed
//! self-manufactured chains to N unowned Sybils and admit them all.
//!
//! Per §19.2 (CEG 1.0-RC11) the witness-chain walk yields **trust+serve
//! ONLY** — never membership. CIRISVerify v5.8.0's verdict type cannot
//! express member admission, so a producer that emitted one would be
//! rejected on the wire. The surface is therefore:
//!
//! - [`recursive_trust_bootstrap_trust_serve`] — the witness-chain
//!   walk. Yields [`AdmissionVerdict::AdmitTrustServe`] (trust+serve
//!   only) or [`AdmissionVerdict::Refuse`]. This is the ONLY function
//!   that walks the chain and emits a verdict.
//! - [`extract_owner_binding_for_destination_gate`] — a pure projection
//!   that surfaces the candidate's §5.6.8.10 owner-binding fields
//!   (`user_owner` / `delegates_to` / `identity_occurrence`) as an
//!   [`OwnerBinding`] when all three are present. It does NOT walk the
//!   chain and does NOT decide membership. The membership decision is
//!   the destination's: it composes this binding with the live
//!   `user`-owner `delegates_to` + community `consensus_protocol`
//!   check (non-infra) or the §13.3 founder-quorum check (infra-root) —
//!   a transitive chain alone MUST NOT satisfy either. That live gate
//!   lives OUTSIDE this module.
//!
//! The legacy [`recursive_trust_bootstrap`] name is kept as a thin
//! deprecated wrapper that returns the **trust+serve** variant (the
//! safe default — never membership).
//!
//! # Algorithm (shared chain walk)
//!
//! Both entry points share [`walk_trust_chain`]. It takes an
//! already-verified candidate [`SignedClaim`] plus the local node's
//! [`TrustGraph`] and the candidate's supplied [`WitnessChain`], and:
//!
//! 1. Refuses with [`AdmissionRefusal::SignatureInvalid`] if the
//!    candidate's `verified` flag is false. **Signature verification
//!    is the caller's job** — this function operates over the trust
//!    topology only.
//! 2. If the candidate's `signer_peer_id` is in `trust_graph.roots`,
//!    anchors at `trust_distance` `0`.
//! 3. Refuses with [`AdmissionRefusal::ChainTooLong`] if the chain's
//!    length exceeds [`MAX_WITNESS_CHAIN_LEN`] (hard cap of 5,
//!    independent of `trust_graph.max_chain_depth`) OR exceeds
//!    `trust_graph.max_chain_depth`.
//! 4. Walks the witness chain in reverse chronological order (newest
//!    claim first, oldest last — i.e. `claims.iter().enumerate().rev()`
//!    since index `0` is the OLDEST). While walking it tracks the set
//!    of `signer_peer_id`s seen; a repeat signer is a trust-graph
//!    cycle and refuses with [`AdmissionRefusal::TrustGraphCycle`].
//!    For each chain entry that is itself unverified, refuses with
//!    [`AdmissionRefusal::SignatureInvalid`] (the chain must be fully
//!    signed). For each verified chain entry, if its `signer_peer_id`
//!    is in `trust_graph.roots`, anchor distance is `0`; if it's a
//!    granter in `trust_graph.grants` with `chain_depth <=
//!    trust_graph.max_chain_depth`, anchor distance is `chain_depth`.
//!    Otherwise the entry is unanchored and the loop continues. The
//!    grant `weight` of each anchoring/granter entry is accumulated.
//!    When an anchor is found at chain index `i` with anchor distance
//!    `d`, the candidate's distance is `d + (chain.len() - i)`.
//! 5. If the cumulative candidate distance would exceed
//!    `trust_graph.max_chain_depth`, refuses with
//!    [`AdmissionRefusal::BudgetExceeded`].
//! 6. §13.3 aggregate-weight cap: the sum of grant weights along the
//!    walked path must not exceed `root_trust / 2` where `root_trust`
//!    is the trust weight at the anchor ([`TrustGrant::DEFAULT_WEIGHT`]
//!    for a direct root). Exceeding it refuses with
//!    [`AdmissionRefusal::AggregateWeightCapExceeded`].
//! 7. If no chain entry anchors, refuses with
//!    [`AdmissionRefusal::ChainExhausted`].
//!
//! ## §10.1.5.1.1 gate discipline
//!
//! The admission-verdict functions in this module are themselves
//! §10.1.5.1.1 gates. They MUST NOT trust an in-band `verified` flag
//! arriving from outside the gate boundary. The `verified: bool` field
//! on [`SignedClaim`] is `#[serde(skip)]` to enforce this at the wire
//! level: a wire-incoming claim deserializes with `verified == false`
//! (the serde default for `bool`), so it cannot ride in pre-flagged as
//! `true`. The flag is purely in-process and may only be set after the
//! caller verifies the hybrid-PQC signature against the signer's
//! pubkeys; an unverified candidate or chain entry is refused with
//! [`AdmissionRefusal::SignatureInvalid`] before any admit path.
//!
//! # Wire contract
//!
//! [`SignedClaim::canonical_value`] produces the canonical-bytes
//! input the hybrid signer must sign over. The signed canonical
//! value field order is (see [`SignedClaim::CANONICAL_FIELD_ORDER`]):
//!
//! 1. `signed_at_unix_ms` — 8 bytes BE u64
//! 2. `claim_version` — 2 bytes BE u16
//! 3. `claim_kind` — length-prefixed UTF-8 (4 bytes BE u32 length +
//!    bytes)
//! 4. `signer_peer_id` — length-prefixed UTF-8 (4 bytes BE u32
//!    length + bytes)
//! 5. `claim_bytes_hex` — length-prefixed lowercase-hex ASCII
//!    (4 bytes BE u32 length + bytes)
//! 6. `user_owner` — §5.6.8.10 owner-binding, optional. Encoded as
//!    a 1-byte presence flag (`0x00` absent / `0x01` present);
//!    when present, followed by length-prefixed UTF-8.
//! 7. `delegates_to` — same optional encoding.
//! 8. `identity_occurrence` — same optional encoding.
//!
//! `claim_bytes` is encoded as lowercase hex in the canonical value
//! so the canonical-bytes input remains pure-ASCII and is safe to
//! diff/log/structure-print. Hybrid sig fields (Ed25519 + ML-DSA-65)
//! live OUTSIDE the canonical bytes on [`SignedClaim`].
//!
//! ## Owner-binding additive-field back-compat
//!
//! The three owner-binding fields are **additive** and keep the
//! existing `CIRIS-CLAIM-v1` domain separator. A verifier that
//! predates them treats them as `None`; the presence-flag encoding
//! means a `None` owner-binding contributes exactly three `0x00`
//! bytes at the tail, so a legacy claim (no owner-binding) and a
//! new claim with all-`None` owner-binding produce **byte-identical**
//! canonical values — the wire change is backward compatible.
//!
//! # `TrustGrant` re-export
//!
//! v3.10.0 Part 3 (CIRISEdge#136, deterministic ALM topology)
//! authors the canonical [`TrustGrant`] type. Part 4 re-exports it
//! from `crate::holonomic::deterministic_topology` so there is exactly
//! one wire-shape across the substrate.

use std::collections::{BTreeSet, HashSet};

use serde::{Deserialize, Serialize};

/// Hard cap on witness-chain length (CEG N1/N2, F-1).
///
/// Independent of [`TrustGraph::max_chain_depth`]: even if a node
/// configures a larger `max_chain_depth`, a witness chain longer than
/// this is refused with [`AdmissionRefusal::ChainTooLong`]. Caps the
/// blast radius of a caller-supplied chain.
pub const MAX_WITNESS_CHAIN_LEN: usize = 5;

// ─── Trust-graph types ─────────────────────────────────────────────

/// A signed grant of trust from one peer to another.
///
/// Re-exported from Part 3 ([`crate::holonomic::deterministic_topology`])
/// — that module owns the canonical shape. Part 4 reads the
/// `chain_depth` field as the distance-from-root anchor when computing
/// trust budgets in [`bootstrap_admit`].
pub use crate::holonomic::deterministic_topology::TrustGrant;

/// The local node's view of trust.
///
/// `roots` are pubkey-form peer ids the local node trusts directly
/// (out-of-band, hard-coded, or via prior accord acceptance).
/// `grants` extend trust transitively; `max_chain_depth` caps how
/// far a witness chain may extend before bootstrap refuses.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustGraph {
    /// Pubkey-form peer ids the local node trusts directly.
    pub roots: Vec<String>,

    /// Transitive grants — same shape as Part 3.
    pub grants: Vec<TrustGrant>,

    /// Maximum number of trust hops from a root before bootstrap
    /// refuses with [`AdmissionRefusal::ChainTooLong`] or
    /// [`AdmissionRefusal::BudgetExceeded`].
    pub max_chain_depth: u8,
}

impl TrustGraph {
    /// Look up the anchor distance AND grant weight of a peer id.
    ///
    /// Returns:
    /// - `Some((0, TrustGrant::DEFAULT_WEIGHT))` if the peer id is in
    ///   [`Self::roots`] (a direct root carries full trust weight).
    /// - `Some((chain_depth, weight))` of the FIRST grant whose
    ///   `granter_peer_id == peer_id` and `chain_depth <=
    ///   max_chain_depth`.
    /// - `None` otherwise.
    ///
    /// Iteration is deterministic in the order grants were added.
    /// The weight is surfaced so the §13.3 aggregate-weight cap can
    /// sum grant weights along the walked chain.
    fn anchor_for(&self, peer_id: &str) -> Option<(u8, u32)> {
        if self.roots.iter().any(|r| r == peer_id) {
            return Some((0, TrustGrant::DEFAULT_WEIGHT));
        }
        for grant in &self.grants {
            if grant.granter_peer_id == peer_id && grant.chain_depth <= self.max_chain_depth {
                return Some((grant.chain_depth, grant.weight));
            }
        }
        None
    }
}

// ─── Signed-claim envelope ─────────────────────────────────────────

/// Generic signed-claim envelope — the bootstrap surface.
///
/// We already have specific signed-claim types like
/// [`SignedRelayCapacity`](crate::transport::realtime_av_alm::SignedRelayCapacity);
/// this is the **generic** shape used by the recursive-trust
/// bootstrap algorithm. `claim_bytes` is the canonical bytes of the
/// inner claim — opaque to this module.
///
/// # Signature contract
///
/// `signature_ed25519_base64` and `signature_ml_dsa_65_base64` are
/// **hybrid sig fields outside the canonical bytes**. Same hybrid
/// shape as [`SignedRelayCapacity`]: classical Ed25519 over
/// [`Self::canonical_value`], then ML-DSA-65 over `(canonical ||
/// ed25519_sig)`.
///
/// The `verified` flag is a documented caller contract:
/// [`recursive_trust_bootstrap`] DOES NOT re-verify the signature
/// — the verification call lives at the caller. The function takes
/// already-verified claims as input and trusts `verified` to be
/// true; if it's false, the function refuses with
/// [`AdmissionRefusal::SignatureInvalid`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedClaim {
    /// What kind of claim this is — e.g. `"trust_grant"`,
    /// `"holding_claim"`, `"wholeness_witness"`. Opaque to the
    /// bootstrap algorithm; bound into the canonical bytes so a
    /// `trust_grant` signature can't be replayed as a
    /// `holding_claim`.
    pub claim_kind: String,

    /// Pubkey-form peer id of the signer. Bound into the canonical
    /// bytes so the signer can't be substituted post-sign.
    pub signer_peer_id: String,

    /// Canonical bytes of the inner claim. Opaque to this module.
    pub claim_bytes: Vec<u8>,

    /// Wall-clock the claim was signed. Bootstrap doesn't validate
    /// the timestamp — that's the policy layer's job.
    pub signed_at_unix_ms: u64,

    /// Schema version of the inner claim. Bound into the canonical
    /// bytes so a v1 signature can't be replayed as v2.
    pub claim_version: u16,

    /// §5.6.8.10 owner-binding: the `user`-owner peer_id whose live
    /// `delegates_to` admits this claim toward MEMBERSHIP. `None`
    /// means this claim carries no owner-binding, so
    /// [`extract_owner_binding_for_destination_gate`] yields `None`
    /// and the destination's membership gate has nothing to act on.
    /// Bound into the canonical bytes so the owner can't be forged
    /// post-sign.
    pub user_owner: Option<String>,

    /// §5.6.8.10 — the peer this claim delegates membership to. Must
    /// match the destination's identity for membership admission
    /// (the destination performs that match — this module only
    /// surfaces the field). Bound into the canonical bytes.
    pub delegates_to: Option<String>,

    /// §5.6.8.10 — the `identity_occurrence` (instance-of-identity)
    /// the claim is bound to at the destination. Bound into the
    /// canonical bytes.
    pub identity_occurrence: Option<String>,

    /// Base64 Ed25519 signature over [`Self::canonical_value`].
    /// Outside the canonical bytes.
    pub signature_ed25519_base64: String,

    /// Base64 ML-DSA-65 signature over `(canonical ||
    /// ed25519_sig)`. Outside the canonical bytes.
    pub signature_ml_dsa_65_base64: String,

    /// In-process verification flag. NEVER serialized — `#[serde(skip)]`
    /// ensures this cannot arrive over the wire as `true`. Set this to
    /// `true` ONLY after calling the appropriate hybrid-PQC verification
    /// function in-process against `signer_peer_id`'s pubkeys.
    ///
    /// Admission-verdict functions in this module are themselves
    /// §10.1.5.1.1 gates: they do NOT treat this flag as a substitute
    /// for verification. A wire-incoming claim deserializes with
    /// `verified == false` (serde default for `bool`), so it is refused
    /// with [`AdmissionRefusal::SignatureInvalid`] until the caller has
    /// verified it in-process and set the flag.
    ///
    /// Default: false (fail-secure).
    #[serde(skip)]
    pub verified: bool,
}

impl SignedClaim {
    /// Documented canonical-value field order. The signed canonical
    /// value field order is locked here so cross-language signers
    /// (PyO3 / UniFFI / future Swift binding) all produce the same
    /// bytes.
    pub const CANONICAL_FIELD_ORDER: &'static [&'static str] = &[
        "signed_at_unix_ms",
        "claim_version",
        "claim_kind",
        "signer_peer_id",
        "claim_bytes_hex",
        "user_owner",
        "delegates_to",
        "identity_occurrence",
    ];

    /// Domain separator for the canonical bytes. Disambiguates from
    /// other CIRIS signed envelopes (relay-capacity, accord,
    /// envelope, ...).
    pub const DOMAIN_SEP: &'static [u8; 16] = b"CIRIS-CLAIM-v1\0\0";

    /// Build the canonical-bytes input the hybrid signer signs
    /// over. Field order matches [`Self::CANONICAL_FIELD_ORDER`].
    ///
    /// `claim_bytes` is encoded as lowercase hex so the canonical
    /// bytes remain pure-ASCII (safe to diff / log / structure-
    /// print). Each variable-length field is length-prefixed with
    /// a 4-byte BE u32 byte length.
    ///
    /// The three owner-binding fields are appended in locked order
    /// at the tail, each as a 1-byte presence flag followed (when
    /// present) by a length-prefixed UTF-8 value. An all-`None`
    /// owner-binding therefore appends exactly three `0x00` bytes,
    /// matching a legacy claim that predates these fields.
    #[must_use]
    pub fn canonical_value(&self) -> Vec<u8> {
        let claim_bytes_hex = lowercase_hex(&self.claim_bytes);

        let mut out = Vec::with_capacity(
            Self::DOMAIN_SEP.len()
                + 8
                + 2
                + 4
                + self.claim_kind.len()
                + 4
                + self.signer_peer_id.len()
                + 4
                + claim_bytes_hex.len()
                + 3,
        );

        out.extend_from_slice(Self::DOMAIN_SEP);
        out.extend_from_slice(&self.signed_at_unix_ms.to_be_bytes());
        out.extend_from_slice(&self.claim_version.to_be_bytes());

        push_len_prefixed(&mut out, self.claim_kind.as_bytes());
        push_len_prefixed(&mut out, self.signer_peer_id.as_bytes());
        push_len_prefixed(&mut out, claim_bytes_hex.as_bytes());

        push_optional(&mut out, self.user_owner.as_deref());
        push_optional(&mut out, self.delegates_to.as_deref());
        push_optional(&mut out, self.identity_occurrence.as_deref());

        out
    }
}

/// Append a 4-byte BE u32 length prefix + bytes.
fn push_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    #[allow(clippy::cast_possible_truncation)]
    let len = bytes.len() as u32;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

/// Append an optional UTF-8 field: a 1-byte presence flag (`0x00`
/// absent / `0x01` present), then — when present — a length-prefixed
/// value. `None` contributes a single `0x00` byte.
fn push_optional(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        Some(v) => {
            out.push(0x01);
            push_len_prefixed(out, v.as_bytes());
        }
        None => out.push(0x00),
    }
}

/// Lowercase hex encoder. Local because this module has no
/// `hex`-crate dep at the Cargo level for the holonomic surface
/// (and the canonical-bytes path is hot enough we'd rather not
/// pull a transitive dep just for this one call site).
fn lowercase_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ─── Witness chain ─────────────────────────────────────────────────

/// An ordered list of [`SignedClaim`]s, each signed by a peer.
///
/// Index `0` is the OLDEST claim. The bootstrap algorithm walks
/// BACKWARDS through the chain (newest first, oldest last) looking
/// for the first claim whose signer anchors to a trust root.
///
/// `chain_version` lets the federation evolve the chain encoding
/// without breaking already-circulating chains; v1 is the only
/// version defined today.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessChain {
    /// Ordered chronologically; index `0` is the oldest claim.
    pub claims: Vec<SignedClaim>,

    /// Schema version of the witness-chain encoding. v1 today.
    pub chain_version: u16,
}

// ─── Admission verdict ─────────────────────────────────────────────

/// §5.6.8.10 owner-binding surfaced by
/// [`extract_owner_binding_for_destination_gate`].
///
/// Carries the three owner-binding fields the destination needs to
/// run its live `delegates_to` + `consensus_protocol` check. This
/// module does NOT perform that check, and (per §19.2) does NOT walk
/// the trust chain to produce it — it only projects the binding fields
/// off a candidate claim when all three are present. The membership
/// decision is the destination's, not the chain walk's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnerBinding {
    /// The `user`-owner peer_id whose live `delegates_to` admits the
    /// candidate toward membership.
    pub user_owner: String,
    /// The peer this claim delegates membership to.
    pub delegates_to: String,
    /// The `identity_occurrence` the claim is bound to at the
    /// destination.
    pub identity_occurrence: String,
}

/// The outcome of the recursive-trust-bootstrap admission surface.
///
/// **§19.2 RC11 — trust+serve ONLY.** The chain walk yields exactly
/// two outcomes: [`Self::AdmitTrustServe`] or [`Self::Refuse`]. There
/// is deliberately NO `AdmitMember` variant. CIRISVerify v5.8.0's
/// verdict type cannot express member admission — the cross-impl
/// verifier rejects any producer that emits a membership verdict from
/// the chain walk. Membership is a SEPARATE destination-side gate
/// (§5.6.8.10 live owner-binding / §13.3 founder-quorum) that consumes
/// the owner-binding fields surfaced by
/// [`extract_owner_binding_for_destination_gate`]; it is not, and must
/// never be, an output of this trust-graph reachability computation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionVerdict {
    /// **Trust+serve admission ONLY.** The chain authenticates that
    /// the peer can be SERVED (rarity-counted via #134, topology-
    /// included via #136) but is NOT a member of any community. The
    /// §5.6.8.10 owner-binding gate must run separately at the
    /// destination for membership.
    ///
    /// `trust_distance` is the number of trust hops between the peer
    /// and the anchoring root (0 means the peer IS a root).
    /// `anchored_to_root` is the pubkey-form peer id of the anchor
    /// the chain reached.
    AdmitTrustServe {
        trust_distance: u8,
        anchored_to_root: String,
    },
    /// Peer cannot be admitted at the requested tier.
    Refuse { reason: AdmissionRefusal },
}

/// Why a peer was refused admission.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdmissionRefusal {
    /// No claim in the witness chain anchored to a root in the
    /// local trust graph.
    ChainExhausted,
    /// The candidate claim or a chain entry was not pre-verified
    /// by the caller. [`recursive_trust_bootstrap`] does NOT
    /// re-verify signatures.
    SignatureInvalid,
    /// The witness chain has more entries than the hard cap
    /// ([`MAX_WITNESS_CHAIN_LEN`]) or than
    /// [`TrustGraph::max_chain_depth`] allows.
    ChainTooLong,
    /// An anchor exists but the candidate's cumulative trust
    /// distance would exceed [`TrustGraph::max_chain_depth`].
    BudgetExceeded,
    /// The witness chain visits the same `signer_peer_id` twice —
    /// a trust-graph cycle. Caller-supplied chains can be looped to
    /// inflate reachability, so a repeat signer is rejected.
    TrustGraphCycle,
    /// The sum of grant weights along the walked chain exceeds the
    /// §13.3 aggregate-weight cap (`0.5 × root_trust` at the anchor).
    AggregateWeightCapExceeded,
}

// ─── The chain walk ────────────────────────────────────────────────

/// A successful chain walk: the candidate anchors to `anchored_to_root`
/// at `trust_distance` hops, within both the depth budget and the
/// §13.3 aggregate-weight cap.
struct ChainAnchor {
    trust_distance: u8,
    anchored_to_root: String,
}

/// Walk the witness chain and either anchor the candidate to the
/// trust graph or return a refusal. The core of
/// [`recursive_trust_bootstrap_trust_serve`]; it performs the
/// trust+serve-level checks ONLY (verification flags, depth + hard
/// cap, cycle rejection, budget, §13.3 weight cap). Per §19.2 this is
/// the full extent of the chain walk — membership is never an output.
/// Owner-binding is the destination gate's concern, surfaced
/// separately by [`extract_owner_binding_for_destination_gate`].
///
/// See the module-level docs for the step-by-step. Returns
/// `Ok(ChainAnchor)` on a successful walk, `Err(reason)` otherwise.
fn walk_trust_chain(
    p_signed_claim: &SignedClaim,
    trust_graph: &TrustGraph,
    witness_chain: &WitnessChain,
) -> Result<ChainAnchor, AdmissionRefusal> {
    // Step 1 — refuse fast if the candidate claim isn't verified.
    if !p_signed_claim.verified {
        return Err(AdmissionRefusal::SignatureInvalid);
    }

    // Step 2 — if the candidate's signer is already a root, anchor
    // at distance 0. A direct root carries full trust weight and a
    // zero-hop walk accumulates no grant weight, so the §13.3 cap is
    // trivially satisfied.
    if trust_graph
        .roots
        .iter()
        .any(|r| r == &p_signed_claim.signer_peer_id)
    {
        return Ok(ChainAnchor {
            trust_distance: 0,
            anchored_to_root: p_signed_claim.signer_peer_id.clone(),
        });
    }

    // Step 3 — chain length check against BOTH the hard cap
    // (MAX_WITNESS_CHAIN_LEN) and the configured max chain depth,
    // before any walk.
    let chain_len = witness_chain.claims.len();
    if chain_len > MAX_WITNESS_CHAIN_LEN || chain_len > usize::from(trust_graph.max_chain_depth) {
        return Err(AdmissionRefusal::ChainTooLong);
    }

    // Step 4 — walk newest → oldest (index 0 == oldest, so
    // `.enumerate().rev()` yields (len-1, newest) down to (0,
    // oldest)). First anchor wins.
    //
    // `seen` rejects trust-graph cycles: a caller-supplied chain that
    // revisits a signer can loop to inflate reachability, so a repeat
    // `signer_peer_id` is rejected. Detection is O(chain_len) time and
    // space — and chain_len is hard-capped at MAX_WITNESS_CHAIN_LEN
    // (5), so it is trivially bounded.
    //
    // `weight_acc` accumulates the §13.3 grant weights of the granter
    // entries crossed before the anchor.
    let roots_set: BTreeSet<&str> = trust_graph.roots.iter().map(String::as_str).collect();
    let mut seen: HashSet<&str> = HashSet::with_capacity(chain_len);

    // §13.3 weight accounting. Roots are the hard terminal anchor; a
    // granter accumulates its weight and the walk continues so a root
    // deeper in the chain still wins. `granter_acc` is the running sum
    // of granter weights crossed; `granter_fallback` remembers the
    // FIRST (newest) granter anchor so a chain that never reaches a
    // root can still anchor on it. When a root terminates, the sum
    // capped is `granter_acc`; when the fallback granter terminates,
    // the sum capped is `granter_acc` MINUS the fallback's own weight
    // (its weight is the budget, not part of the sum).
    let mut granter_acc: u64 = 0;
    let mut granter_fallback: Option<(usize, u8, u32)> = None;

    for (i, claim) in witness_chain.claims.iter().enumerate().rev() {
        if !claim.verified {
            return Err(AdmissionRefusal::SignatureInvalid);
        }

        let signer = claim.signer_peer_id.as_str();
        if !seen.insert(signer) {
            return Err(AdmissionRefusal::TrustGraphCycle);
        }

        // Direct-root anchor at chain index i: root_trust is full and
        // every granter weight crossed before it counts toward the cap.
        if roots_set.contains(signer) {
            return finish_anchor(
                i,
                chain_len,
                0,
                granter_acc,
                TrustGrant::DEFAULT_WEIGHT,
                signer,
                trust_graph.max_chain_depth,
            );
        }

        // Granter entry at chain index i: accumulate its weight and
        // remember it as the fallback anchor (the newest granter is
        // the closest anchor on the candidate's side), then continue
        // the walk in case a root appears deeper.
        if let Some((d, w)) = trust_graph.anchor_for(signer) {
            granter_acc = granter_acc.saturating_add(u64::from(w));
            if granter_fallback.is_none() {
                granter_fallback = Some((i, d, w));
            }
        }

        // Unanchored intermediate entry contributes no §13.3 weight.
    }

    // Step 5 — no root terminated the walk. If a granter anchor was
    // seen, finalize on it: its own weight is the budget, so the
    // capped sum is the accumulated granter weight MINUS that budget.
    if let Some((i, d, w)) = granter_fallback {
        let crossed = granter_acc.saturating_sub(u64::from(w));
        return finish_anchor(
            i,
            chain_len,
            d,
            crossed,
            w,
            witness_chain.claims[i].signer_peer_id.as_str(),
            trust_graph.max_chain_depth,
        );
    }

    Err(AdmissionRefusal::ChainExhausted)
}

/// Finish a successful anchor: compute the candidate distance, then
/// enforce the depth budget and the §13.3 aggregate-weight cap
/// (`sum <= root_trust / 2`).
///
/// `chain_len - i` is the number of trust hops between the anchor
/// claim and the candidate (the candidate sits "after" the newest
/// claim, so one extra hop than the index gap to the end).
fn finish_anchor(
    i: usize,
    chain_len: usize,
    anchor_dist: u8,
    weight_acc: u64,
    root_trust: u32,
    anchored_to_root: &str,
    max_chain_depth: u8,
) -> Result<ChainAnchor, AdmissionRefusal> {
    // hops_to_candidate = (chain_len - i) — guaranteed >= 1 because
    // i < chain_len everywhere this is called from. Bound to u8 via
    // saturating cast — the chain-length check earlier ensures
    // chain_len <= max_chain_depth <= u8::MAX so no truncation in
    // practice.
    let hops_to_candidate = chain_len - i; // >= 1
    let hops_u8 = u8::try_from(hops_to_candidate).unwrap_or(u8::MAX);
    let total = anchor_dist.saturating_add(hops_u8);
    if total > max_chain_depth {
        return Err(AdmissionRefusal::BudgetExceeded);
    }

    // §13.3 aggregate-weight cap: the sum of the TRANSITIVE grant
    // weights crossed before the anchor (`weight_acc`) must not exceed
    // `root_trust / 2`, where `root_trust` is the trust weight at the
    // anchor itself. The anchor's own weight is the budget, not part
    // of the sum — a bare anchor (no transitive grants crossed,
    // `weight_acc == 0`) is always within the cap. Integer math only —
    // wire-determinism critical.
    let cap = u64::from(root_trust) / 2;
    if weight_acc > cap {
        return Err(AdmissionRefusal::AggregateWeightCapExceeded);
    }

    Ok(ChainAnchor {
        trust_distance: total,
        anchored_to_root: anchored_to_root.to_string(),
    })
}

// ─── Public admission surface ──────────────────────────────────────

/// Admit at **TRUST+SERVE** scope only (witness-chain reachability).
///
/// This is what the chain walk authenticates; it does NOT grant
/// membership. See module-level docs for the full algorithm. Pure
/// compute over the trust topology — signature verification lives at
/// the caller per the [`SignedClaim::verified`] contract.
///
/// Returns [`AdmissionVerdict::AdmitTrustServe`] on a successful walk,
/// otherwise [`AdmissionVerdict::Refuse`].
#[must_use]
pub fn recursive_trust_bootstrap_trust_serve(
    p_signed_claim: &SignedClaim,
    trust_graph: &TrustGraph,
    witness_chain: &WitnessChain,
) -> AdmissionVerdict {
    match walk_trust_chain(p_signed_claim, trust_graph, witness_chain) {
        Ok(anchor) => AdmissionVerdict::AdmitTrustServe {
            trust_distance: anchor.trust_distance,
            anchored_to_root: anchor.anchored_to_root,
        },
        Err(reason) => AdmissionVerdict::Refuse { reason },
    }
}

/// §19.2 — surface the §5.6.8.10 owner-binding off a candidate claim
/// for the destination's SEPARATE membership gate.
///
/// This is NOT an admission decision and deliberately does NOT walk
/// the trust chain. Per §19.2 the chain walk yields trust+serve only
/// (see [`AdmissionVerdict`]); the membership decision belongs to the
/// destination, which composes:
/// - non-infra: the §5.6.8.10 owner-binding precondition (live
///   `user`-owner `delegates_to` + community `consensus_protocol`)
/// - infra-root: §13.3 founder-quorum (a transitive chain alone MUST
///   NOT satisfy it)
///
/// That live gate lives OUTSIDE this module. All this function does is
/// project the three owner-binding fields off the candidate claim:
/// returns `Some(OwnerBinding)` when all three (`user_owner`,
/// `delegates_to`, `identity_occurrence`) are present, else `None`.
/// `None` means the destination gate has nothing to act on — it is not
/// itself a refusal, since the trust+serve walk and the membership gate
/// are independent surfaces.
#[must_use]
pub fn extract_owner_binding_for_destination_gate(
    p_signed_claim: &SignedClaim,
) -> Option<OwnerBinding> {
    match (
        &p_signed_claim.user_owner,
        &p_signed_claim.delegates_to,
        &p_signed_claim.identity_occurrence,
    ) {
        (Some(user_owner), Some(delegates_to), Some(identity_occurrence)) => Some(OwnerBinding {
            user_owner: user_owner.clone(),
            delegates_to: delegates_to.clone(),
            identity_occurrence: identity_occurrence.clone(),
        }),
        _ => None,
    }
}

/// Legacy entry point — kept for v4.0.x backward compatibility.
///
/// # Deprecated
///
/// Prefer the explicit [`recursive_trust_bootstrap_trust_serve`]. This
/// wrapper returns the **trust+serve** variant — the safe default that
/// never grants membership (per §19.2 the chain walk never can) — so
/// v4.0.x callers keep compiling without silently laundering
/// membership.
#[must_use]
#[deprecated(note = "use recursive_trust_bootstrap_trust_serve; the chain walk is \
            trust+serve only (§19.2). For owner-binding, use \
            extract_owner_binding_for_destination_gate")]
pub fn recursive_trust_bootstrap(
    p_signed_claim: &SignedClaim,
    trust_graph: &TrustGraph,
    witness_chain: &WitnessChain,
) -> AdmissionVerdict {
    recursive_trust_bootstrap_trust_serve(p_signed_claim, trust_graph, witness_chain)
}

// ───────────────────────────────────────────────────────────────────
// Tests
// ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn claim(kind: &str, signer: &str, version: u16) -> SignedClaim {
        SignedClaim {
            claim_kind: kind.to_string(),
            signer_peer_id: signer.to_string(),
            claim_bytes: vec![0xde, 0xad, 0xbe, 0xef],
            signed_at_unix_ms: 1_700_000_000_000,
            claim_version: version,
            user_owner: None,
            delegates_to: None,
            identity_occurrence: None,
            signature_ed25519_base64: "ed25519-stub".into(),
            signature_ml_dsa_65_base64: "ml-dsa-65-stub".into(),
            verified: true,
        }
    }

    /// A candidate claim carrying the full §5.6.8.10 owner-binding.
    fn owner_bound_claim(kind: &str, signer: &str) -> SignedClaim {
        let mut c = claim(kind, signer, 1);
        c.user_owner = Some("USER_OWNER_PEER".into());
        c.delegates_to = Some(signer.to_string());
        c.identity_occurrence = Some(format!("{signer}#occ-1"));
        c
    }

    #[allow(clippy::similar_names)]
    fn grant(granter: &str, grantee: &str, dist: u8) -> TrustGrant {
        TrustGrant {
            granter_peer_id: granter.to_string(),
            grantee_peer_id: grantee.to_string(),
            chain_depth: dist,
            granted_at_unix_ms: 1_700_000_000_000,
            weight: TrustGrant::canonical_weight_for_depth(dist),
        }
    }

    #[test]
    fn direct_root_admits_at_distance_zero() {
        let candidate = claim("trust_grant", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 0,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn one_hop_chain_admits_at_distance_one() {
        // Candidate isn't a root, but the chain has a single entry
        // whose signer IS a root. Candidate distance = 1.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let root_witness = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            // Grant from root to candidate — bootstrap doesn't
            // require this grant to exist (the chain itself is
            // the evidence), but it's the realistic shape.
            grants: vec![grant("ROOT_PEER", "CANDIDATE_PEER", 0)],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![root_witness],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 1,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn chain_exhausted_returns_refuse_chain_exhausted() {
        // Candidate isn't a root; no chain entry's signer anchors
        // to a root or to a grant.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let stranger_a = claim("wholeness_witness", "STRANGER_A", 1);
        let stranger_b = claim("wholeness_witness", "STRANGER_B", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![stranger_a, stranger_b],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::ChainExhausted,
            }
        );
    }

    #[test]
    fn chain_longer_than_max_depth_returns_refuse_chain_too_long() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        // max_chain_depth = 2 but chain has 3 entries.
        let c1 = claim("wholeness_witness", "PEER_1", 1);
        let c2 = claim("wholeness_witness", "PEER_2", 1);
        let c3 = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 2,
        };
        let chain = WitnessChain {
            claims: vec![c1, c2, c3],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::ChainTooLong,
            }
        );
    }

    #[test]
    fn canonical_bytes_locked_field_order() {
        // Lock the canonical-bytes field order against accidental
        // reorder. Field order is asserted via two checks:
        //
        //   1. CANONICAL_FIELD_ORDER constant matches the doc.
        //   2. The byte layout puts each field at its documented
        //      offset.
        assert_eq!(
            SignedClaim::CANONICAL_FIELD_ORDER,
            &[
                "signed_at_unix_ms",
                "claim_version",
                "claim_kind",
                "signer_peer_id",
                "claim_bytes_hex",
                "user_owner",
                "delegates_to",
                "identity_occurrence",
            ]
        );

        let c = SignedClaim {
            claim_kind: "tg".into(),
            signer_peer_id: "P".into(),
            claim_bytes: vec![0xab, 0xcd],
            signed_at_unix_ms: 0x0011_2233_4455_6677,
            claim_version: 0x0102,
            user_owner: None,
            delegates_to: None,
            identity_occurrence: None,
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
            verified: true,
        };
        let bytes = c.canonical_value();

        // Domain sep — 16 bytes.
        assert_eq!(&bytes[..16], SignedClaim::DOMAIN_SEP);

        // signed_at_unix_ms — 8 bytes BE.
        assert_eq!(&bytes[16..24], &0x0011_2233_4455_6677_u64.to_be_bytes());

        // claim_version — 2 bytes BE.
        assert_eq!(&bytes[24..26], &0x0102_u16.to_be_bytes());

        // claim_kind — 4 byte BE u32 length + 2 bytes "tg".
        assert_eq!(&bytes[26..30], &2u32.to_be_bytes());
        assert_eq!(&bytes[30..32], b"tg");

        // signer_peer_id — 4 byte BE u32 length + 1 byte "P".
        assert_eq!(&bytes[32..36], &1u32.to_be_bytes());
        assert_eq!(&bytes[36..37], b"P");

        // claim_bytes_hex — 4 byte BE u32 length + 4 bytes
        // "abcd" (lowercase hex of [0xab, 0xcd]).
        assert_eq!(&bytes[37..41], &4u32.to_be_bytes());
        assert_eq!(&bytes[41..45], b"abcd");

        // Three owner-binding fields, all None → three 0x00 bytes.
        assert_eq!(&bytes[45..48], &[0x00, 0x00, 0x00]);

        // No trailing bytes.
        assert_eq!(bytes.len(), 48);
    }

    #[test]
    fn walks_chain_backwards() {
        // Chain ordering: [oldest, newer, newest]. Only the OLDEST
        // signer (index 0) is a root. Bootstrap walks newest →
        // oldest and anchors at index 0. The candidate's distance
        // therefore equals chain_len - 0 == 3.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let oldest = claim("wholeness_witness", "OLDEST_ROOT", 1);
        let newer = claim("wholeness_witness", "MID_PEER", 1);
        let newest = claim("wholeness_witness", "NEWEST_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["OLDEST_ROOT".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![oldest, newer, newest],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 3,
                anchored_to_root: "OLDEST_ROOT".to_string(),
            }
        );
    }

    // ─── Bonus invariant tests ───────────────────────────────────

    #[test]
    fn unverified_candidate_refused_signature_invalid() {
        let mut candidate = claim("trust_grant", "ROOT_PEER", 1);
        candidate.verified = false;
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::SignatureInvalid,
            }
        );
    }

    #[test]
    fn unverified_chain_entry_refused_signature_invalid() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let mut anchor = claim("wholeness_witness", "ROOT_PEER", 1);
        anchor.verified = false;
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![anchor],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::SignatureInvalid,
            }
        );
    }

    #[test]
    fn budget_exceeded_when_anchor_distance_plus_hops_overflows_depth() {
        // max_chain_depth = 2, chain length = 2 (passes ChainTooLong),
        // anchor at index 0 has chain_depth = 1 → total
        // distance = 1 + 2 = 3 > 2 → BudgetExceeded.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let mid = claim("wholeness_witness", "MID_PEER", 1);
        let granter = claim("wholeness_witness", "GRANTER_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            // GRANTER_PEER is at distance 1 from ROOT_PEER —
            // within max_chain_depth (2), so anchor_distance_for
            // returns Some(1). Adding 2 hops to candidate → 3.
            grants: vec![grant("GRANTER_PEER", "OTHER", 1)],
            max_chain_depth: 2,
        };
        let chain = WitnessChain {
            claims: vec![granter, mid],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::BudgetExceeded,
            }
        );
    }

    #[test]
    fn lowercase_hex_matches_documented_alphabet() {
        assert_eq!(lowercase_hex(&[]), "");
        assert_eq!(lowercase_hex(&[0x00]), "00");
        assert_eq!(lowercase_hex(&[0xff]), "ff");
        assert_eq!(lowercase_hex(&[0x0a, 0xbc, 0xde, 0xf0]), "0abcdef0");
    }

    /// F-5 (CIRISEdge#143): the in-process `verified` flag MUST be
    /// `#[serde(skip)]` so it can neither be emitted on the wire nor
    /// arrive over the wire pre-set to `true`. A wire-incoming claim
    /// asserting `"verified":true` MUST round-trip to `false`
    /// (fail-secure default).
    #[test]
    fn verified_flag_not_serialized() {
        let claim = claim("trust_grant", "PEER_A", 1);
        assert!(claim.verified, "fixture should start verified");

        let json = serde_json::to_string(&claim).expect("serialize");
        assert!(
            !json.contains("\"verified\""),
            "verified must not serialize, got: {json}"
        );

        // A wire-incoming JSON that tries to smuggle `verified:true`
        // must deserialize to `false` (the serde-skip default).
        let incoming = r#"{
            "claim_kind": "trust_grant",
            "signer_peer_id": "PEER_A",
            "claim_bytes": [222, 173, 190, 239],
            "signed_at_unix_ms": 1700000000000,
            "claim_version": 1,
            "user_owner": null,
            "delegates_to": null,
            "identity_occurrence": null,
            "signature_ed25519_base64": "ed25519-stub",
            "signature_ml_dsa_65_base64": "ml-dsa-65-stub",
            "verified": true
        }"#;
        let parsed: SignedClaim = serde_json::from_str(incoming).expect("parse");
        assert!(
            !parsed.verified,
            "verified must default to false from the wire"
        );
    }
    // ─── F-1 (CIRISEdge#143) — trust-serve / membership split ─────

    /// Build a grant with an explicit `weight` (for the §13.3 cap).
    #[allow(clippy::similar_names)]
    fn grant_w(granter: &str, grantee: &str, dist: u8, weight: u32) -> TrustGrant {
        TrustGrant {
            granter_peer_id: granter.to_string(),
            grantee_peer_id: grantee.to_string(),
            chain_depth: dist,
            granted_at_unix_ms: 1_700_000_000_000,
            weight,
        }
    }

    #[test]
    fn trust_serve_walk_succeeds_without_owner_binding() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        assert!(candidate.user_owner.is_none());
        let root_witness = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![root_witness],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 1,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn owner_binding_absent_yields_none() {
        // §19.2: a candidate with no owner-binding fields surfaces
        // nothing for the destination gate. This is NOT a refusal —
        // the chain walk and the membership gate are independent.
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        assert_eq!(extract_owner_binding_for_destination_gate(&candidate), None);
    }

    #[test]
    fn owner_binding_present_is_surfaced_without_chain_walk() {
        // §19.2: the projection surfaces the three owner-binding fields
        // off the candidate claim alone — no TrustGraph / WitnessChain
        // is consulted, because membership is the destination's gate,
        // never an output of the trust-graph walk.
        let candidate = owner_bound_claim("holding_claim", "CANDIDATE_PEER");
        assert_eq!(
            extract_owner_binding_for_destination_gate(&candidate),
            Some(OwnerBinding {
                user_owner: "USER_OWNER_PEER".to_string(),
                delegates_to: "CANDIDATE_PEER".to_string(),
                identity_occurrence: "CANDIDATE_PEER#occ-1".to_string(),
            })
        );
    }

    #[test]
    fn owner_binding_partial_yields_none() {
        // All three fields are required; a partial binding (a forged or
        // truncated claim) surfaces nothing rather than a half-binding.
        let mut candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        candidate.user_owner = Some("USER_OWNER_PEER".into());
        // delegates_to + identity_occurrence left None.
        assert_eq!(extract_owner_binding_for_destination_gate(&candidate), None);
    }

    #[test]
    fn chain_depth_5_admits() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let claims = vec![
            claim("wholeness_witness", "ROOT_PEER", 1),
            claim("wholeness_witness", "P1", 1),
            claim("wholeness_witness", "P2", 1),
            claim("wholeness_witness", "P3", 1),
            claim("wholeness_witness", "P4", 1),
        ];
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 5,
        };
        let chain = WitnessChain {
            claims,
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 5,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }

    #[test]
    fn chain_depth_6_refuses_chain_too_long() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let claims = vec![
            claim("wholeness_witness", "ROOT_PEER", 1),
            claim("wholeness_witness", "P1", 1),
            claim("wholeness_witness", "P2", 1),
            claim("wholeness_witness", "P3", 1),
            claim("wholeness_witness", "P4", 1),
            claim("wholeness_witness", "P5", 1),
        ];
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 255,
        };
        let chain = WitnessChain {
            claims,
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::ChainTooLong,
            }
        );
    }

    #[test]
    fn trust_graph_cycle_refuses() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let dup_a = claim("wholeness_witness", "DUP_PEER", 1);
        let dup_b = claim("wholeness_witness", "DUP_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 5,
        };
        let chain = WitnessChain {
            claims: vec![dup_a, dup_b],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::TrustGraphCycle,
            }
        );
    }

    #[test]
    fn aggregate_weight_cap_refuses() {
        let candidate = claim("holding_claim", "CANDIDATE_PEER", 1);
        let claims = vec![
            claim("wholeness_witness", "ROOT_PEER", 1),
            claim("wholeness_witness", "G3", 1),
            claim("wholeness_witness", "G2", 1),
            claim("wholeness_witness", "G1", 1),
        ];
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![
                grant_w("G1", "X", 1, 100),
                grant_w("G2", "X", 1, 100),
                grant_w("G3", "X", 1, 100),
            ],
            max_chain_depth: 5,
        };
        let chain = WitnessChain {
            claims,
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap_trust_serve(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::Refuse {
                reason: AdmissionRefusal::AggregateWeightCapExceeded,
            }
        );
    }

    #[test]
    fn canonical_bytes_includes_owner_binding_fields() {
        let bare = claim("holding_claim", "PEER", 1);
        let bound = owner_bound_claim("holding_claim", "PEER");

        let bare_bytes = bare.canonical_value();
        let bound_bytes = bound.canonical_value();

        assert_ne!(bare_bytes, bound_bytes);

        let tail = &bare_bytes[bare_bytes.len() - 3..];
        assert_eq!(tail, &[0x00, 0x00, 0x00]);

        assert!(
            bound_bytes
                .windows("USER_OWNER_PEER".len())
                .any(|w| w == b"USER_OWNER_PEER"),
            "user_owner value must be in the canonical bytes"
        );
        assert!(
            bound_bytes
                .windows("PEER#occ-1".len())
                .any(|w| w == b"PEER#occ-1"),
            "identity_occurrence value must be in the canonical bytes"
        );
    }

    #[test]
    #[allow(deprecated)]
    fn legacy_wrapper_returns_trust_serve() {
        let candidate = owner_bound_claim("holding_claim", "CANDIDATE_PEER");
        let root_witness = claim("wholeness_witness", "ROOT_PEER", 1);
        let graph = TrustGraph {
            roots: vec!["ROOT_PEER".into()],
            grants: vec![],
            max_chain_depth: 4,
        };
        let chain = WitnessChain {
            claims: vec![root_witness],
            chain_version: 1,
        };

        let verdict = recursive_trust_bootstrap(&candidate, &graph, &chain);
        assert_eq!(
            verdict,
            AdmissionVerdict::AdmitTrustServe {
                trust_distance: 1,
                anchored_to_root: "ROOT_PEER".to_string(),
            }
        );
    }
}
