//! Announce attestation — the authenticated transport-identity ↔
//! federation-key binding (CIRISEdge#15 / CIRISVerify#28 Phase 3).
//!
//! ## Why this exists (AV-42)
//!
//! A Reticulum destination is a **dedicated dual-key transport
//! identity** (`hash(x25519 ‖ ed25519)`), separate from the
//! federation Ed25519 signing key — the federation seed never enters
//! Leviculum (AV-17). v0.3.1's announce-driven discovery recorded
//! `key_id → destination` straight off the announce app-data:
//! trust-on-first-use. Any peer could announce `key_id=lens-steward`
//! paired with its own destination and intercept everything
//! `send("lens-steward", ..)` routes. That is **AV-42 — spoofed
//! transport-identity ↔ federation-key binding** (see
//! `docs/THREAT_MODEL.md` §4).
//!
//! ## The attestation
//!
//! The announce app-data carries an [`AnnounceAttestation`]: the
//! announcer's transport-identity pubkey, its federation `key_id`,
//! its federation Ed25519 pubkey, a rotation `epoch`, and a
//! **federation-key signature** over the canonical bytes of
//! `{transport_identity_pubkey, federation_key_id, epoch}`. The
//! signature is produced by the federation [`crate::LocalSigner`] —
//! the same Ed25519 key that signs federation envelopes — so it is
//! verifiable against the directory's `pubkey_ed25519_base64`.
//!
//! The binding becomes self-authenticating: the resolver roots the
//! federation key against persist's directory
//! (`root_binding`, CIRISPersist v1.12.0) and then verifies this
//! attestation signature against the now-directory-confirmed pubkey.
//! An announcer that does not hold `key_id`'s federation seed cannot
//! forge the signature; AV-42 closes.
//!
//! ## Canonical signing bytes (FSD §3.4)
//!
//! The signature covers [`AttestationPayload::canonical_bytes`] — a
//! deterministic, length-prefixed encoding of the three signed
//! fields. Length prefixes make the field boundaries unambiguous so
//! the encoding is injective (no two distinct field triples share a
//! byte string). The non-signed fields (`federation_pubkey_*`) are
//! verification *inputs*, not signed content — they are checked
//! against the directory, not trusted off the wire.

use serde::{Deserialize, Serialize};

/// Domain-separation tag prepended to the canonical signing bytes.
/// Distinguishes an announce-attestation signature from a federation
/// envelope signature so a signature lifted from one context cannot
/// be replayed into the other.
const ATTESTATION_DOMAIN: &[u8] = b"ciris-edge/announce-attestation/v1";

/// Domain for the **v2** payload that also binds the transport **x25519**
/// (encryption) half — CIRISEdge#317. Distinct from the v1 domain so a v1
/// signature can never be replayed as v2 (or vice versa): the two payload
/// shapes live in disjoint signature spaces.
const ATTESTATION_DOMAIN_V2: &[u8] = b"ciris-edge/announce-attestation/v2";

/// The three signed fields of an [`AnnounceAttestation`], in the
/// canonical order the signature covers.
///
/// Construct via [`AttestationPayload::new`]; the federation key
/// signs [`Self::canonical_bytes`], and the receiver re-derives the
/// same bytes from the announce to verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPayload<'a> {
    /// The announcer's 32-byte Reticulum transport-identity Ed25519
    /// public key (the ed25519 half of the dual-key identity — the
    /// half `ReticulumNode::connect` needs as the `signing_key`).
    pub transport_identity_pubkey: &'a [u8; 32],
    /// CIRISEdge#333 — the announcer's 32-byte transport-identity **x25519**
    /// (encryption) half. **SIGNED, never transmitted in `app_data`**: the
    /// announce packet already carries the full transport identity as its
    /// `public_key` (`x25519 ‖ ed25519`, binary — leviculum `announce.rs`
    /// `build_announce_payload`). A verifier reads both halves from
    /// `announce.public_key()` and re-derives this payload to check the
    /// signature. Binding by SIGNING OVER them (not re-sending them) is what
    /// keeps the app_data inside the MTU budget.
    pub transport_x25519_pubkey: Option<&'a [u8; 32]>,
    /// The announcer's federation `key_id` (`federation_keys.key_id`).
    pub federation_key_id: &'a str,
    /// The transport-identity rotation epoch. Monotonic per
    /// `federation_key_id`; an attestation for an older epoch than
    /// one already rooted is stale and the resolver ignores it.
    pub epoch: u64,
}

impl<'a> AttestationPayload<'a> {
    /// Construct a v1 payload from its three signed fields (no transport
    /// x25519). Use [`Self::with_transport_x25519`] to bind the x25519 half.
    #[must_use]
    pub fn new(
        transport_identity_pubkey: &'a [u8; 32],
        federation_key_id: &'a str,
        epoch: u64,
    ) -> Self {
        Self {
            transport_identity_pubkey,
            transport_x25519_pubkey: None,
            federation_key_id,
            epoch,
        }
    }

    /// CIRISEdge#317 — bind the transport **x25519** half, upgrading the payload
    /// to the v2 canonical shape (distinct signature domain).
    #[must_use]
    pub fn with_transport_x25519(mut self, transport_x25519_pubkey: &'a [u8; 32]) -> Self {
        self.transport_x25519_pubkey = Some(transport_x25519_pubkey);
        self
    }

    /// The exact bytes the federation key signs / a verifier checks.
    ///
    /// v1 layout (all integers big-endian):
    /// `DOMAIN ‖ len(ed25519) ‖ ed25519 ‖ len(key_id) ‖ key_id ‖ epoch`.
    ///
    /// v2 layout (when [`Self::transport_x25519_pubkey`] is set):
    /// `DOMAIN_V2 ‖ len(ed25519) ‖ ed25519 ‖ len(x25519) ‖ x25519 ‖ len(key_id) ‖ key_id ‖ epoch`.
    ///
    /// Length prefixes make each encoding injective; the distinct domain keeps
    /// v1 and v2 signatures in disjoint spaces.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let key_id = self.federation_key_id.as_bytes();
        // Length prefixes are `u64` big-endian — wide enough that the
        // `usize → u64` widening is lossless on every supported target.
        let ed_len = self.transport_identity_pubkey.len() as u64;
        let key_id_len = key_id.len() as u64;
        if let Some(x25519) = self.transport_x25519_pubkey {
            // v2 — binds the FULL transport identity (ed25519 + x25519).
            let x_len = x25519.len() as u64;
            let mut out = Vec::with_capacity(
                ATTESTATION_DOMAIN_V2.len() + 8 + 32 + 8 + 32 + 8 + key_id.len() + 8,
            );
            out.extend_from_slice(ATTESTATION_DOMAIN_V2);
            out.extend_from_slice(&ed_len.to_be_bytes());
            out.extend_from_slice(self.transport_identity_pubkey);
            out.extend_from_slice(&x_len.to_be_bytes());
            out.extend_from_slice(x25519);
            out.extend_from_slice(&key_id_len.to_be_bytes());
            out.extend_from_slice(key_id);
            out.extend_from_slice(&self.epoch.to_be_bytes());
            out
        } else {
            // v1 — transport ed25519 only (unchanged).
            let mut out =
                Vec::with_capacity(ATTESTATION_DOMAIN.len() + 8 + 32 + 8 + key_id.len() + 8);
            out.extend_from_slice(ATTESTATION_DOMAIN);
            out.extend_from_slice(&ed_len.to_be_bytes());
            out.extend_from_slice(self.transport_identity_pubkey);
            out.extend_from_slice(&key_id_len.to_be_bytes());
            out.extend_from_slice(key_id);
            out.extend_from_slice(&self.epoch.to_be_bytes());
            out
        }
    }
}

/// A federation-key-signed transport-identity binding, carried in the
/// Reticulum announce app-data.
///
/// The wire form is JSON (the announce app-data is an opaque byte
/// blob; JSON keeps it inspectable and forward-compatible). All byte
/// fields are base64-standard.
///
/// # Authentication
///
/// `signature` is **not** trusted on its own — it proves only that
/// whoever holds `federation_key_id`'s Ed25519 seed signed this
/// `(transport_identity_pubkey, federation_key_id, epoch)` triple.
/// The resolver still roots `federation_key_id` against the persist
/// directory (`root_binding`) and verifies `signature` against the
/// **directory-confirmed** pubkey — never against the
/// `federation_pubkey_ed25519_base64` carried here, which is a
/// claim. See [`crate::transport::reticulum`]'s cold-start path.
/// CIRISEdge#205 (CIRISVerify#28 Phase 4 / AV-42) — the enforcement
/// posture for the RNS §5.6.8.8.1.1 destination-hash consistency check on
/// the announce cold-start path. The federation binding (`key_id →
/// transport identity`) is ALWAYS enforced via `root_binding` + the
/// attestation signature; this knob governs the *additional* check that
/// the announce's own `destination_hash` recomputes from its identity
/// pubkeys (`ReceivedAnnounce::verify_destination_hash`).
///
/// **`Advisory` MUST be the default.** The flip to `RequireTransportBinding`
/// is a **dated fleet-floor coordination event** (CIRISVerify#28 Phase 4):
/// every federation repo must emit conformant transport bindings before
/// Edge enforces, or authentic peers get dropped. This is NOT a silent
/// default change — operators opt in once the floor is met. Mirrors the
/// [`crate::cohort_scope::CohortScopeEnforcement`] staged-rollout discipline.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TransportBindingEnforcement {
    /// Tolerate a missing/mismatched destination-hash binding — admit the
    /// announce (records the claimed hash). **The default** — current
    /// v-series behavior, no silent change.
    #[default]
    Advisory,
    /// Log a `tracing::warn!` on mismatch but still admit — migration aid
    /// while the fleet floor rolls out.
    WarnOnly,
    /// Drop an announce whose `destination_hash` does not recompute from
    /// its identity pubkeys — fail-secure (AV-42). The Phase-4 target,
    /// enabled only after the dated fleet-floor coordination event.
    RequireTransportBinding,
}

impl TransportBindingEnforcement {
    /// Stable string-token for telemetry.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::WarnOnly => "warn_only",
            Self::RequireTransportBinding => "require_transport_binding",
        }
    }
}

/// CIRISEdge#333 — the hard app_data budget an announce must fit inside.
///
/// From leviculum's own constants (`reticulum-core::constants`) and
/// `build_announce_payload`'s layout
/// (`public_key(64) ‖ name_hash(10) ‖ random_hash(10) ‖ [ratchet(32)] ‖
/// signature(64) ‖ app_data`):
///
/// ```text
/// MTU                                 500
///   − HEADER_MINSIZE (2 + 1 + 16)     −19
///   − IFAC_MIN_SIZE                    −1
///   − public_key (x25519 ‖ ed25519)   −64
///   − name_hash                       −10
///   − random_hash                     −10
///   − ratchet                         −32
///   − signature                       −64
/// ───────────────────────────────────────
///   app_data budget                   300
/// ```
///
/// `Node::announce_destination` packs into a fixed `[0u8; MTU]` buffer, so an
/// oversized `app_data` makes `pack()` fail and the announce **never leaves the
/// box** — the node becomes invisible to the mesh while looking healthy locally.
/// The pre-#333 JSON attestation was 337 B (410 B once #317 added the x25519
/// field): it had **never** fit, which is the root cause of the whole AV-42
/// rooting saga (no attested announce ever propagated an RNS path).
///
/// The value is **not** hardcoded here — it is leviculum's own derived budget
/// (`MTU − IFAC − header − fixed_payload`), pulled from the source of truth so
/// it cannot silently rot if leviculum changes a header size or the ratchet
/// default. `with_ratchet = true`: edge announces are ratcheted, whose fixed
/// payload (180 B) is larger than the un-ratcheted case, so 300 B (not 332 B) is
/// the value a smaller-fits-so-does-larger argument does NOT get to assume.
/// (leviculum#22 / v0.9.0+ciris.1 exported this; before, edge duplicated `300`.)
pub const ANNOUNCE_APP_DATA_BUDGET: usize = leviculum_core::announce_app_data_budget(true);

/// The binary wire tag for [`AnnounceAttestation::to_app_data`]. A version byte
/// so a future shape is distinguishable rather than mis-parsed.
const ATTESTATION_WIRE_V1: u8 = 0x01;

/// CIRISEdge#436 — the wire tag for a commitment-bearing attestation: the v1
/// layout with a 32-byte [`manifest commitment`](AnnounceAttestation::manifest_commitment)
/// appended after the signature. A DISTINCT version byte (the type's own
/// convention: a new shape must be distinguishable, never mis-parsed): a
/// pre-#436 parser refuses `0x02` with its typed unknown-version error — the
/// same clean refusal it gives any non-CIRIS announce — while an
/// absent-commitment announce still packs as `0x01`, byte-identical to today.
const ATTESTATION_WIRE_V2: u8 = 0x02;

/// Fixed overhead of the packed attestation, excluding `federation_key_id`:
/// `version(1) ‖ key_id_len(1) ‖ federation_pubkey(32) ‖ epoch(8) ‖ signature(64)`.
const ATTESTATION_FIXED_OVERHEAD: usize = 1 + 1 + 32 + 8 + 64;

/// CIRISEdge#436 — byte length of the optional manifest commitment
/// (`sha256(JCS(manifest_contribution))`, see
/// [`crate::bundle_gate::manifest_commitment_of_bundle`]).
pub const MANIFEST_COMMITMENT_LEN: usize = 32;

/// CIRISEdge#436 — fixed overhead of the v2 (commitment-bearing) wire shape.
const ATTESTATION_V2_FIXED_OVERHEAD: usize = ATTESTATION_FIXED_OVERHEAD + MANIFEST_COMMITMENT_LEN;

/// CIRISEdge#333 — the longest `federation_key_id` that can appear in an
/// announce. Derived, not chosen: it is whatever [`ANNOUNCE_APP_DATA_BUDGET`]
/// leaves after the fixed overhead. A longer key_id cannot be announced at all
/// (the packet would exceed the MTU and never transmit), so it is refused at
/// compose time instead. Real key_ids are ~20–45 B; this is a wide margin.
pub const MAX_FEDERATION_KEY_ID_LEN: usize = ANNOUNCE_APP_DATA_BUDGET - ATTESTATION_FIXED_OVERHEAD;

/// CIRISEdge#436 — the longest `federation_key_id` a COMMITMENT-BEARING
/// announce can carry: the commitment's 32 bytes come out of the same hard
/// app_data budget, so the bound shrinks by exactly
/// [`MANIFEST_COMMITMENT_LEN`]. Still a wide margin over real ~20–45 B key_ids.
pub const MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT: usize =
    ANNOUNCE_APP_DATA_BUDGET - ATTESTATION_V2_FIXED_OVERHEAD;

// The load-bearing invariant, checked AT COMPILE TIME: the worst admissible
// attestation fits the announce budget. Add a field to the wire shape without
// shrinking the key_id bound and THIS fails the build — which is the whole point
// of CIRISEdge#333 (the old shape failed silently, on the wire, at runtime).
const _: () = assert!(
    ATTESTATION_FIXED_OVERHEAD + MAX_FEDERATION_KEY_ID_LEN <= ANNOUNCE_APP_DATA_BUDGET,
    "the worst-case announce attestation must fit ANNOUNCE_APP_DATA_BUDGET"
);

// CIRISEdge#436 — the same compile-time gate for the commitment-bearing shape:
// the worst admissible v2 attestation fits the budget too.
const _: () = assert!(
    ATTESTATION_V2_FIXED_OVERHEAD + MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT
        <= ANNOUNCE_APP_DATA_BUDGET,
    "the worst-case commitment-bearing announce attestation must fit ANNOUNCE_APP_DATA_BUDGET"
);

/// A federation-key-signed transport-identity binding, carried in the Reticulum
/// announce app-data.
///
/// # Wire form: BINARY, and it does NOT carry the transport pubkeys
///
/// ```text
/// u8(version=1) ‖ u8(len key_id) ‖ key_id ‖ federation_pubkey_ed25519(32)
///               ‖ u64_be(epoch) ‖ signature(64)
/// ```
///
/// CIRISEdge#436 — when [`Self::manifest_commitment`] is `Some`, the version
/// byte is `2` and the 32-byte commitment is appended after the signature:
///
/// ```text
/// u8(version=2) ‖ … v1 fields … ‖ manifest_commitment(32)
/// ```
///
/// Absent-commitment announces stay **byte-identical** to the pre-#436 wire
/// (version `1`), both directions: an old peer parses them unchanged, and this
/// parser accepts old announces unchanged. A commitment-bearing announce is a
/// NEW shape by design — an old peer refuses it with its typed
/// unknown-version parse error (the same clean refusal any non-CIRIS announce
/// gets), which is why announcing a commitment is strictly opt-in (only a node
/// with its own build bundle configured emits one).
///
/// Two deliberate choices, both forced by [`ANNOUNCE_APP_DATA_BUDGET`]:
///
/// 1. **The transport pubkeys are NOT in `app_data`.** The announce packet
///    already transmits them, in binary, as its own `public_key` (64 B). The
///    old JSON shape re-encoded those same bytes as base64 — ~140 B of pure
///    duplication, *more* than the 104 B by which it overflowed. They are still
///    **bound**: the signature covers them ([`AttestationPayload`]); a verifier
///    supplies them from `announce.public_key()`.
/// 2. **Binary, not JSON.** JSON key names alone cost ~110 B of a 300 B budget.
///    A broadcast primitive under a hard MTU is the wrong place for a
///    self-describing format. This shape is ~150 B, leaving real headroom.
///
/// # Authentication
///
/// `signature` is **not** trusted on its own — it proves only that whoever holds
/// `federation_key_id`'s Ed25519 seed signed the
/// `(transport identity, federation_key_id, epoch)` binding. The resolver still
/// roots `federation_key_id` against the persist directory (`root_binding`) and
/// verifies the signature against the **directory-confirmed** pubkey — never
/// against the `federation_pubkey_ed25519` carried here, which is a claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnounceAttestation {
    /// The announcer's federation `key_id`.
    pub federation_key_id: String,
    /// The announcer's *claimed* federation Ed25519 public key (32 B). A
    /// verification input rooted against the directory — never trusted as-is.
    pub federation_pubkey_ed25519: [u8; 32],
    /// Transport-identity rotation epoch.
    pub epoch: u64,
    /// Ed25519 signature by the federation key over
    /// [`AttestationPayload::canonical_bytes`] (which covers the transport
    /// identity read from the announce's own `public_key`).
    pub signature: [u8; 64],
    /// CIRISEdge#436 — OPTIONAL 32-byte **manifest commitment**:
    /// `sha256(JCS(manifest_contribution))` of the announcer's own
    /// build-attestation bundle
    /// ([`crate::bundle_gate::manifest_commitment_of_bundle`] — the same
    /// canonical preimage the bundle's producer signs internally). The
    /// commitment BINDS the announce to the link-borne package: a received
    /// bundle upgrades this peer Advisory→Rooted only if its manifest hashes
    /// to exactly this value AND the full CIRISVerify#181 chain verifies.
    ///
    /// Deliberately NOT covered by the attestation's federation-key
    /// signature: third-party integrity already rides the RNS announce
    /// signature (leviculum validates the announce's own signature over its
    /// `app_data` before surfacing it), the announcer IS the presenter (a
    /// self-signed field adds nothing against it), and keeping the signed
    /// payload unchanged means no third signature domain — a v2 announce
    /// verifies with the exact same canonical bytes as v1. Trust NEVER flows
    /// from this field alone: a stripped/altered commitment can only make the
    /// package refuse (fail-closed), never widen anything.
    pub manifest_commitment: Option<[u8; MANIFEST_COMMITMENT_LEN]>,
}

/// Errors decoding / verifying an [`AnnounceAttestation`].
#[derive(thiserror::Error, Debug)]
pub enum AttestationError {
    /// The announce app-data was not valid attestation JSON.
    #[error("attestation parse: {0}")]
    Parse(String),
    /// A base64 field did not decode, or decoded to the wrong length.
    #[error("attestation field decode: {0}")]
    FieldDecode(String),
    /// The Ed25519 signature did not verify against the federation
    /// pubkey. AV-42 — a spoofed binding fails here.
    #[error("attestation signature verification failed")]
    SignatureMismatch,
    /// CIRISEdge#333 — the packed attestation exceeds the announce app_data
    /// budget. Refused at COMPOSE time: an oversized announce silently fails to
    /// transmit (leviculum packs into a fixed `[0u8; MTU]`), leaving the node
    /// invisible to the mesh while it looks healthy locally.
    #[error("attestation is {actual} B; the announce app_data budget is {budget} B")]
    TooLarge { actual: usize, budget: usize },
}

impl AnnounceAttestation {
    /// Serialize to announce app-data bytes (BINARY — see the type docs).
    ///
    /// # Errors
    /// [`AttestationError::Parse`] if `federation_key_id` exceeds 255 bytes, or
    /// if the packed form would exceed [`ANNOUNCE_APP_DATA_BUDGET`] — the latter
    /// is the CIRISEdge#333 compose-time gate: an announce that cannot fit is
    /// refused HERE, loudly, rather than silently failing to transmit and making
    /// the node invisible to the mesh.
    pub fn to_app_data(&self) -> Result<Vec<u8>, AttestationError> {
        let key_id = self.federation_key_id.as_bytes();
        // CIRISEdge#436 — the commitment's 32 bytes come out of the same hard
        // budget, so a commitment-bearing attestation gets the tighter key_id
        // bound. Absent commitment ⇒ the pre-#436 bound and wire, byte-identical.
        let (fixed_overhead, max_key_id) = if self.manifest_commitment.is_some() {
            (
                ATTESTATION_V2_FIXED_OVERHEAD,
                MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT,
            )
        } else {
            (ATTESTATION_FIXED_OVERHEAD, MAX_FEDERATION_KEY_ID_LEN)
        };
        if key_id.len() > max_key_id {
            return Err(AttestationError::TooLarge {
                actual: fixed_overhead + key_id.len(),
                budget: ANNOUNCE_APP_DATA_BUDGET,
            });
        }
        let key_id_len = u8::try_from(key_id.len())
            .map_err(|_| AttestationError::Parse("federation_key_id too long".to_string()))?;
        let mut out = Vec::with_capacity(fixed_overhead + key_id.len());
        out.push(if self.manifest_commitment.is_some() {
            ATTESTATION_WIRE_V2
        } else {
            ATTESTATION_WIRE_V1
        });
        out.push(key_id_len);
        out.extend_from_slice(key_id);
        out.extend_from_slice(&self.federation_pubkey_ed25519);
        out.extend_from_slice(&self.epoch.to_be_bytes());
        out.extend_from_slice(&self.signature);
        if let Some(commitment) = &self.manifest_commitment {
            out.extend_from_slice(commitment);
        }

        if out.len() > ANNOUNCE_APP_DATA_BUDGET {
            return Err(AttestationError::TooLarge {
                actual: out.len(),
                budget: ANNOUNCE_APP_DATA_BUDGET,
            });
        }
        Ok(out)
    }

    /// Parse an [`AnnounceAttestation`] from announce app-data bytes.
    ///
    /// # Errors
    /// [`AttestationError::Parse`] when `app_data` is not a well-formed
    /// attestation — e.g. an empty (unattested) announce, a legacy JSON
    /// attestation, or a non-CIRIS app's announce.
    pub fn from_app_data(app_data: &[u8]) -> Result<Self, AttestationError> {
        let bad = |m: &str| AttestationError::Parse(m.to_string());
        if app_data.len() < 2 {
            return Err(bad("attestation too short"));
        }
        // CIRISEdge#436 — v1 (no commitment, the pre-#436 wire, accepted
        // unchanged) or v2 (v1 + a trailing 32-byte manifest commitment).
        let commitment_present = match app_data[0] {
            ATTESTATION_WIRE_V1 => false,
            ATTESTATION_WIRE_V2 => true,
            other => {
                return Err(AttestationError::Parse(format!(
                    "unknown attestation wire version {other:#04x}"
                )));
            }
        };
        let key_id_len = app_data[1] as usize;
        let want = 2
            + key_id_len
            + 32
            + 8
            + 64
            + if commitment_present {
                MANIFEST_COMMITMENT_LEN
            } else {
                0
            };
        if app_data.len() != want {
            return Err(AttestationError::Parse(format!(
                "attestation length {} != expected {want}",
                app_data.len()
            )));
        }
        let mut off = 2;
        let federation_key_id = std::str::from_utf8(&app_data[off..off + key_id_len])
            .map_err(|e| AttestationError::Parse(format!("key_id not utf-8: {e}")))?
            .to_string();
        off += key_id_len;
        let federation_pubkey_ed25519: [u8; 32] = app_data[off..off + 32]
            .try_into()
            .map_err(|_| bad("federation pubkey"))?;
        off += 32;
        let epoch = u64::from_be_bytes(
            app_data[off..off + 8]
                .try_into()
                .map_err(|_| bad("epoch"))?,
        );
        off += 8;
        let signature: [u8; 64] = app_data[off..off + 64]
            .try_into()
            .map_err(|_| bad("signature"))?;
        off += 64;
        let manifest_commitment = if commitment_present {
            Some(
                app_data[off..off + MANIFEST_COMMITMENT_LEN]
                    .try_into()
                    .map_err(|_| bad("manifest commitment"))?,
            )
        } else {
            None
        };
        Ok(Self {
            federation_key_id,
            federation_pubkey_ed25519,
            epoch,
            signature,
            manifest_commitment,
        })
    }

    /// Verify [`Self::signature`] over the canonical attestation bytes against
    /// `federation_pubkey_ed25519` — the **32-byte Ed25519 public key the persist
    /// directory confirmed** for `federation_key_id`, never the claim carried on
    /// the wire.
    ///
    /// CIRISEdge#333: `announce_public_key` is the announce's OWN
    /// `public_key` — the transport identity, `x25519(32) ‖ ed25519(32)` (see
    /// leviculum `build_announce_payload`). The attestation no longer transmits
    /// those bytes; it BINDS them, and the verifier supplies them from the packet
    /// it just received. A spoofer cannot pair someone else's `key_id` with its
    /// own destination: the signature covers the transport identity the packet
    /// arrived with (AV-42).
    ///
    /// # Errors
    /// - [`AttestationError::SignatureMismatch`] — the signature did not verify.
    /// - [`AttestationError::FieldDecode`] — the Ed25519 verify call failed.
    pub fn verify_signature(
        &self,
        federation_pubkey_ed25519: &[u8; 32],
        announce_public_key: &[u8; 64],
    ) -> Result<(), AttestationError> {
        use ciris_crypto::ClassicalVerifier;

        // leviculum `Identity::public_key_bytes()` = x25519 ‖ ed25519.
        let x25519: [u8; 32] = announce_public_key[..32]
            .try_into()
            .map_err(|_| AttestationError::FieldDecode("announce x25519 half".into()))?;
        let ed25519: [u8; 32] = announce_public_key[32..]
            .try_into()
            .map_err(|_| AttestationError::FieldDecode("announce ed25519 half".into()))?;

        let canonical = AttestationPayload::new(&ed25519, &self.federation_key_id, self.epoch)
            .with_transport_x25519(&x25519)
            .canonical_bytes();

        let verified = ciris_crypto::Ed25519Verifier::new()
            .verify(federation_pubkey_ed25519, &canonical, &self.signature)
            .map_err(|e| AttestationError::FieldDecode(format!("ed25519 verify: {e}")))?;

        if verified {
            Ok(())
        } else {
            Err(AttestationError::SignatureMismatch)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciris_crypto::ClassicalSigner;

    /// The static worst-case gate: even a max-length (255 B) federation key_id
    /// packs inside the announce app_data budget. This is the CIRISEdge#333
    /// guarantee — *adding a field must fail the build/tests, not the mesh*.
    #[test]
    fn worst_case_attestation_fits_the_announce_budget() {
        // The MAXIMUM admissible key_id must pack inside the budget — this is the
        // compile-time invariant, re-asserted at runtime against the real packer.
        let att = AnnounceAttestation {
            federation_key_id: "k".repeat(MAX_FEDERATION_KEY_ID_LEN),
            federation_pubkey_ed25519: [0; 32],
            epoch: u64::MAX,
            signature: [0; 64],
            manifest_commitment: None,
        };
        let packed = att.to_app_data().expect("worst case must fit");
        assert_eq!(packed.len(), ANNOUNCE_APP_DATA_BUDGET);
    }

    /// CIRISEdge#436 — the SAME static gate for the commitment-bearing shape:
    /// the maximum admissible v2 attestation (max key_id + 32 B commitment)
    /// packs exactly at the announce budget — headroom proven against the real
    /// packer, not assumed from the v1 case.
    #[test]
    fn worst_case_commitment_bearing_attestation_fits_the_announce_budget() {
        let att = AnnounceAttestation {
            federation_key_id: "k".repeat(MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT),
            federation_pubkey_ed25519: [0; 32],
            epoch: u64::MAX,
            signature: [0; 64],
            manifest_commitment: Some([0xC0; 32]),
        };
        let packed = att.to_app_data().expect("worst v2 case must fit");
        assert_eq!(packed.len(), ANNOUNCE_APP_DATA_BUDGET);
        // The bound is exactly 32 B tighter than v1 — the commitment's cost.
        assert_eq!(
            MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT,
            MAX_FEDERATION_KEY_ID_LEN - MANIFEST_COMMITMENT_LEN
        );
    }

    /// A realistic attestation is far inside budget (the old JSON shape was
    /// 337 B — 410 B once #317 added the x25519 field — against a 300 B budget,
    /// so it had NEVER fit).
    #[test]
    fn realistic_attestation_is_well_inside_budget() {
        let att = AnnounceAttestation {
            federation_key_id: "ciris-agent-bootstrap-vroaxowlhv-rktt5f5yyv".to_string(),
            federation_pubkey_ed25519: [0x11; 32],
            epoch: 7,
            signature: [0x22; 64],
            manifest_commitment: None,
        };
        let packed = att.to_app_data().expect("must fit");
        assert!(
            packed.len() <= ANNOUNCE_APP_DATA_BUDGET,
            "packed {} B > budget {ANNOUNCE_APP_DATA_BUDGET} B",
            packed.len()
        );
        // Real headroom, not a squeaker.
        assert!(packed.len() < 200, "expected ~150 B, got {}", packed.len());

        // CIRISEdge#436 — the same realistic attestation WITH a commitment:
        // +32 B, still deep inside the 300 B budget (headroom proof).
        let with_commitment = AnnounceAttestation {
            manifest_commitment: Some([0xAB; 32]),
            ..att
        };
        let packed_v2 = with_commitment.to_app_data().expect("v2 must fit");
        assert_eq!(packed_v2.len(), packed.len() + MANIFEST_COMMITMENT_LEN);
        assert!(
            packed_v2.len() < 232,
            "expected ~181 B, got {}",
            packed_v2.len()
        );
        assert!(packed_v2.len() <= ANNOUNCE_APP_DATA_BUDGET);
    }

    /// An over-budget attestation is refused at COMPOSE time — loudly — rather
    /// than silently failing to transmit.
    #[test]
    fn over_budget_attestation_is_refused_at_compose_time() {
        // One byte past the bound: refused HERE, loudly — never silently
        // transmitted-and-dropped (which is what made the node invisible).
        let att = AnnounceAttestation {
            federation_key_id: "k".repeat(MAX_FEDERATION_KEY_ID_LEN + 1),
            federation_pubkey_ed25519: [0; 32],
            epoch: 0,
            signature: [0; 64],
            manifest_commitment: None,
        };
        assert!(matches!(
            att.to_app_data(),
            Err(AttestationError::TooLarge { .. })
        ));

        // CIRISEdge#436 — the v2 bound is enforced too: a key_id that fits v1
        // but is one byte past the COMMITMENT-bearing bound refuses at compose
        // time the moment a commitment is attached (never a silent
        // over-budget announce that fails to transmit).
        let v2_over = AnnounceAttestation {
            federation_key_id: "k".repeat(MAX_FEDERATION_KEY_ID_LEN_WITH_COMMITMENT + 1),
            federation_pubkey_ed25519: [0; 32],
            epoch: 0,
            signature: [0; 64],
            manifest_commitment: Some([0; 32]),
        };
        assert!(matches!(
            v2_over.to_app_data(),
            Err(AttestationError::TooLarge { .. })
        ));
        // Sanity: the SAME key_id without the commitment still fits (the
        // refusal above is the commitment's 32 B, nothing else).
        let v1_same = AnnounceAttestation {
            manifest_commitment: None,
            ..v2_over
        };
        assert!(v1_same.to_app_data().is_ok());
    }

    /// CIRISEdge#436 wire-compat, BOTH directions.
    ///
    /// Direction 1 (old parses new): an ABSENT commitment packs byte-identical
    /// to the pre-#436 v1 wire — asserted against a hand-built v1 layout (the
    /// old encoder's spec), so a pre-#436 peer parses a new node's default
    /// announce unchanged.
    ///
    /// Direction 2 (new parses old): a hand-built v1 blob (what an old peer
    /// emits) parses to `manifest_commitment: None` — today's shape untouched.
    ///
    /// And the v2 shape round-trips with its commitment intact.
    #[test]
    fn wire_compat_absent_commitment_is_byte_identical_and_v2_round_trips() {
        let key_id = "edge-key-compat";
        let att = AnnounceAttestation {
            federation_key_id: key_id.to_string(),
            federation_pubkey_ed25519: [0x33; 32],
            epoch: 9,
            signature: [0x44; 64],
            manifest_commitment: None,
        };

        // The pre-#436 v1 layout, built by hand:
        // version(1)=0x01 ‖ len ‖ key_id ‖ pubkey(32) ‖ epoch(8) ‖ sig(64).
        let mut expected = vec![0x01u8, u8::try_from(key_id.len()).unwrap()];
        expected.extend_from_slice(key_id.as_bytes());
        expected.extend_from_slice(&[0x33; 32]);
        expected.extend_from_slice(&9u64.to_be_bytes());
        expected.extend_from_slice(&[0x44; 64]);

        // Direction 1: byte-identical to the old wire.
        assert_eq!(att.to_app_data().unwrap(), expected);

        // Direction 2: the old wire parses to the None-commitment shape.
        let parsed = AnnounceAttestation::from_app_data(&expected).unwrap();
        assert_eq!(parsed, att);
        assert_eq!(parsed.manifest_commitment, None);

        // v2 round-trip: commitment survives, version byte is 0x02, and the
        // body is the v1 bytes + the trailing 32.
        let commitment = [0x5A; 32];
        let v2 = AnnounceAttestation {
            manifest_commitment: Some(commitment),
            ..att.clone()
        };
        let packed = v2.to_app_data().unwrap();
        assert_eq!(packed[0], 0x02);
        assert_eq!(&packed[1..packed.len() - 32], &expected[1..]);
        assert_eq!(&packed[packed.len() - 32..], &commitment);
        assert_eq!(AnnounceAttestation::from_app_data(&packed).unwrap(), v2);

        // A TRUNCATED v2 (commitment declared by the version byte but bytes
        // missing) refuses with a typed length error — never mis-parses as v1.
        assert!(matches!(
            AnnounceAttestation::from_app_data(&packed[..packed.len() - 1]),
            Err(AttestationError::Parse(_))
        ));
    }

    /// Round-trip + AV-42: the signature binds the transport identity the packet
    /// ARRIVED with, even though the attestation never transmits it. A spoofer
    /// pairing someone else's key_id with its own destination fails.
    #[test]
    fn binds_the_announce_transport_identity_without_transmitting_it() {
        let signer = ciris_crypto::Ed25519Signer::random().unwrap();
        let fed_pubkey: [u8; 32] = signer.public_key().unwrap().try_into().unwrap();

        // The announce's own public_key = transport identity (x25519 ‖ ed25519).
        let mut announce_pk = [0u8; 64];
        announce_pk[..32].copy_from_slice(&[0xAA; 32]); // x25519
        announce_pk[32..].copy_from_slice(&[0xBB; 32]); // ed25519

        let x: [u8; 32] = announce_pk[..32].try_into().unwrap();
        let e: [u8; 32] = announce_pk[32..].try_into().unwrap();
        let payload = AttestationPayload::new(&e, "edge-key-honest", 7).with_transport_x25519(&x);
        let sig: [u8; 64] = signer
            .sign(&payload.canonical_bytes())
            .unwrap()
            .try_into()
            .unwrap();

        let att = AnnounceAttestation {
            federation_key_id: "edge-key-honest".to_string(),
            federation_pubkey_ed25519: fed_pubkey,
            epoch: 7,
            signature: sig,
            manifest_commitment: None,
        };

        // Binary round-trip.
        let parsed = AnnounceAttestation::from_app_data(&att.to_app_data().unwrap()).unwrap();
        assert_eq!(parsed, att);

        // Verifies against the identity the packet carried.
        parsed.verify_signature(&fed_pubkey, &announce_pk).unwrap();

        // CIRISEdge#436 — the manifest commitment is NOT in the signed
        // payload (no third signature domain): the SAME signature verifies
        // with a commitment attached. Integrity of the commitment rides the
        // RNS announce signature; trust never flows from the field alone.
        let with_commitment = AnnounceAttestation {
            manifest_commitment: Some([0x77; 32]),
            ..parsed.clone()
        };
        let v2_parsed =
            AnnounceAttestation::from_app_data(&with_commitment.to_app_data().unwrap()).unwrap();
        v2_parsed
            .verify_signature(&fed_pubkey, &announce_pk)
            .unwrap();

        // AV-42: a spoofer replays this attestation on ITS OWN destination — the
        // announce's public_key differs, so the bound signature fails.
        let mut spoof_pk = announce_pk;
        spoof_pk[32..].copy_from_slice(&[0xCC; 32]); // attacker's transport ed25519
        assert!(matches!(
            parsed.verify_signature(&fed_pubkey, &spoof_pk),
            Err(AttestationError::SignatureMismatch)
        ));

        // AV-42: a spoofed key_id fails (signed content differs).
        let mut spoofed = parsed.clone();
        spoofed.federation_key_id = "edge-key-victim".to_string();
        assert!(matches!(
            spoofed.verify_signature(&fed_pubkey, &announce_pk),
            Err(AttestationError::SignatureMismatch)
        ));
    }

    /// An unattested (empty app_data) or legacy-JSON announce parses to a typed
    /// error, not a panic.
    #[test]
    fn empty_or_legacy_app_data_is_rejected_cleanly() {
        assert!(matches!(
            AnnounceAttestation::from_app_data(b""),
            Err(AttestationError::Parse(_))
        ));
        assert!(matches!(
            AnnounceAttestation::from_app_data(br#"{"federation_key_id":"x"}"#),
            Err(AttestationError::Parse(_))
        ));
    }

    #[test]
    fn transport_binding_enforcement_default_is_advisory() {
        assert_eq!(
            TransportBindingEnforcement::default(),
            TransportBindingEnforcement::Advisory
        );
    }

    #[test]
    fn transport_binding_enforcement_serde_and_token_round_trip() {
        for (variant, token) in [
            (TransportBindingEnforcement::Advisory, "advisory"),
            (TransportBindingEnforcement::WarnOnly, "warn_only"),
            (
                TransportBindingEnforcement::RequireTransportBinding,
                "require_transport_binding",
            ),
        ] {
            assert_eq!(variant.as_str(), token);
            let json = serde_json::to_string(&variant).unwrap();
            assert_eq!(json, format!("\"{token}\""));
            let back: TransportBindingEnforcement = serde_json::from_str(&json).unwrap();
            assert_eq!(back, variant);
        }
    }
}
