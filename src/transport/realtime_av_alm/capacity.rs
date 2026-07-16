//! ALM-A — signed [`RelayCapacity`] advertisement primitive
//! (CIRISEdge v3.8.0, PR #131 follow-up + CIRISEdge#128 MDC extension).
//!
//! ## What this module is
//!
//! The data type peers publish to declare their relay willingness +
//! sustained uplink budget for application-layer multicast (mesh-tree
//! video). The advertisement is **signed** by the advertiser using the
//! hybrid Ed25519 + ML-DSA-65 federation key bundle (same shape as
//! [`crate::identity::sign_envelope`]) — without that, a malicious peer
//! could claim infinite capacity to attract subscribers and grief the
//! tree topology.
//!
//! ## What the type means
//!
//! A [`RelayCapacity`] is a *measurement* — `uplink_mbps` is sustained
//! observed throughput over the trailing [`MEASUREMENT_WINDOW_SECS`],
//! NOT a paper-spec maximum. Peers re-mint the advertisement at least
//! once per [`STALE_AFTER_SECS`] (the receiver-side gate);
//! receivers treat older advertisements as withdrawn.
//!
//! ## HNDL discipline
//!
//! The signature MUST be hybrid (Ed25519 + ML-DSA-65) — never
//! classical-only. The v3.7.0 substrate's `LocalSigner` already does
//! this: [`crate::identity::sign_envelope`] signs Ed25519 over
//! canonical bytes AND ML-DSA-65 over `canonical || ed25519_sig` (the
//! AV-33 bound-signature pattern that prevents stripping). ALM-A reuses
//! the same shape via [`SignedRelayCapacity::sign`] taking a
//! `&LocalSigner` — see § "Signer choice" below.
//!
//! ## Signer choice — no project-wide async trait, so we plumb to
//! [`LocalSigner`] directly
//!
//! `ciris-crypto` exports a generic `HybridSigner<C, P>` struct, but
//! its `ClassicalSigner` + `PqcSigner` traits are **sync** and don't
//! match the project's hardware-backed signers
//! (`ciris-keyring::HardwareSigner` is **async**, because TPM /
//! Secure Enclave / StrongBox round-trip to hardware). The runtime
//! pattern edge uses is [`crate::identity::LocalSigner`] (carries
//! `Arc<dyn HardwareSigner>` + `Option<Arc<dyn PqcSigner>>` from
//! `ciris-keyring`). We plumb to that — same trait surface as
//! `sign_envelope` — so ALM-A integrates with the actual production
//! signer the way every other signed-envelope path on edge does.
//!
//! ## Wire codec choice — serde_json
//!
//! `SignedRelayCapacity` serializes via **serde + serde_json**. The
//! reasons match [`crate::identity::QrPayload`] + the federation
//! handshake — one wire-codec idiom across the federation surface, and
//! the advertisement is small enough (low-hundreds of bytes plus the
//! ~3.3 KiB ML-DSA-65 sig) that the JSON-vs-tls byte cost is irrelevant.
//!
//! Canonical signing bytes are NOT the full JSON — see
//! [`RelayCapacity::canonical_bytes_for_signing`]. They are a
//! deterministic length-prefixed concatenation so signing is stable
//! across serde_json formatting differences.
//!
//! ## Replay protection
//!
//! The **signed preimage** is the cross-impl canonical shape owned by
//! Verify (§19.4 N8) — `peer_id ‖ uplink_mbps ‖ epoch` — so only these
//! bind the hybrid signature (see
//! [`RelayCapacity::canonical_bytes_for_signing`], CIRISEdge#359):
//! - `advertiser_key_id` (= Verify's `peer_id`) — owner-bound identity;
//! - `epoch` — so an advertisement minted before an MLS epoch rotation
//!   cannot be replayed at the new epoch.
//!
//! `measured_at_unix_ms` + the [`STALE_AFTER_SECS`] receive-side gate
//! still bounds how long any advert is honoured. `stream_id` and the MDC
//! `sub_stream_commitments` remain on the wire as **unsigned** planner
//! fields (the join planner + deterministic topology read them) but are
//! NOT in the signed preimage — Verify's `verify_relay_capacity` is the
//! joint source of truth and never signed over them.
//!
//! ## CIRISEdge#128 — Multiple Description Coding (MDC, "holographic")
//!
//! v3.8.0 introduces an additive [`RelayCapacity::sub_stream_commitments`]
//! field — a vector of per-sub-stream commitments under MDC mode
//! (`CODEC_MDC = 0x03`). User-facing semantics: any subset of MDC
//! sub-streams decodes at proportional fidelity, so a receiver can
//! "split each half equally" across multiple parents and reassemble
//! high-bandwidth quality from the union of available descriptions.
//!
//! - **Empty `sub_stream_commitments`** — peer carries the whole stream
//!   opaquely (`CODEC_OPAQUE`) or accepts ANY sub-stream up to the
//!   overall `uplink_mbps` budget. Backwards-compatible with v1
//!   single-codec capacities.
//! - **Non-empty `sub_stream_commitments`** — peer commits to specific
//!   sub-streams (variable depth, runtime-configurable — substrate is
//!   depth-agnostic; the codec layer picks). Receivers compose their
//!   quality level from the union of available sub-stream parents.
//!
//! Signing canonical-bytes domain separator is `CIRISALM-CAPv2\0\0` —
//! shared byte-for-byte with Verify's
//! [`ciris_verify_core::holonomic::preimage::DOMAIN_RELAY_CAPACITY`].
//! The MDC `sub_stream_commitments` are additive planner state; they
//! ride the wire unsigned and do NOT change the signed preimage.

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::identity::LocalSigner;
use crate::transport::realtime_av::{Epoch, ReceiverLayerPolicy, StreamId};

/// Federation-key identifier — alias kept consistent with
/// [`crate::transport::realtime_av_session::PeerKeyId`] and
/// [`crate::transport::realtime_av_relay::PeerKeyId`]. The federation
/// `key_id` (not the RNS identity hash). Alias rather than newtype so
/// the ALM surface composes directly with existing call sites.
pub type PeerKeyId = String;

/// Receive-side staleness gate. Receivers MUST treat
/// [`SignedRelayCapacity`] advertisements whose `capacity.measured_at_unix_ms`
/// is older than this many seconds at the local wall clock as withdrawn —
/// i.e. NOT a valid relay-parent candidate. Publishers refresh at least
/// this often (typically more often to absorb clock skew + measurement
/// jitter).
pub const STALE_AFTER_SECS: u64 = 30;

/// Publisher-side measurement window. Producers SHOULD compute
/// [`RelayCapacity::uplink_mbps`] from observed throughput over the
/// trailing window of this length — long enough to absorb instantaneous
/// jitter (TCP slow-start, RNS Link congestion bursts), short enough
/// that a peer that just lost its uplink isn't still advertising stale
/// capacity at the next [`STALE_AFTER_SECS`] tick.
pub const MEASUREMENT_WINDOW_SECS: u64 = 60;

/// Path identifying one MDC sub-stream within a stream's symmetric
/// decomposition. Empty path = the whole stream opaquely (codec_id =
/// `CODEC_OPAQUE`). Each byte is one bit-position in the dyadic split:
/// `[0]` = first half; `[0, 1]` = first-half's second quadrant; etc.
///
/// Variable-depth per the v3.8.0 user directive — the substrate is
/// depth-agnostic; the codec layer picks the depth based on stream
/// config (see CIRISEdge#128).
pub type SubStreamPath = Vec<u8>;

/// Per-sub-stream commitment carried inside a [`RelayCapacity`].
///
/// A peer with heterogeneous uplink can advertise commitments to some
/// MDC sub-streams but not others — e.g. a constrained mobile relay
/// commits only to the base half (`sub_stream_path = [0]`) and lets
/// other peers pick up the second half. Receivers reconstruct the
/// requested quality by joining sub-stream parents from the union of
/// commitments.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubStreamCommitment {
    /// Dyadic path identifying this sub-stream — see [`SubStreamPath`].
    pub sub_stream_path: SubStreamPath,
    /// Uplink budget (Mbps) reserved for this sub-stream specifically.
    /// Independent of the outer [`RelayCapacity::uplink_mbps`] — a peer
    /// MAY commit `commitments.iter().map(|c| c.uplink_budget_mbps).sum()`
    /// greater than `uplink_mbps` if commitments are mutually exclusive
    /// at the codec layer (e.g. peer expects only one sub-stream to be
    /// actively requested at a time). The honest case has the sum at or
    /// below `uplink_mbps`.
    pub uplink_budget_mbps: f32,
    /// Maximum concurrent subscribers for this sub-stream.
    pub max_subscribers: u16,
}

/// Errors the ALM-A capacity surface can return.
#[derive(Debug, thiserror::Error)]
pub enum AlmCapacityError {
    /// The advertisement's `measured_at_unix_ms` is older than
    /// [`STALE_AFTER_SECS`] at the verifier's wall clock. Treat the
    /// advertisement as withdrawn; do NOT route through this relay.
    #[error("relay capacity advertisement is stale")]
    Stale,
    /// Hybrid signature did not verify under the advertiser's
    /// federation pubkeys. Either the bytes were tampered with, the
    /// signer used a different key, or the advertisement was signed
    /// for a different `(stream_id, epoch)` binding. The error is
    /// uniform across these cases.
    #[error("relay capacity hybrid signature did not verify")]
    SignatureInvalid,
    /// A subscription admission check via [`RelayCapacity::has_room_for`]
    /// or [`RelayCapacity::has_room_for_substream`] returned `false`.
    #[error("insufficient relay capacity: cannot admit another subscriber")]
    InsufficientCapacity,
    /// Wire decode — input too short or malformed JSON.
    #[error("relay capacity wire decode failed: {0}")]
    WireDecode(String),
    /// The advertiser's pubkey bundle handed to [`SignedRelayCapacity::verify`]
    /// lacks the ML-DSA-65 half.
    #[error("relay capacity verifier requires ML-DSA-65 pubkey for hybrid verification")]
    PqcPubkeyMissing,
    /// Signer used at [`SignedRelayCapacity::sign`] time does NOT have
    /// the PQC half — classical-only ALM advertisements are an HNDL
    /// downgrade vector and structurally rejected at sign site.
    #[error("relay capacity signer must have ML-DSA-65 PQC half (HNDL discipline)")]
    SignerLacksPqc,
    /// A hardware-signer call (Ed25519 or ML-DSA-65) failed at sign
    /// time.
    #[error("relay capacity signer error: {0}")]
    SignerError(String),
}

/// Per-peer ALM relay-capacity advertisement.
///
/// Construct via [`RelayCapacity::new`] (timestamp-agnostic — the
/// caller threads the wall clock so the type is testable without a
/// real clock dep). Wrap in [`SignedRelayCapacity::sign`] before
/// publishing.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RelayCapacity {
    /// Sustained uplink budget in megabits per second the peer can
    /// spend on forwarding realtime A/V chunks. **Measured, NOT
    /// paper-spec** — peers SHOULD update this from observed
    /// throughput over the last [`MEASUREMENT_WINDOW_SECS`].
    pub uplink_mbps: f32,
    /// Maximum concurrent streams the peer will relay.
    pub max_streams: u16,
    /// Maximum subscribers per stream. Caps the per-stream egress —
    /// otherwise `uplink_mbps` alone could be exhausted by one popular
    /// stream's fan-out.
    pub max_subscribers_per_stream: u16,
    /// Unix milliseconds when this advertisement was minted (publisher
    /// wall clock at measurement time). Receivers MUST treat
    /// advertisements older than [`STALE_AFTER_SECS`] as withdrawn.
    pub measured_at_unix_ms: u64,
    /// Layers this relay supports. A peer MAY opt-in to forwarding
    /// only low-fidelity chunks (e.g. mobile relay).
    /// `ReceiverLayerPolicy::UNCAPPED` = forward any layer.
    pub max_layer_supported: ReceiverLayerPolicy,
    /// Per-sub-stream commitments under MDC mode (CIRISEdge#128).
    /// Empty = peer carries the whole stream opaquely (`CODEC_OPAQUE`)
    /// or accepts any sub-stream up to the overall `uplink_mbps`
    /// budget. Non-empty = peer commits to specific sub-streams;
    /// receivers compose their quality level from the union of
    /// available sub-stream parents.
    ///
    /// CIRISEdge#128 MDC mode (`CODEC_MDC = 0x03`) — the user-facing
    /// "holographic" semantics where any subset of sub-streams decodes
    /// at proportional fidelity.
    #[serde(default)]
    pub sub_stream_commitments: Vec<SubStreamCommitment>,
}

impl RelayCapacity {
    /// Construct a fresh capacity advertisement at the supplied wall
    /// clock. The module is timestamp-agnostic for testability.
    ///
    /// Defaults to empty `sub_stream_commitments` — opaque-mode relay.
    /// Use [`RelayCapacity::with_substream_commitments`] to declare
    /// MDC sub-stream commitments.
    #[must_use]
    pub fn new(
        uplink_mbps: f32,
        max_streams: u16,
        max_subscribers_per_stream: u16,
        max_layer_supported: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
    ) -> Self {
        Self {
            uplink_mbps,
            max_streams,
            max_subscribers_per_stream,
            max_layer_supported,
            measured_at_unix_ms: wall_clock_unix_ms,
            sub_stream_commitments: Vec::new(),
        }
    }

    /// Same as [`RelayCapacity::new`] but attaches MDC sub-stream
    /// commitments (CIRISEdge#128).
    #[must_use]
    pub fn with_substream_commitments(
        uplink_mbps: f32,
        max_streams: u16,
        max_subscribers_per_stream: u16,
        max_layer_supported: ReceiverLayerPolicy,
        wall_clock_unix_ms: u64,
        sub_stream_commitments: Vec<SubStreamCommitment>,
    ) -> Self {
        Self {
            uplink_mbps,
            max_streams,
            max_subscribers_per_stream,
            max_layer_supported,
            measured_at_unix_ms: wall_clock_unix_ms,
            sub_stream_commitments,
        }
    }

    /// Is this capacity stale at the given wall clock?
    ///
    /// Returns `true` iff `now_unix_ms - self.measured_at_unix_ms >=
    /// STALE_AFTER_SECS * 1000`. A negative skew is NOT stale.
    #[must_use]
    pub fn is_stale(&self, now_unix_ms: u64) -> bool {
        let Some(age_ms) = now_unix_ms.checked_sub(self.measured_at_unix_ms) else {
            return false;
        };
        age_ms >= STALE_AFTER_SECS.saturating_mul(1000)
    }

    /// Does this capacity have room for one more subscriber at the
    /// given chunk bitrate (opaque, whole-stream check)?
    ///
    /// Returns `true` iff BOTH:
    /// - `current_subscribers < self.max_subscribers_per_stream`, AND
    /// - `(current_subscribers + 1) * stream_bitrate_mbps <=
    ///   self.uplink_mbps`.
    ///
    /// For MDC sub-stream checks see [`Self::has_room_for_substream`].
    #[must_use]
    pub fn has_room_for(&self, stream_bitrate_mbps: f32, current_subscribers: u16) -> bool {
        if current_subscribers >= self.max_subscribers_per_stream {
            return false;
        }
        let prospective_subscribers = u32::from(current_subscribers) + 1;
        #[allow(clippy::cast_precision_loss)]
        let prospective_egress_mbps =
            (prospective_subscribers as f32) * stream_bitrate_mbps.max(0.0);
        prospective_egress_mbps <= self.uplink_mbps
    }

    /// Does this capacity have room to forward one more subscriber for
    /// the specified MDC sub-stream at the given bitrate?
    ///
    /// Lookup order (CIRISEdge#128 MDC mode):
    ///   1. If `sub_stream_path` exactly matches a [`SubStreamCommitment`]
    ///      in `sub_stream_commitments`, check that commitment's budget
    ///      (`max_subscribers` cap + `uplink_budget_mbps`).
    ///   2. If no commitment matches AND
    ///      `sub_stream_commitments.is_empty()`, fall back to the
    ///      overall `uplink_mbps` budget via [`Self::has_room_for`]
    ///      (opaque-mode relay).
    ///   3. Otherwise (commitments declared but none matches) → this
    ///      peer does NOT serve the requested sub-stream → `false`.
    #[must_use]
    pub fn has_room_for_substream(
        &self,
        sub_stream_path: &[u8],
        stream_bitrate_mbps: f32,
        current_subscribers_on_substream: u16,
    ) -> bool {
        // Lookup-by-path.
        if let Some(commitment) = self
            .sub_stream_commitments
            .iter()
            .find(|c| c.sub_stream_path.as_slice() == sub_stream_path)
        {
            if current_subscribers_on_substream >= commitment.max_subscribers {
                return false;
            }
            let prospective = u32::from(current_subscribers_on_substream) + 1;
            #[allow(clippy::cast_precision_loss)]
            let prospective_egress = (prospective as f32) * stream_bitrate_mbps.max(0.0);
            return prospective_egress <= commitment.uplink_budget_mbps;
        }
        // No specific commitment found.
        if self.sub_stream_commitments.is_empty() {
            // Opaque-mode peer: fall back to the whole-stream budget.
            return self.has_room_for(stream_bitrate_mbps, current_subscribers_on_substream);
        }
        // Commitments declared but none matches → refusal.
        false
    }

    /// Canonical bytes for hybrid signing — **delegated verbatim to
    /// Verify** so an edge-minted advert verifies under Verify's
    /// [`ciris_verify_core::holonomic::alm::verify_relay_capacity`]
    /// (§19.4 N8; CIRISEdge#359 Crypto-DRY).
    ///
    /// Layout is Verify's canonical §19.0 preimage:
    ///
    /// ```text
    ///   b"CIRISALM-CAPv2\0\0"            // domain (16 bytes)
    ///   u32_be(advertiser_key_id.len())  // length prefix
    ///   advertiser_key_id bytes          // Verify's `peer_id`
    ///   u32_be(uplink_mbps)              // f32 rounded → u32 Mbps
    ///   u64_be(epoch)
    /// ```
    ///
    /// **What is NOT signed** (deliberate, per the finding): `stream_id`,
    /// `max_streams`, `max_subscribers_per_stream`, `measured_at_unix_ms`,
    /// `max_layer_supported`, and the MDC `sub_stream_commitments`. These
    /// were never load-bearing for topology scoring; they remain on the
    /// wire as **unsigned** planner fields. Edge does NOT fork a wider
    /// preimage — Verify is the single source of truth for these bytes.
    ///
    /// `uplink_mbps` is edge-internal `f32` but Verify's canonical field
    /// is `u32`, so it is rounded to the nearest integer via
    /// [`uplink_mbps_to_u32`] before framing. Producer and verifier both
    /// route through this method, so the rounding is symmetric.
    #[must_use]
    pub fn canonical_bytes_for_signing(&self, advertiser_key_id: &str, epoch: Epoch) -> Vec<u8> {
        // Single shared construction — Verify's builder, not an edge fork.
        ciris_verify_core::holonomic::alm::SignedRelayCapacity {
            peer_id: advertiser_key_id.to_string(),
            uplink_mbps: uplink_mbps_to_u32(self.uplink_mbps),
            epoch: epoch.0,
        }
        .signing_preimage()
    }
}

/// Deterministic, saturating `f32` Mbps → `u32` Mbps for the signed
/// preimage. Verify's canonical `uplink_mbps` field is `u32`; edge
/// measures throughput as `f32`. Rust's `as` cast saturates (NaN → 0,
/// negative → 0, `> u32::MAX` → `u32::MAX`), so this is total and
/// stable. Both the signer and the verifier call it, so the rounding
/// never diverges across the sign/verify boundary.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub fn uplink_mbps_to_u32(mbps: f32) -> u32 {
    mbps.round() as u32
}

/// The advertiser's federation signing pubkeys — what the verifier
/// recomputes the hybrid signature against.
///
/// Distinct from [`crate::transport::federation_session::PeerKexPubkeys`]
/// which carries X25519 + ML-KEM-768 for **key agreement**; this
/// carries Ed25519 + ML-DSA-65 for **signature verification**.
#[derive(Debug, Clone)]
pub struct PeerSigningPubkeys {
    /// 32-byte Ed25519 verification key.
    pub ed25519_pub: Vec<u8>,
    /// ML-DSA-65 verification key (1952 bytes per FIPS 204 final).
    /// `None` for classical-only peers, but such peers cannot be
    /// verified as ALM relays.
    pub ml_dsa_65_pub: Option<Vec<u8>>,
}

/// Wire form of a signed ALM relay-capacity advertisement.
///
/// The signature is hybrid Ed25519 + ML-DSA-65 over
/// [`RelayCapacity::canonical_bytes_for_signing`] — same bound-signature
/// pattern as [`crate::identity::sign_envelope`]:
///
/// 1. `classical_sig = Ed25519::sign(canonical_bytes)`
/// 2. `pqc_sig = MLDSA65::sign(canonical_bytes || classical_sig)`
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRelayCapacity {
    /// Federation `key_id` of the advertising peer.
    pub advertiser_key_id: PeerKeyId,
    /// The capacity claim itself.
    pub capacity: RelayCapacity,
    /// Stream binding.
    pub stream_id: StreamId,
    /// Epoch binding.
    pub epoch: Epoch,
    /// Ed25519 signature over canonical bytes, base64.
    pub signature_ed25519_base64: String,
    /// ML-DSA-65 signature over `canonical || ed25519_sig`, base64.
    pub signature_ml_dsa_65_base64: String,
}

impl SignedRelayCapacity {
    /// Sign a [`RelayCapacity`] for a stream + epoch using the caller's
    /// [`LocalSigner`].
    ///
    /// HNDL discipline: returns [`AlmCapacityError::SignerLacksPqc`]
    /// when `signer.pqc.is_none()`.
    pub async fn sign(
        capacity: RelayCapacity,
        stream_id: StreamId,
        epoch: Epoch,
        advertiser_key_id: PeerKeyId,
        signer: &LocalSigner,
    ) -> Result<Self, AlmCapacityError> {
        let pqc = signer
            .pqc
            .as_ref()
            .ok_or(AlmCapacityError::SignerLacksPqc)?;

        let canonical = capacity.canonical_bytes_for_signing(&advertiser_key_id, epoch);

        let ed25519_sig = signer
            .classical
            .sign(&canonical)
            .await
            .map_err(|e| AlmCapacityError::SignerError(format!("ed25519 sign: {e}")))?;

        let mut bound = canonical;
        bound.extend_from_slice(&ed25519_sig);
        let pqc_sig = pqc
            .sign(&bound)
            .await
            .map_err(|e| AlmCapacityError::SignerError(format!("ml_dsa_65 sign: {e}")))?;

        Ok(Self {
            advertiser_key_id,
            capacity,
            stream_id,
            epoch,
            signature_ed25519_base64: base64::engine::general_purpose::STANDARD
                .encode(&ed25519_sig),
            signature_ml_dsa_65_base64: base64::engine::general_purpose::STANDARD.encode(&pqc_sig),
        })
    }

    /// Verify the hybrid signature against the advertiser's published
    /// pubkeys.
    pub fn verify(&self, advertiser_pubkeys: &PeerSigningPubkeys) -> Result<(), AlmCapacityError> {
        use ciris_crypto::{ClassicalVerifier, Ed25519Verifier, MlDsa65Verifier, PqcVerifier};

        let pqc_pub = advertiser_pubkeys
            .ml_dsa_65_pub
            .as_ref()
            .ok_or(AlmCapacityError::PqcPubkeyMissing)?;

        let ed25519_sig = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_ed25519_base64)
            .map_err(|_| AlmCapacityError::SignatureInvalid)?;
        let pqc_sig = base64::engine::general_purpose::STANDARD
            .decode(&self.signature_ml_dsa_65_base64)
            .map_err(|_| AlmCapacityError::SignatureInvalid)?;

        let canonical = self
            .capacity
            .canonical_bytes_for_signing(&self.advertiser_key_id, self.epoch);

        let ed25519_ok = Ed25519Verifier::new()
            .verify(&advertiser_pubkeys.ed25519_pub, &canonical, &ed25519_sig)
            .map_err(|_| AlmCapacityError::SignatureInvalid)?;
        if !ed25519_ok {
            return Err(AlmCapacityError::SignatureInvalid);
        }

        let mut bound = canonical;
        bound.extend_from_slice(&ed25519_sig);
        let pqc_ok = MlDsa65Verifier::new()
            .verify(pqc_pub, &bound, &pqc_sig)
            .map_err(|_| AlmCapacityError::SignatureInvalid)?;
        if !pqc_ok {
            return Err(AlmCapacityError::SignatureInvalid);
        }

        Ok(())
    }

    /// Wire-encode as JSON bytes.
    pub fn to_wire(&self) -> Result<Vec<u8>, AlmCapacityError> {
        serde_json::to_vec(self).map_err(|e| AlmCapacityError::WireDecode(e.to_string()))
    }

    /// Wire-decode a JSON-encoded advertisement.
    pub fn from_wire(bytes: &[u8]) -> Result<Self, AlmCapacityError> {
        serde_json::from_slice(bytes).map_err(|e| AlmCapacityError::WireDecode(e.to_string()))
    }
}

// Serde shim for StreamId — the realtime_av StreamId is `pub [u8; 32]`
// and doesn't implement Serialize / Deserialize. Same applies to Epoch
// and ReceiverLayerPolicy. These impls live here (close to the
// consumer) rather than in realtime_av so the upstream wire shape stays
// untouched.

mod stream_id_serde {
    use super::StreamId;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for StreamId {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(s)
        }
    }
    impl<'de> Deserialize<'de> for StreamId {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            <[u8; 32]>::deserialize(d).map(StreamId)
        }
    }
}

mod epoch_serde {
    use super::Epoch;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    impl Serialize for Epoch {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            self.0.serialize(s)
        }
    }
    impl<'de> Deserialize<'de> for Epoch {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            u64::deserialize(d).map(Epoch)
        }
    }
}

mod layer_policy_serde {
    use super::ReceiverLayerPolicy;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    #[allow(clippy::struct_field_names)]
    #[derive(Serialize, Deserialize)]
    struct Repr {
        max_spatial: u8,
        max_temporal: u8,
        max_quality: u8,
    }

    impl Serialize for ReceiverLayerPolicy {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            Repr {
                max_spatial: self.max_spatial,
                max_temporal: self.max_temporal,
                max_quality: self.max_quality,
            }
            .serialize(s)
        }
    }
    impl<'de> Deserialize<'de> for ReceiverLayerPolicy {
        fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
            let r = Repr::deserialize(d)?;
            Ok(ReceiverLayerPolicy {
                max_spatial: r.max_spatial,
                max_temporal: r.max_temporal,
                max_quality: r.max_quality,
            })
        }
    }
}

#[cfg(test)]
#[allow(clippy::similar_names, clippy::float_cmp)]
mod tests {
    use super::*;
    use ciris_keyring::{Ed25519SoftwareSigner, MlDsa65SoftwareSigner};
    use std::sync::Arc;

    fn stream(seed: u8) -> StreamId {
        StreamId([seed; 32])
    }

    fn test_capacity(now_unix_ms: u64) -> RelayCapacity {
        RelayCapacity::new(100.0, 4, 16, ReceiverLayerPolicy::UNCAPPED, now_unix_ms)
    }

    fn synth_seed(disc: u8) -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::try_from(i)
                .expect("index < 32")
                .wrapping_mul(31)
                .wrapping_add(disc);
        }
        seed
    }

    async fn test_signer(seed_disc: u8) -> (LocalSigner, PeerSigningPubkeys) {
        let key_id = format!("alm-test-{seed_disc}");
        let ed_seed = synth_seed(seed_disc);
        let pqc_seed = synth_seed(seed_disc ^ 0x55);
        let classical = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&ed_seed, &key_id).expect("ed25519 from_bytes"),
        );
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&pqc_seed, format!("{key_id}-pqc"))
                .expect("ml_dsa_65 from_seed_bytes"),
        );

        let ed_pub = ciris_keyring::HardwareSigner::public_key(classical.as_ref())
            .await
            .expect("ed25519 public_key");
        let pqc_pub = ciris_keyring::PqcSigner::public_key(pqc.as_ref())
            .await
            .expect("ml_dsa_65 public_key");

        let signer = LocalSigner::new(key_id, classical, Some(pqc));
        let pubkeys = PeerSigningPubkeys {
            ed25519_pub: ed_pub,
            ml_dsa_65_pub: Some(pqc_pub),
        };
        (signer, pubkeys)
    }

    #[test]
    fn capacity_freshness_truth_table() {
        let base: u64 = 1_700_000_000_000;
        let cap = test_capacity(base);
        assert!(!cap.is_stale(base));
        assert!(!cap.is_stale(base + 29_000));
        assert!(cap.is_stale(base + 30_000));
        assert!(cap.is_stale(base + 31_000));
        assert!(cap.is_stale(base + 60_000));
        assert!(!cap.is_stale(base.saturating_sub(5_000)));
    }

    #[test]
    fn capacity_has_room_truth_table() {
        let cap = RelayCapacity::new(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
        );
        let stream_bitrate = 2.5_f32;
        assert!(cap.has_room_for(stream_bitrate, 0));
        assert!(cap.has_room_for(stream_bitrate, 10));
        assert!(cap.has_room_for(stream_bitrate, 15));
        assert!(!cap.has_room_for(stream_bitrate, 16));
        assert!(!cap.has_room_for(stream_bitrate, 17));

        let small =
            RelayCapacity::new(5.0, 4, 16, ReceiverLayerPolicy::UNCAPPED, 1_700_000_000_000);
        assert!(small.has_room_for(2.5, 0));
        assert!(small.has_room_for(2.5, 1));
        assert!(!small.has_room_for(2.5, 2));

        assert!(cap.has_room_for(-1.0, 0));
    }

    #[tokio::test]
    async fn signed_capacity_round_trip_verifies() {
        let (signer, pubkeys) = test_signer(0xA1).await;
        let cap = test_capacity(1_700_000_000_000);

        let signed =
            SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        signed.verify(&pubkeys).expect("verify ok");
    }

    #[tokio::test]
    async fn signed_capacity_tamper_signature_refused() {
        let (signer, pubkeys) = test_signer(0xA2).await;
        let cap = test_capacity(1_700_000_000_000);

        let mut signed =
            SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        let mut chars: Vec<char> = signed.signature_ed25519_base64.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        signed.signature_ed25519_base64 = chars.into_iter().collect();

        let r = signed.verify(&pubkeys);
        assert!(matches!(r, Err(AlmCapacityError::SignatureInvalid)));
    }

    #[tokio::test]
    async fn signed_capacity_tamper_capacity_refused() {
        let (signer, pubkeys) = test_signer(0xA3).await;
        let cap = test_capacity(1_700_000_000_000);

        let mut signed =
            SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        signed.capacity.uplink_mbps = 9_999.0;

        let r = signed.verify(&pubkeys);
        assert!(matches!(r, Err(AlmCapacityError::SignatureInvalid)));
    }

    /// CIRISEdge#359: `stream_id` is an **unsigned** planner field — it
    /// left the signed preimage when edge adopted Verify's §19.4 layout.
    /// Mutating it therefore does NOT break the hybrid signature (the
    /// stream binding is enforced out-of-band by the roster, not the
    /// advert signature).
    #[tokio::test]
    async fn signed_capacity_stream_id_is_unsigned() {
        let (signer, pubkeys) = test_signer(0xA4).await;
        let cap = test_capacity(1_700_000_000_000);

        let mut signed =
            SignedRelayCapacity::sign(cap, stream(0xAA), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        signed.stream_id = stream(0xBB);

        // Signature still verifies — stream_id is not in the preimage.
        signed
            .verify(&pubkeys)
            .expect("stream_id is unsigned; verify still ok");
    }

    #[tokio::test]
    async fn signed_capacity_cross_epoch_refused() {
        let (signer, pubkeys) = test_signer(0xA5).await;
        let cap = test_capacity(1_700_000_000_000);

        let mut signed =
            SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        signed.epoch = Epoch(8);

        let r = signed.verify(&pubkeys);
        assert!(matches!(r, Err(AlmCapacityError::SignatureInvalid)));
    }

    #[tokio::test]
    async fn sign_rejects_classical_only_signer() {
        let key_id = "alm-test-classical-only";
        let ed_seed = synth_seed(0xC0);
        let classical = Arc::new(
            Ed25519SoftwareSigner::from_bytes(&ed_seed, key_id).expect("ed25519 from_bytes"),
        );
        let signer = LocalSigner::new(key_id, classical, None);
        let cap = test_capacity(1_700_000_000_000);
        let r = SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), key_id.to_string(), &signer)
            .await;
        assert!(matches!(r, Err(AlmCapacityError::SignerLacksPqc)));
    }

    #[tokio::test]
    async fn verify_rejects_classical_only_pubkeys() {
        let (signer, mut pubkeys) = test_signer(0xA6).await;
        let cap = test_capacity(1_700_000_000_000);
        let signed =
            SignedRelayCapacity::sign(cap, stream(0x42), Epoch(7), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        pubkeys.ml_dsa_65_pub = None;
        let r = signed.verify(&pubkeys);
        assert!(matches!(r, Err(AlmCapacityError::PqcPubkeyMissing)));
    }

    #[tokio::test]
    async fn wire_round_trip() {
        let (signer, pubkeys) = test_signer(0xC1).await;
        let cap = RelayCapacity::new(
            42.5,
            3,
            12,
            ReceiverLayerPolicy {
                max_spatial: 2,
                max_temporal: 3,
                max_quality: 1,
            },
            1_700_000_500_000,
        );

        let signed =
            SignedRelayCapacity::sign(cap, stream(0xCC), Epoch(99), signer.key_id.clone(), &signer)
                .await
                .expect("sign");

        let bytes = signed.to_wire().expect("to_wire");
        assert!(!bytes.is_empty());

        let decoded = SignedRelayCapacity::from_wire(&bytes).expect("from_wire");

        assert_eq!(decoded.advertiser_key_id, signed.advertiser_key_id);
        assert_eq!(decoded.capacity.uplink_mbps, signed.capacity.uplink_mbps);
        assert_eq!(decoded.capacity.max_streams, signed.capacity.max_streams);
        assert_eq!(
            decoded.capacity.max_subscribers_per_stream,
            signed.capacity.max_subscribers_per_stream
        );
        assert_eq!(
            decoded.capacity.measured_at_unix_ms,
            signed.capacity.measured_at_unix_ms
        );
        assert_eq!(
            decoded.capacity.max_layer_supported,
            signed.capacity.max_layer_supported
        );
        assert_eq!(decoded.stream_id.0, signed.stream_id.0);
        assert_eq!(decoded.epoch.0, signed.epoch.0);
        assert_eq!(
            decoded.signature_ed25519_base64,
            signed.signature_ed25519_base64
        );
        assert_eq!(
            decoded.signature_ml_dsa_65_base64,
            signed.signature_ml_dsa_65_base64
        );

        decoded
            .verify(&pubkeys)
            .expect("verify after wire round-trip");
    }

    #[test]
    fn wire_truncated_input_refused() {
        let r = SignedRelayCapacity::from_wire(b"{{{{{{{{");
        assert!(matches!(r, Err(AlmCapacityError::WireDecode(_))));

        let r = SignedRelayCapacity::from_wire(b"");
        assert!(matches!(r, Err(AlmCapacityError::WireDecode(_))));

        let r = SignedRelayCapacity::from_wire(b"{\"advertiser_key_id\":\"foo\"");
        assert!(matches!(r, Err(AlmCapacityError::WireDecode(_))));
    }

    /// CIRISEdge#359 canonical-length regression — Verify's §19.4 layout:
    /// domain(16) + u32 len-prefix(4) + peer_id + u32 uplink(4) + u64
    /// epoch(8). For a 7-byte `peer_id` that is 16+4+7+4+8 = 39 bytes,
    /// independent of the (now-unsigned) commitments/layer/stream fields.
    #[test]
    fn canonical_bytes_length_is_verify_layout() {
        let cap = RelayCapacity::with_substream_commitments(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
            // Commitments present but MUST NOT change the preimage length.
            vec![commitment(vec![0], 10.0, 4), commitment(vec![1], 12.5, 6)],
        );
        let bytes = cap.canonical_bytes_for_signing("relay-1", Epoch(42));
        assert_eq!(bytes.len(), 39, "verify layout: 16 + 4 + 7 + 4 + 8");
        assert_eq!(&bytes[..16], b"CIRISALM-CAPv2\0\0");
    }

    // ─────────────────────────────────────────────────────────────
    // MDC sub-stream commitments — CIRISEdge#128.
    // ─────────────────────────────────────────────────────────────

    fn commitment(path: Vec<u8>, budget: f32, subs: u16) -> SubStreamCommitment {
        SubStreamCommitment {
            sub_stream_path: path,
            uplink_budget_mbps: budget,
            max_subscribers: subs,
        }
    }

    #[test]
    fn substream_commitment_has_room_for_specific_path() {
        // Two commitments: first-half (path [0]) at 10 Mbps / 4 subs,
        // second-half (path [1]) at 10 Mbps / 4 subs.
        let cap = RelayCapacity::with_substream_commitments(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
            vec![commitment(vec![0], 10.0, 4), commitment(vec![1], 10.0, 4)],
        );
        // Path [0]: 1 sub at 2.5 Mbps → 5 Mbps prospective ≤ 10. Admit.
        assert!(cap.has_room_for_substream(&[0], 2.5, 1));
        // Path [0]: 3 subs at 2.5 Mbps → 4 × 2.5 = 10 ≤ 10. Admit.
        assert!(cap.has_room_for_substream(&[0], 2.5, 3));
        // Path [0]: 4 subs → at the cap. Reject.
        assert!(!cap.has_room_for_substream(&[0], 2.5, 4));
        // Path [1] same admission, independent.
        assert!(cap.has_room_for_substream(&[1], 2.5, 0));
    }

    #[test]
    fn substream_no_commitment_falls_back_to_uplink_budget() {
        // Opaque-mode peer — no commitments declared.
        let cap = RelayCapacity::new(
            10.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
        );
        // Any path goes through the overall budget.
        assert!(cap.has_room_for_substream(&[0], 2.5, 0));
        assert!(cap.has_room_for_substream(&[1], 2.5, 0));
        // [0, 1] path also works — opaque means accept any.
        assert!(cap.has_room_for_substream(&[0, 1], 2.5, 0));
        // Bandwidth check still applies. 4 subs × 2.5 = 10 = budget; admit.
        // 5th sub: 5 × 2.5 = 12.5 > 10 → reject.
        assert!(!cap.has_room_for_substream(&[0], 2.5, 4));
    }

    #[test]
    fn substream_commitment_declared_but_no_match_refuses() {
        // Peer commits to first-half only.
        let cap = RelayCapacity::with_substream_commitments(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
            vec![commitment(vec![0], 10.0, 4)],
        );
        // [0] matches → admit.
        assert!(cap.has_room_for_substream(&[0], 2.5, 0));
        // [1] doesn't match; commitments non-empty → refuse.
        assert!(!cap.has_room_for_substream(&[1], 2.5, 0));
        // [0, 1] doesn't exactly match → refuse.
        assert!(!cap.has_room_for_substream(&[0, 1], 2.5, 0));
    }

    #[tokio::test]
    async fn signed_capacity_v2_round_trip_with_substream_commitments() {
        let (signer, pubkeys) = test_signer(0xD0).await;
        let cap = RelayCapacity::with_substream_commitments(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
            vec![
                commitment(vec![0], 10.0, 4),
                commitment(vec![1], 12.5, 6),
                commitment(vec![0, 1], 5.0, 2),
            ],
        );

        let signed = SignedRelayCapacity::sign(
            cap.clone(),
            stream(0xDE),
            Epoch(123),
            signer.key_id.clone(),
            &signer,
        )
        .await
        .expect("sign");

        let bytes = signed.to_wire().expect("to_wire");
        let decoded = SignedRelayCapacity::from_wire(&bytes).expect("from_wire");

        assert_eq!(
            decoded.capacity.sub_stream_commitments.len(),
            3,
            "round-trip preserves commitment count"
        );
        assert_eq!(
            decoded.capacity.sub_stream_commitments,
            cap.sub_stream_commitments
        );

        // Hybrid signature still verifies — the canonical bytes are
        // length-prefixed so the order is deterministic.
        decoded.verify(&pubkeys).expect("verify v2 round-trip");
    }

    /// CIRISEdge#359: MDC `sub_stream_commitments` are **unsigned**
    /// planner state under Verify's §19.4 layout, so mutating a
    /// commitment does NOT break the hybrid signature. (Commitment
    /// integrity for topology admission is the planner's concern; the
    /// advert signature only covers `peer_id ‖ uplink_mbps ‖ epoch`.)
    #[tokio::test]
    async fn signed_capacity_v2_substream_commitments_are_unsigned() {
        let (signer, pubkeys) = test_signer(0xD1).await;
        let cap = RelayCapacity::with_substream_commitments(
            100.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
            vec![commitment(vec![0], 10.0, 4)],
        );

        let mut signed = SignedRelayCapacity::sign(
            cap,
            stream(0xDE),
            Epoch(123),
            signer.key_id.clone(),
            &signer,
        )
        .await
        .expect("sign");

        // Bump the commitment's budget — commitments are not in the
        // signed preimage, so verification still succeeds.
        signed.capacity.sub_stream_commitments[0].uplink_budget_mbps = 99.0;
        signed
            .verify(&pubkeys)
            .expect("commitments are unsigned; verify still ok");
    }

    /// CIRISEdge#359 golden cross-impl preimage vector (§19.4 N8). ALM was
    /// absent from the §19 vector set; this pins the edge-produced signing
    /// bytes to Verify's canonical `signing_preimage()` for a fixed input,
    /// and to a hard-coded byte literal so neither side can drift silently.
    ///
    /// Fixed input: `peer_id = "relay-1"`, `uplink_mbps = 500`, `epoch = 3`
    /// (the same tuple Verify's own N8 unit test signs).
    #[test]
    fn golden_preimage_matches_verify_signing_bytes() {
        // domain(16) ‖ u32_be(len "relay-1"=7) ‖ "relay-1" ‖ u32_be(500) ‖ u64_be(3)
        const GOLDEN: &[u8] = &[
            // b"CIRISALM-CAPv2\0\0"
            0x43, 0x49, 0x52, 0x49, 0x53, 0x41, 0x4c, 0x4d, 0x2d, 0x43, 0x41, 0x50, 0x76, 0x32,
            0x00, 0x00, // u32_be(7)
            0x00, 0x00, 0x00, 0x07, // "relay-1"
            0x72, 0x65, 0x6c, 0x61, 0x79, 0x2d, 0x31, // u32_be(500) = 0x000001F4
            0x00, 0x00, 0x01, 0xF4, // u64_be(3)
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        ];

        // Edge producer (f32 500.0 rounds to u32 500).
        let cap = RelayCapacity::new(
            500.0,
            4,
            16,
            ReceiverLayerPolicy::UNCAPPED,
            1_700_000_000_000,
        );
        let edge_bytes = cap.canonical_bytes_for_signing("relay-1", Epoch(3));

        // Verify's canonical builder, constructed independently.
        let verify_bytes = ciris_verify_core::holonomic::alm::SignedRelayCapacity {
            peer_id: "relay-1".to_string(),
            uplink_mbps: 500,
            epoch: 3,
        }
        .signing_preimage();

        assert_eq!(
            edge_bytes, GOLDEN,
            "edge preimage drifted from the golden vector"
        );
        assert_eq!(
            verify_bytes, GOLDEN,
            "verify preimage drifted from the golden vector"
        );
        assert_eq!(
            edge_bytes, verify_bytes,
            "edge and verify must produce byte-identical ALM preimages"
        );
        assert_eq!(&edge_bytes[..16], b"CIRISALM-CAPv2\0\0");
    }
}
