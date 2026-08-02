//! CIRISEdge#439 — the **delivered counterpart** of the signed relay-capacity
//! claim, keyed exactly to the claim, plus the CEG dimension a
//! delivered-vs-claimed score is *about*.
//!
//! ## Half 1 — the dimension ([`CAPACITY_RELAY_DELIVERY_DIMENSION`])
//!
//! `capacity:relay_delivery:v1`, named **here**, edge-side. Provenance of the
//! naming authority (the #439 finding, verified against both substrate repos):
//!
//! - **Verify's dimension registry is NOT the extension point.** Verify
//!   v11.0.0's `federation_provenance::dim::ALL` is *"the authoritative,
//!   exhaustive registry of the **verify-owned** dimension namespace"* — a
//!   closed static pin of CC part_3's families, with
//!   `foreign_dimensions_do_not_resolve` enforcing that non-verify dimensions
//!   never resolve there. There is no registration API by design: each
//!   producer owns its own namespace, and verify's registry pins verify's.
//! - **Persist owns the FAMILY policy, not the leaves.** Persist recognizes
//!   `capacity:*` by prefix (`capacity_claim_family`) as the open-sender,
//!   consent-gated reputation family; its own fixtures mint leaves
//!   (`capacity:core_identity:v1`) without any closed leaf set. Family
//!   admission is B1 ([`check_capacity_not_self_attested`] — never
//!   self-attested, either wire shape) and B5
//!   (`check_capacity_consent_admission` — a live [`CAPACITY_CONSENT_SCOPE`]
//!   consent from the subject covering the attester, CIRISConstitution#46).
//! - **Edge owns the ALM vocabulary** (#439: "Edge owns the ALM vocabulary;
//!   edge should name the leaf"), so edge names the leaf under persist's
//!   family, following the family's convention (`capacity:{leaf}:v{N}`,
//!   mechanism-named — what is *measured*, no ladder framing). The server
//!   must never restate this string — it imports the constant.
//!
//! ## Half 2 — the delivered counterpart, keyed to the claim
//!
//! [`SignedRelayCapacity`] is keyed by `(advertiser_key_id, stream_id,
//! epoch)`. The pre-existing counters (`envelopes_sent_total` per
//! `MessageType`, `transport_bytes_out_total` per `TransportId`) key on the
//! wrong axes — there is no join, so delivered-vs-claimed was *undefined*,
//! not imprecise. [`ObservationKey`] closes the join structurally: its only
//! constructors are [`ObservationKey::of_claim`] (from the signed claim) and
//! [`ObservationKey::of_delivery`] (from the receive loop's
//! [`ReconstructedChunk`] + the parent it was dialed from), so a claim and a
//! delivery meet on the same key **by construction**.
//!
//! [`DeliveredAccumulator`] is the pure accumulation: the consumer opens a
//! window against the claim it planned by ([`DeliveredAccumulator::open_window`]),
//! feeds every chunk its receive loop surfaces
//! ([`DeliveredAccumulator::record`], or the [`observe_delivery`] tap over
//! the `spawn_subscriber_loop` channel), and finalizes a
//! [`DeliveredObservation`] — delivered bytes/chunks over a wall-clock
//! window against the **signed** claim field (`uplink_mbps` through
//! [`uplink_mbps_to_u32`], the same rounding the hybrid signature covers).
//! A delivery with no open claim window is booked
//! ([`DeliveredAccumulator::unmatched_chunks`]), never silently counted —
//! delivered-without-a-claim has no counterpart to be scored against.
//!
//! ## The emission — edge emits, LensCore scores (AV_ALM_DESIGN §7)
//!
//! [`emit_delivered_observation`] produces the persist scores-plane row:
//! `attestation_type = scores`, envelope `dimension =
//! capacity:relay_delivery:v1`, **subject = the relay** (`attested_key_id`),
//! **attester = the consumer** (`attesting_key_id`), hybrid-signed over the
//! CEG-canonical envelope bytes (the same JCS + bound-PQC discipline as
//! [`crate::touch_claim`]). The envelope `score` is the measured fulfillment
//! ratio — a *measurement*, not a verdict: the honesty score proper is
//! LensCore's, composed fleet-wide with multi-observer corroboration and
//! hysteresis (§6 "give grace"). Edge never scores.
//!
//! **Fail-closed consent gate (B5).** Emission is refused unless the relay's
//! live `analyze` consent covering this consumer resolves `Granted` through
//! persist's one canonical scoped fold (`resolve_scoped_consent`) — the same
//! edge persist's own admission re-checks. Every refusal is a **named**
//! [`DeliveryWithholdReason`], never a silent drop. The latch-consent wiring
//! (the relay minting its `analyze` grant when it accepts a subscriber's
//! latch) does not exist yet; until it lands, live meshes take the
//! `ConsentNotGranted` path by design — genesis goes dark deliberately
//! (CC#46: the plane opens when subjects open it). `dry_run` builds and
//! signs the full row without submitting, so the shape is exercisable today.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use chrono::{DateTime, Utc};
use sha2::{Digest as _, Sha256};
use tokio::sync::mpsc;

use ciris_persist::federation::admission::{
    check_capacity_not_self_attested, CAPACITY_CONSENT_SCOPE,
};
use ciris_persist::federation::hard_case::ConsentState;
use ciris_persist::federation::types::{attestation_tier, attestation_type, cohort_scope};
use ciris_persist::federation::{Attestation, FederationDirectory, SignedAttestation};
use ciris_persist::prelude::ceg_produce_canonicalize;

use crate::identity::LocalSigner;
use crate::transport::realtime_av::{Epoch, StreamId};
use crate::transport::realtime_av_dispatcher::ReconstructedChunk;

use super::capacity::{uplink_mbps_to_u32, PeerKeyId, SignedRelayCapacity};

/// The CEG dimension a relay delivered-vs-claimed measurement is **about** —
/// the edge-named leaf under persist's open-sender, consent-gated
/// `capacity:*` family (see the module docs for why edge names it and
/// neither verify nor persist do). Consumers (CIRISServer's LensCore)
/// import this constant; restating the string downstream is the
/// producer-restates-substrate failure mode #439 documents.
///
/// Family admission this leaf inherits (persist-enforced at
/// `put_attestation`, mirrored here pre-emission):
/// - **B1 / AV-62** — never self-attested
///   ([`check_capacity_not_self_attested`]).
/// - **B5 / CC#46** — a live [`CAPACITY_CONSENT_SCOPE`] (`analyze`) consent
///   from the subject (the relay) covering the attester (this consumer).
pub const CAPACITY_RELAY_DELIVERY_DIMENSION: &str = "capacity:relay_delivery:v1";

/// The join key — **the claim key**, `(advertiser_key_id, stream_id,
/// epoch)`, exactly as [`SignedRelayCapacity`] is keyed. Constructed only
/// from the two sides of the join ([`Self::of_claim`] /
/// [`Self::of_delivery`]), so a claim and a delivered measurement can never
/// be keyed differently.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObservationKey {
    /// Federation `key_id` of the advertising relay (the claim's signer,
    /// and the parent the consumer dialed).
    pub advertiser_key_id: PeerKeyId,
    /// Stream binding, as carried on the claim and on every reconstructed
    /// chunk.
    pub stream_id: StreamId,
    /// Epoch binding — the claim's replay fence and the chunk's epoch.
    pub epoch: Epoch,
}

impl ObservationKey {
    /// The key of a signed capacity claim — the CLAIM side of the join.
    #[must_use]
    pub fn of_claim(claim: &SignedRelayCapacity) -> Self {
        Self {
            advertiser_key_id: claim.advertiser_key_id.clone(),
            stream_id: claim.stream_id,
            epoch: claim.epoch,
        }
    }

    /// The key of one delivered chunk — the DELIVERY side of the join. The
    /// `parent` is the relay this consumer's inbound link was dialed to
    /// (the subscriber knows its parent; the chunk carries the stream +
    /// epoch it was sealed under).
    #[must_use]
    pub fn of_delivery(parent: &PeerKeyId, chunk: &ReconstructedChunk) -> Self {
        Self {
            advertiser_key_id: parent.clone(),
            stream_id: chunk.stream_id,
            epoch: chunk.epoch,
        }
    }
}

/// One finalized delivered-vs-claimed measurement window — the record
/// LensCore scores. Keyed to the claim; carries the **signed** claim field
/// it is measured against.
#[derive(Debug, Clone, PartialEq)]
pub struct DeliveredObservation {
    /// The claim key this observation is the counterpart of.
    pub key: ObservationKey,
    /// The claimed sustained uplink, in whole Mbps — the value under the
    /// hybrid signature ([`uplink_mbps_to_u32`] of the claim's
    /// `uplink_mbps`; producer and verifier share the rounding). The only
    /// capacity field worth holding a relay to is the one it signed.
    pub claimed_uplink_mbps: u32,
    /// Plaintext bytes this consumer's receive loop actually surfaced from
    /// this relay in the window (AEAD-authenticated deliveries only — the
    /// loop counts nothing it could not open).
    pub delivered_bytes: u64,
    /// Chunks surfaced in the window.
    pub delivered_chunks: u64,
    /// Window start, unix ms (when the consumer opened the window against
    /// the claim).
    pub window_start_unix_ms: u64,
    /// Window end, unix ms (finalize time).
    pub window_end_unix_ms: u64,
}

impl DeliveredObservation {
    /// Observed delivery rate over the window, Mbps. `0.0` for an empty or
    /// inverted window (the emit path refuses those before they become a
    /// row).
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // bytes ≪ 2^52 in any real window
    pub fn delivered_mbps(&self) -> f64 {
        let window_ms = self
            .window_end_unix_ms
            .saturating_sub(self.window_start_unix_ms);
        if window_ms == 0 {
            return 0.0;
        }
        // bytes*8 bits / (ms/1000 s) / 1e6 = Mbps.
        (self.delivered_bytes as f64) * 8.0 * 1000.0 / (window_ms as f64) / 1_000_000.0
    }

    /// The measured fulfillment ratio in `[0, 1]` — delivered rate against
    /// the signed claim, clamped (over-delivery is simply honest). A zero
    /// claim cannot be fallen short of, so it measures `1.0`.
    ///
    /// A **measurement**, not the honesty score: LensCore composes the
    /// score fleet-wide with corroboration + hysteresis (AV_ALM_DESIGN §6).
    #[must_use]
    pub fn fulfillment_ratio(&self) -> f64 {
        if self.claimed_uplink_mbps == 0 {
            return 1.0;
        }
        (self.delivered_mbps() / f64::from(self.claimed_uplink_mbps)).clamp(0.0, 1.0)
    }
}

/// One open measurement window.
#[derive(Debug)]
struct OpenWindow {
    claimed_uplink_mbps: u32,
    delivered_bytes: u64,
    delivered_chunks: u64,
    window_start_unix_ms: u64,
}

/// Pure per-claim accumulation of delivered bytes/chunks — no clock, no
/// I/O, no directory. The caller threads wall-clock ms (the same
/// testability discipline as [`super::capacity::RelayCapacity::new`]).
#[derive(Debug, Default)]
pub struct DeliveredAccumulator {
    windows: HashMap<ObservationKey, OpenWindow>,
    unmatched_chunks: u64,
}

impl DeliveredAccumulator {
    /// Fresh accumulator with no open windows.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or refresh) the measurement window for `claim`. Keys off the
    /// claim itself — [`ObservationKey::of_claim`] — and snapshots the
    /// **signed** uplink field. Re-opening an already-open key (the relay
    /// coalesced a re-sign inside the window) keeps the window start and
    /// counters and adopts the freshest signed claim value.
    pub fn open_window(&mut self, claim: &SignedRelayCapacity, now_unix_ms: u64) {
        let claimed = uplink_mbps_to_u32(claim.capacity.uplink_mbps);
        self.windows
            .entry(ObservationKey::of_claim(claim))
            .and_modify(|w| w.claimed_uplink_mbps = claimed)
            .or_insert(OpenWindow {
                claimed_uplink_mbps: claimed,
                delivered_bytes: 0,
                delivered_chunks: 0,
                window_start_unix_ms: now_unix_ms,
            });
    }

    /// Count one chunk the receive loop surfaced from `parent` into its
    /// open window. Returns `true` if a window matched; a delivery with no
    /// open claim window is booked in [`Self::unmatched_chunks`] and NOT
    /// counted — delivered-without-a-claim has no counterpart, and folding
    /// it into some other key would be exactly the key-mismatch #439 is
    /// about.
    pub fn record(&mut self, parent: &PeerKeyId, chunk: &ReconstructedChunk) -> bool {
        let key = ObservationKey::of_delivery(parent, chunk);
        if let Some(w) = self.windows.get_mut(&key) {
            w.delivered_bytes += chunk.plaintext.len() as u64;
            w.delivered_chunks += 1;
            true
        } else {
            self.unmatched_chunks += 1;
            false
        }
    }

    /// Chunks that arrived with no open claim window — booked loudly,
    /// never silently counted (CIRISEdge#425 discipline).
    #[must_use]
    pub fn unmatched_chunks(&self) -> u64 {
        self.unmatched_chunks
    }

    /// Number of currently-open windows.
    #[must_use]
    pub fn open_window_count(&self) -> usize {
        self.windows.len()
    }

    /// Close the window for `key`, stamping `now_unix_ms` as the window
    /// end. `None` if no window was open for the key.
    pub fn finalize(
        &mut self,
        key: &ObservationKey,
        now_unix_ms: u64,
    ) -> Option<DeliveredObservation> {
        let w = self.windows.remove(key)?;
        Some(DeliveredObservation {
            key: key.clone(),
            claimed_uplink_mbps: w.claimed_uplink_mbps,
            delivered_bytes: w.delivered_bytes,
            delivered_chunks: w.delivered_chunks,
            window_start_unix_ms: w.window_start_unix_ms,
            window_end_unix_ms: now_unix_ms,
        })
    }
}

/// Tap a subscriber receive loop: re-yield every [`ReconstructedChunk`]
/// from `upstream` (the channel [`spawn_subscriber_loop`] /
/// [`AvSubscriber::subscribe`] returned) while recording it into
/// `accumulator` against `parent` — the relay this inbound link was dialed
/// to. The accumulation is fed by the REAL receive-loop output; nothing is
/// counted that the loop did not surface.
///
/// [`spawn_subscriber_loop`]: crate::transport::realtime_av_dispatcher::AvDispatcher::spawn_subscriber_loop
/// [`AvSubscriber::subscribe`]: crate::transport::realtime_av_runtime::AvSubscriber::subscribe
#[must_use]
pub fn observe_delivery(
    parent: PeerKeyId,
    mut upstream: mpsc::Receiver<ReconstructedChunk>,
    accumulator: Arc<Mutex<DeliveredAccumulator>>,
) -> mpsc::Receiver<ReconstructedChunk> {
    // Depth matches the dispatcher's own subscriber channel.
    let (tx, rx) = mpsc::channel::<ReconstructedChunk>(64);
    tokio::spawn(async move {
        while let Some(chunk) = upstream.recv().await {
            accumulator
                .lock()
                .expect("delivered accumulator poisoned")
                .record(&parent, &chunk);
            if tx.send(chunk).await.is_err() {
                break; // downstream consumer gone — stream over.
            }
        }
    });
    rx
}

/// The scores-plane envelope for one [`DeliveredObservation`] — the exact
/// JSON persist canonicalizes and this consumer hybrid-signs. Shape mirrors
/// persist's own scores rows (`dimension` + `score` + the measurement
/// fields); the claim key rides in full so LensCore can join observations
/// from independent consumers on the same claim.
#[must_use]
pub fn delivery_envelope(observation: &DeliveredObservation) -> serde_json::Value {
    serde_json::json!({
        "dimension": CAPACITY_RELAY_DELIVERY_DIMENSION,
        "score": observation.fulfillment_ratio(),
        "stream_id_hex": hex::encode(observation.key.stream_id.0),
        "epoch": observation.key.epoch.0,
        "claimed_uplink_mbps": observation.claimed_uplink_mbps,
        "delivered_bytes": observation.delivered_bytes,
        "delivered_chunks": observation.delivered_chunks,
        "delivered_mbps": observation.delivered_mbps(),
        "window_start_unix_ms": observation.window_start_unix_ms,
        "window_end_unix_ms": observation.window_end_unix_ms,
    })
}

/// Why an emission was withheld — every refusal is named, never silent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryWithholdReason {
    /// The consumer IS the advertiser — B1/AV-62, refused via persist's own
    /// [`check_capacity_not_self_attested`] (the authority's rule, not a
    /// restatement), before the consent gate so the refusal names
    /// self-emission rather than being shadowed by "no consent".
    SelfEmission,
    /// The relay's live [`CAPACITY_CONSENT_SCOPE`] (`analyze`) consent
    /// covering this consumer did not resolve `Granted` (B5 / CC#46).
    /// Until the latch-consent wiring mints the grant at latch-accept,
    /// this is the expected live-mesh path.
    ConsentNotGranted {
        /// The resolved stance, `Debug`-formatted (`Unspecified` /
        /// `Revoked` / `Expired`).
        stance: String,
    },
    /// The consent read itself failed — fail-closed, and the transient
    /// error is carried rather than cached.
    ConsentUnresolvable {
        /// The directory error.
        error: String,
    },
    /// A zero-length (or inverted) window is not a measurement; a rate
    /// cannot be computed from it, so no row is minted.
    EmptyWindow,
}

/// Outcome of [`emit_delivered_observation`].
#[derive(Debug)]
pub enum DeliveryEmitOutcome {
    /// The signed row was submitted and admitted by the directory.
    Emitted {
        /// The deterministic (content-addressed) attestation id.
        attestation_id: String,
    },
    /// Dry-run: the row passed every edge-side gate and is fully signed,
    /// but was NOT submitted.
    DryRunAdmissible {
        /// The signed, ready-to-submit row.
        attestation: Box<Attestation>,
    },
    /// Refused, with the reason named.
    Withheld {
        /// Why.
        reason: DeliveryWithholdReason,
    },
}

/// A fault (not a policy refusal) building or submitting the row.
#[derive(Debug, thiserror::Error)]
pub enum DeliveryEmitError {
    /// The signer has no ML-DSA-65 half — a classical-only scores row is
    /// an HNDL downgrade and will not admit at persist's hybrid ingest
    /// gate; structurally refused at sign site (same rule as
    /// [`super::capacity::AlmCapacityError::SignerLacksPqc`]).
    #[error("delivery emission signer must have ML-DSA-65 PQC half (HNDL discipline)")]
    SignerLacksPqc,
    /// CEG canonicalization of the envelope failed.
    #[error("delivery envelope canonicalize failed: {0}")]
    Canonicalize(String),
    /// A hardware-signer call failed.
    #[error("delivery emission sign failed: {0}")]
    Sign(String),
    /// The directory refused or failed the submission.
    #[error("delivery emission submit failed: {0}")]
    Submit(String),
}

/// Emit one [`DeliveredObservation`] as a scores-plane row about the relay
/// — subject = `observation.key.advertiser_key_id`, attester =
/// `signer.key_id` — gated fail-closed on the relay's `analyze` consent
/// (see the module docs). `dry_run = true` runs every gate and signs the
/// row but does not submit.
///
/// # Errors
///
/// [`DeliveryEmitError`] on a signing/canonicalization/submission *fault*.
/// Policy refusals are NOT errors — they return
/// [`DeliveryEmitOutcome::Withheld`] with the reason named.
pub async fn emit_delivered_observation(
    directory: &dyn FederationDirectory,
    signer: &LocalSigner,
    observation: &DeliveredObservation,
    dry_run: bool,
    now: DateTime<Utc>,
) -> Result<DeliveryEmitOutcome, DeliveryEmitError> {
    // (0) A measurement needs a window.
    if observation.window_end_unix_ms <= observation.window_start_unix_ms {
        return Ok(DeliveryEmitOutcome::Withheld {
            reason: DeliveryWithholdReason::EmptyWindow,
        });
    }

    // (1) B1/AV-62 — via persist's OWN rule, upstream of consent so the
    // refusal reports as self-emission (persist orders these gates the
    // same way, for the same reason).
    if check_capacity_not_self_attested(
        Some(CAPACITY_RELAY_DELIVERY_DIMENSION),
        &signer.key_id,
        &observation.key.advertiser_key_id,
    )
    .is_err()
    {
        return Ok(DeliveryEmitOutcome::Withheld {
            reason: DeliveryWithholdReason::SelfEmission,
        });
    }

    // (2) B5/CC#46 — the relay's live `analyze` consent covering this
    // consumer, through persist's ONE canonical scoped fold. The consent
    // edge points AT the attester and is authored BY the subject, so
    // target = us, subject-author = the relay (the same orientation
    // persist's `check_capacity_consent_admission` resolves).
    let stance = match directory
        .resolve_scoped_consent(
            &signer.key_id,
            &observation.key.advertiser_key_id,
            CAPACITY_CONSENT_SCOPE,
            None,
            now,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                relay = %observation.key.advertiser_key_id,
                error = %e,
                "capacity-delivery emission: consent unresolvable — withholding (fail-closed, #439)"
            );
            return Ok(DeliveryEmitOutcome::Withheld {
                reason: DeliveryWithholdReason::ConsentUnresolvable {
                    error: e.to_string(),
                },
            });
        }
    };
    if stance != ConsentState::Granted {
        tracing::info!(
            relay = %observation.key.advertiser_key_id,
            stance = ?stance,
            "capacity-delivery emission withheld: no live analyze grant from the relay \
             covering this consumer (B5/CC#46; latch-consent wiring pending, #439)"
        );
        return Ok(DeliveryEmitOutcome::Withheld {
            reason: DeliveryWithholdReason::ConsentNotGranted {
                stance: format!("{stance:?}"),
            },
        });
    }

    // (3) Build + hybrid-sign the row.
    let attestation = build_delivery_row(signer, observation, now).await?;
    let attestation_id = attestation.attestation_id.clone();

    if dry_run {
        return Ok(DeliveryEmitOutcome::DryRunAdmissible {
            attestation: Box::new(attestation),
        });
    }

    directory
        .put_attestation(SignedAttestation { attestation })
        .await
        .map_err(|e| DeliveryEmitError::Submit(e.to_string()))?;
    Ok(DeliveryEmitOutcome::Emitted { attestation_id })
}

/// Build + hybrid-sign the scores-plane row for one observation — JCS
/// canonical bytes + the AV-33 bound-PQC pattern (ML-DSA-65 over
/// `canonical ‖ ed25519_sig`), the same discipline as
/// [`crate::touch_claim`]'s producer. The `attestation_id` is
/// content-addressed off the envelope hash, so identical window contents
/// dedupe to one row.
async fn build_delivery_row(
    signer: &LocalSigner,
    observation: &DeliveredObservation,
    now: DateTime<Utc>,
) -> Result<Attestation, DeliveryEmitError> {
    let pqc = signer
        .pqc
        .as_ref()
        .ok_or(DeliveryEmitError::SignerLacksPqc)?;
    let envelope = delivery_envelope(observation);
    let canonical = ceg_produce_canonicalize(&envelope)
        .map_err(|e| DeliveryEmitError::Canonicalize(e.to_string()))?;
    let original_content_hash = hex::encode(Sha256::digest(&canonical));
    let ed_sig = signer
        .classical
        .sign(&canonical)
        .await
        .map_err(|e| DeliveryEmitError::Sign(format!("ed25519 sign: {e}")))?;
    let mut bound = canonical;
    bound.extend_from_slice(&ed_sig);
    let pqc_sig = pqc
        .sign(&bound)
        .await
        .map_err(|e| DeliveryEmitError::Sign(format!("ml_dsa_65 sign: {e}")))?;

    let attestation_id = format!("capacity-delivery-{}", &original_content_hash[..16]);
    Ok(Attestation {
        attestation_id,
        attesting_key_id: signer.key_id.clone(),
        attested_key_id: observation.key.advertiser_key_id.clone(),
        attestation_type: attestation_type::SCORES.to_owned(),
        weight: None,
        asserted_at: now,
        expires_at: None,
        attestation_envelope: envelope,
        original_content_hash,
        scrub_signature_classical: B64.encode(&ed_sig),
        scrub_signature_pqc: Some(B64.encode(&pqc_sig)),
        scrub_key_id: signer.key_id.clone(),
        scrub_timestamp: now,
        pqc_completed_at: None,
        persist_row_hash: String::new(),
        subject_key_ids: Vec::new(),
        withdraws_admission_rule: None,
        cohort_scope: cohort_scope::FEDERATION.to_owned(),
        tier: attestation_tier::FEDERATION.to_owned(),
        promoted_at: None,
        additional_scrubs: Vec::new(),
    })
}

#[cfg(test)]
#[allow(clippy::float_cmp)]
mod tests {
    use super::*;
    use crate::transport::realtime_av::{
        seal_av_inner, ChunkLayer, ChunkSeq, EpochDek, ReceiverLayerPolicy, CODEC_OPAQUE,
    };
    use crate::transport::realtime_av_alm::capacity::RelayCapacity;
    use crate::transport::realtime_av_dispatcher::{
        AvDispatcher, AvDispatcherConfig, AvDispatcherError, AvInboundLink, AvLinkReceiver,
        AvLinkSender, AvRole, AvSubscriberLink,
    };
    use ciris_crypto::{ClassicalSigner as _, Ed25519Signer, MlDsa65Signer, PqcSigner as _};
    use ciris_keyring::{Ed25519SoftwareSigner, MlDsa65SoftwareSigner};
    use ciris_persist::federation::consent::consent_dimension::{
        STATE_GRANTED_PREFIX, STATE_REVOKED_PREFIX,
    };
    use ciris_persist::federation::types::{algorithm, KeyRecord, SignedKeyRecord};
    use ciris_persist::store::MemoryBackend;
    use tokio::time::{timeout, Duration};

    fn stream(seed: u8) -> StreamId {
        StreamId([seed; 32])
    }

    /// An unsigned-claim fixture — the accumulator keys off the claim's
    /// key fields; signature verification is upstream of this module
    /// (same construction as the transit-gate tests).
    fn claim(advertiser: &str, s: StreamId, epoch: u64, uplink_mbps: f32) -> SignedRelayCapacity {
        SignedRelayCapacity {
            advertiser_key_id: advertiser.to_string(),
            capacity: RelayCapacity::new(uplink_mbps, 4, 16, ReceiverLayerPolicy::UNCAPPED, 1_000),
            stream_id: s,
            epoch: Epoch(epoch),
            signature_ed25519_base64: String::new(),
            signature_ml_dsa_65_base64: String::new(),
        }
    }

    fn chunk(s: StreamId, epoch: u64, seq: u64, len: usize) -> ReconstructedChunk {
        ReconstructedChunk {
            stream_id: s,
            epoch: Epoch(epoch),
            chunk_seq: ChunkSeq(seq),
            plaintext: vec![0xAB; len],
        }
    }

    // ─── the join key ────────────────────────────────────────────────

    /// #439's core structural fix: the claim side and the delivery side
    /// construct the SAME key, and any component divergence un-joins them.
    #[test]
    fn observation_key_is_the_claim_key_by_construction() {
        let c = claim("relay-1", stream(0x42), 7, 100.0);
        let k_claim = ObservationKey::of_claim(&c);
        let k_delivery =
            ObservationKey::of_delivery(&"relay-1".to_string(), &chunk(stream(0x42), 7, 0, 10));
        assert_eq!(k_claim, k_delivery, "claim and delivery meet on one key");

        // Any component divergence breaks the join.
        assert_ne!(
            k_claim,
            ObservationKey::of_delivery(&"relay-2".to_string(), &chunk(stream(0x42), 7, 0, 10))
        );
        assert_ne!(
            k_claim,
            ObservationKey::of_delivery(&"relay-1".to_string(), &chunk(stream(0x43), 7, 0, 10))
        );
        assert_ne!(
            k_claim,
            ObservationKey::of_delivery(&"relay-1".to_string(), &chunk(stream(0x42), 8, 0, 10))
        );
    }

    // ─── pure accumulation ───────────────────────────────────────────

    #[test]
    fn delivery_without_an_open_claim_window_is_booked_unmatched_not_counted() {
        let mut acc = DeliveredAccumulator::new();
        assert!(!acc.record(&"relay-1".to_string(), &chunk(stream(1), 1, 0, 100)));
        assert_eq!(acc.unmatched_chunks(), 1);
        assert_eq!(acc.open_window_count(), 0);
        assert!(
            acc.finalize(
                &ObservationKey::of_claim(&claim("relay-1", stream(1), 1, 50.0)),
                2_000
            )
            .is_none(),
            "nothing was accumulated for a window never opened"
        );
    }

    #[test]
    fn window_refresh_adopts_freshest_signed_claim_and_keeps_counters() {
        let mut acc = DeliveredAccumulator::new();
        let s = stream(2);
        acc.open_window(&claim("relay-1", s, 3, 100.0), 1_000);
        assert!(acc.record(&"relay-1".to_string(), &chunk(s, 3, 0, 500)));

        // The relay coalesce-re-signs a lower claim mid-window: snapshot
        // updates, counters and window start survive.
        acc.open_window(&claim("relay-1", s, 3, 40.0), 5_000);
        assert!(acc.record(&"relay-1".to_string(), &chunk(s, 3, 1, 250)));

        let obs = acc
            .finalize(
                &ObservationKey::of_claim(&claim("relay-1", s, 3, 40.0)),
                9_000,
            )
            .expect("window open");
        assert_eq!(obs.claimed_uplink_mbps, 40, "freshest signed value");
        assert_eq!(obs.delivered_bytes, 750, "counters survive the refresh");
        assert_eq!(obs.delivered_chunks, 2);
        assert_eq!(obs.window_start_unix_ms, 1_000, "window start survives");
        assert_eq!(obs.window_end_unix_ms, 9_000);
        assert_eq!(acc.open_window_count(), 0, "finalize closes the window");
    }

    #[test]
    fn fulfillment_ratio_truth_table() {
        let mk = |claimed: u32, bytes: u64, window_ms: u64| DeliveredObservation {
            key: ObservationKey::of_claim(&claim("r", stream(9), 1, 0.0)),
            claimed_uplink_mbps: claimed,
            delivered_bytes: bytes,
            delivered_chunks: 1,
            window_start_unix_ms: 0,
            window_end_unix_ms: window_ms,
        };
        // 10 Mbps claimed; 10s window; 12.5 MB = 100 Mbit → 10 Mbps → 1.0.
        assert_eq!(mk(10, 12_500_000, 10_000).fulfillment_ratio(), 1.0);
        // Half delivered → 0.5.
        assert_eq!(mk(10, 6_250_000, 10_000).fulfillment_ratio(), 0.5);
        // Over-delivery clamps to 1.0 (over-delivering is honest).
        assert_eq!(mk(10, 25_000_000, 10_000).fulfillment_ratio(), 1.0);
        // A zero claim cannot be fallen short of.
        assert_eq!(mk(0, 0, 10_000).fulfillment_ratio(), 1.0);
        // Zero delivered against a real claim → 0.0.
        assert_eq!(mk(10, 0, 10_000).fulfillment_ratio(), 0.0);
        // Empty window → rate 0.0 (and the emit path refuses it upstream).
        assert_eq!(mk(10, 1_000, 0).delivered_mbps(), 0.0);
    }

    #[test]
    fn delivery_envelope_pins_dimension_and_claim_key() {
        let obs = DeliveredObservation {
            key: ObservationKey::of_claim(&claim("relay-1", stream(0xCC), 42, 100.0)),
            claimed_uplink_mbps: 100,
            delivered_bytes: 1_234,
            delivered_chunks: 5,
            window_start_unix_ms: 1_000,
            window_end_unix_ms: 11_000,
        };
        let env = delivery_envelope(&obs);
        assert_eq!(env["dimension"], CAPACITY_RELAY_DELIVERY_DIMENSION);
        assert_eq!(env["stream_id_hex"], hex::encode([0xCC; 32]));
        assert_eq!(env["epoch"], 42);
        assert_eq!(env["claimed_uplink_mbps"], 100);
        assert_eq!(env["delivered_bytes"], 1_234);
        assert_eq!(env["delivered_chunks"], 5);
        assert_eq!(env["window_start_unix_ms"], 1_000);
        assert_eq!(env["window_end_unix_ms"], 11_000);
        // The dimension is inside persist's capacity:* family — the family
        // gate persist keys on is a prefix match.
        assert!(CAPACITY_RELAY_DELIVERY_DIMENSION.starts_with("capacity:"));
    }

    // ─── field provenance: the REAL receive loop feeds the counters ──

    struct MpscSender {
        tx: mpsc::Sender<Vec<u8>>,
    }
    #[async_trait::async_trait]
    impl AvLinkSender for MpscSender {
        async fn send(&self, bytes: &[u8]) -> Result<(), AvDispatcherError> {
            self.tx
                .send(bytes.to_vec())
                .await
                .map_err(|e| AvDispatcherError::SendFailed(e.to_string()))
        }
    }
    struct MpscReceiver {
        rx: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    }
    #[async_trait::async_trait]
    impl AvLinkReceiver for MpscReceiver {
        async fn recv(&self) -> Result<Vec<u8>, AvDispatcherError> {
            self.rx
                .lock()
                .await
                .recv()
                .await
                .ok_or_else(|| AvDispatcherError::RecvFailed("closed".into()))
        }
    }

    /// Test-field-provenance (#336 lesson): the accumulator is fed from the
    /// EXACT chunks the real publisher→subscriber wire path surfaces —
    /// publisher dispatcher outer-seals per-link, the subscriber loop opens
    /// both AEAD layers, and the [`observe_delivery`] tap records what the
    /// loop ACTUALLY produced (verified against the chunks drained
    /// downstream), not synthetic counters.
    #[tokio::test]
    #[allow(clippy::too_many_lines)] // publish + receive loop + tap + finalize: one scenario
    async fn accumulator_counts_the_real_receive_loop_output() {
        let s = stream(0x51);
        let dek = [0x77u8; 32];
        let transit = [0x21u8; 32];
        let parent: PeerKeyId = "relay-parent".to_string();

        // Publisher → subscriber over an in-memory link pair.
        let (tx, rx_wire) = mpsc::channel::<Vec<u8>>(64);
        let mut publisher = AvDispatcher::new(AvDispatcherConfig {
            stream_id: s,
            local_role: AvRole::Publisher,
            epoch_dek: Some(dek),
            initial_subscribers: vec![AvSubscriberLink {
                subscriber: "consumer".to_string(),
                transit_key: transit,
                link_id: b"tap-link".to_vec(),
                outbound_send: Box::new(MpscSender { tx }),
            }],
            inbound_links: vec![],
        })
        .expect("publisher");
        let mut subscriber = AvDispatcher::new(AvDispatcherConfig {
            stream_id: s,
            local_role: AvRole::Subscriber,
            epoch_dek: Some(dek),
            initial_subscribers: vec![],
            inbound_links: vec![AvInboundLink {
                transit_key: transit,
                link_id: b"tap-link".to_vec(),
                inbound_recv: Box::new(MpscReceiver {
                    rx: tokio::sync::Mutex::new(rx_wire),
                }),
            }],
        })
        .expect("subscriber");

        // The tap over the REAL receive loop.
        let acc = Arc::new(Mutex::new(DeliveredAccumulator::new()));
        let mut tapped = observe_delivery(
            parent.clone(),
            subscriber.spawn_subscriber_loop(),
            acc.clone(),
        );

        // Open the window against the parent's claim BEFORE delivery.
        acc.lock()
            .expect("acc")
            .open_window(&claim(&parent, s, 1, 25.0), 10_000);

        // Publish three chunks of known plaintext lengths at epoch 1.
        let dek_typed = EpochDek::from_bytes(dek);
        let lens = [100usize, 257, 1_024];
        for (i, len) in lens.iter().enumerate() {
            let inner = seal_av_inner(
                &vec![0x5Au8; *len],
                &dek_typed,
                s,
                Epoch(1),
                ChunkSeq(i as u64),
                CODEC_OPAQUE,
                ChunkLayer::BASE,
            )
            .expect("inner seal");
            publisher.publish_inner(inner).await.expect("publish");
        }

        // Drain what the loop surfaced; the tap forwards verbatim.
        let mut surfaced_bytes = 0u64;
        for _ in 0..lens.len() {
            let c = timeout(Duration::from_secs(5), tapped.recv())
                .await
                .expect("no timeout")
                .expect("chunk");
            assert_eq!(c.stream_id, s);
            assert_eq!(c.epoch, Epoch(1));
            surfaced_bytes += c.plaintext.len() as u64;
        }

        // One more chunk at epoch 2 — NO open window for that key: booked
        // unmatched, never folded into the epoch-1 window.
        let inner = seal_av_inner(
            &[0xEEu8; 64],
            &dek_typed,
            s,
            Epoch(2),
            ChunkSeq(0),
            CODEC_OPAQUE,
            ChunkLayer::BASE,
        )
        .expect("inner seal epoch 2");
        publisher
            .publish_inner(inner)
            .await
            .expect("publish epoch 2");
        let stray = timeout(Duration::from_secs(5), tapped.recv())
            .await
            .expect("no timeout")
            .expect("stray chunk");
        assert_eq!(stray.epoch, Epoch(2));

        let obs = acc
            .lock()
            .expect("acc")
            .finalize(
                &ObservationKey::of_claim(&claim(&parent, s, 1, 25.0)),
                20_000,
            )
            .expect("window open");
        assert_eq!(
            obs.delivered_bytes, surfaced_bytes,
            "accumulated bytes == exactly what the receive loop surfaced"
        );
        assert_eq!(
            obs.delivered_bytes,
            lens.iter().map(|l| *l as u64).sum::<u64>(),
            "…which is the published plaintext total (AEAD round-trip exact)"
        );
        assert_eq!(obs.delivered_chunks, lens.len() as u64);
        assert_eq!(obs.claimed_uplink_mbps, 25);
        assert_eq!(
            acc.lock().expect("acc").unmatched_chunks(),
            1,
            "the epoch-2 delivery had no claim window — booked, not counted"
        );
    }

    // ─── the emission gate: the REAL consent machinery ───────────────
    //
    // Fixture-signature helpers mirroring persist's `tier_ingest::
    // test_support` (`pub(crate)` over there — replicated per the
    // edge.rs / bridge.rs test corpus convention): deterministic
    // per-key_id hybrid keypairs, so the registered key and the signing
    // key collapse to the same identity.

    fn seed_for(key_id: &str) -> [u8; 32] {
        let mut seed = [0x11u8; 32];
        for (i, b) in key_id.bytes().take(32).enumerate() {
            seed[i] = b;
        }
        seed
    }

    fn hybrid_pubkeys(key_id: &str) -> (String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(key_id)).expect("ed seed");
        let mldsa = Box::new(MlDsa65Signer::from_seed(&seed_for(key_id)).expect("mldsa seed"));
        (
            B64.encode(ed.public_key().expect("ed pk")),
            Some(B64.encode(mldsa.public_key().expect("mldsa pk"))),
        )
    }

    fn sign_attestation_envelope(
        signing_key_id: &str,
        envelope: &serde_json::Value,
    ) -> (String, String, Option<String>) {
        let ed = Ed25519Signer::from_seed(&seed_for(signing_key_id)).expect("ed seed");
        let mldsa =
            Box::new(MlDsa65Signer::from_seed(&seed_for(signing_key_id)).expect("mldsa seed"));
        let canonical = ceg_produce_canonicalize(envelope).expect("ceg canonicalize");
        let och = hex::encode(Sha256::digest(&canonical));
        let ed_sig = ed.sign(&canonical).expect("ed sign");
        let mut bound = canonical.clone();
        bound.extend_from_slice(&ed_sig);
        let pqc_sig = mldsa.sign(&bound).expect("mldsa sign");
        (och, B64.encode(&ed_sig), Some(B64.encode(&pqc_sig)))
    }

    fn key_record(key_id: &str) -> KeyRecord {
        let now = Utc::now();
        let (ed_pk, mldsa_pk) = hybrid_pubkeys(key_id);
        KeyRecord {
            key_id: key_id.into(),
            pubkey_ed25519_base64: ed_pk,
            pubkey_ml_dsa_65_base64: mldsa_pk,
            algorithm: algorithm::HYBRID.into(),
            identity_type: "node".into(),
            identity_ref: format!("node-ref-{key_id}"),
            valid_from: now,
            valid_until: None,
            registration_envelope: serde_json::json!({
                "key_id": key_id,
                "identity_type": "node",
            }),
            original_content_hash: "0".repeat(64),
            scrub_signature_classical: "x".repeat(88),
            scrub_signature_pqc: None,
            scrub_key_id: key_id.into(),
            scrub_timestamp: now,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            capability_roles: Vec::new(),
            attestation_evidence: None,
            consent_role: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A subject-authored `consent:state:{stance}` row naming `scopes`,
    /// pointed at `covers` — byte-shaped as persist's own
    /// `bootstrap_admission::test_support::consent_scope_row` mints it
    /// (the consent representation `resolve_scoped_consent` folds).
    fn consent_row(
        id: &str,
        subject: &str,
        covers: &str,
        stance_dimension: &str,
        asserted_at: DateTime<Utc>,
    ) -> Attestation {
        let envelope = serde_json::json!({
            "dimension": stance_dimension,
            "scope": [CAPACITY_CONSENT_SCOPE],
        });
        let (och, sc, sp) = sign_attestation_envelope(subject, &envelope);
        Attestation {
            attestation_id: id.to_owned(),
            attesting_key_id: subject.to_owned(),
            attested_key_id: covers.to_owned(),
            attestation_type: attestation_type::SCORES.to_owned(),
            weight: None,
            asserted_at,
            expires_at: None,
            attestation_envelope: envelope,
            original_content_hash: och,
            scrub_signature_classical: sc,
            scrub_signature_pqc: sp,
            scrub_key_id: subject.to_owned(),
            scrub_timestamp: asserted_at,
            pqc_completed_at: None,
            persist_row_hash: String::new(),
            subject_key_ids: vec![subject.to_owned()],
            withdraws_admission_rule: None,
            cohort_scope: cohort_scope::FEDERATION.to_owned(),
            tier: attestation_tier::FEDERATION.to_owned(),
            promoted_at: None,
            additional_scrubs: Vec::new(),
        }
    }

    /// A [`LocalSigner`] whose hybrid keys derive from the SAME
    /// deterministic seeds as [`key_record`] — the registered key and the
    /// production signing path collapse to one identity, so the emitted
    /// row verifies at persist's real ingest gate.
    fn local_signer(key_id: &str) -> LocalSigner {
        let seed = seed_for(key_id);
        let classical =
            Arc::new(Ed25519SoftwareSigner::from_bytes(&seed, key_id).expect("ed25519 from_bytes"));
        let pqc = Arc::new(
            MlDsa65SoftwareSigner::from_seed_bytes(&seed, format!("{key_id}-pqc"))
                .expect("ml_dsa_65 from_seed_bytes"),
        );
        LocalSigner::new(key_id, classical, Some(pqc))
    }

    fn observation(consumer_parent: &str) -> DeliveredObservation {
        DeliveredObservation {
            key: ObservationKey::of_claim(&claim(consumer_parent, stream(0x61), 5, 50.0)),
            claimed_uplink_mbps: 50,
            delivered_bytes: 62_500_000, // 500 Mbit over 10 s = 50 Mbps → ratio 1.0
            delivered_chunks: 100,
            window_start_unix_ms: 1_000,
            window_end_unix_ms: 11_000,
        }
    }

    async fn seeded_backend(relay: &str, consumer: &str) -> Arc<MemoryBackend> {
        let backend = Arc::new(MemoryBackend::new());
        for kid in [relay, consumer] {
            backend
                .put_public_key(SignedKeyRecord {
                    record: key_record(kid),
                })
                .await
                .expect("seed key");
        }
        backend
    }

    #[tokio::test]
    async fn emit_withholds_an_empty_window() {
        let backend = Arc::new(MemoryBackend::new());
        let signer = local_signer("cap-consumer-empty");
        let mut obs = observation("cap-relay-empty");
        obs.window_end_unix_ms = obs.window_start_unix_ms; // not a measurement
        let out = emit_delivered_observation(&*backend, &signer, &obs, true, Utc::now())
            .await
            .expect("no fault");
        assert!(
            matches!(
                out,
                DeliveryEmitOutcome::Withheld {
                    reason: DeliveryWithholdReason::EmptyWindow
                }
            ),
            "zero-length window is refused before any gate: {out:?}"
        );
    }

    /// B1/AV-62 mirrored through persist's OWN rule — and ordered BEFORE
    /// the consent gate, so self-emission reports as self-emission
    /// rather than being shadowed by "no consent" (persist's ordering,
    /// for persist's stated reason).
    #[tokio::test]
    async fn emit_refuses_self_emission_via_persists_own_rule() {
        let backend = Arc::new(MemoryBackend::new());
        let signer = local_signer("cap-self");
        let obs = observation("cap-self"); // advertiser == signer
        let out = emit_delivered_observation(&*backend, &signer, &obs, true, Utc::now())
            .await
            .expect("no fault");
        assert!(
            matches!(
                out,
                DeliveryEmitOutcome::Withheld {
                    reason: DeliveryWithholdReason::SelfEmission
                }
            ),
            "self-emission names itself (not 'no consent'): {out:?}"
        );
    }

    /// B5/CC#46 fail-closed: with NO analyze grant from the relay, the
    /// emission is withheld with the resolved stance named — driven
    /// through persist's real `resolve_scoped_consent` fold.
    #[tokio::test]
    async fn emit_withholds_without_the_relays_analyze_grant() {
        let (relay, consumer) = ("cap-relay-ng", "cap-consumer-ng");
        let backend = seeded_backend(relay, consumer).await;
        let signer = local_signer(consumer);
        let out =
            emit_delivered_observation(&*backend, &signer, &observation(relay), true, Utc::now())
                .await
                .expect("no fault");
        match out {
            DeliveryEmitOutcome::Withheld {
                reason: DeliveryWithholdReason::ConsentNotGranted { stance },
            } => assert_eq!(stance, "Unspecified", "the resolved stance is named"),
            other => panic!("expected ConsentNotGranted, got {other:?}"),
        }
    }

    /// The full flip: the relay's live `analyze` grant (seeded through the
    /// REAL `put_attestation` admission, in persist's own consent-row
    /// shape) opens the gate — dry-run yields the signed row, submit lands
    /// it on the scores plane THROUGH persist's own B1+B5 put-gates, and
    /// it reads back keyed to the relay under the edge-named dimension.
    #[tokio::test]
    async fn emit_flips_on_grant_and_lands_on_the_scores_plane() {
        let (relay, consumer) = ("cap-relay-ok", "cap-consumer-ok");
        let backend = seeded_backend(relay, consumer).await;
        let signer = local_signer(consumer);
        let obs = observation(relay);
        let t0 = Utc::now() - chrono::Duration::seconds(120);

        // The relay grants this consumer `analyze`.
        backend
            .put_attestation(SignedAttestation {
                attestation: consent_row(
                    "grant-cap-ok",
                    relay,
                    consumer,
                    &format!("{STATE_GRANTED_PREFIX}:v1"),
                    t0,
                ),
            })
            .await
            .expect("the subject's own analyze grant admits");

        // Dry-run: every edge gate passes; the row is signed + shaped.
        let out = emit_delivered_observation(&*backend, &signer, &obs, true, Utc::now())
            .await
            .expect("no fault");
        let DeliveryEmitOutcome::DryRunAdmissible { attestation } = out else {
            panic!("expected DryRunAdmissible, got {out:?}");
        };
        assert_eq!(
            attestation.attesting_key_id, consumer,
            "attester = consumer"
        );
        assert_eq!(attestation.attested_key_id, relay, "subject = relay");
        assert_eq!(attestation.attestation_type, attestation_type::SCORES);
        assert_eq!(
            attestation.attestation_envelope["dimension"],
            CAPACITY_RELAY_DELIVERY_DIMENSION
        );
        assert_eq!(attestation.attestation_envelope["score"], 1.0);

        // Submit: persist's REAL put-gates (hybrid ingest + B1 + B5) admit it.
        let out = emit_delivered_observation(&*backend, &signer, &obs, false, Utc::now())
            .await
            .expect("submission admits through persist's own gates");
        let DeliveryEmitOutcome::Emitted { attestation_id } = out else {
            panic!("expected Emitted, got {out:?}");
        };

        // Read back: the row is on the relay's scores plane.
        let rows = backend
            .list_attestations_for(relay)
            .await
            .expect("list_attestations_for");
        let found = rows
            .iter()
            .find(|a| a.attestation_id == attestation_id)
            .expect("the emitted row reads back");
        assert_eq!(
            found.attestation_envelope["dimension"],
            CAPACITY_RELAY_DELIVERY_DIMENSION
        );
        assert_eq!(found.attesting_key_id, consumer);
    }

    /// Consent is revocable and the edge gate re-closes: a NEWER
    /// revocation naming the scope flips the fold back, and the refusal
    /// names the stance.
    #[tokio::test]
    async fn revocation_recloses_the_emission_gate() {
        let (relay, consumer) = ("cap-relay-rv", "cap-consumer-rv");
        let backend = seeded_backend(relay, consumer).await;
        let signer = local_signer(consumer);
        let obs = observation(relay);
        let t0 = Utc::now() - chrono::Duration::seconds(120);

        backend
            .put_attestation(SignedAttestation {
                attestation: consent_row(
                    "grant-cap-rv",
                    relay,
                    consumer,
                    &format!("{STATE_GRANTED_PREFIX}:v1"),
                    t0,
                ),
            })
            .await
            .expect("grant admits");
        // Strictly LATER than the grant — the fold is latest-wins.
        backend
            .put_attestation(SignedAttestation {
                attestation: consent_row(
                    "revoke-cap-rv",
                    relay,
                    consumer,
                    &format!("{STATE_REVOKED_PREFIX}:v1"),
                    t0 + chrono::Duration::seconds(60),
                ),
            })
            .await
            .expect("revocation admits");

        let out = emit_delivered_observation(&*backend, &signer, &obs, true, Utc::now())
            .await
            .expect("no fault");
        match out {
            DeliveryEmitOutcome::Withheld {
                reason: DeliveryWithholdReason::ConsentNotGranted { stance },
            } => assert_eq!(stance, "Revoked", "the post-revocation stance is named"),
            other => panic!("expected ConsentNotGranted(Revoked), got {other:?}"),
        }
    }
}
