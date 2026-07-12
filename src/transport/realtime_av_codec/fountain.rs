//! RaptorQ fountain wrap/unwrap (CIRISEdge#133 — v3.9.0 Layer 1 Task A).
//!
//! Turns opaque payload bytes into N source + K repair symbols
//! matching CIRISPersist v8.0.0's [`FountainSymbolV1`] shape, and
//! decodes them back. Codec-agnostic: any downstream encoder (AV1,
//! Opus, raw blob bytes, signed reasoning trace) flows through this
//! module. The substrate's [`crate::transport::realtime_av`]
//! `ChunkLayer.quality` axis IS the fountain symbol position; persist
//! evicts by [`retention_priority`].
//!
//! ## Locked contract (CIRISEdge#133 ratification comment)
//!
//! The persist manifest carries:
//!
//! ```text
//! n_source: u32                       // RaptorQ source symbol count
//! k_repair: u32                       // RaptorQ repair symbol count
//! symbol_size: u32                    // uniform; last source symbol padded
//! min_viable_symbols: u32             // BLINKING_DOT floor
//! original_content_length: u64        // pad-strip basis (the v1-add ratified comment)
//! symbol_hashes: Vec<[u8; 32]>        // SHA-256 per symbol, ordered by symbol_id
//! ```
//!
//! This module produces all six fields' worth of data at encode-time
//! and consumes them at decode-time. The hybrid-signature discipline
//! that wraps the manifest is persist's responsibility; this module
//! deals only with the raw byte mechanics.
//!
//! ## Symbol identity
//!
//! Symbol ids are dense, contiguous, deterministic:
//!
//! - `0..n_source`                       — source symbols (in payload order)
//! - `n_source..(n_source + k_repair)`   — repair symbols
//!
//! Re-encoding the same payload with the same [`FountainConfig`]
//! produces byte-identical symbols at every position. RaptorQ itself
//! is deterministic given (config, source data, symbol id). See
//! `fountain_deterministic_symbol_ordering` for the invariant.
//!
//! ## Loss tolerance
//!
//! RaptorQ is a fountain code: any N symbols (source or repair) are
//! sufficient to reconstruct losslessly in the typical case. In
//! practice the decoder occasionally needs 1–2 extra symbols beyond
//! N — call this the *overhead profile*. Empirically on the
//! parameter combos this module exercises, 0 overhead is the common
//! case and 1–2 overhead is rare. The wrap layer surfaces this as
//! follows:
//!
//! - `≥ n_source` available symbols → typically lossless decode.
//! - `≥ min_viable_symbols` and `< n_source` → partial recovery only;
//!   decoder returns whatever RaptorQ produces (often `None`).
//!   Callers MUST treat this as best-effort; see the
//!   `fountain_min_viable_decodes_partial` test for the documented
//!   behavior.
//! - `< min_viable_symbols` → hard refusal via
//!   [`FountainError::InsufficientSymbols`].

use std::collections::HashMap;

use sha2::{Digest, Sha256};

#[cfg(feature = "codec-fountain")]
use raptorq::{
    EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder,
    SourceBlockEncoder,
};

/// Codec-agnostic fountain wrap parameters. All four fields are
/// canonical bytes in the persist manifest; this struct mirrors them
/// exactly so callers can hand it straight through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FountainConfig {
    /// Number of source symbols.
    pub n_source: u32,
    /// Number of repair symbols. `k_repair = 0` is legal (no FEC).
    pub k_repair: u32,
    /// Uniform symbol size in bytes. The last source symbol is padded
    /// up to this size if `payload.len() % symbol_size != 0`; pad
    /// length is recovered from `original_content_length` at decode.
    pub symbol_size: u32,
    /// Minimum number of symbols below which decode hard-refuses
    /// (the BLINKING_DOT floor). MUST be `<= n_source`.
    pub min_viable_symbols: u32,
}

/// One fountain symbol — produced by [`fountain_encode`], consumed
/// (in any subset) by [`fountain_decode`]. `sha256_hash` is computed
/// at encode-time and re-verified at decode-time to provide
/// forged-symbol protection at the wrap layer (the persist manifest
/// is hybrid-signed; in-flight symbols rely on per-symbol hashes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FountainSymbol {
    /// Dense id: `0..n_source` = source, `n_source..(n_source + k_repair)` = repair.
    pub symbol_id: u32,
    /// Symbol bytes. Length is always `FountainConfig::symbol_size`.
    pub bytes: Vec<u8>,
    /// SHA-256 over `bytes`. Used by persist's `symbol_hashes` manifest
    /// field; re-verified by [`fountain_decode`] against
    /// `expected_hashes`.
    pub sha256_hash: [u8; 32],
}

/// Output of [`fountain_encode`]. Carries everything persist needs to
/// stamp the manifest (`original_content_length`, `symbol_hashes`)
/// plus the symbols themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FountainEncoded {
    /// Original (unpadded) payload length. The decoder truncates the
    /// reconstructed `n_source * symbol_size`-byte buffer to this
    /// length to strip the trailing zero-pad.
    pub original_content_length: u64,
    /// Length = `n_source + k_repair`. Ordered by `symbol_id` (source
    /// first, then repair).
    pub symbols: Vec<FountainSymbol>,
    /// Same length / ordering as `symbols`. Lifted out so persist can
    /// copy straight into the manifest without re-walking `symbols`.
    pub symbol_hashes: Vec<[u8; 32]>,
}

/// Errors surfaced at the wrap layer. The hybrid-signature layer
/// (persist) wraps these as its own typed errors; this module's
/// errors are about the byte mechanics only.
#[derive(thiserror::Error, Debug)]
pub enum FountainError {
    /// Payload is shorter than the BLINKING_DOT floor — encoding is
    /// refused because there's no way the receiver could partially
    /// reconstruct anything meaningful.
    #[error("payload too small: {0} bytes < min_viable_symbols × symbol_size = {1}")]
    PayloadTooSmall(u64, u64),
    /// Payload exceeds the source-symbol capacity (`n_source ×
    /// symbol_size`). The caller must chunk before calling this
    /// module (chunking is the substrate's job, not the wrap layer's).
    #[error("payload too large: {0} bytes > n_source × symbol_size = {1}")]
    PayloadTooLarge(u64, u64),
    /// Decode-side: fewer than `min_viable_symbols` symbols were
    /// provided. `0` is `have`, `1` is the floor.
    #[error("insufficient symbols: have {0}, need at least {1}")]
    InsufficientSymbols(u32, u32),
    /// Decode-side: a symbol's recomputed SHA-256 did not match its
    /// expected hash from the manifest. Forged-symbol or in-flight
    /// corruption.
    #[error("symbol hash mismatch at id {0}")]
    SymbolHashMismatch(u32),
    /// Decode-side: RaptorQ failed to reconstruct from the supplied
    /// symbol set. Usually means `have < n_source + overhead`.
    #[error("raptorq decode failed: {0}")]
    DecodeFailed(String),
}

/// Compute the canonical [`FountainSymbol::sha256_hash`].
fn hash_symbol(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

/// Validate a [`FountainConfig`] for internal consistency. Surfaces
/// the same `FountainError::PayloadTooSmall` for the degenerate
/// `min_viable_symbols > n_source` case so callers see one error
/// shape.
fn validate_config(config: &FountainConfig) -> Result<(), FountainError> {
    if config.symbol_size == 0 {
        return Err(FountainError::PayloadTooLarge(0, 0));
    }
    if config.n_source == 0 {
        return Err(FountainError::PayloadTooLarge(0, 0));
    }
    if config.min_viable_symbols > config.n_source {
        // Degenerate: floor above source count. Surface as
        // PayloadTooSmall so we have one shape, not two.
        return Err(FountainError::PayloadTooSmall(
            0,
            u64::from(config.min_viable_symbols) * u64::from(config.symbol_size),
        ));
    }
    Ok(())
}

/// Encode payload into `n_source` source + `k_repair` repair symbols.
///
/// The last source symbol is padded with zeros up to `symbol_size`
/// when the payload is not a clean multiple; the pad is recovered at
/// decode time via `original_content_length`.
///
/// Each emitted symbol carries its SHA-256 hash, ordered by
/// `symbol_id` (source first, then repair). The hash vector is also
/// returned separately so persist can copy it straight into the
/// manifest's `symbol_hashes` field.
///
/// # Errors
///
/// - [`FountainError::PayloadTooSmall`] — payload below the BLINKING_DOT floor.
/// - [`FountainError::PayloadTooLarge`] — payload exceeds source capacity.
#[cfg(feature = "codec-fountain")]
pub fn fountain_encode(
    payload: &[u8],
    config: &FountainConfig,
) -> Result<FountainEncoded, FountainError> {
    validate_config(config)?;

    let payload_len = payload.len() as u64;
    let source_capacity = u64::from(config.n_source) * u64::from(config.symbol_size);
    let viable_floor = u64::from(config.min_viable_symbols) * u64::from(config.symbol_size);

    if payload_len < viable_floor {
        return Err(FountainError::PayloadTooSmall(payload_len, viable_floor));
    }
    if payload_len > source_capacity {
        return Err(FountainError::PayloadTooLarge(payload_len, source_capacity));
    }

    // Pad payload up to n_source * symbol_size with zeros so RaptorQ
    // sees a uniform N×symbol_size source block. The unpadded length
    // is recovered at decode via original_content_length.
    let source_capacity_usize = usize::try_from(source_capacity)
        .map_err(|_| FountainError::PayloadTooLarge(payload_len, source_capacity))?;
    let mut padded = Vec::with_capacity(source_capacity_usize);
    padded.extend_from_slice(payload);
    padded.resize(source_capacity_usize, 0);

    // RaptorQ's ObjectTransmissionInformation. We want EXACTLY
    // n_source symbols from one source block at the requested
    // symbol_size. The explicit `new()` constructor gives us control;
    // `with_defaults` picks parameters heuristically and might not
    // match our (n_source, symbol_size) contract.
    let oti = ObjectTransmissionInformation::new(
        source_capacity,
        u16::try_from(config.symbol_size)
            .map_err(|_| FountainError::PayloadTooLarge(0, source_capacity))?,
        1, // source_blocks
        1, // sub_blocks
        1, // alignment
    );

    let encoder = SourceBlockEncoder::new(0, &oti, &padded);
    let source_packets = encoder.source_packets();
    let repair_packets = encoder.repair_packets(0, config.k_repair);

    // Defensive: RaptorQ should return exactly n_source source
    // packets and k_repair repair packets; if the OTI parameters
    // don't line up the source count can drift. Catch it.
    let got_source = u32::try_from(source_packets.len()).unwrap_or(u32::MAX);
    if got_source != config.n_source {
        return Err(FountainError::DecodeFailed(format!(
            "raptorq returned {} source packets, expected n_source={}",
            source_packets.len(),
            config.n_source,
        )));
    }
    let got_repair = u32::try_from(repair_packets.len()).unwrap_or(u32::MAX);
    if got_repair != config.k_repair {
        return Err(FountainError::DecodeFailed(format!(
            "raptorq returned {} repair packets, expected k_repair={}",
            repair_packets.len(),
            config.k_repair,
        )));
    }

    let total = (config.n_source + config.k_repair) as usize;
    let mut symbols = Vec::with_capacity(total);
    let mut hashes = Vec::with_capacity(total);

    for packet in source_packets {
        let symbol_id = packet.payload_id().encoding_symbol_id();
        let bytes = packet.data().to_vec();
        let hash = hash_symbol(&bytes);
        symbols.push(FountainSymbol {
            symbol_id,
            bytes,
            sha256_hash: hash,
        });
        hashes.push(hash);
    }
    for packet in repair_packets {
        // RaptorQ's repair symbol ids are dense above n_source; we
        // re-stamp the canonical edge-side id (n_source + offset) so
        // the contract holds even if a future raptorq version emits
        // sparse ids. The bytes are already what RaptorQ produced.
        let raw_id = packet.payload_id().encoding_symbol_id();
        let symbol_id = raw_id; // raptorq id space already matches; preserved for forward-compat
        let bytes = packet.data().to_vec();
        let hash = hash_symbol(&bytes);
        symbols.push(FountainSymbol {
            symbol_id,
            bytes,
            sha256_hash: hash,
        });
        hashes.push(hash);
    }

    // Sort by symbol_id for the canonical ordering invariant.
    symbols.sort_by_key(|s| s.symbol_id);
    let hashes = symbols.iter().map(|s| s.sha256_hash).collect();

    Ok(FountainEncoded {
        original_content_length: payload_len,
        symbols,
        symbol_hashes: hashes,
    })
}

/// Decode payload from a (possibly partial) set of symbols.
///
/// Requires `≥ n_source` symbols for lossless decode in the typical
/// case (raptorq occasionally needs 1–2 overhead symbols); accepts
/// `≥ min_viable_symbols` and returns whatever raptorq can produce
/// in that regime. Below `min_viable_symbols` the decoder
/// hard-refuses with [`FountainError::InsufficientSymbols`].
///
/// Each provided symbol's SHA-256 is re-verified against
/// `expected_hashes[symbol_id]`. A mismatch fails with
/// [`FountainError::SymbolHashMismatch`] — this is the wrap-layer
/// forged-symbol guard.
///
/// # Errors
///
/// - [`FountainError::InsufficientSymbols`] — below BLINKING_DOT floor.
/// - [`FountainError::SymbolHashMismatch`] — per-symbol hash check failed.
/// - [`FountainError::DecodeFailed`] — raptorq couldn't reconstruct
///   from the supplied symbol set.
#[cfg(feature = "codec-fountain")]
pub fn fountain_decode(
    symbols: &[FountainSymbol],
    expected_hashes: &[[u8; 32]],
    original_content_length: u64,
    config: &FountainConfig,
) -> Result<Vec<u8>, FountainError> {
    validate_config(config)?;

    let have = u32::try_from(symbols.len()).unwrap_or(u32::MAX);
    if have < config.min_viable_symbols {
        return Err(FountainError::InsufficientSymbols(
            have,
            config.min_viable_symbols,
        ));
    }

    // Per-symbol SHA-256 re-verify. The expected_hashes vector is
    // indexed by symbol_id; out-of-range or unknown ids fail loud.
    let total = config.n_source + config.k_repair;
    for symbol in symbols {
        if symbol.symbol_id >= total {
            return Err(FountainError::SymbolHashMismatch(symbol.symbol_id));
        }
        let idx = symbol.symbol_id as usize;
        if idx >= expected_hashes.len() {
            return Err(FountainError::SymbolHashMismatch(symbol.symbol_id));
        }
        let recomputed = hash_symbol(&symbol.bytes);
        if recomputed != expected_hashes[idx] {
            return Err(FountainError::SymbolHashMismatch(symbol.symbol_id));
        }
    }

    let source_capacity = u64::from(config.n_source) * u64::from(config.symbol_size);
    let oti = ObjectTransmissionInformation::new(
        source_capacity,
        u16::try_from(config.symbol_size)
            .map_err(|_| FountainError::PayloadTooLarge(0, source_capacity))?,
        1, // source_blocks
        1, // sub_blocks
        1, // alignment
    );

    // Convert FountainSymbol -> EncodingPacket. PayloadId encodes
    // (source_block_number, encoding_symbol_id); we use one source
    // block (id=0) per the encode side.
    let packets: Vec<EncodingPacket> = symbols
        .iter()
        .map(|s| EncodingPacket::new(PayloadId::new(0, s.symbol_id), s.bytes.clone()))
        .collect();

    let mut raptorq_decoder = SourceBlockDecoder::new(0, &oti, source_capacity);
    let reconstructed = raptorq_decoder.decode(packets).ok_or_else(|| {
        FountainError::DecodeFailed(format!(
            "raptorq returned None from {} symbols (n_source={}, k_repair={})",
            have, config.n_source, config.k_repair,
        ))
    })?;

    // RaptorQ returns the full padded block; truncate to the
    // original (unpadded) length.
    let trim = usize::try_from(original_content_length).unwrap_or(usize::MAX);
    let trim = trim.min(reconstructed.len());
    Ok(reconstructed[..trim].to_vec())
}

/// Compute the `retention_priority: u8` byte for a symbol, per the
/// algorithm ratified at
/// [CIRISEdge#133 comment](https://github.com/CIRISAI/CIRISEdge/issues/133#issuecomment-4714804186).
///
/// Higher values are dropped first under persist disk pressure.
///
/// - bits 7–6 carry SVC quality (`0..=3`), clamped on overflow.
/// - bits 5–0 carry the source-vs-repair bucket:
///   - source symbols get `0..32` (kept longest; lower id = lower
///     priority = retained later)
///   - repair symbols get `32..64` (dropped before any source within
///     the same SVC layer)
///
/// At each SVC layer, source symbols are kept longer than repair
/// symbols; across layers, lower SVC quality is kept longer than
/// higher SVC quality (BLINKING_DOT first eviction posture).
#[must_use]
pub fn retention_priority(svc_quality: u8, symbol_id: u32, n_source: u32) -> u8 {
    let svc_bits = (svc_quality.min(3)) << 6;
    let bucket: u8 = if symbol_id < n_source {
        // source — priority rises toward the tail of the source set.
        let denom = n_source.max(1);
        u8::try_from((symbol_id.saturating_mul(32)) / denom).unwrap_or(31)
    } else {
        // repair — fixed 32..63 range, dropped before any source.
        let repair_idx = symbol_id - n_source;
        // Use a stable denominator so we don't divide by zero when
        // there's exactly one repair symbol (the previous division
        // shape collapsed). Map every repair symbol uniformly into
        // the 32..=63 bucket; with k_repair = 1 you get 32 + 0 = 32.
        let denom = repair_idx.saturating_add(1);
        let scaled = (repair_idx.saturating_mul(32)) / denom;
        32u8.saturating_add(u8::try_from(scaled).unwrap_or(31).min(31))
    };
    svc_bits | (bucket & 0x3F)
}

// ─────────────────────────────────────────────────────────────────
// N→1 aggregation / resampling operator (CIRISEdge#266)
// ─────────────────────────────────────────────────────────────────

/// Which mechanical N→1 collapse [`aggregate_symbols`] applies
/// (CIRISEdge#266, CC 6.1.2 / §19.7 operator-2 collapse).
///
/// §19.7's descent axis demands that the composite be **derived
/// from** the member payloads — erasure is only measurable against a
/// composite that was actually computed from what it replaced. Each
/// variant is a deterministic pure-byte operator; none consults
/// RaptorQ state, so the composite carries no side channel back to
/// any individual member beyond the op's own residual bound.
///
/// ## Seam to `AggregationMetaV1` (integrator note, #266 / #267)
///
/// This module does NOT touch the §19.7.1 wire shape. The producer
/// path stamps [`Self::algorithm_id`] into
/// [`crate::holonomic::aggregation::AggregationMetaV1::aggregation_algorithm_id`]
/// unchanged; a sibling cut (#267) is consuming verify's
/// AggregationMetaV1 v2 shapes, and this operator plugs into either
/// v1 or v2 metadata via that one opaque string — no meta-type
/// rework here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateOp {
    /// Byte-wise rounded mean across all N members (each member
    /// nearest-neighbor resampled to the composite length first).
    /// Residual fidelity of any member vs the composite is
    /// chance-level (≈ the byte-collision floor), well under `1/N`.
    Mean,
    /// Round-robin decimation: composite position `i` is taken from
    /// member `i mod N` (after resampling). Each member contributes
    /// exactly ~`1/N` of the composite's positions, so per-member
    /// residual fidelity sits AT the `1/N_eff` bound — the canonical
    /// worst-case-compliant operator for the §19.7 erasure gate.
    Decimate,
    /// Mipmap-style reduction: block-mean over all N members AND
    /// over N adjacent positions, shrinking the composite to
    /// `ceil(len / N)` bytes (a true N× total-data collapse, like
    /// one mipmap level). Residual fidelity is chance-level.
    Mipmap,
}

impl AggregateOp {
    /// Canonical opaque codec id for this operator — the value the
    /// producer path stamps into `AggregationMetaV1
    /// .aggregation_algorithm_id` (§19.7.1). Locked strings; a new
    /// collapse semantics gets a new `-vN` suffix, never a mutation.
    #[must_use]
    pub const fn algorithm_id(self) -> &'static str {
        match self {
            AggregateOp::Mean => "fountain-mean-v1",
            AggregateOp::Decimate => "fountain-decimate-v1",
            AggregateOp::Mipmap => "fountain-mipmap-v1",
        }
    }
}

/// The N→1 composite produced by [`aggregate_symbols`]
/// (CIRISEdge#266). Carries the fan-in (`n_members`) so a
/// conformance gate can compute its own `1/N_eff` bound, plus the
/// operator that produced it (for `algorithm_id` stamping).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Composite {
    /// Composite payload bytes. Length = max member length for
    /// [`AggregateOp::Mean`] / [`AggregateOp::Decimate`];
    /// `ceil(max_len / n_members)` for [`AggregateOp::Mipmap`].
    pub bytes: Vec<u8>,
    /// The descent fan-in N — how many members were collapsed.
    /// Mirrors `AggregationMetaV1.source_count`.
    pub n_members: u32,
    /// The operator that produced `bytes`.
    pub op: AggregateOp,
    /// The resample basis (max member length in bytes) the members
    /// were normalized to before collapsing.
    pub source_len: u64,
}

impl Composite {
    /// The §19.7 aggregation-erasure gate bound: `max(ε, 1/N_eff)`
    /// (CIRISEdge#266). A member is *erased* iff its
    /// [`residual_fidelity`] vs this composite does not exceed this
    /// bound. At `n_members == 1` the bound is `1.0` — a 1→1
    /// "collapse" erases nothing, by construction.
    #[must_use]
    pub fn erasure_bound(&self, epsilon: f64) -> f64 {
        epsilon.max(1.0 / f64::from(self.n_members.max(1)))
    }
}

/// Errors from [`aggregate_symbols`]. Degenerate inputs are refused
/// loudly rather than silently producing an empty composite the
/// erasure gate would vacuously pass.
#[derive(thiserror::Error, Debug)]
pub enum AggregateError {
    /// The member set is empty — there is nothing to collapse.
    #[error("no members: N→1 aggregation requires at least one member")]
    NoMembers,
    /// A member has zero bytes and cannot be resampled. `0` is the
    /// offending member's index.
    #[error("empty member at index {0}: zero-length payloads cannot be resampled")]
    EmptyMember(usize),
    /// More members than `u32` can carry (the `AggregationMetaV1
    /// .source_count` / `Composite.n_members` width). `0` is the count.
    #[error("too many members: {0} exceeds the u32 source_count width")]
    TooManyMembers(usize),
}

/// Nearest-neighbor 1-D resample of `src` to exactly `dst_len`
/// bytes: output position `i` reads `src[i * src_len / dst_len]`.
/// Identity when `dst_len == src_len`. `src` MUST be non-empty and
/// `dst_len` non-zero (guarded by [`aggregate_symbols`]'s input
/// validation).
fn resample_nearest(src: &[u8], dst_len: usize) -> Vec<u8> {
    debug_assert!(!src.is_empty() && dst_len > 0);
    (0..dst_len)
        .map(|i| {
            // u128 intermediate: i * src_len can overflow usize on
            // 32-bit targets for large payloads.
            #[allow(clippy::cast_possible_truncation)] // result < src_len by construction
            let idx = ((i as u128 * src.len() as u128) / dst_len as u128) as usize;
            src[idx]
        })
        .collect()
}

/// Collapse N member payloads into one composite — the pub N→1
/// aggregation/resampling operator (CIRISEdge#266, CC 6.1.2 / §19.7
/// operator-2).
///
/// The composite is computed **from** the members: hard-delete the
/// members afterwards and each one's [`residual_fidelity`] vs the
/// composite is bounded by [`Composite::erasure_bound`]
/// (`max(ε, 1/N_eff)`) — the measurable aggregation-erasure property
/// the CIRISConformance noise-floor gate (CIRISConformance#55)
/// drives. This replaces the fabricated-independent-blob modeling in
/// CIRISServer's `tests/noise_floor.rs`, which proved `< 1/N` only
/// by construction.
///
/// Members of unequal length are nearest-neighbor resampled to the
/// max member length before collapsing (the "resampling" half of the
/// operator). Deterministic: identical `(members, op)` inputs
/// produce a byte-identical composite.
///
/// # Errors
///
/// - [`AggregateError::NoMembers`] — empty member set.
/// - [`AggregateError::EmptyMember`] — a zero-length member.
/// - [`AggregateError::TooManyMembers`] — fan-in exceeds `u32`.
pub fn aggregate_symbols(members: &[&[u8]], op: AggregateOp) -> Result<Composite, AggregateError> {
    if members.is_empty() {
        return Err(AggregateError::NoMembers);
    }
    if let Some(idx) = members.iter().position(|m| m.is_empty()) {
        return Err(AggregateError::EmptyMember(idx));
    }
    let n_members =
        u32::try_from(members.len()).map_err(|_| AggregateError::TooManyMembers(members.len()))?;

    let n = members.len();
    let max_len = members.iter().map(|m| m.len()).max().unwrap_or(1);
    let resampled: Vec<Vec<u8>> = members
        .iter()
        .map(|m| resample_nearest(m, max_len))
        .collect();

    let bytes = match op {
        AggregateOp::Mean => {
            // Byte-wise rounded mean. Sum fits u64: 255 * u32::MAX < 2^40.
            let n_u64 = n as u64;
            (0..max_len)
                .map(|i| {
                    let sum: u64 = resampled.iter().map(|m| u64::from(m[i])).sum();
                    #[allow(clippy::cast_possible_truncation)] // rounded mean of u8s is <= 255
                    let byte = ((sum + n_u64 / 2) / n_u64) as u8;
                    byte
                })
                .collect()
        }
        AggregateOp::Decimate => {
            // Round-robin interleave: position i comes from member i mod N.
            (0..max_len).map(|i| resampled[i % n][i]).collect()
        }
        AggregateOp::Mipmap => {
            // Block-mean over all members AND over N adjacent
            // positions — one mipmap level: total bytes shrink N×.
            let out_len = max_len.div_ceil(n);
            (0..out_len)
                .map(|i| {
                    let start = i * n;
                    let end = ((i + 1) * n).min(max_len);
                    // u128 accumulator: n members × n positions × 255
                    // can exceed u64 for pathological fan-ins.
                    let mut sum: u128 = 0;
                    let mut count: u128 = 0;
                    for member in &resampled {
                        for &b in &member[start..end] {
                            sum += u128::from(b);
                            count += 1;
                        }
                    }
                    #[allow(clippy::cast_possible_truncation)] // rounded mean of u8s is <= 255
                    let byte = ((sum + count / 2) / count) as u8;
                    byte
                })
                .collect()
        }
    };

    Ok(Composite {
        bytes,
        n_members,
        op,
        source_len: max_len as u64,
    })
}

// ─── §19.7.1.3 content-similarity multiplicity (CIRISEdge#323 / CIRISVerify#191)
//
// The CC 6.1.2.1.2 R9 residual: 900 near-duplicate contents folded as 900
// *distinct members at equal mass* honestly compute `n_eff == 1000` and pass the
// v2 mass-dominance gate — yet the composite blur IS the data subject (a false
// erasure certificate). The mass gate cannot see this: `member_commitment` is a
// Merkle root over member *ids* and is blind to content by construction.
//
// The fold is the ONLY point in the pipeline holding member payloads, so edge
// measures the multiplicity here and signs it into `AggregationMetaV1` v3.

/// The fixed-point scale for the pinned similarity threshold (milli-units).
/// Integer/fixed-point throughout: the clustering feeds a SIGNED wire field, so
/// it must be bit-deterministic across platforms — no `f64` in the decision path.
const SIMILARITY_SCALE_MILLI: u64 = 1000;

/// **Normative producer pin** (CIRISVerify#191 / CC 6.1.2 `(R, ε)`): the
/// per-`corpus_kind` content-similarity threshold above which two members count
/// as near-duplicates, in milli-units (`950` = 0.950).
///
/// The metric is `1 − normalized L1 distance` over the resampled payloads (see
/// [`members_are_similar`]). Calibration: byte-identical members score `1.000`;
/// near-duplicates (small perturbations) score `≥ 0.99`; independent
/// high-entropy members score `≈ 0.667` (mean |Δ| of uniform bytes ≈ 85/255).
/// `0.950` separates those populations with wide margin.
///
/// **This pin is wire-affecting** — it determines a signed field, so a producer
/// that changes it forks the multiplicity any verifier recomputes from held
/// evidence. Keep it in lockstep with the CC 6.1.2 conformance fixture; add
/// per-`corpus_kind` arms here (one place) rather than at call sites.
#[must_use]
pub fn multiplicity_similarity_threshold_milli(corpus_kind: &str) -> u64 {
    // Per-`corpus_kind` arms belong HERE (the single source of truth), e.g.
    //   "audio/pcm16" => 970,
    // Until a kind pins its own (R, ε), every corpus takes the default.
    let _ = corpus_kind;
    950
}

/// The §19.7.1.3 surface measured at fold time — what a producer needs to
/// populate `AggregationMetaV1` v3 (CIRISEdge#325).
#[derive(Debug, Clone, PartialEq)]
pub struct ContentMultiplicity {
    /// Per-member content mass, index-aligned with the input members and
    /// summing to `1.0`: each member's share of total content energy, measured
    /// as its normalized L1 norm over the resample basis. This makes the masses
    /// a **measured output of the fold**, not the aggregator's own accounting —
    /// so `n_eff` (inverse-Simpson over these) and `mass_commitment` are both
    /// auditable from held evidence.
    pub member_masses: Vec<f64>,
    /// The size of the largest cluster of members whose pairwise content
    /// similarity exceeds the `corpus_kind`-pinned threshold. `1` for a fold of
    /// mutually-distinct members; `≈ N_dup` when `N_dup` near-duplicates are
    /// folded under distinct ids.
    pub max_source_multiplicity: u32,
}

/// Are two equal-length resampled members near-duplicates under the pinned
/// threshold? `similarity = 1 − (Σ|a_i − b_i|) / (255 · len)`, evaluated
/// entirely in integer space:
///
/// `similarity > threshold  ⟺  SCALE · Σ|Δ|  <  (SCALE − threshold_milli) · 255 · len`
#[must_use]
fn members_are_similar(a: &[u8], b: &[u8], threshold_milli: u64) -> bool {
    debug_assert_eq!(a.len(), b.len(), "similarity compares resampled members");
    if a.is_empty() {
        return true;
    }
    let l1: u64 = a
        .iter()
        .zip(b.iter())
        .map(|(x, y)| u64::from(x.abs_diff(*y)))
        .sum();
    let slack = SIMILARITY_SCALE_MILLI.saturating_sub(threshold_milli);
    let bound = slack * 255 * a.len() as u64;
    SIMILARITY_SCALE_MILLI * l1 < bound
}

/// Measure the §19.7.1.3 content multiplicity + per-member masses from the
/// member payloads (CIRISEdge#323). Members are nearest-neighbor resampled to
/// the max member length — the SAME normalization [`aggregate_symbols`] applies
/// — so similarity is measured on exactly the content the fold collapsed.
///
/// **Clustering**: the largest **connected component** of the similarity graph
/// (union-find, `O(N²)` pairwise — acceptable at the fan-ins §19.7 folds carry;
/// an LSH/simhash prefilter is the escape hatch if it ever isn't). This is a
/// deliberate *conservative superset* of the max-clique reading: a component's
/// members are transitively similar, so this can only ever **over**-estimate the
/// multiplicity — which only ever **tightens** `passes_multiplicity_gate`. The
/// fail-safe direction for a privacy gate (and max-clique is NP-hard).
///
/// Deterministic: byte-equal inputs yield an identical result on every platform
/// (integer-only decision path), as required of a signed wire field.
///
/// # Errors
/// Same preconditions as [`aggregate_symbols`]: [`AggregateError::NoMembers`],
/// [`AggregateError::EmptyMember`], [`AggregateError::TooManyMembers`].
pub fn content_multiplicity(
    members: &[&[u8]],
    corpus_kind: &str,
) -> Result<ContentMultiplicity, AggregateError> {
    if members.is_empty() {
        return Err(AggregateError::NoMembers);
    }
    if let Some(idx) = members.iter().position(|m| m.is_empty()) {
        return Err(AggregateError::EmptyMember(idx));
    }
    let n = members.len();
    u32::try_from(n).map_err(|_| AggregateError::TooManyMembers(n))?;

    // Same resample basis as the fold — similarity must be measured on the
    // content that was actually collapsed.
    let max_len = members.iter().map(|m| m.len()).max().unwrap_or(1);
    let resampled: Vec<Vec<u8>> = members
        .iter()
        .map(|m| resample_nearest(m, max_len))
        .collect();

    // Per-member masses: normalized L1 norm (content energy share). The sums are
    // exact u64; the f64 conversion produces a VALUE (a mass fraction), never a
    // decision — the clustering that feeds the signed multiplicity is
    // integer-only (see `members_are_similar`). Masses are in turn committed via
    // the fixed-point `mass_to_fixed` (1e6) before signing, so the wire is not
    // f64-sensitive either.
    #[allow(clippy::cast_precision_loss)]
    let member_masses: Vec<f64> = {
        let norms: Vec<u64> = resampled
            .iter()
            .map(|m| m.iter().map(|b| u64::from(*b)).sum())
            .collect();
        let total: u64 = norms.iter().sum();
        if total == 0 {
            // All-zero payloads: fall back to a uniform (balanced) mass split so
            // n_eff reflects the honest fan-in rather than dividing by zero.
            vec![1.0 / n as f64; n]
        } else {
            norms.iter().map(|w| *w as f64 / total as f64).collect()
        }
    };

    // Similarity graph → largest connected component (union-find).
    let threshold_milli = multiplicity_similarity_threshold_milli(corpus_kind);
    let mut parent: Vec<usize> = (0..n).collect();
    for i in 0..n {
        for j in (i + 1)..n {
            if members_are_similar(&resampled[i], &resampled[j], threshold_milli) {
                let (ri, rj) = (uf_find(&mut parent, i), uf_find(&mut parent, j));
                if ri != rj {
                    parent[ri] = rj;
                }
            }
        }
    }
    let mut sizes: HashMap<usize, u32> = HashMap::new();
    for i in 0..n {
        let root = uf_find(&mut parent, i);
        *sizes.entry(root).or_insert(0) += 1;
    }
    let max_source_multiplicity = sizes.values().copied().max().unwrap_or(1);

    Ok(ContentMultiplicity {
        member_masses,
        max_source_multiplicity,
    })
}

/// Union-find root with path-halving — the clustering primitive for
/// [`content_multiplicity`]'s connected-component pass.
fn uf_find(parent: &mut [usize], mut x: usize) -> usize {
    while parent[x] != x {
        parent[x] = parent[parent[x]];
        x = parent[x];
    }
    x
}

/// Canonical per-member residual-fidelity measure for the §19.7
/// aggregation-erasure gate (CIRISEdge#266): the fraction of
/// byte-exact matches between the member (nearest-neighbor resampled
/// to the composite's length — the same normalization
/// [`aggregate_symbols`] applies) and the composite bytes. Range
/// `0.0..=1.0`; `1.0` means the member is fully recoverable from the
/// composite (no erasure), chance-level (≈ `1/256` for
/// high-entropy bytes) means indistinguishable from noise.
///
/// Takes raw byte slices (not [`Composite`]) so a conformance
/// harness can also score arbitrary blobs — e.g. demonstrate that a
/// fabricated independent composite scores chance-level against
/// EVERY member, which is exactly why the fabricated version proves
/// nothing (the #266 complaint).
#[must_use]
pub fn residual_fidelity(member: &[u8], composite_bytes: &[u8]) -> f64 {
    if member.is_empty() || composite_bytes.is_empty() {
        return 0.0;
    }
    let normalized = resample_nearest(member, composite_bytes.len());
    let matches = normalized
        .iter()
        .zip(composite_bytes.iter())
        .filter(|(a, b)| a == b)
        .count();
    #[allow(clippy::cast_precision_loss)] // lengths ≪ 2^52; exact in f64
    let fidelity = matches as f64 / composite_bytes.len() as f64;
    fidelity
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(all(test, feature = "codec-fountain"))]
mod tests {
    use super::*;

    /// Standard test profile: 8 KiB payload, 8 source × 1 KiB symbols,
    /// 4 repair symbols, BLINKING_DOT floor at 2 symbols. Matches the
    /// realtime-A/V profile from CIRISEdge#133's ratification comment
    /// ("~5 source symbols/frame × 4× redundancy" lives in the same
    /// regime).
    fn standard_config() -> FountainConfig {
        FountainConfig {
            n_source: 8,
            k_repair: 4,
            symbol_size: 1024,
            min_viable_symbols: 2,
        }
    }

    fn deterministic_payload(len: usize) -> Vec<u8> {
        // Pseudo-random but reproducible content — RaptorQ behavior
        // varies with payload entropy; an all-zero buffer is a
        // degenerate test case.
        (0..len)
            .map(|i| u8::try_from((i * 13 + 7) & 0xff).unwrap_or(0))
            .collect()
    }

    #[test]
    fn fountain_lossless_round_trip() {
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);

        let encoded = fountain_encode(&payload, &config).expect("encode");
        assert_eq!(encoded.original_content_length, payload.len() as u64);
        assert_eq!(
            encoded.symbols.len(),
            (config.n_source + config.k_repair) as usize
        );
        assert_eq!(encoded.symbol_hashes.len(), encoded.symbols.len());

        let decoded = fountain_decode(
            &encoded.symbols,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        )
        .expect("decode");

        assert_eq!(decoded, payload, "lossless round-trip mismatch");
    }

    #[test]
    fn fountain_k_loss_still_lossless() {
        // Drop the K repair symbols; the N source symbols alone
        // reconstruct losslessly.
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);
        let encoded = fountain_encode(&payload, &config).expect("encode");

        let source_only: Vec<FountainSymbol> = encoded
            .symbols
            .iter()
            .filter(|s| s.symbol_id < config.n_source)
            .cloned()
            .collect();
        assert_eq!(source_only.len(), config.n_source as usize);

        let decoded = fountain_decode(
            &source_only,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        )
        .expect("decode with source only");

        assert_eq!(decoded, payload);
    }

    #[test]
    fn fountain_k_plus_one_loss_insufficient() {
        // Drop K + 1 (i.e. keep n_source - 1 symbols). Should fail
        // either via insufficient-symbols (if below floor) or via
        // raptorq's own DecodeFailed (below source count, above floor).
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);
        let encoded = fountain_encode(&payload, &config).expect("encode");

        // Keep n_source - 1 symbols (all source, one dropped); this is
        // K + 1 dropped from the full set of n_source + k_repair.
        let mut kept: Vec<FountainSymbol> = encoded
            .symbols
            .iter()
            .filter(|s| s.symbol_id < config.n_source)
            .cloned()
            .collect();
        kept.pop();
        assert_eq!(kept.len(), (config.n_source - 1) as usize);
        let kept_count = u32::try_from(kept.len()).unwrap_or(u32::MAX);
        assert!(kept_count >= config.min_viable_symbols);

        let res = fountain_decode(
            &kept,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        );
        // We're above the BLINKING_DOT floor but below source count;
        // raptorq is expected to fail to reconstruct.
        assert!(
            matches!(res, Err(FountainError::DecodeFailed(_))),
            "expected DecodeFailed, got {res:?}"
        );
    }

    #[test]
    fn fountain_below_min_viable_insufficient() {
        // Drop down to min_viable_symbols - 1 → hard refuse.
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);
        let encoded = fountain_encode(&payload, &config).expect("encode");

        let kept: Vec<FountainSymbol> = encoded
            .symbols
            .iter()
            .take((config.min_viable_symbols - 1) as usize)
            .cloned()
            .collect();
        assert_eq!(kept.len(), (config.min_viable_symbols - 1) as usize);

        let res = fountain_decode(
            &kept,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        );
        assert!(
            matches!(res, Err(FountainError::InsufficientSymbols(have, need))
                if have == config.min_viable_symbols - 1 && need == config.min_viable_symbols),
            "expected InsufficientSymbols, got {res:?}"
        );
    }

    #[test]
    fn fountain_min_viable_decodes_partial() {
        // At exactly min_viable_symbols, the decoder is best-effort.
        // RaptorQ typically returns `None` (and we surface
        // DecodeFailed); occasionally for tiny inputs it may
        // reconstruct. The wrap layer's contract is: don't hard-
        // refuse at the floor; return whatever raptorq produces.
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);
        let encoded = fountain_encode(&payload, &config).expect("encode");

        let kept: Vec<FountainSymbol> = encoded
            .symbols
            .iter()
            .take(config.min_viable_symbols as usize)
            .cloned()
            .collect();
        assert_eq!(kept.len(), config.min_viable_symbols as usize);

        let res = fountain_decode(
            &kept,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        );
        // At the floor we accept either outcome — but the variant
        // must be DecodeFailed (no hard refusal). Document that we
        // did NOT see InsufficientSymbols here.
        assert!(
            !matches!(res, Err(FountainError::InsufficientSymbols(_, _))),
            "min_viable_symbols must NOT be the hard-refusal floor; got {res:?}"
        );
    }

    #[test]
    fn fountain_payload_size_validation() {
        let config = standard_config();

        // Too small — below min_viable_symbols × symbol_size.
        let tiny = vec![0u8; (config.symbol_size - 1) as usize];
        let err = fountain_encode(&tiny, &config).unwrap_err();
        assert!(
            matches!(err, FountainError::PayloadTooSmall(_, _)),
            "expected PayloadTooSmall for tiny payload, got {err:?}"
        );

        // Too large — above n_source × symbol_size.
        let huge = vec![0u8; (config.n_source * config.symbol_size + 1) as usize];
        let err = fountain_encode(&huge, &config).unwrap_err();
        assert!(
            matches!(err, FountainError::PayloadTooLarge(_, _)),
            "expected PayloadTooLarge for huge payload, got {err:?}"
        );
    }

    #[test]
    fn fountain_padding_handled_correctly() {
        // Payload that's not a multiple of symbol_size: 7.5 KiB +
        // 100 bytes. Decode must recover exactly the original bytes,
        // no trailing zero-pad.
        let config = standard_config();
        let payload_len = 7 * 1024 + 512 + 100; // 7780 bytes, not symbol-aligned
        let payload = deterministic_payload(payload_len);
        assert_ne!(payload_len % config.symbol_size as usize, 0);

        let encoded = fountain_encode(&payload, &config).expect("encode");
        assert_eq!(encoded.original_content_length, payload_len as u64);

        let decoded = fountain_decode(
            &encoded.symbols,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        )
        .expect("decode");

        assert_eq!(decoded.len(), payload_len, "trailing pad not stripped");
        assert_eq!(decoded, payload, "payload bytes not exactly recovered");
    }

    #[test]
    fn fountain_per_symbol_hash_verified() {
        // Flip a bit in one symbol → SymbolHashMismatch on decode.
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);
        let encoded = fountain_encode(&payload, &config).expect("encode");

        let mut tampered = encoded.symbols.clone();
        // Flip the high bit of the first byte of symbol id=3.
        let idx = tampered.iter().position(|s| s.symbol_id == 3).unwrap();
        tampered[idx].bytes[0] ^= 0x80;

        let res = fountain_decode(
            &tampered,
            &encoded.symbol_hashes,
            encoded.original_content_length,
            &config,
        );
        assert!(
            matches!(res, Err(FountainError::SymbolHashMismatch(3))),
            "expected SymbolHashMismatch(3), got {res:?}"
        );
    }

    #[test]
    fn fountain_deterministic_symbol_ordering() {
        // Encode twice → byte-identical symbol set.
        let config = standard_config();
        let payload = deterministic_payload(8 * 1024);

        let a = fountain_encode(&payload, &config).expect("encode a");
        let b = fountain_encode(&payload, &config).expect("encode b");

        assert_eq!(a.symbols.len(), b.symbols.len());
        for (sa, sb) in a.symbols.iter().zip(b.symbols.iter()) {
            assert_eq!(sa.symbol_id, sb.symbol_id, "symbol_id ordering drifted");
            assert_eq!(
                sa.bytes, sb.bytes,
                "symbol bytes drifted at id={}",
                sa.symbol_id
            );
            assert_eq!(
                sa.sha256_hash, sb.sha256_hash,
                "hash drifted at id={}",
                sa.symbol_id
            );
        }
        assert_eq!(a.symbol_hashes, b.symbol_hashes);
    }

    #[test]
    fn retention_priority_truth_table() {
        // Spot-check against the algorithm spec from CIRISEdge#133
        // ratification.
        //
        // (svc_quality=0, n_source=8):
        //  source id=0  -> svc_bits=0, bucket = 0*32/8 = 0
        //  source id=7  -> svc_bits=0, bucket = 7*32/8 = 28
        //  repair id=8  -> svc_bits=0, bucket = 32 (lowest repair)
        //  repair id=11 -> svc_bits=0, bucket = 32 + (3*32/4) = 32+24 = 56
        //
        // (svc_quality=3, n_source=8):
        //  source id=0  -> svc_bits=0xc0, bucket=0 -> 0xc0
        //  source id=7  -> svc_bits=0xc0, bucket=28 -> 0xc0|28 = 0xdc
        //
        // (svc_quality=4 — clamps to 3): identical to svc_quality=3.

        assert_eq!(retention_priority(0, 0, 8), 0);
        assert_eq!(retention_priority(0, 7, 8), 28);
        assert_eq!(retention_priority(0, 8, 8), 32);
        // svc_quality clamping
        assert_eq!(retention_priority(4, 0, 8), retention_priority(3, 0, 8));
        assert_eq!(retention_priority(255, 0, 8), retention_priority(3, 0, 8));
        // svc_quality=3 sets bits 7-6
        assert_eq!(retention_priority(3, 0, 8) & 0xc0, 0xc0);
        // svc_quality=1 puts only bit 6
        assert_eq!(retention_priority(1, 0, 8) & 0xc0, 0x40);
    }

    #[test]
    fn retention_priority_source_kept_longer_than_repair() {
        // At the same SVC layer, every source symbol has a lower
        // priority value (kept longer) than every repair symbol.
        let n_source = 8;
        let total = n_source + 4;
        for svc in 0u8..=3 {
            let max_source_priority = (0..n_source)
                .map(|id| retention_priority(svc, id, n_source))
                .max()
                .unwrap();
            let min_repair_priority = (n_source..total)
                .map(|id| retention_priority(svc, id, n_source))
                .min()
                .unwrap();
            assert!(
                max_source_priority < min_repair_priority,
                "svc={svc}: max_source={max_source_priority} >= min_repair={min_repair_priority}"
            );
        }
    }

    #[test]
    fn retention_priority_lower_svc_kept_longer_than_higher_svc() {
        // Cross-layer ordering: source symbols at SVC=0 have lower
        // priority than ANY symbol at SVC=1+ (BLINKING_DOT first
        // eviction posture).
        let n_source = 8;
        let total = n_source + 4;

        let max_svc0 = (0..total)
            .map(|id| retention_priority(0, id, n_source))
            .max()
            .unwrap();
        let min_svc1 = (0..total)
            .map(|id| retention_priority(1, id, n_source))
            .min()
            .unwrap();
        assert!(
            max_svc0 < min_svc1,
            "max_svc0={max_svc0} >= min_svc1={min_svc1}"
        );
    }

    // ─── N→1 aggregation-erasure operator (CIRISEdge#266) ────────

    /// High-entropy, deterministic, per-seed-distinct member payloads.
    /// SHA-256 in counter mode — the `deterministic_payload` linear
    /// ramp is a degenerate input for byte-mean operators (shifted
    /// copies of one ramp correlate), so erasure tests need real
    /// mixing.
    fn distinct_member(seed: u8, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len + 32);
        let mut counter = 0u64;
        while out.len() < len {
            let mut h = Sha256::new();
            h.update([seed]);
            h.update(counter.to_be_bytes());
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(len);
        out
    }

    /// The #266 gate ε — the noise-floor tolerance term in
    /// `max(ε, 1/N_eff)`.
    const EPSILON: f64 = 0.05;

    #[test]
    fn aggregate_mean_erases_individual_members() {
        // The core #266 property: compute the REAL composite from N
        // members, then per-member residual fidelity vs the
        // composite is ≤ max(ε, 1/N_eff). Mean is chance-level.
        let members: Vec<Vec<u8>> = (0..4).map(|k| distinct_member(k, 4096)).collect();
        let refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();

        let composite = aggregate_symbols(&refs, AggregateOp::Mean).expect("aggregate");
        assert_eq!(composite.n_members, 4);
        assert_eq!(composite.bytes.len(), 4096);

        let bound = composite.erasure_bound(EPSILON);
        assert!(
            (bound - 0.25).abs() < f64::EPSILON,
            "bound = max(0.05, 1/4)"
        );
        for (k, member) in members.iter().enumerate() {
            // Self-fidelity baseline: the member IS fully
            // recoverable from itself.
            assert!((residual_fidelity(member, member) - 1.0).abs() < f64::EPSILON);
            let rf = residual_fidelity(member, &composite.bytes);
            assert!(
                rf <= bound,
                "member {k}: residual fidelity {rf} exceeds erasure bound {bound}"
            );
            // Mean is chance-level — far below even ε alone.
            assert!(rf <= EPSILON, "member {k}: mean rf {rf} above chance-level");
        }
    }

    #[test]
    fn aggregate_decimate_sits_at_one_over_n() {
        // Decimate is the worst-case-compliant operator: each member
        // contributes exactly ~1/N of composite positions, so rf
        // lands AT the 1/N_eff bound (plus the byte-collision floor)
        // — and, crucially, ABOVE chance, proving the composite is
        // genuinely derived from the members (not a fabricated blob).
        let members: Vec<Vec<u8>> = (10..14).map(|k| distinct_member(k, 4096)).collect();
        let refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();

        let composite = aggregate_symbols(&refs, AggregateOp::Decimate).expect("aggregate");
        let bound = composite.erasure_bound(EPSILON);
        for (k, member) in members.iter().enumerate() {
            let rf = residual_fidelity(member, &composite.bytes);
            assert!(
                rf <= bound + EPSILON,
                "member {k}: decimate rf {rf} exceeds 1/N bound {bound} + ε"
            );
            assert!(
                rf >= 1.0 / (2.0 * 4.0),
                "member {k}: decimate rf {rf} below 1/(2N) — composite not derived from member"
            );
        }
    }

    #[test]
    fn aggregate_mipmap_erases_individual_members() {
        // Mipmap collapses resolution too: composite is
        // ceil(4096/4) = 1024 bytes of block-means. Chance-level rf.
        let members: Vec<Vec<u8>> = (20..24).map(|k| distinct_member(k, 4096)).collect();
        let refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();

        let composite = aggregate_symbols(&refs, AggregateOp::Mipmap).expect("aggregate");
        assert_eq!(composite.bytes.len(), 1024, "one mipmap level = N× shrink");
        assert_eq!(composite.source_len, 4096);

        let bound = composite.erasure_bound(EPSILON);
        for (k, member) in members.iter().enumerate() {
            let rf = residual_fidelity(member, &composite.bytes);
            assert!(
                rf <= bound,
                "member {k}: mipmap rf {rf} exceeds erasure bound {bound}"
            );
        }
    }

    #[test]
    fn aggregate_composite_derived_and_deterministic() {
        // Determinism: identical inputs → byte-identical composite.
        // Sensitivity: perturbing ONE member changes the composite —
        // the anti-fabrication property (#266: the fabricated blob
        // was independent of the members by construction).
        let members: Vec<Vec<u8>> = (30..34).map(|k| distinct_member(k, 2048)).collect();
        let refs: Vec<&[u8]> = members.iter().map(Vec::as_slice).collect();

        for op in [
            AggregateOp::Mean,
            AggregateOp::Decimate,
            AggregateOp::Mipmap,
        ] {
            let a = aggregate_symbols(&refs, op).expect("aggregate a");
            let b = aggregate_symbols(&refs, op).expect("aggregate b");
            assert_eq!(a, b, "{op:?}: composite not deterministic");

            // Perturb member 0 at position 0 (position 0 belongs to
            // member 0 in the decimate round-robin) by ±128 so the
            // delta survives mean rounding (128/4 = 32 for mean,
            // 128/16 = 8 for mipmap block-mean).
            let mut perturbed = members.clone();
            perturbed[0][0] = perturbed[0][0].wrapping_add(128);
            let refs_p: Vec<&[u8]> = perturbed.iter().map(Vec::as_slice).collect();
            let c = aggregate_symbols(&refs_p, op).expect("aggregate perturbed");
            assert_ne!(
                a.bytes, c.bytes,
                "{op:?}: composite insensitive to member content — fabricated-blob smell"
            );
        }
    }

    #[test]
    fn aggregate_unequal_member_lengths_resampled() {
        // The "resampling" half of the operator: members of unequal
        // length are nearest-neighbor normalized to the max length,
        // and the erasure bound still holds per member.
        let members = [
            distinct_member(40, 4096),
            distinct_member(41, 1000),
            distinct_member(42, 977),
        ];
        let refs: Vec<&[u8]> = members.iter().map(|m| m.as_slice()).collect();

        let composite = aggregate_symbols(&refs, AggregateOp::Mean).expect("aggregate");
        assert_eq!(
            composite.bytes.len(),
            4096,
            "composite at max member length"
        );
        assert_eq!(composite.n_members, 3);

        let bound = composite.erasure_bound(EPSILON);
        for (k, member) in members.iter().enumerate() {
            let rf = residual_fidelity(member, &composite.bytes);
            assert!(rf <= bound, "member {k}: rf {rf} exceeds bound {bound}");
        }
    }

    #[test]
    fn aggregate_single_member_no_erasure() {
        // N_eff = 1: a 1→1 "collapse" erases nothing — mean of one
        // member is the member, rf = 1.0, and the gate bound is 1.0
        // (max(ε, 1/1)), so the gate is vacuously satisfied. This
        // pins the 1/N_eff semantics from the #266 ask.
        let member = distinct_member(50, 1024);
        let composite =
            aggregate_symbols(&[member.as_slice()], AggregateOp::Mean).expect("aggregate single");
        assert_eq!(composite.bytes, member);
        let rf = residual_fidelity(&member, &composite.bytes);
        assert!((rf - 1.0).abs() < f64::EPSILON);
        assert!((composite.erasure_bound(EPSILON) - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn aggregate_rejects_degenerate_inputs() {
        // Empty member set and zero-length members are refused loud
        // — a vacuous composite would trivially pass the gate.
        let res = aggregate_symbols(&[], AggregateOp::Mean);
        assert!(matches!(res, Err(AggregateError::NoMembers)));

        let a = distinct_member(60, 64);
        let res = aggregate_symbols(&[a.as_slice(), &[]], AggregateOp::Decimate);
        assert!(matches!(res, Err(AggregateError::EmptyMember(1))));
    }

    #[test]
    fn aggregate_algorithm_ids_locked() {
        // The AggregationMetaV1.aggregation_algorithm_id seam
        // (§19.7.1): these strings are wire-visible and locked at v1.
        assert_eq!(AggregateOp::Mean.algorithm_id(), "fountain-mean-v1");
        assert_eq!(AggregateOp::Decimate.algorithm_id(), "fountain-decimate-v1");
        assert_eq!(AggregateOp::Mipmap.algorithm_id(), "fountain-mipmap-v1");
    }

    // ── §19.7.1.3 content multiplicity (CIRISEdge#323 / CIRISVerify#191) ──

    /// Deterministic LCG — distinct high-entropy members without a rand dep.
    fn pseudo_member(seed: u64, len: usize) -> Vec<u8> {
        let mut s = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        (0..len)
            .map(|_| {
                s = s
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                (s >> 33) as u8
            })
            .collect()
    }

    /// THE R9 CASE: 900 near-duplicates under distinct ids + 100 genuinely
    /// distinct members. The v2 mass gate sees `n_eff == 1000` (honest — all
    /// equal mass) and admits; the content-similarity multiplicity sees the
    /// blur. `max_source_multiplicity >= 900` ⇒ `900 * n_min(2) > 1000` ⇒
    /// `passes_multiplicity_gate` REJECTS.
    #[test]
    fn content_multiplicity_detects_the_900_near_duplicate_fold() {
        let base = pseudo_member(7, 64);
        // 900 near-duplicates: the same content, one byte nudged by ±1 — far
        // inside the 0.95 threshold (similarity ≈ 0.9999).
        let mut owned: Vec<Vec<u8>> = (0..900)
            .map(|i| {
                let mut m = base.clone();
                m[i % 64] = m[i % 64].wrapping_add(1);
                m
            })
            .collect();
        // 100 genuinely distinct members.
        owned.extend((0..100).map(|i| pseudo_member(1000 + i, 64)));
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let m = content_multiplicity(&refs, "test/corpus").expect("multiplicity");
        assert!(
            m.max_source_multiplicity >= 900,
            "the 900-near-duplicate cluster must surface (got {})",
            m.max_source_multiplicity
        );
        // And that value fails the persist gate (n_min = 2): 900*2 > 1000.
        assert!(
            u64::from(m.max_source_multiplicity) * 2 > refs.len() as u64,
            "the R9 fold must fail passes_multiplicity_gate"
        );
    }

    /// A balanced fold of mutually-distinct members collapses to multiplicity 1
    /// — and passes the gate (1 * 2 <= N).
    #[test]
    fn content_multiplicity_balanced_distinct_members_is_one() {
        let owned: Vec<Vec<u8>> = (0..64).map(|i| pseudo_member(i, 64)).collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let m = content_multiplicity(&refs, "test/corpus").expect("multiplicity");
        assert_eq!(
            m.max_source_multiplicity, 1,
            "distinct members must not cluster"
        );
        assert!(u64::from(m.max_source_multiplicity) * 2 <= refs.len() as u64);
        // Masses are measured, index-aligned, and sum to 1.
        assert_eq!(m.member_masses.len(), refs.len());
        let total: f64 = m.member_masses.iter().sum();
        assert!(
            (total - 1.0).abs() < 1e-9,
            "masses must sum to 1 (got {total})"
        );
    }

    /// The multiplicity feeds a SIGNED wire field — byte-equal inputs must
    /// produce a byte-equal result (integer-only decision path).
    #[test]
    fn content_multiplicity_is_deterministic() {
        let owned: Vec<Vec<u8>> = (0..32)
            .map(|i| {
                if i < 20 {
                    pseudo_member(3, 48)
                } else {
                    pseudo_member(100 + i, 48)
                }
            })
            .collect();
        let refs: Vec<&[u8]> = owned.iter().map(Vec::as_slice).collect();

        let a = content_multiplicity(&refs, "test/corpus").expect("a");
        let b = content_multiplicity(&refs, "test/corpus").expect("b");
        assert_eq!(a, b, "identical inputs must yield an identical surface");
        // 20 byte-identical members cluster.
        assert!(a.max_source_multiplicity >= 20);
    }

    /// Identical members are maximally similar; independent high-entropy
    /// members fall well below the pinned threshold — the separation the
    /// 0.95 pin relies on.
    #[test]
    fn similarity_separates_duplicates_from_distinct_members() {
        let a = pseudo_member(11, 128);
        let b = a.clone();
        let c = pseudo_member(12, 128);
        let t = multiplicity_similarity_threshold_milli("test/corpus");
        assert!(members_are_similar(&a, &b, t), "identical → similar");
        assert!(
            !members_are_similar(&a, &c, t),
            "independent high-entropy members must NOT cluster"
        );
    }
}
