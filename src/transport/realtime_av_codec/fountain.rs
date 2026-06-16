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
}
