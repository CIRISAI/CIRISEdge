//! Opus voice codec adapter — libopus 1.x via the `opus` crate
//! (CIRISEdge#133 Layer 1 Task C, v3.9.0).
//!
//! Opus is the WebRTC / Discord / Mumble baseline: 5–26.5 ms
//! algorithmic delay (Opus 1.6), royalty-free, IETF RFC 6716. This
//! module wraps the `opus` crate's `Encoder` / `Decoder` behind a
//! CIRIS-shaped surface that the realtime A/V mesh + relay surfaces
//! consume as the voice lane's codec adapter.
//!
//! ## Module name (`opus_voice`, not `opus`)
//!
//! The crate name is `opus`. If this sub-module were also named
//! `opus` the `use opus::*;` patterns inside the module would
//! collide with the path `crate::transport::realtime_av_codec::opus`
//! at any caller that does `use crate::transport::realtime_av_codec`
//! and then `use opus::Encoder`. Naming the sub-module `opus_voice`
//! (and the public types `OpusVoiceEncoder` / `OpusVoiceDecoder`)
//! sidesteps the collision permanently.
//!
//! ## What this module IS
//!
//! - [`OpusVoiceEncoder`] / [`OpusVoiceDecoder`] — thin wrappers over
//!   `opus::Encoder` / `opus::Decoder` with config validation and a
//!   CIRIS-shaped error type.
//! - [`OpusEncoderConfig`] — the validated config shape (sample rate
//!   ∈ {8, 12, 16, 24, 48} kHz; channels ∈ {1, 2}; frame duration
//!   ∈ {2.5, 5, 10, 20, 40, 60} ms).
//! - [`OpusVoiceDecoder::decode_lost_frame`] — packet-loss
//!   concealment. The decoder synthesizes silence / extrapolation when
//!   a frame is lost. Critical for the holographic mesh's
//!   "any subset reconstructs at proportional fidelity" property at
//!   the voice layer: a lost frame returns PCM of the expected length
//!   (silence / decoder's PLC), not a length-zero gap that desyncs the
//!   playback clock.
//!
//! ## What this module is NOT
//!
//! - **A transport.** Encoded bytes flow into the realtime A/V mesh /
//!   relay surface as `chunk_plaintext`; this module never touches
//!   the transit / epoch keys.
//! - **A jitter buffer.** The decoder is stateless across calls; the
//!   caller owns playout scheduling.
//! - **A video codec.** Subsequent v3.9.0 layers (Task D and beyond)
//!   add AV1 / H.265 adapters.

use opus::{Application as OpusApp, Bitrate, Channels, Decoder, Encoder};

/// Opus application mode — the codec internally picks SILK (speech) vs
/// CELT (general audio) vs hybrid based on this hint + the configured
/// frame size + bitrate. Mirrors `opus::Application`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpusApplication {
    /// Optimized for speech, lowest CPU + delay budget. The default
    /// for voice calls.
    Voip,
    /// Optimized for general audio (music). Higher quality but more
    /// CPU + larger frame budget.
    Audio,
    /// Tighter delay budget than `Voip`. Used by realtime control
    /// surfaces where latency dominates intelligibility (e.g. live
    /// musical performance, low-latency monitoring).
    LowDelay,
}

impl From<OpusApplication> for OpusApp {
    fn from(app: OpusApplication) -> Self {
        match app {
            OpusApplication::Voip => OpusApp::Voip,
            OpusApplication::Audio => OpusApp::Audio,
            OpusApplication::LowDelay => OpusApp::LowDelay,
        }
    }
}

/// Validated encoder configuration. Construct via the public-field
/// literal syntax; validation happens in [`OpusVoiceEncoder::new`].
#[derive(Debug, Clone)]
pub struct OpusEncoderConfig {
    /// Sample rate in Hz. Opus accepts {8 000, 12 000, 16 000, 24 000,
    /// 48 000}. Any other value → `OpusError::InvalidConfig`.
    pub sample_rate_hz: u32,
    /// 1 = mono, 2 = stereo. Any other value → `OpusError::InvalidConfig`.
    pub channels: u8,
    /// Application hint — see [`OpusApplication`].
    pub application: OpusApplication,
    /// Target bitrate in kbps. `None` lets opus decide (CBR-ish auto).
    /// Bounded by the codec to a sensible range; very low values may
    /// be rounded up.
    pub bitrate_kbps: Option<u32>,
    /// Frame duration in ms. Opus accepts {2.5, 5, 10, 20, 40, 60} ms;
    /// expressed here as `u8`. The 2.5 ms slot is encoded as `0` and
    /// MUST be set via the [`OpusEncoderConfig::FRAME_2_5_MS`]
    /// constant — `0` is otherwise rejected.
    pub frame_duration_ms: u8,
}

impl OpusEncoderConfig {
    /// Sentinel value for the 2.5 ms frame slot (the only sub-ms-
    /// granularity opus duration; can't be expressed natively in a
    /// `u8` ms field).
    pub const FRAME_2_5_MS: u8 = 0;

    /// Returns the number of PCM samples per channel that one frame
    /// at this config holds. Multiply by `channels` for the total
    /// interleaved-PCM buffer size.
    pub fn samples_per_channel(&self) -> usize {
        // Special-case the 2.5 ms slot.
        let sr = self.sample_rate_hz as usize;
        if self.frame_duration_ms == Self::FRAME_2_5_MS {
            // 2.5 ms = sample_rate * 25 / 10000
            sr * 25 / 10_000
        } else {
            sr * self.frame_duration_ms as usize / 1000
        }
    }
}

/// Decoded PCM frame — interleaved i16 samples, native byte order.
/// `pcm_i16.len() == sample_rate_hz × duration_s × channels`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusFrame {
    /// Interleaved if stereo (L, R, L, R, ...).
    pub pcm_i16: Vec<i16>,
    pub sample_rate_hz: u32,
    pub channels: u8,
}

/// Encoded Opus packet — the codec output bytes plus the frame
/// duration the decoder needs for sizing its output buffer (since
/// the encoded packet itself doesn't carry a self-describing
/// duration field in our wire shape; the mesh / relay surfaces
/// carry it alongside).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusEncodedFrame {
    pub bytes: Vec<u8>,
    pub frame_duration_ms: u8,
}

/// Maximum encoded packet size opus might produce per RFC 6716
/// §3.1: a TOC byte + up to 1275 bytes of payload per 20 ms frame,
/// plus inter-frame framing. We size the encode buffer at 4000 B
/// (the size the opus reference encoder docs recommend as a safe
/// upper bound for any single frame).
const MAX_ENCODED_FRAME_BYTES: usize = 4000;

/// Errors surfaced by the opus codec adapter.
#[derive(thiserror::Error, Debug)]
pub enum OpusError {
    #[error("opus config invalid: {0}")]
    InvalidConfig(String),
    #[error("opus encode failed: {0}")]
    EncodeFailed(String),
    #[error("opus decode failed: {0}")]
    DecodeFailed(String),
    #[error("pcm size mismatch: expected {expected} samples, got {actual}")]
    PcmSizeMismatch { expected: usize, actual: usize },
}

/// Validate sample rate + channels into the `opus` crate's enum.
fn validate_channels(channels: u8) -> Result<Channels, OpusError> {
    match channels {
        1 => Ok(Channels::Mono),
        2 => Ok(Channels::Stereo),
        n => Err(OpusError::InvalidConfig(format!(
            "channels must be 1 (mono) or 2 (stereo); got {n}"
        ))),
    }
}

/// Validate the sample rate against Opus's permitted set.
fn validate_sample_rate(sample_rate_hz: u32) -> Result<(), OpusError> {
    match sample_rate_hz {
        8_000 | 12_000 | 16_000 | 24_000 | 48_000 => Ok(()),
        n => Err(OpusError::InvalidConfig(format!(
            "sample_rate_hz must be one of {{8000, 12000, 16000, 24000, 48000}}; got {n}"
        ))),
    }
}

/// Validate a frame duration ms value (2.5 / 5 / 10 / 20 / 40 / 60).
fn validate_frame_duration(frame_duration_ms: u8) -> Result<(), OpusError> {
    match frame_duration_ms {
        // 0 is the 2.5 ms sentinel.
        OpusEncoderConfig::FRAME_2_5_MS | 5 | 10 | 20 | 40 | 60 => Ok(()),
        n => Err(OpusError::InvalidConfig(format!(
            "frame_duration_ms must be one of {{0(=2.5), 5, 10, 20, 40, 60}}; got {n}"
        ))),
    }
}

/// Opus voice encoder. Stateful across frames (the codec carries
/// inter-frame prediction state); construct one per stream.
pub struct OpusVoiceEncoder {
    inner: Encoder,
    config: OpusEncoderConfig,
    samples_per_channel: usize,
    expected_pcm_len: usize,
}

impl OpusVoiceEncoder {
    /// Construct a new encoder from a validated config. Errors:
    /// `InvalidConfig` for any out-of-range field; otherwise the
    /// underlying `opus::Encoder::new` error is wrapped as
    /// `EncodeFailed` (constructor errors are vanishingly rare —
    /// libopus rejects nothing the validated config admits).
    pub fn new(config: OpusEncoderConfig) -> Result<Self, OpusError> {
        validate_sample_rate(config.sample_rate_hz)?;
        let channels = validate_channels(config.channels)?;
        validate_frame_duration(config.frame_duration_ms)?;

        let mut inner = Encoder::new(config.sample_rate_hz, channels, config.application.into())
            .map_err(|e| OpusError::EncodeFailed(format!("encoder init: {e}")))?;

        if let Some(kbps) = config.bitrate_kbps {
            let bps = i32::try_from(kbps).map_err(|_| {
                OpusError::InvalidConfig(format!("bitrate_kbps overflows i32: {kbps}"))
            })?;
            let bps = bps.checked_mul(1000).ok_or_else(|| {
                OpusError::InvalidConfig(format!("bitrate_kbps * 1000 overflows: {kbps}"))
            })?;
            inner
                .set_bitrate(Bitrate::Bits(bps))
                .map_err(|e| OpusError::EncodeFailed(format!("set_bitrate: {e}")))?;
        }

        let samples_per_channel = config.samples_per_channel();
        let expected_pcm_len = samples_per_channel * config.channels as usize;
        Ok(Self {
            inner,
            config,
            samples_per_channel,
            expected_pcm_len,
        })
    }

    /// Encode one frame's worth of PCM. The PCM length must be exactly
    /// `sample_rate_hz × frame_duration_ms / 1000 × channels` samples
    /// (interleaved if stereo). A wrong length is the most common
    /// caller bug — surface it as `PcmSizeMismatch` BEFORE handing the
    /// bytes to libopus (libopus's error message in that case is
    /// `BadArg`, which obscures the cause).
    pub fn encode(&mut self, frame: &OpusFrame) -> Result<OpusEncodedFrame, OpusError> {
        if frame.sample_rate_hz != self.config.sample_rate_hz {
            return Err(OpusError::InvalidConfig(format!(
                "frame sample_rate_hz {} does not match encoder config {}",
                frame.sample_rate_hz, self.config.sample_rate_hz
            )));
        }
        if frame.channels != self.config.channels {
            return Err(OpusError::InvalidConfig(format!(
                "frame channels {} does not match encoder config {}",
                frame.channels, self.config.channels
            )));
        }
        if frame.pcm_i16.len() != self.expected_pcm_len {
            return Err(OpusError::PcmSizeMismatch {
                expected: self.expected_pcm_len,
                actual: frame.pcm_i16.len(),
            });
        }

        let mut out = vec![0u8; MAX_ENCODED_FRAME_BYTES];
        let n = self
            .inner
            .encode(&frame.pcm_i16, &mut out)
            .map_err(|e| OpusError::EncodeFailed(format!("{e}")))?;
        out.truncate(n);
        Ok(OpusEncodedFrame {
            bytes: out,
            frame_duration_ms: self.config.frame_duration_ms,
        })
    }

    /// Samples per channel that one frame at this encoder's config
    /// holds. Exposed so callers can size their PCM ring buffer.
    pub fn samples_per_channel(&self) -> usize {
        self.samples_per_channel
    }
}

/// Opus voice decoder. Stateful across frames (the codec carries
/// PLC + inter-frame state); construct one per stream.
pub struct OpusVoiceDecoder {
    inner: Decoder,
    sample_rate_hz: u32,
    channels: u8,
}

impl OpusVoiceDecoder {
    /// Construct a new decoder. The decoder does not need to know
    /// the application mode (Voip / Audio / LowDelay); that's an
    /// encoder hint only.
    pub fn new(sample_rate_hz: u32, channels: u8) -> Result<Self, OpusError> {
        validate_sample_rate(sample_rate_hz)?;
        let opus_channels = validate_channels(channels)?;
        let inner = Decoder::new(sample_rate_hz, opus_channels)
            .map_err(|e| OpusError::DecodeFailed(format!("decoder init: {e}")))?;
        Ok(Self {
            inner,
            sample_rate_hz,
            channels,
        })
    }

    /// Decode an encoded packet to interleaved i16 PCM. The output
    /// length is determined by the encoded packet's internal
    /// duration field (libopus extracts it); we trust libopus's
    /// answer over the `frame_duration_ms` on `OpusEncodedFrame`
    /// (which is hinted only) — libopus would reject a mismatch as
    /// `BufferTooSmall`.
    pub fn decode(&mut self, encoded: &OpusEncodedFrame) -> Result<OpusFrame, OpusError> {
        let samples_per_channel =
            samples_per_channel_for(self.sample_rate_hz, encoded.frame_duration_ms)?;
        let total = samples_per_channel * self.channels as usize;
        let mut pcm = vec![0i16; total];
        // `fec=false` — we're decoding a present packet, not concealing
        // a lost one (PLC lives on `decode_lost_frame`).
        let decoded_samples_per_channel = self
            .inner
            .decode(&encoded.bytes, &mut pcm, false)
            .map_err(|e| OpusError::DecodeFailed(format!("{e}")))?;
        // libopus returns samples per channel; trim the buffer in case
        // it returned fewer than we sized for (rare; happens if the
        // encoded packet's internal duration differs from
        // `frame_duration_ms`).
        let decoded_total = decoded_samples_per_channel * self.channels as usize;
        pcm.truncate(decoded_total);
        Ok(OpusFrame {
            pcm_i16: pcm,
            sample_rate_hz: self.sample_rate_hz,
            channels: self.channels,
        })
    }

    /// Synthesize a lost frame via libopus's packet-loss concealment.
    /// The PCM returned has the same length as a normal `decode` would
    /// have produced for a frame of `frame_duration_ms` — critical for
    /// the holographic mesh's "any subset reconstructs at proportional
    /// fidelity" property at the voice layer (the playback clock stays
    /// aligned even when a frame is dropped).
    ///
    /// libopus's PLC mechanism: pass an empty input slice to `decode`.
    /// The codec extrapolates from prior state (or emits silence on
    /// cold-start).
    pub fn decode_lost_frame(&mut self, frame_duration_ms: u8) -> Result<OpusFrame, OpusError> {
        validate_frame_duration(frame_duration_ms)?;
        let samples_per_channel = samples_per_channel_for(self.sample_rate_hz, frame_duration_ms)?;
        let total = samples_per_channel * self.channels as usize;
        let mut pcm = vec![0i16; total];
        // libopus PLC convention: empty input slice → "the frame at
        // this position was lost; please conceal".
        let decoded_samples_per_channel = self
            .inner
            .decode(&[], &mut pcm, false)
            .map_err(|e| OpusError::DecodeFailed(format!("plc: {e}")))?;
        let decoded_total = decoded_samples_per_channel * self.channels as usize;
        pcm.truncate(decoded_total);
        Ok(OpusFrame {
            pcm_i16: pcm,
            sample_rate_hz: self.sample_rate_hz,
            channels: self.channels,
        })
    }
}

fn samples_per_channel_for(sample_rate_hz: u32, frame_duration_ms: u8) -> Result<usize, OpusError> {
    validate_frame_duration(frame_duration_ms)?;
    let sr = sample_rate_hz as usize;
    if frame_duration_ms == OpusEncoderConfig::FRAME_2_5_MS {
        Ok(sr * 25 / 10_000)
    } else {
        Ok(sr * frame_duration_ms as usize / 1000)
    }
}

// ── tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic sine wave at `freq_hz` for the given
    /// duration. Used as the round-trip fixture: Opus is lossy, so we
    /// can't byte-compare PCM-in vs PCM-out — but a sine wave's
    /// dominant frequency survives encode/decode with high SNR.
    #[allow(
        clippy::cast_precision_loss,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss
    )]
    fn sine_pcm(
        sample_rate_hz: u32,
        channels: u8,
        samples_per_channel: usize,
        freq_hz: f32,
    ) -> Vec<i16> {
        let mut out = Vec::with_capacity(samples_per_channel * channels as usize);
        let two_pi = 2.0 * std::f32::consts::PI;
        for n in 0..samples_per_channel {
            let t = n as f32 / sample_rate_hz as f32;
            let s = (two_pi * freq_hz * t).sin();
            // Scale to ~half-range to avoid clipping after codec
            // overshoot.
            let i = (s * 16_000.0) as i16;
            for _ in 0..channels {
                out.push(i);
            }
        }
        out
    }

    /// PSNR between two i16 PCM buffers. Returns +∞ for byte-identical
    /// inputs. Opus voice round-trip typically clears 25 dB at decent
    /// bitrates; we set the assertion floor well below that.
    #[allow(clippy::cast_precision_loss)]
    fn pcm_psnr_db(reference: &[i16], decoded: &[i16]) -> f64 {
        assert_eq!(reference.len(), decoded.len(), "psnr length mismatch");
        if reference.is_empty() {
            return f64::INFINITY;
        }
        let mut sse: f64 = 0.0;
        for (&r, &d) in reference.iter().zip(decoded.iter()) {
            let diff = f64::from(r) - f64::from(d);
            sse += diff * diff;
        }
        let mse = sse / reference.len() as f64;
        if mse == 0.0 {
            return f64::INFINITY;
        }
        // PSNR using full i16 peak.
        let peak = f64::from(i16::MAX);
        10.0 * (peak * peak / mse).log10()
    }

    #[test]
    fn opus_voip_round_trip() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 16_000,
            channels: 1,
            application: OpusApplication::Voip,
            bitrate_kbps: Some(32),
            frame_duration_ms: 20,
        };
        let samples_per_channel = config.samples_per_channel();
        assert_eq!(samples_per_channel, 320);

        let mut enc = OpusVoiceEncoder::new(config.clone()).expect("enc new");
        let mut dec = OpusVoiceDecoder::new(16_000, 1).expect("dec new");

        // Run several frames through to let the codec settle (Opus's
        // first few frames carry significant startup distortion that
        // would skew a single-frame PSNR measurement).
        let mut total_decoded: Vec<i16> = Vec::new();
        let mut total_reference: Vec<i16> = Vec::new();
        for _ in 0..10 {
            let pcm = sine_pcm(16_000, 1, samples_per_channel, 440.0);
            let frame = OpusFrame {
                pcm_i16: pcm.clone(),
                sample_rate_hz: 16_000,
                channels: 1,
            };
            let encoded = enc.encode(&frame).expect("encode");
            assert!(!encoded.bytes.is_empty(), "encoded bytes empty");
            let decoded = dec.decode(&encoded).expect("decode");
            assert_eq!(decoded.pcm_i16.len(), samples_per_channel);
            total_reference.extend_from_slice(&pcm);
            total_decoded.extend_from_slice(&decoded.pcm_i16);
        }

        // Drop the first 3 frames (codec warm-up) before computing
        // PSNR.
        let drop = 3 * samples_per_channel;
        let psnr = pcm_psnr_db(&total_reference[drop..], &total_decoded[drop..]);
        // Opus 32 kbps mono 16 kHz on a pure sine should clear ~15 dB
        // PSNR comfortably (the codec is psychoacoustic, not waveform-
        // fitting; sine fidelity is reasonable but not stellar).
        assert!(
            psnr > 10.0,
            "voip round-trip PSNR {psnr:.2} dB below 10 dB floor"
        );
    }

    #[test]
    fn opus_stereo_audio_round_trip() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 48_000,
            channels: 2,
            application: OpusApplication::Audio,
            bitrate_kbps: Some(96),
            frame_duration_ms: 20,
        };
        let samples_per_channel = config.samples_per_channel();
        assert_eq!(samples_per_channel, 960);

        let mut enc = OpusVoiceEncoder::new(config.clone()).expect("enc new");
        let mut dec = OpusVoiceDecoder::new(48_000, 2).expect("dec new");

        for _ in 0..5 {
            let pcm = sine_pcm(48_000, 2, samples_per_channel, 880.0);
            let frame = OpusFrame {
                pcm_i16: pcm,
                sample_rate_hz: 48_000,
                channels: 2,
            };
            let encoded = enc.encode(&frame).expect("encode");
            assert!(!encoded.bytes.is_empty(), "encoded bytes empty");
            let decoded = dec.decode(&encoded).expect("decode");
            assert_eq!(decoded.pcm_i16.len(), samples_per_channel * 2);
            assert_eq!(decoded.channels, 2);
            assert_eq!(decoded.sample_rate_hz, 48_000);
        }
    }

    #[test]
    fn opus_low_delay_config() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 48_000,
            channels: 1,
            application: OpusApplication::LowDelay,
            bitrate_kbps: Some(64),
            frame_duration_ms: 5,
        };
        let samples_per_channel = config.samples_per_channel();
        assert_eq!(samples_per_channel, 240);

        let mut enc = OpusVoiceEncoder::new(config.clone()).expect("enc new");
        let mut dec = OpusVoiceDecoder::new(48_000, 1).expect("dec new");

        let pcm = sine_pcm(48_000, 1, samples_per_channel, 1000.0);
        let frame = OpusFrame {
            pcm_i16: pcm,
            sample_rate_hz: 48_000,
            channels: 1,
        };
        let encoded = enc.encode(&frame).expect("encode");
        // 5 ms low-delay at 64 kbps: encoded packet very small (sub-
        // MTU; well under 500 B).
        assert!(
            encoded.bytes.len() < 500,
            "low-delay 5ms packet {} bytes — expected < 500",
            encoded.bytes.len()
        );
        let decoded = dec.decode(&encoded).expect("decode");
        assert_eq!(decoded.pcm_i16.len(), samples_per_channel);
    }

    #[test]
    fn opus_pcm_size_validation() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 16_000,
            channels: 1,
            application: OpusApplication::Voip,
            bitrate_kbps: Some(24),
            frame_duration_ms: 20,
        };
        let mut enc = OpusVoiceEncoder::new(config).expect("enc new");
        // 20 ms @ 16 kHz mono = 320 samples; pass 256.
        let frame = OpusFrame {
            pcm_i16: vec![0; 256],
            sample_rate_hz: 16_000,
            channels: 1,
        };
        match enc.encode(&frame) {
            Err(OpusError::PcmSizeMismatch { expected, actual }) => {
                assert_eq!(expected, 320);
                assert_eq!(actual, 256);
            }
            Err(other) => panic!("expected PcmSizeMismatch, got error: {other}"),
            Ok(_) => panic!("expected PcmSizeMismatch, got Ok"),
        }
    }

    #[test]
    fn opus_plc_synthesizes_lost_frame() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 16_000,
            channels: 1,
            application: OpusApplication::Voip,
            bitrate_kbps: Some(32),
            frame_duration_ms: 20,
        };
        let samples_per_channel = config.samples_per_channel();
        let mut enc = OpusVoiceEncoder::new(config).expect("enc new");
        let mut dec = OpusVoiceDecoder::new(16_000, 1).expect("dec new");

        // Encode 3 frames.
        let pcm = sine_pcm(16_000, 1, samples_per_channel, 440.0);
        let f1 = OpusFrame {
            pcm_i16: pcm.clone(),
            sample_rate_hz: 16_000,
            channels: 1,
        };
        let f2 = OpusFrame {
            pcm_i16: pcm.clone(),
            sample_rate_hz: 16_000,
            channels: 1,
        };
        let f3 = OpusFrame {
            pcm_i16: pcm,
            sample_rate_hz: 16_000,
            channels: 1,
        };
        let e1 = enc.encode(&f1).expect("encode 1");
        let _e2 = enc.encode(&f2).expect("encode 2");
        let e3 = enc.encode(&f3).expect("encode 3");

        // Decode 1, PLC for 2, decode 3. All three must yield PCM of
        // the expected length — that's the load-bearing property
        // (proportional-fidelity playback clock alignment).
        let d1 = dec.decode(&e1).expect("decode 1");
        let d2 = dec.decode_lost_frame(20).expect("plc");
        let d3 = dec.decode(&e3).expect("decode 3");
        assert_eq!(d1.pcm_i16.len(), samples_per_channel, "d1 len");
        assert_eq!(d2.pcm_i16.len(), samples_per_channel, "plc len");
        assert_eq!(d3.pcm_i16.len(), samples_per_channel, "d3 len");
    }

    #[test]
    fn opus_bitrate_constraint_respected() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 16_000,
            channels: 1,
            application: OpusApplication::Voip,
            bitrate_kbps: Some(8),
            frame_duration_ms: 20,
        };
        let samples_per_channel = config.samples_per_channel();
        let mut enc = OpusVoiceEncoder::new(config).expect("enc new");

        // 20 ms @ 8 kbps = 160 bits = 20 bytes/frame target. Allow a
        // generous upper bound (overhead, codec startup) — anything
        // under 60 B per frame confirms the constraint is in effect.
        // Without the bitrate cap, the codec defaults to ~32 kbps for
        // 16 kHz mono, producing ~80 B/frame.
        let mut max_bytes = 0;
        for _ in 0..20 {
            let pcm = sine_pcm(16_000, 1, samples_per_channel, 440.0);
            let frame = OpusFrame {
                pcm_i16: pcm,
                sample_rate_hz: 16_000,
                channels: 1,
            };
            let encoded = enc.encode(&frame).expect("encode");
            max_bytes = max_bytes.max(encoded.bytes.len());
        }
        assert!(
            max_bytes < 60,
            "max encoded bytes {max_bytes} exceeds 8 kbps budget (expected < 60)",
        );
    }

    #[test]
    fn opus_invalid_sample_rate_rejected() {
        let config = OpusEncoderConfig {
            sample_rate_hz: 22_050, // not in {8/12/16/24/48} kHz
            channels: 1,
            application: OpusApplication::Voip,
            bitrate_kbps: None,
            frame_duration_ms: 20,
        };
        match OpusVoiceEncoder::new(config) {
            Err(OpusError::InvalidConfig(msg)) => {
                assert!(msg.contains("22050"), "msg should mention 22050: {msg}");
            }
            Err(other) => panic!("expected InvalidConfig, got error: {other}"),
            Ok(_) => panic!("expected InvalidConfig, got Ok"),
        }

        match OpusVoiceDecoder::new(22_050, 1) {
            Err(OpusError::InvalidConfig(_)) => {}
            Err(other) => panic!("expected InvalidConfig for decoder, got error: {other}"),
            Ok(_) => panic!("expected InvalidConfig for decoder, got Ok"),
        }
    }
}
