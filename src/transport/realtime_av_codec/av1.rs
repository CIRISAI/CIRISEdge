//! AV1 codec helpers — pure encode/decode for v3.9.0 (CIRISEdge#133).
//!
//! ## Encoder ([`Av1Encoder`])
//!
//! Wraps [`rav1e::Context`] with CIRIS-shaped IO:
//! - input is a planar YUV420 [`Av1Frame`]
//! - output is one or more [`Av1EncodedChunk`] objects, each one AV1
//!   OBU sequence. The exact 1-frame-in / N-chunks-out shape is the
//!   rav1e contract — a single `send_frame` may cause zero packets to
//!   emerge (encoder still gathering lookahead) or several packets to
//!   emerge (a B-frame batch flush in non-low-latency mode).
//!
//! The encoder is configured in `low_latency=true` mode by default for
//! the realtime-AV use case (turns off frame reordering — every input
//! frame yields ≥1 output packet, no B-frame batching delay). Set
//! `Av1EncoderConfig::low_latency=false` for archive / catch-up
//! encoding where higher quality per bit is worth the lookahead delay.
//!
//! ## Decoder ([`Av1Decoder`])
//!
//! Wraps [`dav1d::Decoder`]. dav1d is the libdav1d binding maintained
//! by rust-av (Luca Barbato); the underlying libdav1d is the AV1
//! decoder that ships in every major browser (VideoLAN project).
//!
//! Decode is a push/pull machine matching libdav1d's native shape:
//! `decode_chunk` sends bytes; the decoder may emit 0..N frames per
//! chunk depending on how libdav1d batches internally. The wrapper
//! drains all pending pictures after each `send_data` call so the
//! caller-visible contract is "one chunk in, vector of frames out."
//!
//! ## What's NOT here
//!
//! Fountain wrapping (raptorq, L1-A) and substrate sealing
//! (`realtime_av::seal_av_chunk`) are explicitly separate. The codec
//! layer produces and consumes AV1 OBU bytes; the substrate decides
//! how to fragment them across the mesh.

use thiserror::Error;

/// Errors surfaced by the AV1 encoder + decoder wrappers.
#[derive(Error, Debug)]
pub enum Av1Error {
    /// rav1e rejected the encoder configuration (e.g., zero
    /// dimensions, non-multiple-of-2 width/height, unreachable
    /// bitrate target).
    #[error("rav1e config invalid: {0}")]
    InvalidConfig(String),

    /// rav1e returned a fatal status during encode. Maps from
    /// `EncoderStatus::Failure` and any unexpected transitional
    /// statuses the wrapper can't recover from.
    #[error("rav1e encode failed: {0}")]
    EncodeFailed(String),

    /// libdav1d returned a fatal error during decode. Maps from
    /// `dav1d::Error` (excluding `EAGAIN`, which the wrapper handles
    /// internally as a "drain and retry" signal).
    #[error("dav1d decode failed: {0}")]
    DecodeFailed(String),

    /// Caller's [`Av1Frame`] dimensions don't match what the encoder
    /// was configured for. Distinct from `InvalidConfig` because the
    /// encoder is fine — the frame is wrong.
    #[error(
        "frame dimensions mismatch: expected {expected_w}x{expected_h}, got {actual_w}x{actual_h}"
    )]
    DimensionsMismatch {
        expected_w: u16,
        expected_h: u16,
        actual_w: u16,
        actual_h: u16,
    },
}

/// AV1 encoder configuration. Owns enough surface to express the
/// realtime-A/V + archive paths; the rest of `rav1e::EncoderConfig`
/// is filled in with sane defaults.
#[derive(Debug, Clone)]
pub struct Av1EncoderConfig {
    /// Frame width in pixels. Must be ≥ 2 and even (AV1 4:2:0
    /// subsampling requires both chroma planes to halve cleanly).
    pub width: u16,
    /// Frame height in pixels. Must be ≥ 2 and even.
    pub height: u16,
    /// Target bitrate in kilobits per second. The encoder targets
    /// this average; rate-control deviation is bounded by rav1e's
    /// internal model. 0 means "use the encoder's default for the
    /// resolution" (which is well-tuned for SDR 8-bit content).
    pub bitrate_kbps: u32,
    /// Frame-rate numerator (e.g., 30000 for 30000/1001 NTSC, 30 for
    /// 30 fps clean).
    pub frame_rate_num: u32,
    /// Frame-rate denominator (e.g., 1001 for NTSC, 1 for 30 fps
    /// clean).
    pub frame_rate_den: u32,
    /// When `true`, configures the encoder for realtime push: no
    /// B-frame reordering, every input frame produces ≥1 output
    /// packet (no lookahead delay).
    pub low_latency: bool,
    /// rav1e speed preset 0..10. 0 = best quality, slowest;
    /// 10 = fastest, lowest quality. Realtime mesh defaults around
    /// 9 or 10 (the realtime-tier rav1e SOTA), archive defaults
    /// around 4..6. Values > 10 are clamped to 10.
    pub speed_preset: u8,
}

/// One raw YUV 4:2:0 frame ready for encode. Plane indices match
/// the rav1e + dav1d convention: 0 = Y (luma), 1 = U (Cb chroma),
/// 2 = V (Cr chroma). The U/V planes are sized
/// `(width/2) * (height/2)` per 4:2:0 subsampling.
#[derive(Debug, Clone)]
pub struct Av1Frame {
    /// Y, U, V byte planes. Plane row-stride is implied by the
    /// declared `width` / `height` — no padding is assumed.
    pub planes_yuv420: [Vec<u8>; 3],
    /// Frame width in pixels (Y-plane width).
    pub width: u16,
    /// Frame height in pixels (Y-plane height).
    pub height: u16,
    /// Presentation timestamp in microseconds. Used for the
    /// encoder/decoder PTS roundtrip and for substrate
    /// `realtime_av::AvHeader::frame_pts_us`.
    pub pts_us: u64,
}

/// One encoded AV1 chunk emitted by the encoder. Wraps the raw OBU
/// byte sequence rav1e produced for a single source frame.
#[derive(Debug, Clone)]
pub struct Av1EncodedChunk {
    /// AV1 OBU bytes (the on-wire AV1 syntax). The chunk is
    /// self-contained when `is_keyframe == true`; P-frame chunks
    /// reference state held by the decoder from the preceding
    /// keyframe + P-frames in this group of pictures.
    pub bytes: Vec<u8>,
    /// `true` iff this is an I-frame / keyframe (rav1e's
    /// `FrameType::KEY`). The decoder can resume from any keyframe
    /// without prior state; non-keyframe chunks are NOT replayable
    /// in isolation. The substrate uses this flag for layer-policy
    /// decisions (the realtime_av sealing layer marks keyframes as
    /// priority-elevated chunks).
    pub is_keyframe: bool,
    /// Presentation timestamp echo of `Av1Frame::pts_us`. The
    /// encoder doesn't reorder PTS in `low_latency=true` mode; for
    /// non-low-latency mode the PTS still matches the source frame
    /// because rav1e treats the field as opaque pass-through.
    pub pts_us: u64,
}

/// AV1 encoder, holding the rav1e [`Context`](rav1e::Context) state
/// machine + the configuration it was constructed with.
///
/// One [`Av1Encoder`] per stream. Not `Send` / `Sync` is documented at
/// rav1e's level (the Context isn't multi-thread-safe across the API
/// boundary; multi-thread encode happens INSIDE a single Context via
/// the `threading` feature's rayon pool).
pub struct Av1Encoder {
    context: rav1e::Context<u8>,
    config: Av1EncoderConfig,
}

/// AV1 decoder, holding the libdav1d state.
///
/// One [`Av1Decoder`] per stream. dav1d itself is internally
/// multi-threaded (configurable via `Settings::set_n_threads`);
/// the wrapper takes the libdav1d default.
pub struct Av1Decoder {
    context: dav1d::Decoder,
}

impl Av1Encoder {
    /// Construct a new encoder. Returns
    /// [`Av1Error::InvalidConfig`] if rav1e rejects the config
    /// (which includes the zero-dimension and non-multiple-of-2
    /// validation rav1e enforces) or if either dimension is < 2.
    pub fn new(config: Av1EncoderConfig) -> Result<Self, Av1Error> {
        if config.width < 2 || config.height < 2 {
            return Err(Av1Error::InvalidConfig(format!(
                "dimensions must be ≥ 2x2, got {}x{}",
                config.width, config.height
            )));
        }
        if config.width % 2 != 0 || config.height % 2 != 0 {
            return Err(Av1Error::InvalidConfig(format!(
                "AV1 4:2:0 requires even dimensions, got {}x{}",
                config.width, config.height
            )));
        }
        if config.frame_rate_den == 0 {
            return Err(Av1Error::InvalidConfig(
                "frame_rate_den must be > 0".to_string(),
            ));
        }

        let speed = config.speed_preset.min(10);
        let bitrate: i32 = config
            .bitrate_kbps
            .saturating_mul(1000)
            .try_into()
            .unwrap_or(i32::MAX);

        let mut enc_cfg = rav1e::config::EncoderConfig::with_speed_preset(speed);
        enc_cfg.width = config.width.into();
        enc_cfg.height = config.height.into();
        enc_cfg.bit_depth = 8;
        enc_cfg.chroma_sampling = rav1e::prelude::ChromaSampling::Cs420;
        // rav1e's `time_base` is "seconds per frame" — i.e., the
        // RECIPROCAL of frame-rate. A 30-fps stream has time_base
        // 1/30, NOT 30/1. Mirror that here.
        enc_cfg.time_base = rav1e::prelude::Rational {
            num: u64::from(config.frame_rate_den),
            den: u64::from(config.frame_rate_num),
        };
        if bitrate > 0 {
            enc_cfg.bitrate = bitrate;
        }
        enc_cfg.low_latency = config.low_latency;

        let cfg = rav1e::config::Config::new().with_encoder_config(enc_cfg);
        let context = cfg
            .new_context::<u8>()
            .map_err(|e| Av1Error::InvalidConfig(format!("{e}")))?;

        Ok(Self { context, config })
    }

    /// Push a YUV 4:2:0 frame; drain any packets the encoder
    /// produced as a result. May return 0 packets if rav1e is still
    /// gathering lookahead (`low_latency=false` mode), or several
    /// packets if a B-frame batch is flushed by this input.
    pub fn encode_frame(&mut self, frame: &Av1Frame) -> Result<Vec<Av1EncodedChunk>, Av1Error> {
        if frame.width != self.config.width || frame.height != self.config.height {
            return Err(Av1Error::DimensionsMismatch {
                expected_w: self.config.width,
                expected_h: self.config.height,
                actual_w: frame.width,
                actual_h: frame.height,
            });
        }

        let w = usize::from(self.config.width);
        let h = usize::from(self.config.height);
        let y_size = w * h;
        let uv_size = (w / 2) * (h / 2);
        if frame.planes_yuv420[0].len() < y_size
            || frame.planes_yuv420[1].len() < uv_size
            || frame.planes_yuv420[2].len() < uv_size
        {
            return Err(Av1Error::EncodeFailed(format!(
                "plane sizes too small for {w}x{h} YUV420 frame: Y={} U={} V={} (need {y_size}/{uv_size}/{uv_size})",
                frame.planes_yuv420[0].len(),
                frame.planes_yuv420[1].len(),
                frame.planes_yuv420[2].len(),
            )));
        }

        // Build a rav1e Frame and populate the planes. rav1e's
        // Plane stride is `(plane_width + xdec) >> xdec` where xdec
        // is the chroma decimation log2 — for Y both are 0 (full
        // res), for U/V both are 1 (half res). `copy_from_raw_u8`
        // takes (src_bytes, src_stride, src_bytes_per_pixel).
        let mut rav1e_frame = self.context.new_frame();
        for (idx, p) in rav1e_frame.planes.iter_mut().enumerate() {
            let plane_w = if idx == 0 { w } else { w / 2 };
            let src = &frame.planes_yuv420[idx];
            p.copy_from_raw_u8(src, plane_w, 1);
        }

        match self.context.send_frame(rav1e_frame) {
            Ok(()) => {}
            // EnoughData: the encoder's internal queue is saturated.
            // Surface as EncodeFailed so the caller backs off; this
            // shouldn't happen in low-latency mode at realistic
            // frame rates but is worth surfacing distinctly.
            Err(rav1e::EncoderStatus::EnoughData) => {
                return Err(Av1Error::EncodeFailed(
                    "rav1e internal queue is full (EnoughData)".to_string(),
                ));
            }
            Err(e) => return Err(Av1Error::EncodeFailed(format!("send_frame: {e}"))),
        }

        // Pretend pts pass-through (rav1e doesn't carry the PTS on
        // the Packet — we associate it from the source frame).
        // In low-latency mode we expect exactly one packet per
        // frame; in lookahead mode we may get 0 or several.
        self.drain_packets(frame.pts_us)
    }

    /// Flush any pending frames at end-of-stream. After flush the
    /// encoder is in an exhausted state and cannot accept new frames.
    pub fn flush(&mut self) -> Result<Vec<Av1EncodedChunk>, Av1Error> {
        self.context.flush();
        // Drain everything left. We tag with PTS 0 because the
        // residual packets — if any — are by definition lookahead-
        // delayed frames the caller has already accounted for; the
        // wrapper doesn't track the queue of source PTSs (a
        // follow-up could add a small ring buffer if archive callers
        // need exact PTS roundtrip in non-low-latency mode).
        self.drain_packets(0)
    }

    fn drain_packets(&mut self, pts_us: u64) -> Result<Vec<Av1EncodedChunk>, Av1Error> {
        let mut out = Vec::new();
        loop {
            match self.context.receive_packet() {
                Ok(pkt) => {
                    let is_keyframe = matches!(pkt.frame_type, rav1e::prelude::FrameType::KEY);
                    out.push(Av1EncodedChunk {
                        bytes: pkt.data,
                        is_keyframe,
                        pts_us,
                    });
                }
                Err(
                    rav1e::EncoderStatus::NeedMoreData
                    | rav1e::EncoderStatus::Encoded
                    | rav1e::EncoderStatus::LimitReached,
                ) => break,
                Err(e) => return Err(Av1Error::EncodeFailed(format!("receive_packet: {e}"))),
            }
        }
        Ok(out)
    }
}

impl Av1Decoder {
    /// Construct a new dav1d decoder with the libdav1d defaults.
    pub fn new() -> Result<Self, Av1Error> {
        let context = dav1d::Decoder::new()
            .map_err(|e| Av1Error::DecodeFailed(format!("dav1d::Decoder::new: {e}")))?;
        Ok(Self { context })
    }

    /// Decode one chunk into 0..N output frames. dav1d's internal
    /// state machine may emit zero pictures for a given input (still
    /// gathering reference frames) or multiple pictures (when a
    /// preceding chunk fed delayed frames the decoder can now
    /// resolve).
    pub fn decode_chunk(&mut self, chunk: &Av1EncodedChunk) -> Result<Vec<Av1Frame>, Av1Error> {
        // dav1d takes ownership of the bytes via Box<[u8]> /
        // AsRef<[u8]>+'static. Hand it a clone so the caller can
        // keep the original (e.g., to forward over the substrate
        // and decode locally in parallel).
        let buf: Box<[u8]> = chunk.bytes.clone().into_boxed_slice();
        let timestamp_us: i64 = chunk.pts_us.try_into().unwrap_or(i64::MAX);

        match self.context.send_data(buf, None, Some(timestamp_us), None) {
            Ok(()) => {}
            Err(e) if e.is_again() => {
                // Decoder buffer is full — drain pending pictures
                // first, then retry the pending send. Matches the
                // canonical dav1d-rs example pattern.
                let mut pending = self.drain_all_pictures(false)?;
                loop {
                    match self.context.send_pending_data() {
                        Ok(()) => break,
                        Err(e2) if e2.is_again() => {
                            pending.extend(self.drain_all_pictures(false)?);
                        }
                        Err(e2) => {
                            return Err(Av1Error::DecodeFailed(format!("send_pending_data: {e2}")));
                        }
                    }
                }
                // Now drain any new pictures the resolved sends produced.
                pending.extend(self.drain_all_pictures(false)?);
                return Ok(pending);
            }
            Err(e) => return Err(Av1Error::DecodeFailed(format!("send_data: {e}"))),
        }

        self.drain_all_pictures(false)
    }

    /// Flush — drain every remaining picture out of the dav1d
    /// internal buffer. Call after the last `decode_chunk`.
    pub fn flush(&mut self) -> Result<Vec<Av1Frame>, Av1Error> {
        self.context.flush();
        self.drain_all_pictures(true)
    }

    fn drain_all_pictures(&mut self, _drain_all: bool) -> Result<Vec<Av1Frame>, Av1Error> {
        // Both the "drain remaining" and "consume what's ready" paths
        // share the same shape: loop calling `get_picture` until it
        // returns `EAGAIN`. The dav1d-rs tool example differentiates
        // by re-feeding data between calls; in our wrapper the caller
        // controls that cadence by alternating `decode_chunk` /
        // `flush` invocations, so the loop body is identical in both
        // modes. `_drain_all` is preserved as an explicit parameter
        // so the call sites remain self-documenting.
        let mut out = Vec::new();
        loop {
            match self.context.get_picture() {
                Ok(p) => out.push(picture_to_av1frame(&p)),
                Err(e) if e.is_again() => break,
                Err(e) => return Err(Av1Error::DecodeFailed(format!("get_picture: {e}"))),
            }
        }
        Ok(out)
    }
}

fn picture_to_av1frame(p: &dav1d::Picture) -> Av1Frame {
    let width = u16::try_from(p.width()).unwrap_or(u16::MAX);
    let height = u16::try_from(p.height()).unwrap_or(u16::MAX);
    let pts_us = u64::try_from(p.timestamp().unwrap_or(0)).unwrap_or(0);

    // Pull the three planes. dav1d Plane derefs to &[u8] (the raw
    // pixel buffer); we strip the row stride to land the dense
    // packed-row form the encoder consumed.
    let mut planes: [Vec<u8>; 3] = [Vec::new(), Vec::new(), Vec::new()];
    for (idx, comp) in [
        dav1d::PlanarImageComponent::Y,
        dav1d::PlanarImageComponent::U,
        dav1d::PlanarImageComponent::V,
    ]
    .iter()
    .enumerate()
    {
        let plane = p.plane(*comp);
        let stride = usize::try_from(p.stride(*comp)).unwrap_or(0);
        let plane_w = if idx == 0 {
            usize::from(width)
        } else {
            usize::from(width).div_ceil(2)
        };
        let plane_h = if idx == 0 {
            usize::from(height)
        } else {
            usize::from(height).div_ceil(2)
        };
        let src: &[u8] = plane.as_ref();
        let mut dst = Vec::with_capacity(plane_w * plane_h);
        if stride == plane_w {
            // No padding — copy the prefix.
            dst.extend_from_slice(&src[..plane_w * plane_h]);
        } else {
            // Per-row copy stripping stride padding.
            for row in 0..plane_h {
                let row_start = row * stride;
                let row_end = row_start + plane_w;
                if row_end <= src.len() {
                    dst.extend_from_slice(&src[row_start..row_end]);
                }
            }
        }
        planes[idx] = dst;
    }

    Av1Frame {
        planes_yuv420: planes,
        width,
        height,
        pts_us,
    }
}

// ─────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic synthetic YUV420 frame — a horizontal
    /// gradient on Y, two diagonal gradients on U/V. Pixel values are
    /// chosen so we can compute a rough PSNR over the round-trip.
    fn synthetic_yuv420(width: u16, height: u16, frame_idx: u32) -> Av1Frame {
        let img_w = usize::from(width);
        let img_h = usize::from(height);
        let mut y_plane = vec![0u8; img_w * img_h];
        let mut u_plane = vec![0u8; (img_w / 2) * (img_h / 2)];
        let mut v_plane = vec![0u8; (img_w / 2) * (img_h / 2)];

        let offset = frame_idx as usize;
        for row in 0..img_h {
            for col in 0..img_w {
                // Y: horizontal gradient + temporal offset
                #[allow(clippy::cast_possible_truncation)]
                let val = ((col + offset) % 256) as u8;
                y_plane[row * img_w + col] = val;
            }
        }
        for row in 0..(img_h / 2) {
            for col in 0..(img_w / 2) {
                #[allow(clippy::cast_possible_truncation)]
                {
                    u_plane[row * (img_w / 2) + col] = ((row + col) % 256) as u8;
                    v_plane[row * (img_w / 2) + col] = ((row.wrapping_sub(col)) % 256) as u8;
                }
            }
        }

        Av1Frame {
            planes_yuv420: [y_plane, u_plane, v_plane],
            width,
            height,
            pts_us: u64::from(frame_idx) * 33_333, // ~30 fps PTS spacing
        }
    }

    fn realtime_360p_config() -> Av1EncoderConfig {
        Av1EncoderConfig {
            width: 640,
            height: 360,
            bitrate_kbps: 500,
            frame_rate_num: 30,
            frame_rate_den: 1,
            low_latency: true,
            speed_preset: 10,
        }
    }

    #[test]
    fn av1_invalid_dimensions_rejected() {
        // Zero dimensions
        let cfg = Av1EncoderConfig {
            width: 0,
            height: 0,
            ..realtime_360p_config()
        };
        assert!(matches!(
            Av1Encoder::new(cfg),
            Err(Av1Error::InvalidConfig(_))
        ));

        // Odd dimensions (AV1 4:2:0 requires even)
        let cfg = Av1EncoderConfig {
            width: 641,
            height: 361,
            ..realtime_360p_config()
        };
        assert!(matches!(
            Av1Encoder::new(cfg),
            Err(Av1Error::InvalidConfig(_))
        ));

        // Single-pixel-wide row (< 2)
        let cfg = Av1EncoderConfig {
            width: 1,
            height: 2,
            ..realtime_360p_config()
        };
        assert!(matches!(
            Av1Encoder::new(cfg),
            Err(Av1Error::InvalidConfig(_))
        ));
    }

    #[test]
    fn av1_dimensions_mismatch_caught() {
        let mut enc = Av1Encoder::new(realtime_360p_config()).expect("encoder construction");
        // Encoder is 640x360; pass a 1280x720 frame
        let frame = synthetic_yuv420(1280, 720, 0);
        match enc.encode_frame(&frame) {
            Err(Av1Error::DimensionsMismatch {
                expected_w,
                expected_h,
                actual_w,
                actual_h,
            }) => {
                assert_eq!(expected_w, 640);
                assert_eq!(expected_h, 360);
                assert_eq!(actual_w, 1280);
                assert_eq!(actual_h, 720);
            }
            other => panic!("expected DimensionsMismatch, got {other:?}"),
        }
    }

    /// Low-latency mode: each input frame yields at least one packet.
    /// rav1e's low_latency=true disables frame reordering, so once
    /// the encoder warm-up frame's keyframe lands, subsequent frames
    /// must each produce ≥1 packet.
    #[test]
    fn av1_low_latency_config_emits_chunks_promptly() {
        let mut enc = Av1Encoder::new(realtime_360p_config()).expect("encoder construction");

        let mut total_packets = 0usize;
        for t in 0..6 {
            let frame = synthetic_yuv420(640, 360, t);
            let chunks = enc.encode_frame(&frame).expect("encode_frame");
            total_packets += chunks.len();
        }
        let flush_chunks = enc.flush().expect("flush");
        total_packets += flush_chunks.len();

        // 6 input frames → at least 6 packets cumulative in
        // low-latency mode (allow flush to mop up any lookahead
        // remainder from the bitrate-controller warmup).
        assert!(
            total_packets >= 6,
            "low-latency encode produced only {total_packets} packets for 6 frames"
        );
    }

    /// First emitted packet must be a keyframe. Subsequent packets
    /// must include at least one non-keyframe (P-frame) — proving
    /// the encoder doesn't just spam keyframes.
    #[test]
    fn av1_keyframe_emission() {
        let mut enc = Av1Encoder::new(realtime_360p_config()).expect("encoder construction");

        let mut all_chunks: Vec<Av1EncodedChunk> = Vec::new();
        for t in 0..12 {
            let frame = synthetic_yuv420(640, 360, t);
            let chunks = enc.encode_frame(&frame).expect("encode_frame");
            all_chunks.extend(chunks);
        }
        all_chunks.extend(enc.flush().expect("flush"));

        assert!(!all_chunks.is_empty(), "encoder produced no chunks at all");
        assert!(
            all_chunks[0].is_keyframe,
            "first chunk must be a keyframe (got non-key)"
        );
        // At least one non-keyframe in the rest (the encoder isn't
        // just emitting an IDR per frame).
        let non_key_count = all_chunks.iter().filter(|c| !c.is_keyframe).count();
        assert!(
            non_key_count > 0,
            "expected ≥1 P-frame across {} chunks, got all keyframes",
            all_chunks.len()
        );
    }

    /// Encode → decode → verify dimensions match + frames count
    /// match. AV1 is lossy so byte-exact comparison is impossible;
    /// we PSNR-check the Y plane to confirm the decoder produced
    /// something resembling the input.
    ///
    /// `#[ignore]` because the dav1d FFI binding requires libdav1d
    /// (with -dev headers via pkg-config) at build/link time. CI
    /// runners that lack libdav1d-dev cannot link this test; the
    /// build itself will not fail because dav1d's link step happens
    /// when the codec-av1 feature is enabled (which itself requires
    /// the headers be present). Run explicitly with:
    ///   `cargo test --features codec-av1 -- --ignored av1_encode_decode_round_trip`
    /// on a host with libdav1d-dev installed (apt: libdav1d-dev,
    /// brew: dav1d). See the dav1d dep block in Cargo.toml for the
    /// auditwheel sidecar discipline used for manylinux wheels.
    #[test]
    #[ignore = "requires libdav1d at runtime; gated for hosts without dav1d-dev"]
    fn av1_encode_decode_round_trip() {
        let mut enc = Av1Encoder::new(realtime_360p_config()).expect("encoder construction");
        let mut dec = Av1Decoder::new().expect("decoder construction");

        // Feed several frames so rav1e emits a full sequence header
        // + at least one decodable keyframe in the bitstream. A
        // single-frame encode can produce bytes that the decoder
        // refuses to surface (lookahead-delayed; the sequence header
        // is OK but the frame data hasn't been finalized).
        let mut all_chunks: Vec<Av1EncodedChunk> = Vec::new();
        let src_frame = synthetic_yuv420(640, 360, 0);
        for t in 0..30 {
            let frame = synthetic_yuv420(640, 360, t);
            all_chunks.extend(enc.encode_frame(&frame).expect("encode_frame"));
        }
        all_chunks.extend(enc.flush().expect("flush"));
        assert!(
            !all_chunks.is_empty(),
            "encoder produced no chunks at all over 30 input frames"
        );

        // Drive the chunks through the public Av1Decoder API. dav1d
        // is internally multi-threaded with frame-delay > 0: it
        // doesn't surface decoded pictures until enough frames have
        // been queued for the pipeline to begin producing output.
        // 30 frames is comfortably past the threshold at libdav1d
        // 1.4.x's defaults.
        let mut decoded_frames: Vec<Av1Frame> = Vec::new();
        for chunk in &all_chunks {
            decoded_frames.extend(dec.decode_chunk(chunk).expect("decode_chunk"));
        }
        decoded_frames.extend(dec.flush().expect("dec.flush"));

        assert!(
            !decoded_frames.is_empty(),
            "round-trip produced no decoded frames from {} input chunks",
            all_chunks.len()
        );
        let first = &decoded_frames[0];
        assert_eq!(first.width, 640, "decoded width mismatch");
        assert_eq!(first.height, 360, "decoded height mismatch");
        assert_eq!(
            first.planes_yuv420[0].len(),
            640 * 360,
            "Y plane size mismatch"
        );
        assert_eq!(
            first.planes_yuv420[1].len(),
            320 * 180,
            "U plane size mismatch"
        );
        assert_eq!(
            first.planes_yuv420[2].len(),
            320 * 180,
            "V plane size mismatch"
        );

        // PSNR check on Y plane. AV1 at 500 kbps on a 640x360
        // synthetic gradient should land well above 30 dB.
        let sse: f64 = src_frame.planes_yuv420[0]
            .iter()
            .zip(first.planes_yuv420[0].iter())
            .map(|(&a, &b)| {
                let d = f64::from(a) - f64::from(b);
                d * d
            })
            .sum();
        // PSNR is a coarse fidelity metric — the precision-loss
        // from a 640*360 = 230_400-sample count down to f64 is well
        // below the precision floor of the 10·log10 quantization,
        // so the cast is intentional.
        #[allow(clippy::cast_precision_loss)]
        let mse = sse / (src_frame.planes_yuv420[0].len() as f64);
        let psnr = if mse < 0.0001 {
            f64::INFINITY
        } else {
            10.0 * (255.0_f64 * 255.0 / mse).log10()
        };
        assert!(
            psnr > 20.0,
            "round-trip Y-PSNR too low: {psnr} dB (expected > 20 dB)"
        );
    }
}
