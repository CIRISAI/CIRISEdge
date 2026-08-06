//! CIRISEdge#436 — the link-borne **build-attestation-bundle frame** (`CBND`).
//!
//! The announce carries only a 32-byte manifest commitment (the app_data
//! budget is ~300 B — CIRISEdge#333); the multi-KiB attestation package rides
//! the **established link** instead, on the exact seam the AV-42/KEX planes
//! already use: a tagged frame on the link-frame paths (`try_send` packets,
//! `CFRG`-fragmented when oversized, reassembled in `attribute_and_deliver`).
//!
//! A `CBND` frame is a TRANSPORT-level control frame — like a `CFRG` fragment
//! or `CNAK` — consumed by the transport (`handle_peer_bundle_frame`), never
//! delivered as an envelope and never reaching the replication router. The
//! fourth distinct 4-byte magic keeps the dispatch a glance:
//! `CRPL` whole replication frame · `CFRG` fragment · `CNAK` fragment-ARQ NAK
//! · `CBND` peer build-attestation bundle.
//!
//! Wire layout: `magic[4] ‖ version[1] ‖ bundle bytes` — the bundle bytes are
//! the JSON `SignedCegObject` exactly as [`crate::bundle_gate::PeerBundleStore`]
//! stores them, capped by [`crate::bundle_gate::MAX_PEER_BUNDLE_BYTES`]
//! (checked by the receiver BEFORE any parse — cheap reject first).

use crate::bundle_gate::MAX_PEER_BUNDLE_BYTES;

/// Frame magic — distinct from `CRPL` (whole replication frame), `CFRG`
/// (fragment), and `CNAK` (fragment-ARQ NAK).
pub const PEER_BUNDLE_MAGIC: [u8; 4] = *b"CBND";

/// Wire version byte — a future shape is distinguishable, never mis-parsed
/// (the same discipline as the announce attestation's version byte).
pub const PEER_BUNDLE_WIRE_V1: u8 = 0x01;

/// `magic[4] ‖ version[1]`.
pub const PEER_BUNDLE_HEADER_LEN: usize = 5;

/// Hard cap on a whole `CBND` frame: header + the store's bundle cap.
pub const MAX_PEER_BUNDLE_FRAME_BYTES: usize = PEER_BUNDLE_HEADER_LEN + MAX_PEER_BUNDLE_BYTES;

/// Wrap `bundle_bytes` (the JSON `SignedCegObject`) as a v1 `CBND` frame.
#[must_use]
pub fn encode(bundle_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_BUNDLE_HEADER_LEN + bundle_bytes.len());
    out.extend_from_slice(&PEER_BUNDLE_MAGIC);
    out.push(PEER_BUNDLE_WIRE_V1);
    out.extend_from_slice(bundle_bytes);
    out
}

/// True iff `bytes` starts with the `CBND` magic (any version). The dispatch
/// predicate — version/shape validation happens in [`decode`], loudly.
#[must_use]
pub fn is_peer_bundle_frame(bytes: &[u8]) -> bool {
    bytes.len() >= PEER_BUNDLE_MAGIC.len() && bytes[..4] == PEER_BUNDLE_MAGIC
}

/// The bundle bytes of a well-formed v1 `CBND` frame; `None` for a wrong
/// magic, an unknown version, or a headerless/empty-body frame (a bundle is
/// never zero bytes — an empty body is a malformed frame, not an empty
/// bundle).
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<&[u8]> {
    if !is_peer_bundle_frame(bytes)
        || bytes.len() <= PEER_BUNDLE_HEADER_LEN
        || bytes[4] != PEER_BUNDLE_WIRE_V1
    {
        return None;
    }
    Some(&bytes[PEER_BUNDLE_HEADER_LEN..])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_malformed() {
        let bundle = br#"{"kind":"build_attestation_bundle"}"#;
        let frame = encode(bundle);
        assert!(is_peer_bundle_frame(&frame));
        assert_eq!(decode(&frame), Some(bundle.as_slice()));

        // Wrong magic / other planes' magics are never bundle frames.
        assert!(!is_peer_bundle_frame(b"CRPL...."));
        assert!(!is_peer_bundle_frame(b"CFRG...."));
        assert!(!is_peer_bundle_frame(b"CNAK...."));
        assert!(!is_peer_bundle_frame(b"CB"));
        assert_eq!(decode(b"CRPL....x"), None);

        // Unknown version: recognized as a CBND frame (dispatch consumes it)
        // but decodes to None — refused loudly downstream, never mis-parsed.
        let mut v2 = frame.clone();
        v2[4] = 0x02;
        assert!(is_peer_bundle_frame(&v2));
        assert_eq!(decode(&v2), None);

        // Header-only / empty-body frames are malformed.
        assert_eq!(decode(&frame[..PEER_BUNDLE_HEADER_LEN]), None);
        assert_eq!(decode(b""), None);
    }

    /// The four link-frame magics stay pairwise distinct — the dispatch
    /// invariant the module docs promise.
    #[test]
    fn magic_is_distinct_from_every_other_link_frame_magic() {
        use crate::replication::wire_frame::REPLICATION_FRAME_MAGIC;
        use crate::transport::frame_fragment::{FRAGMENT_MAGIC, NAK_MAGIC};
        let magics = [
            PEER_BUNDLE_MAGIC,
            REPLICATION_FRAME_MAGIC,
            FRAGMENT_MAGIC,
            NAK_MAGIC,
        ];
        for (i, a) in magics.iter().enumerate() {
            for b in magics.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
    }
}
