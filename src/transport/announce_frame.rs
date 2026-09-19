//! CIRISEdge#627 — **the announce rides the link.**
//!
//! A `CANN` link frame carries this node's signed announce attestation — the
//! SAME `app_data` bytes the RNS announce carries — over an established link,
//! so the receiver can bind the link's proven remote identity to a federation
//! `key_id` without waiting for the RNS announce to propagate, be queued, or
//! survive the cold-start worker's backlog (#547, #530). It is pushed FIRST on
//! every link this node initiates (after `LINKIDENTIFY`, before any other send)
//! and on every inbound link at `LinkEstablished`, exactly where the peer bundle
//! (`CBND`, #436) already is.
//!
//! The frame is bound to the link by **equality, not by trust**: the receiver
//! requires `transport_public_key` to equal the link's own
//! `Identity::public_key_bytes()` (all 64 bytes, `x25519 ‖ ed25519`) and then
//! verifies the attestation exactly as it verifies an RNS announce. A relayed or
//! replayed frame from some other identity fails the equality and is dropped by
//! name. No new trust is granted anywhere: the binding this installs is the
//! same Stage-1 (directory-free, `Advisory`) binding an RNS announce installs.
//!
//! Wire (v1), all fixed-width:
//!
//! ```text
//! "CANN" (4) ‖ version 0x01 (1) ‖ transport_public_key (64) ‖ announced_dest (16) ‖ app_data (rest)
//! ```

use crate::transport::attestation::ANNOUNCE_APP_DATA_BUDGET;

/// The four-byte tag every announce-on-link frame starts with. Pairwise
/// distinct from `CBND` / `CRPL` / `CFRG` / `CNAK` (pinned by
/// `peer_bundle_frame::tests::magic_is_distinct_from_every_other_link_frame_magic`).
pub const ANNOUNCE_FRAME_MAGIC: [u8; 4] = *b"CANN";

/// Wire version. A receiver refuses any other value.
pub const ANNOUNCE_FRAME_WIRE_V1: u8 = 0x01;

/// `magic (4) + version (1) + transport_public_key (64) + announced_dest (16)`.
pub const ANNOUNCE_FRAME_HEADER_LEN: usize = 4 + 1 + 64 + 16;

/// The largest frame `encode` can produce: the header plus the announce
/// app-data budget. A receiver refuses anything longer before parsing it.
pub const MAX_ANNOUNCE_FRAME_BYTES: usize = ANNOUNCE_FRAME_HEADER_LEN + ANNOUNCE_APP_DATA_BUDGET;

/// A decoded announce-on-link frame. Borrowed views only — the caller still
/// owns the bytes, and nothing here has been verified yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnounceOnLink<'a> {
    /// The announcer's full transport public key, `x25519 (32) ‖ ed25519 (32)`
    /// — the value `ReceivedAnnounce::public_key()` carries for an RNS
    /// announce. MUST equal the link's proven remote identity.
    pub transport_public_key: &'a [u8; 64],
    /// The destination the announcer announces on (its named destination).
    pub announced_dest: [u8; 16],
    /// The `AnnounceAttestation` app-data, byte-identical to the RNS announce's.
    pub app_data: &'a [u8],
}

/// Frame this node's announce for a link.
#[must_use]
pub fn encode(
    transport_public_key: &[u8; 64],
    announced_dest: [u8; 16],
    app_data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(ANNOUNCE_FRAME_HEADER_LEN + app_data.len());
    out.extend_from_slice(&ANNOUNCE_FRAME_MAGIC);
    out.push(ANNOUNCE_FRAME_WIRE_V1);
    out.extend_from_slice(transport_public_key);
    out.extend_from_slice(&announced_dest);
    out.extend_from_slice(app_data);
    out
}

/// Cheap dispatch predicate: does this link frame start with the `CANN` tag?
#[must_use]
pub fn is_announce_frame(bytes: &[u8]) -> bool {
    bytes.len() >= ANNOUNCE_FRAME_MAGIC.len() && bytes[..4] == ANNOUNCE_FRAME_MAGIC
}

/// Decode a `CANN` frame. `None` for a wrong magic, a wrong version, a frame
/// shorter than its header, an empty app-data, or a frame over the budget —
/// all shape refusals a caller reports by name.
#[must_use]
pub fn decode(bytes: &[u8]) -> Option<AnnounceOnLink<'_>> {
    if !is_announce_frame(bytes) || bytes.len() < ANNOUNCE_FRAME_HEADER_LEN + 1 {
        return None;
    }
    if bytes.len() > MAX_ANNOUNCE_FRAME_BYTES || bytes[4] != ANNOUNCE_FRAME_WIRE_V1 {
        return None;
    }
    let transport_public_key: &[u8; 64] = bytes[5..69].try_into().ok()?;
    let announced_dest: [u8; 16] = bytes[69..85].try_into().ok()?;
    Some(AnnounceOnLink {
        transport_public_key,
        announced_dest,
        app_data: &bytes[ANNOUNCE_FRAME_HEADER_LEN..],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_refuses_every_shape_fault() {
        let pk = [7u8; 64];
        let dest = [9u8; 16];
        let app = b"attestation-bytes".to_vec();
        let frame = encode(&pk, dest, &app);
        assert!(is_announce_frame(&frame));
        let decoded = decode(&frame).expect("well-formed v1 frame");
        assert_eq!(decoded.transport_public_key, &pk);
        assert_eq!(decoded.announced_dest, dest);
        assert_eq!(decoded.app_data, app.as_slice());

        // Header-only (no app-data) is not an announce.
        assert_eq!(decode(&frame[..ANNOUNCE_FRAME_HEADER_LEN]), None);
        // Wrong version.
        let mut v2 = frame.clone();
        v2[4] = 0x02;
        assert_eq!(decode(&v2), None);
        // Wrong magic.
        let mut bad = frame.clone();
        bad[0] = b'X';
        assert!(!is_announce_frame(&bad));
        assert_eq!(decode(&bad), None);
        // Over budget.
        let huge = encode(&pk, dest, &vec![0u8; ANNOUNCE_APP_DATA_BUDGET + 1]);
        assert_eq!(decode(&huge), None);
        assert_eq!(decode(b""), None);
    }
}
