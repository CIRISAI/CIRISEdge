//! CC 5.4.3 — **the referral**: what a node at its shaped-link bound hands the
//! peer it bounces. A bare "home elsewhere" leaves a refused peer holding
//! nothing, and a peer with no shaped home cannot reach a consent, so the
//! refusal carries up to three nodes with free slots, each with what the peer
//! needs to dial it without a further lookup.
//!
//! **The frame.** `SHRF` frames on the Channel, sealed like everything else on
//! the link, in the `fragment_tagged` framing the route answer uses. The body
//! is JSON: an action ([`ReferralAction`]) and up to [`MAX_REFERRALS`] entries,
//! each a [`RouteAnswer`]: the referred node's own hybrid-signed route row and
//! its key record. The peer verifies an entry exactly as it verifies a route it
//! fetched from that node, so a referrer can vouch for nothing it could not
//! have fetched, and can only withhold.
//!
//! **Order on the wire.** The frames go BEFORE the `SHAP` refusal: the dialler
//! closes the moment that answer lands. A 43.x dialler reads the refusal's
//! class byte as malformed and closes either way.
//!
//! **Who may be referred (Eric, 2026-11-04).** Offering relay is the consent to
//! be referred. A referral names any ANNOUNCED node, owned or not, that reports
//! free shaped slots, and a node reports only while its relay offering is on
//! ([`crate::onion::policy::relay_offering`]: a phone only on Wi-Fi while
//! charging; never a node that turned on the Anonymous Tier, which proxies
//! nothing, CC 5.4.6 `CLM-referred-peer-is-proxy`). When the offering ends
//! the next report says zero and it drops out of every peer's ranking.
//!
//! **Who is ranked.** Shaped peers report their free slots in the in-band
//! capability body ([`crate::transport::link_shaping::capability_body`]). Most
//! free slots first, ties in random order, so refused peers do not herd onto
//! one; a node handed out first loses a slot in the local hint until its next
//! report. A serve seat ranks below every edge node and only as the last
//! entry. A report is a hint: a stale one costs the peer a refused dial and it
//! tries the next.
//!
//! **Two actions, one frame.** [`ReferralAction::Refused`] is a dialler bounced
//! at the bound. [`ReferralAction::Move`] is reserved for displacement
//! (CIRISEdge#939): a peer told to leave a running link. v44 sends only the
//! first, and treats a received `Move` on an unanswered offer the same way.

use std::collections::HashSet;
use std::time::Duration;

use rand::seq::SliceRandom as _;
use serde::{Deserialize, Serialize};

use super::av_transit_handshake::{fragment_tagged, AvHandshakeError, Reassembler};
use super::route_fetch::RouteAnswer;
use crate::verify::RootingDirectory;

/// Tag of a referral frame.
pub const REFERRAL_MAGIC: [u8; 4] = *b"SHRF";
/// Entries in one referral, at most.
pub const MAX_REFERRALS: usize = 3;
/// A referral's body, at most: three route answers with room to spare. Past
/// it the last entries are dropped, never the frame.
pub const MAX_REFERRAL_BYTES: usize = 96 * 1024;
/// How long a refusal may spend reading candidates. The refusal goes out on
/// time with what is ready, an empty list at worst.
pub const REFERRAL_BUILD_BUDGET: Duration = Duration::from_secs(2);
/// Candidates a refusal reads the directory for, at most.
pub const REFERRAL_CANDIDATE_READS: usize = 8;

/// What a referral asks of the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferralAction {
    /// A dialler refused at the bound: home on one of these.
    Refused,
    /// A shaped peer displaced to make room (CIRISEdge#939): move to one of
    /// these and keep shaping.
    Move,
}

/// The referral a peer receives.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferralFrame {
    /// What the peer is asked to do.
    pub action: ReferralAction,
    /// In the order to try them. Empty: the peer uses its fallback order.
    pub referrals: Vec<RouteAnswer>,
}

/// Whether `bytes` is a referral frame.
#[must_use]
pub fn is_referral_frame(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == REFERRAL_MAGIC
}

/// A reassembler for `SHRF` frames.
#[must_use]
pub fn referral_reassembler() -> Reassembler {
    Reassembler::tagged(REFERRAL_MAGIC, MAX_REFERRAL_BYTES)
}

/// Frame `frame` for a link of `frame_limit`, dropping the last entries until
/// it fits [`MAX_REFERRAL_BYTES`]. `Ok` carries the frames and how many
/// entries they name.
///
/// # Errors
/// The framing's (a `frame_limit` too small), or a row that does not
/// serialise.
pub fn encode_referrals(
    mut frame: ReferralFrame,
    frame_limit: usize,
) -> Result<(Vec<Vec<u8>>, usize), AvHandshakeError> {
    let malformed = |_| AvHandshakeError::Malformed("a referral that does not serialise");
    frame.referrals.truncate(MAX_REFERRALS);
    let mut body = serde_json::to_vec(&frame).map_err(malformed)?;
    while body.len() > MAX_REFERRAL_BYTES && frame.referrals.pop().is_some() {
        body = serde_json::to_vec(&frame).map_err(malformed)?;
    }
    let frames = fragment_tagged(REFERRAL_MAGIC, MAX_REFERRAL_BYTES, &body, frame_limit)?;
    Ok((frames, frame.referrals.len()))
}

/// Decode a reassembled referral. Entries past [`MAX_REFERRALS`] are ignored.
///
/// # Errors
/// A body that is not a referral.
pub fn decode_referrals(bytes: &[u8]) -> Result<ReferralFrame, serde_json::Error> {
    let mut frame: ReferralFrame = serde_json::from_slice(bytes)?;
    frame.referrals.truncate(MAX_REFERRALS);
    Ok(frame)
}

/// A shaped peer that reported room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferralCandidate {
    /// Its occurrence key id.
    pub key_id: String,
    /// The free slots it last reported.
    pub free_slots: u8,
    /// It holds a serve seat.
    pub seat: bool,
}

/// `candidates` in the order to consider them: edge nodes before seats, most
/// free slots first, ties in random order. A node with no room, or in
/// `excluded`, is dropped.
#[must_use]
pub fn rank_referrals<R: rand::Rng + ?Sized, S: std::hash::BuildHasher>(
    mut candidates: Vec<ReferralCandidate>,
    excluded: &HashSet<String, S>,
    rng: &mut R,
) -> Vec<ReferralCandidate> {
    candidates.retain(|c| c.free_slots > 0 && !excluded.contains(&c.key_id));
    candidates.shuffle(rng);
    candidates.sort_by_key(|c| (c.seat, std::cmp::Reverse(c.free_slots)));
    candidates
}

/// `key_id`'s live route and key record, ready to refer: the node announced in
/// the CC's sense ([`RootingDirectory::node_announced`]), so a node that chose
/// not to be listed is never handed out, and it carries a transit pair. `None`
/// is every other answer. Whether it offers relay was settled by its report: a
/// node that does not reports no slots.
pub async fn referable_route(
    rooting: &dyn RootingDirectory,
    key_id: &str,
    announced: bool,
) -> Option<RouteAnswer> {
    if !announced || !rooting.node_announced(key_id).await.ok()? {
        return None;
    }
    let route = rooting.signed_reticulum_route(key_id).await.ok()??;
    if route.transport_destination.retired_at.is_some()
        || !matches!(route.transit_kex_pair(), Ok(Some(_)))
    {
        return None;
    }
    let key_record_row = rooting.own_key_record_row(key_id).await.ok()?;
    Some(RouteAnswer {
        route,
        key_record_row,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng as _;

    fn candidate(key_id: &str, free_slots: u8, seat: bool) -> ReferralCandidate {
        ReferralCandidate {
            key_id: key_id.to_owned(),
            free_slots,
            seat,
        }
    }

    /// Most free slots first; a seat below every edge node, however much room
    /// it has; a full node and an excluded one never named.
    #[test]
    fn edge_nodes_rank_above_seats_by_free_slots() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let excluded: HashSet<String> = ["peer".to_owned()].into_iter().collect();
        let ranked = rank_referrals(
            vec![
                candidate("seat", 8, true),
                candidate("edge-1", 1, false),
                candidate("edge-5", 5, false),
                candidate("full", 0, false),
                candidate("peer", 8, false),
            ],
            &excluded,
            &mut rng,
        );
        let names: Vec<&str> = ranked.iter().map(|c| c.key_id.as_str()).collect();
        assert_eq!(names, ["edge-5", "edge-1", "seat"]);
    }

    /// Ties break at random, so the first name moves between refusals.
    #[test]
    fn a_tie_breaks_at_random() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(11);
        let firsts: HashSet<String> = (0..64)
            .map(|_| {
                rank_referrals(
                    vec![
                        candidate("a", 3, false),
                        candidate("b", 3, false),
                        candidate("c", 3, false),
                    ],
                    &HashSet::new(),
                    &mut rng,
                )[0]
                .key_id
                .clone()
            })
            .collect();
        assert_eq!(firsts.len(), 3, "{firsts:?}");
    }

    /// An empty referral frames and decodes: "no targets known" is an answer.
    #[test]
    fn an_empty_referral_is_a_frame() {
        let (frames, named) = encode_referrals(
            ReferralFrame {
                action: ReferralAction::Refused,
                referrals: Vec::new(),
            },
            400,
        )
        .unwrap();
        assert_eq!(named, 0);
        assert!(frames.iter().all(|f| is_referral_frame(f)));
        let mut r = referral_reassembler();
        let mut body = None;
        for f in &frames {
            body = r.push(f).unwrap();
        }
        let back = decode_referrals(&body.expect("whole")).unwrap();
        assert_eq!(back.action, ReferralAction::Refused);
        assert!(back.referrals.is_empty());
    }

    /// The same frame carries a move, for displacement (CIRISEdge#939).
    #[test]
    fn the_frame_carries_a_refusal_and_a_move() {
        let body = serde_json::to_vec(&ReferralFrame {
            action: ReferralAction::Move,
            referrals: Vec::new(),
        })
        .unwrap();
        assert!(String::from_utf8_lossy(&body).contains("\"move\""));
        assert_eq!(
            decode_referrals(&body).unwrap().action,
            ReferralAction::Move
        );
    }
}
