//! CC 5.4.6 — **the Anonymous Tier** (FSD/ONION_ROUTING.md), wired and
//! DORMANT in v44 (Eric, 2026-11-02): it runs only when the node's operator
//! opts in ([`policy::OnionPolicy::enabled`], default off) AND the layer deal
//! reports the tier available (three relays per layer on the deal and
//! answering). The CC has not yet pinned the packet, and the canonical bundle
//! seats too few relays for any layer to reach three, so in v44 every node
//! answers `onion_tier_not_opted_in` or `onion_tier_unavailable_floor`.
//!
//! - [`packet`] — the `outfox-xwing-v1` codec (draft X-Wing hop KEM, LIONESS
//!   body), submitted to the CC with `docs/onion_packet_wire.md` and its KATs;
//! - [`hop_key`] — the ONE place a node's hop key is read off the fold (today
//!   the transit pair stands in; persist 61.0.1 swaps in `onion_hop_pubkeys`),
//!   use-time separation, and custody of the node's own hop secret;
//! - [`policy`] — the opt-in, the device relay policy and every refusal token;
//! - [`relay`] — the relay step: shaped links only, replay, period, hold bound;
//! - [`sender`] — route choice over the deal and the publication packet;
//! - [`pseudonym`] — the fresh hybrid publication key of CC 5.4.6 item 9;
//! - [`runtime`] — the node's tier state the transport consults.
//!
//! The layer deal and the liveness fold live in
//! `crate::transport::onion_layers` / `onion_liveness`.

pub mod hop_key;
pub mod packet;
#[cfg(feature = "_reticulum-module")]
pub mod policy;
pub mod pseudonym;
pub mod relay;
#[cfg(feature = "_reticulum-module")]
pub mod runtime;
pub mod sender;
pub mod tokens;
