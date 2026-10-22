//! CC 5.4.6 — the Anonymous Tier (FSD/ONION_ROUTING.md). This module holds the
//! parts that need no persist row: the `outfox-xwing-v1` packet codec
//! ([`packet`]). The layer deal and the liveness fold live in
//! `crate::transport::onion_layers` / `onion_liveness`.

pub mod packet;
