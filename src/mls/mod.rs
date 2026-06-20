//! Substrate-tier MLS state for scope-native privacy (CIRISEdge#175,
//! v6.0.0).
//!
//! Distinct from `transport::realtime_av_mls` — the per-AV-stream
//! MLS exporter-bound media key state used by the realtime AV
//! dispatcher. This module owns the **persistent, substrate-tier**
//! MLS group state per `(community_id, group_epoch)` referenced by
//! CEWP `SCOPE_PRIVACY.md` §3.3 (Welcome wrap), §3.5 (archive_mode),
//! and §2.2 (group exporter_secret → record_id / symbol subkeys via
//! verify v6.3.0's `ciris_crypto::scope_privacy`).
//!
//! # Layering
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │ scope_privacy.rs (verify v6.3.0 re-exports)                 │
//! │     k_record_id  │  k_symbol  │  derive_record_id  │ …      │
//! └───────────────────────────┬─────────────────────────────────┘
//!                             │
//! ┌───────────────────────────┴─────────────────────────────────┐
//! │ mls/                                                        │
//! │  ├── archive_mode      — §3.5 per-community config          │
//! │  ├── welcome_wrap      — §3.3 HPKE-Base + ML-DSA-65 Welcome │
//! │  ├── scope_state       — substrate-tier StorageProvider     │
//! │  │                      (openmls 0.8) over EncryptedKVStore │
//! └─────────────────────────────────────────────────────────────┘
//! ```

pub mod archive_mode;
pub mod scope_state;
pub mod welcome_wrap;

pub use archive_mode::{ArchiveMode, ArchiveModeError, DEFAULT_ROTATE_FORWARD_WINDOW_DAYS};
pub use scope_state::{ScopeStateProvider, ScopeStateProviderError};
pub use welcome_wrap::{
    unwrap_welcome, wrap_welcome, FederationDirectoryEntry, WelcomeWrapError, WrappedWelcome,
};
