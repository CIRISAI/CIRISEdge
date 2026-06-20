//! §3.5 per-community archive policy (CIRISEdge#175, v6.0.0).
//!
//! CEWP `SCOPE_PRIVACY.md` §3.5 — MLS epoch advance bounds the
//! lifetime of `K_record_id` / `K_symbol`. Each community configures
//! one of:
//!
//! - [`ArchiveMode::RotateForward`] (default, 30-day window): honest
//!   holders delete past-epoch keys after the window. Forward-secrecy
//!   is **honest-holder discipline, not cryptographic** — a holder
//!   under coercion or running modified software can retain keys
//!   (FSD §7.8 — warm-state seizure / dishonest holder).
//! - [`ArchiveMode::Retain`]: holders retain past-epoch keys
//!   indefinitely for archive readability; an adversary compromising
//!   a member at epoch N+k recovers everything back to their join
//!   epoch.
//!
//! Stored alongside the MLS group state in the
//! [`super::scope_state::ScopeStateProvider`]'s KV under the
//! `"archive_mode"` namespace.

use serde::{Deserialize, Serialize};

/// FSD §3.5 default rotate-forward window (days).
pub const DEFAULT_ROTATE_FORWARD_WINDOW_DAYS: u32 = 30;

/// Reserved KV namespace under which the per-community archive_mode
/// value is stored in the [`super::scope_state::ScopeStateProvider`].
pub const ARCHIVE_MODE_NAMESPACE: &str = "archive_mode";

/// FSD §3.5 per-community archive policy.
///
/// **Honest-holder discipline.** [`ArchiveMode::RotateForward`] is
/// the default and provides forward-secrecy *only against an honest
/// holder under uncoerced operation*. A holder under coercion, a
/// holder running modified software, or a warm-state seizure of the
/// holder's RAM (FSD §7.8) all defeat forward-secrecy structurally;
/// the policy is not cryptographic. Communities that need
/// archive-readable history opt to [`ArchiveMode::Retain`] knowing
/// that an adversary compromising any member at epoch N+k recovers
/// everything back to that member's join epoch.
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ArchiveMode {
    /// Honest holders delete past-epoch `K_record_id` / `K_symbol`
    /// keys after `window_days`. The default; the FSD §3.5 policy.
    RotateForward {
        /// Retention window (days) after which past-epoch keys are
        /// deleted. Default [`DEFAULT_ROTATE_FORWARD_WINDOW_DAYS`].
        window_days: u32,
    },
    /// Holders retain past-epoch keys indefinitely for archive
    /// readability. Trades forward-secrecy for archive-readable
    /// history.
    Retain,
}

impl ArchiveMode {
    /// The FSD §3.5 default: `RotateForward { window_days = 30 }`.
    #[must_use]
    pub const fn default_rotate_forward() -> Self {
        Self::RotateForward {
            window_days: DEFAULT_ROTATE_FORWARD_WINDOW_DAYS,
        }
    }

    /// Stable string-token for telemetry / structured logging.
    #[must_use]
    pub const fn kind_token(&self) -> &'static str {
        match self {
            Self::RotateForward { .. } => "rotate_forward",
            Self::Retain => "retain",
        }
    }

    /// `true` iff this mode provides honest-holder forward-secrecy
    /// (rotate-forward only).
    #[must_use]
    pub const fn is_forward_secret(&self) -> bool {
        matches!(self, Self::RotateForward { .. })
    }
}

impl Default for ArchiveMode {
    fn default() -> Self {
        Self::default_rotate_forward()
    }
}

/// Errors from the archive_mode persistence surface.
#[derive(Debug, thiserror::Error)]
pub enum ArchiveModeError {
    /// The `window_days` value is out of acceptable bounds. FSD §3.5
    /// has no explicit ceiling, but values >= 10 years (3650 days)
    /// are rejected as almost certainly operator error — a community
    /// asking for 10-year forward-secret rotation effectively wants
    /// `Retain` and should opt in explicitly.
    #[error("rotate_forward window_days {0} out of bounds (1..=3650)")]
    WindowDaysOutOfBounds(u32),
    /// Underlying KV store error (passed through from persist's
    /// `EncryptedKVStore`).
    #[error("archive_mode kv error: {0}")]
    Kv(String),
    /// Codec error decoding a stored archive_mode value.
    #[error("archive_mode decode error: {0}")]
    Decode(String),
}

impl ArchiveMode {
    /// Validate the mode for storage. `RotateForward { window_days = 0 }`
    /// or `window_days > 3650` (10y) is rejected — see [`ArchiveModeError`].
    pub fn validate(&self) -> Result<(), ArchiveModeError> {
        match self {
            Self::RotateForward { window_days } => {
                if *window_days == 0 || *window_days > 3650 {
                    return Err(ArchiveModeError::WindowDaysOutOfBounds(*window_days));
                }
                Ok(())
            }
            Self::Retain => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_rotate_forward_30_days() {
        assert_eq!(
            ArchiveMode::default(),
            ArchiveMode::RotateForward { window_days: 30 }
        );
    }

    #[test]
    fn kind_token_stable() {
        assert_eq!(ArchiveMode::default().kind_token(), "rotate_forward");
        assert_eq!(ArchiveMode::Retain.kind_token(), "retain");
    }

    #[test]
    fn forward_secret_only_rotate_forward() {
        assert!(ArchiveMode::default().is_forward_secret());
        assert!(!ArchiveMode::Retain.is_forward_secret());
    }

    #[test]
    fn validate_accepts_sane_windows() {
        assert!(ArchiveMode::RotateForward { window_days: 1 }
            .validate()
            .is_ok());
        assert!(ArchiveMode::RotateForward { window_days: 30 }
            .validate()
            .is_ok());
        assert!(ArchiveMode::RotateForward { window_days: 3650 }
            .validate()
            .is_ok());
        assert!(ArchiveMode::Retain.validate().is_ok());
    }

    #[test]
    fn validate_rejects_out_of_bounds_window() {
        assert!(matches!(
            ArchiveMode::RotateForward { window_days: 0 }.validate(),
            Err(ArchiveModeError::WindowDaysOutOfBounds(0))
        ));
        assert!(matches!(
            ArchiveMode::RotateForward { window_days: 3651 }.validate(),
            Err(ArchiveModeError::WindowDaysOutOfBounds(3651))
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let m = ArchiveMode::RotateForward { window_days: 30 };
        let s = serde_json::to_string(&m).unwrap();
        let back: ArchiveMode = serde_json::from_str(&s).unwrap();
        assert_eq!(back, m);

        let r = ArchiveMode::Retain;
        let s = serde_json::to_string(&r).unwrap();
        let back: ArchiveMode = serde_json::from_str(&s).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn namespace_pinned() {
        assert_eq!(ARCHIVE_MODE_NAMESPACE, "archive_mode");
    }
}
