//! HTTP/HTTPS fallback transport.
//!
//! Documented fallback per OQ-02; Reticulum is canonical. Used by
//! deployments where Reticulum can't run (cloud-only, restrictive
//! networks). TLS at the deployment edge handles encryption (AV-15);
//! edge does not add a third encryption layer.
//!
//! Implementation lands in a subsequent commit (Phase 1 lens-cutover
//! work). This module is the placeholder so the feature flag and
//! re-export path are stable from v0.1.0.

// Implementation skeleton lands here; re-exported as
// `ciris_edge::transport::http::HttpTransport` once it does.
