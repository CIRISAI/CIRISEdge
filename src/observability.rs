//! Observability — structured logs + OTLP metrics + health probes.
//!
//! Mission: every message in or out is auditable. Federation trust
//! requires that any peer can answer "what did you receive, what did
//! you send, what was the verify outcome, when, from whom" — without
//! forensic archaeology.
//! ([`MISSION.md`](../../MISSION.md) §2 `observability/`.)
//!
//! # Structured log fields (per-message)
//!
//! - `signing_key_id` — sender's federation_keys.key_id
//! - `body_sha256_prefix` — joins to persist's forensic indices
//!   (Bridge already trained on this join key during the v0.2.x
//!   debug)
//! - `verify_result` — typed reject code or `verified`
//! - `handler_duration_ms` — handler-time, excludes verify
//! - `transport` — TransportId (http / reticulum-rs / lora / ...)
//!
//! # OTLP metrics
//!
//! Per-transport counters: `messages_in_total`, `messages_out_total`,
//! `verify_pass_total`, `verify_fail_total{reject_class}`.
//! Histograms: `verify_latency_seconds`, `handler_latency_seconds`,
//! `transport_send_latency_seconds`. Gauges: `inbound_queue_depth`,
//! `replay_window_size`. Outbound-queue gauges per FSD/EDGE_OUTBOUND_QUEUE.md §7.
//!
//! Implementation lands in a subsequent commit; this module is the
//! placeholder so the public-API path stays stable.
