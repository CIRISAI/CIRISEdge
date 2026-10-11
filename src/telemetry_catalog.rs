//! CIRISEdge#820 P1 — edge's telemetry catalogue (CIRISServer
//! `FSD/UNIFIED_TELEMETRY.md` §3.2–§3.3).
//!
//! Every metric edge emits through the `metrics` facade, and every span name
//! it opens, is declared here: name, kind, unit, label keys with their BOUNDED
//! value sets, description, histogram buckets, and the
//! [`crate::observability::EdgeMetricsBundle`] field(s) it projects. The
//! server merges this catalogue with persist's, leviculum's and the agent's
//! into the served `/metrics` HELP text and gates the merge.
//!
//! # Libraries emit, the host exports
//!
//! Edge installs NO recorder. With none installed every emission here is a
//! no-op. The host (the server) installs one recorder for the process.
//!
//! - Counters and gauges are PULL-published by [`publish_bundle`], from the
//!   same [`crate::observability::EdgeMetrics`] bag the bindings' snapshots
//!   read: the bag is the single source, and the bundle (PyO3 / UniFFI) and
//!   the facade are two projections of it. Counters are recorded with
//!   `absolute` (the bag's cumulative value), gauges with `set`.
//! - Histograms cannot be pull-published (the facade records samples, not
//!   bucket counts), so each is recorded at its observation site through
//!   [`record_histogram`], from the sites its spec lists.
//!
//! The facade identifies a series by name and labels only. Two `Edge`s in one
//! process publishing to ONE global recorder write the same series, and
//! `absolute` from each flip-flops it. That is acceptable because production
//! runs one `Edge` per process (a node has exactly one owner), the host clears
//! its recorder at each fold start, and tests isolate with
//! `metrics::with_local_recorder`.
//!
//! # One label style
//!
//! Label keys are snake_case words; label values are the stable snake tokens
//! the code already uses (`as_str()` / `as_wire_str()` / the `*_` const
//! tokens). A value outside a label's declared set publishes as
//! [`OTHER_LABEL`], so no runtime string (a peer, an error message) can mint a
//! series. Per-peer and per-row detail is NOT a metric ([`NOT_METRICS`]); it is
//! served on demand from domain state.
//!
//! # The gate
//!
//! `telemetry_catalog_gate` (below) fails when: a published series is not
//! catalogued, or carries an undeclared label key or value; a catalogue entry
//! is never published; a bundle field is neither projected by a spec nor
//! listed in [`NOT_METRICS`]; two entries (edge's, or edge's against
//! leviculum's `METRIC_CATALOG`) render to one Prometheus series name; a
//! facade macro is used outside this module; a histogram is recorded from a
//! site its spec does not list; or a span name in `src/` is not in
//! [`SPAN_CATALOG`].

use std::collections::BTreeMap;

use ciris_persist::federation::attestation_apply::AttestationRefusalReason;
use ciris_persist::federation::register::KeyRefusalReason;
use metrics::{Label, Unit};

use crate::messages::MessageType;
use crate::observability::{
    DeliveryClass, LinkCloseCause, LinkPoolCloseReason, RoundOutcome, VerifyErrorClass,
    WithholdReason, LINK_UP_OUTCOMES, RESPONDER_ROUND_OUTCOMES,
};
use crate::replication::bridge::ApplyRefusalClass;
use crate::replication::EnvelopeKind;

/// The value a label takes when the code produced one outside its declared
/// set.
pub const OTHER_LABEL: &str = "other";

/// Counter, gauge or histogram.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricKind {
    /// Monotonic, cumulative since the `Edge` was built.
    Counter,
    /// A level read now.
    Gauge,
    /// A distribution recorded at its observation sites.
    Histogram,
}

/// One label key and every value it may take. [`OTHER_LABEL`] is always
/// allowed in addition.
#[derive(Debug, Clone, Copy)]
pub struct LabelSpec {
    /// The snake_case key.
    pub key: &'static str,
    /// The bounded value set.
    pub values: &'static [&'static str],
}

/// One metric edge emits.
#[derive(Debug, Clone, Copy)]
pub struct MetricSpec {
    /// OpenTelemetry-style dotted name, `ciris.edge.*`. The host renders it
    /// per FSD §3.1 ([`rendered_series`]).
    pub name: &'static str,
    /// Counter, gauge or histogram.
    pub kind: MetricKind,
    /// The unit; it supplies the rendered unit suffix.
    pub unit: Unit,
    /// The only label keys the metric carries, with their bounded values.
    pub labels: &'static [LabelSpec],
    /// HELP text.
    pub description: &'static str,
    /// Histogram bucket upper bounds (ascending; `+Inf` implicit). Changing
    /// them is a breaking change to the series: a new name, never an edit.
    /// Empty for counters and gauges.
    pub buckets: &'static [f64],
    /// The [`crate::observability::EdgeMetricsBundle`] field(s) this spec
    /// projects.
    pub bundle_fields: &'static [&'static str],
    /// Histograms only: the functions (`path::fn`) that call
    /// [`record_histogram`] for this spec. The gate holds the code to it.
    pub sites: &'static [&'static str],
}

/// A bundle field that is deliberately NOT a metric, and why.
#[derive(Debug, Clone, Copy)]
pub struct NotMetric {
    /// The [`crate::observability::EdgeMetricsBundle`] field.
    pub bundle_field: &'static str,
    /// Why it stays out of the facade.
    pub reason: &'static str,
}

/// One span name edge opens.
#[derive(Debug, Clone, Copy)]
pub struct SpanSpec {
    /// The span name as `tracing` records it (for `#[instrument]` without a
    /// `name`, the function's name).
    pub name: &'static str,
    /// Where it is opened (`path::fn`).
    pub site: &'static str,
    /// What unit of work it covers.
    pub description: &'static str,
}

const fn counter(
    name: &'static str,
    unit: Unit,
    labels: &'static [LabelSpec],
    bundle_fields: &'static [&'static str],
    description: &'static str,
) -> MetricSpec {
    MetricSpec {
        name,
        kind: MetricKind::Counter,
        unit,
        labels,
        description,
        buckets: &[],
        bundle_fields,
        sites: &[],
    }
}

const fn gauge(
    name: &'static str,
    unit: Unit,
    labels: &'static [LabelSpec],
    bundle_fields: &'static [&'static str],
    description: &'static str,
) -> MetricSpec {
    MetricSpec {
        name,
        kind: MetricKind::Gauge,
        unit,
        labels,
        description,
        buckets: &[],
        bundle_fields,
        sites: &[],
    }
}

const fn histogram(
    name: &'static str,
    labels: &'static [LabelSpec],
    buckets: &'static [f64],
    bundle_fields: &'static [&'static str],
    sites: &'static [&'static str],
    description: &'static str,
) -> MetricSpec {
    MetricSpec {
        name,
        kind: MetricKind::Histogram,
        unit: Unit::Seconds,
        labels,
        description,
        buckets,
        bundle_fields,
        sites,
    }
}

const fn label(key: &'static str, values: &'static [&'static str]) -> LabelSpec {
    LabelSpec { key, values }
}

/// The catalogued spec named `name`.
///
/// # Panics
///
/// When `name` is not catalogued: every call site passes a name from this
/// module's own constants, so a miss is a programming error the gate's tests
/// reach first.
#[must_use]
pub fn spec(name: &str) -> &'static MetricSpec {
    METRIC_CATALOG
        .iter()
        .find(|s| s.name == name)
        .unwrap_or_else(|| panic!("metric {name} is not in METRIC_CATALOG"))
}

/// `value` if `key`'s declared set holds it, else [`OTHER_LABEL`]: the one
/// place a runtime label value becomes a series label.
#[must_use]
pub fn bounded(spec: &MetricSpec, key: &str, value: &str) -> &'static str {
    spec.labels
        .iter()
        .find(|l| l.key == key)
        .and_then(|l| l.values.iter().copied().find(|v| *v == value))
        .unwrap_or(OTHER_LABEL)
}

fn labels_of(spec: &'static MetricSpec, values: &[&str]) -> Vec<Label> {
    debug_assert_eq!(
        spec.labels.len(),
        values.len(),
        "{}: label arity",
        spec.name
    );
    spec.labels
        .iter()
        .zip(values)
        .map(|(l, v)| Label::new(l.key, bounded(spec, l.key, v)))
        .collect()
}

/// Record one observation of `seconds` into histogram `name` with
/// `label_values` (in the spec's label order). Called only from the sites
/// the spec lists.
pub fn record_histogram(name: &str, label_values: &[&str], seconds: f64) {
    let spec = spec(name);
    debug_assert_eq!(spec.kind, MetricKind::Histogram, "{name}");
    metrics::histogram!(spec.name, labels_of(spec, label_values)).record(seconds);
}

/// Describe every catalogued metric to the installed recorder (unit + HELP).
pub fn describe_all() {
    for s in METRIC_CATALOG {
        match s.kind {
            MetricKind::Counter => metrics::describe_counter!(s.name, s.unit, s.description),
            MetricKind::Gauge => metrics::describe_gauge!(s.name, s.unit, s.description),
            MetricKind::Histogram => {
                metrics::describe_histogram!(s.name, s.unit, s.description);
            }
        }
    }
}

/// Values gathered for one publish, summed per (spec, label values) so two
/// raw values that both fold to [`OTHER_LABEL`] add up instead of the second
/// `absolute` overwriting the first.
#[derive(Default)]
struct Publish {
    counters: BTreeMap<(&'static str, Vec<&'static str>), u64>,
    gauges: BTreeMap<(&'static str, Vec<&'static str>), f64>,
}

impl Publish {
    fn bound(spec: &'static MetricSpec, values: &[&str]) -> Vec<&'static str> {
        spec.labels
            .iter()
            .zip(values)
            .map(|(l, v)| bounded(spec, l.key, v))
            .collect()
    }

    fn count(&mut self, name: &str, values: &[&str], v: u64) {
        let s = spec(name);
        debug_assert_eq!(s.kind, MetricKind::Counter, "{name}");
        let slot = self
            .counters
            .entry((s.name, Self::bound(s, values)))
            .or_insert(0);
        *slot = slot.saturating_add(v);
    }

    fn level(&mut self, name: &str, values: &[&str], v: f64) {
        let s = spec(name);
        debug_assert_eq!(s.kind, MetricKind::Gauge, "{name}");
        *self
            .gauges
            .entry((s.name, Self::bound(s, values)))
            .or_insert(0.0) += v;
    }

    fn emit(self) {
        for ((name, values), v) in self.counters {
            metrics::counter!(name, label_vec(name, &values)).absolute(v);
        }
        for ((name, values), v) in self.gauges {
            metrics::gauge!(name, label_vec(name, &values)).set(v);
        }
    }
}

fn label_vec(name: &str, values: &[&'static str]) -> Vec<Label> {
    spec(name)
        .labels
        .iter()
        .zip(values)
        .map(|(l, v)| Label::new(l.key, *v))
        .collect()
}

// ─── Label value sets ──────────────────────────────────────────────────────
//
// Enum-backed sets are BUILT from the enum's `ALL` through its stable token
// fn (a `const fn`), so a variant added to the enum is in the catalogue by
// construction. Literal-token sets are listed here; a token the code adds
// without listing it publishes as `other` (never a new series) until it is.

/// `[T::ALL[i].$tok(), …]` as a `const` array.
macro_rules! tokens {
    ($all:expr, $tok:ident) => {{
        let mut out = [""; $all.len()];
        let mut i = 0;
        while i < $all.len() {
            out[i] = $all[i].$tok();
            i += 1;
        }
        out
    }};
}

/// As [`tokens!`], leaving out the one token `$skip` (which must be present).
macro_rules! tokens_without {
    ($all:expr, $tok:ident, $skip:expr) => {{
        let mut out = [""; $all.len() - 1];
        let (mut i, mut j) = (0, 0);
        while i < $all.len() {
            let t = $all[i].$tok();
            if !const_str_eq(t, $skip) {
                out[j] = t;
                j += 1;
            }
            i += 1;
        }
        assert!(j == out.len(), "the skipped token is not in ALL");
        out
    }};
}

const fn const_str_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

const MESSAGE_TYPES: [&str; MessageType::ALL.len()] = tokens!(MessageType::ALL, as_str);
const ENVELOPE_KINDS: [&str; EnvelopeKind::ALL.len()] = tokens!(EnvelopeKind::ALL, as_wire_str);
const VERIFY_CLASSES: [&str; VerifyErrorClass::ALL.len()] = tokens!(VerifyErrorClass::ALL, as_str);
const DELIVERY_CLASSES: [&str; DeliveryClass::ALL.len()] = tokens!(DeliveryClass::ALL, as_str);
const ROUND_OUTCOMES: [&str; RoundOutcome::ALL.len()] = tokens!(RoundOutcome::ALL, as_str);
const WITHHOLD_REASONS: [&str; WithholdReason::ALL.len()] = tokens!(WithholdReason::ALL, as_str);
const POOL_CLOSE_REASONS: [&str; LinkPoolCloseReason::ALL.len()] =
    tokens!(LinkPoolCloseReason::ALL, as_str);
const LINK_CLOSE_CAUSES: [&str; LinkCloseCause::ALL.len()] = tokens!(LinkCloseCause::ALL, as_str);
const APPLY_REFUSAL_CLASSES: [&str; ApplyRefusalClass::ALL.len()] =
    tokens!(ApplyRefusalClass::ALL, as_str);

/// The persist key-refusal token edge books as a DUPLICATE, never on the
/// refusal ledger (`replication::bridge::key_outcome_to_apply`); the gate
/// holds the mapping to it.
pub const KEY_REFUSAL_BOOKED_AS_DUPLICATE: &str =
    KeyRefusalReason::AlreadyAnchoredIdentical.as_str();
/// As [`KEY_REFUSAL_BOOKED_AS_DUPLICATE`], for attestations
/// (`replication::bridge::attestation_outcome_to_apply`).
pub const ATTESTATION_REFUSAL_BOOKED_AS_DUPLICATE: &str =
    AttestationRefusalReason::AlreadyPresentIdentical.as_str();
/// Persist's key-refusal tokens edge books, imported from the authority.
pub const KEY_REFUSAL_REASONS: [&str; KeyRefusalReason::ALL.len() - 1] = tokens_without!(
    KeyRefusalReason::ALL,
    as_str,
    KEY_REFUSAL_BOOKED_AS_DUPLICATE
);
/// Persist's attestation-refusal tokens edge books, imported from the
/// authority.
pub const ATTESTATION_REFUSAL_REASONS: [&str; AttestationRefusalReason::ALL.len() - 1] = tokens_without!(
    AttestationRefusalReason::ALL,
    as_str,
    ATTESTATION_REFUSAL_BOOKED_AS_DUPLICATE
);

/// The production `TransportId` consts' tokens. A host-minted id publishes
/// as `other`.
pub const TRANSPORTS: &[&str] = &["http", "reticulum-rs", "leviculum", "lora", "serial", "i2p"];
/// Send-failure classes edge itself produces: `transport_error_class` (edge.rs)
/// and the HTTP transports' peer rejects. A `Reject { class }` from a
/// downstream `Transport` impl outside this set publishes as `other`.
pub const SEND_FAILURE_CLASSES: &[&str] = &[
    "unreachable",
    "timeout",
    "config",
    "io",
    "body_too_large",
    "peer_blackholed",
    "no_route_to_peer",
    "rate_limited",
    "client_error",
    "unauthorized",
];
const SESSION_ROLES: &[&str] = &["initiator", "responder"];
const LINK_DIRECTIONS: &[&str] = &["inbound", "outbound"];
const BLOB_SERVE_REFUSALS: &[&str] = &[
    "blob_serve_scope_undeterminable",
    "blob_serve_arrival_scope_insufficient",
    "blob_serve_group_mismatch",
    "blob_serve_discriminator_unheld",
    "blob_serve_discriminator_on_derived_address",
    crate::observability::BLOB_SERVE_REFUSED_WITHDRAWN,
    "chunk_not_in_named_dag",
    "no_chunk_source_wired",
];
const BLOB_PULL_SOURCES: &[&str] = &[
    "self:author_nodes",
    "self:claim_index",
    "family:author_nodes",
    "family:claim_index",
    "community:author_nodes",
    "community:claim_index",
    "federation:author_nodes",
    "federation:claim_index",
];
const BLOB_PULL_REFUSALS: &[&str] = &[
    "size_mismatch",
    "no_epoch",
    "dag_manifest_mismatch",
    "dag_total_size_mismatch",
    "dag_over_cap",
    "dag_chunk_mismatch",
    "dag_chunk_missing",
];
const BLOB_DAG_PHASES: &[&str] = &[
    "inbound_verify_chunk_body",
    "inbound_parse_chunk_body",
    "serve_gate_read",
    "serve_gate_read_sign",
    "serve_ship",
    "serve_chunk",
    "dag_fetch_wait",
    "dag_adopt",
    "dag_promote",
];
/// `blob_dag_chunks` keys that are cumulative counts.
pub const BLOB_DAG_CHUNK_COUNTS: &[&str] = &["skipped_held", "adopt_batches", "adopted"];
/// `blob_dag_chunks` keys that are peak levels (`max_blob_dag_chunks`).
pub const BLOB_DAG_CHUNK_PEAKS: &[&str] = &["in_flight_peak", "adopt_batch_peak"];
const DELIVERY_RECEIPTS: &[&str] = &[
    "receipt_root_unpublished",
    "receipt_tree_size_short",
    "receipt_epoch_mismatch",
    "receipt_signer_not_member",
    "receipt_duplicate",
    "receipt_malformed",
    "receipt_file_unknown",
    "receipt_substrate",
    "admitted",
    "emitted",
    "not_emitted_no_sth",
    "not_emitted_sth_refused",
    "not_emitted_failed",
    "re_offer_suppressed_receipted",
];
const BLOB_ROUTE_REFUSALS: &[&str] = &[
    "blob_scope_undeterminable",
    "blob_no_address_table",
    "blob_group_not_installed",
    "blob_holder_not_in_group",
    "blob_holder_sealed_out",
    "blob_public_is_not_scoped",
];
const BLOB_SCOPED_CARRIERS: &[&str] = &[
    "send:derived_address",
    "send:identity_link",
    "send:path_unknown_derived",
    "serve:identity_link_admitted",
    "serve:reply_path",
    "serve:reply_queued_fallback",
];
const BOOTSTRAP_DOOR_DECISIONS: &[&str] = &["not_applicable", "attributed", "unbound"];
const TRANSPORT_INBOUND_DROPS: &[&str] = &["identity_frame_on_scoped_link"];
const AV_EVENTS: &[&str] = &[
    crate::observability::AV_SENT,
    crate::observability::AV_SEND_REFUSED_CHUNK_TOO_LARGE,
    crate::observability::AV_SEND_CONGESTED,
    crate::observability::AV_SEND_LINK_GONE,
    crate::observability::AV_SEND_FAILED,
    crate::observability::AV_LINK_OPENED,
    crate::observability::AV_LINK_ARRIVED,
    crate::observability::AV_INBOUND_DELIVERED,
    crate::observability::AV_INBOUND_DROPPED_QUEUE_FULL,
    crate::observability::AV_INBOUND_DROPPED_UNATTRIBUTED,
    crate::observability::AV_INBOUND_DROPPED_NO_CONSUMER,
    crate::observability::AV_INBOUND_DROPPED_ARRIVALS_FULL,
    crate::observability::AV_INBOUND_DROPPED_CONSUMER_GONE,
    crate::observability::AV_INBOUND_DROPPED_RESOURCE,
];
const FIRST_CONTACT_OUTCOMES: &[&str] = &[
    "first_contact_record_names_other_key",
    "first_contact_record_not_self_signed",
    "first_contact_sender_budget_spent",
    "first_contact_link_budget_spent",
    "first_contact_node_budget_spent",
    "first_contact_at_capacity",
    "first_contact_proof_of_possession_failed",
    "first_contact_key_refused",
    "first_contact_directory_unreadable",
    "first_contact_no_directory",
    "first_contact_known_key",
    "first_contact_admitted",
    "first_contact_unsolicited_introductions",
    "owner_binding_admitted",
    "owner_binding_held",
    "owner_binding_answered",
    "owner_binding_answer_failed",
    "owner_binding_pushed",
    "owner_binding_push_incomplete",
    "owner_binding_deliver_oversized",
    "owner_binding_owner_unresolved",
    "owner_binding_receiver_unowned",
    "owner_binding_not_own_owner",
    "owner_binding_signature_invalid",
    "owner_binding_malformed",
    "owner_binding_door_refused",
];
const LINK_UP_STAGES: &[&str] = &[
    crate::observability::LINK_UP_STAGE_BUNDLE_GATE,
    crate::observability::LINK_UP_STAGE_ANNOUNCE_INTAKE,
    crate::observability::LINK_UP_STAGE_OWNER_BINDING,
];

// ─── Histogram names (recorded at their sites) ─────────────────────────────

/// One anti-entropy round's wall time, by kind.
pub const ROUND_DURATION: &str = "ciris.edge.replication.round.duration";
/// One advertise-sweep permit wait.
pub const SWEEP_PERMIT_WAIT: &str = "ciris.edge.sweep.permit.wait";
/// A responder link-up stage's time since `LinkEstablished`, by stage.
pub const RESPONDER_LINK_UP_DURATION: &str = "ciris.edge.responder.link_up.duration";

const KIND: LabelSpec = label("kind", &ENVELOPE_KINDS);

/// Every metric edge emits.
pub const METRIC_CATALOG: &[MetricSpec] = &[
    counter("ciris.edge.envelope.sent", Unit::Count, &[label("message_type", &MESSAGE_TYPES)], &["envelopes_sent_total"], "Envelopes sent, by message type."),
    counter("ciris.edge.envelope.received", Unit::Count, &[label("message_type", &MESSAGE_TYPES)], &["envelopes_received_total"], "Envelopes received, by message type."),
    counter("ciris.edge.send.failure", Unit::Count, &[label("transport", TRANSPORTS), label("class", SEND_FAILURE_CLASSES)], &["send_failures_total"], "Transport send failures, by transport and failure class."),
    counter("ciris.edge.verify.failure", Unit::Count, &[label("class", &VERIFY_CLASSES)], &["verify_failures_total"], "Inbound envelopes that failed verification, by class."),
    counter("ciris.edge.durable.enqueued", Unit::Count, &[label("class", &DELIVERY_CLASSES)], &["durable_enqueued_total"], "Sends enqueued on the durable outbound queue, by delivery class (cumulative, not a depth)."),
    counter("ciris.edge.transport.received", Unit::Bytes, &[label("transport", TRANSPORTS)], &["transport_bytes_in_total"], "Bytes received, by transport."),
    counter("ciris.edge.transport.sent", Unit::Bytes, &[label("transport", TRANSPORTS)], &["transport_bytes_out_total"], "Bytes sent, by transport."),
    counter("ciris.edge.inbound.dropped.low_trust", Unit::Count, &[], &["inbound_dropped_low_trust"], "Inbound envelopes dropped for a sender below the trust floor."),
    counter("ciris.edge.replication.round.outcome", Unit::Count, &[label("outcome", &ROUND_OUTCOMES)], &["replication_round_outcomes_total"], "Initiator anti-entropy rounds, by outcome."),
    counter("ciris.edge.replication.inbound.backpressure_drop", Unit::Count, &[], &["replication_inbound_backpressure_drops"], "Replication frames dropped on a full session inbox."),
    counter("ciris.edge.replication.inbound.backpressure_drop.by_role", Unit::Count, &[label("role", SESSION_ROLES)], &["replication_inbound_backpressure_drops_by_role"], "Replication frames dropped on a full session inbox, by the session's role."),
    counter("ciris.edge.blob.route.refusal", Unit::Count, &[label("reason", BLOB_ROUTE_REFUSALS)], &["blob_route_refusals"], "Scoped blob sends refused at routing, by reason."),
    counter("ciris.edge.blob.serve.refusal", Unit::Count, &[label("reason", BLOB_SERVE_REFUSALS)], &["blob_serve_refusals"], "Blob chunk serves refused, by reason."),
    counter("ciris.edge.blob.serve.legacy_dag_walk", Unit::Count, &[], &["blob_serve_legacy_dag_walks"], "Chunk serves answered by the legacy DAG walk."),
    counter("ciris.edge.blob.scoped_carrier", Unit::Count, &[label("carrier", BLOB_SCOPED_CARRIERS)], &["blob_scoped_carriers"], "Scoped blob frames, by side and carrier."),
    counter("ciris.edge.blob.pull.source", Unit::Count, &[label("source", BLOB_PULL_SOURCES)], &["blob_pull_sources"], "Blob pulls, by scope and holder source."),
    counter("ciris.edge.blob.pull.refusal", Unit::Count, &[label("reason", BLOB_PULL_REFUSALS)], &["blob_pull_refusals"], "Blob pulls refused, by reason."),
    counter("ciris.edge.blob.dag.phase.time", Unit::Nanoseconds, &[label("phase", BLOB_DAG_PHASES)], &["blob_dag_phases"], "Total time spent in each blob DAG phase."),
    counter("ciris.edge.blob.dag.phase.samples", Unit::Count, &[label("phase", BLOB_DAG_PHASES)], &["blob_dag_phases"], "Samples of each blob DAG phase."),
    counter("ciris.edge.blob.dag.chunks", Unit::Count, &[label("outcome", BLOB_DAG_CHUNK_COUNTS)], &["blob_dag_chunks"], "Blob DAG chunks, by outcome."),
    gauge("ciris.edge.blob.dag.chunks.peak", Unit::Count, &[label("peak", BLOB_DAG_CHUNK_PEAKS)], &["blob_dag_chunks"], "Blob DAG chunk peaks (in flight, adopt batch)."),
    counter("ciris.edge.delivery.receipt", Unit::Count, &[label("outcome", DELIVERY_RECEIPTS)], &["delivery_receipts"], "File delivery receipts, by outcome."),
    counter("ciris.edge.bootstrap.door", Unit::Count, &[label("decision", BOOTSTRAP_DOOR_DECISIONS)], &["bootstrap_door_outcomes"], "Bootstrap attribution door decisions."),
    counter("ciris.edge.transport.inbound.drop", Unit::Count, &[label("reason", TRANSPORT_INBOUND_DROPS)], &["transport_inbound_drops"], "Inbound transport frames dropped, by reason."),
    counter("ciris.edge.first_contact", Unit::Count, &[label("outcome", FIRST_CONTACT_OUTCOMES)], &["first_contact_outcomes"], "First-contact and owner-binding outcomes."),
    counter("ciris.edge.av.event", Unit::Count, &[label("event", AV_EVENTS)], &["av_plane"], "A/V plane events."),
    counter("ciris.edge.replication.routed", Unit::Count, &[label("role", SESSION_ROLES)], &["replication_routed_to_responder_total", "replication_routed_to_initiator_total"], "Inbound replication frames routed, by the receiving session's role."),
    counter("ciris.edge.replication.reply.dropped", Unit::Count, &[], &["replication_reply_dropped_total"], "Replication replies dropped with no session to take them."),
    counter("ciris.edge.announce.intake.eviction", Unit::Count, &[], &["announce_intake_evictions"], "Announces evicted from the intake queue."),
    counter("ciris.edge.transport.packet.dropped", Unit::Count, &[], &["transport_packets_dropped"], "Packets the transport dropped."),
    counter("ciris.edge.transport.known_destination.eviction", Unit::Count, &[], &["known_destination_evictions"], "Known-destination evictions (mirrored from leviculum)."),
    gauge("ciris.edge.link.pool.links", Unit::Count, &[], &["link_pool_links"], "Links in the dial pools."),
    gauge("ciris.edge.link.pool.max_per_destination", Unit::Count, &[], &["link_pool_max_per_destination"], "The largest dial pool for one destination."),
    counter("ciris.edge.link.pool.closed", Unit::Count, &[label("reason", &POOL_CLOSE_REASONS)], &["link_pool_closed_by_reason"], "Pooled links that left their pool, by reason."),
    gauge("ciris.edge.link.open", Unit::Count, &[label("direction", LINK_DIRECTIONS)], &["inbound_links", "outbound_links"], "Open links, by direction."),
    counter("ciris.edge.link.closed", Unit::Count, &[label("direction", LINK_DIRECTIONS), label("reason", &LINK_CLOSE_CAUSES)], &["inbound_link_closed_by_reason", "outbound_link_closed_by_reason"], "Links closed, by direction and cause."),
    counter("ciris.edge.link.before_binding", Unit::Count, &[], &["link_before_binding"], "Links that came up before their peer's binding."),
    counter("ciris.edge.announce.queue.drop_first_seen", Unit::Count, &[], &["announce_queue_drop_first_seen"], "First-seen announces dropped from a full queue."),
    counter("ciris.edge.channel_first.skipped_over_cap", Unit::Count, &[], &["channel_first_skipped_over_cap"], "Replies that skipped the channel-first path for being over its cap."),
    gauge("ciris.edge.announce.binding.latency.last", Unit::Seconds, &[], &["announce_to_binding_ms_last"], "The last announce-to-binding latency."),
    counter("ciris.edge.withhold", Unit::Count, &[label("reason", &WITHHOLD_REASONS)], &["withholds_by_reason"], "Rows withheld from a peer, by reason."),
    counter("ciris.edge.replication.envelope.served", Unit::Count, &[KIND], &["replication_envelopes_served_total"], "Envelopes served to peers, by kind."),
    counter("ciris.edge.replication.envelope.applied", Unit::Count, &[KIND], &["replication_applied_total"], "Replicated envelopes admitted, by kind."),
    counter("ciris.edge.replication.envelope.duplicate", Unit::Count, &[KIND], &["replication_duplicate_total"], "Replicated envelopes already held, by kind."),
    counter("ciris.edge.apply.refusal", Unit::Count, &[KIND], &["apply_refusals_by_kind"], "Replicated envelopes refused at admission, by kind."),
    counter("ciris.edge.apply.refusal.key", Unit::Count, &[label("reason", &KEY_REFUSAL_REASONS)], &["key_apply_refusals_by_reason"], "Key records refused at admission, by persist's reason."),
    counter("ciris.edge.apply.refusal.attestation", Unit::Count, &[label("reason", &ATTESTATION_REFUSAL_REASONS)], &["attestation_apply_refusals_by_reason"], "Attestations refused at admission, by persist's reason."),
    counter("ciris.edge.apply.refusal.class", Unit::Count, &[label("class", &APPLY_REFUSAL_CLASSES)], &["apply_refusals_by_class"], "Replicated rows refused at admission, by refusal class."),
    counter("ciris.edge.signer.parked", Unit::Count, &[KIND], &["rows_parked_on_signer"], "Rows parked waiting on their signer, by kind."),
    counter("ciris.edge.signer.released", Unit::Count, &[], &["signer_releases"], "Parked rows released when their signer arrived."),
    counter("ciris.edge.retry.suppressed", Unit::Count, &[], &["retry_suppressions"], "Re-applies suppressed by the refusal memory."),
    counter("ciris.edge.signer.park.eviction", Unit::Count, &[], &["signer_park_evictions"], "Parked rows evicted from a full park."),
    gauge("ciris.edge.refusal_memory.entries", Unit::Count, &[], &["refusal_memory_len"], "Entries in the refusal memory."),
    gauge("ciris.edge.refusal_memory.capacity", Unit::Count, &[], &["refusal_memory_capacity"], "The refusal memory's capacity."),
    gauge("ciris.edge.signer.park.entries", Unit::Count, &[], &["parked_on_signer_len"], "Rows parked waiting on their signer."),
    gauge("ciris.edge.signer.park.capacity", Unit::Count, &[], &["parked_on_signer_capacity"], "The signer park's capacity."),
    histogram(ROUND_DURATION, &[KIND], crate::observability::REPLICATION_ROUND_DURATION_BUCKETS_SECONDS, &["replication_round_duration_seconds"], &["src/observability.rs::observe_round_duration"], "One anti-entropy round's wall time, from holding the permit to its outcome."),
    histogram(SWEEP_PERMIT_WAIT, &[], crate::observability::SWEEP_PERMIT_WAIT_BUCKETS_SECONDS, &["sweep_permit_wait_seconds"], &["src/observability.rs::observe_sweep_permit_wait"], "The wait for a bounded advertise-sweep permit."),
    counter("ciris.edge.responder.round", Unit::Count, &[KIND, label("outcome", &RESPONDER_ROUND_OUTCOMES)], &["responder_rounds_total"], "Responder-side rounds, by kind and lifecycle outcome."),
    histogram(RESPONDER_LINK_UP_DURATION, &[label("stage", LINK_UP_STAGES)], crate::observability::RESPONDER_LINK_UP_BUCKETS_SECONDS, &["responder_link_up_seconds"], &["src/observability.rs::responder_link_up_stage"], "Time from a responder's LinkEstablished to the end of each link-up stage."),
    counter("ciris.edge.responder.link_up", Unit::Count, &[label("outcome", &LINK_UP_OUTCOMES)], &["responder_link_up_total"], "Responder link-ups, by outcome."),
    counter("ciris.edge.link.recovered", Unit::Count, &[], &["recovered_links_total"], "Links recovered after a transient failure."),
    counter("ciris.edge.ship.unclaimed_refused", Unit::Count, &[], &["unclaimed_ship_refused_total"], "Ships refused for a lane whose claim failed."),
];

/// Bundle fields that are deliberately not metrics.
pub const NOT_METRICS: &[NotMetric] = &[
    NotMetric {
        bundle_field: "peer_reachability_ratio",
        reason: "per peer (FSD §3.3: no per-peer series); served from the reachability tracker",
    },
    NotMetric {
        bundle_field: "recent_withholds",
        reason: "a 64-entry ring of (peer, detail) records; the counts are ciris.edge.withhold",
    },
    NotMetric {
        bundle_field: "removal_delivery",
        reason: "per tracked row, with the peers that have not acked it; served from the ledger",
    },
];

/// Every span name edge opens. Each `#[tracing::instrument]` in `src/` names
/// its span explicitly, so the name here is the name recorded.
pub const SPAN_CATALOG: &[SpanSpec] = &[
    SpanSpec {
        name: "anti_entropy_round",
        site: "src/replication/scheduler.rs",
        description: "One anti-entropy round (INFO), instrumenting the round future.",
    },
    SpanSpec {
        name: "transport.send",
        site: "src/edge.rs",
        description: "One transport send attempt (DEBUG).",
    },
    SpanSpec {
        name: "edge.send",
        site: "src/edge.rs::send",
        description: "Edge::send.",
    },
    SpanSpec {
        name: "edge.send_durable",
        site: "src/edge.rs::send_durable",
        description: "Edge::send_durable.",
    },
    SpanSpec {
        name: "edge.send_mandatory",
        site: "src/edge.rs::send_mandatory",
        description: "Edge::send_mandatory.",
    },
    SpanSpec {
        name: "edge.send_federation",
        site: "src/edge.rs::send_federation",
        description: "Edge::send_federation.",
    },
    SpanSpec {
        name: "edge.dispatch_inbound",
        site: "src/edge.rs::dispatch_inbound",
        description: "One inbound envelope's dispatch.",
    },
];

// ─── The pull publish ──────────────────────────────────────────────────────

/// Publish every counter and gauge in `b` through the facade (histograms are
/// recorded at their sites). See the module docs for the single-source and
/// one-`Edge`-per-process reasoning.
// One block per bundle field, straight-line; gauges are u64 levels far below
// 2^52, so the f64 cast loses nothing.
#[allow(clippy::too_many_lines, clippy::cast_precision_loss)]
pub fn publish_bundle(b: &crate::observability::EdgeMetricsBundle) {
    describe_all();
    let mut p = Publish::default();
    for (mt, v) in &b.envelopes_sent_total {
        p.count("ciris.edge.envelope.sent", &[mt.as_str()], *v);
    }
    for (mt, v) in &b.envelopes_received_total {
        p.count("ciris.edge.envelope.received", &[mt.as_str()], *v);
    }
    for ((t, class), v) in &b.send_failures_total {
        p.count("ciris.edge.send.failure", &[t.0, class.as_str()], *v);
    }
    for (c, v) in &b.verify_failures_total {
        p.count("ciris.edge.verify.failure", &[c.as_str()], *v);
    }
    for (c, v) in &b.durable_enqueued_total {
        p.count("ciris.edge.durable.enqueued", &[c.as_str()], *v);
    }
    for (t, v) in &b.transport_bytes_in_total {
        p.count("ciris.edge.transport.received", &[t.0], *v);
    }
    for (t, v) in &b.transport_bytes_out_total {
        p.count("ciris.edge.transport.sent", &[t.0], *v);
    }
    for (o, v) in &b.replication_round_outcomes_total {
        p.count("ciris.edge.replication.round.outcome", &[o.as_str()], *v);
    }
    for (name, map) in [
        (
            "ciris.edge.replication.inbound.backpressure_drop.by_role",
            &b.replication_inbound_backpressure_drops_by_role,
        ),
        ("ciris.edge.blob.route.refusal", &b.blob_route_refusals),
        ("ciris.edge.blob.serve.refusal", &b.blob_serve_refusals),
        ("ciris.edge.blob.scoped_carrier", &b.blob_scoped_carriers),
        ("ciris.edge.blob.pull.source", &b.blob_pull_sources),
        ("ciris.edge.blob.pull.refusal", &b.blob_pull_refusals),
        ("ciris.edge.delivery.receipt", &b.delivery_receipts),
        ("ciris.edge.bootstrap.door", &b.bootstrap_door_outcomes),
        (
            "ciris.edge.transport.inbound.drop",
            &b.transport_inbound_drops,
        ),
        ("ciris.edge.first_contact", &b.first_contact_outcomes),
        ("ciris.edge.av.event", &b.av_plane),
        ("ciris.edge.link.pool.closed", &b.link_pool_closed_by_reason),
        (
            "ciris.edge.apply.refusal.key",
            &b.key_apply_refusals_by_reason,
        ),
        (
            "ciris.edge.apply.refusal.attestation",
            &b.attestation_apply_refusals_by_reason,
        ),
        ("ciris.edge.apply.refusal.class", &b.apply_refusals_by_class),
        ("ciris.edge.responder.link_up", &b.responder_link_up_total),
    ] {
        for (k, v) in map {
            p.count(name, &[k.as_str()], *v);
        }
    }
    for (phase, (total_ns, samples)) in &b.blob_dag_phases {
        p.count(
            "ciris.edge.blob.dag.phase.time",
            &[phase.as_str()],
            *total_ns,
        );
        p.count(
            "ciris.edge.blob.dag.phase.samples",
            &[phase.as_str()],
            *samples,
        );
    }
    for (k, v) in &b.blob_dag_chunks {
        if BLOB_DAG_CHUNK_PEAKS.contains(&k.as_str()) {
            p.level("ciris.edge.blob.dag.chunks.peak", &[k.as_str()], *v as f64);
        } else {
            p.count("ciris.edge.blob.dag.chunks", &[k.as_str()], *v);
        }
    }
    for (name, v) in [
        (
            "ciris.edge.inbound.dropped.low_trust",
            b.inbound_dropped_low_trust,
        ),
        (
            "ciris.edge.replication.inbound.backpressure_drop",
            b.replication_inbound_backpressure_drops,
        ),
        (
            "ciris.edge.blob.serve.legacy_dag_walk",
            b.blob_serve_legacy_dag_walks,
        ),
        (
            "ciris.edge.replication.reply.dropped",
            b.replication_reply_dropped_total,
        ),
        (
            "ciris.edge.announce.intake.eviction",
            b.announce_intake_evictions,
        ),
        (
            "ciris.edge.transport.packet.dropped",
            b.transport_packets_dropped,
        ),
        (
            "ciris.edge.transport.known_destination.eviction",
            b.known_destination_evictions,
        ),
        ("ciris.edge.link.before_binding", b.link_before_binding),
        (
            "ciris.edge.announce.queue.drop_first_seen",
            b.announce_queue_drop_first_seen,
        ),
        (
            "ciris.edge.channel_first.skipped_over_cap",
            b.channel_first_skipped_over_cap,
        ),
        ("ciris.edge.signer.released", b.signer_releases),
        ("ciris.edge.retry.suppressed", b.retry_suppressions),
        ("ciris.edge.signer.park.eviction", b.signer_park_evictions),
        ("ciris.edge.link.recovered", b.recovered_links_total),
        (
            "ciris.edge.ship.unclaimed_refused",
            b.unclaimed_ship_refused_total,
        ),
    ] {
        p.count(name, &[], v);
    }
    p.count(
        "ciris.edge.replication.routed",
        &["responder"],
        b.replication_routed_to_responder_total,
    );
    p.count(
        "ciris.edge.replication.routed",
        &["initiator"],
        b.replication_routed_to_initiator_total,
    );
    for (direction, map) in [
        ("inbound", &b.inbound_link_closed_by_reason),
        ("outbound", &b.outbound_link_closed_by_reason),
    ] {
        for (reason, v) in map {
            p.count("ciris.edge.link.closed", &[direction, reason.as_str()], *v);
        }
    }
    for (name, map) in [
        (
            "ciris.edge.replication.envelope.served",
            &b.replication_envelopes_served_total,
        ),
        (
            "ciris.edge.replication.envelope.applied",
            &b.replication_applied_total,
        ),
        (
            "ciris.edge.replication.envelope.duplicate",
            &b.replication_duplicate_total,
        ),
        ("ciris.edge.apply.refusal", &b.apply_refusals_by_kind),
        ("ciris.edge.signer.parked", &b.rows_parked_on_signer),
    ] {
        for (kind, v) in map {
            p.count(name, &[kind.as_wire_str()], *v);
        }
    }
    for (key, v) in &b.responder_rounds_total {
        let (kind, outcome) = key.split_once(':').unwrap_or((key.as_str(), ""));
        p.count("ciris.edge.responder.round", &[kind, outcome], *v);
    }
    for (w, v) in &b.withholds_by_reason {
        p.count("ciris.edge.withhold", &[w.as_str()], *v);
    }
    p.level("ciris.edge.link.pool.links", &[], b.link_pool_links as f64);
    p.level(
        "ciris.edge.link.pool.max_per_destination",
        &[],
        b.link_pool_max_per_destination as f64,
    );
    p.level("ciris.edge.link.open", &["inbound"], b.inbound_links as f64);
    p.level(
        "ciris.edge.link.open",
        &["outbound"],
        b.outbound_links as f64,
    );
    p.level(
        "ciris.edge.announce.binding.latency.last",
        &[],
        b.announce_to_binding_ms_last as f64 / 1e3,
    );
    p.level(
        "ciris.edge.refusal_memory.entries",
        &[],
        b.refusal_memory_len as f64,
    );
    p.level(
        "ciris.edge.refusal_memory.capacity",
        &[],
        b.refusal_memory_capacity as f64,
    );
    p.level(
        "ciris.edge.signer.park.entries",
        &[],
        b.parked_on_signer_len as f64,
    );
    p.level(
        "ciris.edge.signer.park.capacity",
        &[],
        b.parked_on_signer_capacity as f64,
    );
    p.emit();
}

/// The Prometheus series names `spec` renders to under FSD §3.1's recommended
/// naming: dots and invalid characters to `_`, the unit word appended unless
/// the name already ends with it, `_total` on counters, and
/// `_bucket`/`_sum`/`_count` for histograms. The server's merged-catalogue
/// gate is authoritative; this lets edge fail first.
#[must_use]
pub fn rendered_series(name: &str, kind: MetricKind, unit: Unit) -> Vec<String> {
    let mut base: String = name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let word = match unit {
        Unit::Count => "",
        Unit::Percent => "ratio",
        u => u.as_str(),
    };
    if !word.is_empty() && !base.ends_with(&format!("_{word}")) {
        base.push('_');
        base.push_str(word);
    }
    match kind {
        MetricKind::Counter if base.ends_with("_total") => vec![base],
        MetricKind::Counter => vec![format!("{base}_total")],
        MetricKind::Gauge => vec![base],
        MetricKind::Histogram => vec![
            format!("{base}_bucket"),
            format!("{base}_sum"),
            format!("{base}_count"),
        ],
    }
}

/// CIRISEdge#820 — the completeness gate (FSD §3.3).
#[cfg(test)]
mod telemetry_catalog_gate {
    use std::collections::{BTreeSet, HashMap};

    use metrics_util::debugging::{DebugValue, DebuggingRecorder};
    use metrics_util::MetricKind as FacadeKind;

    use super::*;
    use crate::observability::{EdgeMetrics, EdgeMetricsBundle, EDGE_METRICS_BUNDLE_FIELDS};
    use crate::transport::TransportId;

    type Series = Vec<(FacadeKind, String, Vec<(String, String)>, DebugValue)>;

    fn capture(f: impl FnOnce()) -> Series {
        let recorder = DebuggingRecorder::new();
        let snapshotter = recorder.snapshotter();
        metrics::with_local_recorder(&recorder, f);
        snapshotter
            .snapshot()
            .into_vec()
            .into_iter()
            .map(|(ck, _, _, v)| {
                let (kind, key) = ck.into_parts();
                let labels = key
                    .labels()
                    .map(|l| (l.key().to_owned(), l.value().to_owned()))
                    .collect();
                (kind, key.name().to_owned(), labels, v)
            })
            .collect()
    }

    fn strs(values: &[&str]) -> HashMap<String, u64> {
        values.iter().map(|v| ((*v).to_owned(), 1)).collect()
    }

    /// A bundle holding every declared label value of every family.
    fn full_bundle() -> EdgeMetricsBundle {
        let mut b = EdgeMetrics::new().snapshot();
        b.envelopes_sent_total = MessageType::ALL.iter().map(|m| (m.clone(), 1)).collect();
        b.envelopes_received_total = b.envelopes_sent_total.clone();
        for t in TRANSPORTS.iter().copied() {
            for c in SEND_FAILURE_CLASSES {
                b.send_failures_total
                    .insert((TransportId(t), (*c).to_owned()), 1);
            }
            b.transport_bytes_in_total.insert(TransportId(t), 1);
            b.transport_bytes_out_total.insert(TransportId(t), 1);
        }
        b.verify_failures_total = VerifyErrorClass::ALL.iter().map(|c| (*c, 1)).collect();
        b.durable_enqueued_total = DeliveryClass::ALL.iter().map(|c| (*c, 1)).collect();
        b.replication_round_outcomes_total = RoundOutcome::ALL.iter().map(|c| (*c, 1)).collect();
        b.withholds_by_reason = WithholdReason::ALL.iter().map(|c| (*c, 1)).collect();
        b.replication_inbound_backpressure_drops_by_role = strs(SESSION_ROLES);
        b.blob_route_refusals = strs(BLOB_ROUTE_REFUSALS);
        b.blob_serve_refusals = strs(BLOB_SERVE_REFUSALS);
        b.blob_scoped_carriers = strs(BLOB_SCOPED_CARRIERS);
        b.blob_pull_sources = strs(BLOB_PULL_SOURCES);
        b.blob_pull_refusals = strs(BLOB_PULL_REFUSALS);
        b.blob_dag_phases = BLOB_DAG_PHASES
            .iter()
            .map(|p| ((*p).to_owned(), (10, 1)))
            .collect();
        b.blob_dag_chunks = strs(BLOB_DAG_CHUNK_COUNTS);
        b.blob_dag_chunks.extend(strs(BLOB_DAG_CHUNK_PEAKS));
        b.delivery_receipts = strs(DELIVERY_RECEIPTS);
        b.bootstrap_door_outcomes = strs(BOOTSTRAP_DOOR_DECISIONS);
        b.transport_inbound_drops = strs(TRANSPORT_INBOUND_DROPS);
        b.first_contact_outcomes = strs(FIRST_CONTACT_OUTCOMES);
        b.av_plane = strs(AV_EVENTS);
        b.link_pool_closed_by_reason = strs(&POOL_CLOSE_REASONS);
        b.inbound_link_closed_by_reason = strs(&LINK_CLOSE_CAUSES);
        b.outbound_link_closed_by_reason = strs(&LINK_CLOSE_CAUSES);
        b.key_apply_refusals_by_reason = strs(&KEY_REFUSAL_REASONS);
        b.attestation_apply_refusals_by_reason = strs(&ATTESTATION_REFUSAL_REASONS);
        b.apply_refusals_by_class = strs(&APPLY_REFUSAL_CLASSES);
        b.responder_link_up_total = strs(&LINK_UP_OUTCOMES);
        let kinds: HashMap<EnvelopeKind, u64> = EnvelopeKind::ALL.iter().map(|k| (*k, 1)).collect();
        b.replication_envelopes_served_total = kinds.clone();
        b.replication_applied_total = kinds.clone();
        b.replication_duplicate_total = kinds.clone();
        b.apply_refusals_by_kind = kinds.clone();
        b.rows_parked_on_signer = kinds;
        for k in ENVELOPE_KINDS {
            for o in RESPONDER_ROUND_OUTCOMES {
                b.responder_rounds_total.insert(format!("{k}:{o}"), 1);
            }
        }
        b
    }

    /// Record every histogram through its production site.
    fn observe_every_histogram(m: &EdgeMetrics) {
        for k in EnvelopeKind::ALL {
            m.observe_round_duration(k, std::time::Duration::from_millis(200));
        }
        m.observe_sweep_permit_wait(std::time::Duration::from_millis(20));
        for (i, stage) in LINK_UP_STAGES.iter().enumerate() {
            let link = [u8::try_from(i).unwrap_or(0); 16];
            m.responder_link_up_begin(link);
            m.responder_link_up_stage(link, *stage);
        }
    }

    /// (a) every published series is catalogued, with exactly its declared
    /// label keys and only declared values; (b) every catalogue entry is
    /// published.
    #[test]
    fn every_published_series_is_catalogued_and_every_entry_is_published() {
        let m = EdgeMetrics::new();
        let series = capture(|| {
            publish_bundle(&full_bundle());
            observe_every_histogram(&m);
        });
        let mut seen = BTreeSet::new();
        for (kind, name, labels, _) in &series {
            let spec = METRIC_CATALOG
                .iter()
                .find(|s| s.name == name)
                .unwrap_or_else(|| panic!("{name} is published but not catalogued"));
            let want = match spec.kind {
                MetricKind::Counter => FacadeKind::Counter,
                MetricKind::Gauge => FacadeKind::Gauge,
                MetricKind::Histogram => FacadeKind::Histogram,
            };
            assert_eq!(*kind, want, "{name}: published kind");
            let keys: Vec<&str> = labels.iter().map(|(k, _)| k.as_str()).collect();
            let declared: Vec<&str> = spec.labels.iter().map(|l| l.key).collect();
            assert_eq!(keys, declared, "{name}: label keys");
            for (k, v) in labels {
                let set = spec
                    .labels
                    .iter()
                    .find(|l| l.key == k)
                    .expect("declared key");
                assert!(
                    set.values.contains(&v.as_str()),
                    "{name}: label {k}={v} is not declared (a full bundle publishes no `other`)"
                );
            }
            seen.insert(name.clone());
        }
        let unpublished: Vec<&str> = METRIC_CATALOG
            .iter()
            .map(|s| s.name)
            .filter(|n| !seen.contains(*n))
            .collect();
        assert!(
            unpublished.is_empty(),
            "catalogued but never published: {unpublished:?}"
        );
    }

    /// A value outside a label's set publishes as `other`, never as itself,
    /// and two such values sum into the one `other` series.
    #[test]
    fn an_undeclared_label_value_publishes_as_other() {
        let mut b = EdgeMetrics::new().snapshot();
        b.send_failures_total
            .insert((TransportId("host-minted"), "peer said: no".to_owned()), 2);
        b.send_failures_total
            .insert((TransportId("another"), "free text".to_owned()), 3);
        let series = capture(|| publish_bundle(&b));
        let failures: Vec<_> = series
            .iter()
            .filter(|(_, n, _, _)| n == "ciris.edge.send.failure")
            .collect();
        assert_eq!(failures.len(), 1, "{failures:?}");
        let (_, _, labels, value) = failures[0];
        assert_eq!(
            labels,
            &vec![
                ("transport".to_owned(), OTHER_LABEL.to_owned()),
                ("class".to_owned(), OTHER_LABEL.to_owned())
            ]
        );
        assert_eq!(*value, DebugValue::Counter(5));
    }

    /// (c) every bundle field is projected by a spec or declared not a
    /// metric, never both, and no spec names a field the bundle lacks.
    #[test]
    fn every_bundle_field_is_a_metric_or_declared_not_one() {
        let projected: BTreeSet<&str> = METRIC_CATALOG
            .iter()
            .flat_map(|s| s.bundle_fields.iter().copied())
            .collect();
        let not: BTreeSet<&str> = NOT_METRICS.iter().map(|n| n.bundle_field).collect();
        let fields: BTreeSet<&str> = EDGE_METRICS_BUNDLE_FIELDS.iter().copied().collect();
        let both: Vec<_> = projected.intersection(&not).collect();
        assert!(both.is_empty(), "both a metric and NOT_METRICS: {both:?}");
        let missing: Vec<_> = fields
            .iter()
            .filter(|f| !projected.contains(*f) && !not.contains(*f))
            .collect();
        assert!(
            missing.is_empty(),
            "bundle fields with no catalogue entry (add a MetricSpec or a NOT_METRICS row): {missing:?}"
        );
        let unknown: Vec<_> = projected
            .union(&not)
            .filter(|f| !fields.contains(*f))
            .collect();
        assert!(
            unknown.is_empty(),
            "catalogue names fields the bundle lacks: {unknown:?}"
        );
    }

    /// (d) no two catalogue entries, edge's or edge's against leviculum's,
    /// render to one Prometheus series name; names are unique and namespaced.
    #[test]
    fn rendered_series_names_do_not_collide() {
        let mut owner: HashMap<String, String> = HashMap::new();
        let mut entries: Vec<(String, MetricKind, Unit)> = METRIC_CATALOG
            .iter()
            .map(|s| {
                assert!(s.name.starts_with("ciris.edge."), "{}: namespace", s.name);
                (s.name.to_owned(), s.kind, s.unit)
            })
            .collect();
        #[cfg(feature = "transport-reticulum")]
        for s in leviculum_std::telemetry::METRIC_CATALOG {
            let kind = match s.kind {
                leviculum_std::telemetry::MetricKind::Counter => MetricKind::Counter,
                leviculum_std::telemetry::MetricKind::Gauge => MetricKind::Gauge,
            };
            entries.push((s.name.to_owned(), kind, s.unit));
        }
        for (name, kind, unit) in entries {
            for series in rendered_series(&name, kind, unit) {
                if let Some(prev) = owner.insert(series.clone(), name.clone()) {
                    panic!("{prev} and {name} both render {series}");
                }
            }
        }
    }

    /// Histogram buckets are ascending and every histogram names its sites.
    #[test]
    fn histograms_declare_buckets_and_sites() {
        for s in METRIC_CATALOG {
            if s.kind == MetricKind::Histogram {
                assert!(!s.buckets.is_empty() && !s.sites.is_empty(), "{}", s.name);
                assert!(s.buckets.windows(2).all(|w| w[0] < w[1]), "{}", s.name);
            } else {
                assert!(s.buckets.is_empty() && s.sites.is_empty(), "{}", s.name);
            }
        }
    }

    fn sources() -> Vec<(String, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, String)>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let rel = path
                        .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                        .expect("under the crate")
                        .display()
                        .to_string();
                    out.push((rel, std::fs::read_to_string(&path).expect("read source")));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    const THIS_FILE: &str = "src/telemetry_catalog.rs";

    /// (e) the facade is touched only from this module, and (h) every
    /// histogram is recorded only from the sites its spec lists (each a sync
    /// fn on `EdgeMetrics`, so no span guard can be held across an await
    /// there; `span_guard_790` bans span guards in `src/` outright).
    #[test]
    fn the_facade_is_used_only_here_and_histograms_only_from_their_sites() {
        let facade = [
            concat!("metrics", "::counter!"),
            concat!("metrics", "::gauge!"),
            concat!("metrics", "::histogram!"),
            concat!("metrics", "::describe_"),
            concat!("use ", "metrics::"),
        ];
        let call = concat!("record", "_histogram(");
        let consts = [
            ("ROUND_DURATION", ROUND_DURATION),
            ("SWEEP_PERMIT_WAIT", SWEEP_PERMIT_WAIT),
            ("RESPONDER_LINK_UP_DURATION", RESPONDER_LINK_UP_DURATION),
        ];
        let mut found: Vec<(String, &str)> = Vec::new();
        let mut stray = Vec::new();
        for (file, text) in sources() {
            if file == THIS_FILE {
                continue;
            }
            let lines: Vec<&str> = text.lines().collect();
            for (n, line) in lines.iter().enumerate() {
                let code = line.split("//").next().unwrap_or("");
                if facade.iter().any(|f| code.contains(f)) {
                    stray.push(format!("{file}:{}: {}", n + 1, line.trim()));
                }
                if !code.contains(call) {
                    continue;
                }
                let site_fn = lines[..n]
                    .iter()
                    .rev()
                    .find_map(|l| {
                        let l = l.trim_start();
                        let rest = l
                            .strip_prefix("pub fn ")
                            .or_else(|| l.strip_prefix("fn "))?;
                        Some(rest.split(['(', '<']).next().unwrap_or(rest).to_owned())
                    })
                    .unwrap_or_default();
                let window = lines[n..lines.len().min(n + 3)].join(" ");
                let (_, name) = consts
                    .iter()
                    .find(|(c, _)| window.contains(&format!("telemetry_catalog::{c}")))
                    .unwrap_or_else(|| {
                        panic!("{file}:{}: histogram name not a catalogue const", n + 1)
                    });
                found.push((format!("{file}::{site_fn}"), *name));
            }
        }
        assert!(
            stray.is_empty(),
            "the metrics facade used outside {THIS_FILE}:\n{}",
            stray.join("\n")
        );
        for (site, name) in &found {
            assert!(
                spec(name).sites.contains(&site.as_str()),
                "{name} recorded from {site}, which its spec does not list"
            );
        }
        for s in METRIC_CATALOG
            .iter()
            .filter(|s| s.kind == MetricKind::Histogram)
        {
            for site in s.sites {
                assert!(
                    found.iter().any(|(f, n)| f == site && *n == s.name),
                    "{}: listed site {site} records nothing",
                    s.name
                );
            }
        }
    }

    /// (e) every span name opened in `src/` is in [`SPAN_CATALOG`], every
    /// `#[instrument]` names its span, and every catalogued span is opened.
    #[test]
    fn every_span_name_is_catalogued() {
        fn quoted(after: &str) -> Option<String> {
            let rest = after.trim_start().strip_prefix('"')?;
            Some(rest.split('"').next()?.to_owned())
        }
        let mut names = BTreeSet::new();
        let mut unnamed = Vec::new();
        for (file, text) in sources() {
            if file == THIS_FILE {
                continue;
            }
            for level in ["info", "debug", "trace", "warn", "error"] {
                let mac = format!("{level}{}", concat!("_span", "!("));
                for (i, _) in text.match_indices(&mac) {
                    match quoted(&text[i + mac.len()..]) {
                        Some(n) => {
                            names.insert(n);
                        }
                        None => unnamed.push(format!("{file}: {mac} without a literal name")),
                    }
                }
            }
            for attr in [
                concat!("#[tracing::", "instrument("),
                concat!("#[", "instrument("),
            ] {
                for (i, _) in text.match_indices(attr) {
                    let body = &text[i..];
                    let body = &body[..body.find(")]").unwrap_or(body.len())];
                    match body
                        .find("name =")
                        .and_then(|j| quoted(&body[j + "name =".len()..]))
                    {
                        Some(n) => {
                            names.insert(n);
                        }
                        None => {
                            unnamed.push(format!("{file}: #[instrument] without `name = \"…\"`"))
                        }
                    }
                }
            }
        }
        assert!(unnamed.is_empty(), "{}", unnamed.join("\n"));
        let catalogued: BTreeSet<String> = SPAN_CATALOG.iter().map(|s| s.name.to_owned()).collect();
        let uncatalogued: Vec<_> = names.difference(&catalogued).collect();
        assert!(
            uncatalogued.is_empty(),
            "span names not in SPAN_CATALOG: {uncatalogued:?}"
        );
        let unopened: Vec<_> = catalogued.difference(&names).collect();
        assert!(
            unopened.is_empty(),
            "catalogued spans nothing opens: {unopened:?}"
        );
    }

    /// Persist's refusal tokens: the catalogued set is exactly what edge's
    /// mapping fns book, so the Duplicate-mapped token is left out by the
    /// mapping, not by hand.
    #[test]
    fn refusal_reason_sets_are_what_the_mapping_books() {
        use ciris_persist::federation::attestation_apply::ReplicatedAttestationOutcome;
        use ciris_persist::federation::register::ReplicatedKeyOutcome;
        let booked: BTreeSet<&str> = KeyRefusalReason::ALL
            .iter()
            .filter_map(|r| {
                crate::replication::bridge::key_outcome_to_apply(
                    Ok(ReplicatedKeyOutcome::Refused { reason: *r }),
                    "",
                )
                .1
            })
            .collect();
        assert_eq!(
            booked,
            KEY_REFUSAL_REASONS.iter().copied().collect::<BTreeSet<_>>()
        );
        let booked: BTreeSet<&str> = AttestationRefusalReason::ALL
            .iter()
            .filter_map(|r| {
                crate::replication::bridge::attestation_outcome_to_apply(
                    ReplicatedAttestationOutcome::Refused { reason: *r },
                    "",
                )
                .1
            })
            .collect();
        assert_eq!(
            booked,
            ATTESTATION_REFUSAL_REASONS
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        );
    }

    /// The `transport` set is the production `TransportId` consts.
    #[test]
    fn transports_are_the_transport_id_consts() {
        let consts = [
            TransportId::HTTP,
            TransportId::RETICULUM_RS,
            TransportId::LEVICULUM,
            TransportId::LORA,
            TransportId::SERIAL,
            TransportId::I2P,
        ];
        let ids: Vec<&str> = consts.iter().map(|t| t.0).collect();
        assert_eq!(ids, TRANSPORTS);
    }
}
