//! The catalogue's completeness, the bag's mechanics, and the witness harness
//! every signal test leans on.

// `-1.0` and `0.0` here are sentinels and whole seconds, stored exactly.
#![allow(clippy::float_cmp)]

use super::*;
use crate::observability::{
    EdgeMetrics, FlatMetrics, AV_PLANE_LABELS, DIRECT_LINK_LABELS, EDGE_METRICS_BUNDLE_FIELDS,
    LINK_SEAL_LABELS, LINK_SHAPING_FRAMES_REAL, LINK_SHAPING_LABELS, LINK_STALL_LABELS,
    PEER_BINDING_LABELS,
};

fn flat(m: &EdgeMetrics) -> FlatMetrics {
    m.snapshot().flatten()
}

fn read(f: &FlatMetrics, key: &str) -> f64 {
    #[allow(clippy::cast_precision_loss)]
    if let Some(n) = f.counters.get(key) {
        return *n as f64;
    }
    *f.gauges
        .get(key)
        .unwrap_or_else(|| panic!("{key} is not a series"))
}

/// What the signal tests read through: the value of a series before and after
/// a real change, and that it moved the way it was claimed to.
struct Witness<'m> {
    metrics: &'m EdgeMetrics,
    before: FlatMetrics,
}

impl<'m> Witness<'m> {
    fn of(metrics: &'m EdgeMetrics) -> Self {
        Self {
            before: flat(metrics),
            metrics,
        }
    }

    fn rose(&self, key: &str) {
        let (was, now) = (read(&self.before, key), read(&flat(self.metrics), key));
        assert!(now > was, "{key} should rise: {was} -> {now}");
    }

    fn fell(&self, key: &str) {
        let (was, now) = (read(&self.before, key), read(&flat(self.metrics), key));
        assert!(now < was, "{key} should fall: {was} -> {now}");
    }
}

#[test]
fn every_bundle_field_has_exactly_one_row_and_every_row_a_field() {
    let mut rows: Vec<&str> = TELEMETRY_CATALOGUE.iter().map(|s| s.field).collect();
    rows.sort_unstable();
    let before = rows.len();
    rows.dedup();
    assert_eq!(before, rows.len(), "a field is catalogued twice");
    let mut fields: Vec<&str> = EDGE_METRICS_BUNDLE_FIELDS.to_vec();
    fields.sort_unstable();
    assert_eq!(fields, rows);
}

#[test]
fn every_name_is_a_unique_dotted_ciris_edge_name() {
    let mut names = std::collections::BTreeSet::new();
    for s in TELEMETRY_CATALOGUE {
        assert!(s.name.starts_with("ciris.edge."), "{}", s.name);
        assert!(
            s.name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'),
            "{}",
            s.name
        );
        assert!(names.insert(s.name), "{} is used twice", s.name);
        assert!(!s.description.is_empty(), "{} says nothing", s.name);
    }
}

/// A peer in a label is a per-peer series, hashed or not. Two old fields are
/// keyed by peer; nothing may join them, and neither may leave the operator.
#[test]
fn no_label_names_a_peer_but_the_two_old_ones_and_they_stay_operator_only() {
    let mut peer_keyed = Vec::new();
    for s in TELEMETRY_CATALOGUE {
        let Some((key, values)) = s.label else {
            continue;
        };
        if values == LabelValues::PeerKeyed {
            assert_eq!(s.exposure, Exposure::OperatorOnly, "{}", s.field);
            peer_keyed.push(s.field);
            continue;
        }
        for forbidden in ["peer", "link", "room", "key_id", "address", "dest"] {
            assert!(!key.contains(forbidden), "{}: `{key}`", s.field);
        }
    }
    assert_eq!(peer_keyed, ["peer_reachability_ratio", "recent_withholds"]);
}

/// The one public field. A new one is a privacy decision, made here.
#[test]
fn liveness_is_the_only_public_field() {
    let public: Vec<&str> = TELEMETRY_CATALOGUE
        .iter()
        .filter(|s| s.exposure == Exposure::PublicSafe)
        .map(|s| s.field)
        .collect();
    assert_eq!(public, ["node_alive"]);
}

/// `FSD/PRIVACY_MODES.md` §5 — what must stay out of the bundle altogether.
#[test]
fn per_link_and_real_traffic_series_are_not_in_the_bundle() {
    for f in EDGE_METRICS_BUNDLE_FIELDS {
        for held_back in ["transit", "peers_shaping", "homed", "tail", "referral_peer"] {
            assert!(!f.contains(held_back), "{f}");
        }
    }
    let m = EdgeMetrics::default();
    m.inc_link_shaping(LINK_SHAPING_FRAMES_REAL);
    let bundle = m.snapshot();
    assert!(!bundle.link_shaping.contains_key(LINK_SHAPING_FRAMES_REAL));
    let key = format!("link_shaping.{LINK_SHAPING_FRAMES_REAL}");
    assert!(!bundle.flatten().counters.contains_key(&key));
    assert_eq!(
        m.link_shaping().get(LINK_SHAPING_FRAMES_REAL),
        Some(&1),
        "kept in process for the transport's own witnesses"
    );
}

/// A missing series and a 0 are different answers, so every closed label is
/// a series before anything happens.
#[test]
fn every_closed_label_is_present_at_zero_on_a_fresh_bag() {
    let f = flat(&EdgeMetrics::default());
    let series = |field: &str, label: &str| {
        let at = format!("{field}.{label}");
        let hist = format!("{at}.count");
        f.counters.contains_key(&at) || f.gauges.contains_key(&at) || f.counters.contains_key(&hist)
    };
    let mut missing = Vec::new();
    for s in TELEMETRY_CATALOGUE {
        let values: Vec<&str> = match s.label {
            Some((_, LabelValues::Closed(v))) => v.to_vec(),
            Some((_, LabelValues::EnvelopeKinds)) => {
                EnvelopeKind::ALL.iter().map(|k| k.as_wire_str()).collect()
            }
            _ => continue,
        };
        for label in values {
            if label != LINK_SHAPING_FRAMES_REAL && !series(s.field, label) {
                missing.push(format!("{}.{label}", s.field));
            }
        }
    }
    assert!(missing.is_empty(), "{missing:?}");
    for key in load_tier_change_keys() {
        assert!(f
            .counters
            .contains_key(&format!("load_tier_changes_total.{key}")));
    }
    for class in REFUSAL_CLASSES {
        let key = format!("apply_refusals.{APPLY_REFUSAL_REFUSED_THEN_ADMITTED}:{class}");
        assert!(f.counters.contains_key(&key), "{key}");
    }
}

/// A label list that forgets a new constant would silently leave that series
/// sparse, so the source is the list's witness.
#[test]
fn every_label_constant_is_in_its_family_list() {
    let source = include_str!("../observability.rs");
    let constants = |prefix: &str| -> Vec<String> {
        let mut out = Vec::new();
        let mut text = source;
        while let Some(at) = text.find(&format!("pub const {prefix}")) {
            let rest = &text[at..];
            let (decl, tail) = rest.split_once(';').expect("a const ends");
            if decl.contains("&str =") {
                let value = decl.split('"').nth(1).expect("a string value");
                out.push(value.to_owned());
            }
            text = tail;
        }
        out
    };
    for (prefix, list) in [
        ("LINK_SEAL_", LINK_SEAL_LABELS),
        ("LINK_SHAPING_", LINK_SHAPING_LABELS),
        ("DIRECT_LINK_", DIRECT_LINK_LABELS),
        ("AV_", AV_PLANE_LABELS),
        ("ALM_", AV_PLANE_LABELS),
        ("LINK_STALL_", LINK_STALL_LABELS),
        ("ADVERTISE_", crate::observability::ADVERTISE_LABELS),
        ("PEER_BINDING_", PEER_BINDING_LABELS),
    ] {
        for value in constants(prefix) {
            assert!(
                value == LINK_SHAPING_FRAMES_REAL || list.contains(&value.as_str()),
                "{value} is not in its family's list"
            );
        }
    }
}

#[test]
fn the_refusal_class_list_is_the_enum_and_the_decision_list_too() {
    use crate::replication::bridge::ApplyRefusalClass;
    for class in ApplyRefusalClass::ALL {
        assert!(REFUSAL_CLASSES.contains(&class.as_str()), "{class:?}");
    }
    assert_eq!(ApplyRefusalClass::ALL.len() + 1, REFUSAL_CLASSES.len());
    for (kind, _) in crate::decision_rows::DecisionRowKind::PREFIXES {
        assert!(DECISION_ROW_KINDS.contains(&kind.as_str()), "{kind:?}");
    }
}

#[test]
fn every_series_this_module_owns_stays_inside_the_slots() {
    for bounds in [
        EVENT_HANDLER_BUCKETS,
        SEAL_KEYING_BUCKETS,
        REPLICATION_WAIT_BUCKETS,
        SHAPING_ROW_WAIT_BUCKETS,
        ALM_FAILOVER_GAP_BUCKETS,
        CALL_SETUP_BUCKETS,
        FIRST_CONTACT_BUCKETS,
        REFUSAL_ATTEMPT_BUCKETS,
        WAKE_FIRST_ROUND_BUCKETS,
    ] {
        assert!(bounds.len() < HIST_SLOTS, "{bounds:?}");
        assert!(bounds.windows(2).all(|w| w[0] < w[1]), "{bounds:?}");
    }
}

#[test]
fn a_histogram_lands_each_value_in_its_le_bucket() {
    let h = AtomicHistogram::default();
    h.observe(EVENT_HANDLER_BUCKETS, Duration::from_micros(50));
    h.observe(EVENT_HANDLER_BUCKETS, Duration::from_millis(5));
    h.observe(EVENT_HANDLER_BUCKETS, Duration::from_secs(60));
    let s = h.snapshot(EVENT_HANDLER_BUCKETS);
    assert_eq!(s.count, 3);
    assert_eq!(s.cumulative[0], 1, "<= 100 us");
    assert_eq!(s.cumulative[1], 1, "<= 1 ms");
    assert_eq!(s.cumulative[2], 2, "<= 10 ms");
    assert_eq!(s.cumulative[7], 2, "<= 30 s");
    assert_eq!(s.cumulative[8], 3, "+Inf");
    assert!((s.sum_seconds - 60.00505).abs() < 1e-6);
}

/// The harness can't be fooled by a value someone stored: nothing happened
/// between its two reads, so nothing rose.
#[test]
#[should_panic(expected = "should rise")]
fn a_stored_constant_does_not_pass() {
    let m = EdgeMetrics::default();
    m.telemetry.set_load(2, 2);
    Witness::of(&m).rose("load_tier");
}

/// An age is measured, not stored: with no beat it grows on its own, and a
/// reader cannot mistake a stale stamp for a live loop.
#[test]
fn a_loop_that_stops_beating_ages() {
    let t = EdgeTelemetry::default();
    let key = "event";
    assert_eq!(t.snapshot().loop_last_progress_age_seconds[key], -1.0);
    t.loop_stamps[LoopName::Event as usize].store(1, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(1100));
    assert!(t.snapshot().loop_last_progress_age_seconds[key] >= 1.0);
    t.beat(LoopName::Event);
    assert_eq!(t.snapshot().loop_last_progress_age_seconds[key], 0.0);
    t.beat_off(LoopName::Event);
    assert_eq!(
        t.snapshot().loop_last_progress_age_seconds[key],
        -1.0,
        "parked reads as not running, not as wedged"
    );
}

#[test]
fn alive_needs_both_loops_and_a_stale_one_clears_it() {
    let t = EdgeTelemetry::default();
    assert_eq!(t.snapshot().node_alive, 0, "nothing has turned");
    t.beat(LoopName::Event);
    assert_eq!(t.snapshot().node_alive, 0, "the ladder has not");
    t.beat(LoopName::Ladder);
    assert_eq!(t.snapshot().node_alive, 1);
    t.beat_off(LoopName::Ladder);
    assert_eq!(t.snapshot().node_alive, 0);
}

#[test]
fn a_reply_lane_counts_while_it_lives_and_not_after() {
    let t = EdgeTelemetry::default();
    let a = Arc::new(AtomicUsize::new(3));
    let b = Arc::new(AtomicUsize::new(7));
    t.register_reply_lane(&a);
    t.register_reply_lane(&b);
    let q = t.snapshot().replication_reply_queued;
    assert_eq!((q["sum"], q["max"]), (10, 7));
    drop(b);
    let q = t.snapshot().replication_reply_queued;
    assert_eq!((q["sum"], q["max"]), (3, 3));
}

#[test]
fn wake_to_first_round_counts_once_per_wake() {
    let m = EdgeMetrics::default();
    let w = Witness::of(&m);
    m.telemetry.note_round_completed();
    assert_eq!(m.snapshot().wake_first_round_duration_seconds.count, 0);
    m.telemetry.note_woken();
    m.telemetry.note_round_completed();
    m.telemetry.note_round_completed();
    assert_eq!(m.snapshot().wake_first_round_duration_seconds.count, 1);
    w.rose("wake_first_round_duration_seconds.count");
}

fn links(n: usize) -> impl Fn(ShapingClass) -> usize {
    move |_| n
}

fn ten_seconds(_: ShapingClass) -> Duration {
    Duration::from_secs(10)
}

#[test]
fn nothing_shaped_is_readable_until_a_window_closes() {
    let m = EdgeMetrics::default();
    let w = &m.telemetry.shaping_windows;
    w.tick(1, links(3), ten_seconds);
    for _ in 0..40 {
        w.note_real(ShapingClass::Server);
    }
    w.note_row_wait(ShapingClass::Server, Duration::from_secs(2));
    let hidden = m.snapshot();
    assert_eq!(hidden.shaping_frames_real_windowed["server"], 0);
    assert_eq!(hidden.shaping_row_wait_seconds["server"].count, 0);

    w.tick(9_000, links(3), ten_seconds);
    assert_eq!(
        m.snapshot().shaping_frames_real_windowed["server"],
        0,
        "the window is still open"
    );
    w.tick(10_001, links(3), ten_seconds);
    let shown = m.snapshot();
    assert_eq!(
        shown.shaping_frames_real_windowed["server"], 32,
        "rounded down to a multiple of 16"
    );
    assert_eq!(shown.shaping_row_wait_seconds["server"].count, 1);
    assert_eq!(shown.shaping_frames_real_windowed["home"], 0, "per class");
}

/// With one link an aggregate is a per-peer series. Under the floor the window
/// is dropped, and a later window never carries it to the bundle.
#[test]
fn a_class_under_the_floor_publishes_nothing_now_or_later() {
    let m = EdgeMetrics::default();
    let w = &m.telemetry.shaping_windows;
    w.tick(1, links(2), ten_seconds);
    for _ in 0..64 {
        w.note_real(ShapingClass::Home);
    }
    w.note_row_wait(ShapingClass::Home, Duration::from_secs(2));
    w.tick(10_001, links(2), ten_seconds);
    let s = m.snapshot();
    assert_eq!(s.shaping_frames_real_windowed["home"], 0);
    assert_eq!(s.shaping_row_wait_seconds["home"].count, 0);
    assert_eq!(s.shaping_windows_withheld["home"], 1, "and it says so");

    w.tick(20_001, links(3), ten_seconds);
    let s = m.snapshot();
    assert_eq!(s.shaping_frames_real_windowed["home"], 0, "nothing carried");
    assert_eq!(
        s.shaping_windows_withheld["home"], 1,
        "an empty window hides nothing"
    );
}

#[test]
fn a_tier_change_is_booked_with_who_put_it_there() {
    let m = EdgeMetrics::default();
    let ladder = crate::load_ladder::SharedLadder::default();
    ladder.attach_telemetry(Arc::clone(&m.telemetry));
    let w = Witness::of(&m);
    assert_eq!(m.snapshot().load_pressure_report_age_seconds, -1.0);
    ladder.set_host_pressure(crate::LoadPressure::Critical);
    w.rose("load_tier");
    w.rose("load_host_pressure");
    w.rose("load_tier_changes_total.load_tier:2:host:critical");
    assert!(m.snapshot().load_pressure_report_age_seconds >= 0.0);
}

#[test]
fn a_gauge_falls_too() {
    let m = EdgeMetrics::default();
    m.telemetry.set_seal_awaiting(5, 4096);
    let w = Witness::of(&m);
    m.telemetry.set_seal_awaiting(1, 0);
    w.fell("seal_awaiting_links");
    w.fell("seal_awaiting_bytes");
}

/// The server enforces exposure from this page's list, so it may not drift.
#[test]
fn the_operators_page_lists_every_field_as_the_catalogue_does() {
    let page = include_str!("../../docs/TELEMETRY_CATALOGUE.md");
    for s in TELEMETRY_CATALOGUE {
        let exposure = match s.exposure {
            Exposure::PublicSafe => "public-safe",
            Exposure::OperatorOnly => "operator-only",
        };
        let row = format!("| `{}` | `{}` |", s.field, s.name);
        let line = page
            .lines()
            .find(|l| l.starts_with(&row))
            .unwrap_or_else(|| panic!("{} is not on the page", s.field));
        assert!(line.ends_with(&format!("| {exposure} |")), "{line}");
    }
}
