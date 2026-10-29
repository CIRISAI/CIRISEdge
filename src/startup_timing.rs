//! How long each startup phase took, as one INFO line.
//!
//! A report that a node starts slower names no phase unless the node logs
//! one: an agent's log showed only "Initialize Edge Runtime" and the next
//! line ~1.5–1.9 s later, with nothing in between. [`StartupPhases`] marks
//! each phase boundary and logs every phase's duration and the total once,
//! so the next such report reads the phase off the operator's own log.

use std::time::{Duration, Instant};

/// Phase boundaries of one startup, in order.
#[derive(Debug)]
pub struct StartupPhases {
    what: &'static str,
    started: Instant,
    last: Instant,
    phases: Vec<(&'static str, Duration)>,
}

impl StartupPhases {
    /// Start timing `what` (the startup being measured) now.
    #[must_use]
    pub fn start(what: &'static str) -> Self {
        let now = Instant::now();
        Self {
            what,
            started: now,
            last: now,
            phases: Vec::new(),
        }
    }

    /// The phase named `phase` ended now.
    pub fn mark(&mut self, phase: &'static str) {
        let now = Instant::now();
        self.phases.push((phase, now - self.last));
        self.last = now;
    }

    /// Each phase in milliseconds, in order, and the total.
    #[must_use]
    pub fn summary(&self) -> String {
        let mut out = String::new();
        for (name, d) in &self.phases {
            out.push_str(&format!("{name}={:.1}ms ", ms(*d)));
        }
        out.push_str(&format!("total={:.1}ms", ms(self.last - self.started)));
        out
    }

    /// Log [`Self::summary`] at INFO.
    pub fn log(&self) {
        tracing::info!(
            startup = self.what,
            phases = %self.summary(),
            total_ms = ms(self.last - self.started),
            "startup phases"
        );
    }
}

fn ms(d: Duration) -> f64 {
    d.as_secs_f64() * 1000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phases_are_named_in_order_and_sum_to_the_total() {
        let mut p = StartupPhases::start("test");
        std::thread::sleep(Duration::from_millis(5));
        p.mark("first");
        std::thread::sleep(Duration::from_millis(5));
        p.mark("second");
        let s = p.summary();
        let first = s.find("first=").expect("first named");
        let second = s.find("second=").expect("second named");
        assert!(first < second, "in order: {s}");
        assert!(s.ends_with("ms") && s.contains("total="), "{s}");
        let sum: Duration = p.phases.iter().map(|(_, d)| *d).sum();
        assert_eq!(
            sum,
            p.last - p.started,
            "the phases cover the whole startup"
        );
    }
}
