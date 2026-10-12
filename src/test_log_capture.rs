//! Test-only log capture shared by every `src/` test that asserts on what was
//! logged (CIRISEdge#858, #763).
//!
//! A scoped (`set_default`) dispatcher alone is racy when tests run
//! concurrently: `tracing` caches each callsite's interest and the global max
//! level process-wide, and a sibling test registering the same `info!`
//! callsite with no subscriber can store "never" just after the capturing
//! test's dispatcher rebuilt the cache, leaving the line dead until the next
//! rebuild. It dropped a signer's park line in about a third of concurrent
//! runs and never in serial ones. [`Captured::info_subscriber`] first holds
//! INFO interest process-wide ([`hold_info_interest`]), so no callsite can
//! resolve to "never"; the scoped capture still receives its own thread's
//! events. The `test_log_capture_gate` pins every `set_default(` in `src/` to
//! this path, so the race is fixed as a class.

use std::sync::{Arc, Mutex};

/// A `tracing` writer into a shared buffer.
#[derive(Clone, Default)]
pub(crate) struct Captured(pub(crate) Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().expect("capture").extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

impl Captured {
    /// An INFO-and-above, colourless subscriber writing into this buffer, for
    /// `tracing::subscriber::set_default`. Holds INFO interest process-wide
    /// first.
    pub(crate) fn info_subscriber(&self) -> impl tracing::Subscriber + Send + Sync {
        hold_info_interest();
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_max_level(tracing::Level::INFO)
            .with_ansi(false)
            .finish()
    }

    /// Everything captured so far.
    pub(crate) fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("capture").clone()).expect("utf8")
    }
}

/// Install, once per process, a global subscriber that wants INFO and
/// discards it. If another test installed a global first (`init_logging`'s
/// test does), that one also wants `ciris_edge` INFO, which is all this needs,
/// and the failed install is ignored.
pub(crate) fn hold_info_interest() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .with_writer(std::io::sink)
                .with_max_level(tracing::Level::INFO)
                .finish(),
        );
    });
}

/// Every `set_default(` in `src/` builds its subscriber through
/// [`Captured::info_subscriber`]: a new scoped capture cannot reintroduce the
/// race.
#[cfg(test)]
mod test_log_capture_gate {
    #[test]
    fn every_scoped_capture_holds_info_interest() {
        fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
            for entry in std::fs::read_dir(dir).expect("read src dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("read source");
                    let lines: Vec<&str> = text.lines().collect();
                    let call = concat!("subscriber::set", "_default(");
                    for (n, line) in lines.iter().enumerate() {
                        let code = line.split("//").next().unwrap_or("");
                        if !code.contains(call) {
                            continue;
                        }
                        let window = lines[n..lines.len().min(n + 3)].join(" ");
                        if !window.contains("info_subscriber()") {
                            out.push(format!("{}:{}: {}", path.display(), n + 1, line.trim()));
                        }
                    }
                }
            }
        }
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut found = Vec::new();
        walk(&src, &mut found);
        assert!(
            found.is_empty(),
            "a scoped log capture that does not hold INFO interest process-wide \
             (use `crate::test_log_capture::Captured::info_subscriber()`):\n{}",
            found.join("\n")
        );
    }
}
