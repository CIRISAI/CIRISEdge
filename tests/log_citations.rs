//! CIRISEdge#875 — every issue citation in an operator-visible log line says
//! whether it is history (a closed issue: why the gate exists) or tracked (open
//! work). Operators read a bare "(CIRISEdge#425)" on a working gate as a live
//! bug. The scan is `tools/log_citations.py check` (WARN, ERROR and the
//! `drop_inbound` choke point); the state of each issue is applied by its
//! `rewrite` mode from `gh`, so this test needs no network.

#[test]
fn every_operator_visible_issue_citation_says_history_or_tracked_875() {
    let root = env!("CARGO_MANIFEST_DIR");
    let out = std::process::Command::new("python3")
        .args(["-I", "tools/log_citations.py", "check"])
        .current_dir(root)
        .output()
        .expect("python3 runs");
    assert!(
        out.status.success(),
        "bare issue citations in WARN/ERROR/drop_inbound strings — write `history: \
         CIRISEdge#N` (closed) or `tracked: CIRISEdge#N` (open); \
         `python3 -I tools/log_citations.py rewrite <states.tsv>` applies them:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}
