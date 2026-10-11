//! CIRISEdge#820 (CIRISServer `FSD/UNIFIED_TELEMETRY.md` §3.2) — exactly ONE
//! `metrics` package in the dependency graph.
//!
//! Each 0.x minor of `metrics` owns its own global recorder. If edge's
//! `metrics` and leviculum's ever resolve to two semver-incompatible
//! versions, edge publishes into a recorder nobody installed and every edge
//! series is silent, with nothing failing. Cargo unifies semver-compatible
//! requirements into one package, so more than one `metrics` entry in the
//! lockfile is exactly that split. Read offline from `Cargo.lock`.

fn metrics_versions(lockfile: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut lines = lockfile.lines();
    while let Some(line) = lines.next() {
        if line.trim() == "name = \"metrics\"" {
            let version = lines
                .next()
                .and_then(|l| l.trim().strip_prefix("version = \""))
                .and_then(|v| v.strip_suffix('"'))
                .unwrap_or("?");
            out.push(version.to_owned());
        }
    }
    out
}

#[test]
fn exactly_one_metrics_package_is_linked() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let lockfile = std::fs::read_to_string(&path).expect("read Cargo.lock");
    let versions = metrics_versions(&lockfile);
    assert_eq!(
        versions.len(),
        1,
        "`metrics` resolves to {versions:?}: more than one facade means more than \
         one global recorder, and edge's series would publish into one nobody \
         installed. Align edge's `metrics` requirement with leviculum's."
    );
}

#[test]
fn the_parser_sees_a_second_version() {
    let two = "[[package]]\nname = \"metrics\"\nversion = \"0.23.0\"\n\n\
               [[package]]\nname = \"metrics\"\nversion = \"0.24.6\"\n\n\
               [[package]]\nname = \"metrics-util\"\nversion = \"0.19.1\"\n";
    assert_eq!(metrics_versions(two), ["0.23.0", "0.24.6"]);
}
