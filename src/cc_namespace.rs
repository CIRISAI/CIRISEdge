//! **The CC namespace grammar, vendored for replay** (CIRISEdge#706,
//! CIRISConstitution#112).
//!
//! CC publishes two generated files beside Part 3: `namespace_registry.json`
//! (every family row — prefix, segments, closed leaves) and
//! `namespace_match_vectors.json` (962 `(dimension, family, refusal)` triples,
//! exactly as the reference matcher `tools/cc_namespace_match.py` answers them).
//! The contract on the vectors file: *every consumer replays these against its
//! own matcher*. Both are vendored byte-for-byte under
//! `vendor/constitution/` from [`VENDORED_CC_COMMIT`]; nothing here restates a
//! CC value.
//!
//! **Edge's matcher is persist's.** Edge classifies a dimension only through
//! persist ([`ciris_persist::federation::namespace::attestation_family`], read
//! by [`crate::family_gates::gates_for`]); the full-match, refusal-bearing
//! matcher the vectors describe is persist v50's
//! `namespace::matcher::match_family` (CIRISPersist#924), which does not exist
//! at the pinned persist v49. The replay therefore lands `#[ignore]`d in
//! [`crate::field_conformance`] and is wired at the v33.0.0 adopt
//! (CIRISEdge#702); what runs today is the pin, the fixture checks and the
//! family-helper coverage, which need no matcher.
//!
//! Test-only: the files are ~325 KB and nothing in production reads them.

/// The CIRISConstitution commit both files are vendored from (CC `main` at
/// the rc5 PDF finalisation). Byte-identical to `c60d0a6` (the rc5 cut), which
/// is what persist v50 vendors — so the replay persist runs and the one edge
/// runs read the same bytes.
pub const VENDORED_CC_COMMIT: &str = "a4d29a64278f3ced3b8502dfb2502d3a41ce879b";

/// `_meta.registry_sha256` — the hash of the GRAMMAR (families + `_meta`
/// minus the prose hash), CSD/3's pin. A wording edit to Part 3 moves only
/// `source_sha256`; a grammar edit moves this.
pub const VENDORED_REGISTRY_SHA256: &str =
    "07e0c72538f3dd42451cac0c5f2529eed37bea3e8996640de2749aabb960b7fb";

/// The number of vectors the pinned file carries (released rc5).
pub const VENDORED_N_VECTORS: usize = 962;

/// `vendor/constitution/namespace_registry.json`, byte-for-byte.
pub const REGISTRY_JSON: &str = include_str!("../vendor/constitution/namespace_registry.json");

/// `vendor/constitution/namespace_match_vectors.json`, byte-for-byte.
pub const VECTORS_JSON: &str = include_str!("../vendor/constitution/namespace_match_vectors.json");

/// One published vector.
#[derive(Debug, Clone)]
pub struct Vector {
    /// The dimension the reference was asked about.
    pub dimension: String,
    /// The registry family prefix it resolves to (`None` = open vocabulary).
    pub family: Option<String>,
    /// The refusal token it earns (`None` = admitted).
    pub refusal: Option<String>,
}

/// Every vector, in file order.
///
/// # Panics
/// If the vendored file does not parse — a vendoring defect, loud by design.
#[must_use]
pub fn vectors() -> Vec<Vector> {
    let root: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("vendored vectors parse");
    root["vectors"]
        .as_array()
        .expect("`vectors` is an array")
        .iter()
        .map(|v| Vector {
            dimension: v["dimension"].as_str().expect("dimension").to_owned(),
            family: v["family"].as_str().map(str::to_owned),
            refusal: v["refusal"].as_str().map(str::to_owned),
        })
        .collect()
}

/// Every registry family prefix, in file order (`"accord:*"`,
/// `"consent:state:{stance}"`, …).
///
/// # Panics
/// If the vendored file does not parse.
#[must_use]
pub fn registry_prefixes() -> Vec<String> {
    let root: serde_json::Value =
        serde_json::from_str(REGISTRY_JSON).expect("vendored registry parses");
    root["families"]
        .as_array()
        .expect("`families` is an array")
        .iter()
        .map(|f| f["prefix"].as_str().expect("prefix").to_owned())
        .collect()
}

/// The family STEM of a prefix or dimension — its first segment with the
/// trailing `:` (`"consent:state:{stance}"` → `"consent:"`).
#[must_use]
pub fn stem(prefix: &str) -> &str {
    prefix.find(':').map_or(prefix, |i| &prefix[..=i])
}

/// Serialise `v` exactly as Python's `json.dumps(v, sort_keys=True,
/// separators=(",", ":"))` does with its default `ensure_ascii=True` — the
/// preimage `tools/build_cc_namespace.py` hashes into `registry_sha256`.
///
/// Keys are sorted explicitly (independent of serde_json's map order), every
/// non-ASCII code point is written `\uXXXX` (astral ones as a surrogate pair),
/// and the ASCII escapes match CPython's. The registry carries no floats; an
/// integer is written as its decimal digits.
pub fn python_canonical_json(v: &serde_json::Value, out: &mut String) {
    use std::fmt::Write as _;
    match v {
        serde_json::Value::Null => out.push_str("null"),
        serde_json::Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        serde_json::Value::Number(n) => {
            let _ = write!(out, "{n}");
        }
        serde_json::Value::String(s) => {
            out.push('"');
            for c in s.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    '\u{08}' => out.push_str("\\b"),
                    '\u{0c}' => out.push_str("\\f"),
                    c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                        let mut buf = [0u16; 2];
                        for unit in c.encode_utf16(&mut buf) {
                            let _ = write!(out, "\\u{unit:04x}");
                        }
                    }
                    c => out.push(c),
                }
            }
            out.push('"');
        }
        serde_json::Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                python_canonical_json(x, out);
            }
            out.push(']');
        }
        serde_json::Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                python_canonical_json(&serde_json::Value::String(k.clone()), out);
                out.push(':');
                python_canonical_json(&m[k], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// CIRISEdge#706 item 4 — the re-vendor's pin. Recomputes
    /// `_meta.registry_sha256` over the vendored grammar exactly as CC's
    /// generator does and requires it to equal the file's own claim, the
    /// vectors file's claim, and [`VENDORED_REGISTRY_SHA256`]. A hand edit to
    /// either file, or a re-vendor that moved the bytes without the pin, fails
    /// here; a CC wording edit (which moves only `source_sha256`) does not.
    #[test]
    fn vendored_grammar_hashes_to_its_pin() {
        use sha2::{Digest, Sha256};
        let root: serde_json::Value = serde_json::from_str(REGISTRY_JSON).unwrap();
        let meta = root["_meta"].as_object().expect("_meta object");
        let claimed = meta["registry_sha256"].as_str().expect("registry_sha256");
        let mut grammar_meta = meta.clone();
        grammar_meta.remove("source_sha256");
        grammar_meta.remove("registry_sha256");
        let grammar = serde_json::json!({
            "_meta": serde_json::Value::Object(grammar_meta),
            "families": root["families"].clone(),
        });
        let mut preimage = String::new();
        python_canonical_json(&grammar, &mut preimage);
        let recomputed = hex::encode(Sha256::digest(preimage.as_bytes()));
        assert_eq!(
            recomputed, claimed,
            "the vendored registry does not hash to its own _meta.registry_sha256 — \
             it was edited after CC generated it"
        );
        assert_eq!(
            claimed, VENDORED_REGISTRY_SHA256,
            "re-vendored without moving VENDORED_REGISTRY_SHA256 (bytes and pin move together)"
        );
        let vroot: serde_json::Value = serde_json::from_str(VECTORS_JSON).unwrap();
        assert_eq!(
            vroot["_meta"]["registry_sha256"], VENDORED_REGISTRY_SHA256,
            "the vectors were generated from a different grammar than the vendored registry"
        );
        assert_eq!(meta["cc_version"], "1.0-rc5");
        // The commit is a full 40-hex SHA — a re-vendor records exactly where the bytes came from.
        assert!(
            VENDORED_CC_COMMIT.len() == 40
                && VENDORED_CC_COMMIT.bytes().all(|b| b.is_ascii_hexdigit()),
            "VENDORED_CC_COMMIT must be a full commit SHA"
        );
        assert_eq!(
            root["families"].as_array().unwrap().len() as u64,
            meta["n_families"].as_u64().unwrap(),
            "_meta.n_families disagrees with the rows the file carries"
        );
    }

    #[test]
    fn the_vendored_vectors_are_the_released_set() {
        let vs = vectors();
        assert_eq!(vs.len(), VENDORED_N_VECTORS);
        // Every family a vector names is a row the vendored registry carries.
        let prefixes: std::collections::HashSet<String> = registry_prefixes().into_iter().collect();
        for v in &vs {
            if let Some(f) = &v.family {
                assert!(
                    prefixes.contains(f),
                    "vector {:?} names family {f:?}, which the registry does not carry",
                    v.dimension
                );
            }
        }
    }

    #[test]
    fn python_canonical_json_matches_cpython_on_the_tricky_cases() {
        let mut s = String::new();
        python_canonical_json(
            &serde_json::json!({"b": "—\u{1F600}\"\\\n", "a": [1, true, null]}),
            &mut s,
        );
        assert_eq!(
            s,
            "{\"a\":[1,true,null],\"b\":\"\\u2014\\ud83d\\ude00\\\"\\\\\\n\"}"
        );
    }
}
