#!/usr/bin/env python3
"""Generate `src/ffi/kept_directory.rs`: a `FederationDirectory` that holds the
capsules its inner directory proxy was built from, and delegates every trait
method to it.

WHY. Persist's `build_ops_directory` returns an `Arc<dyn FederationDirectory>`
over a bitwise copy of the `directory_ops_capsule`'s `{ data, vtable }` and of
the `executor_capsule`'s. Each capsule's destructor frees what its copy points
at, so the proxy is sound only while both capsules live. Persist's proxy type
has no field for them; this wrapper is that field. It lives exactly as long as
anything that can reach the proxy (edge hands out only the wrapper).

WHY EVERY METHOD. The inner proxy's own defaults compose through ITS `self`,
so delegating every method, required and defaulted alike, keeps behaviour
identical to the bare proxy. (Persist's fault double must not delegate
compositions; this wrapper injects nothing, so it can.)

The trait is parsed with persist's own generator
(`scripts/gen_directory_double.py`, its `trait_body` / `parse` /
`default_methods` / `split_args`), from the persist source edge is built
against. The output is committed; cargo never runs this.

Run:   python3 tools/gen_kept_directory.py --from-cargo-metadata
Check: python3 tools/gen_kept_directory.py --from-cargo-metadata --check
       (tests/kept_directory_current.rs runs this: a persist bump that adds a
       trait method, defaulted or required, fails the suite until the wrapper
       is regenerated. A stale wrapper would silently answer a new defaulted
       method with the trait default instead of the proxy's override.)
`--persist-src <checkout>` names the persist source directly instead.
"""
from __future__ import annotations

import argparse
import importlib.util
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "src" / "ffi" / "kept_directory.rs"


# CIRISEdge#988 — the trait's BLOCKING sync methods. Through persist's ops
# proxy each is a round trip on persist's runtime that blocks its caller (and
# answers a fail-closed fallback after 30 s), and persist's code compiled into
# edge calls them from async bodies, i.e. on runtime workers. Each is answered
# by a latch: a value read through the proxy is kept for the process, EXCEPT
# the proxy's fail-closed fallback (and, for the node key, None), which is
# never kept: the next use reads again, failing closed meanwhile.
#
# (name, value type, latch type, `is_kept(&value)` expression, latch→value)
#  - node_key_id: the value only moves None → Some(k), and k is the Engine's
#    own signer-derived key on every route persist sets it by (registration,
#    engine.rs:3221; the lazy fills :1458/:8351), so a kept Some never goes
#    stale; None (a first-run node before registration, which persist reads
#    as "no audience check", CIRISPersist#1269) and the timeout sentinel are
#    never kept.
#  - hardware_attestation_policy / withdraws_delegation_depth: set only on a
#    concrete backend before the host builds its Engine (no Engine or Python
#    setter), so stable for the process; the timeout fallbacks (the
#    refuse-all policy, depth 0) are never kept.
LATCHED_SYNC = [
    (
        "node_key_id",
        "Option<String>",
        "String",
        "v.as_deref().filter(|k| *k != ciris_persist::ffi::directory_capsule::NODE_KEY_ID_UNAVAILABLE).map(str::to_owned)",
        "Some(k.clone())",
    ),
    (
        "hardware_attestation_policy",
        "std::sync::Arc<HardwareAttestationPolicy>",
        "std::sync::Arc<HardwareAttestationPolicy>",
        "(*v != ciris_persist::ffi::directory_capsule::refuse_all_hardware_attestation_policy()).then(|| std::sync::Arc::clone(&v))",
        "std::sync::Arc::clone(k)",
    ),
    (
        "withdraws_delegation_depth",
        "usize",
        "usize",
        "(v != 0).then_some(v)",
        "*k",
    ),
]

# Sync methods the ops proxy answers without crossing the capsule (it returns
# itself, a reference, or the trait default): delegated live.
PURE_SYNC = {
    "as_dyn_directory",
    "blackhole_rules_surface",
    "edge_detection_surface",
    "peer_quota_observation",
    "trust_root_standing_cache",
}


def load_persist_generator(persist: Path):
    script = persist / "scripts" / "gen_directory_double.py"
    spec = importlib.util.spec_from_file_location("persist_gen", script)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def methods_of(gen, persist: Path):
    body = gen.trait_body((persist / "src" / "federation" / "mod.rs").read_text())
    required = gen.parse(body)
    if not required:
        sys.exit("parsed zero required methods: the trait shape changed")
    defaults = [(n, a, r) for n, a, r, _leaf in gen.default_methods(body)]
    seen, out = set(), []
    for m in sorted(required + defaults):
        if m[0] not in seen:
            seen.add(m[0])
            out.append(m)
    return out


def sync_methods(gen, persist: Path) -> set[str]:
    """Depth-0 trait methods declared `fn` without `async`: delegated without
    an `.await`."""
    import re

    body = gen.trait_body((persist / "src" / "federation" / "mod.rs").read_text())
    s = gen.sanitize(body)
    depth, at = 0, []
    for ch in s:
        at.append(depth)
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    out = set()
    for m in re.finditer(r"(\basync\s+)?\bfn\s+([a-z0-9_]+)\s*\(", s):
        if at[m.start()] == 0 and not m.group(1):
            out.add(m.group(2))
    return out


def test_anchor_methods(persist: Path) -> set[str]:
    """Trait methods persist compiles only under `cfg(any(test, feature =
    "test-anchor"))` (CIRISPersist#1001). A lib build without the feature has
    no such method, so the wrapper's override carries
    `cfg(feature = "test-anchor")`: edge's feature turns persist's on. Without
    it the Android and iOS PyO3 lanes, which build the lib alone, fail with
    E0407."""
    import re

    text = (persist / "src" / "federation" / "mod.rs").read_text()
    return set(
        re.findall(
            r'#\[cfg\(any\(test,\s*feature\s*=\s*"test-anchor"\)\)\]\s*'
            r"(?:async\s+)?fn\s+([a-z0-9_]+)\s*\(",
            text,
        )
    )


def render(gen, methods, sync: set[str], anchored: set[str] = frozenset()) -> str:
    L = []
    A = L.append
    A("//! CIRISEdge#960 — **a directory proxy that holds its capsules.**")
    A("//!")
    A("//! GENERATED by `tools/gen_kept_directory.py` from the persist trait edge is")
    A("//! built against. Do not edit by hand. See the generator for why every")
    A("//! method is delegated.")
    A("")
    A("#![allow(clippy::all, clippy::pedantic, unused_imports)]")
    A("")
    A("use std::sync::Arc;")
    A("")
    A("use ciris_persist::federation::*;")
    A("")
    A("/// `inner` (persist's directory-ops proxy) and the capsules its copies point")
    A("/// into. Dropping the last clone releases the capsules; nothing else holds")
    A("/// them on edge's behalf.")
    A("///")
    A("/// The trait's blocking SYNC reads are answered by latches (see the")
    A("/// generator's `LATCHED_SYNC`): a value read through the proxy is kept for")
    A("/// the process, except the proxy's fail-closed fallback (and an absent node")
    A("/// key), which is never kept, so the next use reads again. Each latch is")
    A("/// tried once in [`Self::new`] (init, the host's thread), so in the steady")
    A("/// state no runtime worker blocks on a sync read.")
    A("pub(crate) struct KeptDirectory {")
    A("    inner: Arc<dyn FederationDirectory>,")
    for name, _ty, latch, _k, _v in LATCHED_SYNC:
        A(f"    {name}: std::sync::OnceLock<{latch}>,")
    A("    _executor: Arc<crate::ffi::pyo3::KeptExecutor>,")
    A("    _capsule: pyo3::Py<pyo3::PyAny>,")
    A("}")
    A("")
    A("impl KeptDirectory {")
    A("    pub(crate) fn new(")
    A("        inner: Arc<dyn FederationDirectory>,")
    A("        executor: Arc<crate::ffi::pyo3::KeptExecutor>,")
    A("        capsule: pyo3::Py<pyo3::PyAny>,")
    A("    ) -> Self {")
    A("        let kept = Self {")
    A("            inner,")
    for name, *_ in LATCHED_SYNC:
        A(f"            {name}: std::sync::OnceLock::new(),")
    A("            _executor: executor,")
    A("            _capsule: capsule,")
    A("        };")
    for name, *_ in LATCHED_SYNC:
        A(f"        let _ = FederationDirectory::{name}(&kept);")
    A("        kept")
    A("    }")
    A("}")
    A("")
    A(f"// {len(methods)} delegations, generated.")
    A("#[async_trait::async_trait]")
    A("impl FederationDirectory for KeptDirectory {")
    for name, args_src, ret in methods:
        # The trait is written inside persist: its `crate::` / `super::` paths
        # name persist's own modules from out here.
        def outside(t: str) -> str:
            return t.replace("crate::", "ciris_persist::").replace(
                "super::", "ciris_persist::federation::"
            )

        args_src, ret = outside(args_src), outside(ret)
        args = gen.split_args(args_src)
        params = [a for a in args if a.strip() not in ("&self", "self", "&mut self")]
        # A `mut` binding in the trait's default body is unused here.
        params = [p[4:] if p.startswith("mut ") else p for p in params]
        names = []
        for p in params:
            nm = p.split(":")[0].strip()
            if nm.startswith("mut "):
                nm = nm[4:].strip()
            names.append(nm)
        arglist = ", ".join(["&self"] + params)
        call = ", ".join(names)
        if name == "as_dyn_directory":
            A("    fn as_dyn_directory(&self) -> &dyn FederationDirectory {")
            A("        self")
            A("    }")
            continue
        if name in anchored:
            A("    // persist compiles this method only under `test` or `test-anchor`.")
            A('    #[cfg(feature = "test-anchor")]')
        latched = {l[0]: l for l in LATCHED_SYNC}
        if name in latched:
            _n, _ty, _latch, kept_expr, value_of = latched[name]
            A(f"    fn {name}({arglist}) -> {ret} {{")
            A("        // Kept once read; the proxy's fail-closed fallback is never kept, so")
            A("        // a slow first round trip does not stick for the process.")
            if name == "node_key_id":
                A("        // The value only moves None -> Some(k), and k is the Engine's own")
                A("        // signer-derived key on every route persist sets it by, so a kept")
                A("        // Some never goes stale; None is never kept (CIRISPersist#1269).")
            A(f"        if let Some(k) = self.{name}.get() {{")
            A(f"            return {value_of};")
            A("        }")
            A(f"        let v = self.inner.{name}({call});")
            A(f"        match {kept_expr} {{")
            A(f"            Some(keep) => {{ let k = self.{name}.get_or_init(|| keep); {value_of} }}")
            A("            None => v,")
            A("        }")
            A("    }")
            continue
        if name in sync:
            A(f"    fn {name}({arglist}) -> {ret} {{")
            A(f"        self.inner.{name}({call})")
            A("    }")
            continue
        A(f"    async fn {name}({arglist}) -> {ret} {{")
        A(f"        self.inner.{name}({call}).await")
        A("    }")
    A("}")
    return "\n".join(L) + "\n"


def rustfmt(text: str) -> str:
    try:
        r = subprocess.run(["rustfmt", "--edition", "2021", "--emit", "stdout"],
                           input=text, capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError):
        return text
    out = r.stdout
    i = out.find("//! ")
    return out[i:] if i > 0 else out


def pinned_persist_src() -> Path:
    """The ciris-persist source cargo resolved for this workspace's lock."""
    import json

    # Offline first: the answer is in the lockfile and the local checkout, and
    # a developer box may have no network. A CI runner that fetched only its
    # own target's crates cannot resolve the full graph offline (cargo
    # metadata exits 101 there), so the second try may use the network.
    base = ["cargo", "metadata", "--format-version", "1", "--locked"]
    run = None
    for extra in (["--offline"], []):
        run = subprocess.run(base + extra, cwd=ROOT, capture_output=True, text=True)
        if run.returncode == 0:
            break
    if run.returncode != 0:
        sys.exit(f"cargo metadata failed ({run.returncode}):\n{run.stderr[-2000:]}")
    out = run.stdout
    pkgs = [p for p in json.loads(out)["packages"] if p["name"] == "ciris-persist"]
    if len(pkgs) != 1:
        sys.exit(f"expected one ciris-persist package in the graph, found {len(pkgs)}")
    return Path(pkgs[0]["manifest_path"]).parent


def impl_blocks(trait: str):
    """Every `impl ... <trait> for <Type>` block in src/ and tests/, as
    (path, type, set of method names defined at the block's top level)."""
    import re

    out = []
    for path in sorted(list((ROOT / "src").rglob("*.rs")) + list((ROOT / "tests").rglob("*.rs"))):
        text = path.read_text()
        for m in re.finditer(
            r"impl(?:<[^>]*>)?\s+(?:[A-Za-z_:]+::)?" + trait + r"\s+for\s+([A-Za-z_0-9]+)\s*\{",
            text,
        ):
            i, depth = m.end(), 1
            body_start = i
            while depth and i < len(text):
                c = text[i]
                depth += (c == "{") - (c == "}")
                i += 1
            body = text[body_start : i - 1]
            # Methods at the block's own depth only.
            d, names, j = 0, set(), 0
            for fm in re.finditer(r"[{}]|\b(?:async\s+)?fn\s+([a-z0-9_]+)\s*[<(]", body):
                tok = fm.group(0)
                if tok == "{":
                    d += 1
                elif tok == "}":
                    d -= 1
                elif d == 0:
                    names.add(fm.group(1))
            out.append((path.relative_to(ROOT), m.group(1), names))
    return out


def check_doubles(methods) -> int:
    """CIRISEdge#988 — every implementor of persist's `FederationDirectory` in
    this tree defines EVERY trait method, so no caller can reach a trait
    default body through it: a default answers `Unsupported` (or a
    plausible empty) where the store would answer, and a witness over the
    double then tests the default. Fails naming each double and the methods
    it lacks."""
    want = {name for name, _args, _ret in methods}
    bad = 0
    blocks = impl_blocks("FederationDirectory")
    for path, ty, names in blocks:
        missing = sorted(want - names)
        extra = sorted(names - want)
        if missing:
            bad += 1
            print(f"MISSING: {path} impl FederationDirectory for {ty} lacks {len(missing)}: {', '.join(missing)}")
        if extra:
            bad += 1
            print(f"EXTRA: {path} impl FederationDirectory for {ty} defines non-trait methods: {', '.join(extra)}")
        if not missing and not extra:
            print(f"OK {path} {ty}: {len(names)}/{len(want)}")
    if not blocks:
        print("no FederationDirectory implementor found: the scan is broken")
        return 1
    return bad


def main() -> None:
    ap = argparse.ArgumentParser()
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--persist-src", type=Path)
    src.add_argument("--from-cargo-metadata", action="store_true")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--check-doubles", action="store_true")
    a = ap.parse_args()
    if a.from_cargo_metadata:
        a.persist_src = pinned_persist_src()
    gen = load_persist_generator(a.persist_src)
    methods = methods_of(gen, a.persist_src)
    if a.check_doubles:
        sys.exit(1 if check_doubles(methods) else 0)
    sync = sync_methods(gen, a.persist_src)
    known = {l[0] for l in LATCHED_SYNC} | PURE_SYNC
    if sync != known:
        # A new sync method would be delegated live: a blocking round trip on
        # whatever thread calls it. Decide how it is answered, then list it.
        sys.exit(f"the trait's sync methods changed: {sorted(sync)} != LATCHED_SYNC + PURE_SYNC {sorted(known)}")
    text = rustfmt(
        render(
            gen,
            methods,
            sync,
            test_anchor_methods(a.persist_src),
        )
    )
    if a.check:
        if (OUT.read_text() if OUT.exists() else "") != text:
            sys.exit(f"STALE: {OUT.relative_to(ROOT)} ({len(methods)} methods); regenerate")
        print(f"OK kept directory is current ({len(methods)} delegations)")
        return
    OUT.write_text(text)
    print(f"wrote {OUT.relative_to(ROOT)} ({len(methods)} delegations)")


if __name__ == "__main__":
    main()
