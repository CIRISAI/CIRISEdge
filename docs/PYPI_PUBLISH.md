# Distribution runbook — CIRISEdge is git-tag-only (PyPI publishing REMOVED)

> **Status: PyPI publishing was removed in v16.0.1 (CIRISEdge#471).**
> There is no `publish-pypi` job, no OIDC trusted-publisher setup, and
> `pip install ciris-edge` is **not** a supported path. This file used to be
> the PyPI operator runbook; it now documents the actual distribution model so
> anyone who lands here (e.g. from `docs/RELEASE_NOTES.md`) gets the truth.
>
> **45.x LTS: edge no longer ships Python at all.** It ships as a Rust crate
> plus UniFFI bindings. v45.1.9 is the last release with Python wheels.

## Why no PyPI

- **`ciris-edge` exceeds the PyPI project-size quota** — the publish always
  failed `400 Project size too large`, so PyPI was never a working channel.
- **The substrate siblings aren't on PyPI either** — `ciris-persist` stopped
  publishing at v30.4.0, and `ciris-verify` is git-tag-only. A PyPI
  `Requires-Dist` on them would resolve to "No matching distribution".
- So **no one consumes edge (or its wheels) off PyPI.** Keeping a permanently
  red `publish-pypi` job on every release tag only hid real failures.

## How CIRISEdge is actually consumed

**Edge ships as a Rust crate plus UniFFI bindings. It no longer ships
Python: v45.1.9 is the last release with Python assets.**

| Consumer | Mechanism |
|----------|-----------|
| Rust crates (CIRISServer, …) | pin the **Cargo git tag**: `ciris-edge = { git = "…/CIRISEdge", tag = "v45.1.9" }` |
| Python (CIRISAgent) | rides the **`ciris-server` one-wheel** (#896), which compiles edge's `pyo3` binding in and resolves ONE process-wide `ciris-persist` by construction |
| Mobile / native | the **GitHub Release** assets: Android per-ABI `.so`, `CIRISEdge.xcframework`, UniFFI Kotlin + Swift bindings |

The Python assets that v45.1.9 and earlier attached, and that later releases
do not: the four desktop abi3 wheels (linux x86_64 + aarch64, darwin arm64,
windows x64), `ciris-edge-v<ver>-android-wheels.tar.gz` (Chaquopy), and
`ciris-edge-v<ver>-ios.tar.gz` (BeeWare PyO3 `.abi3.so`).

The `pyo3` feature, `src/ffi/pyo3.rs`, `pyproject.toml` and `python/` stay in
the tree until the v62 line. CIRISServer compiles the binding into its wheel,
and CIRISConformance's nightly matrix source-builds edge from its git pin
through `pyproject.toml`. CI keeps all of it alive: `linux-x86_64 (pyo3-lib)`
runs the binding's unit tests, `lint` clippies it and checks the
`pyo3-sqlite` subset, and `desktop-release-build` compiles it in release on
all four desktop platforms. `pyproject.toml`'s `ciris-persist` range is a
**source-build major-tracker + co-resident version-agreement declaration**,
not an install-time index requirement; it cannot be resolved from PyPI by
design.

## What ships on a release tag

Pushing a `v*` tag runs `ci.yml`. When the edge-side jobs are green,
`mobile-release` creates the GitHub Release (it is the **only** publisher) and
attaches **10 assets**:

- `ciris-edge-v<ver>-android.tar.gz`: `libciris_edge.so` for arm64-v8a, x86_64, armeabi-v7a;
- `ciris-edge-v<ver>-xcframework.tar.gz`: `CIRISEdge.xcframework` (device + simulator);
- `ciris-edge-v<ver>-kotlin-bindings.tar.gz` and `ciris-edge-v<ver>-swift-bindings.tar.gz`;
- **one hybrid-signed manifest per shipped native binary**
  (`ciris-edge-<ver>-<label>.manifest.json`, five of them: `android-arm64-v8a`,
  `android-x86_64`, `android-armeabi-v7a`, `ios-aarch64`, `ios-aarch64-sim`).
  `build-manifest` produces them with `ciris-build-sign` (Ed25519 + ML-DSA-65).
  The android-arm64-v8a manifest is the canonical one and carries
  `EdgeExtras`. All five target hashes are registered with CIRISRegistry and
  round-trip verified;
- `SHA256SUMS` over all of the above.

Through v45.1.9 the four manifests signed the desktop wheels and the release
had 15 assets.

`mobile-release` gates on `desktop-release-build`, `build-manifest`,
`linux-x86_64-test`, `darwin-aarch64-test`, `lint` and `license-audit`. A
release whose tests failed, whose manifests are missing, or whose pyo3 binding
no longer builds on one of CIRISServer's desktop platforms is never published.

## Verifying a downloaded binary

1. Download the tarball and the `ciris-edge-<version>-<label>.manifest.json`
   for the target from the Release (or check its line in `SHA256SUMS`).
2. Verify the manifest signature with `ciris-build-verify` (from the CIRISVerify
   build-tool tarball) against the edge build steward key `ciris-edge-build-v1`.
3. Confirm the manifest's `binary_hash` matches the `sha256` of the target's
   `libciris_edge.so` (in `android.tar.gz`) or `libciris_edge.dylib` (inside
   the xcframework slice).

## Known-benign red on release tags

Both tag-only jobs that used to be expected red are gone: the PyPI publish
(removed in v16.0.1) and cohabitation conformance (removed with the wheels in
the 45.x LTS; that job belongs on CIRISServer's wheel now). Verify a release by
**edge-side jobs green + the asset count (10)**, not an all-green board.
