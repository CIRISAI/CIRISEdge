# Distribution runbook — CIRISEdge is git-tag-only (PyPI publishing REMOVED)

> **Status: PyPI publishing was removed in v16.0.1 (CIRISEdge#471).**
> There is no `publish-pypi` job, no OIDC trusted-publisher setup, and
> `pip install ciris-edge` is **not** a supported path. This file used to be
> the PyPI operator runbook; it now documents the actual distribution model so
> anyone who lands here (e.g. from `docs/RELEASE_NOTES.md`) gets the truth.

## Why no PyPI

- **`ciris-edge` exceeds the PyPI project-size quota** — the publish always
  failed `400 Project size too large`, so PyPI was never a working channel.
- **The substrate siblings aren't on PyPI either** — `ciris-persist` stopped
  publishing at v30.4.0, and `ciris-verify` is git-tag-only. A PyPI
  `Requires-Dist` on them would resolve to "No matching distribution".
- So **no one consumes edge (or its wheels) off PyPI.** Keeping a permanently
  red `publish-pypi` job on every release tag only hid real failures.

## How CIRISEdge is actually consumed

| Consumer | Mechanism |
|----------|-----------|
| Rust crates (CIRISServer, …) | pin the **Cargo git tag**: `ciris-edge = { git = "…/CIRISEdge", tag = "v16.0.1" }` |
| Python (CIRISAgent) | rides the **`ciris-server` one-wheel** (#896), which bundles edge + resolves ONE process-wide `ciris-persist` by construction |
| Mobile / native | the **GitHub Release** tarballs (android, ios, xcframework, kotlin/swift bindings) |
| Desktop Python wheels | the **GitHub Release** — the four abi3 wheels (linux x86_64 + aarch64, darwin arm64, windows x64), each beside its hybrid-signed manifest |

`pyproject.toml`'s `ciris-persist>=31,<32` is a **source-build major-tracker +
co-resident version-agreement declaration**, not an install-time index
requirement — it is unresolvable from PyPI by design.

## What ships on a release tag

Pushing a `v*` tag runs `ci.yml`. On green edge-side, `mobile-release` creates
the GitHub Release (it is the **sole** publisher) and attaches:

- the mobile/native tarballs + `SHA256SUMS`;
- the **four desktop abi3 wheels**;
- **one hybrid-signed manifest per desktop platform** (`ciris-edge-<version>-<label>.manifest.json`),
  produced by `build-manifest` via `ciris-build-sign` (Ed25519 + ML-DSA-65). The
  linux-x86_64 manifest is additionally registered with CIRISRegistry as the
  canonical; all four ride the Release so **every platform's binary is verifiable
  against a signed manifest**.

`mobile-release` gates on the desktop quality jobs (`pyo3-wheel`,
`build-manifest`, `linux-x86_64-test`, `darwin-aarch64-test`) so a wheel whose
platform tests or manifest build failed is never distributed.

## Verifying a downloaded wheel

1. Download the wheel + its `ciris-edge-<version>-<label>.manifest.json` from the
   Release (or check its line in `SHA256SUMS`).
2. Verify the manifest signature with `ciris-build-verify` (from the CIRISVerify
   build-tool tarball) against the edge build steward key `ciris-edge-build-v1`.
3. Confirm the manifest's `binary_hash` matches `sha256` of the wheel.

## Known-benign red on release tags

Two tag-only jobs are expected to be red and do **not** gate the release:
the historical PyPI publish (now removed) and — until every substrate sibling
re-pins — cohabitation conformance. Verify a release by **edge-side jobs green +
the GitHub Release artifacts**, not an all-green board.
