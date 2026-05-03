# PyPI publishing — operator runbook

CIRISEdge publishes `ciris-edge` wheels to PyPI on every tag push via
OIDC trusted publishing (no long-lived API token in CI). Mirrors
the pattern CIRISPersist + CIRISVerify use.

This doc covers the **one-time setup** needed on the PyPI side before
the first tag push triggers a successful publish.

---

## TL;DR — checklist

1. Reserve the project name on PyPI.
2. Configure trusted publisher pointing at this repo + the `ci.yml`
   workflow + the `pypi` environment.
3. Push a v-prefixed tag. Wheels publish; `pip install ciris-edge`
   works.

Total time: ~5 minutes if you have a PyPI account already.

---

## Why OIDC trusted publishing (no API token)

Older PyPI publish flows used long-lived API tokens uploaded as GitHub
repo secrets. Tokens leak; rotation is manual; revocation is reactive.

PyPI's trusted publishing (PEP 740 / OIDC) replaces that:

- GitHub Actions issues a short-lived JWT identifying the workflow run.
- PyPI verifies the JWT against a pre-configured trust policy
  ("only allow uploads from `CIRISAI/CIRISEdge`'s `ci.yml` workflow
  running in the `pypi` environment").
- No persistent credential stored anywhere.

Recommended pattern across the OSS ecosystem (sigstore cosign, npm
provenance, etc.). What the
[PyPI docs themselves recommend](https://docs.pypi.org/trusted-publishers/).

---

## Setup steps

### 1. Reserve `ciris-edge` on PyPI

If you've never published to PyPI before, you'll need an account
first. Once logged in:

- Go to <https://pypi.org/manage/account/publishing/>
- Click "Add a new pending publisher" (this works *before* the project
  exists — you reserve the name + configure trust in one step)
- Fill in:
  - **PyPI Project Name**: `ciris-edge`
  - **Owner**: `CIRISAI`
  - **Repository name**: `CIRISEdge`
  - **Workflow name**: `ci.yml`
  - **Environment name**: `pypi`

The "Pending Publisher" form publishes the trust policy *before* the
first upload. After the first successful upload, PyPI promotes it to
an active "trusted publisher" on the now-created project.

### 2. (Optional) Tag-pattern restrictions

If you want to restrict who can trigger publishes (e.g., only release
tags from `main`, not arbitrary tags from any branch), add a tag-
pattern filter in the publisher config. Skip for v0.1.0; can add later.

### 3. Confirm the GitHub environment exists

GitHub Actions environments are created on demand — the first
workflow run referencing `environment: pypi` creates it. Or
preemptively:

- <https://github.com/CIRISAI/CIRISEdge/settings/environments>
- "New environment" → name `pypi`
- (Optional) Add deployment protection rules. **Recommended:
  "Required reviewers"** with the repo maintainer(s) — adds a manual
  approval step before each PyPI publish.

### 4. Push the tag

After steps 1-3, the next `git tag v0.1.0 && git push origin v0.1.0`
triggers `.github/workflows/ci.yml::publish-pypi`. The job:

1. Waits for `pyo3-wheel` (matrix of 3 entries) + `lint` +
   `license-audit` + `linux-x86_64-test` + `darwin-aarch64-test` to
   succeed.
2. Downloads all three wheel artifacts (linux x86_64 + aarch64, darwin
   arm64) via the `ciris_edge-wheel-*` glob.
3. Sanity-checks count + shape (rejects anything that isn't exactly
   3 cp311-abi3 wheels — prevents v0.1.10-class regressions reaching
   consumers).
4. Calls `pypa/gh-action-pypi-publish@release/v1` with
   `attestations: true`. One sigstore attestation bundle covers all
   three wheels.
5. PyPI accepts the upload via OIDC trusted publishing.
6. `pip install ciris-edge==0.1.0` works within ~30 seconds of the
   workflow finishing on every supported `(os, arch)`.

### Wheel matrix

| Target triple                | Wheel tag                  | Runner             | Phase |
|------------------------------|----------------------------|--------------------|-------|
| `x86_64-unknown-linux-gnu`   | `manylinux_2_34_x86_64`    | `ubuntu-latest`    | 1     |
| `aarch64-unknown-linux-gnu`  | `manylinux_2_34_aarch64`   | `ubuntu-24.04-arm` | 1     |
| `aarch64-apple-darwin`       | `macosx_11_0_arm64`        | `macos-14`         | 1     |

`darwin-x86_64` (macos-13) intentionally omitted: GitHub Actions Intel
macOS runners queue indefinitely due to capacity issues. CIRISPersist's
matrix dropped it for the same reason; CIRISAgent's `build.yml`
explicitly notes "macOS Intel: built and uploaded manually". Add back
via manual upload if a real consumer asks.

iOS / Android out of scope here — they ship via swift-bridge / uniffi
native packaging at Phase 3, not PyPI.

---

## How this compounds with the BuildManifest signature

Once the `build-manifest` CI job lands (OQ-12 closure; pending
`scripts/emit_edge_extras.py`), the edge build pipeline has **three
layers** of provenance:

| Layer | What it proves | Where it lives |
|---|---|---|
| Source-of-truth git tag | "This commit is what CIRISAI's repo says" | GitHub repo |
| BuildManifest hybrid signature (Ed25519 + ML-DSA-65) | "This binary was built from that commit by CIRISAI's signing key" | CIRISRegistry, fetchable via `GET /v1/verify/binary-manifest/<version>?project=ciris-edge` |
| PEP 740 attestation | "This PyPI artifact was uploaded by CIRISAI's GHA workflow running on that commit" | PyPI, fetchable via `pip install --attestations ...` |

A consumer pinning `pip install ciris-edge==0.1.0` gets:

- Fast install from PyPI's CDN.
- `ciris-persist >= 0.4.0` and `ciris-verify >= 1.8.6` pulled
  transitively (matches the install graph the lens / agent / registry
  already use).
- Optional attestation-verify (defense-in-depth on the PyPI
  distribution channel).
- Cross-check via CIRISRegistry — the wheel's sha256 in PyPI must
  match `binaries["x86_64-unknown-linux-gnu"]` in the registered
  BuildManifest (once `build-manifest` lands).

The cryptographic root remains the BuildManifest. PyPI is the fast
delivery channel; verifiable but not load-bearing on its own.

---

## Failure modes

- **First tag push after setup, publish fails with "trusted publisher
  not found".** PyPI's pending-publisher took longer than expected to
  propagate, or the workflow filename doesn't match. Check the values
  entered in step 1 against `.github/workflows/ci.yml`. Re-run the
  failed job once trust propagates.

- **`skip-existing: true` swallowing a real failure.** If the wheel
  for the tagged version *already exists* on PyPI, the action skips
  silently. That's intentional for re-runs. To actually re-publish,
  bump to a fresh version.

- **Non-cp311-abi3 wheel.** Sanity check rejects it before publish.
  This is the v0.1.10-class regression — silently shipping a wrong
  shape would be worse than failing.

- **Registry round-trip 404 on first attempt** (when `build-manifest`
  lands). `api.registry.ciris-services-1.ai` has a read-after-write
  window between registration POST and the immediately-following GET.
  Persist v0.4.0's tag CI hit this and the second attempt was clean.
  Mitigation in `build-manifest` job: sleep + retry on the round-trip
  step (3-5 second initial sleep, exponential backoff to ~30s). See
  `~/.claude/projects/-home-emoore-CIRISEdge/memory/reference_registry_race.md`
  for context.

---

## Rotation

Trusted publisher config doesn't rotate — there's no key material to
expire. To revoke (e.g., if the workflow is compromised):

- PyPI project settings → "Trusted publishers" → remove the entry.
- Re-add with the corrected config.

PyPI keeps an audit log of publisher-config changes per project.
