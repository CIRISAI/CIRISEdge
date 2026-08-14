#!/usr/bin/env python3
"""Cargo.toml <-> pyproject.toml version-skew guard (CIRISEdge#84).

Reads the Cargo.toml pinned tag for `ciris-persist` and the pyproject.toml
PEP 440 constraint for the matching Python wheel; fails CI with a clear
diff if the Cargo pin does not satisfy the pyproject constraint.

Background: the v1.7.0 -> v2.0.1 cascade shipped three wheels with
`Requires-Dist: ciris-persist<5,>=4.15.0` while the bundled cdylib linked
persist v5.x. `pip install ciris-edge ciris-persist==5.x` ->
ResolutionImpossible. Caught downstream by CIRISLensCore; fixed at v2.0.2.
This guard would have caught it pre-merge.

Exits 0 on satisfied; non-zero with a human-readable diff otherwise.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from packaging.specifiers import SpecifierSet
from packaging.version import Version


CARGO_TOML = Path("Cargo.toml")
PYPROJECT_TOML = Path("pyproject.toml")

# (Cargo crate name, pyproject Python package name) pairs to check.
# Only crates that ship as standalone Python wheels are checkable; the
# verify family (ciris-keyring / ciris-crypto) ride statically inside the
# cdylib and have no Python wheel to skew against.
PAIRS = [
    ("ciris-persist", "ciris-persist"),
]


def cargo_pinned_tag(crate: str, text: str) -> str:
    """Return the SemVer string Cargo.toml pins `crate` to (via `tag =`).

    Picks the FIRST matching line; tolerant of comments preceding the
    line. Edge pins persist twice (main deps + dev-deps) but on the same
    tag — taking the first is fine.
    """
    # Accept a release tag `vX.Y.Z` AND a pre-release/build tag `vX.Y.Z-rc.N`
    # (RC staging adopts, e.g. `v31.2.0-rc.1`) — the suffix is captured so the
    # PEP 440 comparison below sees the real pre-release version.
    pattern = rf'^\s*{re.escape(crate)}\s*=\s*\{{[^}}]*tag\s*=\s*"v(\d+\.\d+\.\d+(?:[-.+][0-9A-Za-z.+-]*)?)"'
    match = re.search(pattern, text, re.M)
    if not match:
        raise SystemExit(
            f"check_cargo_pyproject_skew: no `tag = \"vX.Y.Z\"` (or `vX.Y.Z-rc.N`) "
            f"entry for {crate} in Cargo.toml"
        )
    return match.group(1)


def pyproject_constraint(package: str, text: str) -> str:
    """Return the PEP 440 constraint pyproject.toml applies to `package`.

    Looks at `[project.dependencies]` entries of the form
    `"ciris-persist>=5.5.5,<6"`.
    """
    pattern = rf'"{re.escape(package)}\s*([^"]+)"'
    match = re.search(pattern, text)
    if not match:
        raise SystemExit(
            f"check_cargo_pyproject_skew: no dependency line for {package} in pyproject.toml"
        )
    return match.group(1).strip()


def main() -> int:
    cargo_text = CARGO_TOML.read_text()
    pyproject_text = PYPROJECT_TOML.read_text()

    failures: list[str] = []
    successes: list[str] = []

    for crate, package in PAIRS:
        cargo_version = cargo_pinned_tag(crate, cargo_text)
        constraint = pyproject_constraint(package, pyproject_text)
        spec = SpecifierSet(constraint)
        v = Version(cargo_version)
        # prereleases=True: this guard checks MAJOR/range consistency (would a pip
        # resolve skew like the v2.0.1 cascade), and an RC pin like 31.2.0rc1 is
        # consistent with `>=31,<32`. packaging excludes pre-releases from a
        # release-only spec by default, so ask explicitly.
        if spec.contains(v, prereleases=True):
            successes.append(
                f"  OK   {crate}: Cargo v{cargo_version} satisfies pyproject {constraint!r}"
            )
        else:
            failures.append(
                f"  FAIL {crate}: Cargo v{cargo_version} does NOT satisfy pyproject {constraint!r}"
            )

    if failures:
        print("Cargo.toml <-> pyproject.toml version skew detected:", file=sys.stderr)
        for line in failures:
            print(line, file=sys.stderr)
        if successes:
            print("\nOther pairs (ok):", file=sys.stderr)
            for line in successes:
                print(line, file=sys.stderr)
        print(
            "\nFix: bump pyproject.toml's `dependencies` constraint to include the "
            "Cargo-pinned version, or roll back the Cargo tag.",
            file=sys.stderr,
        )
        return 1

    print("Cargo.toml <-> pyproject.toml version pins consistent:")
    for line in successes:
        print(line)
    return 0


if __name__ == "__main__":
    sys.exit(main())
