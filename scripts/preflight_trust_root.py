#!/usr/bin/env python3
"""preflight_trust_root.py — the release pre-flight's registry trust-root check.

CIRISPersist#809, restored as a GATE in v50.0.0 (CIRISPersist#926 ruling (b)).

The registry's GET /v1/steward-key serves the portable trust root — the accord
GenesisBundle (CIRISRegistry v3.0.0+). Until v50.0.0 this check REPORTED the
bundle's quorum and gated nothing on it ("a check that cannot fail is a
report"): for the length of the trust-root transition it could not catch a
registry serving a bundle whose quorum had collapsed. The operator ruled the
transition over on #926, so the new-shape half now asserts what CIRISEdge#571
asserts:

  * NEW `bundle` shape -> GATED: `consensus_protocol` must parse as quorum:M/N
    (1 <= M <= N; an unparseable protocol is refused, never guessed), and the
    DISTINCT authorizing holders that are named in the bundle's own `holders`
    must reach M. Short -> exit 1.
  * OLD `stewards` shape -> gated on a deployed steward, unchanged.
  * UNRECOGNISED shape / unreadable body -> fails closed.

What it still does NOT do, said plainly: it counts authorizations, it does not
verify their signatures (this is an unauthenticated read in a CI step; the
cryptographic verification is persist's own `verify_bundle_quorum`, which every
consumer runs). `served_by.accepts_this_root` stays a warning. A
`ciris-canonical` community row served beside the bundle (#926) is reported,
not gated: the registry's route does not serve it yet, and a gate on it would
red every tag run on somebody else's deploy window.

Usage:
  preflight_trust_root.py <steward-key.json>   # the live check
  preflight_trust_root.py --self-test          # the fault-injection fixtures
"""

import json
import sys


class Refused(Exception):
    """The pre-flight refuses: the tag run must stop."""


def parse_quorum(protocol):
    """`quorum:M/N` -> (M, N); anything else -> None."""
    if not isinstance(protocol, str) or not protocol.startswith("quorum:"):
        return None
    m_s, sep, n_s = protocol[len("quorum:"):].partition("/")
    if not sep or not m_s.isdigit() or not n_s.isdigit():
        return None
    m, n = int(m_s), int(n_s)
    if not 1 <= m <= n:
        return None
    return m, n


def check(d):
    """Judge one /v1/steward-key body. Returns report lines; raises Refused."""
    if not isinstance(d, dict):
        raise Refused(f"registry /v1/steward-key is {type(d).__name__}, expected object")

    if isinstance(d.get("bundle"), dict):
        b = d["bundle"]
        holders = b.get("holders") or []
        auths = b.get("authorizations") or []
        proto = b.get("consensus_protocol")
        lines = [
            "registry trust root: accord GenesisBundle (CIRISRegistry v3.0.0 shape)",
            f"  charter_root_key_id={d.get('charter_root_key_id', '?')}",
            f"  bundle_version={b.get('version', '?')} family_key_id={b.get('family_key_id', '?')}",
            f"  consensus_protocol={proto}  holders={len(holders)}  authorizations={len(auths)}",
            f"  serve_nodes={len(b.get('serve_nodes') or [])}  attestations={len(b.get('attestations') or [])}",
        ]
        quorum = parse_quorum(proto)
        if quorum is None:
            raise Refused(
                f"bundle consensus_protocol {proto!r} is not quorum:M/N — "
                "a verifier must not guess the threshold (CIRISPersist#809)"
            )
        m, _n = quorum
        seated = set()
        for h in holders:
            rec = h.get("record", h) if isinstance(h, dict) else {}
            if isinstance(rec, dict) and rec.get("key_id"):
                seated.add(rec["key_id"])
        distinct = {
            a.get("holder_key_id")
            for a in auths
            if isinstance(a, dict) and a.get("holder_key_id") in seated
        }
        if len(distinct) < m:
            raise Refused(
                f"bundle quorum NOT met: {len(distinct)} distinct seated holder "
                f"authorization(s), {proto} requires {m} (CIRISPersist#809)"
            )
        lines.append(f"  quorum met: {len(distinct)} distinct seated holder(s) >= {m}")
        community = d.get("community")
        if isinstance(community, dict):
            cid = (community.get("community") or {}).get("community_key_id", "?")
            lines.append(
                f"  community beside the bundle: {cid} "
                f"(cosignatures={len(community.get('cosignatures') or [])}; reported, not gated)"
            )
        else:
            lines.append("  community beside the bundle: none served (reported, not gated)")
        served = d.get("served_by") or {}
        if not served.get("accepts_this_root", False):
            print(
                "::warning::registry node "
                f"{served.get('node_key_id', '?')} reports accepts_this_root=false "
                "(informational: the outer envelope is unsigned by design)",
                file=sys.stderr,
            )
        return lines

    if "stewards" in d:
        deployed = [s for s in (d.get("stewards") or []) if s.get("deployed")]
        if not deployed:
            raise Refused("registry has no deployed stewards")
        p = d.get("verification_policy", {})
        return [
            "registry trust root: M-of-N steward list (pre-v3.0.0 shape)",
            f"  steward key_id={deployed[0]['key_id']}",
            f"  verification policy={p.get('threshold', '?')}-of-{p.get('of_total', '?')} "
            f"{p.get('scheme', '')}",
        ]

    raise Refused(
        "registry /v1/steward-key matched no known shape "
        f"(top-level keys: {sorted(d)}). Expected either a v3.0.0 "
        "`bundle` or a pre-v3.0.0 `stewards` list."
    )


def _bundle(auth_ids, proto="quorum:2/3"):
    return {
        "bundle": {
            "version": 3,
            "family_key_id": "humanity-accord",
            "holders": [{"record": {"key_id": k}} for k in ("A1", "B1", "C1")],
            "serve_nodes": [{"record": {"key_id": "ciris-canonical-1"}}],
            "consensus_protocol": proto,
            "attestations": [],
            "authorizations": [{"holder_key_id": k} for k in auth_ids],
        },
        "charter_root_key_id": "humanity-accord",
        "served_by": {"node_key_id": "n", "accepts_this_root": True},
    }


# (name, body, must_pass). The `authorizations: []` row is the fixture #809
# said to re-run when the gate is restored: it must flip from exit 0 to exit 1.
FIXTURES = [
    ("bundle 2-of-3", _bundle(["A1", "B1"]), True),
    ("bundle 3-of-3", _bundle(["A1", "B1", "C1"]), True),
    ("bundle authorizations forced to []", _bundle([]), False),
    ("bundle 1-of-3", _bundle(["A1"]), False),
    ("bundle duplicate holder", _bundle(["A1", "A1"]), False),
    ("bundle non-holder authorization", _bundle(["A1", "Z9"]), False),
    ("bundle unparseable protocol", _bundle(["A1", "B1"], proto="majority"), False),
    ("bundle M > N", _bundle(["A1", "B1"], proto="quorum:4/3"), False),
    ("old shape, steward deployed", {"stewards": [{"key_id": "s", "deployed": True}]}, True),
    ("old shape, none deployed", {"stewards": [{"key_id": "s", "deployed": False}]}, False),
    ("unknown third shape", {"something": 1}, False),
    ("non-object body", [1, 2], False),
]


def self_test():
    failures = []
    for name, body, must_pass in FIXTURES:
        try:
            check(body)
            passed = True
        except Refused:
            passed = False
        if passed != must_pass:
            failures.append(f"{name}: expected {'pass' if must_pass else 'REFUSE'}")
    if failures:
        for f in failures:
            print(f"::error::preflight self-test: {f}", file=sys.stderr)
        return 1
    print(f"preflight self-test: {len(FIXTURES)} fixtures, every verdict as expected")
    return 0


def main(argv):
    if argv[1:] == ["--self-test"]:
        return self_test()
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    try:
        with open(argv[1]) as fh:
            d = json.load(fh)
    except Exception as exc:  # noqa: BLE001 — any unreadable body fails closed
        print(f"::error::registry /v1/steward-key unreadable or not JSON: {exc}", file=sys.stderr)
        return 1
    try:
        for line in check(d):
            print(line)
    except Refused as why:
        print(f"::error::{why}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
