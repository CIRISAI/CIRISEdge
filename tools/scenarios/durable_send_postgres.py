"""Scenario: single send_durable_inline_text against postgres.

Reproduces CIRISEdge#58 / CIRISPersist#139 — intermittent hang in the
postgres durable-send path with sub-25% rate. Designed to be driven
by tools/race_repro.py.

Expects: postgres reachable at $CIRIS_REPRO_DSN
(default postgres://postgres:postgres@localhost:5433/conformance).
"""
import json
import os
import secrets
import sys
import tempfile

DB = os.environ.get(
    "CIRIS_REPRO_DSN",
    "postgres://postgres:postgres@localhost:5433/conformance",
)


def stamp(phase: str) -> None:
    """Emit a phase marker so the harness can localize a hang to a step."""
    import time
    print(f"PHASE {time.perf_counter() * 1000:.1f}ms {phase}", file=sys.stderr, flush=True)


def main() -> None:
    stamp("python_start")
    import ciris_persist as cp
    stamp("import_persist")
    from ciris_edge.ciris_edge import init_edge_runtime
    stamp("import_edge")

    d = tempfile.mkdtemp()
    seed_path = os.path.join(d, "s")
    open(seed_path, "wb").write(secrets.token_bytes(32))
    idp = os.path.join(d, "t.id")
    open(idp, "wb").write(b"\x00" * 64)

    cp.reset_engine()
    key_id = "d-" + secrets.token_hex(8)

    stamp("pre_engine")
    engine = cp.Engine(DB, key_id, local_key_id=key_id, local_key_path=seed_path)
    stamp("post_engine")

    kid = engine.register_federation_key("agent", "ref", None, None, None)
    stamp("post_register_key")

    edge = init_edge_runtime(engine, idp, listen_addr="127.0.0.1:0")
    stamp("post_init_edge_runtime")

    handle = edge.send_durable_inline_text(kid, "race-probe")
    stamp("post_send_durable")

    payload = {
        "durable_returned": type(handle).__name__,
    }
    # Capture the wheel's panic count if the build exposes it (v1.1.7+).
    import ciris_edge
    if hasattr(ciris_edge, "panic_count"):
        payload["panic_count"] = ciris_edge.panic_count()

    print(json.dumps(payload))
    sys.stdout.flush()
    os._exit(0)


if __name__ == "__main__":
    main()
