"""ciris_edge — Reticulum-native federation transport for the CIRIS stack.

Mission alignment: see ``MISSION.md``. This Python package is a thin
wrapper over the Rust crate; the lens FastAPI cutover (Phase 1) and
the agent Python pipeline (Phase 2) call into ``Edge`` from Python
during their alongside-window cutovers.

Phase 1 surface (lens cutover):

>>> import ciris_edge
>>> import ciris_persist as cp
>>> engine = cp.Engine(dsn="postgres://lens:lens@localhost:5432/cirislens")
>>> # Edge construction lands as the Rust surface stabilizes.
>>> # See FSD/CIRIS_EDGE.md §3.2 for the call shape.

Trust model (OQ-11 closure): hybrid Ed25519 + ML-DSA-65 verify is the
day-1 v0.1.0 posture. Edge calls
``ciris_persist.Engine.verify_hybrid_via_directory`` on every inbound
message. Three consumer policies are configurable per peer:

- ``strict`` — reject any envelope whose sender's federation_keys
  row is hybrid-pending.
- ``soft_freshness`` — accept hybrid-pending rows within a freshness
  window; reject older ones.
- ``ed25519_fallback`` — accept Ed25519-only verification.

Delivery class (OQ-09 closure): two outbound channels, no
middle-ground. ``send()`` ships ephemeral messages with caller-owned
retry; ``send_durable()`` ships through ``cirislens.edge_outbound_queue``
with edge-owned persistent retry. Delivery class lives on the message
type, not the call site — caller can't pick wrong.
"""

from .ciris_edge import SUPPORTED_SCHEMA_VERSIONS, __version__

# Edge, DurableHandle, HybridPolicy, etc. register here as the Rust
# surface comes online in subsequent commits. Public re-export list
# below tracks what's actually available.

__all__ = ["SUPPORTED_SCHEMA_VERSIONS", "__version__"]
