"""ciris_edge — Reticulum-native federation transport for the CIRIS stack.

Mission alignment: see ``MISSION.md``. This Python package is a thin
wrapper over the Rust crate; the lens FastAPI cutover (Phase 1) and
the agent Python pipeline (Phase 2) call into ``Edge`` from Python
during their alongside-window cutovers.

Phase 1 surface (lens cutover) — v2.2.0:

>>> import ciris_edge
>>> import ciris_persist as cp
>>> engine = cp.Engine(dsn="postgres://lens:lens@localhost:5432/cirislens")
>>> edge = ciris_edge.init_edge_runtime(
...     engine=engine,
...     identity_path="/var/lib/ciris/edge/identity",
...     listen_addr="0.0.0.0:4242",
...     bootstrap_peers=["public-relay.example.org:4242"],
...     announce_interval_seconds=300,
...     local_epoch=0,
...     hybrid_policy="soft_freshness",
...     soft_freshness_window_seconds=86400,
...     agent_mode="client",
... )
>>> pubkeys = edge.transport_identity_pubkeys()
>>> # {"x25519_pub_base64": "...", "ed25519_pub_base64": "..."}

See ``FSD/CIRIS_EDGE.md`` §3.2 for the full call shape (including the
``https_*`` / ``hybrid_policy`` / ``agent_mode`` parameter set).

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

Cohabitation accessors (v2.1.0+): ``Edge.engine()`` returns the host
persist Engine PyObject (CIRISLensCore#43 P0 — reach the same engine
the host wired in); ``Edge.transport_identity_pubkeys()`` returns the
X25519 + Ed25519 dual-key bytes for persist's LocalIdentityAggregate
RET-transport role (CIRISPersist#199).
"""

from .ciris_edge import (
    SUPPORTED_SCHEMA_VERSIONS,
    DurableHandle,
    Edge,
    NetworkEventSubscription,
    ReplicationHandle,
    SubscriptionHandle,
    VerifiedFeedSubscription,
    __version__,
    init_edge_runtime,
)

__all__ = [
    "SUPPORTED_SCHEMA_VERSIONS",
    "DurableHandle",
    "Edge",
    "NetworkEventSubscription",
    "ReplicationHandle",
    "SubscriptionHandle",
    "VerifiedFeedSubscription",
    "__version__",
    "init_edge_runtime",
]
