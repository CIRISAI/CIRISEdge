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
...     hybrid_policy="strict",
...     agent_mode="client",
... )
>>> pubkeys = edge.transport_identity_pubkeys()
>>> # {"x25519_pub_base64": "...", "ed25519_pub_base64": "..."}

See ``FSD/CIRIS_EDGE.md`` §3.2 for the full call shape (including the
``https_*`` / ``hybrid_policy`` / ``agent_mode`` parameter set).

Trust model (OQ-11 closure): hybrid Ed25519 + ML-DSA-65 verify is the
only posture. Edge calls
``ciris_persist.Engine.verify_hybrid_via_directory`` on every inbound
message, hybrid-required. ``hybrid_policy`` accepts ``"strict"`` only;
any other value (the retired ``soft_freshness`` and ``ed25519_fallback``
among them) raises ``ValueError("verify_policy_violation: ...")``
(CC 5.3.2.4.3.1, CIRISEdge#957, CIRISPersist#1233). The keyword stays
until persist v62 removes the argument.

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


def _elf_needed(path):
    """DT_NEEDED names of an ELF64 little-endian shared object, or None.

    Reads only the program headers and the dynamic segment (a few KiB of a
    large file). Anything unexpected returns None.
    """
    import struct

    with open(path, "rb") as f:
        ident = f.read(64)
        if len(ident) < 64 or ident[:4] != b"\x7fELF" or ident[4] != 2 or ident[5] != 1:
            return None
        phoff = struct.unpack_from("<Q", ident, 0x20)[0]
        phentsize, phnum = struct.unpack_from("<HH", ident, 0x36)
        f.seek(phoff)
        ph = f.read(phentsize * phnum)
        loads, dyn = [], None
        for i in range(phnum):
            p_type, _flags, off, vaddr, _pa, filesz, _memsz, _al = struct.unpack_from(
                "<IIQQQQQQ", ph, i * phentsize
            )
            if p_type == 1:  # PT_LOAD
                loads.append((vaddr, off, filesz))
            elif p_type == 2:  # PT_DYNAMIC
                dyn = (off, filesz)
        if dyn is None:
            return None
        f.seek(dyn[0])
        raw = f.read(dyn[1])
        needed, strtab, strsz = [], None, None
        for i in range(0, len(raw) - 15, 16):
            tag, val = struct.unpack_from("<qQ", raw, i)
            if tag == 0:  # DT_NULL
                break
            if tag == 1:  # DT_NEEDED
                needed.append(val)
            elif tag == 5:  # DT_STRTAB
                strtab = val
            elif tag == 10:  # DT_STRSZ
                strsz = val
        if strtab is None or strsz is None:
            return None
        str_off = next((off + strtab - va for va, off, sz in loads if va <= strtab < va + sz), None)
        if str_off is None:
            return None
        f.seek(str_off)
        table = f.read(strsz)
    return [table[n : table.index(b"\0", n)].decode() for n in needed]


def _share_persist_sqlite() -> None:
    """A source-built edge calls persist's bundled sqlite, not the system's.

    CIRISEdge#50: edge runs persist's SqliteBackend code (compiled into
    edge's .so) on connections persist opened, so both MUST call ONE sqlite.
    A repaired wheel already shares persist's copy: its DT_NEEDED names the
    same hashed ``libsqlite3-<hash>.so.0`` persist bundles, which the loader
    maps once (RTLD_LOCAL). A source build (``pip install git+...``) instead
    needs the system ``libsqlite3.so.0``, a second instance never
    initialised, and the first ``sqlite3_prepare_v2`` on persist's
    connection jumps through a null ``xMalloc`` (SIGSEGV, no output).

    Only in that case (edge's extension NEEDs the unhashed
    ``libsqlite3.so.0``) is persist's copy loaded RTLD_GLOBAL ahead of
    edge's .so, so edge's ``sqlite3_*`` bind to it. RTLD_GLOBAL also rebinds
    a later stdlib ``sqlite3``, which is why a wheel never takes this path.
    Linux only; never raises; any doubt is a no-op.
    """
    import sys

    if not sys.platform.startswith("linux"):
        return
    try:
        import ctypes
        import glob
        import importlib.util
        import os

        here = os.path.dirname(os.path.abspath(__file__))
        exts = glob.glob(os.path.join(here, "ciris_edge*.so"))
        if len(exts) != 1 or "libsqlite3.so.0" not in (_elf_needed(exts[0]) or []):
            return
        spec = importlib.util.find_spec("ciris_persist")
        if spec is None or not spec.submodule_search_locations:
            return
        pkg_dir = os.path.abspath(list(spec.submodule_search_locations)[0])
        libs_dir = os.path.join(os.path.dirname(pkg_dir), "ciris_persist.libs")
        for lib in sorted(glob.glob(os.path.join(libs_dir, "libsqlite3-*.so*"))):
            ctypes.CDLL(lib, mode=os.RTLD_NOW | os.RTLD_GLOBAL)
            return
    except Exception:  # noqa: BLE001 - a preload must never break the import
        return


_share_persist_sqlite()

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
    init_logging,
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
    "init_logging",
]
