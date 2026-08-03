window.BENCHMARK_DATA = {
  "lastUpdate": 1785721788199,
  "repoUrl": "https://github.com/CIRISAI/CIRISEdge",
  "entries": {
    "ciris-edge transport / A-V-mesh / replication benchmarks": [
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "aa979d5847f086b60b59758a8c6f8eb24f76a5aa",
          "message": "feat(v15.9.0): adopt persist v24.2.0 — typed Key refusals carry the branch + the receive-plane mirror ledger\n\nAdopts CIRISPersist v24.2.0 (676cef4, CIRISPersist#565): the answer to\nCIRISEdge#433's companion ask. `ReplicatedKeyOutcome::Refused` is no\nlonger a bare variant — `Refused { reason: KeyRefusalReason }` names the\nbranch that fired, a closed APPEND-ONLY 9-token contract (our six became\nnine upstream: AmbiguousOwner split owner_absent/owner_ambiguous,\nconflicting_version out of first-seen-wins, store_conflict naming the\nplan-free sites honestly).\n\n- bridge.rs: the one-site seam flip, extracted as pure\n  `key_outcome_to_apply` (unit-tested exhaustively over\n  KeyRefusalReason::ALL). BOTH duplicate halves map to Duplicate —\n  persist's sharper finding, not just our ask: byte-identical re-offers\n  were already right via Unchanged; the real gap was\n  already_anchored_identical (same-envelope-DIFFERENT-BYTES legitimate\n  re-encoding of an anchored record) reading as a security-shaped refusal\n  on every baked-seed node's common path. Taking only the new variant\n  would have left that path misreported.\n- Receive-plane mirror of the #433 withhold ledger (the explicit yes):\n  apply_refusals_by_kind[EnvelopeKind] books every Refused at the #425\n  choke (all planes), key_apply_refusals_by_reason[token] books the typed\n  Key-plane branch by persist's stable token — bounded cardinality by the\n  append-only contract, keyed on the enum constant, never message prose\n  (the two-lists-that-disagree rule). Same inversion, other direction:\n  \"did anything move, and if not, what stopped it?\" asked of what we were\n  OFFERED.\n- pyo3 metrics_snapshot exports both axes.\n- Wire-drive test boundary note: on the MemoryBackend a pubkey-swap\n  fixture currently classifies store_conflict (the plan-free site);\n  edge's test asserts COHERENCE (message token == booked token ∈ the\n  closed set, both axes book once) — which branch classifies is persist's\n  certified unit, not ours.\n\nGates: fmt; clippy -D warnings --all-targets (transport-http +\ntransport-reticulum + pyo3 + test-anchor); lib 731/0 default, 795/0\ntransport-reticulum; test-anchor lane 38/38 (the #435 lane's first\npersist-adopt regression pass); bridge 37/37; observability 8/8;\nfield_conformance green vs the v15.9.0 restamp.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_012MqRfBEZ3CHfbMt6E2yw48",
          "timestamp": "2026-07-31T20:50:53-05:00",
          "tree_id": "da23390ed15936d6f6858116d821ea43eaeac028",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/aa979d5847f086b60b59758a8c6f8eb24f76a5aa"
        },
        "date": 1785556925554,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40439636,
            "range": "± 44338",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2920113,
            "range": "± 59442",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 200,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 674,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2522,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 10046,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 76902,
            "range": "± 536",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 112,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 298,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 973,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3735,
            "range": "± 93",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 91,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 52,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1359134,
            "range": "± 105345",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1314368,
            "range": "± 59086",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1385257,
            "range": "± 189018",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1411450,
            "range": "± 192636",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 3152749,
            "range": "± 650735",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 3443,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 3438,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 3472,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 3541,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 4128,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 57,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 243,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 490,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 975,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1956,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3869,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 5972,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 105,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 459,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 844,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 1690,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3368,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 7395,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 17507,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 332,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1330,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2661,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 5325,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 10643,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 21265,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 33136,
            "range": "± 220",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 1245,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 4947,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 9899,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 19805,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 39583,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 79158,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 123643,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 138,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 264,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 517,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 1024,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 2016,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 3187,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 262,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 492,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 953,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 1877,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 3368,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 5794,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 253,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 758,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1429,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2772,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 5464,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 10847,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 16907,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 920,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 2757,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 5201,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 10098,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 19891,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 39464,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 61477,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 213,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 405,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 868,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1970,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4992,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 10200,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 103,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 331,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 650,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 2292,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2724,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 6283,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 12272,
            "range": "± 234",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 264,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 812,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1558,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 3090,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 6329,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 13575,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 21758,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 929,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 2818,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 5353,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 10472,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 20878,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 42387,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 67788,
            "range": "± 222",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 151,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 486,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 955,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 2055,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4890,
            "range": "± 102",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 12757,
            "range": "± 158",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 26330,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 247,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 742,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1425,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 2969,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 6589,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 15837,
            "range": "± 377",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 30627,
            "range": "± 438",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 623,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1769,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3324,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6627,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 13763,
            "range": "± 268",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 30301,
            "range": "± 143",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 52723,
            "range": "± 237",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 2178,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 5985,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 11077,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 21498,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 42769,
            "range": "± 553",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 87523,
            "range": "± 273",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 141804,
            "range": "± 330",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 329,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 1032,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 2025,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 4597,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 10356,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 28334,
            "range": "± 283",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 57244,
            "range": "± 956",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 541,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1557,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 2938,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 6211,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 13928,
            "range": "± 106",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 34410,
            "range": "± 461",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 63875,
            "range": "± 407",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 1360,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 3692,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 6884,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 13644,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 28341,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 63047,
            "range": "± 471",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 110531,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 4669,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 12324,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 22596,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 43588,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 86668,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 177618,
            "range": "± 328",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 288517,
            "range": "± 181",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 252,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 1045,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 4137,
            "range": "± 520",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 16958,
            "range": "± 4805",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 158,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 694,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2852,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 11584,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 162328,
            "range": "± 1090",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 1620,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 6573,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 28341,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 213768,
            "range": "± 836",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 582919,
            "range": "± 5261",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 253,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 1003,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 550,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 4289,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 361,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2315,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 16604,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1428,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 9266,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 172,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 89,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 702,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 361,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 2905,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1475,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 11795,
            "range": "± 237",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 358,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 5927,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 159681,
            "range": "± 988",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1396,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 23490,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 587,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 278,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2511,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1250,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 10106,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 5112,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 142623,
            "range": "± 1329",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 357,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 21210,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 579143,
            "range": "± 6614",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1426,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 294158,
            "range": "± 1204",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 113,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 461,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 248,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1839,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 1234,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 915,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 6766,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 4399,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3680,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 28968,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 16869,
            "range": "± 166",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 14592,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 328,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 170,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 164,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1313,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 686,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 656,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 5255,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2818,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2624,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 21014,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 11565,
            "range": "± 391",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 10502,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 83139,
            "range": "± 450",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 160795,
            "range": "± 2129",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 37521,
            "range": "± 293",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 2703,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 272,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 2154,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 2153,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 10812,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 272,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 8649,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 8615,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 43231,
            "range": "± 77",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 272,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 34640,
            "range": "± 229",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 34450,
            "range": "± 231",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 172914,
            "range": "± 1139",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 272,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 236868,
            "range": "± 1245",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 137894,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 675275,
            "range": "± 4003",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 272,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 850529,
            "range": "± 7989",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 538379,
            "range": "± 282",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 177,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 733,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2974,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 11934,
            "range": "± 211",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 469,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1929,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 7819,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 106176,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 875,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3637,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 14366,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 198677,
            "range": "± 1549",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1935,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 7709,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 32077,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 121490,
            "range": "± 3753",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 6168,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 24656,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 96779,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 363598,
            "range": "± 1166",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3903,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3900,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3971,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 3927,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 2040,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3928,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 181,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 2041,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6941,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6940,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 28381,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 28471,
            "range": "± 99",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 114217,
            "range": "± 378",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 114413,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 457596,
            "range": "± 1057",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 457976,
            "range": "± 1481",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1838946,
            "range": "± 2653",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1838888,
            "range": "± 4905",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7350296,
            "range": "± 3326",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7361737,
            "range": "± 7702",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 56213,
            "range": "± 320",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 26107,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 84753,
            "range": "± 610",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 58726,
            "range": "± 244",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 178804,
            "range": "± 1144",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 141675,
            "range": "± 1277",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 518592,
            "range": "± 2922",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 442790,
            "range": "± 3862",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1868664,
            "range": "± 15913",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1629743,
            "range": "± 10310",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 7200260,
            "range": "± 52937",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 6264150,
            "range": "± 61935",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1379,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1771,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 630,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 919,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1170,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1435,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 515,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 350,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 596,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "d53c7d42ca77467d8381d6e44e090a9fe5360179",
          "message": "fix(v15.9.1): #432 — heal the live-map/durable-store attribution divergence in place\n\nCloses #432.\n\nA peer whose first contact is an announce is admitted at (Advisory,\nowns_key=false) — root_binding returns UnknownKeyId before the peer's\nfederation key resolves — and the live peers map and the durable\ntransport_destinations store have INDEPENDENT writers: the announce path\nmoves both in one motion, but a replication-/server-side rooting updates\nonly the store. On a long-lived canonical the attribution gate then reads\nthe stale live entry forever: persist says `rooted`, the resolver says\nAdvisory, every Attestation-plane frame drops, and only a process restart\n(whose boot prime re-reads persist) heals it. Two production\nreproductions, two independent keys, ~2 days dark fleet-wide; new-agent\nonboarding could not work at all.\n\nThe fix — the #432 asks, in order:\n\n1. UPGRADE THE LIVE MAP WHEN A BINDING IS ROOTED, not only at boot:\n   `heal_or_report_attribution_miss` — at the attribution-failure point\n   (bounded by the existing per-key_id throttle; the first failing frame\n   always Emits, so a genuine divergence heals on frame ONE), consult the\n   durable store (`RootingDirectory::stored_reticulum_binding`, a new\n   point-read over persist's list_transport_destinations_for). If the\n   store holds `rooted` FOR THE SAME transport identity the link proved\n   (identity-hash equality — the store is authority for TRUST, never for\n   IDENTITY), upgrade the live entry in place (provenance=Rooted,\n   owns_key=true, epoch=max) and attribute the SAME frame, item 2\n   permitting. A one-peer, mid-session boot prime — exactly the motion a\n   restart performs, made automatic.\n2. MAKE THE DIVERGENCE DETECTABLE: the heal WARNs loudly on upgrade; a\n   store rooting a DIFFERENT identity WARNs divergence-not-healed (trust\n   is never laundered across identities); a peers-map miss with a rooted\n   store WARNs lost-entry divergence.\n3. THE MESSAGE CARRIES ITS EVIDENCE: the #404 warn now includes\n   stored_provenance beside the resolved operands, and the hint is\n   OPERAND-CONDITIONAL — the old unconditional \"churn downgrade\" hint\n   printed against owns_key=false operands and sent the reader to the\n   wrong cause for a day.\n\nPure decision core (`divergence_heal_decision`) unit-tested with the\nEXACT operands both reproductions logged; the read half tested against\nthe real write-through shapes (Advisory first-contact write, then the\nindependent rooted write at a higher epoch).\n\nIf persist still holds Advisory for a fresh peer, the heal has nothing to\nact on — first-contact rooting via the announce-borne verify attestation\npackage is the follow-up (filed separately; pending the verify-side\npresenter-binding confirmation). And if a healed peer lacks its hybrid\nSignedTransportDestination, the distinct item-2 warn names #406.\n\nGates: fmt; clippy -D warnings --all-targets (transport-http +\ntransport-reticulum + pyo3 + test-anchor); lib 797/0 transport-reticulum,\n731/0 default; reticulum_loopback 2/2; field_conformance vs the v15.9.1\nrestamp.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_012MqRfBEZ3CHfbMt6E2yw48",
          "timestamp": "2026-07-31T22:58:16-05:00",
          "tree_id": "b0edcf57576df52ae7ab000c094816ed4fb090b2",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/d53c7d42ca77467d8381d6e44e090a9fe5360179"
        },
        "date": 1785562088504,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 35427834,
            "range": "± 29066",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2094683,
            "range": "± 93409",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 67,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 174,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2393,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 9397,
            "range": "± 257",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 69074,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 98,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 256,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 849,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3171,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 84,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 46,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 47,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1526158,
            "range": "± 146797",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1460239,
            "range": "± 40740",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1539916,
            "range": "± 112115",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1559205,
            "range": "± 210243",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 1508393,
            "range": "± 66634",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 2145,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 2149,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 2196,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 2354,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 2962,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 478,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 956,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1964,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3874,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 6136,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 400,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 801,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 1601,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3430,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 6597,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 10673,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 289,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1155,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2311,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 4622,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 9244,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 20069,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 31301,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 1025,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 4100,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 8199,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 16398,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 32805,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 65581,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 102482,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 134,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 254,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 493,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 980,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 1933,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 3019,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 427,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 897,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 1766,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 3437,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 5280,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 217,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 705,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1329,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2578,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 5075,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 10135,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 15789,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 875,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 2618,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 4941,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 9590,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 18880,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 37465,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 58387,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 59,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 196,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 397,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 800,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1723,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4098,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 7571,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 101,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 311,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 597,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 1198,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2420,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 5698,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 9724,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 253,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 779,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1484,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 2919,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 5907,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 12358,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 20450,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 773,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 2328,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 4406,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 8589,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 17069,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 34582,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 55059,
            "range": "± 153",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 147,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 469,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 911,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 1867,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4205,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 10218,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 19623,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 231,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 692,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1315,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 2671,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 5676,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 13200,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 23785,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 591,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1669,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3109,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6094,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 12400,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 24888,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 43517,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 1828,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 4994,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 9224,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 17778,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 35252,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 71758,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 115379,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 321,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 993,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 1918,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 3959,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 8984,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 22478,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 43245,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 505,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1468,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 2765,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 5627,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 12088,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 27962,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 53447,
            "range": "± 117",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 1295,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 3506,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 6472,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 12661,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 25838,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 52337,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 89880,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 4210,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 11447,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 21102,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 40691,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 80637,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 164388,
            "range": "± 161",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 264200,
            "range": "± 239",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 54,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 245,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 932,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 3860,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 15588,
            "range": "± 138",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 163,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 648,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2600,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 10804,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 160931,
            "range": "± 214",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 588,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 2385,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 9705,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 139382,
            "range": "± 1232",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 592295,
            "range": "± 1414",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 32,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 238,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 131,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 952,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 514,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 3912,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 345,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2098,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 15397,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1351,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 8475,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 160,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 638,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 333,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 2614,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1335,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 10606,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 347,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 5501,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 159947,
            "range": "± 1490",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1364,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 22082,
            "range": "± 278",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 579,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 290,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2347,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1173,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 9608,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 72,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 4825,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 138556,
            "range": "± 204",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 347,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 19479,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 590671,
            "range": "± 1150",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1361,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 285203,
            "range": "± 828",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 107,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 430,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 236,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 201,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1590,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 930,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 807,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 6432,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 3978,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3227,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 25231,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 29,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 15526,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 13471,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 313,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 163,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 157,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1253,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 649,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 631,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 5011,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2626,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2527,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 20045,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 10815,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 10108,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 76947,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 78,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 162474,
            "range": "± 463",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 39086,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 1147,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 289,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 580,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 570,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 4589,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 289,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 2354,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 2283,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 18353,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 289,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 9503,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 9141,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 73111,
            "range": "± 98",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 286,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 139169,
            "range": "± 321",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 36595,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 285634,
            "range": "± 167",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 286,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 586670,
            "range": "± 1068",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 142894,
            "range": "± 248",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 172,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 684,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2847,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 11170,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 425,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1711,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 7254,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 110919,
            "range": "± 93",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 820,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3336,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 13689,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 199996,
            "range": "± 278",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1717,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 6992,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 27824,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 115421,
            "range": "± 1436",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 5745,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 23010,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 88722,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 362158,
            "range": "± 11191",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3605,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3576,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3573,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 3565,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 174,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 1861,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3578,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 174,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 1872,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6910,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6907,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 27669,
            "range": "± 142",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 27612,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 113593,
            "range": "± 143",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 113569,
            "range": "± 141",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 455351,
            "range": "± 367",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 455945,
            "range": "± 302",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1822568,
            "range": "± 1328",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1823127,
            "range": "± 958",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7280822,
            "range": "± 3181",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7284086,
            "range": "± 32431",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 50810,
            "range": "± 359",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 23539,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 76295,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 50813,
            "range": "± 63",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 162073,
            "range": "± 724",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 128446,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 472782,
            "range": "± 2108",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 404080,
            "range": "± 1939",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1700821,
            "range": "± 6334",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1489332,
            "range": "± 11998",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 6656602,
            "range": "± 78196",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 5805196,
            "range": "± 29268",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1265,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1615,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 591,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 820,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1052,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1268,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 364,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 344,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 539,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "532fce0c744bcb1008572562f7cddc7719df332f",
          "message": "feat(v15.10.0): the unblocked wave — #430 transit gate wired, #438 honest fountain math + benches, #352 pushdown verdict pinned\n\nThree parallel lanes, one cut (see the merge commits for each lane's\nfull story):\n\n- #430 (CLOSED): infra:transport hop-eligibility gate — TransitGate over\n  persist's resolve_transit_eligibility (zero trust logic in edge),\n  authoritative-TTL cache + 30s negative TTL + via_root invalidation,\n  AvSubscriber::plan_parent_gated as the live-path planner, bridge\n  revocation observer for event-driven invalidation, ALLOW path proven\n  through persist's own 7-witness exercise. The CI test-anchor lane\n  widens to the whole lib.\n- #438 (CLOSED): the fountain table's double defect fixed — the target\n  had slipped a column AND the table (and the issue's own recompute)\n  used a naive independence model over 30 peers when only 26 distinct\n  symbols exist. Table now regenerates from an executable exact\n  derivation; design target restated to what the constants MEET (≥99%\n  @ q=0.90, ≥99.9% @ q=0.95; constants unchanged); Lane-B sim dump\n  reproduces it by measurement; a real-RaptorQ criterion bench measures\n  d(m) + the availability×decode composite (0.994994 @ q=0.90 — the\n  restated target holds under real decode). Workflow wiring included:\n  bench.yml run_bench line + codec-fountain in the compile gate.\n- #352 (CLOSED as contractually-empty): persist v17.5.0 (#455) reversed\n  the issue's premise after filing — list_scores is the caller-gated\n  consumer view (using it for the sweep is the documented #336\n  silent-narrowing shape) and list_attestation_log keeps gossip policy\n  at the consumer tier by contract; AttestationFilter cannot express\n  the advertise predicate regardless. Verdict documented at the filter\n  site; the projection boundary + #433 ledger eligibility rule pinned\n  by a five-row matrix equivalence test.\n\nGates (union): fmt; clippy -D warnings --all-targets on transport-http +\ntransport-reticulum + pyo3 + test-anchor + codec-fountain; lib 747/0\ndefault, 813/0 reticulum, 749/0 test-anchor; cargo bench --no-run on the\nCI gate's exact feature set; field_conformance vs the v15.10.0 restamp.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_012MqRfBEZ3CHfbMt6E2yw48",
          "timestamp": "2026-08-02T15:43:55-05:00",
          "tree_id": "fa95cc8105fce0aae2c230c79006117bc8a8fa57",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/532fce0c744bcb1008572562f7cddc7719df332f"
        },
        "date": 1785709632166,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40418665,
            "range": "± 93028",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2351221,
            "range": "± 265322",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 194,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 669,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2549,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 10027,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 76066,
            "range": "± 197",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 63,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 104,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 260,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 854,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3180,
            "range": "± 109",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 91,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1415058,
            "range": "± 250753",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1433430,
            "range": "± 210732",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1403241,
            "range": "± 617953",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1405459,
            "range": "± 190381",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 3171806,
            "range": "± 439242",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 3292,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 3299,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 3359,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 3560,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 3995,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 240,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 473,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 960,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1938,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3743,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 5949,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 105,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 422,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 835,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 1678,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3324,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 6677,
            "range": "± 67",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 11164,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 328,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1312,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2623,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 5248,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 10493,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 20992,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 32529,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 1092,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 4368,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 8739,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 17485,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 34964,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 69947,
            "range": "± 510",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 109264,
            "range": "± 106",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 256,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 497,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 981,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 1945,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 3028,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 149,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 515,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 1966,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 3921,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 3635,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 11761,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 249,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 745,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1401,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2762,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 5437,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 10624,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 16547,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 1811,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 6426,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 12576,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 24890,
            "range": "± 291",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 49494,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 98712,
            "range": "± 432",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 154100,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 202,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 411,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 862,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1982,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4784,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 9116,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 99,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 325,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 641,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 1243,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2806,
            "range": "± 27",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 6248,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 11423,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 267,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 821,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1570,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 3136,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 6412,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 13734,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 20814,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 831,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 2517,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 4773,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 9364,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 18676,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 37944,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 60858,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 150,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 489,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 951,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 2109,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4846,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 12236,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 23759,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 246,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 741,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1425,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 2973,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 6518,
            "range": "± 86",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 15269,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 28973,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 622,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1764,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3306,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6591,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 13566,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 29873,
            "range": "± 164",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 47733,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 1965,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 5435,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 10098,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 19278,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 38407,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 78725,
            "range": "± 95",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 127280,
            "range": "± 183",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 327,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 1037,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 2049,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 4425,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 10452,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 27446,
            "range": "± 262",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 54223,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 546,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1593,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 3049,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 6229,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 13975,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 33032,
            "range": "± 141",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 63962,
            "range": "± 145",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 2374,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 7785,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 15039,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 29976,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 60918,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 127857,
            "range": "± 258",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 110577,
            "range": "± 175",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 4208,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 11078,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 20325,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 39206,
            "range": "± 172",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 78078,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 160792,
            "range": "± 249",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 262341,
            "range": "± 5908",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 279,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 1027,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 4304,
            "range": "± 930",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 16636,
            "range": "± 134",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 157,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 692,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2868,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 11753,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 152241,
            "range": "± 1010",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 637,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 2580,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 10469,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 134476,
            "range": "± 1347",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 572963,
            "range": "± 3891",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 34,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 258,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 142,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 1029,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 558,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 4286,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 361,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2296,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 16997,
            "range": "± 198",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1410,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 9349,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 172,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 699,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 353,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 2997,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1475,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 11884,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 358,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 6334,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 152845,
            "range": "± 976",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1402,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 23376,
            "range": "± 62",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 625,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2559,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1277,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 10277,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 5198,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 134998,
            "range": "± 889",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 362,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 20932,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 573669,
            "range": "± 10329",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1412,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 280931,
            "range": "± 2266",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 105,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 128,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 422,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 233,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 210,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1692,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 1011,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 843,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 7262,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 4310,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3376,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 28451,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 16847,
            "range": "± 160",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 14189,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 328,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 173,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 166,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1314,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 698,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 665,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 5255,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2910,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2661,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 21014,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 84,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 11617,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 9527,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 81279,
            "range": "± 1067",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 156575,
            "range": "± 895",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 41469,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 1251,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 310,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 631,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 625,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 5002,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 310,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 2586,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 2502,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 20036,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 310,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 10365,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 10006,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 80052,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 310,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 138164,
            "range": "± 779",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 40037,
            "range": "± 314",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 312876,
            "range": "± 471",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 310,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 600608,
            "range": "± 4281",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 156398,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 174,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 724,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2923,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 11827,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 470,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1937,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 8004,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 103807,
            "range": "± 444",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 880,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3683,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 14542,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 193815,
            "range": "± 1553",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1916,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 7784,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 32191,
            "range": "± 489",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 121553,
            "range": "± 185",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 6186,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 24638,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 105961,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 366367,
            "range": "± 13850",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3932,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3931,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3942,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 3893,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 178,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 2041,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3948,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 2034,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6967,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6933,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 28313,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 28459,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 114794,
            "range": "± 254",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 114836,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 459150,
            "range": "± 432",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 459858,
            "range": "± 512",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1840851,
            "range": "± 1618",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1839596,
            "range": "± 2185",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7357576,
            "range": "± 3583",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7354813,
            "range": "± 44168",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 55719,
            "range": "± 607",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 25716,
            "range": "± 281",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 83304,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 57563,
            "range": "± 213",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 176068,
            "range": "± 944",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 139009,
            "range": "± 3260",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 513947,
            "range": "± 1346",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 439551,
            "range": "± 6978",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1846895,
            "range": "± 13546",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1611129,
            "range": "± 11732",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 7183613,
            "range": "± 62901",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 6230876,
            "range": "± 43974",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1385,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1736,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 654,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 899,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1125,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1392,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 350,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 315,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 585,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m20",
            "value": 1703,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m23",
            "value": 1838,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m26",
            "value": 545,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/encode_n20_k6",
            "value": 1104,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail80pct_x100000",
            "value": 84514,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail85pct_x100000",
            "value": 95738,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail90pct_x100000",
            "value": 99508,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail95pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "ce7b8c7bbadc0eed58657757bc11598c98d4ce9e",
          "message": "merge: #281 canonical-genesis bootstrap adopt — baked recognition + tombstone-filtered dials (consumer-side #377 subtraction)",
          "timestamp": "2026-08-02T17:21:12-05:00",
          "tree_id": "d8679e93974d0a1a22db3c4fa5df76fd15d8b04d",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/ce7b8c7bbadc0eed58657757bc11598c98d4ce9e"
        },
        "date": 1785715945428,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40470971,
            "range": "± 42338",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 3585198,
            "range": "± 270880",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 75,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 199,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 684,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2588,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 9985,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 77821,
            "range": "± 3218",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 122,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 326,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 969,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3687,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 89,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 51,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 48,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1505413,
            "range": "± 113963",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1511628,
            "range": "± 123566",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1453293,
            "range": "± 228041",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1500325,
            "range": "± 224280",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 3787700,
            "range": "± 180913",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 3293,
            "range": "± 48",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 3307,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 3361,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 3562,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 4003,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 229,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 443,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 914,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1863,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3614,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 5769,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 104,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 453,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 1345,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 2692,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3612,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 6534,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 11254,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 333,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1334,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2670,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 5330,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 10660,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 21335,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 32504,
            "range": "± 103",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 1085,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 4340,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 8679,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 17359,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 34714,
            "range": "± 118",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 69421,
            "range": "± 145",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 108502,
            "range": "± 945",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 131,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 244,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 489,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 975,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 1924,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 3019,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 116,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 283,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 507,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 911,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 3884,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 3382,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 5600,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 247,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 736,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1389,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2694,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 5305,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 10522,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 14880,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 813,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 2437,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 4604,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 8939,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 17609,
            "range": "± 634",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 34930,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 54420,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 201,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 404,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 854,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1922,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4884,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 9338,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 322,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 637,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 1301,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2674,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 10765,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 11627,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 267,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 804,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1542,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 3069,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 6291,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 13810,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 21268,
            "range": "± 187",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 1687,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 3563,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 6083,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 11183,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 21523,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 42874,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 68328,
            "range": "± 81",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 147,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 472,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 949,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 2049,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4852,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 12663,
            "range": "± 138",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 25631,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 237,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 717,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1388,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 2905,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 6613,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 15790,
            "range": "± 193",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 29150,
            "range": "± 403",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 621,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1754,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3292,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6548,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 13551,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 29770,
            "range": "± 429",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 76277,
            "range": "± 265",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 1941,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 5380,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 10001,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 19464,
            "range": "± 277",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 38841,
            "range": "± 105",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 79775,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 129810,
            "range": "± 136",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 320,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 1024,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 1994,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 4359,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 10253,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 27909,
            "range": "± 1600",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 57410,
            "range": "± 881",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 521,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1521,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 2918,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 6217,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 14124,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 34417,
            "range": "± 426",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 66678,
            "range": "± 959",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 1376,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 3726,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 6991,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 13928,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 28562,
            "range": "± 103",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 61544,
            "range": "± 348",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 102268,
            "range": "± 610",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 8149,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 26926,
            "range": "± 29",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 52050,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 102739,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 205210,
            "range": "± 213",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 415256,
            "range": "± 595",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 660578,
            "range": "± 1393",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 274,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 985,
            "range": "± 47",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 4237,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 16764,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 166,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 692,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2859,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 11470,
            "range": "± 122",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 161035,
            "range": "± 16728",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 587,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 2555,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 26421,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 210286,
            "range": "± 1688",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 611898,
            "range": "± 5548",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 129,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 66,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 480,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 269,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 1505,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 557,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 4655,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 359,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2761,
            "range": "± 145",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 16595,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1411,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 9416,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 172,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 695,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 350,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 2873,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1451,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 19547,
            "range": "± 8368",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 362,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 5985,
            "range": "± 265",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 161673,
            "range": "± 1672",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1409,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 23741,
            "range": "± 422",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 548,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 272,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2254,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1112,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 9062,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 77,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 4614,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 138684,
            "range": "± 1910",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 358,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 18510,
            "range": "± 79",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 583780,
            "range": "± 7293",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1412,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 290947,
            "range": "± 5579",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 101,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 127,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 450,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 258,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 228,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1802,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 1036,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 880,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 6569,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 8623,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3290,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 27536,
            "range": "± 34",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 16850,
            "range": "± 150",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 13825,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 335,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 83,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 176,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 169,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1341,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 84,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 692,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 677,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 5370,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 84,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2807,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2707,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 21432,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 11322,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 10827,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 73699,
            "range": "± 110",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 162881,
            "range": "± 1794",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 37481,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 1239,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 629,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 615,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 4957,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 2580,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 2458,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 19829,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 10399,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 9835,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 79328,
            "range": "± 724",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 312,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 143324,
            "range": "± 2880",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 39336,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 309624,
            "range": "± 206",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 304,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 570356,
            "range": "± 3794",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 151975,
            "range": "± 869",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 179,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 730,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2963,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 11958,
            "range": "± 154",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 453,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1942,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 7839,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 110738,
            "range": "± 1036",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 878,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3629,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 14304,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 201544,
            "range": "± 1186",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1929,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 7316,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 31479,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 125190,
            "range": "± 494",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 6175,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 24938,
            "range": "± 99",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 90899,
            "range": "± 803",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 371880,
            "range": "± 14536",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3981,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3877,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3916,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 3918,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 180,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 2019,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3922,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 180,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 2017,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6918,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6934,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 28231,
            "range": "± 57",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 28239,
            "range": "± 64",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 114527,
            "range": "± 276",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 114567,
            "range": "± 6308",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 457458,
            "range": "± 427",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 458001,
            "range": "± 962",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1832885,
            "range": "± 21297",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1833273,
            "range": "± 1507",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7325141,
            "range": "± 8492",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7329819,
            "range": "± 2215",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 54995,
            "range": "± 381",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 25810,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 83152,
            "range": "± 335",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 57785,
            "range": "± 287",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 177847,
            "range": "± 1257",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 142221,
            "range": "± 759",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 518626,
            "range": "± 1680",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 437904,
            "range": "± 2374",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1867411,
            "range": "± 16281",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1612341,
            "range": "± 12202",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 7200974,
            "range": "± 90400",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 6235728,
            "range": "± 96888",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1373,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1761,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 616,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 872,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1130,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1373,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 41,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 501,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 313,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 580,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m20",
            "value": 1693,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m23",
            "value": 1818,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m26",
            "value": 548,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/encode_n20_k6",
            "value": 1096,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail80pct_x100000",
            "value": 84514,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail85pct_x100000",
            "value": 95738,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail90pct_x100000",
            "value": 99508,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail95pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "aa81d25b29f13ea1138d810b3914f47f45698460",
          "message": "feat(v15.12.0): the receipts wave — #441 removal-delivery receipts, #439 capacity:relay_delivery:v1 + consent-gated emission, #437 bundle-gated Rooted save\n\nThree lanes on the v25/v11 pins (see merge commits). Gates: superset\nclippy clean; lib 778/844/780 (default/reticulum/test-anchor).\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_012MqRfBEZ3CHfbMt6E2yw48",
          "timestamp": "2026-08-02T18:53:24-05:00",
          "tree_id": "267f6313c53f74c8b21737d1e0ada1e4eb072993",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/aa81d25b29f13ea1138d810b3914f47f45698460"
        },
        "date": 1785721081948,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 45680175,
            "range": "± 20709",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2405549,
            "range": "± 161066",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 67,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 177,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 618,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2368,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 9464,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 69313,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 61,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 108,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 289,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 967,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3702,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 81,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 43,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1173539,
            "range": "± 64386",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1185497,
            "range": "± 152340",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1334650,
            "range": "± 230809",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1166725,
            "range": "± 140437",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 1355570,
            "range": "± 367285",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 2230,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 2246,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 2302,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 2456,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 3053,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 53,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 225,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 452,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 875,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1779,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3565,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 5586,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 103,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 414,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 830,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 1660,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3326,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 6286,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 10336,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 315,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1223,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2447,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 4894,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 9789,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 19646,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 30693,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 1192,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 4757,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 9516,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 18568,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 37120,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 74261,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 116047,
            "range": "± 159",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 44,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 132,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 249,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 480,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 972,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 1887,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 2898,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 80,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 240,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 452,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 873,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 1692,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 3345,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 5546,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 230,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 692,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1306,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2531,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 4994,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 9912,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 15881,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 740,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 2222,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 4199,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 8149,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 16049,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 31873,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 49656,
            "range": "± 76",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 197,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 433,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 812,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1798,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4298,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 8071,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 95,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 304,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 593,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 1197,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2454,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 5910,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 10478,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 255,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 788,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1497,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 2965,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 6046,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 12363,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 19450,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 757,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 2296,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 4348,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 8507,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 16951,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 34406,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 55036,
            "range": "± 104",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 468,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 910,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 1898,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4262,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 10894,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 21417,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 242,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 719,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1373,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 2707,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 5858,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 13873,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 26159,
            "range": "± 49",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 591,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1693,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3165,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6254,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 12844,
            "range": "± 87",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 27782,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 47148,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 2025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 5580,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 10328,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 19977,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 39661,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 81044,
            "range": "± 100",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 130762,
            "range": "± 1975",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 317,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 1000,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 1953,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 4097,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 9386,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 24116,
            "range": "± 53",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 47150,
            "range": "± 69",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 521,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1501,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 2787,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 5668,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 12463,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 29541,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 55635,
            "range": "± 91",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 1262,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 3459,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 6412,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 12604,
            "range": "± 22",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 25954,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 53395,
            "range": "± 66",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 92449,
            "range": "± 529",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 4477,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 11808,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 21625,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 41480,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 82295,
            "range": "± 287",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 168419,
            "range": "± 210",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 272556,
            "range": "± 342",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 231,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 961,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 3942,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 15114,
            "range": "± 239",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 154,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 642,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2620,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 10571,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 163793,
            "range": "± 610",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 581,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 2348,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 9647,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 142714,
            "range": "± 517",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 584687,
            "range": "± 1502",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 33,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 246,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 132,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 932,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 513,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 3795,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 346,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2073,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 15170,
            "range": "± 101",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1366,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 8416,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 161,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 640,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 17,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 330,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 2596,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1336,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 11091,
            "range": "± 229",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 345,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 5440,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 161262,
            "range": "± 525",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1361,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 21796,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 580,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 294,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2338,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 18,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1172,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 9620,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 71,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 4852,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 141750,
            "range": "± 307",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 344,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 19493,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 584824,
            "range": "± 1036",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1366,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 285373,
            "range": "± 941",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 3,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 97,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 58,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 49,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 427,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 233,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 215,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1705,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 937,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 861,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 6284,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 27,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 3742,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3162,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 26674,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 25,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 15227,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 12278,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 285,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 149,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 141,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1142,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 624,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 565,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 4570,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2531,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2263,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 18280,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 10603,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 9077,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 70979,
            "range": "± 50",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 69,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 162775,
            "range": "± 1514",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 33911,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 1140,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 287,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 574,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 568,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 4561,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 287,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 2340,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 2287,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 18238,
            "range": "± 41",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 284,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 9638,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 9155,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 72581,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 282,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 142774,
            "range": "± 759",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 36644,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 283683,
            "range": "± 920",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 282,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 585628,
            "range": "± 2766",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 143065,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 161,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 655,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2669,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 10721,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 427,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1709,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 7051,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 111940,
            "range": "± 335",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 815,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3283,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 13445,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 199946,
            "range": "± 1057",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1703,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 6881,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 27479,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 109573,
            "range": "± 295",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 5384,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 21694,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 86761,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 330009,
            "range": "± 8151",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3402,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3511,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3511,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 3512,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 176,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 1842,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3507,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 174,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 1841,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6816,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6807,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 27402,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 27319,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 112469,
            "range": "± 78",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 112323,
            "range": "± 71",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 450688,
            "range": "± 943",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 450961,
            "range": "± 884",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1795746,
            "range": "± 1174",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1795541,
            "range": "± 1629",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7179608,
            "range": "± 3091",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7183437,
            "range": "± 3924",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 50910,
            "range": "± 252",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 23511,
            "range": "± 59",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 76890,
            "range": "± 173",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 51480,
            "range": "± 368",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 162580,
            "range": "± 482",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 128797,
            "range": "± 1658",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 473768,
            "range": "± 1743",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 404501,
            "range": "± 3504",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1703291,
            "range": "± 7930",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1489497,
            "range": "± 18600",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 6593037,
            "range": "± 45765",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 5775888,
            "range": "± 38234",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1242,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1562,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 570,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 798,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1016,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1245,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 40,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 332,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 305,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 519,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 37,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m20",
            "value": 1566,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m23",
            "value": 1755,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m26",
            "value": 540,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/encode_n20_k6",
            "value": 1044,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail80pct_x100000",
            "value": 84514,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail85pct_x100000",
            "value": 95738,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail90pct_x100000",
            "value": 99508,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail95pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      },
      {
        "commit": {
          "author": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "committer": {
            "email": "mooreericnyc@gmail.com",
            "name": "Eric Moore",
            "username": "emooreatx"
          },
          "distinct": true,
          "id": "8bf567d71f88d1ebf23b11b5a2f8a03dbd4d545d",
          "message": "fix(v15.12.1): #442 — the evidence TSV ships its header row (the file no longer vendors as zero coverage)\n\ncheck_claims.py strips # comments and DictReader consumes the first\nnon-comment line as the header — so edge's headerless TSV parsed its\nfirst DATA row as fieldnames and silently skipped everything else:\nvendored as zero coverage, failed nothing (the CIRISConstitution#54\nsilence-reads-as-coverage class). The generator now emits\ndecimal_id/claim_id/repo/path#symbol/crate@version as the first\nnon-comment line (persist's shape verbatim), the vendored TSV carries\nit, and the evidence_tsv_matches_emitted drift test now pins the header\nround-trip too. Rows restamped @v15.12.1 for the Constitution wall pin.\n\nCo-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>\nClaude-Session: https://claude.ai/code/session_012MqRfBEZ3CHfbMt6E2yw48",
          "timestamp": "2026-08-02T19:06:39-05:00",
          "tree_id": "d2f40cf697040d95316f534640e81740811b0cc1",
          "url": "https://github.com/CIRISAI/CIRISEdge/commit/8bf567d71f88d1ebf23b11b5a2f8a03dbd4d545d"
        },
        "date": 1785721786732,
        "tool": "cargo",
        "benches": [
          {
            "name": "calibration/splitmix64_10m",
            "value": 40426474,
            "range": "± 56627",
            "unit": "ns/iter"
          },
          {
            "name": "calibration/dram_random_walk_500k",
            "value": 2568826,
            "range": "± 418410",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/256",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/1024",
            "value": 199,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/4096",
            "value": 660,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/16384",
            "value": 2616,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_single/65536",
            "value": 10032,
            "range": "± 82",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_verify_bulk/1k_256B",
            "value": 75844,
            "range": "± 492",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/256",
            "value": 65,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/1024",
            "value": 111,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/4096",
            "value": 324,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/16384",
            "value": 980,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "envelope_canonicalize/65536",
            "value": 3733,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/OpaqueEvent",
            "value": 92,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/FederationAnnouncement",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/ContentFetch",
            "value": 52,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "dispatch_inbound/StewardDirective",
            "value": 50,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/256",
            "value": 1421662,
            "range": "± 364639",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/1024",
            "value": 1483316,
            "range": "± 139171",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/4096",
            "value": 1411226,
            "range": "± 152882",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/16384",
            "value": 1327365,
            "range": "± 107279",
            "unit": "ns/iter"
          },
          {
            "name": "transport_reticulum_loopback/65536",
            "value": 2991277,
            "range": "± 619189",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/256",
            "value": 3255,
            "range": "± 85",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/1024",
            "value": 3235,
            "range": "± 38",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/4096",
            "value": 3270,
            "range": "± 58",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/16384",
            "value": 3481,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "transport_http_loopback/65536",
            "value": 3943,
            "range": "± 73",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/2",
            "value": 55,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/8",
            "value": 237,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/16",
            "value": 477,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/32",
            "value": 936,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/64",
            "value": 1905,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/128",
            "value": 3794,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame1024B/200",
            "value": 5901,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/2",
            "value": 170,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/8",
            "value": 452,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/16",
            "value": 834,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/32",
            "value": 1669,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/64",
            "value": 3295,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/128",
            "value": 7210,
            "range": "± 14",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame4096B/200",
            "value": 11333,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/2",
            "value": 595,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/8",
            "value": 1180,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/16",
            "value": 2362,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/32",
            "value": 4724,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/64",
            "value": 9447,
            "range": "± 23",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/128",
            "value": 18889,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame16384B/200",
            "value": 33535,
            "range": "± 729",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/2",
            "value": 3259,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/8",
            "value": 13033,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/16",
            "value": 26093,
            "range": "± 21",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/32",
            "value": 52181,
            "range": "± 135",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/64",
            "value": 104331,
            "range": "± 328",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/128",
            "value": 208690,
            "range": "± 527",
            "unit": "ns/iter"
          },
          {
            "name": "naive_seal_chunk_n_recipients/frame65536B/200",
            "value": 326050,
            "range": "± 376",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/2",
            "value": 45,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/8",
            "value": 137,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/16",
            "value": 259,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/32",
            "value": 503,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/64",
            "value": 1001,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/128",
            "value": 2017,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame1024B/200",
            "value": 3087,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/2",
            "value": 182,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/8",
            "value": 286,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/16",
            "value": 511,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/32",
            "value": 961,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/64",
            "value": 1823,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/128",
            "value": 7760,
            "range": "± 30",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame4096B/200",
            "value": 12142,
            "range": "± 32",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/2",
            "value": 227,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/8",
            "value": 676,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/16",
            "value": 1274,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/32",
            "value": 2473,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/64",
            "value": 4862,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/128",
            "value": 9638,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame16384B/200",
            "value": 15021,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/2",
            "value": 1939,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/8",
            "value": 3787,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/16",
            "value": 6250,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/32",
            "value": 11180,
            "range": "± 51",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/64",
            "value": 21047,
            "range": "± 289",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/128",
            "value": 35101,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "inner_once_outer_n_recipients/frame65536B/200",
            "value": 54709,
            "range": "± 80",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/2",
            "value": 59,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/8",
            "value": 195,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/16",
            "value": 408,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/32",
            "value": 883,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/64",
            "value": 1989,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/128",
            "value": 4788,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame1024B/200",
            "value": 9219,
            "range": "± 329",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/2",
            "value": 104,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/8",
            "value": 336,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/16",
            "value": 660,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/32",
            "value": 1245,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/64",
            "value": 2689,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/128",
            "value": 6203,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame4096B/200",
            "value": 11595,
            "range": "± 45",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/2",
            "value": 267,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/8",
            "value": 826,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/16",
            "value": 1580,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/32",
            "value": 3137,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/64",
            "value": 6410,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/128",
            "value": 13510,
            "range": "± 56",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame16384B/200",
            "value": 21217,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/2",
            "value": 943,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/8",
            "value": 2854,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/16",
            "value": 5399,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/32",
            "value": 10577,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/64",
            "value": 21047,
            "range": "± 39",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/128",
            "value": 42758,
            "range": "± 169",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/1-layer-opaque-frame65536B/200",
            "value": 67723,
            "range": "± 553",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/2",
            "value": 149,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/8",
            "value": 478,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/16",
            "value": 949,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/32",
            "value": 2022,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/64",
            "value": 4763,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/128",
            "value": 12648,
            "range": "± 160",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame1024B/200",
            "value": 24439,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/2",
            "value": 246,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/8",
            "value": 735,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/16",
            "value": 1408,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/32",
            "value": 3033,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/64",
            "value": 6361,
            "range": "± 52",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/128",
            "value": 19490,
            "range": "± 240",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame4096B/200",
            "value": 29824,
            "range": "± 26",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/2",
            "value": 633,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/8",
            "value": 1771,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/16",
            "value": 3321,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/32",
            "value": 6612,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/64",
            "value": 13678,
            "range": "± 272",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/128",
            "value": 29734,
            "range": "± 200",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame16384B/200",
            "value": 48570,
            "range": "± 360",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/2",
            "value": 2199,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/8",
            "value": 6061,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/16",
            "value": 11245,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/32",
            "value": 21796,
            "range": "± 348",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/64",
            "value": 43300,
            "range": "± 108",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/128",
            "value": 88550,
            "range": "± 4143",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/3-spatial-av1-svc-frame65536B/200",
            "value": 143622,
            "range": "± 2213",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/2",
            "value": 325,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/8",
            "value": 1024,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/16",
            "value": 1997,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/32",
            "value": 4520,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/64",
            "value": 10321,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/128",
            "value": 27163,
            "range": "± 55",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame1024B/200",
            "value": 54920,
            "range": "± 582",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/2",
            "value": 537,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/8",
            "value": 1543,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/16",
            "value": 2959,
            "range": "± 35",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/32",
            "value": 6322,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/64",
            "value": 14053,
            "range": "± 28",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/128",
            "value": 32865,
            "range": "± 318",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame4096B/200",
            "value": 65715,
            "range": "± 90",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/2",
            "value": 1330,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/8",
            "value": 3685,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/16",
            "value": 6860,
            "range": "± 43",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/32",
            "value": 13611,
            "range": "± 46",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/64",
            "value": 28245,
            "range": "± 327",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/128",
            "value": 57508,
            "range": "± 165",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame16384B/200",
            "value": 104104,
            "range": "± 1082",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/2",
            "value": 4720,
            "range": "± 60",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/8",
            "value": 12492,
            "range": "± 37",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/16",
            "value": 22914,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/32",
            "value": 44167,
            "range": "± 77",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/64",
            "value": 87793,
            "range": "± 250",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/128",
            "value": 179686,
            "range": "± 162",
            "unit": "ns/iter"
          },
          {
            "name": "layered_inner_once_outer_admitted/7-cell-full-svc-frame65536B/200",
            "value": 293433,
            "range": "± 910",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/2",
            "value": 88,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/8",
            "value": 269,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/32",
            "value": 1054,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/128",
            "value": 3877,
            "range": "± 125",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_4096B/500",
            "value": 16203,
            "range": "± 433",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/2",
            "value": 165,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/8",
            "value": 685,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/32",
            "value": 2942,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/128",
            "value": 11477,
            "range": "± 97",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_16384B/500",
            "value": 160616,
            "range": "± 29029",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/2",
            "value": 616,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/8",
            "value": 2548,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/32",
            "value": 10151,
            "range": "± 316",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/128",
            "value": 139791,
            "range": "± 1136",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_uncapped/frame_65536B/500",
            "value": 566190,
            "range": "± 11913",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/2",
            "value": 62,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/2",
            "value": 31,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/8",
            "value": 257,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/8",
            "value": 136,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/32",
            "value": 1027,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/32",
            "value": 76,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/32",
            "value": 551,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/128",
            "value": 4203,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/128",
            "value": 370,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/128",
            "value": 2323,
            "range": "± 65",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_4096B/500",
            "value": 16526,
            "range": "± 213",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_4096B/500",
            "value": 1412,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_4096B/500",
            "value": 9204,
            "range": "± 924",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/2",
            "value": 164,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/2",
            "value": 90,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/8",
            "value": 701,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/8",
            "value": 362,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/32",
            "value": 3001,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/32",
            "value": 75,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/32",
            "value": 1603,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/128",
            "value": 11372,
            "range": "± 61",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/128",
            "value": 363,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/128",
            "value": 6010,
            "range": "± 20",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_16384B/500",
            "value": 163089,
            "range": "± 1791",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_16384B/500",
            "value": 1409,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_16384B/500",
            "value": 24539,
            "range": "± 442",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/2",
            "value": 612,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/2",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/2",
            "value": 306,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/8",
            "value": 2510,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/8",
            "value": 19,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/8",
            "value": 1252,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/32",
            "value": 10653,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/32",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/32",
            "value": 5102,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/128",
            "value": 140452,
            "range": "± 1255",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/128",
            "value": 364,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/128",
            "value": 69495,
            "range": "± 237",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_uncapped/frame_65536B/500",
            "value": 573942,
            "range": "± 2762",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/all_blinking_dot/frame_65536B/500",
            "value": 1398,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "relay_forward_n_subscribers_with_layer_filter/mixed_50_50/frame_65536B/500",
            "value": 282309,
            "range": "± 6549",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/2",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/8",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/32",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/128",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_set_policy_overhead/500",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/2",
            "value": 115,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/2",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/2",
            "value": 57,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/2",
            "value": 56,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/8",
            "value": 457,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/8",
            "value": 28,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/8",
            "value": 259,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/8",
            "value": 226,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/32",
            "value": 1842,
            "range": "± 31",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/32",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/32",
            "value": 1041,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/32",
            "value": 817,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/128",
            "value": 7399,
            "range": "± 6",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/128",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/128",
            "value": 4185,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/128",
            "value": 3621,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_4096B/500",
            "value": 28319,
            "range": "± 24",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_4096B/500",
            "value": 26,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_4096B/500",
            "value": 16522,
            "range": "± 94",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_4096B/500",
            "value": 13655,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/2",
            "value": 300,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/2",
            "value": 75,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/2",
            "value": 175,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/2",
            "value": 143,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/8",
            "value": 1197,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/8",
            "value": 74,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/8",
            "value": 682,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/8",
            "value": 578,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/32",
            "value": 4788,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/32",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/32",
            "value": 2901,
            "range": "± 13",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/32",
            "value": 2590,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/128",
            "value": 20991,
            "range": "± 36",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/128",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/128",
            "value": 27794,
            "range": "± 129",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/128",
            "value": 10348,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_16384B/500",
            "value": 81616,
            "range": "± 84",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_16384B/500",
            "value": 82,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_16384B/500",
            "value": 227929,
            "range": "± 1304",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_16384B/500",
            "value": 36217,
            "range": "± 163",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/2",
            "value": 1213,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/2",
            "value": 301,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/2",
            "value": 612,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/2",
            "value": 609,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/8",
            "value": 4853,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/8",
            "value": 301,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/8",
            "value": 2510,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/8",
            "value": 2436,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/32",
            "value": 19411,
            "range": "± 174",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/32",
            "value": 301,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/32",
            "value": 10623,
            "range": "± 70",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/32",
            "value": 9751,
            "range": "± 9",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/128",
            "value": 77656,
            "range": "± 83",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/128",
            "value": 301,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/128",
            "value": 144960,
            "range": "± 4448",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/128",
            "value": 39017,
            "range": "± 866",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/mesh_publisher/frame_65536B/500",
            "value": 303498,
            "range": "± 1778",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_publisher/frame_65536B/500",
            "value": 301,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_relay/frame_65536B/500",
            "value": 586209,
            "range": "± 3240",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_vs_relay_comparison/relay_outer_only/frame_65536B/500",
            "value": 152353,
            "range": "± 112",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_8",
            "value": 183,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_32",
            "value": 711,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_128",
            "value": 2873,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_400kbps/N_500",
            "value": 11972,
            "range": "± 123",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_8",
            "value": 470,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_32",
            "value": 1895,
            "range": "± 16",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_128",
            "value": 7846,
            "range": "± 10",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_2500kbps/N_500",
            "value": 111880,
            "range": "± 1913",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_8",
            "value": 817,
            "range": "± 4",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_32",
            "value": 3715,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_128",
            "value": 14504,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "relay_sustained_throughput/br_5000kbps/N_500",
            "value": 206029,
            "range": "± 5587",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_1",
            "value": 1893,
            "range": "± 2",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_4",
            "value": 7756,
            "range": "± 42",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_16",
            "value": 33014,
            "range": "± 92",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_32/S_64",
            "value": 123853,
            "range": "± 419",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_1",
            "value": 6099,
            "range": "± 44",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_4",
            "value": 24395,
            "range": "± 74",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_16",
            "value": 97096,
            "range": "± 425",
            "unit": "ns/iter"
          },
          {
            "name": "relay_streams_per_core/N_100/S_64",
            "value": 375070,
            "range": "± 3721",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_BASE/64",
            "value": 3959,
            "range": "± 11",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_BASE/64",
            "value": 3962,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_BASE/64",
            "value": 3905,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_mid_1_1_1/64",
            "value": 4008,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_mid_1_1_1/64",
            "value": 181,
            "range": "± 1",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_mid_1_1_1/64",
            "value": 2028,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_uncapped/layer_high_2_2_2/64",
            "value": 3905,
            "range": "± 7",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_all_blinking_dot/layer_high_2_2_2/64",
            "value": 179,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "relay_layered_bandwidth_saving/policy_mixed_50_50/layer_high_2_2_2/64",
            "value": 2027,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2",
            "value": 6938,
            "range": "± 18",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2",
            "value": 6957,
            "range": "± 15",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/8",
            "value": 28411,
            "range": "± 54",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/8",
            "value": 28521,
            "range": "± 75",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/32",
            "value": 114472,
            "range": "± 298",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/32",
            "value": 114721,
            "range": "± 869",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/128",
            "value": 457974,
            "range": "± 701",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/128",
            "value": 459102,
            "range": "± 4613",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/512",
            "value": 1836576,
            "range": "± 6265",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/512",
            "value": 1836020,
            "range": "± 2548",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Join/2048",
            "value": 7326913,
            "range": "± 5713",
            "unit": "ns/iter"
          },
          {
            "name": "flat_unicast_rewrap/Leave/2048",
            "value": 7331116,
            "range": "± 7635",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2",
            "value": 55780,
            "range": "± 685",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2",
            "value": 25722,
            "range": "± 130",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/8",
            "value": 83586,
            "range": "± 832",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/8",
            "value": 57569,
            "range": "± 436",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/32",
            "value": 178905,
            "range": "± 1259",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/32",
            "value": 139815,
            "range": "± 1090",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/128",
            "value": 513436,
            "range": "± 2987",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/128",
            "value": 436443,
            "range": "± 1450",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/512",
            "value": 1843994,
            "range": "± 13888",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/512",
            "value": 1607428,
            "range": "± 14642",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Join/2048",
            "value": 7198556,
            "range": "± 81514",
            "unit": "ns/iter"
          },
          {
            "name": "mls_rekey/Leave/2048",
            "value": 6282418,
            "range": "± 51096",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_round_trip_correctness/full_64KiB_frame",
            "value": 1366,
            "range": "± 12",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_multi_parent_dedup/dual_parent_64KiB_frame",
            "value": 1857,
            "range": "± 75",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/1",
            "value": 762,
            "range": "± 25",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/2",
            "value": 876,
            "range": "± 17",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/3",
            "value": 1233,
            "range": "± 33",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_degraded_quality/subscribed_substreams/4",
            "value": 1474,
            "range": "± 40",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_planner_picks_distinct_parents/plan_4_substreams",
            "value": 42,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_inner_seal_4x",
            "value": 635,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_outer_seal_4x",
            "value": 315,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_dedup_observe_4x",
            "value": 13,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_aead_open_4x",
            "value": 585,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh_e2e_full_round_trip_cost_decomposition/step_reassemble_4x",
            "value": 36,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m20",
            "value": 1708,
            "range": "± 8",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m23",
            "value": 1939,
            "range": "± 5",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/decode/m26",
            "value": 709,
            "range": "± 3",
            "unit": "ns/iter"
          },
          {
            "name": "fountain_reconstruction/encode_n20_k6",
            "value": 1107,
            "range": "± 19",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail80pct_x100000",
            "value": 84514,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail85pct_x100000",
            "value": 95738,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail90pct_x100000",
            "value": 99508,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "fountain/reconstruction/avail95pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/antientropy_rounds_loss2pct_mean_x1000",
            "value": 1015,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/reassembly_delivery_ratio_loss3pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N1_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N8_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N32_x1000",
            "value": 1050,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "replication/convergence_rounds/N128_x1000",
            "value": 1025,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m1_rtt_stretch_p95_x1000",
            "value": 1000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m2_reparent_p99_ms",
            "value": 1997,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m8_continuity_first_delivery_loss5pct_x100000",
            "value": 99989,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N10",
            "value": 2,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N10",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N100",
            "value": 4,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N100",
            "value": 6,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth/N1000",
            "value": 5,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/depth_bound/N1000",
            "value": 7,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss0pct_x100000",
            "value": 100000,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss5pct_x100000",
            "value": 99988,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss10pct_x100000",
            "value": 99899,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss15pct_x100000",
            "value": 99673,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/continuity/loss20pct_x100000",
            "value": 99207,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn0pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn5pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn10pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn15pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          },
          {
            "name": "mesh/m3_heal_gap_p95/churn20pct_ms",
            "value": 100,
            "range": "± 0",
            "unit": "ns/iter"
          }
        ]
      }
    ]
  }
}