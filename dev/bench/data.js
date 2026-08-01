window.BENCHMARK_DATA = {
  "lastUpdate": 1785556926124,
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
      }
    ]
  }
}