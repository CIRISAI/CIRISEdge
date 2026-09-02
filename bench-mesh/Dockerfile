# syntax=docker/dockerfile:1.7
#
# The mesh-harness image: one `edge_node` binary plus one deterministic
# encoded video file. Every container in `compose.yaml` runs this image;
# what differs between them is the environment and the volumes.
#
# Two things this Dockerfile is careful about:
#
#   1. **Cache.** `ciris-edge` pulls openmls + libcrux + leviculum +
#      persist from git; a cold build is tens of minutes. Cargo's
#      registry, git checkouts, and `target/` are all mounted as BuildKit
#      caches, so a warm rebuild after an edit to `src/bin/edge_node.rs`
#      relinks the binary rather than rebuilding the dependency graph.
#      Without this the edit-run loop is unusable.
#
#      Two things to know. `COPY . /src` preserves source mtimes, which
#      is what keeps cargo's fingerprints valid across builds — if that
#      ever stops holding, every build becomes a cold one. And the
#      `target/` mount is `sharing=locked`, so a build killed mid-flight
#      can leave the next one recompiling from scratch; `docker buildx
#      prune` if a "warm" rebuild is inexplicably slow.
#
#   2. **Determinism of the media.** The video is generated at IMAGE BUILD
#      time from ffmpeg's synthetic `testsrc` with fixed duration, fixed
#      size, fixed rate, and fixed encoder settings, so the same
#      Dockerfile produces the same bytes and run-to-run numbers are
#      comparable. Nothing large or license-encumbered enters the repo.

# ─── Stage 1: the media ─────────────────────────────────────────────
FROM debian:bookworm-slim AS media

RUN apt-get update \
 && apt-get install -y --no-install-recommends ffmpeg ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ARG MEDIA_SECONDS=8
ARG MEDIA_SIZE=320x240
ARG MEDIA_FPS=15

# `-preset ultrafast -tune zerolatency -g 15` keeps the encode cheap and
# the GOP short, so a mid-stream epoch advance lands near an IDR rather
# than deep inside a long GOP. `-bf 0` removes B-frames so access units
# come out in decode order — the harness ships them in sequence.
#
# `-fflags +bitexact -flags +bitexact` and the fixed `-sws_flags` pin the
# encoder's non-deterministic knobs; the SHA-256 is printed at build time
# so a media change is visible in the build log rather than silently
# moving every latency number.
RUN set -eux; \
    ffmpeg -hide_banner -loglevel error -nostdin \
      -f lavfi -i "testsrc=duration=${MEDIA_SECONDS}:size=${MEDIA_SIZE}:rate=${MEDIA_FPS}" \
      -c:v libx264 -preset ultrafast -tune zerolatency \
      -pix_fmt yuv420p -g "${MEDIA_FPS}" -bf 0 -crf 26 \
      -fflags +bitexact -flags +bitexact -sws_flags bitexact \
      -f h264 /media/testsrc.h264 2>/dev/null \
    || { mkdir -p /media; ffmpeg -hide_banner -loglevel error -nostdin \
      -f lavfi -i "testsrc=duration=${MEDIA_SECONDS}:size=${MEDIA_SIZE}:rate=${MEDIA_FPS}" \
      -c:v libx264 -preset ultrafast -tune zerolatency \
      -pix_fmt yuv420p -g "${MEDIA_FPS}" -bf 0 -crf 26 \
      -fflags +bitexact -flags +bitexact -sws_flags bitexact \
      -f h264 /media/testsrc.h264; }; \
    ls -l /media/testsrc.h264; \
    sha256sum /media/testsrc.h264 | tee /media/testsrc.h264.sha256

# ─── Stage 2: build ─────────────────────────────────────────────────
FROM rust:1.97-bookworm AS build

# `libsqlite3-dev` — persist links the system libsqlite3 dynamically
# (CIRISPersist#132/#133); building without it fails at link time.
# `cmake`/`clang` are libcrux's build-time requirements for the X-Wing
# ciphersuite provider.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      libsqlite3-dev pkg-config cmake clang git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# The whole crate: `edge_node` is a `[[bin]]` inside it, and `build.rs`
# runs uniffi over `udl/`, so a dependency-only pre-build layer would
# have to reproduce the manifest exactly. The BuildKit caches below make
# the incremental case fast without that fragility.
COPY . /src

ARG FEATURES="transport-reticulum,mesh-harness"
ARG PROFILE=release

RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/src/target,sharing=locked \
    set -eux; \
    cargo build --profile "${PROFILE}" --features "${FEATURES}" --bin edge_node; \
    install -Dm0755 "/src/target/${PROFILE}/edge_node" /out/edge_node

# ─── Stage 3: runtime ───────────────────────────────────────────────
FROM debian:bookworm-slim AS runtime

# Runtime needs only libsqlite3 (dynamically linked, above) and CA certs.
# No ffmpeg, no toolchain — the media is copied in already encoded.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libsqlite3-0 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --create-home --uid 10001 edge

COPY --from=build /out/edge_node /usr/local/bin/edge_node
COPY --from=media /media/testsrc.h264 /media/testsrc.h264
COPY --from=media /media/testsrc.h264.sha256 /media/testsrc.h264.sha256

# `/state` is the container's PRIVATE volume: its federation seed, its
# leviculum transport identity, its sealed KV. `/mesh` is the SHARED
# volume and carries public bootstrap data only.
RUN mkdir -p /state /mesh /results && chown -R edge:edge /state /mesh /results
USER edge

ENV EDGE_MEDIA=/media/testsrc.h264 \
    EDGE_STATE_DIR=/state \
    EDGE_MESH_DIR=/mesh \
    EDGE_RESULTS=/results/mesh.jsonl \
    RUST_BACKTRACE=1

ENTRYPOINT ["/usr/local/bin/edge_node"]
