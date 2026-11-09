# syntax=docker/dockerfile:1.4
#
# Multi-stage build for NORA artifact registry.
# Compiles inside Alpine — musl version always matches runtime.
#
# Usage:
#   docker build .                                             # Alpine (default)
#   docker buildx build --target binary --output type=local,dest=out .      # amd64 binary
#   docker buildx build --target binary-arm64 --output type=local,dest=out .  # arm64 binary (cross-compiled)
#

# ── Build ──────────────────────────────────────────────────────────────────
FROM packages.maestra.io/docker-hub/library/rust:1-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS builder

# apk through nora (packages.maestra.io, 3-day hold, issues-maestra#1649): BuildKit secret
# PRIVATE_PACKAGES_TOKEN (CI: a fresh OIDC token; local: an nra_ token,
# docker build --secret id=PRIVATE_PACKAGES_TOKEN,env=PRIVATE_PACKAGES_TOKEN .).
RUN --mount=type=secret,id=PRIVATE_PACKAGES_TOKEN,required=true --mount=type=bind,from=public.ecr.aws/g5f9s8a4/nora-apk:1.0.0@sha256:55df38687c301e6fefa230dc1c71a8841618214cc549ade71be740b25822a00e,target=/nora-apk \
    /nora-apk/nora-apk add --no-cache musl-dev

WORKDIR /build

# Pin the build toolchain: rustup reads rust-toolchain.toml and installs the
# exact channel, so the release binary is reproducible regardless of the base
# image's bundled rustc.
COPY rust-toolchain.toml ./
COPY Cargo.toml Cargo.lock ./
COPY nora-registry/ nora-registry/
# The fuzz member's manifest and targets (not its corpus, see .dockerignore) keep
# the workspace intact so --locked holds; `-p nora-registry` never builds them.
COPY fuzz/ fuzz/

# CARGO_FEATURES: extra cargo args, e.g. "--no-default-features --features mimalloc"
# drops the rpm and deb registries (and their rpgp signer) but keeps the allocator.
# A production binary must carry mimalloc: the static musl build otherwise serialises
# every allocation on one lock (perf: native_queued_spin_lock_slowpath, 12.10 and
# 16-19.10.2026). The grep below fails the build when the feature got dropped.
# The binary shipped carries no fault injection route (`/__fi/`, src/fault_injection.rs),
# whatever features or build inputs this build was given: grep refuses it.
ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked -p nora-registry $CARGO_FEATURES && \
    cp target/release/nora /nora && \
    strip /nora && \
    (grep -a -q mimalloc /nora || { echo 'nora built without mimalloc (add --features mimalloc)' >&2; exit 1; }) && \
    ! grep -qF '/__fi/' /nora

# ── Binary export (for CI release artifacts) ───────────────────────────────
FROM scratch AS binary
COPY --from=builder /nora /nora

# ── Cross-compile arm64 (runs natively on x86, no QEMU) ──────────────────
FROM packages.maestra.io/docker-hub/library/rust:1-alpine3.23@sha256:42c2519fdf75d9e34cc61a1aaf34b1a684da9bfd65fe5daefef98d92a801b001 AS cross-arm64

RUN --mount=type=secret,id=PRIVATE_PACKAGES_TOKEN,required=true --mount=type=bind,from=public.ecr.aws/g5f9s8a4/nora-apk:1.0.0@sha256:55df38687c301e6fefa230dc1c71a8841618214cc549ade71be740b25822a00e,target=/nora-apk \
    /nora-apk/nora-apk add --no-cache musl-dev \
    && wget -qO- https://musl.cc/aarch64-linux-musl-cross.tgz | tar xz -C /opt

ENV PATH="/opt/aarch64-linux-musl-cross/bin:$PATH" \
    CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc

WORKDIR /build
# Pin the toolchain before adding the cross target so the target lands on the
# pinned channel (rust-toolchain.toml), keeping the arm64 build reproducible.
COPY rust-toolchain.toml ./
RUN rustup target add aarch64-unknown-linux-musl

COPY Cargo.toml Cargo.lock ./
COPY nora-registry/ nora-registry/
COPY fuzz/ fuzz/

# As for amd64: no fault injection route in the binary shipped.
ARG CARGO_FEATURES=""
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/build/target \
    cargo build --release --locked --target aarch64-unknown-linux-musl -p nora-registry $CARGO_FEATURES && \
    cp target/aarch64-unknown-linux-musl/release/nora /nora && \
    aarch64-linux-musl-strip /nora && \
    (grep -a -q mimalloc /nora || { echo 'nora built without mimalloc (add --features mimalloc)' >&2; exit 1; }) && \
    ! grep -qF '/__fi/' /nora

FROM scratch AS binary-arm64
COPY --from=cross-arm64 /nora /nora

# ── Alpine (default — must be last) ───────────────────────────────────────
FROM packages.maestra.io/docker-hub/library/alpine:3.23@sha256:85fe1e81d6758c208f3e1eed4338a1997e19d4be002d4dd32d3100c9a8c010a0

# apk through nora (packages.maestra.io, 3-day hold, issues-maestra#1649): BuildKit secret
# PRIVATE_PACKAGES_TOKEN (CI: a fresh OIDC token; local: an nra_ token,
# docker build --secret id=PRIVATE_PACKAGES_TOKEN,env=PRIVATE_PACKAGES_TOKEN .).
RUN --mount=type=secret,id=PRIVATE_PACKAGES_TOKEN,required=true --mount=type=bind,from=public.ecr.aws/g5f9s8a4/nora-apk:1.0.0@sha256:55df38687c301e6fefa230dc1c71a8841618214cc549ade71be740b25822a00e,target=/nora-apk \
    /nora-apk/nora-apk upgrade --no-cache \
    && /nora-apk/nora-apk add --no-cache ca-certificates \
    && addgroup -S nora && adduser -S -G nora nora \
    && mkdir -p /data && chown nora:nora /data

COPY --from=builder --chown=nora:nora /nora /usr/local/bin/nora

ENV RUST_LOG=info \
    NORA_HOST=:: \
    NORA_CONFIG_PATH=/etc/nora/config.toml

# Config *values* ship as a FILE, not ENV: env has the highest precedence in
# Config::load and would silently override a user-provided config.toml (#719).
# Only NORA_HOST stays in ENV — binding must survive a bind-mounted (possibly
# partial) config.toml so the container stays reachable (-e NORA_HOST to change).
COPY --chown=nora:nora deploy/config.docker.toml /etc/nora/config.toml

EXPOSE 4000
VOLUME ["/data"]
USER nora

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["/usr/local/bin/nora", "healthcheck"]

ENTRYPOINT ["/usr/local/bin/nora"]
CMD ["serve"]
