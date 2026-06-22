# syntax=docker/dockerfile:1
#
# VELA server image (used by Coolify's Dockerfile build pack).
# Build context is the repository root.

# ---- web build stage: the ephemeral web vault SPA (wasm core + Vite bundle) ----
FROM rust:1-bookworm AS web
# bun (JS toolchain), wasm-pack (prebuilt installer), and the wasm target.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://bun.sh/install | bash \
 && curl -fsSL https://rustwasm.github.io/wasm-pack/installer/init.sh | sh \
 && rustup target add wasm32-unknown-unknown
ENV PATH="/root/.bun/bin:${PATH}"
WORKDIR /src
# vela-wasm-bridge depends on vela-crypto + vela-core.
COPY libVELA/vela-crypto/ libVELA/vela-crypto/
COPY libVELA/vela-core/ libVELA/vela-core/
COPY libVELA/vela-wasm-bridge/ libVELA/vela-wasm-bridge/
COPY webVELA/ webVELA/
WORKDIR /src/webVELA
RUN bun install --frozen-lockfile && bun run build:all

# ---- server build stage ----
FROM rust:1-bookworm AS build
WORKDIR /src
# Copy only what the server workspace needs, preserving the relative layout that
# vela-server's Cargo.toml expects: vela-crypto = { path = "../../libVELA/vela-crypto" }.
# (libVELA/cyclo — the Zig crate — is intentionally NOT copied; the server doesn't use it.)
COPY serverVELA/ serverVELA/
COPY libVELA/vela-crypto/ libVELA/vela-crypto/
WORKDIR /src/serverVELA
# The workspace release profile uses fat LTO + codegen-units=1, whose final link
# can need >2 GB — too much for small home servers. Relax it for the container
# build (negligible runtime impact for this workload). Override via build args on
# a bigger builder to restore fat LTO.
ARG CARGO_PROFILE_RELEASE_LTO=false
ARG CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
ENV CARGO_PROFILE_RELEASE_LTO=${CARGO_PROFILE_RELEASE_LTO} \
    CARGO_PROFILE_RELEASE_CODEGEN_UNITS=${CARGO_PROFILE_RELEASE_CODEGEN_UNITS}
RUN cargo build --release -p vela-server

# ---- runtime stage ----
FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/serverVELA/target/release/vela-server /usr/local/bin/vela-server
# The built SPA, served same-origin by the server when WEB_DIR is set.
COPY --from=web /src/webVELA/dist /usr/local/share/vela-web
# DATA_DIR points at the Coolify persistent volume mounted here at runtime.
# Override LISTEN_ADDR/PASETO_SECRET_KEY/WEBAUTHN_* via Coolify environment variables.
ENV DATA_DIR=/var/lib/vela \
    LISTEN_ADDR=0.0.0.0:8443 \
    WEB_DIR=/usr/local/share/vela-web
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/vela-server"]
CMD ["serve"]
