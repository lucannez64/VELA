# syntax=docker/dockerfile:1
#
# VELA server image (used by Coolify's Dockerfile build pack).
# Build context is the repository root.

# ---- web build stage: the ephemeral web vault SPA (wasm core + Vite bundle) ----
FROM rust:1-bookworm AS web
# Toolchain versions are pinned so upstream install scripts can't silently
# change what lands in the image.
ARG BUN_VERSION=1.2.19
ARG WASM_PACK_VERSION=0.13.1
# bun (JS toolchain), wasm-pack (prebuilt tarball), and the wasm target.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates unzip \
 && rm -rf /var/lib/apt/lists/* \
 && curl -fsSL https://bun.sh/install | bash -s -- "bun-v${BUN_VERSION}" \
 && curl -fsSL "https://github.com/rustwasm/wasm-pack/releases/download/v${WASM_PACK_VERSION}/wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl.tar.gz" \
      | tar -xz --strip-components=1 -C /usr/local/bin \
      "wasm-pack-v${WASM_PACK_VERSION}-x86_64-unknown-linux-musl/wasm-pack" \
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
 && apt-get install -y --no-install-recommends ca-certificates gosu \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home --shell /usr/sbin/nologin vela
COPY --from=build /src/serverVELA/target/release/vela-server /usr/local/bin/vela-server
# The built SPA, served same-origin by the server when WEB_DIR is set.
COPY --from=web /src/webVELA/dist /usr/local/share/vela-web
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
 && mkdir -p /var/lib/vela && chown vela:vela /var/lib/vela
# Production-hardened defaults for the Coolify + Cloudflare Tunnel deployment:
# - VELA_PRODUCTION enables HTTPS enforcement (satisfied by the tunnel's
#   X-Forwarded-Proto / CF-Visitor headers) and rejects wildcard CORS.
# - TRUST_PROXY_HEADERS + TRUSTED_PROXY_CIDRS cover same-host cloudflared
#   (127.0.0.1) and Coolify/Docker bridge networks, so the server resolves the
#   REAL client IP from CF-Connecting-IP / X-Forwarded-For for rate limiting —
#   the operator never shares the 127.0.0.1 bucket with an attacker.
# - The PASETO keypair auto-persists to DATA_DIR (0600), so sessions survive
#   restarts with no env var and no manual step.
# DATA_DIR points at the Coolify persistent volume mounted here at runtime.
# WEBAUTHN_RP_ID / WEBAUTHN_RP_ORIGIN / CORS_ORIGINS still come from Coolify
# environment variables (your domain); anything set there overrides these.
ENV DATA_DIR=/var/lib/vela \
    LISTEN_ADDR=0.0.0.0:8443 \
    WEB_DIR=/usr/local/share/vela-web \
    VELA_PRODUCTION=true \
    TRUST_PROXY_HEADERS=true \
    TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fd00::/8"
EXPOSE 8443
# Starts as root only to fix DATA_DIR ownership, then drops to the vela user.
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["serve"]
