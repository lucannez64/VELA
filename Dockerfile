# syntax=docker/dockerfile:1
#
# VELA server image (used by Coolify's Dockerfile build pack).
# Build context is the repository root.

# ---- build stage ----
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
# DATA_DIR points at the Coolify persistent volume mounted here at runtime.
# Override LISTEN_ADDR/PASETO_SECRET_KEY/WEBAUTHN_* via Coolify environment variables.
ENV DATA_DIR=/var/lib/vela \
    LISTEN_ADDR=0.0.0.0:8443
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/vela-server"]
CMD ["serve"]
