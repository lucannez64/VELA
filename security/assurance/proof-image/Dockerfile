# syntax=docker/dockerfile:1
#
# VELA proof container (assurance T11).
#
# One image carries every symbolic, computational and refinement tool the
# assurance gates need, so a hosted GitHub job runs the same binaries whether
# or not it can install anything from the network:
#
#   Tamarin 1.12.0, Maude 3.5.1, ProVerif 2.05, CryptoVerif 2.12,
#   hax 0.3.7 (frontend/driver/engine, with the frozen opam resolution),
#   F* 2025.10.06, Z3 4.13.3, Rust 1.99.1 and nightly-2025-11-08,
#   Python 3.12.3 (Ubuntu 24.04).
#
# The repository is NOT baked in: mount or check it out at run time
# (GITHUB_WORKSPACE in Actions, `-v "$PWD:/workspace"` with docker run).
# See README.md in this directory.
#
# Base image and OS packages are pinned:
#   - ubuntu:24.04 by manifest-list digest;
#   - every apt package from the immutable 2026-11-04T00:00:00Z snapshot
#     (security/assurance/proof-image/apt-snapshot.conf).
# Tool archives are checksum-pinned where the installer supports it
# (Tamarin, Maude, F*, Z3, CryptoVerif); hax is a pinned git commit.

FROM ubuntu:24.04@sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852

LABEL org.opencontainers.image.title="vela-proof" \
      org.opencontainers.image.description="Pinned VELA assurance proof toolchain" \
      org.opencontainers.image.source="https://github.com/lucannez64/VELA" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

# ── OS packages, from the fixed Ubuntu snapshot ─────────────────────────────
# The snapshot stamp must match security/assurance/proof-image/apt-snapshot.conf
# (check-env-pins.py compares them). --no-install-recommends keeps the package
# set minimal and deterministic. Versions are pinned by the immutable snapshot
# date, not by `=` pins that would break as soon as the archive rotates (see
# apt-snapshot.conf).
# Bootstrap: the bare base image has no CA certificates, and snapshot.ubuntu.com
# redirects http to https. This one step skips TLS peer checks; apt still
# verifies the signed InRelease (Signed-By) and every package hash, and it
# installs ca-certificates from the same snapshot, so later steps verify TLS.
# hadolint ignore=DL3008
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources \
 && printf '%s\n' \
      'Types: deb' \
      'URIs: https://snapshot.ubuntu.com/ubuntu/20261104T000000Z/' \
      'Suites: noble noble-updates noble-security' \
      'Components: main restricted universe multiverse' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/vela-snapshot.sources \
 && apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false -o Acquire::Check-Valid-Until=false -o Acquire::Retries=3 update \
 && DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::https::Verify-Peer=false -o Acquire::https::Verify-Host=false install -y --no-install-recommends \
      build-essential \
      ca-certificates \
      clang \
      curl \
      diffutils \
      file \
      git \
      jq \
      libgmp-dev \
      libgmp10 \
      libgtk2.0-dev \
      libssl-dev \
      nodejs \
      opam \
      pkg-config \
      python3 \
      python3-pip \
      ripgrep \
      unzip \
      wget \
      xz-utils \
 && rm -rf /var/lib/apt/lists/*

# Python is pinned by the snapshot: Ubuntu 24.04 ships 3.12.3. Fail loudly if a
# future snapshot bump changes the interpreter under the proof runners.
RUN test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.12.3" \
 && python3 --version

# ── Tamarin 1.12.0 and Maude 3.5.1 (same archives and hashes as CI) ─────────
# hadolint ignore=SC2016
RUN curl -fL --retry 3 --connect-timeout 30 -o /tmp/tamarin.tar.gz \
      https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz \
 && echo "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6  /tmp/tamarin.tar.gz" | sha256sum -c \
 && tar -xzf /tmp/tamarin.tar.gz -C /usr/local/bin \
 && curl -fL --retry 3 --connect-timeout 30 -o /tmp/maude.zip \
      https://github.com/maude-lang/Maude/releases/download/Maude3.5.1/Maude-3.5.1-linux-x86_64.zip \
 && echo "72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c  /tmp/maude.zip" | sha256sum -c \
 && mkdir -p /opt/maude-3.5.1 \
 && unzip -oq /tmp/maude.zip -d /opt/maude-3.5.1 \
 && chmod +x /opt/maude-3.5.1/maude \
 && printf '%s\n' '#!/bin/sh' 'export MAUDE_LIB=/opt/maude-3.5.1' 'exec "$MAUDE_LIB/maude" "$@"' > /usr/local/bin/maude \
 && chmod +x /usr/local/bin/maude \
 && rm -f /tmp/tamarin.tar.gz /tmp/maude.zip \
 && { tamarin-prover --version 2>&1 | tee /tmp/tamarin-version.txt || true; } \
 && rg -q 'tamarin-prover 1\.12\.0' /tmp/tamarin-version.txt \
 && ! rg -q 'WARNING:|unsupported' /tmp/tamarin-version.txt \
 && maude --version

# ── Rust 1.99.1 and the hax nightly ─────────────────────────────────────────
# rustup itself is fetched from the official endpoint; the toolchains it
# installs are exact versions (1.99.1 and nightly-2025-11-08, the same pins
# dtolnay/rust-toolchain and install-hax.sh use). The published image digest
# freezes the result.
# PATH must hold /opt/cargo/bin before the install step checks rustc.
# opam runs as root in the image build: OPAMROOTISOK/OPAMYES keep it
# non-interactive (sandboxing is already disabled by the installers).
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    CARGO_INCREMENTAL=0 \
    OPAMROOTISOK=1 \
    OPAMYES=1 \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --profile minimal --default-toolchain 1.99.1 --no-modify-path \
 && rustc --version \
 && rustc --version | grep -Eq '^rustc 1\.99\.1 '

# ── hax 0.3.7 frontend/driver/engine with the frozen opam resolution ────────
# Only the two files the installer needs are copied; the repository stays out
# of the image and is mounted at run time.
COPY security/assurance/install-hax.sh /build/security/assurance/install-hax.sh
COPY security/assurance/opam-lock/hax-engine.opam.locked /build/security/assurance/opam-lock/hax-engine.opam.locked
RUN chmod +x /build/security/assurance/install-hax.sh \
 && VELA_HAX_ROOT=/opt/vela-hax-0.3.7 /build/security/assurance/install-hax.sh \
 && rm -rf /build

# ── F* 2025.10.06 with its bundled Z3 4.13.3 (journal correspondence) ───────
COPY security/assurance/install-formal-fstar.sh /build/security/assurance/install-formal-fstar.sh
RUN chmod +x /build/security/assurance/install-formal-fstar.sh \
 && /build/security/assurance/install-formal-fstar.sh /opt/vela-formal-fstar-2025.10.06 \
 && rm -rf /build

# ── Runtime environment ─────────────────────────────────────────────────────
# VELA_PROOF_TOOLS / OPAMROOT are the paths .github/workflows/security.yml
# activates for the refinement matrix; VELA_FSTAR_BIN is what the symbolic
# runners read; CRYPTOVERIF_BIN replaces the host build path.
ENV VELA_HAX_ROOT=/opt/vela-hax-0.3.7 \
    VELA_PROOF_TOOLS=/opt/vela-hax-0.3.7 \
    OPAMROOT=/opt/vela-hax-0.3.7/opam \
    VELA_FSTAR_BIN=/opt/vela-formal-fstar-2025.10.06/fstar/bin/fstar.exe \
    CRYPTOVERIF_BIN=/opt/cryptoverif/cryptoverif2.12/cryptoverif \
    MAUDE_LIB=/opt/maude-3.5.1 \
    LC_ALL=C.UTF-8 \
    LANG=C.UTF-8
ENV PATH=/opt/vela-hax-0.3.7/bin:/opt/vela-hax-0.3.7/opam/vela-hax/bin:/opt/vela-hax-0.3.7/opam/vela-proverif/bin:/opt/vela-hax-0.3.7/fstar/bin:/opt/vela-formal-fstar-2025.10.06/fstar/bin:/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# ── ProVerif 2.05 in its pinned OCaml 5.1.1 switch ──────────────────────────
RUN opam init --bare --disable-sandboxing --no-setup --yes \
 && opam switch create vela-proverif ocaml-base-compiler.5.1.1 --yes \
 && opam install --switch vela-proverif --yes proverif.2.05 \
 && opam list --switch vela-proverif --installed proverif \
 && opam clean --all-switches --yes

# ── CryptoVerif 2.12 (hybrid KEM computational gate) ────────────────────────
RUN curl -fL --retry 3 --connect-timeout 30 -o /tmp/cryptoverif.tar.gz \
      https://bblanche.gitlabpages.inria.fr/CryptoVerif/cryptoverif2.12.tar.gz \
 && echo "77730861be7bfbde5b078f7785db478869d33aba2761a428d50aaad537098757  /tmp/cryptoverif.tar.gz" | sha256sum -c \
 && mkdir -p /opt/cryptoverif \
 && tar -xzf /tmp/cryptoverif.tar.gz -C /opt/cryptoverif \
 && rm -f /tmp/cryptoverif.tar.gz

WORKDIR /opt/cryptoverif/cryptoverif2.12
RUN ./build

# ── Self-check: every tool run-all.sh names, at the pinned version ──────────
RUN set -eux; \
    { tamarin-prover --version 2>&1 || true; } | rg -q 'tamarin-prover 1\.12\.0'; \
    maude --version; \
    proverif -help 2>&1 | grep -Eiq 'proverif 2\.05'; \
    test -x "$CRYPTOVERIF_BIN"; \
    test -f /opt/cryptoverif/cryptoverif2.12/default.ocvl; \
    "$CRYPTOVERIF_BIN" -version || true; \
    fstar.exe --version; \
    z3-4.13.3 --version | grep -F 'Z3 version 4.13.3'; \
    cargo --version; \
    rustc --version | grep -Eq '^rustc 1\.99\.1 '; \
    rustc +nightly-2025-11-08 --version; \
    cargo hax --version | grep -Fx 'version=0.3.7'; \
    command -v cargo-hax driver-hax-frontend-exporter hax-engine jq rg python3; \
    test -x "$OPAMROOT/vela-hax/bin/hax-engine"; \
    test "$(opam list --switch vela-hax --installed --columns=version --short hax-engine)" = 0.3.7; \
    test "$(cat /opt/vela-formal-fstar-2025.10.06/fstar/version.txt)" = 2025.10.06

WORKDIR /workspace
CMD ["/bin/bash"]
