# VELA proof container

One image, one pinned toolchain, for every machine-checked assurance gate:
`.github/workflows/security.yml` runs its hosted proof jobs inside it, and
`.github/workflows/proof-image.yml` builds it and re-runs `run-all.sh` in it.

The repository is **not** baked into the image. The container only carries the
tools; the checkout is mounted at run time (`GITHUB_WORKSPACE` in Actions,
`-v "$PWD:/workspace"` with `docker run`).

## Contents and pins

| Input | Pin | How it is pinned |
|---|---|---|
| Base image | `ubuntu:24.04` | manifest-list digest `sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |
| OS packages, Python 3.12.3 | noble + noble-updates + noble-security | immutable `snapshot.ubuntu.com` stamp `20261104T000000Z` (`apt-snapshot.conf`) |
| Rust (tests, run-all.sh) | 1.99.1 | rustup toolchain name; `rustc --version` asserted at build |
| Rust for hax | nightly-2025-11-08 | rustup toolchain name (same pin as the crate `rust-toolchain.toml` files) |
| hax frontend/driver | 0.3.7 | `cargo install … --locked` in `security/assurance/install-hax.sh` |
| hax engine | 0.3.7, hax commit `d8b5b3d3b666fee8943a351445d2b680105e8ea3` | pinned checkout + `opam install --locked` with `security/assurance/opam-lock/hax-engine.opam.locked` |
| F* | 2025.10.06 | official release archive, SHA-256 `940c187d…59442d` |
| Z3 | 4.13.3 | official archive, SHA-256 `32c7377…0a8722f` |
| Tamarin | 1.12.0 | release archive, SHA-256 `201be06f…4b469c6` |
| Maude | 3.5.1 | release archive, SHA-256 `72ed1ca8…f8f92c` |
| ProVerif | 2.05 | `opam install --switch vela-proverif proverif.2.05` |
| CryptoVerif | 2.12 | release archive, SHA-256 `77730861…098757` |
| Python | 3.12.3 | snapshot apt package; `platform.python_version()` asserted at build |

The Dockerfile itself ends with a self-check that runs every one of those tools
and re-asserts the exact versions, so a drifted base or archive fails the build
instead of silently changing a proof.

`security/assurance/check-env-pins.py` enforces the pins this file describes:
workflow `uses:` SHAs, fixed runner labels, exact tool versions, the apt
snapshot stamp (workflow and Dockerfile must match `apt-snapshot.conf`), the
single-line image reference, and the opam lock.

## Two-phase bootstrap

`security/assurance/proof-image/IMAGE` holds exactly one line, the image
reference by digest:

```
ghcr.io/lucannez64/vela-proof@sha256:<64 hex>
```

A tiny `proof-image` job in `security.yml` reads it. Hosted proof jobs then run
with `container: { image: <that reference> }`, and skip their host tool
installs (`VELA_IN_PROOF_IMAGE=true`). That reference does not exist until the
first build, so the file ships with a placeholder:

```
ghcr.io/lucannez64/vela-proof@sha256:PLACEHOLDER
```

While the placeholder is in place the same jobs run on the host and install the
tools exactly as before — the pre-T11 behaviour, unchanged. Self-hosted
`vela-box` runners always take the host path: they are not assumed to support
docker containers, and the `proof-image` job outputs an empty image for them.
An empty container image means "no job container" (actions/runner#2235).

Phase 1: push to `security/assurance/proof-image/**` (or the opam lock /
installers), or run `workflow_dispatch`. `proof-image.yml` publishes
`ghcr.io/lucannez64/vela-proof:<git sha>`, prints the digest in the job
summary, and runs `run-all.sh` inside that digest.

Phase 2: copy the printed `ghcr.io/lucannez64/vela-proof@sha256:…` line into
`IMAGE` and commit. From the next run on, hosted proof jobs use the image.

Operational note: make the `vela-proof` GHCR package public. Pull requests
from forks get a read-only `GITHUB_TOKEN`; a private package would make their
hosted proof jobs fail at container start.

Moving the pin later is the same edit; keep the tag for the git sha that last
built it.

## Pulling and running by hand

```bash
# The reference from IMAGE (or the job summary of a proof-image run).
img=$(cat security/assurance/proof-image/IMAGE)

# Log in if the package is private (GITHUB_TOKEN with packages:read works in
# Actions; locally use a PAT with read:packages).
docker login ghcr.io

# Symbolic + computational gates, repo mounted read-only.
docker run --rm -v "$PWD:/workspace" -w /workspace \
  -e VELA_BOUNDED=1 -e VELA_CARGO_JOBS=4 \
  "$img" security/assurance/run-all.sh --out /tmp/assurance-logs

# hax/F* gates, one crate per container (this is what the matrix does).
docker run --rm -v "$PWD:/workspace" -w /workspace \
  -e VELA_BOUNDED=1 -e VELA_CARGO_JOBS=4 \
  "$img" serverVELA/vela-session-policy/verify-fstar.sh
```

`VELA_BOUNDED=1` is required inside the container: `security/assurance/bounded.sh`
needs a systemd user manager, which a job container does not have. The hosted
runner's own memory bound applies instead. This is a resource cap, not a check:
every proof step still runs.

## Why `proof-image.yml` splits `run-all.sh --with-fstar`

`run-all.sh --with-fstar` re-extracts and re-checks nine crates sequentially,
which does not fit the 360-minute hosted job cap. The workflow therefore runs:

- `verify-symbolic`: `run-all.sh` (no `--with-fstar`), i.e. correspondence, the
  share journal, network boundaries, the M1-M10 credential-release ladder, all
  thirteen Tamarin families, ProVerif/ORAM and the statistical stash bounds;
- `verify-refinement`: one matrix job per F* run_step, running the same
  `verify-fstar.sh` / `verify-share-facts-fstar.sh` commands `run-all.sh`
  invokes;
- `verify-boundary`: `check-proof-boundary.py` over the regenerated
  extractions, the last run_step.

Together they cover every `run_step` of `run-all.sh --with-fstar`.

## Rebuilding

```bash
docker build -f security/assurance/proof-image/Dockerfile \
  -t ghcr.io/lucannez64/vela-proof:local .
```

To move a pin: update `apt-snapshot.conf` *and* the snapshot URL in the
Dockerfile *and* the three host-fallback copies in `security.yml` (the checker
fails until they agree), then rebuild and update `IMAGE` with the new digest.
