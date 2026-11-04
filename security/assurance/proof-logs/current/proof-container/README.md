# Proof container (T11)

One image runs every hosted proof gate:
`security/assurance/proof-image/Dockerfile` builds it,
`.github/workflows/proof-image.yml` publishes it to
`ghcr.io/lucannez64/vela-proof` and verifies it, and
`.github/workflows/security.yml` runs its proof jobs inside it by digest.

Status: **ready for the first hosted build.** No Docker is available on this
machine or on the build box (the box is reserved for video work and its docker
daemon bypasses the resource limits), so the image has not been built or run
locally. The first GitHub-hosted run of `proof-image.yml` is the evidence for
this directory; the parent adds that run.

## What is pinned

| Input | Pin |
|---|---|
| Base image | `ubuntu:24.04@sha256:fe815609…7ef852` (manifest-list digest) |
| OS packages / Python 3.12.3 | `snapshot.ubuntu.com` stamp `20261104T000000Z` (noble + updates + security) |
| Rust | 1.99.1; hax nightly `nightly-2025-11-08` |
| hax | 0.3.7 frontend/driver, engine commit `d8b5b3d3b666fee8943a351445d2b680105e8ea3`, opam lock `security/assurance/opam-lock/hax-engine.opam.locked` |
| F* / Z3 | 2025.10.06 release (SHA-256 `940c187d…59442d`) / 4.13.3 (SHA-256 `32c7377…0a8722f`) |
| Tamarin / Maude | 1.12.0 (`201be06f…4b469c6`) / 3.5.1 (`72ed1ca8…f8f92c`) |
| ProVerif / CryptoVerif | 2.05 (opam switch `vela-proverif`) / 2.12 (`77730861…098757`) |

The Dockerfile finishes with a self-check that runs all of them and asserts the
versions, so a drifted archive fails the build. The full resolution record is
in [../env-pins/README.md](../env-pins/README.md).

The repository is not baked in: the image only carries tools, and Actions
mounts the checkout at `GITHUB_WORKSPACE`.

## Two-phase bootstrap

`security/assurance/proof-image/IMAGE` is the single switch. It currently
holds:

```
ghcr.io/lucannez64/vela-proof@sha256:PLACEHOLDER
```

- **Placeholder:** the `proof-image` job in `security.yml` outputs an empty
  image; hosted proof jobs run on the runner and install tools exactly as
  before (no behaviour change). Self-hosted `vela-box` runs always take this
  path.
- **Digest:** after `proof-image.yml` publishes the image it prints
  `ghcr.io/lucannez64/vela-proof@sha256:…` in the job summary. Copy that one
  line into `IMAGE`. From the next run, hosted `formal-rekey` and `refinement`
  jobs run with `container: { image: <digest>, credentials: GITHUB_TOKEN }`
  and skip their host install steps (`VELA_IN_PROOF_IMAGE=true`); the
  `Activate and check pinned proof tools` step stays, and now verifies the
  image's versions.

`bounded.sh` cannot run inside a job container (it needs a systemd user
manager), so those jobs set `VELA_BOUNDED=1`; the hosted runner VM is the memory
bound. This is a resource cap, not a check: every proof still runs. The
refinement job keeps its 140-minute cap and the image verification jobs use
caps of 300–360 minutes.

## What `proof-image.yml` runs

`run-all.sh --with-fstar` sequentially re-extracts and re-checks nine crates,
which does not fit the 360-minute hosted job cap, so the workflow runs the same
`run_step`s as three groups:

- `verify-symbolic`: `run-all.sh` **without** `--with-fstar` — correspondence,
  share journal (Tamarin + F* trace equivalence), network boundaries, the
  M1–M10 credential-release ladder, all thirteen Tamarin families,
  ProVerif/ORAM, statistical stash bounds;
- `verify-refinement`: a 9-way matrix running exactly the commands
  `run-all.sh` invokes for the `--with-fstar` block
  (`verify-fstar.sh` for the eight policy crates,
  `verify-share-facts-fstar.sh` for `vela-crypto`);
- `verify-boundary`: `check-proof-boundary.py` over the extractions the matrix
  regenerated — the last run_step.

Together they cover every `run_step` of `run-all.sh --with-fstar`.

## Bootstrap instructions for the parent

1. Push the branch. The `proof-image` workflow triggers on changes under
   `security/assurance/proof-image/**`, `security/assurance/opam-lock/**`,
   `security/assurance/install-hax.sh`,
   `security/assurance/install-formal-fstar.sh` and the workflow itself, or on
   `workflow_dispatch`.
2. Wait for `build` to finish, then copy the printed
   `ghcr.io/lucannez64/vela-proof@sha256:…` line from the job summary into
   `security/assurance/proof-image/IMAGE` and commit.
3. The first run with the real digest proves the container path; its logs belong
   in this directory.

## Limits

- The image digest pins the *output* of the build. The build itself fetches
  rustup from `sh.rustup.rs` (no released installer hash is pinned) and
  opam metadata from opam-repository HEAD; the toolchains and package versions
  it selects are exact, but those two index fetches are not content-pinned.
  Everything with a published archive is SHA-256 verified.
- `opam`'s GTK2 dependency, `nodejs` (hax engine depext) and the Python
  interpreter come from the same fixed Ubuntu snapshot; a snapshot bump is a
  deliberate, reviewable change (checker-enforced).
- `static-scan`, `regression` and `sharing-boundaries` stay on the host: they
  are not proof jobs, and `static-scan` still needs live advisory data
  (cargo-audit). Their scanners and Rust are pinned, their apt packages come
  from the same snapshot.
