# Proof container (T11)

One image runs every hosted proof gate:
`security/assurance/proof-image/Dockerfile` builds it,
`.github/workflows/proof-image.yml` publishes it to
`ghcr.io/lucannez64/vela-proof` and verifies it, and
`.github/workflows/security.yml` runs its proof jobs inside it by digest.

Status: **built, verified and in use**, confirmed 2026-11-06. The image
`ghcr.io/lucannez64/vela-proof@sha256:8c1e20caa5272e464edbf27b021efe0eaa402968421379a090b28e6f7776717b`
was built and verified by [proof-image run 42032364244](https://github.com/lucannez64/VELA/actions/runs/42032364244)
(commit `bf25cff894b5744bcc1d416b9f53f7a61ce2b5ad`). It is the digest in
`security/assurance/proof-image/IMAGE`, pinned by commit `6ab8055c`.
No Docker is used on the build box; the image evidence is GitHub-hosted.

## Hosted evidence: run-all.sh inside the image

[Proof-image run 42032364244](https://github.com/lucannez64/VELA/actions/runs/42032364244)
ran every `run-all.sh --with-fstar` step inside that digest, split into the
symbolic job, nine refinement jobs and the boundary audit. All passed:

| Job | What ran | Result | Time (UTC, 2026-11-05) |
|---|---|---|---|
| `verify-symbolic` | `run-all.sh` without `--with-fstar`: correspondence, share journal, network boundaries, credential-release ladder, Tamarin families, ProVerif ORAM and statistical stash bounds | success | 15:11-15:17 |
| `verify-refinement` x9 | The nine hax/F* commands from `run-all.sh --with-fstar`, each re-extracted and checked | 9/9 success | 15:11-16:18 |
| `verify-boundary` | Assumption/postcondition audit over the freshly regenerated extractions | success | 16:18-16:20 |

The [recorded run metadata](proof-image-run.json) retains each job's URL,
commit, timestamps and conclusion.

[Security run 42150774184](https://github.com/lucannez64/VELA/actions/runs/42150774184)
on `7c171abea420526cfa9d2a2d4d0cc2662a2e8ff5` passed, and the PR reported
all 38 checks passing. Its hosted `formal-rekey` job used the pinned image,
passed the bounded handler/database conformance tests and ran `run-all.sh`;
the hosted sharing and differential-model jobs also use the image.
Self-hosted refinement jobs retain their pinned host tools and shared cache.
See the [security run metadata](security-run.json) and
[formal job steps](hosted-formal-job.json).

The 57-job seed-stability evidence has its own recorded image and provenance
in [proof-stability](../proof-stability/README.md); it is not relabeled as a
run on this newer digest.

The hosted integration fixes included executable permission for the F* cache
launcher, a root-independent audit-failure test, upload retries, named and
bounded conformance steps, independent-trace store resets, and explicit
ordinary-temporary-directory storage for sled test databases (its default
Linux `/dev/shm` path exhausted the container's shared-memory filesystem).
The final green run includes these fixes. Production store opening is unchanged.

### Fixes needed to get there

| Build/run | Failure | Fix |
|---|---|---|
| 41943723974 | opam could not fetch hax-engine: `rsync` missing | `69f7749`: add rsync, patch, m4, bzip2 |
| 41948766236, 41952554034 (first try) | `snapshot.ubuntu.com` 5xx; apt ignored missing indexes | `d0a819d`, `15fc14f`: `--error-on=any` and up to six retries |
| 41952554034 | job containers run steps with `sh`: `set -o pipefail` failed | `72b5d52`: `defaults.run.shell: bash -e {0}` in container jobs |
| 41965442045 | `-fuse-ld=lld` from `.cargo/config.toml`; no `lld` | `7fcc698`: add `lld` (new digest `6b2d4dff…`) |
| stability 41974975299 | git refused the container's workspace (other owner) | `a1a38c8`: `GIT_CONFIG_*` = `safe.directory=*` |

`proof-image.yml` no longer rebuilds when only `IMAGE` or this README's
sibling `proof-image/README.md` changes (a rebuild yields a new digest), and a
`workflow_dispatch` `digest` input verifies a published image as is.

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

`security/assurance/proof-image/IMAGE` is the single switch. It now holds
the digest above; before the first build it held a placeholder:

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
- `static-scan` and `regression` stay on the host; `static-scan` still needs
  live advisory data (cargo-audit). Hosted `sharing-boundaries` uses the image.
  The scanners and Rust are pinned, and hosted apt fallback packages come from
  the same snapshot.
