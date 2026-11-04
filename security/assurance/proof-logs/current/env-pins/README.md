# Environment pins (T10)

Every pin below was resolved from a live source on 2026-11-04, not copied from
memory. `security/assurance/check-env-pins.py` enforces the parts that can be
checked statically; this file records how each value was obtained and what the
pin does and does not cover.

Run the checker at any time:

```
python3 -I security/assurance/check-env-pins.py
```

## GitHub Actions

Every `uses:` line in `.github/workflows/*.yml` (101 in the final tree: 87
rewritten in the eleven pre-existing workflows, one new `checkout` in
`security.yml`, one that was already pinned, and 12 in the new
`proof-image.yml`) names a full commit SHA plus a version comment. Each SHA
came from
`gh api repos/<owner>/<repo>/git/ref/tags/<tag>`; when the ref object was an
annotated tag it was dereferenced with
`gh api repos/<owner>/<repo>/git/tags/<sha>`. The version comment is the
release tag whose commit is that SHA (`gh api repos/<owner>/<repo>/tags`).

| Action | Pin | SHA | Resolution |
|---|---|---|---|
| actions/checkout | v4.4.0 | `11d5960a326750d5838078e36cf38b85af677262` | tag `v4` |
| actions/upload-artifact, upload-artifact/merge | v4.6.2 | `ea165f8d65b6e75b540449e92b4886f43607fa02` | tag `v4` |
| actions/download-artifact | v4.3.0 | `d3f86a106a0bac45b974a628896c90dbdf5c8093` | tag `v4` |
| actions/cache, cache/restore, cache/save | v4.3.0 | `0057852bfaa89a56745cba8c7296529d2fc39830` | tag `v4` |
| actions/setup-java | v4.9.1 | `cf277c60eb25467037889841efdb72551f06f6c3` | tag `v4` |
| Swatinem/rust-cache | v2.9.3 | `d1527c8f67ef9af357290475d4af4b0fab8f12e0` | tag `v2` |
| oven-sh/setup-bun | v2.2.0 | `0c5077e51419868618aeaa5fe8019c62421857d6` | tag `v2` |
| taiki-e/install-action | v2.90.1 | `c509219cf42fba86913069efd0ade2458c59337b` | tag `v2` |
| tauri-apps/tauri-action | v0.6.2 | `84b9d35b5fc46c1e45415bdb6144030364f7ebc5` | tag `v0` |
| softprops/action-gh-release | v2.6.2 | `3bb12739c298aeb8a4eeaf626c5b8d85266b0e65` | tag `v2` |
| android-actions/setup-android | v3.2.2 | `9fc6c4e9069bf8d3d10b2204b1fb8f6ef7065407` | tag `v3` |
| docker/setup-buildx-action | v3.12.0 | `8d2750c68a42422c14e847fe6c8ac0403b4cbd6f` | tag `v3` |
| docker/login-action | v3.7.0 | `c94ce9fb468520275223c153574b00df6fe4bcc9` | tag `v3` |
| docker/metadata-action | v5.10.0 | `c299e40c65443455700f0fdfc63efafe5b349051` | tag `v5` |
| docker/build-push-action | v6.19.2 | `10e90e3645eae34f1e60eeb005ba3a3d33f178e8` | tag `v6` |
| mozilla-actions/sccache-action | v0.0.9 | `7d986dd989559c6ecdb630a3fd2557667be217ad` | already pinned before this task |

`dtolnay/rust-toolchain` publishes no version tags (only `v1`); `1.99.1`,
`stable` and `nightly` are branches. Their commit SHAs were resolved with
`gh api repos/dtolnay/rust-toolchain/branches/<name>` and the action file at
each commit was inspected: the branch bakes its toolchain name into
`action.yml` (`toolchain: 1.99.1`, `stable`, `nightly`), so pinning the commit
keeps the same toolchain:

| Ref | SHA | Comment |
|---|---|---|
| 1.99.1 | `d124f86f28ff42855784ff3319f48ac182c248f8` | `# 1.99.1` |
| stable | `b725eda525362e7cf34af9a7243cac1e3f01a7ec` | `# stable` |
| nightly | `2c76c034f9e32a5d6e2c104dc4df23a22476db04` | `# nightly` |

Residual float: the `stable` and `nightly` pin the *action script*, not the
rustup toolchain it installs; rustup resolves those channel names at run time.
The proof paths do not use them: the proof gates use `1.99.1` and the crate
`rust-toolchain.toml` files pin `nightly-2025-11-08`, which `install-hax.sh`
installs explicitly. `fuzz.yml` (the one nightly user) now pins its runner
image and `cargo-fuzz` instead.

## Runner images

`security.yml` and `proof-image.yml` use only fixed images:

- every Ubuntu job is `ubuntu-24.04` (the previous `ubuntu-latest` jobs in
  `security.yml` are pinned, including `pick-runner`, `refinement-boundary`,
  `static-scan`, `regression` and `formal-rekey`);
- the proof matrix keeps its two-value selector: the fixed hosted label
  `ubuntu-24.04` or the owner's `["self-hosted","vela-box"]` runner list;
- `proof-image.yml` builds and verifies on `ubuntu-24.04`;
- macOS/iOS jobs keep `macos-15`, Windows keeps `windows-latest` (not proof or
  security workflows, and unchanged as out of scope).

## Tool installs

| Tool | Pin | Source |
|---|---|---|
| cargo-audit | 0.22.2 | `crates.io/api/v1/crates/cargo-audit` `max_stable_version` |
| cargo-deny | 0.20.2 | crates.io, same field |
| cargo-fuzz | 0.13.2 | crates.io, same field |
| cargo-deb | 3.8.0 | crates.io, same field |
| cargo-generate-rpm | 0.21.1 | crates.io, same field |
| semgrep | 1.183.0 | `pypi.org/pypi/semgrep/json` `info.version` |

`taiki-e/install-action` now receives `tool@version`; `cargo install` uses
`--locked --version`; `pip install` uses `==`. `bun install` is repo-lockfile
driven and unchanged.

## OS packages on hosted runners

Before this task the proof/security jobs ran `apt-get install` from
`archive.ubuntu.com`, whose `noble-updates` pocket moves. Every remaining apt
install in `security.yml` (Tamarin/Maude prerequisites, ProVerif prerequisites,
the desktop-core build prerequisites, the refinement prerequisites) now points
apt at the immutable snapshot

```
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/20261104T000000Z/
Suites: noble noble-updates noble-security
Components: main restricted universe multiverse
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
```

(the deb822 form is used because the classic one-line `deb` format accepts a
single suite; extra suite names would be read as components), with
`Acquire::Check-Valid-Until=false` (the snapshot is intentionally old relative
to the archive's `Valid-Until`), and `--no-install-recommends`. The
stamp is recorded in `security/assurance/proof-image/apt-snapshot.conf` and the
checker fails if a workflow or the Dockerfile uses a different date. Example
versions this snapshot resolves on amd64: `python3 3.12.3-0ubuntu2.1`,
`opam 2.1.5-1`, `nodejs 18.19.1+dfsg-6ubuntu5`, `libssl-dev 3.0.13-0ubuntu3.16`.

`fuzz.yml` (the third workflow in the checker's proof/security set) installs
`libudev-dev` from the same snapshot; its runner and `cargo-fuzz` are pinned.
Release workflows (`release-desktop.yml`, `release-android.yml`,
`desktop-macos.yml`, `ios-*.yml`, `build-server.yml`, `verify-server.yml`,
`extension-release.yml`) keep distro packages; they are release machinery, not
assurance evidence.

## opam: hax engine transitive resolution

The working switch is `OPAMROOT=~/.local/opt/vela-tools/opam`;

```
opam switch export --switch vela-hax --freeze
```

refuses to run because `hax-engine` is path-pinned (`hax-engine is path pinned,
it can't be exported with --freeze`). The committed lock is therefore an
`opam lock` of the engine package:

```
opam lock --switch vela-hax hax-engine.opam      # hax 0.3.7 engine directory
```

`security/assurance/opam-lock/hax-engine.opam.locked` pins all 108 direct and
transitive dependencies with exact versions, including
`ocaml 5.1.1`, `ocaml-base-compiler 5.1.1`, `dune 3.24.2`,
`ppxlib 0.35.0`, `js_of_ocaml 6.4.1`, `menhir 20260209`, `yojson 3.0.0`.
`install-hax.sh` copies it next to the pinned hax checkout and runs
`opam install --locked`; `opam show --just-file` parses it and a dry-run
against the working switch resolves cleanly:

```
$ opam install --switch vela-hax --dry-run --locked .
[NOTE] Package hax-engine is already installed (current version is 0.3.7).
```

Not pinned: package *metadata* comes from opam-repository HEAD at install time.
The lock fixes versions and opam's per-release archive URL+checksum, but a
removed or retracted release would still break a fresh install. A repository
commit pin would close that gap; it is not done here.

## Base images

`Dockerfile` (the server image) and the proof image pin their base images by
manifest-list digest, resolved from the Docker Hub registry token + manifest
endpoint on 2026-11-04:

| Image | Digest |
|---|---|
| `rust:1-bookworm` | `sha256:c9155318d07341301a78b45ecdd81af2e43b8b297d64e8fd4c5e80d7735607c3` |
| `debian:bookworm-slim` | `sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3` |
| `ubuntu:24.04` (proof image) | `sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852` |

The `Dockerfile` change is limited to those digests; its build steps are
untouched.

## Checks run for this evidence

| Check | Command | Result |
|---|---|---|
| pin policy | `python3 -I security/assurance/check-env-pins.py` | PASS (12 workflows, 3 proof/security) |
| negative self-test | injected unpinned `uses:`, `ubuntu-latest`, bare `cargo-fuzz`, bare `semgrep`, non-snapshot apt, wrong lock path in a scratch copy | every violation reported, exit 1 |
| workflow parse | PyYAML `safe_load` over all 12 workflows | PASS |
| workflow lint | `actionlint 1.7.12` (all workflows) | PASS, no findings |
| Dockerfile lint | `hadolint 2.15.1 security/assurance/proof-image/Dockerfile` | PASS (clean after documented `DL3008` snapshot ignore) |
| shell syntax | `bash -n install-hax.sh install-formal-fstar.sh` | PASS |
| opam lock parse | `opam show --just-file security/assurance/opam-lock/hax-engine.opam.locked` | PASS |
| opam lock install | `opam install --dry-run --locked` with the committed lock | PASS |
| image digest resolution | registry manifest HEAD | PASS |

Unverified here: no Docker is available on this machine, so the proof image
itself was not built or run; the root `Dockerfile` was not rebuilt after the
digest pin (only the `FROM` lines changed); the hosted workflows have not run
on GitHub yet.
