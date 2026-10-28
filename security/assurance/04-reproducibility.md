# 4. Reproducibility

Use the commit containing this package and verify `MANIFEST.sha256` before
running tools. Commit `148ff32` is the implementation baseline; the models
and CI additions here are later changes. The archived CI run at `5a3b72e`
is historical evidence, not evidence for the new protocols.

## 4.1 Pinned toolchain

| Tool | Current gate version | Pin |
|---|---|---|
| Tamarin | 1.12.0 | Release archive SHA-256 `201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6` |
| Maude | 3.5.1 | `Maude3.5.1/Maude-3.5.1-linux-x86_64.zip`, SHA-256 `72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c` |
| ProVerif | 2.05 | `opam install proverif.2.05` in OCaml 5.1.1 switch; version printed in CI |
| CryptoVerif | 2.12 | `cryptoverif2.12.tar.gz`, SHA-256 `77730861be7bfbde5b078f7785db478869d33aba2761a428d50aaad537098757`; bundled `default.ocvl` library |
| OCaml | 5.1.1 | `ocaml-base-compiler.5.1.1` for ProVerif/hax; the prebuilt F★ release reports OCaml 4.14.2 |
| hax frontend/driver | 0.3.7 | `cargo install --version 0.3.7 --locked` |
| hax engine | 0.3.7 | Source commit `d8b5b3d3b666fee8943a351445d2b680105e8ea3` |
| Rust for hax | nightly-2025-11-08 | Compiler components installed explicitly |
| F* | 2025.10.06 | Official Linux x86-64 release, SHA-256 `940c187d7a6dc3e95d17fd5159b5eaec17d62981c7f135a7e6c531ce3b59442d` |
| Z3 | 4.13.3 | Official x64 glibc-2.35 archive, SHA-256 `32c7377026733c9d7b33c21cd77a68f50ba682367207b031a6bfd80140a8722f` |
| Rust tests in security CI | 1.99.1 | `dtolnay/rust-toolchain@1.99.1`; Cargo lockfiles pin crate resolution |

Stable Rust CI uses its default LLVM backend. Do not set
`CARGO_PROFILE_DEV_CODEGEN_BACKEND` in stable jobs: explicit backend selection
requires an unstable Cargo feature. The pinned hax nightly installer enables
that feature explicitly for its own LLVM override.

Maude 3.2 and unversioned ProVerif were used in the historical reference CI.
The new gates use the versions above. OS packages, transitive opam resolution,
GitHub action tags, semgrep, cargo-audit and cargo-deny are not a hermetic
pinned environment. No bit-for-bit build reproducibility is claimed.

The refinement job restores installed proof tools and the pinned Rust nightly
from an exact GitHub Actions cache key containing OS, architecture, Ubuntu 24
and the installer script hash. A miss builds hax under the documented memory
cap and downloads the pinned prebuilt F★/Z3 releases, with a 90-minute cold-install limit inside a two-hour job budget;
completed tools are cached before application proofs. Activation checks
hax/engine/F★ versions and logs Z3/Rust versions. GitHub's cache and tool
installation remain trusted CI infrastructure; a cache key is not a toolchain
soundness proof. VELA extraction output is regenerated and checked on every run.

Application dependency artifacts have a separate Rust cache, restored after
proof-tool activation so it uses the proof job's actual Cargo home. Workspace
mappings resolve to the shared repository-root target directory. It does not
cache VELA proof verdicts: extraction and all F★ checks still run fresh.
The ordinary formal/regression jobs select pinned Rust before cache lookup and
use identical workspace inputs. Only a successful formal job publishes their
combined dependency cache; regression restores it read-only. Parallel jobs on
a cold cache still compile independently, and cross-target/profile/toolchain
builds retain separate artifacts. The first run after these cache-key changes
is expected to be cold. Hosted hit rates and savings require subsequent runs.

## 4.2 Installation

The refinement prerequisites explicitly include the system `nodejs` package:
the pinned hax engine declares it as an opam external dependency. Apt uses
`--no-install-recommends` to avoid the unused distro OCaml installation;
OCaml 5.1.1 is built for hax; F★ uses its official prebuilt release. Apt operations have network
retries/timeouts and a 15-minute refinement prerequisite limit. The separate
ProVerif setup has a 25-minute limit and also omits recommended distro OCaml;
its completed switch is cached before application tests/proofs.

For Linux x86-64, the exact Tamarin/Maude install commands and checksums are
in [security.yml](../../.github/workflows/security.yml), step **Install pinned
Tamarin 1.12.0 and Maude 3.5.1**. Keep the Maude executable beside its `.maude`
prelude files. The PATH entry must be a wrapper setting `MAUDE_LIB` to that
directory; a bare symlink can leave the prelude undiscoverable. CI checks that
Tamarin reports no installation warning before running proofs. Do not use the
old unsupported distro Maude.

```bash
opam init --bare --no-setup --yes
opam switch create vela-proverif ocaml-base-compiler.5.1.1
opam install --switch vela-proverif --yes proverif.2.05
export PATH="$(opam var bin --switch vela-proverif):$PATH"
```

Some ProVerif opam dependencies require GTK2 development packages even for
CLI use. CI installs `libgtk2.0-dev` and `pkg-config`.

The optional full hax installation is scripted for a **clean Linux build
environment** in [`install-hax.sh`](install-hax.sh). It builds hax and one OCaml
switch; F★ and Z3 are downloaded from official releases with checked hashes.
The F★ release is commit `7b347386330d0e5a331a220535b6f15288903234` and includes
its matching standard libraries. Cold hax installation can still take substantial
time; it is not part of the default local run:

```bash
VELA_MEMORY_MAX=6G VELA_STEP_TIMEOUT=5400 security/assurance/bounded.sh security/assurance/install-hax.sh
export OPAMROOT="$HOME/.local/opt/vela-hax-0.3.7/opam"
export PATH="$HOME/.local/opt/vela-hax-0.3.7/bin:$OPAMROOT/vela-hax/bin:$HOME/.local/opt/vela-hax-0.3.7/fstar/bin:$PATH"
```

Use a clean Cargo configuration. The installer explicitly selects LLVM and
sets `--cfg hax` for the names-helper build: ancestor Cargo configurations
can otherwise interfere. Earlier engine attempts exceeded the **3 GiB** cap;
those failure logs remain available. A subsequent native build succeeded in
about 11 minutes with tight OCaml GC, one worker and no swap. Its cap started
at 5 GiB and was raised to **6 GiB** for headroom. A live peak of 5,123,719,168
bytes (4.77 GiB) was observed; the final exact metric failed to collect, while
the systemd journal recorded a rounded 4.7G peak. Dependencies were already
installed, so this is not a cold full-toolchain benchmark.

Fresh extraction and checking then passed for **all eight policy crates**.
Their whole workflows (tests, extraction and F*) used **0.74–2.06 GiB** under
individual 5 GiB caps, sequentially and without swap. See the
[per-crate measurements and harness](proof-logs/current/refinement-5g/).
These observations are not minimum requirements or guarantees for other inputs.

CI toolchain installation now uses **6 GiB** (`VELA_MEMORY_MAX=6G`); its first
successful refinement job passed on `b27dcd6` (see
[hosted logs](proof-logs/current/hosted-refinement-40002230354/README.md)).
Default local runners retain the **3 GiB** cap.

## 4.3 Commands and resource limits

```bash
sha256sum -c security/assurance/MANIFEST.sha256
python3 security/formal/check-correspondence.py
VELA_PROOF_OUT=/tmp/vela-network security/formal/run-network-boundary-proofs.sh
security/assurance/run-all.sh --out /tmp/vela-assurance
security/assurance/run-all.sh --with-fstar --out /tmp/vela-assurance-fstar
```

`run-all.sh` records versions, source commit, dirty status, per-step logs,
credential-release per-theory outputs, and a summary; failures return nonzero.
It includes the 13 original protocol families, the credential-release ladder,
the five new network theories, ProVerif M22 and M24 statistical tests. It does
not run the server exploit suite or every server executable model; those have
separate CI steps. `--with-fstar` adds all eight policy-crate runners, the production share-fact
constructor/composition, prefix and signature gates, plus the extraction
assumption/precondition drift gate. The default run also includes
M28/M29's 21 named journal/composition verdicts via `run-share-journal-proofs.sh`
(ten M28, eleven M29). The M28 all-pairs increment uses documented Chain ghost
instrumentation. The runner also checks the separate typed single-slot F★
lifting/projection development, using prebuilt F★ 2025.10.06 and Z3 4.13.3,
`--cache_off`, version assertion and source/argv logging. The source bridge
between those encodings and Tamarin remains unproved. The `formal-rekey` job
caches the checksum-pinned standalone F★ release via
`install-formal-fstar.sh`; it does not rebuild hax for this step. The runner
checks emitted-action coverage and uses a 600-second default timeout per model;
memory and worker limits remain unchanged.

The computational gate is separate from `run-all.sh`. With the checksum-pinned
CryptoVerif binary and its matching `default.ocvl` beside it, run:

```bash
security/assurance/bounded.sh env CRYPTOVERIF=/path/to/cryptoverif2.12/cryptoverif security/formal/run-cryptoverif-proofs.sh
python3 -m unittest discover -s security/formal/tests -p 'test_cryptoverif_runner.py' -v
```

The gate requires the expected query result and rejects process failures,
missing verdicts and local manual/admitted declarations. Its source scan is a
lexical drift guard. The nonuniform companion also pins its reviewed probability
bound through `check-cryptoverif-bound.py`; this output check does not establish the soundness or adequacy of each
primitive assumption, equation, type or implementation mapping. Model-review
corrections and local evidence are in
`proof-logs/current/computational-review-corrections/`.

`bounded.sh` uses Linux systemd scopes with **3 GiB memory, zero swap, one
Cargo/opam/make/test worker**, and a 30-minute whole-command timeout.
`tamarin-bounded.sh` defaults to 180 seconds (the journal runner uses 600 seconds), one GHC
worker and a 1500 MiB GHC heap. `VELA_STEP_TIMEOUT` and `VELA_PROOF_TIMEOUT`
can raise time limits explicitly. `VELA_MEMORY_MAX` is an explicit memory
override; the documented toolchain installation command configures it to 6G. Without a working systemd manager the
wrapper fails; CI can use the system manager through passwordless sudo.
Use a memory-limited Linux environment on other platforms. Do not set
`VELA_BOUNDED=1` yourself unless an outer wrapper already applies the cap.

Expected symbolic verdicts:

- M1–M10: 83 verified and exactly five named intended falsifications (the
  runner checks the set, not just the count).
- Original M11–M26 protocol families: 176 verified, no falsifications.
- New M13b baseline/fix: 1 + 4 verified; new M19c baseline/fix: 1 + 5;
  M27 device authentication: 6. Baseline verified lemmas are **attack witnesses**.
- ProVerif M22: m22a baseline equivalence fails; m22b and m22c equivalences hold.
- M24: four statistical tests pass.

The five new theories' gate checks every declared lemma by name, rejects
warnings/incomplete analysis, and preserves full output. Other historical
runners use their original count-based gates; see their source for details.

Individual original family commands remain `security/formal/run-<family>-proofs.sh`
(`rekey`, `session`, `enrollment`, `recovery`, `client-recovery`,
`recovery-publication`, `recovery-publication-recovery`, `pair-selection`,
`share-channel`, `web-session-pass-through`, `link-revocation-finality`,
`composition`, `sync-admission`, `oram-access-hiding`). Direct invocation
bypasses the default all-run resource wrapper; prefer `run-all.sh`.

## 4.4 Logs and CI evidence

[`proof-logs/`](proof-logs/) retains curated excerpts from
[CI #39864715971](https://github.com/lucannez64/VELA/actions/runs/39864715971)
at `5a3b72e`: formal, static scan and nine exploit regressions passed.
Fetch the full historical logs while retained with:

```bash
gh run view 39864715971 --repo lucannez64/VELA --log
```

[`proof-logs/current/`](proof-logs/current/) records the current local checks.
Its `README.md` identifies their source, tools and limitations. The full
local symbolic/statistical run passed all configured steps, including all
281 Tamarin verdicts (276 verified and five intended falsifications). The separate `refinement-5g/` evidence records successful fresh hax extraction
and F* checking for all eight policy crates.

The updated workflow defines:

| Job | Gates / evidence |
|---|---|
| `formal-rekey` | Correspondence drift check, network models, full all-model run, executable server models and cross-client Rust tests; uploads `assurance-symbolic-logs` even on failure |
| `sharing-boundaries` | Desktop-core unit suite, including repeated acceptance, stale snapshot and interrupted-commit regressions; uploads `assurance-sharing-logs` |
| `refinement` | Pinned hax/F*/Z3 installation and fresh extraction/checking of eight policy crates and the production share-fact constructor; uploads `assurance-refinement-logs` even on failure |
| `static-scan` | semgrep, Rust scan, cargo audit/deny |
| `regression` | Isolated live exploit regressions |

These additions require an actual branch CI run before claiming CI success.
Earlier installation failures are superseded by the successful local engine
build and eight-crate verification. CI reproduction remains an evidence gap.

## 4.5 Artifact integrity

Regenerate the manifest after reviewed changes and completed log capture:

```bash
security/assurance/make-manifest.sh > security/assurance/MANIFEST.sha256
sha256sum -c security/assurance/MANIFEST.sha256
```

The manifest includes untracked new artifacts that are not ignored in the working tree, so inspect
what is included before publishing. It excludes itself and does not replace
a signed release tag. Review source/model changes before updating
`correspondence.json`; blindly updating hashes defeats its purpose.

## Reused CI proof verdicts

Each CI proof job (`refinement` in `security.yml`) is skipped when its inputs
are byte-identical to a run that already passed. The key is the git object id
of the crate, the outside files its scripts read (`deps` in the matrix), the
workspace `Cargo.toml` and `Cargo.lock`, `security/formal`, the proof-tool pins
and checkers, and the workflow itself. A hit restores that run's logs and
checked extractions, adds `reused.txt` to the logs, and the boundary job audits
them as usual. `security/formal/tests/test_proof_inputs.py` fails if a script
reads an outside path or local crate that the key does not cover. To force a
full rerun, change the `proof-verdict-v1` prefix in the workflow.
