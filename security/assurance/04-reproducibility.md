# 4. Reproducibility

Everything in this package can be re-run from a clean checkout. This
document lists the exact tool versions, how each one is pinned, the commands
to run, the output to expect, and where the reference CI evidence lives.

## 4.1 Pinned toolchain

| Tool | Version | How it is pinned | Used for |
|---|---|---|---|
| Tamarin Prover | **1.12.0** | CI downloads the release tarball and checks its SHA-256 (`201be06f…b469c6`, see `.github/workflows/security.yml`) | All `.spthy` theories |
| Maude | **3.2** in CI (Ubuntu noble `maude 3.2-2build1`); 3.5.1 in maintainer runs | CI: distro package, **not pinned**. Tamarin 1.12.0 reports 3.2 as "unsupported" but produces the same verdicts | Tamarin backend |
| ProVerif | 2.05 according to `security/formal/README.md` | opam `proverif` in switch `vela-proverif` (OCaml 5.1.1). **The package version is not pinned.** CI freezes it through cache key `opam-proverif-ocaml5.1.1-v1`, and the CI log does not record the version | M22 |
| OCaml | 5.1.1 | opam switch (`ocaml-base-compiler.5.1.1`) | ProVerif, hax engine, F\* |
| hax (`cargo-hax`, `hax-driver`, `hax-engine`) | **0.3.7** | `cargo install --version 0.3.7 --locked`; engine from git tag `cargo-hax-v0.3.7`; `hax-lib 0.3.7` in `Cargo.lock` | Rust → F\* and ProVerif extraction |
| Rust nightly for hax | **nightly-2025-11-08** with `rustc-dev`, `llvm-tools-preview`, `rust-analysis`, `rust-src`, `rustfmt` | `serverVELA/vela-rekey-policy/rust-toolchain.toml` | hax frontend |
| F\* | **2025.10.06** | opam `fstar.2025.10.06` in switch `vela-fstar` | Policy proofs |
| Z3 | **4.13.3** | Official release binary installed as `z3-4.13.3`. Each runner checks for that exact name | F\* SMT backend |
| Rust stable | 1.99.1 in the reference CI run | **Not pinned** (`dtolnay/rust-toolchain@stable`). Dependencies are locked by `Cargo.lock` | Executable models, tests, M24 |
| semgrep, cargo-audit, cargo-deny | semgrep 1.182.1 in the reference run | **Not pinned** | Static scan |

Primitive crate versions from the lockfiles at the baseline: `ml-kem 0.3.2`,
`fips204 0.4.6`, `x25519-dalek 2.0.1`, `ed25519-dalek 2.2.0`,
`chacha20poly1305 0.10.1`, `blake3 1.8.5`, `hkdf 0.12.4`, `argon2 0.5.3`,
`pasetors 0.6.8`, `webauthn-rs 0.5.5`.

## 4.2 Installing

### Tamarin and Maude (Linux x86-64)

```bash
curl -fL -o /tmp/tamarin.tar.gz \
  https://github.com/tamarin-prover/tamarin-prover/releases/download/1.12.0/tamarin-prover-1.12.0-linux64-ubuntu.tar.gz
echo "201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6  /tmp/tamarin.tar.gz" | sha256sum -c
sudo tar -xzf /tmp/tamarin.tar.gz -C /usr/local/bin
sudo apt-get install -y maude ripgrep     # or Maude 3.5.1 from maude.cs.illinois.edu
export LC_ALL=C.UTF-8 LANG=C.UTF-8
```

### ProVerif

```bash
opam switch create vela-proverif ocaml-base-compiler.5.1.1
opam install --switch vela-proverif --yes proverif.2.05   # pin explicitly; CI does not
```

### hax, F\*, and Z3

Follow
[`serverVELA/vela-rekey-policy/README.md` § Install the pinned toolchain](../../serverVELA/vela-rekey-policy/README.md#install-the-pinned-toolchain).
In short: rustup nightly-2025-11-08 with the components above; `cargo-hax`
and `hax-driver` 0.3.7; hax engine in opam switch `vela-hax`; F\* 2025.10.06
in a **separate** switch `vela-fstar` (their PPX constraints conflict);
`z3-4.13.3` on `PATH`. Then:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
```

## 4.3 Running

### Everything

```bash
git checkout 5a3b72e7f6d2081cc91b9610adc62a54981f0857
sha256sum -c security/assurance/MANIFEST.sha256
security/assurance/run-all.sh --out ./assurance-logs                 # ~10–20 min
security/assurance/run-all.sh --with-fstar --out ./assurance-logs    # adds hax/F*
```

`run-all.sh` writes `versions.txt`, one log per step, and `summary.txt`.
It exits non-zero if any step fails.

### Individual checks

| Check | Command (from repo root) | Expected |
|---|---|---|
| M1–M10 credential release | `run-all.sh` (step `tamarin-m1-m10-credential-release`), or the loop in `security/formal/README.md` | 83 verified; falsified exactly `m1.secrecy`, `m2.secrecy`, `m9b.credential_never_leaks`, `m9c.credential_never_leaks`, `m9c.unused_credentials_stay_secret` |
| M11 rekey | `security/formal/run-rekey-proofs.sh` | `31 verified, 0 falsified, 0 warnings` |
| M12 session | `security/formal/run-session-proofs.sh` | 14 |
| M13 enrollment | `security/formal/run-enrollment-proofs.sh` | 16 |
| M14 recovery | `security/formal/run-recovery-proofs.sh` | 18 |
| M15 client recovery | `security/formal/run-client-recovery-proofs.sh` | 15 |
| M16 publication | `security/formal/run-recovery-publication-proofs.sh` | 14 |
| M17 crash recovery | `security/formal/run-recovery-publication-recovery-proofs.sh` | 14 |
| M18 pair selection | `security/formal/run-pair-selection-proofs.sh` | 15 |
| M19 share channel | `security/formal/run-share-channel-proofs.sh` | 2 + 6 |
| M20 pass-through | `security/formal/run-web-session-pass-through-proofs.sh` | 7 |
| M21 revocation | `security/formal/run-link-revocation-finality-proofs.sh` | 3 |
| M23 sync | `security/formal/run-sync-admission-proofs.sh` | 11 |
| M26 composition | `security/formal/run-composition-proofs.sh` | 4 + 6 |
| M22 ORAM (ProVerif) | `security/formal/run-oram-access-hiding-proofs.sh` | m22a cannot be proved (intended); m22b, m22c true |
| M24 ORAM stash | `security/formal/run-oram-stash-bounds-tests.sh` | 4/4 tests pass |
| hax/F\* per crate | `<crate>/verify-fstar.sh` for the 7 crates in [§3.2](03-implementation-correspondence.md#crate-inventory-92-extracted-entry-points) | `cargo test` passes, extraction succeeds, F\* reports all VCs discharged |
| Executable models | see the `Exhaust the bounded model…` and `Verify the … epoch wire contract` steps in `security.yml` | all pass |
| Exploit regressions | `cargo build --manifest-path serverVELA/Cargo.toml && security/exploits/run-exploits.sh` | 9 × `[PASS]` |
| Static scan | `security/run-scan.sh` | `VELA security scan: PASS` |

The Tamarin runners fail closed: any `WARNING:`, `analysis incomplete`, or
unexpected `falsified`, or any drift in the lemma count, fails the gate.
Most derive their expected count from the theory (`grep -cE
'^(lemma|exists-trace)'`). The rekey, session, recovery, client-recovery,
publication, pair-selection, and pass-through runners hard-code it.

### Interactive inspection

```bash
tamarin-prover interactive security/formal/       # browse proofs and attack graphs at http://127.0.0.1:3001
proverif -in pitype <(cat security/formal/hax_pv_prelude.pvl \
  libVELA/vela-crypto/proofs/proverif/extraction/lib.pvl \
  security/formal/m22a_static_position_baseline.pv)   # shows the m22a attack trace
```

## 4.4 Proof logs

[`proof-logs/`](proof-logs/) holds filtered excerpts from the reference CI
run on the baseline commit:

| File | Contents |
|---|---|
| `ci-39864715971-formal.txt` | Tool versions, every Tamarin and ProVerif gate line, statistical and executable-model test results |
| `ci-39864715971-static-scan.txt` | semgrep, `scan.py`, `cargo audit` and `cargo deny` for 5 crates: all clean |
| `ci-39864715971-regression.txt` | The 9 exploit regressions, each blocked |

The full logs stay on GitHub for the Actions retention period. Fetch them
with:

```bash
gh run view 39864715971 --repo lucannez64/VELA --log > security-run.log
```

hax/F\* logs are **not** in CI. We will attach a maintainer `--with-fstar`
run to the engagement. Until then, treat **[REF]** claims as reproducible
but not independently witnessed.

## 4.5 CI evidence

Workflow: [`.github/workflows/security.yml`](../../.github/workflows/security.yml).
It runs on pushes to `main` and on pull requests that touch `security/`,
`serverVELA/`, `libVELA/`, the clients, or lockfiles.

| Job | Gates |
|---|---|
| `formal-rekey` | All CI-gated Tamarin families, ProVerif M22, statistical M24, executable models, cross-client wire matrix |
| `static-scan` | semgrep (extension JS), `security/scan.py` (Rust rules), `cargo audit` and `cargo deny` for 5 crates |
| `regression` | 9 live exploit regressions against an isolated loopback server |

Reference run:
<https://github.com/lucannez64/VELA/actions/runs/39864715971>, on commit
`5a3b72e`, all three jobs passed (formal job about 9 minutes). Recent history:

```bash
gh run list --repo lucannez64/VELA --workflow security.yml --branch main --limit 20
```

## 4.6 Artifact integrity

[`MANIFEST.sha256`](MANIFEST.sha256) lists SHA-256 hashes of every model,
runner, committed F\* and ProVerif extraction, and policy crate source at
the baseline. Regenerate it with:

```bash
security/assurance/make-manifest.sh > security/assurance/MANIFEST.sha256
```
