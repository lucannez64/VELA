# VELA formal verification and security assurance package

This package is written for external researchers: cryptographers, protocol
analysts, formal-methods people, and auditors. It states what VELA claims,
which of those claims are machine-checked and under which assumptions, how
the models relate to the shipped Rust, how to re-run every check, and what
is not covered.

It is meant to be read skeptically. Each claim is tagged with the evidence
behind it. "Proved" means proved in a stated model. It never means proved
about the deployed system as a whole.

## Baseline

| | |
|---|---|
| Repository | <https://github.com/lucannez64/VELA> (MIT) |
| Baseline commit | `5a3b72e7f6d2081cc91b9610adc62a54981f0857` (2026-10-22) |
| Reference CI run | [security #39864715971](https://github.com/lucannez64/VELA/actions/runs/39864715971): `formal-rekey`, `static-scan`, and `regression` all passed on that commit |
| Protocol specification | [`SPEC.md`](../../SPEC.md) v2.1 |
| Artifact hashes | [`MANIFEST.sha256`](MANIFEST.sha256) |

If you review a later commit, re-run [`run-all.sh`](run-all.sh) and compare
your results with [`proof-logs/`](proof-logs/).

## Contents

| # | Document | Answers |
|---|---|---|
| 1 | [`01-security-claims.md`](01-security-claims.md) | Which confidentiality, authentication, integrity, and compromise-resilience properties VELA claims, each with an ID and its evidence level |
| 2 | [`02-formal-models.md`](02-formal-models.md) | The 30 Tamarin theories and 3 ProVerif models: what each one models, the adversary it gives, and the assumptions it makes |
| 3 | [`03-implementation-correspondence.md`](03-implementation-correspondence.md) | How the models map to Rust, what hax/F\* verifies, and what is trusted or unproved |
| 4 | [`04-reproducibility.md`](04-reproducibility.md) | Pinned tool versions, exact commands, expected outputs, proof logs, and CI evidence |
| 5 | [`05-known-limitations.md`](05-known-limitations.md) | Unproved properties, trusted components, attacks outside the models, and known gaps in the assurance itself |
| 6 | [`06-engaging-researchers.md`](06-engaging-researchers.md) | Audit scope, priority questions, how to report, and how to engage with the project |

## Evidence levels

Every claim in this package carries one or more of these tags:

| Tag | Meaning |
|---|---|
| **[SYM]** | Proved in a symbolic (Dolev-Yao) model with Tamarin or ProVerif, and gated in CI |
| **[SYM-local]** | Proved in a symbolic model, but **not** run by CI. The result comes from a maintainer's run |
| **[REF]** | A pure Rust decision function is extracted with hax and its postconditions are discharged by F\*. The proof is **not** run by CI (see [§5 G-1](05-known-limitations.md#gaps-in-the-assurance-itself)) |
| **[EXEC]** | Bounded or exhaustive executable model tests against real handlers or real SQL, gated in CI |
| **[EXPLOIT]** | A live exploit regression against an isolated server, gated in CI |
| **[STAT]** | Statistical testing of the production implementation, gated in CI |
| **[ARG]** | Design argument or reliance on a standard primitive. Nothing machine-checked |

## Totals at the baseline commit

| Tool | Scope | Result | In CI |
|---|---|---|---|
| Tamarin 1.12.0 | 17 protocol theories (M11–M26) | 176 lemmas verified, 0 falsified, 0 warnings | yes |
| Tamarin 1.12.0 | 13 credential-release theories (M1–M10) | 83 verified, 5 falsified **by design** (impossibility baselines) | **no** |
| ProVerif (opam, OCaml 5.1.1 switch) | 3 ORAM access-pattern equivalence models (M22) | 2 equivalences proved, 1 baseline attack found as intended | yes |
| hax 0.3.7 + F\* 2025.10.06 + Z3 4.13.3 | 7 policy crates, about 80 extracted entry points | all VCs discharged (maintainer runs) | **no** |
| Rust executable models | rekey, session, enrollment, recovery, client recovery | all pass | yes |
| Exploit regressions | 9 previously confirmed attacks | all blocked | yes |
| Statistical | Path ORAM stash bounds and invariants | 4/4 | yes |

## Quick start

```bash
git clone https://github.com/lucannez64/VELA && cd VELA
git checkout 5a3b72e7f6d2081cc91b9610adc62a54981f0857
sha256sum -c security/assurance/MANIFEST.sha256      # artifacts match this package
# install the toolchain in 04-reproducibility.md, then:
security/assurance/run-all.sh                         # Tamarin + ProVerif + stats
security/assurance/run-all.sh --with-fstar            # also hax/F*
```

## Reporting

Report suspected vulnerabilities privately, as described in
[`SECURITY.md`](../../SECURITY.md) and [§6](06-engaging-researchers.md#reporting).
Model bugs, over-claims in this package, and proofs that pass for the wrong
reason count as security reports too. We want to hear about them.
