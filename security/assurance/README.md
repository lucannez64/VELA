# VELA security assurance for external researchers

Read this package as a set of scoped claims and reviewable evidence.
A proof establishes a property of its stated model, not of the whole deployed
system. Start with the claims, then inspect the assumptions and Rust mapping.

## Baseline

Repository: <https://github.com/lucannez64/VELA> (MIT).
The current implementation baseline is commit `148ff32` (share signatures,
enrollment fingerprint v4, KEM combiner v2). This package adds revised models,
correspondence records, local proof logs and CI configuration on top of it.
[`MANIFEST.sha256`](MANIFEST.sha256) identifies the exact reviewed artifacts;
use the commit containing this manifest to reproduce this package.

The older [CI run #39864715971](https://github.com/lucannez64/VELA/actions/runs/39864715971)
passed on `5a3b72e7f6d2081cc91b9610adc62a54981f0857`. Its logs are historical
baseline evidence. They do not validate the subsequent protocol changes.
The [refinement job passed on `b27dcd6`](proof-logs/current/hosted-refinement-40002230354/README.md).
The complete [security workflow](https://github.com/lucannez64/VELA/actions/runs/40008926193)
passed on `e690dfc`. The subsequent parser/accessor increment awaits hosted CI.

## Contents

1. [Security claims](01-security-claims.md): confidentiality, authentication,
   integrity, compromise resilience, with stable claim IDs.
2. [Formal models](02-formal-models.md): Tamarin and ProVerif adversaries,
   assumptions and model boundaries.
3. [Implementation correspondence](03-implementation-correspondence.md):
   Rust mapping, hax/F* scope and unproved seams.
4. [Reproducibility](04-reproducibility.md): pinned proof tools, commands,
   logs and CI status.
5. [Known limitations](05-known-limitations.md): unproved properties,
   trusted components and attacks outside the models.
6. [Engaging researchers](06-engaging-researchers.md): prioritized audit
   questions, contact routes and ready-to-adapt outreach text.

7. [Implementation-boundary review](07-boundary-review.md): three reproduced,
   sharing caller/storage findings, their fixes, regression coverage and limits.

The caller/storage fixes have executable regression coverage. Their storage
correctness is not a consequence of the pure-policy proofs.

8. [Formalization status](08-formalization-status.md): checked sharing
   extensions, explicit trusted boundary and outstanding whole-system obligations.

9. [Selected proof boundary](09-target-contract.md): trust OS/compiler and
   primitive security; retain VELA construction and application obligations.

10. [Hybrid-signature reduction](10-signature-reduction.md): exact byte-message
    EUF-CMA game and a written reduction to either component, with explicit
    implementation and machine-checking obligations.

11. [Concrete parser refinement](11-parser-refinement.md): byte grammar, checked
    cursor transitions and read-only opened-share observations.

12. [Received-byte transcript](12-authenticated-transcript.md): exact body and
    domain concatenation, compatibility model and remaining opening obligations.

## Evidence levels

| Tag | Meaning |
|---|---|
| **[SYM]** | Symbolic proof witnessed in the linked historical CI run; check baseline before applying it to newer code |
| **[SYM-local]** | Symbolic result from local runs; current CI configuration may gate it, but a successful new CI run is still needed |
| **[REF]** | Fresh local hax extraction and F* checking of selected Rust functions; no whole-handler correctness implication |
| **[EXEC]** | Executable model or test; distinguish linked historical CI results from current local logs |
| **[EXPLOIT]** | Live exploit regression at the cited baseline |
| **[STAT]** | Statistical implementation evidence, not a universal proof |
| **[COMP]** | Computational-model proof checked by CryptoVerif, gated in CI; the game, assumptions and bound are stated with the model |
| **[ARG]** | Design argument or reliance on a primitive; no machine-checked support |

## Recorded results and pending evidence

- Historical CI: 176 Tamarin lemmas; ProVerif M22b/M22c equivalence and the
  intended M22a baseline failure; executable models, statistics and exploit
  regressions. See [`proof-logs/`](proof-logs/).
- Current full local run: **276 verified / 5 intended falsifications** across
  all 35 Tamarin theories, the expected three ProVerif verdicts, and four
  passing ORAM statistical tests. [Run summary](proof-logs/current/full-run/summary.txt).
- Current network-boundary run: **17/17 verified** in five theories, including
  explicit attack witnesses for the old share and enrollment designs.
  Full logs: [`proof-logs/current/`](proof-logs/current/).
- Corpus inventory: **37 Tamarin theories / 299 lemmas**, plus three ProVerif
  models. The earlier full run covers 35 theories; M28 adds seven journal
  properties and M29 adds eleven composed authentication/journal properties.
  Combined evidence is **294 verified / five intended falsifications**; it is
  not a new whole-corpus CI result.
- Current hax/F*: [hosted policy and enrollment checks](proof-logs/current/hosted-enrollment-40039992434/README.md) cover **159 selected functions / 152 explicit
  postconditions** across eight policy crates and the sharing/signature kernels.
  All **18 local enum-equality assumptions were removed** through structural
  Rust comparisons; current generated modules contain zero local `assume val`
  declarations. Imported proof libraries, the String/Vec models and tools remain
  trusted. [Current evidence](proof-logs/current/trusted-boundary/README.md).
- The earlier [resource measurements](proof-logs/current/refinement-5g/) are
  historical: engine build about 4.8 GiB under a cap raised to 6 GiB; individual
  policy workflows 0.74–2.06 GiB under 5 GiB caps. Current proof/regression
  commands used 3 GiB caps without swap; no engine rebuild was needed.
- CI now defines all-model and eight-crate refinement gates and log artifacts.
  Hosted refinement passed on fbe35c0; its full workflow failed before
  CryptoVerif ran. The executable/failure-handling repair awaits hosted checking.
  Toolchain installation in the dedicated CI job has a separate 6 GiB cap;
  local runners default to 3 GiB.

## Quick start

```bash
sha256sum -c security/assurance/MANIFEST.sha256
python3 security/formal/check-correspondence.py
VELA_PROOF_OUT=/tmp/vela-network security/formal/run-network-boundary-proofs.sh
security/assurance/run-all.sh --out /tmp/vela-assurance
# With the pinned hax/F* tools installed:
security/assurance/run-all.sh --with-fstar --out /tmp/vela-assurance-fstar
```

Install tools using [reproducibility](04-reproducibility.md). Runners use one
prover worker, sequential steps, time limits and a 3 GiB process-tree memory
cap with no swap. They require Linux systemd scopes; on other hosts use an
equivalently limited Linux environment. Toolchain installation is separate.

Report privately through [GitHub advisories](https://github.com/lucannez64/VELA/security/advisories/new)
and [`SECURITY.md`](../../SECURITY.md). Private reporting was checked enabled
on 2026-10-23. Model inadequacy, vacuous proofs and overstated claims are
valid assurance findings.
