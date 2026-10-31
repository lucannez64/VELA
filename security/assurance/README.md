# VELA security assurance for external researchers

Read this package as a set of scoped claims and reviewable evidence.
A proof establishes a property of its stated model, not of the whole deployed
system. Start with the claims, then inspect the assumptions and Rust mapping.

## Baseline

Repository: <https://github.com/lucannez64/VELA> (MIT).
The protocol-change starting baseline is commit `148ff32` (share signatures,
enrollment fingerprint v4, KEM combiner v2). This package adds revised models,
correspondence records, local proof logs and CI configuration on top of it.
[`MANIFEST.sha256`](MANIFEST.sha256) identifies the exact reviewed artifacts;
use the commit containing this manifest to reproduce this package.

The older [CI run #39864715971](https://github.com/lucannez64/VELA/actions/runs/39864715971)
passed on `5a3b72e7f6d2081cc91b9610adc62a54981f0857`. Its logs are historical
baseline evidence. They do not validate the subsequent protocol changes.
The [refinement job passed on `b27dcd6`](proof-logs/current/hosted-refinement-40002230354/README.md).
The later complete [security workflow](https://github.com/lucannez64/VELA/actions/runs/40089709666)
passed on `350cd57`, including the 212-postcondition snapshot, seven
computational games and instrumented journal gate. [Hosted evidence](proof-logs/current/hosted-350cd57/README.md)
records that exact head. The later [368bcc0 hosted workflow](proof-logs/current/hosted-368bcc0/README.md)
reproduces the 231-postcondition inventory and the typed journal encoding proof.
The [5d8c366 snapshot](proof-logs/current/hosted-5d8c366/README.md) then passes
all fifteen PR checks with 245 Rust postconditions, including the corrected
sharing constructor. The [fdee2bc hosted baseline](proof-logs/current/hosted-fdee2bc/README.md)
now covers the 249-contract mobile increment, twenty chunk lemmas, six epoch
lemmas and stronger encoded journal proofs, with all fifteen checks passing.
The later [recovery-redemption driver](proof-logs/current/recovery-redemption-driver/README.md),
which fixed a duplicate-enrollment bug, sharing and possession drivers, and
bounded Android/iOS admission tests have their own hosted evidence. All fifteen
checks pass on `c8a377d`; see the [current ledger](08-formalization-status.md).
The login driver and release-build gates passed hosted checks on `5ae87da`.
The subsequent [producer and nonce-composition increment](19-login-producer-composition.md)
passed hosted checks on `8d3610d`. A newer pure raw-byte/world bridge has local
proof evidence; real store/handler refinement remains open.

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
    EUF-CMA game, written component reductions and local CryptoVerif model proofs,
    with explicit implementation and composition obligations.

11. [Concrete parser refinement](11-parser-refinement.md): byte grammar, checked
    cursor transitions and read-only opened-share observations.

12. [Received-byte transcript](12-authenticated-transcript.md): exact body and
    domain concatenation, compatibility model and remaining opening obligations.

13. [Recovery fact refinement](13-recovery-fact-refinement.md): checked observation
    constructors, epoch normalization, atomic insertion and remaining boundaries.

14. [Session observations](14-session-observation-refinement.md): production
    observation constructors and their remaining source obligations.

15. [Possession/enrollment observations](15-recovery-possession-enrollment.md):
    decoded commitment, key-length and grant facts.

16. [Enrollment preflight](16-enrollment-preflight.md): checked rejection
    sequencing before real single-use grant redemption.

17. [Universal chunk admission](17-universal-chunk-admission.md): twenty
    supplemental handwritten lemmas over the unchanged Rust extraction;
    caller flags and native/storage correspondence remain conditional.

18. [Mobile sync admission candidate](18-mobile-sync-admission.md): four
    additional Rust epoch contracts and six epoch lemmas, implemented admitted
    bridge paths and explicit pending runtime/compatibility obligations.

## Evidence levels

| Tag | Meaning |
|---|---|
| **[SYM]** | Symbolic proof (Tamarin/ProVerif) gated in CI; last witnessed in the [368bcc0 hosted workflow](proof-logs/current/hosted-368bcc0/README.md). Re-check against newer code |
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
- Corpus inventory: **37 Tamarin theories / 302 lemmas**, plus three ProVerif
  models. The earlier full run covers 35 theories; M28 adds ten journal
  properties and M29 adds eleven composed authentication/journal properties.
  Combined evidence is **297 verified / five intended falsifications**; it is
  not a new whole-corpus CI result.
- Computational models: nine positive CryptoVerif game results and one explicitly
  unproved legacy baseline, with a random-oracle boundary and uniform/nonuniform GDH abstractions.
  The [review corrections](proof-logs/current/computational-review-corrections/README.md)
  add leaked-key KEM correctness and clarify assumptions; hosted reproduction
  passed for all ten games on fdee2bc. These results do not establish full Rust or quantum-adversary
  construction correspondence.
- Current hax/F*: the [local recovery increment](proof-logs/current/recovery-fact-refinement/README.md)
  extends the earlier [hosted enrollment baseline](proof-logs/current/hosted-enrollment-40039992434/README.md)
  to the hosted 180/173 snapshot. The [web-session observation increment](14-session-observation-refinement.md) extends this locally
  to 190/183; the [possession/enrollment constructors](15-recovery-possession-enrollment.md) bring the current local inventory
  to **256 selected functions / 249 explicit postconditions** across eight policy crates and the sharing/signature kernels.
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
  CryptoVerif ran. The repair and later computational games have since passed
  in the fdee2bc hosted security workflow.
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

19. [Login producer and composition](19-login-producer-composition.md): pure byte
    conversion and unbounded nonce accounting, with explicit store/handler gaps.
