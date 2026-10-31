# Typed journal encoding equivalence: local evidence

This parent working-tree run integrates delegated `1190d6e` as `0b4ef27`,
then corrects claim scope and CI/reproduction issues found by internal review.
It is not an external audit. Hosted reproduction of this F★ step is pending.
The extracted Rust inventory stays at 212 postconditions / 219 selections.

`fstar.log` is a fresh parent check of the final module, with caching disabled,
F★ 2025.10.06 / Z3 4.13.3, full version header, source SHA-256 and argv:

```bash
~/.local/opt/vela-tools/bin/vela-heavy env \
  VELA_FSTAR_BIN=/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe \
  security/formal/m28-trace-equivalence/verify.sh
```

It checks step/trace lifting and projection between typed, initialized,
single-slot encodings. The transfer theorem takes a safety proof as input;
neither all-pairs goal is proved by this artifact. The two directed embeddings
connecting these encodings to actual Tamarin traces remain unproved. See the
[scope and mapping](../../../../formal/m28-trace-equivalence/README.md).
No concrete Rust/filesystem refinement is established.

`journal-runner.log` and the two Tamarin logs record the earlier parent full
gate: ten M28 and eleven M29 verdicts, no falsified goals or warnings. That
run preceded the final shared verifier's cache-off/version/hash logging and
comment-only scope corrections. Its older F★ output is superseded by
`fstar.log`; Tamarin rules, guards, restrictions and lemmas are unchanged.
The full run used `VELA_PROOF_OUT=/tmp/vela-parent-journal-equivalence` and
`VELA_FSTAR_BIN=/tmp/vela-fstar-prebuilt/fstar/bin/fstar.exe` through
`vela-heavy security/formal/run-share-journal-proofs.sh`.

`source-guard-tests.log` records six regression tests, including rejected
proof escapes/options and required Git executable modes. This is a source
drift guard, not a proof soundness or semantic-adequacy certificate.
`prebuilt-activation.log` checks an already installed official F★ release;
it does not claim a fresh network download. CI's standalone installer pins the
release archive SHA-256 and caches F★ independently of hax. No hax rebuild is
needed for this handwritten module. All local heavy runs used the serialized
3 GiB / no swap / one-worker wrapper.
