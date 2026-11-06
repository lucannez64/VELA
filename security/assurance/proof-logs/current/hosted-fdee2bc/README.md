# Hosted baseline fdee2bc

Full head: `fdee2bcf289fb13a78179ee5654e6359bd1b37b6`.
[Security workflow 40116416383](https://github.com/lucannez64/VELA/actions/runs/40116416383)
and all 15 PR checks reported success. Metadata is retained unchanged in
`security-workflow.json` and `pr-checks.json` (the latter includes the historical
PR description at download time).

Downloaded refinement/symbolic artifacts retain the successful sync checks
(historical eleven-contract extraction, focused four-contract epoch extraction,
six handwritten epoch lemmas and twenty handwritten chunk lemmas), journal F*
encoding check, journal runner summary, and symbolic summary. `boundary-excerpt.log`
is the exact job-log line reporting fourteen artifacts /249 explicit Rust
postconditions; the corpus has 256 selected functions. `computational-verdicts.txt`
is an index derived from the ten downloaded CryptoVerif model logs (nine positive
results and the intended legacy v1 control), not a replacement for full logs.
Full artifact bundles remain attached to the linked workflow.

The [iOS workflow](https://github.com/lucannez64/VELA/actions/runs/40116416369)
also reports success after the decode-fixture correction. Its downloaded console
log was incomplete, so this package asserts no independently extracted current
iOS per-test count. The previous head compiled Swift and ran 90 tests with the
single fixture failure documented separately.

This is a hosted scoped-proof baseline, not whole-system refinement or an external
audit. It predates the recovery-redemption lifecycle increment now under development.
