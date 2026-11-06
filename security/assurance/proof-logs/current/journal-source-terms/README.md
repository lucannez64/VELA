# Journal source terms (P2a) evidence

Fresh evidence for `security/formal/m28-trace-equivalence/M28_source_terms.fst`,
the P2a source-term representation for M28. The module transcribes the term
language, facts and seven rule instances of
`security/formal/m28_share_journal.spthy`, defines Tamarin's strict-subterm
order `<<`, proves its order laws and well-foundedness, and proves an
injective embedding of the `'initial'`/`successor` revision fragment into the
concrete term type of `M28TraceEquivalence` with the source order matching the
existing `term_order` record. It is a handwritten transcription checked by F*;
it is not a parser, a trace embedding or a Tamarin proof.

## Command

The gate was run through `vela-heavy` from this worktree:

```sh
VELA_FSTAR_BIN=/home/hirew/.local/opt/vela-formal-fstar-2025.10.06/fstar/bin/fstar.exe \
VELA_STEP_TIMEOUT=3600 \
~/.local/opt/vela-tools/bin/vela-heavy \
  security/formal/m28-trace-equivalence/verify.sh
```

`verify.sh` runs `check-m28-semantic-proof.py` on the existing module,
`check-no-proof-escapes.py` over the tracked F* corpus, prints the pinned F*
version and both module hashes, and verifies
`M28TraceEquivalence.fst` and `M28_source_terms.fst` with
`--cache_off --z3rlimit 100 --z3version 4.13.3 --include <module-dir>`.

The full journal runner was also run through `vela-heavy`:

```sh
VELA_FSTAR_BIN=/home/hirew/.local/opt/vela-formal-fstar-2025.10.06/fstar/bin/fstar.exe \
VELA_STEP_TIMEOUT=3600 VELA_PROOF_OUT=<temporary-dir> \
~/.local/opt/vela-tools/bin/vela-heavy \
  security/formal/run-share-journal-proofs.sh
```

## Results

- `check-m28-semantic-proof.py`: passed.
- `check-no-proof-escapes.py`: 169 tracked F* files, no proof escapes, no
  unimplemented interfaces.
- F* 2025.10.06: `M28TraceEquivalence` and `M28_source_terms` both verified;
  all verification conditions discharged successfully, 0 warnings, 0 local
  assumptions.
- `M28_source_terms.fst` SHA-256:
  `20259d38e29e24e813941eb5cdca227a2950d199c2c4a89d71ce971b982bdc1f`
  (646 lines).
- `M28TraceEquivalence.fst` SHA-256 (unchanged):
  `739c530661a3bbbd49051fb8490f81ed0c42b6b49c4809e3e32dd6dcdbc2e16c`.
- The Tamarin models, rules, restrictions and guards were not changed. The
  journal runner re-ran M28 and M29: 10 M28 and 11 M29 lemmas verified,
  0 falsified, 0 warnings. Their existing verdicts remain the separate
  instrumented-model results reported in
  `proof-logs/current/journal-all-pairs/README.md` and
  `proof-logs/current/journal-inventory/README.md`. The runner summary is in
  `journal-runner.log`; the exact count is also in `metadata.txt`.
- No Rust files were changed; the extraction/postcondition inventory is
  unchanged.

## Scope

- Only the unary `'initial'`/`successor(...)` fragment is mapped to the core
  `term` type. The core type has no name, variable or pair constructors;
  arbitrary adversary `next_revision` terms from
  `In(<next_revision, payload>)` are represented in `sterm`; those outside the
  fragment are not mapped.
- M28 declares `functions: successor/1` and no `equations:` or `builtins:`
  block; pairing is Tamarin's syntactic tuple constructor. This evidence does
  not claim a `.spthy` parser proof or any equational-theory handling beyond
  that free algebra.
- Global `Fr` freshness, `In` derivability, multi-slot projection and the
  actual Tamarin-trace embedding remain open (P2b/P2c/P2d). Facts are
  transcribed as multisets, not extracted from source traces.
- The source guard and arity checks are drift checks, not soundness
  certificates.
