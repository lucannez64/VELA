# Journal source bridge (P2b, P2c, P2d) evidence

This is the evidence for the Tamarin↔F★ source bridge of the share-journal
model `security/formal/m28_share_journal.spthy`. The bridge lives in five new F★
modules under `security/formal/m28-trace-equivalence/`. Their exact statements
are listed in that directory's README. This file records what is proved, what
is trusted, how it was checked and what changed on the way.

## What is proved

Over an F★ source semantics of M28 (below):

1. **Projection and embedding (P2b, P2d).** Take any trace of the original
   seven-rule system that satisfies the `Increasing` restriction, and any
   slot. Its projection to that slot is a `reach_core proper_subterm 'initial'
   item` trace of `M28TraceEquivalence`, with full source terms as revisions,
   transactions and payloads (`M28_source_bridge.embed`). The lift of that
   trace is a `reach_lift` trace (`embedded_lift`).
2. **Admissible lift and erasure (P2d).** Every original trace is a trace of
   the Chain-instrumented system (the `.spthy` as written) with the same
   labels and actions. The instrumented state is the original state plus one
   Chain fact per durable fact, as multisets (`lift_source`). Conversely,
   erasing Chain maps instrumented traces to original traces (`erase_source`).
   Any all-traces or exists-trace property of action traces therefore carries
   between the two systems (`transfer_*`, `witness_*`). That includes Tamarin's
   own verdicts on the instrumented model.
3. **All ten M28 lemmas on source traces.** Each `.spthy` lemma is an F★
   formula of the same name over source action traces.
   - `original_universal_lemmas` / `instrumented_universal_lemmas`: the eight
     all-traces lemmas hold for every restricted trace of both systems:
     `open_has_matching_content_and_pin`,
     `application_requires_prior_durable_journal`,
     `cleanup_requires_prior_durable_vault`, `commit_uses_snapshot_generation`,
     `each_transaction_applies_at_most_once`, `pins_advance_on_every_commit`,
     `committed_pins_never_decrease` and `a_generation_commits_at_most_once`.
   - `original_exists_lemmas` / `instrumented_exists_lemmas`:
     `recovery_is_reachable` and `two_successive_commits_advance` hold on one
     concrete 18-step restricted trace of both systems (`M28_source_witness`).
     In that trace the attacker derives both journal inputs from public names,
     and the Fresh rule draws every fresh name.
4. **Derivability and freshness (P2c, `M28_source_semantics`).**
   - `derivable` is Tamarin's message deduction for the M28 signature. It is
     monotone, yields messages, and is fresh-name confined: a derivable term
     contains only fresh names already in the knowledge (`fresh_name_secret`).
   - On the witness, the attacker learns the slot name, yet the initial vault
     item is provably not derivable (`witness_item_secret`). So source `In`
     inputs are strictly fewer than the encoding's arbitrary inputs.
   - `global_freshness` is Tamarin's global uniqueness of `Fr` names, stated as
     a counting invariant: every drawn name is either an unconsumed `Fr` fact or
     has been consumed exactly once, and no name is drawn twice. The embedding
     uses it for transaction non-reuse and for slot uniqueness.

The two all-pairs goals now use Tamarin's `<<` on the full term algebra
(`sterm_order`), not only the unary `term_order` fragment.

## What is trusted

- **The F★ source semantics is Tamarin's semantics for M28.** This covers:
  - multiset rewriting modulo the builtin pairing equations, with linear and
    persistent facts;
  - the built-in Fresh, ifresh, irecv and isend rules as explicit steps (the
    isend `K(x)` action is not recorded; no lemma or restriction mentions it);
  - message deduction as the inductive `derivable`;
  - restrictions as filters on whole traces;
  - timepoints as trace indices, and the reading of each lemma formula.

  Messages are normal forms over names, `successor/1`, `fst/1`, `snd/1` and
  pairs. Tamarin 1.12.0 lets the attacker send an irreducible `fst($c)`; the
  probe is [`fst-probe.spthy`](fst-probe.spthy), verified with no
  wellformedness warning. So P2a's `fn_symbol` gained `Fst` and `Snd`.
- **The P2a rule schemas are the `.spthy` rules.**
  `security/formal/check-m28-transcription.py` parses both files
  independently. It rejects any difference in:
  - the rule set, or any rule's premises, actions or conclusions (names,
    `!` marks, argument terms);
  - the fact inventory (18 symbols with arities);
  - `functions: successor/1` (no builtins, no equations);
  - the single restriction;
  - the lemma names and kinds against `m28_universal` and `m28_exists`.

  `tests/test_m28_transcription.py` checks that 13 mutations are rejected. This
  is a syntactic drift check, not a parser proof.
- F★ 2025.10.06, its library, Z3 4.13.3 and the toolchain.

The F★ proofs do not use the Tamarin verdicts. Those ten verdicts (and M29's
eleven) are unchanged, and remain an independent check of the instrumented
model.

## Changes to existing proof files

- `M28TraceEquivalence.fst`: **`split` bug fixed.** `SplitThere` gave
  `split (x::l) y rest`, so a PersistJournal that consumed one Snapshot also
  discarded every Snapshot listed before it. Tamarin removes exactly one
  occurrence, and the source could not be embedded into that. It now gives
  `split (x::l) y (x::rest)`. Every earlier theorem re-verifies unchanged (none
  inspected the dropped elements). The header comment now points to the bridge.
- `M28_source_terms.fst`: `fn_symbol` adds `Fst` and `Snd` (see above). The
  P2a theorems are unchanged.
- `m28_share_journal.spthy`: header comment only. Rules, restriction and
  lemmas are unchanged, and the drift check ignores comments.

## Commands and results

See [`verify.log`](verify.log) and [`metadata.txt`](metadata.txt).

```sh
VELA_FSTAR_BIN=$HOME/.local/opt/vela-formal-fstar-2025.10.06/fstar/bin/fstar.exe \
  security/formal/m28-trace-equivalence/verify.sh
python3 -m unittest discover -s security/formal/tests -p 'test_m28_*.py'
```

The build box was unreachable during this work, so the gate ran locally,
capped at 3 GiB, half a CPU core and nice 19 (`systemd-run --user`). Inside that
cap the gate's own `bounded.sh` was skipped with `VELA_BOUNDED=1`, and
`VELA_PROOF_TIMEOUT` was raised to 1500 s for the slower CPU share.
`verify.sh` runs:

1. `check-m28-semantic-proof.py`;
2. `check-no-proof-escapes.py` (no `assume`, `admit` or `axiom` anywhere);
3. `check-m28-transcription.py`;
4. all seven modules in one F★ `--cache_off --z3rlimit 100 --z3version 4.13.3`
   invocation.

No solver option is set inside the new modules.

After merging the T8 seed shim, the same gate passed under Z3 seeds 1, 2 and
3 (`security/assurance/z3-seed/verify-fstar-seeded.sh SEED
security/formal/m28-trace-equivalence/verify.sh`, same local caps). The runs
took 148, 130 and 140 s; see [`verify-seed-1.log`](verify-seed-1.log),
[`verify-seed-2.log`](verify-seed-2.log) and [`verify-seed-3.log`](verify-seed-3.log).
Each log shows the `--z3seed` argument reaching F*.

Tamarin 1.12.0 (Maude 3.5.1) was rerun on the build box once it was
reachable again, using the journal runner's own Tamarin loop on the committed
sources: M28 10 verified and M29 11 verified, 0 falsified, 0 warnings
([`tamarin-runner.log`](tamarin-runner.log), with both summaries). The F★ part
of the runner ran locally as above, because the box mirror has no `.git` for
the git-based checks. The `.spthy` change is to its header comment only.
Rust files are unchanged.
