# Client share admission policy in Kush (experiment)

A port of [`vela-client-share-policy`](../vela-client-share-policy/) (Rust,
proved with hax + F*) where the program **and** its proofs are written in
[Kush](https://github.com/lucannez64/kush). Rust appears only as a dependency:
the original crate is linked through a generated adapter
([`Bridge.toml`](Bridge.toml), [`oracle/`](oracle/)) and used as a
differential test oracle and benchmark baseline. It is not used by the policy.

This is an evaluation of what Kush can do today, not a replacement for the
production crate: VELA's Rust code cannot call it (Kush builds executables and
can call Rust, but cannot yet export a library to Rust).

## Layout

| File | Content |
| --- | --- |
| [`src/policy.kush`](src/policy.kush) | the policy, its specification as guarded constructors, and the lemmas |
| [`tests/main.kush`](tests/main.kush) | differential tests against the Rust crate |
| [`src/main.kush`](src/main.kush) | benchmark: the same generated inputs through Kush and through Rust |
| [`check-proofs.sh`](check-proofs.sh) | checks the proofs, then injects 12 bugs and requires each to be rejected |

## How the proofs work

Kush has no function postconditions (hax's `ensures`). Its executable proof
tool is the erased arithmetic precondition `erased p: { linear facts }`,
discharged at each call site from the branch facts that reach it by a
Fourier–Motzkin decision procedure. Each certificate is re-checked by an
independent checker in the compiler.

The port uses that as follows:

- **Every result is built by a guarded constructor** whose precondition is the
  spec of that result. `accept_first_contact` requires exactly the Rust
  `first_contact_is_admissible`, `apply_update` requires
  `update_is_admissible`, and every rejection requires one *reason*
  (`auth == 0`, `has_pin == 1 && cand <= pinned`, ...). If any return site in
  `plan_share_admission` is not justified by the checks before it, the file
  does not compile.
- **Lemmas** are uncalled functions whose bodies only type-check if their
  hypotheses are contradictory. They prove that every rejection reason
  excludes both admissions (so a rejection always satisfies the Rust
  `Reject` spec), that first contact and update are exclusive, and they
  restate each Rust negative theorem (`unauthenticated_share_can_be_admitted`,
  `stale_revision_update_can_be_applied`, `pinned_share_can_restart_as_first_contact`,
  `exhausted_generation_can_commit`, ...).
- The same pattern covers `initial_acceptance_is_authorized`,
  `next_store_generation` and `recovery_should_apply` (the `||` in recovery
  becomes two accepting constructors).

Kush's `{ ... }` fragment needs integers, so the encoding differs from Rust:

- flags are `i64` with 1 = true and 0 = false. Any other value is malformed
  and rejected first, which is itself proved (a garbage `has_pin` cannot
  reopen first contact);
- revisions and generations are `i64` in `0 ..= i64::MAX`, with `i64::MAX` in
  the role of `u64::MAX`. Negative values are malformed.

## Results (2026-11-06)

All runs were on the developer machine with the Kush compiler at
`816561d`.

- **Proofs:** `kush check` discharges all 79 proof obligations (53 at the
  return sites of the four policy functions, 26 in lemma bodies) in
  **0.14 s**, using a debug build of the compiler. The repository's recorded hax + F* run for the Rust crate took
  31 s (`security/assurance/proof-logs/current/refinement-5g/vela-client-share-policy.log`),
  measured under different conditions and with stronger guarantees (see
  below).
- **Proofs are not vacuous:** `check-proofs.sh` injects 12 bugs (dropped
  lineage check, replay of an equal revision, missing authentication, first
  contact while pinned, revision 0, update from a foreign signer, skipped
  domain check, wrong rejection reason, restoring a deleted item, overwriting
  a pending commit, re-accepting a pinned share, and a false lemma). Each one
  is rejected at compile time, and the error names the exact conjunct that can
  no longer be proved.
- **Agreement with Rust:** `kush test` compares every result with the linked
  Rust crate. That covers all 64 flag combinations × 36 revision pairs
  (decision and permit revision), the generation table, and all
  recovery/acceptance inputs, plus malformed inputs. 4/4 tests pass.
- **Speed:** `kush build --release` runs 10^8 generated decisions with
  identical checksums on both sides:

  | | ns per decision (3 runs) |
  | --- | --- |
  | Kush (Cranelift, `--release`) | 14.2, 15.7, 15.5 |
  | Rust crate (`cargo --release`, same loop in Rust) | 3.9, 3.5, 3.4 |
  | Kush input generator alone | 5.2 |

  Kush is about 4× slower here. The likely causes are Cranelift rather than
  LLVM, no inlining of the small constructor calls, and checked
  multiplication/modulo in the generator. The policy itself has no
  arithmetic, only comparisons.

## What is proved, compared with hax + F*

| Property | hax + F* (Rust) | Kush port |
| --- | --- | --- |
| Every returned decision matches the spec (`admission_matches_spec`) | proved as a postcondition of `plan_share_admission` | proved per return site, by the guarded constructors plus the reason lemmas |
| Negative theorems | proved about compositions with `plan_share_admission` | proved as lemmas about the spec conditions. They apply to `plan_share_admission` because its only accepting returns require those conditions; that "only" is by construction, not a checked theorem |
| Decisions can only be produced by the policy | Rust private field on `SharePinPermit` | **not enforced**: Kush has no private fields, and enum constructors are public |
| No arithmetic overflow | proved | `current + 1` is shown safe by its precondition, but Kush still emits a checked add (the `panic` effect stays in the row) |
| Domain | `bool`, `u64` | `i64` flags (malformed values rejected and proved), `i64` revisions |
| Trusted base | hax extraction, F*, Z3, hax proof libraries | Kush compiler (checker, independent certificate checker, code generator) |

Kush limits met along the way:

- no postconditions or refinement return types, so a fact proved inside a
  function cannot flow to its caller;
- the arithmetic fragment rejects `Bool` atoms and `u64` terms, and a goal
  with no variables (such as `{ 0 >= 1 }`) is not proved even from
  contradictory facts (the lemmas use `v >= 1 && v <= 0` instead);
- proofs never remove runtime overflow checks;
- even `0 - 1` on constants needs the `panic` effect;
- no field privacy;
- no library output for Rust callers.

## Reproduction

```bash
cd libVELA/vela-client-share-policy-kush
kush check                       # all proofs
./check-proofs.sh "$(command -v kush)"   # proofs + 12 injected bugs rejected
kush bindgen Bridge.toml --check # generated adapter is current
kush test                        # differential tests (builds oracle/ with cargo)
kush run --release               # benchmark, 10^8 decisions; last two lines are ps/decision
```
