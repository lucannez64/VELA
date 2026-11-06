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
| [`src/policy.kush`](src/policy.kush) | the policy, its `ensures` specification, and the negative theorems |
| [`tests/main.kush`](tests/main.kush) | differential tests against the Rust crate |
| [`src/main.kush`](src/main.kush) | benchmark: the same generated inputs through Kush and through Rust |
| [`check-proofs.sh`](check-proofs.sh) | checks the proofs, then injects 19 bugs and requires each to be rejected |

## How the proofs work

The port has the Rust crate's shape: the same types (`bool` flags, `u64`
revisions), the same functions, and each hax `ensures` is a Kush `ensures`
clause on the same function:

```kush
pub fn plan_share_admission(facts: ShareAdmissionFacts) -> ShareAdmissionDecision ! {}
    ensures AcceptFirstContact(permit) => { !facts.has_pin && facts.envelope_authenticated && ...
                                            && permit.revision == facts.candidate_revision }
    ensures ApplyUpdate(permit) => { facts.has_pin && ... && facts.candidate_revision > facts.pinned_revision ... }
    ensures Reject => { !(first contact conditions) }
    ensures Reject => { !(update conditions) }
{ ... }

pub fn stale_revision_update_can_be_applied(facts: ShareAdmissionFacts) -> Bool ! {}
    ensures { !result }
{ ... is_admitted(plan_share_admission(...)) ... }
```

- The compiler proves every clause at every value a function returns, from
  the branch conditions that reach it. The prover is Fourier–Motzkin with
  case splits, and an independent checker in the compiler re-checks each
  certificate. A body that can break a clause does not compile.
- A caller receives the callee's clauses as facts about the call's result.
  The 14 negative theorems use this, as in hax: each one calls
  `plan_share_admission` (or `next_store_generation`, ...) on falsified
  facts and proves `!result`.
- `admission_matches_spec` and `store_generation_matches_spec` are not
  separate functions: Kush clauses cannot call functions, so their bodies
  are written out as the clauses (the `Reject` case as two clauses, one per
  negated condition). A Rust `ensures result == P` is written as
  `result => { P }` plus `!result => { !(P) }`.
- `SharePinPermit.revision` is private to the policy module, as in Rust: other
  modules can neither build a permit nor read the field, only call
  `share_permit_revision` (which promises `result == permit.revision`).
- `next_store_generation` computes `current + 1` without an overflow check:
  the compiler proves `current < u64::MAX` at that point and emits a plain
  add, so the function needs no `panic` effect.

## Results (2026-11-06)

All runs were on the developer machine with the Kush compiler at
`d76b546` (debug build of the compiler).

- **Proofs:** `kush check` proves the 33 `ensures` clauses of the 26 policy
  functions in **0.13–0.17 s** (`kush check src/policy.kush`; the whole package with
  tests and benchmark takes 1.2 s).
  The repository's recorded hax + F* run for the Rust crate took 31 s
  (`security/assurance/proof-logs/current/refinement-5g/vela-client-share-policy.log`),
  measured under different conditions.
- **Proofs are not vacuous:** `check-proofs.sh` injects 17 bugs into the
  policy (dropped lineage, signer or authentication check, replay of an equal
  revision, revision 0, first contact while pinned, the old revision in an
  update permit, a valid update rejected, an update counted as not
  admitted, restoring a deleted item, overwriting a pending commit, an
  unchecked counter overflow, re-accepting a pinned share, a false theorem,
  and the same three bugs in the Rust-named predicates) and two attempts to
  forge or read a permit from another module. All 19 are rejected at compile
  time; each proof error names the clause that no longer holds.
- **Agreement with Rust:** `kush test` compares results with the linked Rust
  crate: all 64 flag combinations × 36 revision pairs including `u64::MAX`
  (decision and permit revision), the generation table including
  exhaustion, and all recovery/acceptance inputs. It also runs the negative
  theorems on samples. 4/4 tests pass.
- **Speed:** `kush run --release` runs 10^8 generated decisions with
  identical checksums on both sides:

  | Kush build | Kush ns/decision | Rust ns/decision | machine |
  | --- | --- | --- | --- |
  | this port | 11.9, 11.9, 11.9 | 3.3, 3.3, 3.4 | quiet (load ≈ 2.5) |
  | this port | 17.4, 19.7, 17.2 | 4.5, 4.6, 4.6 | busy (F*/Z3 runs, load ≈ 9) |
  | Rust-shaped body (calls the predicates) | 23.4, 23.8, 24.1 | 3.3, 3.4, 3.3 | quiet |
  | first port (i64 flags, guarded constructors) | 14.2, 15.7, 15.5 | 3.9, 3.5, 3.4 | quiet |

  The Kush input generator alone (same loop, no policy call) takes
  6.2–8.7 ns, so the policy itself is roughly 4–6 ns per decision against
  Rust's 3.3 ns for generator and policy together. Rust is about 3.5× faster
  overall: LLVM inlines and vectorises the loop, while Kush's Cranelift
  backend does not inline calls and keeps the generator's checked
  multiplication and modulo. Writing the conditions out instead of calling
  the predicate functions halves Kush's time; the proofs are the same.

## What is proved, compared with hax + F*

| Property | hax + F* (Rust) | Kush port |
| --- | --- | --- |
| Every returned decision matches the spec | postcondition `admission_matches_spec` | same clauses, written out |
| Negative theorems about `plan_share_admission` and the state decisions | 14, as postconditions | the same 14, as postconditions |
| Only the policy can mint a permit | private field | private field |
| No arithmetic overflow | proved | proved; the checked add is removed |
| Domain | `bool`, `u64` | `bool`, `u64` |
| Trusted base | hax extraction, F*, Z3, hax proof libraries | Kush compiler (checker, certificate checker, code generator) |

Remaining differences and Kush limits:

- clauses cannot call functions, so the spec predicates are written out
  instead of named;
- there is no struct update syntax (`..facts`), so the negative theorems list
  every field;
- the Kush code generator (Cranelift) does not inline calls, which is why
  `plan_share_admission` writes out the conditions instead of calling the
  predicate functions (see the speed table);
- VELA's Rust code cannot call this policy: Kush builds executables and calls
  Rust, but cannot yet export a library to Rust.

## Reproduction

```bash
cd libVELA/vela-client-share-policy-kush
kush check                       # all proofs
./check-proofs.sh "$(command -v kush)"   # proofs + 19 injected bugs rejected
kush bindgen Bridge.toml --check # generated adapter is current
kush test                        # differential tests (builds oracle/ with cargo)
kush run --release               # benchmark, 10^8 decisions; last two lines are ps/decision
```
