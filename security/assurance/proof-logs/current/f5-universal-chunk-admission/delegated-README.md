# F-5 universal independent chunk-admission proof

Evidence for the increment that follows the cherry-picked `57d8bf6`
("Admit mobile sync downloads through verified policy"). It is a separate FIX
commit; `57d8bf6` was not squashed or rewritten and nothing was pushed.

Everything here is produced from the working tree whose policy-side patch has
sha256 `3812c2405234e81887c0289a53e6f7ebc41c8e919972e458f682be28f8644d27`
(base commit `988759389a39997abc75bc8f89808d8ab58f7da4`, the cherry-pick of
`57d8bf6`). Tool versions, argv, counts and artifact hashes are in
`environment.log` and `artifact-hashes.txt`.

## Review finding this answers

`57d8bf6` added hand-written epoch lemmas but left `plan_chunk_download`
"load-bearing" on a self-spec wrapper (`chunk_download_decision_matches_spec`
calls `chunk_download_is_authorized`, which is the same expression) plus one
constant rollback witness (`Some 7`, clock 3). That does not state, let alone
prove, the universal rollback claim an integrator relies on.

This increment keeps the Rust source and therefore the historical extraction
byte-identical, and adds a genuinely independent universal proof over the
**actual extracted planner**:

```
proofs/fstar/chunk-lemmas/Vela_sync_policy_chunk_lemmas.fst
```

## The theorem

For every observation `facts` and every candidate permit `permit`:

```
plan_chunk_download facts = Accept permit
  <=>  aad_binding_verified
    && key_epoch_positive
    && server_lamport >= 1
    && (last_seen_lamport = None
        || server_lamport >= last_seen_lamport)
    && permit.f_lamport = server_lamport
```

and, separately,

```
plan_chunk_download facts = Reject  <=>  the predicate above is false
```

The F* statement of the admission predicate is written over raw
`i64`/`Option i64` values (`chunk_admissible clock last_seen aad epoch`), with
the comparison reversed (`v seen <= v clock`) relative to the implementation,
and it never calls `chunk_download_is_authorized` or
`chunk_download_decision_matches_spec`. `accept_iff_admissible` is about
`plan_chunk_download`, the function the bridges actually call.

"Exact permit clock/epoch fields" in this theorem:

- the permit is exactly `permit_of facts.f_server_lamport` (a one-field record;
  `accept_permit_is_unique` shows no second clock is possible);
- `accepted_permit_is_exact` also fixes `aad_binding_verified = true`,
  `key_epoch_positive = true`, `server_lamport >= 1` and the baseline floor.

The epoch *value* is not in `ChunkDownloadFacts` (the caller reduces it to
`key_epoch_positive`), and the permit has no epoch field; that is a property of
the unchanged `57d8bf6` API and is listed as a limitation below, not hidden.
Adding an epoch to the permit would change the extracted Rust artifact and the
bridge ABI, so it was not done: the unchanged artifact is sufficient for the
universal admission statement.

## Proof structure (20 lemmas)

Guard equivalence and planner equivalence:

1. `authorized_iff_independent_predicate` — the extracted guard, including its
   nested option match, equals the independent predicate (proved by case split
   on the baseline option).
2. `accept_iff_admissible` — the headline equivalence above.
3. `reject_iff_not_admissible` — the refusal direction stated on its own.
4. `accepted_permit_is_exact` — every accepted fact and the exact permit clock.
5. `accept_permit_is_unique` — one permit per observation.
6. `none_baseline_accepts_exactly_positive_bound` — first contact form.

`None` versus `Some 0`:

7. `none_baseline_matches_zero_baseline` — both decide identically for every
   clock (the `>= 1` conjunct already excludes the only clock where a naive
   "None means 0" reading could differ); they stay distinct caller state,
   which the permit does not record.
8. `clock_zero_rejected_without_baseline` — first contact still rejects 0.
9. `clock_zero_rejected_with_zero_baseline` — a recorded zero also rejects 0.

Parameterised old baseline (arbitrary `b`, not the constant 7):

10. `baseline_floor_is_exact` — accept iff `b <= clock` (with the other facts).
11. `stale_clock_rejected_for_any_baseline` — `clock < b` always refuses.
12. `equal_clock_redelivery_admitted` — equal-clock re-delivery is admitted.

Signed clock/epoch negative extremes:

13. `min_i64_clock_rejected` — `i64::MIN` clock refuses for any baseline/flags.
14. `minus_one_clock_rejected` — `-1` refuses even with permissive baseline.
15. `negative_baseline_does_not_admit_nonpositive_clock` — `Some(-7)` cannot
    admit clock 0.
16. `min_i64_baseline_admits_positive_clock` — `i64::MIN` baseline does not
    block clock 1 (the floor is dominated by the positive-clock conjunct).
17. `negative_epoch_flag_rejects_largest_clock` — epoch positivity is
    load-bearing at `i64::MAX`; a signed-negative epoch reaches this kernel as
    `key_epoch_positive = false`.
18. `unverified_aad_rejects_largest_clock` — AAD verification is load-bearing
    at `i64::MAX`.

Nonvacuity of the equivalence:

19. `accept_witness_first_contact` — clock 3 / `None` is accepted with permit 3.
20. `reject_witness_rolled_back` — clock 3 / `Some 7` is rejected.

No lemma uses `assume`, `admit`, `magic`, `unsafe_coerce`, `--lax`,
`--admit_smt_queries` or `--unsafe_tactic_exec`; `verify-fstar-chunk.sh`
strips comments and enforces that, plus the exact counts (11 historical
postconditions, 20 lemmas). No guard was weakened and no Rust postcondition was
changed.

## Counts

| Item | Count |
| --- | --- |
| Rust postconditions changed by this increment | **0** |
| Historical extraction postconditions (`extraction/Vela_sync_policy.fst`) | 11 |
| New hand-written F* lemmas | **20** |
| Focused epoch extraction postconditions (unchanged) | 4 |
| Epoch lemmas (unchanged) | 6 |
| Policy tests (cargo) | 6 (was 5; one new boundary grid) |

`cargo hax` printed `hax: unchanged file
./proofs/fstar/extraction/Vela_sync_policy.fst`, and
`git status --porcelain libVELA/vela-sync-policy/proofs` was clean after the
full run. Artifact hashes:

- historical artifact: `e23bc7556ebb25eaf091ae5f8dd3718f490330e7efd9ea9245714655b1f14add`
- chunk lemmas: `f56e4efeca9ae5867ca03ea6e52d203c7645e7fbfd0e3a988e7c39fe1561ca8f`
- focused epoch artifact: `0b7febd0c062d955831133476fba4afc8d9616b83e6be49b63d6ba10fe404393`
- chunk script: `ccc77f79f2b9ced84a75bf1000193a48ec3ca46cb3e35c3917ba647eb9efa62e`

## Module-name collision (same `Vela_sync_policy` in both artifacts)

`proofs/fstar/extraction/Vela_sync_policy.fst` (historical, 11 contracts) and
`proofs/fstar/extraction-epoch/Vela_sync_policy.fst` (focused epoch kernel)
declare the same F* module name. `verify-fstar-chunk.sh` is a separate
`fstar.exe` invocation with a deliberately restricted include path:

```
--include proofs/fstar/extraction            # historical artifact
--include proofs/fstar/chunk-lemmas
# never proofs/fstar/extraction-epoch
```

The focused epoch script keeps its own invocation and include path. An
accidental resolution would also fail loudly, because the epoch module does not
declare `t_ChunkDownloadFacts`, `t_ChunkDownloadPermit` or
`plan_chunk_download`; the fresh chunk run in `fstar-chunk.log` verifies both
the historical module and the lemma module from source (`--cache_off`).

## Wiring

`verify-fstar.sh` now runs, in order:

1. `cargo test`;
2. historical `cargo hax into` extraction into `proofs/fstar/extraction`;
3. `fstar.exe` over that extraction (unchanged selected set);
4. `verify-fstar-epoch.sh` (separate invocation, focused artifact);
5. `verify-fstar-chunk.sh` (separate invocation, historical artifact +
   chunk lemmas).

`fstar-full-verify.log` is that complete run; it ends with
`All verification conditions discharged successfully` and
`chunk-lemma source gate: 11 historical postconditions, 20 hand-written lemmas`.

The local count/escape gate lives in `verify-fstar-chunk.sh`. The global
`security/assurance/proof-boundary.json`, the assurance manifest, the
correspondence inventory and CI integration are parent-owned and were not
modified.

## Tests

`policy-tests.log`: 6 tests pass. The new
`chunk_admission_boundary_grid_matches_independent_predicate` crosses

- clocks: `i64::MIN`, `-1`, `0`, `1`, `2`, `5`, `i64::MAX`;
- baselines: `None`, `Some(0)`, `Some(1)`, `Some(5)`, `Some(i64::MIN)`,
  `Some(i64::MAX)`;
- AAD/epoch flags: all four combinations,

checks the planner against the independent predicate at every point, checks
that every permit carries the admitted clock, checks `None`/`Some(0)` agree,
and includes explicit nonpositive/extreme boundary assertions plus both
outcomes (nonvacuity).

## Trusted computing base

The theorem is about the pure policy module only. Trusted:

- imported F* models: `Core_models`/`Rust_primitives` machine integers
  (`int_t I64`, `v`, `mk_i64`, `>=.`/`=.`), the `Option` model;
- `Prims`, `FStar`, `LowStar`, `C`, `Spec.Loops`, `TestLib` and hax-lib's
  proof libraries (already cached);
- hax extraction of this crate, the F* kernel/checker, Z3, the Rust compiler
  used for extraction, and the OS.

**No SQL/storage layer, JSON envelope parsing, JNI, Swift/Kotlin wrapper, C FFI
buffer handling or other bridge glue is in this proof TCB.** No such glue is
proved, assumed or modelled here.

## Open limitations (not hidden by the theorem)

- `aad_binding_verified` remains a **conditional input** to the policy. The
  runtime bridges in `57d8bf6` derive it only after a successful sealed
  `open_fleet_chunk`, but this module does not prove that derivation from
  ciphertext bytes, nor that a future caller cannot pass `true` without a real
  open. The theorem starts from the observation.
- `key_epoch_positive` is a caller-reduced boolean. The epoch integer
  comparison is proved separately by the focused epoch kernel
  (`plan_sync_epoch_match`); this module proves the positivity conjunct is
  required and that a false (signed-negative) epoch refuses.
- The permit carries exactly the admitted clock, not the epoch value (API
  unchanged from `57d8bf6`).
- Caller ordering (fetch → admit → decode → merge → persist → record
  baseline), crash atomicity, Android/iOS baseline storage and the unverified
  Swift/Kotlin/JNI/JSON glue remain outside this proof, as recorded in
  `57d8bf6`'s evidence.
- Hax extraction fidelity is trusted; the local gate checks shapes and counts,
  not the extractor.

## Reproduction

```
cd libVELA/vela-sync-policy
export PATH=/tmp/vela-fstar-prebuilt/fstar/bin:$HOME/.local/opt/vela-tools/bin:$HOME/.local/opt/vela-tools/opam/vela-hax/bin:$PATH
export CARGO_HOME=/tmp/vela-hax-cargo
export OPAMROOT=$HOME/.local/opt/vela-tools/opam
export CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-700776df/target
/home/hirew/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh        # full wiring
/home/hirew/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-chunk.sh  # chunk lemmas only
```
