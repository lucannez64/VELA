# Concurrent vault key-rotation composition

## Claim

`serverVELA/vela-rekey-policy/proofs/fstar/rekey-driver-composition/Vela_rekey_policy_rekey_driver_composition.fst`
composes the **extracted** rotation driver (`Vela_rekey_policy.Rekey_driver`)
over one account's shared key row (`key_epoch`, `rekey_state`,
`rekey_starter`, `rekey_id`, `last_rekey_*`).

A schedule is any finite interleaving of actions. `Spawn` starts a `start`,
`capsules`, `commit` or `abort` request from any device or web session, with
any rotation-id and epoch headers. `Step i c` makes request `i` perform the
executor call for the effect its own driver emitted last. The scheduler picks
the outcome `c`: I/O failures, pacing, probe results, clock expiry, and the
CAS's other SQL clauses. Every observation about the key row is computed from
the live world at the step the handler reads it. The freeze CAS, the commit
CAS and `rollback_rekey` evaluate their SQL guard against the live row and
write in that same step.

Counters are keyed on the driver's decisions: a commit counts when the
driver's `committed` flag rises, an abort when the rollback it emitted wins,
and a web-session step when the handler would make any executor call for a
web-session request.

## Exact theorems

For every schedule (`composition_theorem schedule : Lemma (inv (run_world
initial schedule))` and its corollaries):

1. `at_most_one_commit_per_epoch`: the epochs commits were decided from are
   pairwise distinct, and no commit is decided from an epoch that already
   committed.
2. `no_commit_after_abort`: no rotation commits after its abort (explicit,
   timeout rollback, or failed freeze transaction), and no committed rotation
   is rolled back.
3. `committed_ids_are_unique`.
4. `committed_and_aborted_are_disjoint`.
5. `commit_only_after_completeness`: a commit is decided only by a request to
   which both completeness probes returned empty.
6. `starter_only_authority`: every commit and every winning abort removes a
   rotation the request's own device started. The abort SQL
   (`rollback_rekey`) does not check the starter; the driver's load-time
   check does.
7. `web_session_never_authorizes`: no executor call is made for a web
   session.

## Non-vacuity

Witnesses in the module: a full start→commit run commits; a second commit, a
non-starter abort, a commit of an aborted rotation and a web session are each
refused; the starter's abort wins.

`verify-fstar-rekey-driver-composition-mutations.sh` builds four driver
mutants under `/tmp`, never touching the checked-in extraction. For each, the
composition must fail to verify, and a witness module must show the matching
counter becomes positive:

| Mutant | Removed decision | Counter that fires |
|---|---|---|
| `starter` | abort/commit starter checks | `w_non_starter_abort` |
| `commit-skip` | commit on a lost commit CAS | `w_commit_after_abort` |
| `completeness` | failed capsule probe treated as complete | `w_unchecked_commit` |
| `web` | web-session refusal and its contract clause | `w_web_step` |

`mutations.log` is the run on the hosted commit.

## Assumptions

Each SQL statement is atomic and linearizable. The freeze transaction is
linearized at its freeze CAS, and a failed transaction commit reverts exactly
that write. Rotation ids are fresh per freeze CAS (server UUIDs). The handler
performs exactly the effect its driver emitted, in the step it observes the
result (the interpreter proofs cover the loop; the executor methods' SQL is
F-1). Capsule writes, chunk rows, the clock and the readiness/completeness
tables are abstracted into scheduler choices. No new bug was found.

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-rekey-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-rekey-driver-composition-mutations.sh
```

Budget: fuel 1, ifuel 1, `--z3rlimit 100`, `--split_queries always`; the
module checks in about 62 s.
