# Recovery-share lifecycle: driver and composition

## Claim

The four recovery-share handlers (`PUT /recovery/share`,
`POST /recovery/share/finalize`, `DELETE /recovery/share`,
`GET /recovery/share`) reach a pure decision driver
(`src/recovery_share_driver.rs`) and nothing else. `step_share_lifecycle` is
total and every event list is covered by
`proofs/fstar/recovery-share-driver-lemmas`:

- a stage/finalize/delete/read instruction is emitted at most once, only from
  its own first stage, and a delete instruction records that it clears the
  active share and the staged split together (`stage_effect_origin`,
  `promotion_effect_origin`, `delete_effect_origin`, `read_effect_origin`,
  `delete_complete_clears_both`);
- a stage/finalize success has publication evidence: the exact guarded update
  applied, or the live row confirmed the exact already-current split
  (`publication_complete_has_evidence`);
- at most one success and at most one failure are ever produced, never both
  (`at_most_one_success`, `at_most_one_failure`, `never_both`);
- a failed request performs no later effect, and a successful delete has
  `deletes_share = deletes_pending = true`.

`proofs/fstar/recovery-share-driver-composition` composes the extracted driver
with the extracted WebAuthn authentication-finish driver and the extracted
possession-proof driver over one shared account share state. For every
interleaving of stage, finalize, delete, read, rotation/freeze, WebAuthn
attempts and possession steps it proves:

- no WebAuthn `ReleaseGrant` decision is counted while the shared active share
  is absent (`stale_releases = 0`) or names another epoch
  (`superseded_releases = 0`);
- there is at most one current split (`active_count <= 1`), the active and
  pending records are never both present, and each names the live epoch;
- the possession path never releases the share (`proof_releases = 0`,
  `proof_effect_never_releases`);
- the publication/delete/read counters are the drivers' own effects, and a
  delete clears both fields in one decision.

## How the handlers are tied to the checked loop

- `src/recovery_share_interpreter.rs` defines `recovery_share_interpreter!`
  once and expands it into `run_share_lifecycle`; hax extracts that function
  (`proofs/fstar/extraction-recovery-share-interpreter/`).
- `serverVELA/vela-server/src/recovery/mod.rs` expands the same macro with
  `await` over four executor structs, one per handler, each holding only that
  request's I/O. SQL text, statuses, messages, store keys and effect order are
  unchanged.
- `security/formal/tests/test_handler_interpreters.py` lists the handlers as
  WIRED: four `await` expansions, no imported/called driver transitions, and
  one macro definition/expansion in the policy crate.
- The executor traits are declared from one signature list (`executor_trait!`);
  under hax each method has `requires(true)`, so the interpreter proof
  quantifies over every executor. Unused methods on a handler's struct refuse
  with `None` and an error slot instead of panicking.

## Mutations (copies under `/tmp/vela-f2-recshare-mut/`, not committed)

| Mutation | Result |
|---|---|
| `mutation-delete-pending.diff`: `begin_delete` no longer records that it clears the staged split | F* fails the `begin_delete` state/effect postcondition (log: `mutation-delete-pending.log`) |
| `mutation-stale-release.diff`: the WebAuthn live-account observation claims `share_present = true` unconditionally | F* fails `auth_release_implies_current`, so a deleted/superseded release would be counted (log: `mutation-stale-release.log`) |

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  observation honestly; the SQL text is reviewed and exercised by
  `integration.rs` (including the competing-split/finalize and epoch-race
  tests) and by `recovery_lifecycle_model.rs`.
- SQL/store linearizability, the guarded updates themselves, WebAuthn
  cryptography, TTL expiry and multi-node replication remain outside the
  proofs.
- The composition models the guarded updates from the reviewed SQL predicates;
  it does not prove the database enforces them.

## Reproduction

```bash
cd serverVELA/vela-recovery-policy
./verify-fstar-recovery-share-driver.sh      # driver + composition
./verify-fstar-recovery-share-interpreter.sh # interpreter extraction + lemmas
```

`driver-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
