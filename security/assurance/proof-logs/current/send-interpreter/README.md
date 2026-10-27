# One-off share links: handler-to-driver interpreter

## Claim

Each one-off share-link handler reaches its driver only through one loop, and
that loop is checked. For every executor (any implementation of `SendIo`, any
behaviour), the extracted `run_send`:

1. calls exactly the executor method for the effect the driver has just
   emitted, with that effect's permit argument (`insert_send permit`,
   `delete_link permit`), one call per turn, and none once the driver reached a
   verdict (`run_send_is_run_ev`);
2. receives observations that each answer the effect they were returned for,
   and ends in `run_from_create`, `run_from_fetch` or `run_from_delete` for that
   list (`run_ev_follows_the_driver`);
3. reaches a verdict (`CompleteCreate`, `CompleteFetch`, `CompleteDelete`,
   `Fail`) within its 3-turn budget (`run_ev_reaches_a_verdict`);
4. therefore ends in a state where every per-request send theorem holds:
   `create_interpreter_theorem` (bounded permit from `send_effect_is_sound`),
   `fetch_interpreter_theorem` (delivery count ≤ 1, delivery implies consume,
   failure never delivers) and `delete_interpreter_theorem` (no-owner requests
   end failed without deleting; `deleted ⇒ succeeded`).

The lemma module has 20 top-level definitions, 10 of them lemmas, including the
two-term SMT pattern `[SMTPat (fold_range …); SMTPat (iter_turn …)]`; the
`iter_turn_is_run_ev` equality is stated explicitly before the final
`run_send == …` assertion.

The concurrent at-most-one-fetch/delete statements are proved over the
extracted driver in `../send-driver/` (`send-driver-composition`), not here.

## How the handlers are tied to the checked loop

- `serverVELA/vela-share-policy/src/send_interpreter.rs` defines the loop once
  as `send_interpreter!`. `run_send` expands it synchronously; hax extracts
  that function (`proofs/fstar/extraction-send-interpreter/`).
- `serverVELA/vela-server/src/send.rs` expands the same macro with `await` in
  `post_share_link`, `get_share_link` and `delete_share_link`, over executors
  that hold all I/O for their path (`CreateSendIo`, `FetchSendIo`,
  `DeleteSendIo`). Unused methods for a request kind report a storage failure
  rather than panicking; the driver's request kind makes them unreachable.
- `security/formal/tests/test_handler_interpreters.py` requires exactly three
  `await` expansions in `send.rs`, forbids importing or calling driver
  transitions there, and requires the policy crate to define the macro once.
- The executor trait is declared from one signature list (`executor_trait!`):
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor.

## Mutations (copies of the extraction, not committed)

See `../send-driver/README.md`. The owner and single-use mutations also break
the interpreter corollaries because they change the driver the loop runs.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (SQL text, response fields and messages reviewed; exercised
  by `integration.rs`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- SQL atomicity and linearizability, clocks and the `sends` row schema are
  outside this module.

## Reproduction

```bash
cd serverVELA/vela-share-policy
./verify-fstar-send-driver.sh       # driver extraction + lemmas + composition
./verify-fstar-send-interpreter.sh  # interpreter extraction + lemmas
python3 ../../security/formal/tests/test_handler_interpreters.py  # from repo root
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).
No hosted run was recorded for this increment.
