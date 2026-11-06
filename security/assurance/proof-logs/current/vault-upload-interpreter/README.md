# Vault chunk upload/read: handler-to-driver interpreters

## Claim

`PUT /vault/chunk/:id` and `GET /vault/chunk/:id` reach their drivers only
through one loop each, and both loops are checked. For every executor (any
implementation of `UploadIo`/`ReadIo`, any behaviour), the extracted
`run_upload` and `run_read`:

1. call exactly the executor method for the effect the driver has just emitted,
   with that effect's argument (the write permit), one call per turn, and none
   once the driver reached a verdict (`run_upload_is_run_ev`,
   `run_read_is_run_ev`);
2. receive observations that each answer the effect they were returned for, and
   end in `run_from_request request evs` (`read_run_from_request` for the read
   driver) for that list (`run_upload_ev_follows_the_driver`,
   `run_read_ev_follows_the_driver`);
3. reach a verdict (`Complete`/`Fail`, `Serve`/`Fail`) within the budget of 7
   upload effects and 2 read effects (`run_upload_ev_reaches_a_verdict`,
   `run_read_ev_reaches_a_verdict`);
4. therefore end in a state where every per-request upload/read theorem holds:
   a response implies a matched guarded write, a shadow response implies the
   activity refresh, an authoritative response implies the publication, shadow
   writes keep a shadow route, and success and failure exclude each other
   (`run_upload_theorem`, `run_read_theorem`).

The loop invariant is the driver's own transition-soundness predicate
(`upload_state_is_sound` + `upload_effect_is_sound`), so the same extracted
functions also prove that the handler's loop preserves the state invariant the
driver's Rust postconditions describe.

## How the handlers are tied to the checked loops

- `serverVELA/vela-rekey-policy/src/vault_upload_interpreter.rs` defines each
  loop once (`upload_interpreter!`, `read_interpreter!`); `run_upload` and
  `run_read` expand them synchronously and hax extracts those functions
  (`proofs/fstar/extraction-vault-upload-interpreter/`).
- `serverVELA/vela-server/src/vault/chunk.rs` expands the same macros with
  `await` over `PutChunkIo`/`GetChunkIo`, which hold all of the request's I/O:
  the epoch resolution, the shadow attempt, the quota, the guarded
  insert/update, the zero-row re-resolution, the version read-back, the
  rotation-activity refresh, the publication and the row lookup — one async
  method per effect, each returning only its observation type. The schema lock,
  request parsing and response rendering stay outside the loop.
- `security/formal/tests/test_handler_interpreters.py` requires exactly one
  `await` expansion of each macro in the handler, forbids importing or calling
  driver transitions there, and requires the policy crate to define each macro
  once and expand it once.
- The executor traits are declared from one signature list (`executor_trait!`);
  under hax every method gets `requires(true)`, so the proof assumes nothing
  about the executor.

## Executor methods

`UploadIo` (upload): `resolve_epoch`, `authorize_shadow` (returns `None` when
the attempt lookup failed), `enforce_quota`, `guarded_write(permit)`,
`recheck_state`, `reread_version`, `record_shadow_activity`, `publish`.

`ReadIo` (read): `read_epoch` (returns `None` when the served-epoch lookup
failed), `lookup_chunk`.

## Driver changes this needed

Two effects have a *lookup* whose storage failure the driver did not model, so
a handler error would have escaped the loop. Both are additive:

- `UploadEvent::AttemptStorage` + `UploadFailure::AttemptStorage`: the shadow
  attempt could not be loaded (previously `shadow_authority(...)?` returned
  early). The handler still renders the original storage error.
- `ReadEvent::EpochStorage` + `ReadFailure::EpochStorage`: the served epoch
  could not be loaded (previously `read_epoch(...)?` returned early).

Existing events keep their behaviour; the new ones are accepted only in the
stage whose effect produced them (`AuthorizeShadow`, `ReadEpoch`) and are inert
elsewhere, like every other out-of-order event.

## Two invariant gaps found and fixed

Both were latent in `vault_upload_driver.rs`; neither changes handler
behaviour, and both are now covered by tests.

1. `upload_state_is_sound` rejected a reachable state: a temporary web session
   that resolves a **freezing** account's successor route holds
   `shadow && web` until `AuthorizeShadow` refuses it. The predicate demanded
   `!web` for any shadow route, so the state invariant was false on that path
   (`a_web_session_may_hold_a_shadow_route_but_never_leaves_it`). The web
   exclusion now applies to *leaving* the shadow stage (the same shape the F*
   trace invariant already used).
2. `read_state_is_sound` claimed a served row's `version >= 0`. The driver only
   echoes the decoded row, so the claim was not a driver property and made the
   read loop invariant unprovable. The decoder owns that check; the predicate
   no longer restates it.

With those fixed, `upload_step`/`read_step` carry a conditional hax
`ensures` (state and effect soundness are preserved), which is what lets the
extracted loop discharge its `loop_invariant!` and what makes the F* turn
relation total without an extra hypothesis.

## Mutations (copies of the extraction, not committed)

| Mutation | Result |
|---|---|
| `mutation-a.diff`: `ResolveEpoch` calls the quota executor | `run_upload_is_run_ev` fails |
| `mutation-b.diff`: a verdict still calls `publish` | `run_upload_is_run_ev` fails |

Both were checked against copies under `/tmp/vela-mut/`; the log excerpts are
`mutation-a.log` and `mutation-b.log`.

## Assumptions and non-claims

- Each executor method performs the I/O its name describes and reports the
  outcome honestly (the SQL text, store operations and statuses in
  `PutChunkIo`/`GetChunkIo` are reviewed and exercised by
  `vela-server --test integration`, `--test rekey_state_model` and
  `--test session_capability_model`).
- The server's macro expansion differs from the checked one only by `.await`;
  that is a property of `macro_rules!`, not a proof.
- SQL/store linearizability and the store's row-decoding checks.

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
./verify-fstar-vault-upload-driver.sh      # regenerates the driver extraction
./verify-fstar-vault-upload-interpreter.sh # interpreter extraction + lemmas
python3 -m unittest discover -s security/formal/tests -p 'test_*.py'
```

`interpreter-gate.log` is the local run (F* 2025.10.06, Z3 4.13.3, hax 0.3.7).

## Hosted reproduction

The [6be552c security workflow](https://github.com/lucannez64/VELA/actions/runs/40538488807) re-extracted and verified
this interpreter and its lemmas in its crate's chain; all fifteen PR checks
passed. `hosted-6be552c.log` holds the summary and hashes, which match the
local run.
