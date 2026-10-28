# Cross-driver concurrent composition (F-2)

This directory backs one F* composition over the decision drivers that share
account, device, token and ceremony state. It closes the gap left by the
per-driver compositions: each of those proves a race inside one driver's own
state, but none runs the login, admission, revocation, logout, account-deletion,
pairing-completion and recovery-redemption drivers together over one world.

- Gate: `security/formal/cross-driver/verify.sh` (the required gate).
  `verify-fstar-cross-driver.sh` is the same gate under a name that
  `vela-heavy` offloads to the build box.
- Composition module:
  `security/formal/cross-driver/Vela_cross_driver_composition.fst`.
- Focused extractions:
  - `serverVELA/vela-session-policy/proofs/fstar/extraction-f2-cross/`
    (challenge, login, revocation/admission, deletion);
  - `serverVELA/vela-enrollment-policy/proofs/fstar/extraction-f2-cross/`
    (pairing driver and its policy root);
  - `serverVELA/vela-recovery-policy/proofs/fstar/extraction-f2-cross/`
    (redemption driver and its policy root).
- Evidence: this directory (`focused-verify.log`, `mutations/`).

Base commit: `e860213` (worktree `t3-c883d033`).

## World model

`world` is one linearizable shared state:

| Field | Meaning |
|---|---|
| `w_accounts` | `users` rows: present, `key_epoch`, active (`rekey_state IS NULL`) vs freezing |
| `w_devices` | `devices` rows: account, present (false after the deletion commit), durable `revoked`, sled `device:revoked:` sentinel |
| `w_tokens` | issued device tokens: device, live (set only at the extracted `TrackToken` effect), `jti:revoked:` marker |
| `w_challenge` | the one login challenge: present, stored purpose is a login tag, consumed |
| `w_pair` | the one pairing grant+claim: present, devices inserted, account, approving opener |
| `w_rec` | the one recovery grant: present, devices inserted, account, epoch, possession |
| `w_reqs` | per-request extracted driver values plus the spawn-time actor/session facts |
| `w_login_accepts` | accepted atomic challenge takes |
| `w_*` counters | forbidden events and per-object at-most-one violations (below) |

Requests and the extracted transition they run:

| Request | Extracted module | Observations |
|---|---|---|
| `LoginReq` | `Vela_session_policy.Login_driver` | challenge take, device lookup, verifier, backoff reset, issuance, JTI tracking |
| use (`Use`) | `Revocation_driver.plan_admission` | JTI, device sentinel, account presence, durable device row |
| `RevokeReq` | `Revocation_driver` | target lookup, lockout, SQL record, cascade |
| `LogoutReq` | `Revocation_driver` (logout) | JTI marker write |
| `DeleteReq` | `Deletion_driver` | scans, lockouts, transaction, eight deletes, `users` delete, commit |
| `PairReq` | `Enrollment_policy.Pairing_driver` | grant binding, account/epoch, verified completion policy, `take_live_pair`, guarded insert |
| `RecReq` | `Recovery_policy.Driver` | atomic `get_del`, final enrollment/rekey policy, guarded insert, live recheck |

Every observation that is a fact about the shared state is computed from the
**live** world at the step where the handler observes it. Effects are applied in
the same step:

- the login challenge take removes the key atomically (`get_del`);
- a revocation's lockout sets the sentinel and every tracked JTI; its record
  sets `revoked = 1`; the cascade ends approved web sessions (no web tokens are
  modelled, so this is a no-op);
- a deletion's lockouts set the account's sentinels/JTIs, and its transaction
  commit applies the eight deletes and the `users` delete atomically;
- a pairing take clears the grant+claim atomically; its insert is one guarded
  SQL statement checking `users.id`, `key_epoch` and `rekey_state IS NULL`;
- a recovery consume is one atomic `get_del`; its insert is one guarded SQL
  statement checking the same account guard plus the credential/commitment
  guard; a zero-row insert rechecks authority and may restore the grant;
- `plan_admission` is called with the four live observations.

The SQL guards are modelled as written:

- pairing insert:
  `INSERT ... SELECT ... WHERE EXISTS (SELECT 1 FROM users WHERE id = ? AND
  key_epoch = ? AND rekey_state IS NULL)`;
- recovery insert: the same guard plus
  `recovery_webauthn_cred_id = ?` or
  `recovery_auth_hash IS NOT NULL AND recovery_auth_hash <> ''`;
- deletion commit: the eight account-scoped `DELETE`s plus
  `DELETE FROM users WHERE id = ?`, atomically visible at commit;
- revocation record: `UPDATE devices SET revoked = 1 ... WHERE id = ?`.

The `version = ?` conjunct of an update and ciphertext/quota details are not
modelled; ignoring a conjunct can only make a guard accept more, never fewer,
so it cannot hide a forbidden write. A successful pairing/recovery insert is
counted and not added to the fixed `w_devices` table; no theorem depends on
operating on the inserted row afterwards.

## Counters

| Counter | Incremented at |
|---|---|
| `w_admit_revoked` | `plan_admission` admits while the live device sentinel is set or the durable row is not active |
| `w_admit_deleted` | `plan_admission` admits while the live account is absent |
| `w_pair_insert_deleted` | a pairing insert lands while the live account is absent |
| `w_rec_insert_deleted` | a recovery insert lands while the live account is absent |
| `w_pair_revoked_approver` | a completion preflight authorizes `TakeCeremony` while the live approving device is revoked/absent (and, defensively, an insert carries a false decision-time opener fact) |
| `w_cross_account` | a revoke lockout/record effect is authorized for a target in another account |
| `w_revoked_actor` | a revoke lockout/record effect is authorized by a spawn-time inactive actor |
| `w_cross_delete` | the deletion commit effect runs for an account other than the session's |
| `w_double_login` | a login issues a token at `Issue` without an accepted take of the shared challenge |
| `w_double_pair` | a pairing insert lands when the grant already has an inserted device |
| `w_double_rec` | a recovery insert lands when the grant already has an inserted device |
| `w_login_accepts` | an accepted atomic challenge take (bound: at most one) |

## Theorem

The shared invariant (quoted from the module):

```fstar
let inv (w: world) : prop =
  all_requests_ok w.w_reqs /\
  w.w_login_accepts <= b2n w.w_challenge.ch_consumed /\
  FStar.List.Tot.length w.w_tokens <= w.w_login_accepts + w.w_double_login /\
  w.w_double_login = 0 /\
  w.w_cross_account = 0 /\
  w.w_revoked_actor = 0 /\
  w.w_cross_delete = 0 /\
  w.w_admit_revoked = 0 /\
  w.w_admit_deleted = 0 /\
  b2n w.w_pair.pg_present + w.w_pair.pg_devices + count_pair_inflight w.w_reqs <= 1 /\
  w.w_double_pair = 0 /\
  w.w_pair_insert_deleted = 0 /\
  w.w_pair_revoked_approver = 0 /\
  b2n w.w_rec.rg_present + w.w_rec.rg_devices + count_rec_held w.w_reqs <= 1 /\
  w.w_double_rec = 0 /\
  w.w_rec_insert_deleted = 0
```

Headline theorem (every interleaving, every number of requests):

```fstar
let cross_driver_composition_theorem (schedule: list action)
  : Lemma (
      let w = run_world initial schedule in
      inv w /\
      w.w_cross_account = 0 /\
      w.w_revoked_actor = 0 /\
      w.w_cross_delete = 0 /\
      w.w_admit_revoked = 0 /\
      w.w_admit_deleted = 0 /\
      w.w_pair_insert_deleted = 0 /\
      w.w_pair_revoked_approver = 0 /\
      w.w_rec_insert_deleted = 0 /\
      w.w_double_login = 0 /\
      w.w_double_pair = 0 /\
      w.w_double_rec = 0) =
  initial_inv ();
  run_world_inv initial schedule
```

Named consequences of `inv`:

1. no token is admitted for a device whose sentinel or durable row says revoked,
   or for an absent account, at the admission step;
2. no device is inserted by a pairing or recovery completion for an account
   absent at the insert step, and no pairing insert follows a decision taken
   while the live approving device was revoked;
3. no revoke effect is authorized by a spawn-time inactive actor or for a
   cross-account target, and no deletion commits for an account other than the
   session's;
4. one token per login challenge (`length w_tokens <= 1` follows from
   `w_login_accepts <= 1` and `w_double_login = 0`), one device per pairing
   grant and one per recovery grant (the two sum invariants).

### What is modelled vs assumed

Proved by the composition (against the extracted transition functions):

- all counters above stay zero for every schedule;
- every live request keeps its extracted state invariant;
- the login token is issued only after an accepted challenge take, and the
  accepted take count is at most one;
- a pairing/recovery insert is emitted only from the extracted `InFlight` /
  `Insert` stage, and the per-grant sum invariant bounds insertions;
- revoke/deletion effects carry the extracted same-account/actor authority and
  commit only from the extracted commit stage.

Assumed / outside the model:

- SQL statements (`SELECT`, guarded `INSERT`, `UPDATE`, the deletion
  transaction) are linearizable; the eight deletes + `users` delete are one
  atomic commit;
- sled `get_del`, `set_ex` and `take_live_pair` are atomic and consistent with
  the read that follows;
- the handler performs exactly the effect the driver returns in the same
  request step as its observation, and the observations fed to the driver come
  from the world construction above;
- devices are never transferred between accounts; account/device/grant
  identities are stable;
- the pairing and recovery policy roots are trusted extracted code; the rekey
  phase is represented by `ac_active` (active vs freezing), and the recovery
  rekey permit is modelled by the same account guard rather than by extracting
  `vela-rekey-policy`;
- login's hybrid verifier, PASETO issuance, JTI tracking, backoff reset and the
  challenge classifier are trusted observations (always `Valid`, `Issued`,
  `Tracked`, `Reset`, and the stored purpose bit); their failures are covered by
  the per-driver proofs, not re-proved here;
- storage failures in the cross world are not modelled (the per-driver proofs
  cover them); the world is single-node and has no clock/TTL/replication;
- one login challenge, one pairing grant and one recovery grant are modelled,
  with a fixed account table (two accounts) and three initial devices; inserted
  rows are counted, not appended to `w_devices`; no web-session tokens are
  modelled, so the cascade is a no-op.

### In-flight windows, precisely

1. **Admission.** The middleware's PASETO/limit checks and the four admission
   observations are assumed to decide at one linearization point. A request that
   read them before a concurrent revoke/delete and decides after is the
   in-flight window and is outside the model. Once the revocation's lockout
   (sentinel/JTI) or durable `revoked = 1`, or the deletion commit, is visible,
   admission is refused (`w_admit_revoked = w_admit_deleted = 0`).
2. **Revocation actor.** Actor activity is a spawn-time fact, matching the
   driver and handler: an actor authenticated before a concurrent revoke may
   finish its request.
3. **Pairing opener.** The opener's activity is a decision-time fact at the
   completion preflight. A revocation after that decision but before the
   insert is not rechecked by the insert SQL, so the insert may land; the
   theorem bounds inserts by decisions with an active live opener
   (`w_pair_revoked_approver = 0`). The `pair_preflight_take_opener` lemma is
   the bridge from the extracted completion policy to that live fact.
4. **Deletion vs insert.** An insert linearized before the deletion commit may
   land and is removed by the commit; after the commit the account guard
   refuses it. No row survives for a deleted account.

## Non-vacuity witnesses and mutations

Each mutation is a copy under `/tmp/vela-f2-cross-mut/`, never committed. The
checked-in extraction is unchanged. The mutation driver script rebuilds a merged
extraction directory per crate so the mutant module shadows the committed one
(include-path ordering is not relied on). For each mutant:

- the checked-in composition theorem must **fail** (the removed check is
  load-bearing);
- a witness module over the composition definitions must **verify** and show
  the corresponding counter becomes positive (the counter is not dead code).

| Mutant | Removed check (`mutations/*.diff`) | Theorem failure | Witness counters |
|---|---|---|---|
| `admission` | `plan_admission` always `Admit`; `admission_is_authorized` true | `deliver_use_inv`, `assert (observation.f_device_revoked = false)` (line 2121) | `w_admit_revoked > 0`, `w_admit_deleted > 0` |
| `pair-opener` | `on_completion_ready` sets `opener_active := true` | `pair_preflight_take_opener` (line 1283) | `w_pair_revoked_approver > 0` |
| `guard` | `insert_guard` drops `account_present` | `deliver_pair_insert_inv`, `assert (account_present ... = true)` (line 1925) | `w_pair_insert_deleted > 0`, `w_rec_insert_deleted > 0` |
| `revoke-delete` | `on_target_observed` drops the same-account refusal; `begin_revocation` always active; `begin_deletion` drops the session-scope check | `revocation_lookup_account` (line 1490) | `w_cross_account > 0`, `w_revoked_actor > 0`, `w_cross_delete > 0` |
| `missing` | login Missing take accepted; pairing Missing take proceeds to insert; recovery Missing consume proceeds to policy | `login_step_accepted_origin` (line 1227) | `w_double_login > 0`, `w_double_pair > 0`, `w_double_rec > 0` |

The deletion witness seeds the `DeleteUsers`-stage driver directly (the driver's
own 12-step progression is exercised by the deletion driver lemmas) and shows
the commit counter increments for a mismatched session; the theorem failure is
what proves the `begin_deletion` scope check is load-bearing.

Logs are in `mutations/`; each theorem log ends with the failing `Error 19`, and
each witness log ends with `All verification conditions discharged successfully`.
The clean summary is `mutations/summary.txt`.

## Counts and gates

- 8 focused extracted modules: session 4 (challenge, login, revocation,
  deletion), enrollment 2 (policy root + pairing driver), recovery 2 (policy
  root + redemption driver).
- 1 composition module, 2188 lines, 22 schedule actions, 12 counters.
- 5 mutation witnesses, 5 diffs; all 5 mutant theorems fail and all 5 witnesses
  verify.
- `security/formal/cross-driver/verify.sh`: exit 0; source guard reports
  8 extracted modules and 1 proof module, no escapes/options; F* verifies the
  composition (see `focused-verify.log`).
- `python3 -m unittest discover -s security/formal/tests -p 'test_*.py'`:
  54 tests, OK. The suite now includes a guard check over the cross-driver
  sources and an executable-in-git check for the three cross-driver scripts.
- `python3 security/assurance/check-proof-boundary.py`: 14 artifacts, 249
  selected postconditions, 0 reviewed `assume val` (after the rekey gate
  regenerated its gitignored historical extraction).
- `serverVELA/vela-rekey-policy/verify-fstar.sh`: exit 0 (run to regenerate the
  historical extraction the boundary check reads; no tracked file changed).
- Rust behaviour was not changed.

F* 2025.10.06, Z3 4.13.3, hax 0.3.7. The composition uses no `assume`, `admit`,
`axiom`, `--lax` or options other than the source guard's reviewed budget.

## Reproduction

From the repository root, with the hax/F* environment and
`CARGO_TARGET_DIR` set:

```
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh admission
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh pair-opener
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh guard
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh revoke-delete
~/.local/opt/vela-tools/bin/vela-heavy security/formal/cross-driver/verify-fstar-cross-driver-mutations.sh missing
```

`verify.sh` can also be invoked directly; it is the same gate.
