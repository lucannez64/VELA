# Cancellation of the security-handler interpreter loops (F-2)

Every security handler reaches its decision driver only through one of the
proved interpreter loops below, and every one of those loops has a
cancellation lemma. The loop is synchronous in the policy crate
(`run_*`) and hax/F* proves it performs exactly the driver's effects. The
server expands the same macro with `.await` after each executor call.

A handler future is dropped when the client disconnects. The drop can happen
after any executor call and before the next `step`, so the loop stops after an
arbitrary prefix of turns. This evidence proves that **every prefix is a sound
driver state**, for every executor and every `k` up to the loop budget, and
records what the store/SQL already contains at each such point.

## Lemmas

Each lemma is in the interpreter's existing lemma module, so it runs in that
crate's ordinary gate. `sound_transition t` is the conjunction of the driver's
own `*_state_is_sound t.driver` and `*_effect_is_sound t.driver t.effect`; the
state predicate carries the per-request state invariants (listed per driver
below). The statement is uniform:

```
let <loop>_cancellation (#io_t) {| i: t_<Loop>Io io_t |} (k: nat) (s: io_t) (t: t_<Loop>Transition)
  : Lemma (requires sound_transition t)
          (ensures (let (_, t2) = iter_turn #io_t #i k (s, t) in sound_transition t2))
```

The abort-flag loops use their extracted accumulator
(`*_iter_turn`/`*_run_ev`) and prove the same property of the transition inside
it; a turn that returns `None` leaves the previous (sound) transition in place.

| Crate / module | Loops | Lemma |
|---|---|---|
| `vela-session-policy` / `deletion-interpreter-lemmas` | `run_deletion` (`DELETE /account`) | `cancellation` |
| `vela-session-policy` / `login-interpreter-lemmas` | `run_login` (`POST /auth/verify`) | `cancellation` |
| `vela-session-policy` / `revocation-interpreter-lemmas` | `run_revocation`, `run_logout` | `revocation_cancellation`, `logout_cancellation` |
| `vela-enrollment-policy` / `pairing-interpreter-lemmas` | `run_pairing` (all six pairing ceremonies) | `cancellation` |
| `vela-recovery-policy` / `possession-interpreter-lemmas` | `run_possession_initiation`, `run_possession_recover` | `initiation_cancellation`, `recover_cancellation` |
| `vela-recovery-policy` / `redemption-interpreter-lemmas` | `run_redemption` (`POST /recovery/enroll-device`) | `redemption_cancellation` |
| `vela-recovery-policy` / `webauthn-interpreter-lemmas` | registration start/finish, auth start/finish | `rs_cancellation`, `reg_cancellation`, `as_cancellation`, `af_cancellation` |
| `vela-rekey-policy` / `vault-upload-interpreter-lemmas` | upload and read | `upload_cancellation`, `read_cancellation` |
| `vela-share-policy` / `interpreter-lemmas` | all five sharing handlers | `cancellation` |
| `vela-enrollment-policy` / `enroll-interpreter-lemmas` | `run_enroll` (`POST /device/enroll`) | `enroll_cancellation` |
| `vela-share-policy` / `send-interpreter-lemmas` | send create, view, delete | `send_cancellation` |
| `vela-recovery-policy` / `recovery-share-interpreter-lemmas` | recovery-share put, get, delete, finalize (abort-flag form) | `recovery_share_cancellation` |
| `vela-session-policy` / `registration-interpreter-lemmas` | `run_registration` (`POST /account/register`) | `registration_cancellation` |
| `vela-session-policy` / `challenge-issue-interpreter-lemmas` | `run_challenge_issue` (`GET /auth/challenge`) | `challenge_issue_cancellation` |
| `vela-session-policy` / `websession-interpreter-lemmas` | web-session start, grant, token, delete | `websession_{start,grant,token,delete}_cancellation` |
| `vela-rekey-policy` / `rekey-interpreter-lemmas` | rotation start, capsules, commit, abort | `rekey_{start,capsules,commit,abort}_cancellation` |
| `vela-rekey-policy` / `vault-mutation-interpreter-lemmas` | chunk delete, ORAM path write, schema floor, capsule ack, rekey-capable | `chunk_delete_cancellation`, `oram_cancellation`, `schema_cancellation`, `capsule_ack_cancellation`, `rekey_capable_cancellation` |

The second group of rows (from `enroll` down) was added after the first nine
loop families, on commit 4329328, with one mutation per crate (see
[mutations](mutations/README.md)). The store/database review table below
covers the first nine families only.

## Per-request state invariants carried by the sound state

- **deletion:** committed ⇒ `users` deleted and transaction started;
  responded ⇒ committed; failed ⇒ not committed; table deletes only inside an
  open, started transaction; lockouts precede the transaction.
- **login:** responded ⇒ accepted challenge, present device, valid verifier,
  reset backoff, issued and tracked token; tracked ⇒ issued; failure never
  claims a response.
- **revocation/logout:** recorded ⇒ target and lockout observed; cascade ⇒
  lockout; exactly one terminal verdict; a logout success wrote the JTI marker.
- **pairing:** inserted ⇒ stored claim, live opener, verified signature and
  matching user/opener bindings; recorded ⇒ inserted; restored ⇒ failed and not
  inserted; a take implies all completion facts.
- **possession initiation/recovery:** a stored challenge implies the observed
  account/share facts and authorization; issuing a grant implies the consumed
  matched attempt, verified proof and every live release fact; a stored grant
  implies an issued one.
- **redemption:** insert emitted ⇒ matched consumption + policy permit +
  recorded attempt; insert success ⇒ those facts and no restoration;
  restoration only after a failed insert.
- **WebAuthn:** stored registration state/credential implies the observed,
  verified and unique credential and the policy permit; an issued grant implies
  the consumed verified attempt and all live account/share release facts; a
  credential update implies a needed update.
- **vault:** a matched write implies a resolved route and clean permit epoch; a
  web session never leaves the shadow stage; success ⇒ matched write plus
  publication/shadow refresh.
- **sharing:** a committed send/update was authorized for its request kind; a
  revoke commit implies the linked row was revoked and cleanup was issued; an
  inbox delete is recipient-scoped.

## Cancellation points and the store/SQL at that point

A "turn" is the executor call for the effect the driver just emitted. The
consequence below is the state left by a drop after that call and before the
next `step`; the driver state is the prefix state, which the lemmas above prove
sound. `TxGuard` is the server's pinned-connection transaction guard; dropping
it rolls back an uncommitted transaction.

### `DELETE /account` (deletion)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| `scan_devices` | read only | none |
| `lockout_devices` | device JTIs revoked and `device:revoked:` sentinels written in sled (the store error is intentionally ignored) | safe |
| `scan_web_sessions` | read only | none |
| `lockout_web_sessions` | web-session JTIs/sentinels locked out | safe |
| `begin_transaction` | `TxGuard` open; no row deleted; guard drop rolls back | safe |
| `delete_table` (each of seven) | uncommitted deletes inside the open transaction; guard drop rolls back all of them | safe |
| `delete_users` | uncommitted `users` delete; guard drop rolls back | safe |
| `commit` | commit may have succeeded; the account is gone and the client may not see the 200. A retry is `404`. If commit failed, SQLite rolls back. | safe |

No point leaves a driver state the soundness predicate rejects. The lockout
writes are deliberately durable before the transaction, so a rollback can only
shorten the token window.

### `POST /auth/verify` (login)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| `consume_challenge` | challenge row deleted (single use); no token | safe, liveness loss |
| `observe_device` | read only | none |
| `verify_signature` | CPU only | none |
| `record_verification_failure` | backoff/attempt counters incremented | safe (fail closed) |
| `reset_backoff` | success streak reset and `last_active`/name/type update applied; no token yet | safe, liveness loss |
| `issue_token` | PASETO minted in memory only; JTI not tracked and token not returned | safe |
| `track_token` | JTI marker written but token not returned | safe, marker expires |

### `POST /device/revoke` and `POST /auth/logout`

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| revoke `lookup_target` | read only | none |
| revoke `lockout_device` | target JTIs revoked + sentinel written | safe |
| revoke `record_revocation` | `devices.revoked = 1` committed | safe |
| revoke `cascade_web_sessions` | target already revoked; some/all approved web sessions sentinel-locked and `status='revoked', capsule=NULL`. A retry sees `already_revoked` and reruns lockout+cascade, healing the remainder. | safe |
| logout `revoke_jti` | `jti:revoked:` marker written (or not) | safe (fail closed) |

### Pairing handlers (`/device/enrollment-*`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| Invitation `store_package` | package written under the token; client may not see the 200, but can fetch | safe |
| Invitation `redeem_package` | destructive `get_del` removed the package; one-time capsule lost | safe, liveness loss |
| Grant `store_grant` | grant written; response lost; unused grant expires | safe |
| Claim `check_claim` / `write_claim` | claim written (immutable) or not; response lost; claim is visible to the opener | safe |
| Completion `check_account` / `prepare_completion` | reads only | none |
| Completion `take_ceremony` | grant **and** claim consumed by one sled transaction; no device row yet | safe, liveness loss: the ceremony cannot be retried and no device exists |
| Completion `insert_device` | device row committed; result record may not have run | **U-20**, fixed below: fallback by `enrollment_grant_id`; before the fix this was a liveness loss |
| Completion `write_result` | result record written; response lost; `/result` serves it | safe |
| Result `read_result` / `read_claim` / `read_enrolled_device` | reads only | none |

### Possession proof (`/recovery/initiate/proof`, `/recovery/recover/proof`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| Initiation `observe` | reads only | none |
| Initiation `store_challenge` | single-use challenge state stored; client never received it; slot expires | safe, liveness loss |
| Recover `count_attempt` | limiter counters incremented | safe (fail closed) |
| Recover `consume_attempt` | destructive `get_del` consumed the attempt state | safe, liveness loss (restart) |
| Recover `query_account` / `verify_proof` | reads/CPU | none |
| Recover `issue_grant` | single-use grant stored but its id never returned; expires | safe, liveness loss |

### Redemption (`POST /recovery/enroll-device`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| `consume_grant` | recovery grant destructively consumed; no device row | safe, liveness loss |
| `final_policy` | reads/CPU | none |
| `insert_device` | recovered device row committed; response lost; grant already consumed | safe (one device); liveness loss (device id not returned). Analogue of U-20 but outside this task's fix |
| `recheck_authority` | reads only | none |
| `restore_grant` | grant restored; no insert | safe |

### WebAuthn (`/recovery/webauthn/*`, `/recovery/initiate`, `/recovery/recover`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| Registration start `observe` / `ceremony` | reads/CPU | none |
| Registration start `store_state` | registration state stored; client never got the challenge | safe, liveness loss |
| Registration finish `count_attempt` | limiter counters incremented | safe |
| Registration finish `consume_state` | registration state destructively consumed | safe, liveness loss |
| Registration finish `verify` / `uniqueness` | CPU/reads | none |
| Registration finish `persist` | `users.recovery_webauthn_credential/_cred_id` updated; response lost; state consumed | safe (verified/unique credential); retry needs a new ceremony |
| Auth start `observe` / `ceremony` | reads/CPU | none |
| Auth start `store_state` | auth state stored; client never got the challenge | safe, liveness loss |
| Auth finish `count` / `context` | counters/reads | safe |
| Auth finish `consume` | attempt state destructively consumed | safe, liveness loss |
| Auth finish `verify` | CPU only | none |
| Auth finish `update` | credential metadata update committed | safe |
| Auth finish `account` / `release` | reads and in-memory share decode | none (nothing released to a client yet) |
| Auth finish `store_grant` | single-use grant stored but id never returned; expires | safe, liveness loss |

### Vault upload/read (`PUT`/`GET /vault/chunk/:id`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| Upload `resolve_epoch` / `authorize_shadow` / `enforce_quota` | reads only | none |
| Upload `guarded_write` | chunk row inserted/updated (shadow writes are idempotent upserts); client may miss the version header | safe; a retry must re-sync |
| Upload `recheck_state` / `reread_version` | reads only | none |
| Upload `record_shadow_activity` | rotation deadline refreshed | safe |
| Upload `publish` | in-memory change event published; response may be lost | safe |
| Read `read_epoch` / `lookup_chunk` | reads only | none |

### Sharing (`/share/*`)

| Cancellation point | Concrete state after the drop | Safety |
|---|---|---|
| Send `insert_capsule` | the two inserts and the commit are one `TxGuard` transaction: a drop before commit rolls back both rows; a drop after commit leaves one delivered send and the client may not see the response (a retry creates a second, new send) | safe; duplicate on retry |
| Update `observe_link` / `update_linked_item` | read / one guarded `shared_items` update | safe |
| Revoke `observe_link` | read only | none |
| Revoke `revoke_linked_item` | `shared_items.revoked = 1`; the pending `share_inbox` row has **not** been deleted | see finding |
| Revoke `delete_linked_inbox` | inbox row deleted | safe |
| Inbox `delete_inbox_item` | one recipient-scoped delete | safe |
| EK `observe_device` / `update_share_ek` | read / `users.share_ek` update | safe |

## Finding: share revoke leaves a readable inbox capsule

**Location:** `serverVELA/vela-server/src/share/mod.rs`,
`delete_linked_item`: `revoke_linked_item` sets `shared_items.revoked = 1`,
then `delete_linked_inbox` deletes the pending `share_inbox` row.

**Point:** a drop (or a cleanup storage failure, which the historical handler
deliberately ignores) between those two effects leaves the linked item revoked
but its `share_inbox` row present. `GET /share/inbox` reads `share_inbox`
directly and does not join `shared_items`, so the recipient can still fetch the
capsule.

**Assessment:** the *driver* state is sound (`revoked` and `cleanup_issued` are
both set; `share_state_is_sound` permits exactly this state), so the
cancellation lemma does not fail. The gap is the handler's cross-store
eventual cleanup, not the driver decision. It is reported here rather than
changed: the minimal fix would be to exclude revoked `shared_items` in the inbox
read (or to make cleanup first), which is a read-path/ordering change outside
this task's driver-proof scope. It is not a second enrollment or an
unauthorized send; it is an incomplete revocation window.

**Since fixed (U-23):** both inbox queries now exclude items whose
`shared_items` row is revoked, so a revoked share leaves the inbox even if the
cleanup never ran (regression test
`a_revoked_share_leaves_the_inbox_even_if_cleanup_never_ran`).

No other cancellation point leaves a state the driver's soundness predicates
reject, and no mutation of a driver step that sets a success flag before its
effect completed was found.
