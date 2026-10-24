# Device revocation and logout (bounded handler/database conformance)

Test: `serverVELA/vela-server/tests/device_revocation_model.rs` (CI:
`security.yml`, step "Check bounded policies and rekey handler/database
conformance", immediately after `challenge_single_use_model`).

Every command sequence up to `VELA_REVOCATION_MODEL_DEPTH` (default 3) over a
22-command alphabet runs against an independent reference state machine and
against the real Axum router backed by the real Turso schema and sled store.
Three focused tests pin the properties in readable form: a regression sequence,
automatic token renewal, and a token that escaped JTI enumeration.

## What the server actually does

`POST /device/revoke` (`src/device/revoke.rs`), in this order:

1. load the target row (`404` if absent);
2. refuse a target of another account (`403`);
3. refuse an already-revoked target (`400`, from SQL `devices.revoked`);
4. `rate_limit::revoke_all_device_jtis` — write `jti:revoked:{jti}` for every
   JTI in `device:jtis:{target}` and delete the set;
5. `set_ex("device:revoked:{target}", …, 900)`;
6. only then `UPDATE devices SET revoked = 1, revoked_at = ?, revoked_by = ?`.

`POST /auth/logout` (`src/auth/logout.rs`) writes `jti:revoked:{jti}` for the
caller's own token with the 15-minute maximum token lifetime.

`AuthSession::from_request_parts` (`src/middleware.rs`, steps 4–5) is the only
place either record is consulted, in this order: PASETO signature → 8-hour hard
cap → `jti:revoked` → `device:revoked` → per-JTI rate limit → account exists.
`DeviceSession` delegates to `AuthSession`, so every authenticated route is
gated by both checks. Every authenticated handler in `src/routes.rs` extracts
one of those two types; none parses the bearer itself.

The write ordering in `post_revoke` is deliberate: enumerating JTIs **before**
recording the sentinel means a failure of the SQL update still locks the device
out, and the sentinel catches a token issued in the window between the
enumeration and the sentinel write.

| Record | Written by | Consulted by | Lifetime |
|---|---|---|---|
| `jti:revoked:{jti}` | logout, revoke (bulk), middleware renewal | `AuthSession` | 900 s |
| `device:revoked:{id}` | revoke | `AuthSession` | 900 s |
| `devices.revoked` (SQL) | revoke | `/auth/verify` lookup (`AND revoked = 0`), `/devices` listing, `revoke` pre-check | durable |

## Reference model

Universe per trace: account `Alice` with devices `A` (primary), `B`, `C`, and
account `Eve` with device `E`. Token handles: `A0`, `A1` (A holds two slots),
`B0`, `C0`, `E0`. A slot is a **client handle**, not server state: logging in
again into an occupied slot replaces the handle, and the model deliberately
forgets the replaced token still live on the server — nothing in the alphabet
can reach it. `None` means no login ever reached that slot, so requests carry a
bearer the server never issued.

| Transition | Rule |
|---|---|
| `Login(t)` | `401` iff `t`'s device is revoked (M27: revoked devices get no fresh lookup); otherwise `200` and the slot becomes live |
| `Use(t, endpoint)` | `200` iff `t` is live; else `401` |
| `Logout(t)` | `200` and exactly `t` dies iff live; else `401` |
| `Revoke(actor, target)` | `401` dead actor → `403` other account → `400` already revoked → `200`, after which every token of `target` is dead, permanently |

States follow the symbolic vocabulary: M27 `Revoked(dev)` / no fresh device
lookup, M21 revocation finality. Revocation is monotone — nothing in the
alphabet un-revokes.

Server behaviours modelled as observed, not as desired:

- **The last non-revoked device of an account can be revoked.** `post_revoke`
  has no "you would lock yourself out" check. The focused sequence revokes
  `C` (Alice's last live device) and `E` (Eve's only device): both return
  `200`, after which every token is refused and every login fails.
- **A self-revoke succeeds and returns `200`.** Authorization happens in the
  extractor before the handler kills the caller's own tokens.
- **A `403` wins over a `400`.** A cross-account revoke of an already-revoked
  target is still `403` (owner check precedes the revoked check).
- **Logout kills only the addressed token.** With `A0` and `A1` both live,
  `Logout(A0)` leaves `A1` accepted; the model asserts this after every step.

## What is compared at every step

1. HTTP status of the command, and the `revoked` echo on a successful revoke
   (the returned id must be the target, not the actor).
2. Regression checks on response-independent state:
   - SQL `devices` rows of both accounts: the exact four rows, `revoked`,
     `revoked_by` (the actor's device id) and `revoked_at` presence;
   - sled `device:revoked:{id}` present iff the model says revoked.
3. **Which token handles are still accepted**: each of the five handles is
   replayed against `GET /devices`; a handle the model calls dead must be
   `401`, a live one `200`. A live owner token must also list exactly its
   account's devices with the model's `revoked` flags.
4. After every successful revoke, **every** handle of the target is replayed
   against every endpoint in the alphabet (`GET /devices`, `GET /vault/epoch`,
   `GET /share/inbox`, and a real vault write `PUT /vault/chunk/:id`) and must
   be `401` everywhere.

## Exploration

Command alphabet (22): five `Login`s; seven `Use`s covering all four endpoint
kinds (device listing read, vault epoch read, share inbox read, and a real
vault write to a fresh `PUT /vault/chunk/:id` with `If-Match: 0`) on several
devices and both of A's tokens; three `Logout`s (`A0`, `A1`, `B0`); seven
`Revoke`s (normal, self, second-token actor, already-revoked via repetition,
both cross-account directions, and `E` self-revoke).

| Depth | Traces | Steps | Result |
|---|---:|---:|---|
| 1 (smoke) | 23 | 22 | pass |
| 2 (smoke) | 507 | 990 | pass, 1.7 s |
| 3 (CI default) | 11,155 | 32,934 | pass, 55.2 s (`depth3.log`; 55–61 s across runs) |
| 4 | 245,411 | 969,958 | **not run** |

Depth 4 at the measured ~1.7 ms/step projects to ~27 minutes, far over the
~3-minute local budget, so depth 3 is kept. Depth 4 would add traces that
revoke two different devices of the same account in one trace; the focused
sequence already covers both accounts ending with no live device.

Non-vacuity (asserted only at depth ≥ 3, where every shape is reachable; counts
from the checked-in depth-3 run): 193 successful logouts, 193 self-revokes, 65
revokes that left an account with no non-revoked device, 131 cross-account
rejections, 2 already-revoked rejections. Every command kind reaches at least
one success and one refusal: `Login` 200/401, each `Use*` 200/401,
`Logout` 200/401, `Revoke` 200/400/401/403.

The four login challenges are obtained from the real `GET /auth/challenge` once
before the exploration and re-armed under the same `challenge:<b64>` key before
every `Login`. This makes the hybrid signatures precomputable while leaving the
store semantics under test intact; the challenge namespace itself is covered by
`challenge_single_use_model.rs`. Fresh accounts and devices are created for
every trace, so revocation state never leaks between traces; the previous
trace's rows are deleted first so the temporary database reuses its pages
instead of growing by four ~5 KiB device rows per trace (~11k traces at depth
3).

## Properties asserted

- **After `revoke(D)`, no token of `D` is accepted anywhere.** All of D's
  handles are replayed against all four endpoints right after the revoke; every
  later step re-probes them at `/devices`.
- **A revoked device cannot log in again.** `Login(D)` is `401` after
  revocation (from `WHERE id = ? AND revoked = 0`), and the model refuses it at
  every subsequent step.
- **Logout invalidates exactly that token.** `A0` dies while `A1` stays
  accepted at `/devices`; every trace containing a logout asserts this.
- **A revoked actor cannot revoke.** The extractor refuses it before the
  handler; `Revoke(dead actor, target)` is `401`, never `400`/`403`/`200`.
- **No cross-account revocation.** `C0 → E` and `E0 → A` are `403`, and no
  device row of either account changes.
- **Revocation is permanent within the trace.** The model has no un-revoke
  transition; SQL `revoked`, `revoked_by`, `revoked_at` and the sled sentinel
  are compared after every step.
- **Revocation covers a token that escaped JTI enumeration.**
  `the_device_sentinel_stops_a_token_that_escaped_jti_enumeration` issues a
  valid A token without registering its JTI, then revokes A from B; the token
  is refused at all four endpoints, and the test proves the JTI set was empty
  before and after. This is the sequential projection of the enumeration race
  the sentinel exists for.
- **Automatic renewal stays bound to the device.** There is no explicit refresh
  route: `AuthSession` renews within 5 minutes of expiry and returns
  `X-New-Token`. `automatic_renewal_stays_bound_to_the_device` starts from a
  token with 120 s left, asserts the old token is refused after renewal, the
  replacement works, and **both** die when the device is revoked (the
  middleware registers the replacement's JTI with the device).

## Mutation checks (applied locally, then reverted)

`git diff -- serverVELA/vela-server/src/` is empty after the revert; no handler
change was kept.

### 1. Skip the per-JTI revocation check (`if jti_revoked` → `if jti_revoked && false`)

| Test | Result |
|---|---|
| `revoke_and_logout_invalidate_exactly_the_expected_authority` | **fails** at step 9 (after `Logout(A0)`): "token A0 acceptance was 200, model says live=false" (`mutation-skip-jti-check-focused.log`) |
| exhaustive model, depth 2 | **fails** at step 1 of `[Login(A0), Logout(A0)]` with the same assertion (`mutation-skip-jti-check-exhaustive-depth2.log`) |

The exhaustive model catches this because it tracks the exact token handles
that logout and revoke must kill.

### 2. Ignore the device-revoked sentinel (`if device_revoked` → `if device_revoked && false`)

| Test | Result |
|---|---|
| `the_device_sentinel_stops_a_token_that_escaped_jti_enumeration` | **fails**: "a token outside the JTI set survived revocation at Devices" (`mutation-ignore-device-sentinel-sentinel-test.log`) |
| regression sequence | passes (`mutation-ignore-device-sentinel-focused.log`) |
| exhaustive model, depth 2 | passes (`mutation-ignore-device-sentinel-exhaustive-depth2.log`) |

This is expected and recorded rather than hidden: every token the model obtains
comes from `/auth/verify`, which registers its JTI with the device, and
`revoke_all_device_jtis` marks all of them. The sentinel is therefore redundant
for *tracked* tokens in a sequential trace, and only the dedicated untracked-
token test makes it load-bearing. Making the exhaustive alphabet carry an
untracked handle would defeat the model's own token accounting; the focused test
is the honest place to pin it.

## Endpoints that do not go through the revocation check

Every route that authenticates a bearer uses `AuthSession`/`DeviceSession`, so
there is no authenticated handler-side bypass. The following are deliberately
unauthenticated and therefore not gated by device revocation:

- `GET /auth/challenge`, `POST /auth/verify` — verify applies its own
  `revoked = 0` lookup, which is what blocks a revoked device's login;
  `POST /account/register`.
- Pairing: `GET /device/enrollment-package/:token`, `POST
  /device/enrollment-grant/:id/claim` (unguessable grant) and `.../result`
  (signed under the claimed key). The opener-side `POST
  /device/enrollment-grant`, `GET .../:id` and `.../complete` extract
  `DeviceSession` and *are* gated.
- Share links: `GET /send/:id` (unguessable id), `POST /web-session/start`,
  `POST /web-session/:id/token` (poll secret + challenge + ephemeral key).
- Recovery: `POST /recovery/initiate|recover|recover/proof|initiate-proof`
  (their own proof material), `GET /health`.

Update (after this test was written): revoking a device now also revokes
every web session it approved (`web_sessions.approved_by`): their tokens are
rejected via the `device:revoked:{session_id}` sentinel and the rows become
`revoked` with no capsule. A grant also requires the approving device row to
be unrevoked, so a grant racing the revocation cannot survive it. The
regression test is `revoking_a_device_revokes_the_web_sessions_it_approved`
in `tests/integration.rs` (mutation-checked for both parts); this bounded
model does not drive web sessions.

## Not covered

Executable evidence for bounded sequential traces, not a proof.

- Token cryptography: PASETO verification and the hybrid (ML-DSA-87 +
  Ed25519) signatures are assumed to authenticate their messages.
- **Real concurrency** between a revoke and an in-flight request. The ordering
  in `post_revoke` and the sentinel are modelled sequentially; a genuine race
  (request already past the extractor when revocation lands) is not.
- **TTL expiry**: the 15-minute `jti:revoked` / `device:revoked` markers and the
  8-hour hard cap are counted as present for the whole run; no test waits them
  out.
- **Multi-node / distributed stores**, where the sled sentinel and the Turso row
  could be written on different nodes, or where one node's sled lacks the other
  node's markers.
- Account deletion, key rotation/epoch invalidation (a revoked device under a
  rotated epoch), recovery, and web-session lifecycles.
- Rate-limit and quota interactions under sustained load: fresh source
  addresses and one-connection sequential Turso access keep them out of the way.
  (`helpers::test_state` opens Turso with a one-connection pool, which is
  correct for these sequential traces; concurrent session lookups on that pool
  return 500s, as noted in `challenge_single_use_model.rs`.)
- Revoking a device that does not exist (`404`) is not in the alphabet.

## Reproduce

```sh
# CI shape (Docker/heavy wrapper used locally on this machine)
cargo test --manifest-path serverVELA/Cargo.toml --test device_revocation_model

# deeper local exploration (not run: ~27 min projected)
VELA_REVOCATION_MODEL_DEPTH=4 \
  cargo test --manifest-path serverVELA/Cargo.toml \
  --test device_revocation_model every_bounded -- --nocapture
```
