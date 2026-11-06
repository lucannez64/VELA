# Concurrent one-challenge login composition

`Vela_session_policy_login_driver_composition.fst` composes the **actual
extracted** `/auth/verify` decision driver
(`Vela_session_policy.Login_driver.step`) across any number of concurrent
requests that share one challenge nonce.

The module does not restate the per-request transition relation. Every request
is a `t_LoginDriver` advanced only by the extracted `step`; the composition
supplies the effect observations and the nonce state.

## Model

One schedule is an arbitrary `list action`. Actions start a request, take the
nonce, fail a take, or deliver the next observation to any request. The world
state is the stored purpose (`None`, `Some StoredPurpose_Login`,
`Some StoredPurpose_Other`), an admission bit, response/token counters, and the
list of per-request drivers.

| Real effect | Model |
|---|---|
| sled `Store::get_del` of `challenge:<nonce>` | atomic `Take`: present nonce is removed in the same step; `Accepted` only for a login tag, `WrongPurpose` for any other tag, `Missing` when absent |
| `get_del` error | `TakeFailed`: no removal and no admission |
| device row query | `Device i observation` |
| base64 decode + hybrid verifier | `Verify i observation` |
| failure-counter/backoff side effects | `Record i observation` |
| success-streak/backoff reset | `Reset i observation` |
| PASETO issuance | `Issue i observation` |
| JTI tracking | `Track i observation` |

There is deliberately no action that inserts a fresh challenge: the theorem is
about **one** nonce key.

## Results

- `one_nonce_at_most_one_admission`: for every initial purpose and every
  schedule, one nonce admits at most one request, produces at most one
  `Respond` effect, and flips the token-issued flag at most once. The accepted
  request, response and token counts are all at most one.
- `non_login_nonce_never_admits`: if the initial nonce is absent or carries a
  non-login purpose, **no** schedule admits a request, responds, or issues a
  token. This is the expressible purpose-isolation statement; the real
  byte-level classifier is the separate challenge lemma module's theorem.
- Witnesses (checked, not assumed): complete success; two-request contention
  (first take admits, second sees `Missing`); wrong-purpose spending (the take
  removes the nonce and the next request sees `Missing`); absent nonce;
  `get_del` failure preserving the nonce for a later request; verifier
  rejection; and tracking failure after a token was issued (no response).

The proof is an unbounded structural induction over the schedule, with a
per-request token-conservation invariant. Per-step flag changes are derived
from the extracted `step`; no transition case is duplicated as an assumption.

## Comparison with the existing driver compositions

| Driver | Shared single-use object | Conservation result | Extra modelled effect |
|---|---|---|---|
| `vela-recovery-policy` redemption | enrollment grant | at most one device row per grant | guarded insert, restore, TTL expiry |
| `vela-recovery-policy` possession | proof state | at most one grant per proof state and at most `k` counted attempts | attempt budget, live-account/recheck |
| `vela-share-policy` | linked share/inbox | inbox quota, revocation finality | guarded SQL update/delete |
| this login module | challenge nonce | at most one admitted request, response and successful issuance per nonce | purpose-specific take, issuance/tracking failure |

All four use the same pattern: an arbitrary schedule, a shared world, a
per-request `trace_sound` invariant, and token/flag accounting over the
extracted `step`. Unlike redemption and possession, login has no restore step;
a wrong-purpose or successful take irrevocably spends the nonce, and a tracking
failure can leave an issued token without a response.

## Interface assumptions and limits

Proved here: the conditional composition over the extracted driver and the
modelled atomic take.

Not proved here:

- `get_del` linearizability, sled atomicity or durability;
- that the nonce key identifies exactly one stored challenge;
- that the handler's real `challenge` module classification and store bytes
  match `t_StoredPurpose` (the challenge lemma module proves the classifier
  against literal bytes; this module treats the result as the take interface);
- SQL row/guard semantics, device revocation, verifier soundness, PASETO
  security, JTI persistence, crash/retry behavior, clocks, or revocation
  linearization;
- the handler performing exactly the effect the driver returns; an observation
  is assumed to reach the driver in the same step as its effect.

The `nonce_admitted` bit is a model of "this nonce has been consumed by an
accepted login take", not a store fact.

## Evidence

Raw logs, argv, source hashes and the two mutation checks are in
[`security/assurance/proof-logs/current/login-nonce-composition/`](../../../../../security/assurance/proof-logs/current/login-nonce-composition/).
`verify-fstar-login-composition.sh` reuses the reviewed extraction, hashes the
historical extraction before and after, and runs the shared source-policy
guard. It adds **zero** Rust postconditions.

The parent aggregate verifier now includes this composition in its existing
focused F* invocation after fresh extraction, alongside the raw-byte producer.
The standalone verifier remains available for checking existing inputs. It
expects both reviewed challenge lemma modules; the original run below predates
the producer addition. Proof bodies are unchanged apart from scope comments.
