# Challenge store world (F*)

`serverVELA/vela-session-policy/proofs/fstar/challenge-store-world-lemmas/Vela_session_policy_challenge_store_world.fst`
joins the login nonce theorems to the value the real store returns.

Before this module there were two separate results:

- the [raw nonce bridge](../login-raw-nonce-bridge/README.md): at most one
  admission, response and token per nonce, over a model whose nonce is an F*
  `option (t_Slice u8)`;
- the [take adapter](../challenge-take-adapter/README.md): the extracted
  `classify_taken_challenge` is correct over the store's actual result type,
  `Option<Vec<u8>>`.

This module defines a store world whose nonce *is* that result type. Its
`Take` step calls the extracted adapter, exactly as `take_challenge` does after
`get_del`, and empties the slot whatever the decision. All other actions never
read the nonce and reuse the raw model's step.

## Results (10 lemmas, 11 definitions)

- `take_event_agrees`, `take_accepts_agree`: for every store value, the event
  and acceptance the real adapter produces equal what the raw model produces
  for the same bytes.
- `to_raw_store_step`, `to_raw_store_run`: converting the store world to the
  raw world commutes with every action and every schedule.
- `store_one_nonce_at_most_one_admission` (headline): for any store value and
  any interleaving of any number of login requests, at most one request is
  admitted, at most one response is produced and at most one token issuance
  succeeds; the stored value and the admission flag together never exceed one.
- Witnesses: the issued login value is admitted and removed; an issued
  enrollment value is removed and admits nothing.

## Checks

- `full-verify.log`: one `verify-fstar.sh` run. The historical artifact and all
  9 focused modules (2 extracted, 7 handwritten) verify in one invocation;
  17 selections / 12 Rust postconditions, unchanged. Handwritten lemmas: 204
  (194 + 10).
- `mutation-take-keeps-value.log`: in a copy, the take keeps the value instead
  of removing it (as if `get_del` were a plain `get`). The commutation proof
  fails, so the result depends on the take removing the value.
- No `admit`, `assume` or `--lax`; the shared source-policy guard covers the
  new directory, and the fast source-policy test scans it.

## Still assumed

`get_del` is linearizable, removes the value and returns it unchanged; the
handler delivers that value to this decision and performs the driver's
effects; the imported hax `Option`/`Vec` models. No store, SQL, verifier or
handler refinement is claimed. Hosted reproduction is pending.
