# Session-store keys are provably distinct (plan step O4)

**Why:** hax models `format!` so that F* proves every `format!` result equal
([check](../std-model-review/format-collapse/Fmt_collapse.fst)). The session
store built its store keys with `format!`, so in the F* model distinct keys
(`jti:revoked:…`, `challenge:…`, `rl:…`) collapsed into one.

## What changed

- `serverVELA/vela-session-policy/src/store.rs`: the hax-visible key builders
  build each key as its literal prefix plus its arguments with explicit string
  concatenation instead of `format!`. Unit tests compare every new key with
  the old `format!` output, so the stored bytes are unchanged.
- `serverVELA/vela-session-policy/proofs/fstar/models/`: local
  `Alloc.String` and `Rust_primitives.String` models in which concatenation is
  F*'s `^`, so F* can see through the keys. No `assume` or `admit`; every
  interface `val` has a definition.
- `proofs/fstar/store-lemmas/Vela_session_policy_store_keys.fst`: the proofs,
  checked by `verify-fstar-session-executors.sh`.

## Theorems

- **18 per-builder injectivity lemmas** (`key_logout_injective`,
  `key_streak_verify_injective`, …): equal keys from the same builder imply
  equal arguments.
- **`plan_key_disjoint`**: for any two different builders `b1 <> b2` and
  arguments satisfying H, the keys the real extracted plans emit
  (`plan_key`, read from the plan's statement) differ. `plan_key_eq` ties each
  plan's key to its builder.
- **Hypothesis H (`key_hypothesis`)**: for the multi-argument keys and
  `rl:websession:token:`, the final argument is colon-free. It holds because
  those final arguments are UUIDs (device, session, user ids); IP addresses,
  which may contain `:` (IPv6), only appear in non-final positions. H also
  rules out the one prefix-related pair, `rl:websession:token:` and
  `rl:websession:token:ip:`.
- **Non-vacuity witnesses**: two distinct logout keys, distinct namespaces,
  and H holding with an IPv6 scope (`witness_*`).

The resume also fixed a modelling error: `rl:verify:ip:` now takes the IP from
the shared `(ip, device)` scope that `plan_login_limits` actually uses.

## Results (re-run by the parent on the merged tree, 2026-11-04)

[checks-summary.txt](checks-summary.txt):
- `verify-fstar-session-executors.sh`: all verification conditions discharged,
  including the key module.
- `verify-fstar-session-executors-mutations.sh`: every mutant rejected,
  including the new `plan-share-token-prefix` mutant (two builders sharing a
  prefix), rejected by the disjointness proof.
- `cargo test` in vela-session-policy: 116 + 13; `cargo test -p vela-server`:
  pass.
- No existing session-store lemma depended on the collapse: all still verify
  with distinct keys.

## Open

- H is checked by these proofs, not by the code: a future builder whose final
  argument can contain `:` would need a length-prefixed encoding.
- `#[cfg(not(hax))]` key builders in the enrollment, recovery and rekey crates
  still use `format!`; no extracted proof uses them, so they are outside this
  result.
