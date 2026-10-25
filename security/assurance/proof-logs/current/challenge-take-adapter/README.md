# Challenge take adapter (F*)

This evidence directory backs the pure `Option<Vec<u8>>` take adapter and its
hand-written refinement:

- `serverVELA/vela-session-policy/src/challenge.rs`:
  `classify_taken_challenge(&Option<Vec<u8>>, ChallengePurpose) -> ChallengeConsumption`
- `serverVELA/vela-server/src/auth/challenge.rs`: `take_challenge` now performs
  only the actual `Store::get_del` and calls that policy function.
- `serverVELA/vela-session-policy/proofs/fstar/challenge-take-adapter-lemmas/Vela_session_policy_challenge_take_adapter.fst`
- the main focused gate `verify-fstar-login-driver.sh`, which regenerates the
  focused extraction and checks all focused modules in one F* invocation.

## Base and scope

- Base commit: `a1436db` (`Replay the raw nonce bridge in the aggregate gate
  and document its boundary`).
- Worktree: `/home/hirew/.t3/worktrees/VELA/t3-e3b08814`.
- Changed production files:
  - `serverVELA/vela-session-policy/src/challenge.rs` (adapter + 5 tests)
  - `serverVELA/vela-server/src/auth/challenge.rs` (call the adapter after the
    real `get_del`)
- Changed focused artifacts:
  - `proofs/fstar/extraction-login-driver/Vela_session_policy.Challenge.fst`
    (regenerated; adapter appended)
  - `verify-fstar-login-driver.sh` (one extra selection, the new module in the
    shared source guard/argv/hashes, and updated precise counts)
- New files:
  - `proofs/fstar/challenge-take-adapter-lemmas/` (module + README)
  - this evidence directory.
- Untouched: `login_driver.rs`, every existing hand-written F* module (including
  the raw nonce bridge, byte-identical), other handlers, the historical
  extraction, global assurance docs, `MANIFEST.sha256`, `correspondence.json`
  and CI.

## The gap this closes

The server previously did the adapter inline:

```rust
let consumed = state.store.get_del(&format!("challenge:{challenge_b64}"))?;
Ok(classify_consumption(
    consumed.as_deref().map(stored_tag_from_bytes),
    purpose.policy(),
))
```

The pure conversion/decision was therefore outside the extracted policy, and no
proof covered the `Option`/`Vec` step, the `None` case, or the retained length
of the actual store value. The adapter now lives in the policy crate:

```rust
pub fn classify_taken_challenge(
    consumed: &Option<Vec<u8>>,
    expected: ChallengePurpose,
) -> ChallengeConsumption {
    match consumed {
        None => ChallengeConsumption::Missing,
        Some(bytes) => classify_consumption(
            Some(stored_tag_from_bytes(bytes.as_slice())),
            expected,
        ),
    }
}
```

The handler performs only the effectful take; there is no second copy of the
decision. The borrow means the caller keeps the value returned by `get_del`.
The extracted body (hax 0.3.7) is exactly this match over
`Core_models.Option.t_Option (Alloc.Vec.t_Vec u8 Alloc.Alloc.t_Global)` and
calls `Alloc.Vec.impl_1__as_slice` on the `Some` branch; `Login_driver.fst` is
byte-identical.

## What is proved

`Vela_session_policy_challenge_take_adapter` states an **independent
literal-byte specification** over the actual store value:

```fstar
taken_literal_spec consumed expected =
  None -> Missing
  Some v ->
    expected = Login     -> if bytes(v) = "login"     then Accepted else WrongPurpose
    expected = Enroll    -> if bytes(v) = "enroll"    then Accepted else WrongPurpose
    expected = WebToken  -> if bytes(v) = "web_token" then Accepted else WrongPurpose
```

The literal predicates (`vec_is_login`, `vec_is_enroll`, `vec_is_web_token`) read
the byte positions of the actual `Vec` and do not call the implementation's
conversion, classifier or contract helpers. The main theorem

```fstar
classify_taken_challenge_matches_literal :
  classify_taken_challenge consumed expected = taken_literal_spec consumed expected
```

is proved for every `Core_models.Option.t_Option` store result and every
`ChallengePurpose`. Consequences:

- `classify_taken_challenge_none`: `None` is `Missing`, never accepted.
- `taken_accepts_iff_literal`: for a present value, `Accepted` iff the value's
  bytes are exactly `expected`'s literal tag.
- `taken_present_nonmatching_is_wrong_purpose` and `taken_some_never_missing`:
  a present non-matching value is `WrongPurpose`, never `Missing`; the take has
  already removed it.
- `taken_some_retains_actual_length`: the bounded conversion keeps the actual
  store length.
- `taken_long_value_is_wrong_purpose` and `vec_long_is_no_literal`: a value
  longer than nine bytes reaches no literal and is refused for every purpose,
  so the retained prefix cannot alias a short tag.
- `taken_some_login_equals_raw_login_decision`: on a present value, the adapter
  is exactly the earlier checked `raw_login_decision` applied to the same actual
  slice (`classify_consumption (Some (stored_tag_from_bytes slice)) Login`).
- Issuer cases: `taken_issued_accepts_its_purpose`,
  `taken_issued_refuses_other`, `taken_login_issuer_accepted`,
  `taken_login_issuer_equals_raw_login`,
  `taken_enroll_issuer_refused_for_login`,
  `taken_web_token_issuer_refused_for_login`,
  `taken_long_issuer_refused_for_login`,
  `taken_long_issuer_equals_raw_long`, and
  `taken_empty_is_wrong_purpose` are concrete, non-vacuous checks over actual
  `Vec` values.

The proof uses the already checked producer lemmas
(`consumption_accepts_iff_slice`, `issued_path_accepts_only_its_purpose`,
`producer_len`, `long_input_cannot_alias_short`) and the extracted adapter body.
The goal is never used as a hypothesis, and no `assume`, `admit`, `axiom`,
`--lax`, `opaque`, local `val` or self-referential Rust wrapper is used.

## Tests (real code paths)

| Test set | Result |
|---|---|
| `vela-session-policy` unit tests | 23 passed (18 before; +5 adapter) |
| `vela-session-policy` login-driver tests | 13 passed |
| `challenge_single_use_model` (real Store) | 3 passed |
| `login_driver_handler` (real handlers) | 5 passed |
| `integration` `challenge` filter (real Router + Store) | 2 passed |

The adapter tests cover absent (`None`), matching, all cross-purpose
presentations, empty, unknown/truncated, padding, and a long value whose length
must not truncate; one test also asserts the new function agrees with the
former `as_deref().map(stored_tag_from_bytes)` expression on a matrix of values.

The unchanged `integration` tests assert the production behaviour explicitly:
the default purpose is `login`, an invalid purpose is rejected, a login nonce
presented at `/device/enroll` is refused with "challenge was issued for a
different purpose", and the nonce is spent.

## Verification

Successful runs:

- `focused-verify.log`: the main focused gate, exit 0. One `cargo hax` run
  (17 selected functions), source guard "2 extracted modules, 6 proof modules;
  no unreviewed escapes/options", then 8 F* modules verified in one
  `fstar.exe` invocation with `--cache_off`, `--z3rlimit 16000`,
  `--z3version 4.13.3`; "All verification conditions discharged successfully".
- `full-verify.log`: `verify-fstar.sh`, exit 0. The historical 21-selection
  extraction is replayed ("hax: unchanged file"), the historical module is
  verified, then the focused gate above is re-run.
- F* 2025.10.06, Z3 4.13.3, hax 0.3.7, rustc
  1.93.0-nightly (843f8ce2e 2025-11-07) / nightly-2025-11-08.
- Imported hax models emit their retained warnings; zero warnings are not
  claimed.
- Every proof input is a checked-in file; the historical extraction is not
  mixed with the focused partial root modules.

## Mutation check

`mutation-accept-none.diff` mutates a **copy** of the regenerated `Challenge`
module so the adapter's `None` branch returns `Accepted`. F* rejects it
(exit 1, `Error 19` in `classify_taken_challenge_matches_literal`, module lines
164-179), as recorded in `mutation-accept-none.log`. The checked-in extraction
and all inputs were unchanged. Exact argv and the mutant directory are in
`mutation-accept-none-argv.txt`. This shows the `Missing` branch is not proved
by construction and the proof constrains the actual adapter body.

## Explicit assumptions and non-claims

This is a pure adapter refinement. The following remain interface
assumptions/retained trust, not proved here:

- **Trusted boundary:** the OS, compiler, `getrandom`, sled and the imported
  hax models/TCB (`Core_models`, `Alloc.Vec`, `Rust_primitives`) are trusted.
  The `Vec` implementation/allocation/aliasing semantics are the imported hax
  model; this increment does **not** claim the Rust `Vec` implementation is
  verified.
- **Store:** no actual sled atomicity, durability or linearizability proof.
  `get_del` is assumed to remove the key and return the exact stored value
  (or `None`); the adapter is proved over that returned value, not over sled
  internals. TTL/expiry and crash/retry behaviour are not proved.
- **Handler:** the handler passes exactly the `get_del` result to this adapter;
  effect/observation pairing, handler error mapping, `get_del` error status and
  the HTTP layer are not refined.
- **Whole system:** no effects/refinement theorem, no SQL/row/guard semantics,
  no PASETO/JTI security, no verifier soundness, no session/revocation
  linearization, and no claim that the raw bridge or composition covers these.
- The long-value witness uses the checked ten-byte producer value; other
  concrete lengths are covered by the Rust tests and the universally quantified
  lemmas.

## Provenance and currentness

The earlier delegated evidence directories (`login-raw-nonce-bridge`,
`login-raw-nonce-integrated`, `login-tag-producer`, `login-driver`, ...) keep
their original input snapshots and hashes. This increment is local: it is not
hosted, has no CI result, and does not claim that this branch is the current
hosted revision. The parent's raw-bridge review may still adjust scope comments
in modules outside this change; no existing F* body was edited here.

## Counts and hashes

See `counts.txt` and `source-hashes.txt`. In particular:

- new Rust postconditions: **0** (the adapter has none; the 3 challenge
  postconditions are unchanged);
- new generated F* modules: **0** (2 regenerated; `Login_driver` byte-identical);
- new hand-written F* modules: **1** (26 lemmas + 9 definitions);
- existing F*/Rust modules edited: none except the regenerated focused
  extraction and the two production files above;
- handler messages and default purpose: unchanged;
- runner index mode: `100755` (`core.fileMode=false`);
- one mutation check, rejected.

## Reproduction

From `serverVELA/vela-session-policy`, with the environment in `commands.txt`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-login-driver.sh
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar.sh
```

The take-adapter module is wired into the main focused gate. It is not added to
`verify-fstar-login-raw-nonce.sh`, which remains the standalone raw-bridge
runner over its original inputs.

## Parent replay on the current set

After independent review, the parent re-ran the full `verify-fstar.sh` on the
current source set (with the 44-lemma raw nonce bridge): the historical
artifact and all 8 focused modules verified in one invocation, 17 selected
functions / 12 explicit Rust postconditions (`full-verify-current-parent.log`),
and the real-store challenge/login handler tests passed
(`cargo-test-server-handlers-current-parent.log`). `source-hashes.txt` is
re-pinned to that set; the handwritten total is 194 (168 + 26). The fast
source-policy test now also scans `challenge-take-adapter-lemmas/`. The earlier
logs in this folder are the a1436db snapshot. These commands were not run
with `--locked`; no `Cargo.toml` or `Cargo.lock` changed.

## Hosted reproduction

The [ca061a3 security workflow](https://github.com/lucannez64/VELA/actions/runs/40210079502) checked the historical artifact and all
8 focused modules in one invocation; all fifteen PR checks passed.
`hosted-ca061a3.log` holds the argv, summary and module hashes, which match
`source-hashes.txt`.
