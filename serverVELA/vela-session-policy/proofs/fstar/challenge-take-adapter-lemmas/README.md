# Challenge take-adapter lemmas (F*)

Hand-written refinement of the extracted `Option<Vec<u8>>` challenge-take
adapter in `proofs/fstar/extraction-login-driver/Vela_session_policy.Challenge.fst`.

The production function is
`vela_session_policy::challenge::classify_taken_challenge`. The server's
`take_challenge` performs only the effectful `Store::get_del` and then calls it,
so the real conversion/decision path is the extracted function this module
checks.

What is proved, for an arbitrary actual store result and every expected
purpose:

- `None` yields `Missing`;
- `Some v` yields `Accepted` exactly when the bytes carried by `v` are
  `expected`'s literal tag (`login`, `enroll` or `web_token`);
- every other present value — empty, truncated, corrupted, longer than the
  literal, unknown, or another purpose — yields `WrongPurpose` (the take has
  already removed it);
- the bounded conversion retains the actual length, so a long value cannot
  alias a short literal;
- on a present value, the adapter equals the earlier checked
  `raw_login_decision` applied to the same actual slice, and the issued path is
  checked for all three purposes through the adapter.

The literal predicates are written directly over the actual
`Alloc.Vec.t_Vec u8 t_Global` value and its byte positions. They do not call
the implementation's conversion, classifier or contract helpers. No `assume`,
`admit`, `axiom`, `--lax`, `opaque`, local `val` or proof-goal-as-hypothesis is
used.

This is a pure adapter refinement. It does not prove `get_del`
atomicity/durability, sled or handler execution, `Vec` allocation/aliasing,
the trusted imported hax models (`Alloc.Vec`, `Core_models`), TTL/expiry, crash
or retry behaviour, or any effects/refinement theorem. The actual store value
is modelled as a `Vec`, not extracted from sled.

Run the main focused gate (which regenerates the extraction and checks this
module together with the other focused modules) from
`serverVELA/vela-session-policy`:

```
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-login-driver.sh
```
