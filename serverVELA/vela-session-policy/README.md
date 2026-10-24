# Verified web-session capability policy

This crate is the pure production policy for temporary browser capabilities.
Tamarin M12 proves the protocol lifecycle; hax extracts the Rust decisions to
F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `parse_scope_claim` | Explicit unknown scopes reject; `web_session` cannot parse as `device`. Missing claims retain the bounded legacy-device interpretation. |
| `plan_grant` | A grant requires a pending session, matching approver and nonce, a positive epoch, and an RW verification key when RW is requested. |
| `plan_web_session_token` | Issuance requires a live RW grant, its bindings, one consumed challenge, and a valid signature; the plan is always web-scoped and epoch-bound. |
| `plan_device_token` | Device issuance has device scope, no web epoch, a live expiry, and an overflow-safe hard cap. |
| `plan_renewal` | Renewal preserves the exact scope, optional epoch, and hard cap while bounding the new expiry. |
| `authorize_route` | Web sessions may access vault routes but can never receive a permanent-account route permit. |
| `renewal_escalates_authority` | Renewal never changes scope or epoch. |
| `terminal_session_issues_token` | Revoked and expired sessions never issue tokens. |

The proof boundary excludes PASETO cryptography, HTTP parsing, signature
verification, clocks, SQL execution, and storage atomicity. Production code
turns those observations into policy facts and signs only the private
`TokenPlan` returned by the policy. Handler, state-model, and concurrency tests
cover the boundary to Turso and sled.

## Run

Use the hax 0.3.7, Rust nightly 2025-11-08, F* 2025.10.06, and Z3 4.13.3
toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md). Then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner tests the crate, extracts 21 production/theorem entry points, and
asks F* to discharge every postcondition without `--lax`.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-session-proofs.sh
```

Expected: **14 verified, 0 falsified, 0 warnings**.

## Observation construction

`grant_facts` computes the approver comparison from optional account IDs and
requires both a 32-byte nonce and a successful nonce comparison. `web_token_facts`
computes account binding from two present, equal account IDs: `(None, None)`
never grants authority. Both preserve every other supplied observation exactly.
`plan_observed_grant` and `plan_observed_web_token` compose these constructors
with the existing decisions and are called by the production web-session
handlers. Six negative theorems cover absent approvers, wrong nonce length,
cross-account exchange, missing accounts, unconsumed challenges and invalid
signatures. The signature observation comes from the actual verifier result.

The current runner selects 21 functions with 19 explicit postconditions. Two
previously selected comparison predicates have no `ensures`; this increment
adds ten postconditions. Source observations (SQL rows, parsed UUID-to-u128
conversion, status/mode decoding, nonce comparison, signature verification,
clocks and sled challenge consumption) and actual SQL/token effects remain
outside these pure proofs. Rejection paths that return before construction
remain Rust glue; the new constructors do not prove complete handler traces.
