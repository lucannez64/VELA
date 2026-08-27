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

The runner tests the crate, extracts eight production/theorem entry points, and
asks F* to discharge every postcondition without `--lax`.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-session-proofs.sh
```

Expected: **14 verified, 0 falsified, 0 warnings**.
