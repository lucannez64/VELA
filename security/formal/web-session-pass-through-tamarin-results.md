# M20 web-session pass-through assurance record

The final credential-release pass: dynamic route gating for web-session
tokens, closing the last remaining gap after M12's capability lifecycle.

## Gap

M12 proves the web-session *capability lifecycle* — grant, challenge/response
token exchange, renewal, revocation, expiry — and that issued tokens carry
the `web` scope. But the lifecycle alone does not prove what a `web`-scoped
token is *allowed to do* once minted. The actual enforcement is
`authorize_route(scope, class)` in `serverVELA/vela-session-policy`, called
by the `DeviceSession` extractor in `serverVELA/vela-server/src/middleware.rs`:

```
route_is_authorized(scope, class) = scope == Device || class == Vault
```

A web session token may pass through to **vault routes only**; it is
structurally blocked from **permanent-account routes** (recovery, device
enrollment, account deletion). M20 proves this gating.

## Model

`m20_web_session_pass_through.spthy` encodes the policy as rule structure:
`AccessVault` accepts any token, `AcceptAccount` accepts only device tokens
(no rule exists for web tokens on account routes — the blocking is
structural). Token reuse (renewal) is intentionally single-use here to keep
the state space finite; M12 already covers reuse, and the gating depends only
on the scope M12 proves is `web`.

## Proven properties (7/7 verified)

- `web_session_passes_through_to_vault` — a web token traces to a vault
  access (pass-through works).
- `web_session_blocked_from_account_routes` — a web token can never trace to
  an account-route access.
- `device_tokens_retain_full_access` — a device token traces to both route
  classes.
- `account_routes_require_device_token` — every account-route access uses a
  device token.
- `vault_routes_accept_any_token` — vault routes are scope-agnostic.
- `pass_through_reachable` / `device_full_access_reachable` — availability.

## Verification output

```text
m20_web_session_pass_through: 7 verified
m20 web-session pass-through formal proof gate: 7 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-web-session-pass-through-proofs.sh
```

The Rust counterpart is `vela-session_policy::authorize_route` /
`route_is_authorized`, enforced by the `DeviceSession` extractor in
`serverVELA/vela-server/src/middleware.rs`.
