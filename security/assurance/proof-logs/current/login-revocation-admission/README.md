# Login/revocation admission correction

A static internal analysis at c8a377d found a concrete race: login can read an
active device, then issue/track a token after revoke enumerated its JTIs and wrote
a 900-second sentinel. The late token expires after the sentinel; a request in
that window can renew it to the session hard cap. Raising the sentinel TTL is
not a durable authority check.

`before.log` reproduces the admission boundary against the real router/database:
issue/track a token after revocation, remove only the temporary sentinel to project
its expiry, then GET /devices. The old middleware returned 200 instead of 401.
This is a controlled schedule projection, not an instrumented concurrent login or
a fifteen-minute wall-clock test. The server token signer is used by the test to
represent the delayed server issuance, not an attacker-held signing key.

The middleware now checks a matching account/device row with revoked=0 on every
new device-token admission, before renewal. Missing/foreign device rows refuse;
web-session tokens retain their separate path. Already-admitted/in-flight requests
are not cancelled; SQL linearizability and observation/effect fidelity remain
assumptions. This is a tested implementation correction, not a middleware trace
refinement theorem. It is separate from the login driver proof being developed.

Additional reviewed implementation corrections:

- Repeat revoke retries JTI enumeration/sentinel writes as well as the web-session
  cascade, retaining the historical 400 response for an already-revoked device.
- Logout suppresses automatic renewal and never advertises a replacement token.
- Schema/revoke suppress renewal because their clients do not consume a successor;
  the old token remains usable until normal expiry unless deliberately revoked.
- Other handler/error paths can still discard a replacement header. No general
  renewal-delivery/liveness or atomic issuance/revocation theorem is claimed.

`after-focused.log` passes the original regression. `final-suite.log` passes 57
library tests, all seven device-revocation tests (including exhaustive depth-three
traces), and all 67 integration tests. Focused tests check absent/foreign device
rows, retry revocation cleanup and near-expiry logout/schema/revoke behavior.
`initial-suite.log` retains four failures before updating test fixtures: three
used signed device tokens without real device rows, and the cascade test expected
a later 409 where durable admission now rejects at 401. The fixtures now represent
registered devices; the stronger authentication check was preserved.

No cryptographic/F* proof source changed in this runtime correction. Tests run
through the shared heavy wrapper; `environment.txt` and `sources.txt` record the
actual tool versions, argv and source-patch/file hashes. Hosted validation and a
focused review of the fix remain pending. This is not an external audit.
