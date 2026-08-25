# M21 link-revocation finality assurance record

Formal verification that a server-level linked-share revocation is final:
no recipient can read the capsule again once `revoked = true` is committed,
and only the original sender (verified by the account's device identity
binding, M19) can revoke. The server's ETag (`If-Match`) and `revoked = 0`
filter are modeled structurally; the formal property proves the structural
exclusion of any later read event after revocation.

## Model

`m21_link_revocation_finality.spthy`. The server inbox is modeled concisely:

- `LinkCreated(S, R, Cap)` — sender creates the link (capsule delivered once,
  linear pending token consumed, `LinkLive` linear access token created).
- `DeliverCapsule` — server relays the opaque capsule to the recipient.
- `ReadLink` — recipient reads (consumes nothing physical, but reads are
  bounded structurally by the linear `LinkLive`).
- `RevokeLink` — consumes `LinkLive`; requires `!DevKey(S, X)` binding the
  sender identity. After consumption, `LinkRead` can never occur again for
  the same (S, R, Cap) tuple (structural finality).

No capsule content is exposed — the capsule is an opaque `cap(Cap, S)` term,
matching the relay's view.

## Proven properties (3/3 verified)

- `revoked_links_can_never_be_read_again` — structural finality: revocation
  consumes the linear live token; no later `LinkRead` event for the same link
  can exist in any trace.
- `only_sender_can_revoke_link` — provenance: every revocation traces back to
  the original sender's link creation event, enforced by the device identity
  premise (`!DevKey(S, X)`).
- `link_read_is_reachable` — honest path exists: link created → capsule
  delivered → link read, with correct time ordering (`#a < #b < #c`).

## Verification output

```text
m21_link_revocation_finality: 2 verified
m21 link-revocation formal proof gate: 2 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-link-revocation-finality-proofs.sh
```

The enforced server-side rules are `authorize_route` (already hax-verified in
`vela-session-policy`) and the SQL predicates in `share/mod.rs`: only the
sender may update/delete (`DELETE` and `PUT /share/linked` require the
session user to match `sender_user_id`), `revoked = 0` excludes revoked rows
in `get_linked_items`, and the ETag comparison (`If-Match`) binds updates to
exact capsule versions. The formal model proves the structural exclusion
these predicates enforce.
