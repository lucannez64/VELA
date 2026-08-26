# M26 composition assurance record

Cross-milestone composition: proving that three individually verified
subsystems — M18 possession recovery, M19 share-key bindings, M20 web-session
gating — cannot be attacked through their interactions with the M23 rotation
ladder.

## The composition gap

Each subsystem's Tamarin model proves its own properties in isolation. But
component proofs don't compose automatically: a rotation that invalidates one
subsystem's state might create an attack window in another. M26 closes this
by putting all four subsystems in a single Tamarin theory where the account's
live epoch is the central linear token every rule consumes or advances.

## Model

`m26_composition.spthy` models:

- `SetupAccount`: creates the account at epoch E, emitting three validity
  tokens (RecoveryValidity, ShareUpdateValidity, WebValidity) plus the live
  epoch token and a single-use rotation budget.
- `IssuePossessionGrant(U,E)`: consumes RecoveryValidity + CurrentEpoch —
  issues an enrollment grant only while the epoch is live.
- `RegisterShareKey(U,E,K)`: requires an enrolled device plus
  ShareUpdateValidity + CurrentEpoch — registers a share key only while
  the binding validity is live.
- `GrantWebSession(U,E)`: requires an enrolled device + WebValidity.
- `WebVaultPassThrough(U,E)`: requires a live web session AND CurrentEpoch —
  each pass-through action is bound to the current epoch.
- `RotateEpoch`: consumes ALL THREE validity tokens plus CurrentEpoch and
  the rotation budget, advancing to a fresh epoch. After this transition:
  no new grants, no share-key registrations, no web sessions can be granted,
  and any outstanding web session cannot perform vault actions.

## Proven properties (3/3 verified)

- `grants_cannot_outlive_their_rotation` — no possession grant is issued
  after its epoch's rotation has consumed the recovery validity token.
- `share_updates_cannot_outlive_their_rotation` — same for share-key
  registrations.
- `web_actions_cannot_outlive_their_rotation` — same for web-session vault
  actions.

These are exactly the composition seams that individual proofs cannot
express: each requires reasoning about the INTERACTION between a subsystem's
operation and the rotation ladder's destruction of its preconditions.

## Verification output

```text
m26_composition: 3 verified
m26 composition formal proof gate: 3 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-composition-proofs.sh
```
