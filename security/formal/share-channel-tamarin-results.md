# M19 share-channel assurance record

Formal verification of the cross-user item-sharing channel: the share-key
registry, capsule relay, and linked-item lifecycle.

## Baseline impossibility (m19a_ek_registry_baseline.spthy)

The pre-M19 registry accepted any well-sized encapsulation key from an
authenticated session. The model proves the resulting substitution attack is
*reachable* (`substitution_attack_is_reachable`, verified): an adversary with
database write access — or merely a stolen session token — installs their own
encapsulation key for a victim, after which every item shared to that victim
is sealed under a key the adversary holds. `every_seal_uses_a_registered_key`
pins down that the damage flows entirely through the registry.

## Fixed protocol (m19b_share_channel.spthy)

`PUT /share/my-ek` now requires a binding signature
(`vela_crypto::signing::share_ek_binding_message`) made by one of the
account's enrolled device identity keys, verified server-side against that
device's stored public key before the registration lands; registrations are
monotonic in their RFC 3339 binding timestamp, so replayed older bindings are
rejected. The model abstracts this as `RegisterShareKey` consuming the
device's private identity key — signature unforgeability means substitution
requires device-key theft, which is the M13/M14 enrollment-compromise class,
outside this channel's threat boundary (stated in the model header).

Proven properties (6/6 verified, post-revision):

- `registrations_require_enrolled_device_signature` — every registered share
  key traces to an enrolled device and a signed binding.
- `bindings_only_cover_account_owned_keys` — devices only ever sign bindings
  for keys they minted themselves.
- `sends_use_registered_bindings` / `deliveries_require_sends` — items are
  sealed under exactly the recipient's registered binding, and every relayed
  capsule traces to a send.
- `opened_items_were_delivered` — a delivered capsule cannot be opened before
  the server relays it (post-review revision).
- `legitimate_share_exchange_is_reachable` — availability of the honest path.

Item confidentiality is structural: capsules are opaque, no rule discloses an
item's plaintext, and the decryption half of each share keypair never leaves
its device (no leak rules exist in the theory — device-key theft is outside
the threat boundary, covered by the M13/M14 enrollment-compromise class,
as stated in the model header).

## Verification output

```text
m19a_ek_registry_baseline: 2 verified
m19b_share_channel: 6 verified (post-revision; see below)
m19 share-channel formal proof gate: lemma counts derived from the theories,
0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-share-channel-proofs.sh
```

The Rust counterpart is the hax-extracted `vela-share-policy`
(`plan_ek_registration`, `plan_send`, `plan_link_mutation`), enforced by
`serverVELA/vela-server/src/share/mod.rs` and `src/account/mod.rs`.

## Post-review revision (2026-08-26/27)

`OpenItem` now requires a distinct `DeliveredCapsule` fact produced by
`DeliverCapsule`, so opening can only occur after delivery. Re-verified for
this exact revision: all 6 m19b lemmas verified (tamarin-prover 1.12.0),
including `opened_items_were_delivered` and
`legitimate_share_exchange_is_reachable`.

Scope note aligned with the theory header: device-key theft is NOT modeled
(no leak rules); RegisterShareKey enforces possession of !DevKey as its
binding premise, and `signing`/`cap` builtins are unused compatibility
declarations. Adversarial capsule exposure is not modeled.
