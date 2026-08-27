# M18 pair-selection assurance record

Formal verification of the complete 2-of-3 recovery threshold across all
three custodian channels (cloud provider, VELA server, trusted contact).

## Model

`m18_pair_selection.spthy` models one recovery split publishing three shares:

- **Cloud** — public from birth; the adversary replays or relabels envelopes,
  but a share only enters reconstruction after origin-checked authentication
  (`AcceptCloudShare`), the symbolic counterpart of MAC verification against
  the reconstructed secret.
- **Server** — released exclusively behind a verified WebAuthn assertion
  (`ReleaseServerShare`).
- **Trusted contact** — sealed into an opaque envelope at setup
  (`SealContactEnvelope`); the contact answers a recovery request by
  re-sealing the share to the requester's published ephemeral key. Only the
  holder of the matching request secret can deconstruct the response — this
  is exactly the recipient binding the KEM+AEAD envelope enforces in
  `vela-crypto::recovery`. No raw copied contact share can ever enter
  reconstruction.

Pair selection admits exactly three adoption shapes (cloud+server,
cloud+contact, server+contact) with distinct coordinates by construction;
interpolation consumes a linear per-epoch authority, so a committed rotation
retires every old-epoch pair. A possession-proof enrollment grant issues only
after a full pair adoption.

## Proven properties (15/15 verified)

Safety:

- `adoption_requires_pair_authentication` — no adoption without an
  authenticated two-share pair.
- `adopted_pairs_have_distinct_channels` /
  `adopted_pairs_have_distinct_coordinates` — duplicate custodians and
  duplicate Shamir coordinates are impossible.
- `every_authenticated_share_has_exact_context_origin` — any authenticated
  share belongs to exactly one account/epoch/split.
- `cross_account_share_cannot_pair`, `mixed_epoch_shares_cannot_pair`,
  `mixed_split_shares_cannot_pair` — replay, cross-account, mixed-epoch and
  mixed-split combinations cannot reconstruct.
- `server_share_requires_webauthn_release` — Share 2 never leaves the server
  without a passing assertion.
- `contact_share_only_flows_through_recipient_bound_response`,
  `adopted_contact_share_was_recipient_bound` — every contact share used in
  recovery passed through the recipient-bound envelope response path.
- `possession_grant_requires_full_pair_adoption` — the WebAuthn-free
  enrollment grant is issued only after two shares reconstructed the RMS.
- `rotation_blocks_later_old_epoch_adoption` — RMS rotation retires every
  earlier share, including held contact copies.

Availability:

- `legitimate_cloud_server_recovery_is_reachable`,
  `legitimate_cloud_contact_recovery_is_reachable`,
  `legitimate_server_contact_recovery_is_reachable` — losing any single
  custodian (cloud provider or security key included) still leaves a verified
  recovery path through the remaining two channels.

## Verification output

```text
m18_pair_selection: 15 verified
m18 pair-selection formal proof gate: 15 verified, 0 falsified, 0 warnings
```

Toolchain: tamarin-prover 1.12.0, Maude 3.5.1, UTF-8 locale.

Reproduce with:

```sh
./security/formal/run-pair-selection-proofs.sh
```

The Rust counterpart of this policy is the hax-extracted
`vela-client-recovery-policy::plan_reconstruction` (pair selection) and
`vela-client-recovery-policy::plan_contact_delivery` (trusted-contact sealing
and retirement), refined in F* under
`libVELA/vela-client-recovery-policy/`.
