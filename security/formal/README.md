# Formal models — credential release, epoch rotation, and session capability

Symbolic (Dolev-Yao) models checked with
[Tamarin](https://tamarin-prover.com/). The directory contains three independent
families: thirteen credential-release theories (`m1`–`m10`), three vault
epoch-rotation theories (`m11`, `m11b`, `m11c`), the M12 web-session
capability lifecycle, the M13 permanent-device enrollment ceremony, the M14
account-recovery lifecycle, the M15 client recovery boundary, the M16
two-phase recovery-publication protocol, and the M17 crash/restart publication
journal. Together they contain 209 lemmas: 204 verified and five
intentionally falsified impossibility claims.

Read the assurance record for the family being changed:

- [`password-manager-ipc-tamarin-results.md`](password-manager-ipc-tamarin-results.md)
  covers credential release.
- [`rekey-tamarin-results.md`](rekey-tamarin-results.md) covers epoch rotation,
  capsule binding, and mutation authority.
- [`session-tamarin-results.md`](session-tamarin-results.md) covers temporary
  browser grants, token scope, renewal, revocation, and expiry.
- [`enrollment-tamarin-results.md`](enrollment-tamarin-results.md) covers the
  permanent-device rendezvous, exact key binding, replay, and invalidation.
- [`recovery-tamarin-results.md`](recovery-tamarin-results.md) covers WebAuthn
  recovery, share release, credential replacement, and recovered enrollment.
- [`client-recovery-tamarin-results.md`](client-recovery-tamarin-results.md)
  covers cloud/server share binding, authenticated reconstruction, and RMS
  adoption across the desktop, Android, and Apple clients.
- [`recovery-publication-tamarin-results.md`](recovery-publication-tamarin-results.md)
  covers staging, immutable cloud durability, exact finalization, active-pointer
  promotion, same-epoch races, retries, and epoch invalidation.
- [`recovery-publication-recovery-tamarin-results.md`](recovery-publication-recovery-tamarin-results.md)
  covers durable client journaling, crashes at every external-effect boundary,
  same-split resume, abort limits, and stale-epoch retirement.

| File | What it models |
|---|---|
| `m1_indomain.spthy` | in-domain checks only — **falsifies**, the impossibility result |
| `m2_se_alone.spthy` | hardware key storage without a decision escape — **falsifies** |
| `m3_de_se.spthy` | human approval + hardware key: the working-set bound |
| `m4_bool_naive.spthy` | an unbound boolean approval — replayable, worthless |
| `m5_tr_originbound.spthy` | origin-bound signature: zero persistent value |
| `m6_ipc_handshake.spthy` | the real browser↔desktop handshake: pairing, per-client keys, grant lifecycle, browser-spawn gate (no capability file) |
| `m7_oneshot_assertion.spthy` | passkey-shaped one-shot assertion — below the working-set floor |
| `m8_hybrid.spthy` | M7 for passkey origins + M6 for legacy, airtight mode split |
| `m9a_in_core_login.spthy` | in-core login for plain-form sites — credential never enters the domain |
| `m9d_captcha_artifact.spthy` | the CAPTCHA-artifact tier: browser mints the token + cookie jar, core submits the credential — the artifact is adversary-observable and that changes nothing |
| `m9b_engine_login.spthy` | the same via an embedded browser engine — **falsifies**, don't do this |
| `m9c_inprocess_sandbox.spthy` | the same via a JS runtime inside the core — keeps the credential out of the domain, but an escape takes the whole vault instead of the working set |
| `m10_full_ladder.spthy` | the deployment: M7 → M9a → M6 per origin tier |
| `m11_rekey_epoch_state_machine.spthy` | ACTIVE/FREEZING lifecycle, completeness, commit/abort/timeout, acknowledgements, and epoch invalidation |
| `m11b_rekey_capsule_binding.spthy` | authenticated `{epoch, rotation_id, rms}` capsules over an adversarial transport, including relabel/replay attempts |
| `m11c_rekey_mutation_authority.spthy` | atomic web, recovery, and enrollment authorization at the mutation boundary across epoch commits |
| `m12_web_session_capability.spthy` | pending/granted/terminal web-session lifecycle, one-shot artifacts, scope preservation, and permanent-route separation |
| `m13_device_enrollment_ceremony.spthy` | opener-bound permanent-device claim, inspection, exact key/signature binding, atomic completion, result proof, and terminal states |
| `m14_account_recovery_lifecycle.spthy` | attempt/credential-bound WebAuthn recovery, exact share release, one-shot enrollment grant, credential replacement, expiry, and epoch invalidation |
| `m15_client_recovery_boundary.spthy` | adversarial cloud envelopes, exact account/epoch/channel binding, authenticated same-split Shamir reconstruction, and current-epoch RMS adoption |
| `m16_recovery_publication_consistency.spthy` | two-phase server staging/finalization and cloud candidate/pointer promotion, with exact split binding under retries, same-epoch races, and rotation |

`password-manager-ipc-leak-graph.py` produces the quantitative companion
(`.png`): the symbolic models say *which* items can leak, the graph says *how
many*, over time.

## Re-running credential-release proofs

Needs `tamarin-prover` 1.12.0+, `maude` 3.x, and a UTF-8 locale.

```bash
export LC_ALL=C.UTF-8 LANG=C.UTF-8
for f in m1_indomain m2_se_alone m3_de_se m4_bool_naive m5_tr_originbound \
         m6_ipc_handshake m7_oneshot_assertion m8_hybrid m9a_in_core_login \
         m9b_engine_login m9c_inprocess_sandbox m9d_captcha_artifact \
         m10_full_ladder; do
  echo "== $f =="
  tamarin-prover --prove "$f.spthy" 2>/dev/null | grep -E ': (verified|falsified)'
done
```

Expected: **83 verified, 5 falsified** (88 lemmas total across the thirteen
theories). The five falsifications are intended
results, not failures — `m1`/`m2` secrecy, `m9b`'s and `m9c`'s `credential_never_leaks`,
and `m9c`'s `unused_credentials_stay_secret`
are the negative claims the ladder is built on. Any *other* falsification is a
regression.

## Re-running epoch-rotation proofs

The checked runner rejects tool warnings, incomplete results, unexpected
falsifications, and lemma-count drift:

```bash
./run-rekey-proofs.sh
```

Expected: **31 verified, 0 falsified, 0 warnings** across the three theories.
The same command is a required job in `.github/workflows/security.yml`.

## Checking the rekey implementation

Tamarin establishes the protocol properties; hax and F* check that the pure
Rust decisions used by the server refine the corresponding M11/M11c rules.
The implementation proof covers epoch routing, overflow-safe successor
selection, shadow and attempt authority, start readiness, commit completeness,
exact epoch advancement, abort/timeout preservation, commit replay binding, and
the M11c ACTIVE-state permit shared by vault, recovery, and enrollment
mutations. The executable state model checks that the atomic SQL guards accept
exactly the state/epoch relation carried by that permit:

```bash
cd ../../serverVELA/vela-rekey-policy
./verify-fstar.sh
```

See [`../../serverVELA/vela-rekey-policy/README.md`](../../serverVELA/vela-rekey-policy/README.md)
for the pinned hax, F*, and Z3 installation commands and the exact proof
boundary.

## Checking the web-session implementation

M12 checks the protocol lifecycle, while `vela-session-policy` verifies the
production Rust decisions for grant binding, token issuance, renewal, and route
authorization:

```bash
./run-session-proofs.sh
cd ../../serverVELA/vela-session-policy
./verify-fstar.sh
```

Expected: **14 Tamarin lemmas verified** and all F* verification conditions
discharged. See
[`../../serverVELA/vela-session-policy/README.md`](../../serverVELA/vela-session-policy/README.md)
for the exact implementation-proof boundary.

## Checking permanent-device enrollment

M13 proves the symbolic v3 rendezvous lifecycle, while
`vela-enrollment-policy` verifies the Rust decisions used by the grant, claim,
inspection, completion, and result handlers:

```bash
./run-enrollment-proofs.sh
cd ../../serverVELA/vela-enrollment-policy
./verify-fstar.sh
```

Expected: **15 Tamarin lemmas verified** and all F* verification conditions
discharged. The production boundary additionally has a serializable sled
grant+claim take and concurrency tests proving exactly one racing completion
wins. See
[`../../serverVELA/vela-enrollment-policy/README.md`](../../serverVELA/vela-enrollment-policy/README.md).

## Checking account recovery

M14 proves the symbolic WebAuthn recovery and recovered-device lifecycle,
while `vela-recovery-policy` verifies the Rust decisions used by initiation,
credential registration/update, share release, and device enrollment:

```bash
./run-recovery-proofs.sh
cd ../../serverVELA/vela-recovery-policy
./verify-fstar.sh
```

Expected: **18 Tamarin lemmas verified** and all F* verification conditions
discharged. The production boundary binds challenges and grants to the current
credential, atomically consumes sled artifacts, and guards SQL enrollment by
both epoch and credential id. See
[`../../serverVELA/vela-recovery-policy/README.md`](../../serverVELA/vela-recovery-policy/README.md).

## Checking client-side recovery reconstruction

M15 treats the cloud envelope as adversary-controlled and proves that only the
exact cloud/server shares for one account, epoch, and split can reach RMS
adoption. `vela-client-recovery-policy` verifies the shared Rust decisions used
by desktop, Android, and Apple before authenticated Shamir reconstruction:

```bash
./run-client-recovery-proofs.sh
cd ../../libVELA/vela-client-recovery-policy
./verify-fstar.sh
```

Expected: **15 Tamarin lemmas verified** and all F* verification conditions
discharged. The production boundary accepts either a matching split ID on both
shares or the legacy case where both IDs are absent, and rejects one-sided or
mismatched IDs, accounts, epochs, channels, coordinates, and unauthenticated
splits before any RMS is adopted.
See
[`../../libVELA/vela-client-recovery-policy/README.md`](../../libVELA/vela-client-recovery-policy/README.md).

## Checking recovery setup publication

M16 proves that a setup is reported ready only after the exact staged server
share and durable cloud candidate are finalized under one account epoch and
split, then promoted to the active cloud pointer. It also proves that only one
same-epoch racing candidate wins and that rotation blocks old-epoch
finalization. The server policy verifies the production stage/finalize permits:

```bash
./run-recovery-publication-proofs.sh
cd ../../serverVELA/vela-recovery-policy
./verify-fstar.sh
```

Expected: **14 Tamarin lemmas verified** and all F* verification conditions
discharged. The SQL integration test exercises the exact pending-row compare
and atomic promotion used by the HTTP handlers.

## Checking crash-consistent recovery publication

M17 proves that desktop, Android, and Apple can crash after any recovery
publication effect and resume the same account/epoch/split journal without
mixing shares or abandoning a server-finalized publication. Rotation retires
the journal and blocks further writes under its old epoch. The shared Rust
reducer is verified by hax/F* and used directly or through each native bridge:

```bash
./run-recovery-publication-recovery-proofs.sh
cd ../../libVELA/vela-client-recovery-policy
./verify-fstar.sh
```

Expected: **14 Tamarin lemmas verified** and all F* verification conditions
discharged. Client tests cover encrypted journal round trips and impossible
phase rejection; the bounded Rust test exhausts the reducer's Boolean state
space across valid, malformed, and retired epochs.

## Checking the full 2-of-3 pair-selection threshold

M18 proves the complete recovery threshold: any two *distinct* channels —
cloud + server, cloud + trusted contact, or server + trusted contact —
reconstruct the RMS, while cross-account, mixed-epoch, mixed-split,
duplicate-coordinate, duplicate-channel, and raw (non-recipient-bound)
contact shares can never pair. The server releases Share 2 only behind
WebAuthn; trusted-contact shares move exclusively through opaque sealed
envelopes answered to a requester-held ephemeral key; rotation retires every
old-epoch pair. All three honest pairs remain recoverable (availability).

```bash
./run-pair-selection-proofs.sh
cd ../../libVELA/vela-client-recovery-policy
./verify-fstar.sh
```

Expected: **15 Tamarin lemmas verified**. The shared Rust policy is
`vela-client-recovery-policy::plan_reconstruction` /
`plan_contact_delivery`; the recipient-bound envelope construction lives in
`vela-crypto::recovery` (`seal_contact_share`, `open_contact_share_response`)
and the WebAuthn-free enrollment path in the server's possession-proof
endpoints (`/recovery/initiate-proof`, `/recovery/recover/proof`).

## Checking the cross-user share channel

M19 proves the item-sharing protocol: the pre-M19 registry's key-substitution
attack is demonstrated reachable in `m19a_ek_registry_baseline.spthy`
(falsification baseline), and `m19b_share_channel.spthy` proves the fixed
design — share keys register only under a device-signed binding
(`vela share-ek binding v1`, monotonic timestamps), items are sealed only
under registered bindings, deliveries trace to sends, and the honest
exchange is reachable.

```bash
./run-share-channel-proofs.sh
cd ../../serverVELA/vela-share-policy
./verify-fstar.sh
```

Expected: **2 + 5 Tamarin lemmas verified** and all F* verification
conditions discharged. The enforced policy lives in
`serverVELA/vela-share-policy`; the binding construction in
`libVELA/vela-crypto/src/signing.rs`; enforcement in
`serverVELA/vela-server/src/share/mod.rs` and `src/account/mod.rs`.
