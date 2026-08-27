# M14 account-recovery assurance record

`m14_account_recovery_lifecycle.spthy` models recovery challenge creation,
WebAuthn assertion and user verification, share release, credential/epoch-bound
one-shot enrollment grants, device enrollment, credential registration and
replacement, revocation, expiry, and epoch commit.

The checked runner proves 18 lemmas covering attempt and authority binding,
exact share provenance, WebAuthn causality, challenge/grant linearity,
cross-user and replay resistance, credential replacement, revocation, expiry,
rotation invalidation, device-authorized credential registration, and honest
end-to-end reachability.

```text
m14_account_recovery_lifecycle: 18 verified
recovery formal proof gate: 18 verified, 0 falsified, 0 warnings
```

Run with Tamarin 1.12.0+, Maude 3.x, and a UTF-8 locale:

```bash
./run-recovery-proofs.sh
```

The production refinement is checked by hax/F* in
`serverVELA/vela-recovery-policy`; bounded and concurrency tests cover the
policy-to-SQL/sled boundary.
