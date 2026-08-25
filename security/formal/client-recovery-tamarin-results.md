# M15 client-recovery assurance record

`m15_client_recovery_boundary.spthy` models the client boundary between an
adversarial cloud envelope, the WebAuthn-authorized server share, authenticated
Shamir reconstruction, vault epoch rotation, and local RMS adoption.

The checked runner proves 15 lemmas covering exact cloud/server provenance,
account, epoch, split and channel binding, joint share authentication, response
linearity, rotated-epoch invalidation, and honest end-to-end reachability.

```text
m15_client_recovery_boundary: 15 verified
client recovery formal proof gate: 15 verified, 0 falsified, 0 warnings
```

Run with Tamarin 1.12.0+, Maude 3.x, and a UTF-8 locale:

```bash
./run-client-recovery-proofs.sh
```

The production refinement is checked by hax/F* in
`libVELA/vela-client-recovery-policy`. `vela-crypto::recovery` consumes the
verified permit and performs the authenticated Shamir reconstruction used by
desktop, Android, and Apple clients.
