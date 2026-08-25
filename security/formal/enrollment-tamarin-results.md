# M13 permanent-device enrollment assurance record

`m13_device_enrollment_ceremony.spthy` models the v3 rendezvous as a linear
grant bound to its opener, a first-writer claim, inspection and confirmation of
the exact stored keys, completion under the opener's signature and active
epoch, and result collection under the joining key.

The checked runner proves 15 lemmas: single claim and completion, opener-bound
inspection, causal human confirmation, exact signature/capsule and enrolled-key
binding, one device per grant, result provenance and joining-key proof,
revocation/expiry/epoch invalidation, and two honest reachability witnesses.

```text
m13_device_enrollment_ceremony: 15 verified
enrollment formal proof gate: 15 verified, 0 falsified, 0 warnings
```

Run with Tamarin 1.12.0+, Maude 3.x, and a UTF-8 locale:

```bash
./run-enrollment-proofs.sh
```

Tamarin establishes the symbolic protocol properties. The production
refinement is checked by hax/F* in `serverVELA/vela-enrollment-policy`; sled
unit tests exercise first-claim-wins and atomic pair consumption under races.
