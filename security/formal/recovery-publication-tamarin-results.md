# M16 recovery-publication assurance record

`m16_recovery_publication_consistency.spthy` models the two-phase boundary
between replaceable server staging, immutable cloud-candidate durability,
atomic server finalization, mutable active-pointer promotion, and recovery
readiness.

The checked runner proves 14 lemmas covering exact staging and cloud
provenance, a single winner for same-epoch races, loser restaging, exact active
pointer promotion, reconstruction readiness, idempotent winner retries, epoch
rotation, and honest end-to-end reachability.

```text
m16_recovery_publication_consistency: 14 verified
recovery publication formal proof gate: 14 verified, 0 falsified, 0 warnings
```

Run with Tamarin 1.12.0+, Maude 3.x, and a UTF-8 locale:

```bash
./run-recovery-publication-proofs.sh
```

The production refinement is checked by hax/F* in
`serverVELA/vela-recovery-policy`. The HTTP handlers apply those permits to
atomic SQL guards. Desktop, Android, and Apple upload the immutable cloud
candidate before finalization and publish the active pointer only after the
server accepts the exact split.

Cloud durability and provider API correctness are trusted environmental
assumptions; they are not established by the symbolic model.
