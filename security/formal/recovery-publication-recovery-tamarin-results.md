# M17 crash-consistent recovery-publication assurance record

`m17_recovery_publication_recovery.spthy` models the durable client journal,
the four idempotent external effects, a crash before every local phase commit,
same-split restart, pre-finalization abort, and epoch-rotation retirement.

The checked runner proves 14 lemmas: every external effect has an exact durable
account/epoch/split journal; finalization and promotion retain exact cloud and
server provenance; retries require a prior crash and preserve the operation's
identity; rotation prevents later old-epoch writes; a finalized publication
cannot be abandoned; and a trace with crashes at all four boundaries still
reaches readiness.

```text
m17_recovery_publication_recovery: 14 verified
recovery publication recovery proof gate: 14 verified, 0 falsified, 0 warnings
```

Run with Tamarin 1.12.0+, Maude 3.x, and a UTF-8 locale:

```bash
./run-recovery-publication-recovery-proofs.sh
```

The production refinement is checked by hax/F* in
`libVELA/vela-client-recovery-policy`. Desktop calls that policy directly;
Android and Apple call it through their native Rust bridges. Their encrypted
journals commit the exact shares before external I/O and commit progress only
after the server/cloud operation succeeds.

Filesystem, Keychain/Keystore, HTTP, and cloud-provider durability are trusted
environmental assumptions; the symbolic model proves the state-machine logic.
