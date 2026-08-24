# Vault rekey formal-assurance record

This record covers the account epoch transition implemented by the server,
desktop, and shared client cryptography. The checked claim is deliberately
split across symbolic proof, executable state exploration, real-handler
conformance, and cross-client wire tests.

## Symbolic results

Run with Tamarin Prover 1.12.0 and Maude 3.5.1:

| Theory | Verified | Falsified | Scope |
|---|---:|---:|---|
| `m11_rekey_epoch_state_machine.spthy` | 15 | 0 | lifecycle, completeness, outcomes, acknowledgements, invalidation, reachability |
| `m11b_rekey_capsule_binding.spthy` | 4 | 0 | authenticated epoch/rotation binding over adversarial capsule transport |
| `m11c_rekey_mutation_authority.spthy` | 12 | 0 | atomic web, recovery, and enrollment authority across commit |
| **Total** | **31** | **0** | **0 tool warnings** |

The runner fails closed on warnings, incomplete proof output, falsification, or
lemma-count drift:

```bash
cd security/formal
./run-rekey-proofs.sh
```

The proved safety properties include:

- a transition can commit only after all current chunks and active devices are
  represented at the target epoch;
- commit, abort, and timeout are mutually exclusive outcomes for one rotation;
- abort and timeout preserve the active epoch while commit advances it exactly
  once;
- another transition cannot start until every active device acknowledges the
  committed epoch;
- a capsule relabelled by the transport cannot change the authenticated inner
  epoch or rotation id, and a stale capsule cannot be adopted as current;
- a web mutation, recovery-share write, or enrollment can execute only when its
  authenticated authority equals the epoch at the atomic mutation boundary;
- commit invalidates old recovery authority and web-session authority; and
- successful commit, abort, timeout, current-authority mutation, and post-commit
  mutation paths are reachable.

## Executable refinement evidence

`serverVELA/vela-server/tests/rekey_state_model.rs` adds four independent
checks:

1. A finite-state fixed-point traversal explores accepted and rejected commands
   through epoch 3, four symbolic rotation attempts, two devices, and two
   chunks. Coverage assertions require repeated-commit, stale-authority,
   incomplete-commit, wrong-starter, pending-acknowledgement, replay, abort, and
   timeout edges to be reached.
2. The real Axum handlers and Turso schema execute all 4! = 24 upload orderings
   for two shadows and two capsules. Every strict prefix commit must conflict;
   the complete inventory commits and the database is checked afterward.
3. Start is raced against an active-epoch write repeatedly; the resulting
   inventory version must match the winning serial order, ruling out a lost
   write at the freeze boundary.
4. Expired timeout cleanup is raced with commit and checked for complete removal
   of target-epoch artifacts, preservation of the old share and epoch, and
   rejection of delayed artifacts from the retired rotation id.

`vela-crypto::rekey::{seal_fleet_chunk, open_fleet_chunk}` is the single fleet
wire policy used by desktop, web, Android, and Apple bridges. Its matrix test
crosses every producer and consumer at epochs 1–4, preserves the canonical
legacy epoch-1 format, requires exact epoch-bound AAD afterward, and rejects
epoch zero, wrong epochs, wrong chunk ids, wrong revisions, and legacy
ciphertext after epoch 1.

## Boundary of the claim

These results prove properties of the declared Dolev-Yao transition models,
assuming the modeled cryptographic primitives and uncompromised endpoint keys.
They do not prove memory safety of dependencies, correctness of operating
systems, availability, side-channel resistance, or freedom from unrelated
implementation bugs. The executable tests provide evidence that the current
handlers, schema, and four client implementations refine the modeled boundary;
CI keeps both layers mandatory on later changes.
