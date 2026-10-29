# Remaining vault/device mutation drivers (F-2 increment)

`serverVELA/vela-rekey-policy/src/vault_mutation_driver.rs` adds small,
per-request drivers for:

- `DELETE /vault/chunk/:id` — schema floor, ACTIVE route, mutation permit,
  version compare-and-swap, guarded delete, publication;
- `PUT /vault/oram/:tree_id/path/:leaf` — route, permit, quota, one guarded
  write and at most one zero-row re-resolution per bucket, publication;
- `POST /vault/schema` — the device-scoped durable floor write;
- `POST /device/capsule/ack` — the guarded clear and the pending-epoch
  inspection (lost-response replay vs a different pending capsule);
- `POST /device/rekey-capable` — the device-scoped positive attestation.

Handlers expand `chunk_delete_interpreter!`, `oram_interpreter!`,
`schema_interpreter!`, `capsule_ack_interpreter!` and
`rekey_capable_interpreter!`; the handler-interpreter wiring test covers all
five.

Focused extraction: `proofs/fstar/extraction-vault-mutation-driver/`; lemmas:
`proofs/fstar/vault-mutation-driver-lemmas/`; gate:
`verify-fstar-vault-mutation-driver.sh`.

## Verified on 4329328

`chunk_delete_step` first failed its postcondition because the soundness
predicates did not say that a stage before Done has not yet answered, failed or
deleted, so an unreachable state the predicate accepted broke the step. No
reachable trace was affected. The five predicates were strengthened, and the
two larger steps split into per-event helpers with their own contracts. The
new tests found that `begin_oram` accepted a negative `bucket_count` and would
then never reach a verdict; the server always passes `buckets.len()`, so the
handler could not hit it, but the driver now refuses any count `<= 0`
(regression test `oram_refuses_a_non_positive_bucket_count`). Lemma budgets
are `--z3rlimit 100`.

## Exact theorems

`chunk_delete_theorem`, `oram_theorem`, `schema_theorem`, `ack_theorem` and
`capable_theorem`: for every request and event sequence, the final driver
state is sound, at most one success or failure is emitted, and every success
follows the guarded write it depends on (the version CAS and delete for chunk
deletion, every bucket write for ORAM, the floor write, the guarded clear,
the attestation write).

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-vault-mutation-driver.sh
```

