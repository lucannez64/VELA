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

## Status

The F* gate does not pass yet: `chunk_delete_step`'s postcondition fails
(Error 19), so nothing below is claimed until it does. The gate is not chained
from `verify-fstar.sh`. Rust driver tests and the handler wiring pass.

## Intended theorems (not yet verified)

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

