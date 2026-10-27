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

Status: Rust driver tests and the handler wiring pass. The F* gate has not been
run to completion for this increment (the rekey driver gate is the current
blocker); no mutation check is claimed.
