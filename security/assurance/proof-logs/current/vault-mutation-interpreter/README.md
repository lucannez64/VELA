# Vault/device mutation interpreters (F-2 increment)

`src/vault_mutation_interpreter.rs` defines the five loops for the remaining
vault/device mutations once. The server handlers expand them with `.await`,
which `security/formal/tests/test_handler_interpreters.py` enforces.

The synchronous expansions `run_chunk_delete`, `run_oram`, `run_schema`,
`run_capsule_ack` and `run_rekey_capable` plus
`proofs/fstar/vault-mutation-interpreter-lemmas/` specify, for every executor,
one call per emitted effect (with the ORAM bucket index), no call after the
verdict, a verdict within the budget, and the per-request driver state.

Each loop also has a cancellation lemma (`chunk_delete_cancellation`,
`oram_cancellation`, `schema_cancellation`, `capsule_ack_cancellation`,
`rekey_capable_cancellation`): every prefix of turns leaves a sound driver
state ([cancellation](../cancellation/README.md)).

## Reproduction

```bash
cd serverVELA/vela-rekey-policy
~/.local/opt/vela-tools/bin/vela-heavy ./verify-fstar-vault-mutation-interpreter.sh
```

