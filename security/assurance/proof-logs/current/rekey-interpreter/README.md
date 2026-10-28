# Vault key-rotation interpreter (F-2 increment)

`src/rekey_interpreter.rs` defines the four rotation loops once
(`rekey_start_interpreter!`, `rekey_capsules_interpreter!`,
`rekey_commit_interpreter!`, `rekey_abort_interpreter!`). Each handler in
`serverVELA/vela-server/src/vault/rekey.rs` expands exactly one of them with
`.await`; `security/formal/tests/test_handler_interpreters.py` enforces that and
forbids importing or calling a driver transition in the handlers.

The synchronous expansions (`run_start`, `run_capsules`, `run_commit`,
`run_abort`) and the lemma module
`proofs/fstar/rekey-interpreter-lemmas/` prove, for every executor, that the
loop calls only the method for the driver's current effect, performs nothing
after the verdict, reaches a verdict within 67 turns, and ends in the
per-request driver state.

Status: the interpreter extraction and lemma module are present, but the
upstream driver gate currently fails, so this gate is not yet green. The Rust
interpreter conformance tests pass (scripted executors replay every effect and
compare against the driver).
