# Computational-model review corrections

Parent commit: 40c9f30. This increment addresses an internal DeepSeek model/Rust
correspondence review. It is not an independent external audit. All evidence
here is local; a configured CI step is not a successful hosted execution.

The GDH and legacy games now include the correctness equation

```text
mldecap(mlencap_ct(mlpkgen(sk), seed), sk) = mlencap_ss(mlpkgen(sk), seed)
```

This lets public decapsulation with the disclosed key recover the honest
challenge's ML-KEM secret too. It is an explicit perfect-correctness assumption,
not a proof of ML-KEM implementation correctness. No ML-KEM secrecy assumption
is introduced. The snapshots in `models/` preserve all six exact model sources.

`runner.log` and the six model logs record the final hardened CryptoVerif 2.12
run with five proved queries and the explicit legacy non-proof.
`correctness-runner.log` is the summary of an earlier run immediately after the
correctness-equation change; its temporary output directory differs, and the
six retained model logs belong to the final run. The strengthened GDH
bound is unchanged: `4*pDistRerandom + 2*pGDH(t,2*qH) + (2*Qd+2*qH)/|Z|`.
The ML-KEM-survives bound retains its collision and finite-domain terms.
The legacy result is not a counterexample: the conditional hand argument also
requires a second ciphertext with the challenge shared secret, a capability
not implied by secret-key disclosure alone and not supplied by this game.

The corrected claims distinguish uniform prime-order DH from real X25519
clamped/nonuniform scalars and cofactor behavior; the former HPKE justification
was removed. Hash/KDF, perfect-correctness, collision, multi-user, quantum-query,
encoding, Rust and modular-composition gaps remain explicit. Signature bounds
are used for a surviving component; their minimum requires a common game in
which both bounds apply. Contradictory statements that no computational proofs
exist were reconciled with these scoped exceptions.

The hardened gate additionally requires the expected proved query result and
rejects local manual/admitted proof declarations. Its lexical guard does not
validate every primitive assumption/equation/type or establish correspondence.
Synthetic runner/source-guard tests are separate from security-model proofs.

All real proof runs use the shared `vela-heavy` lock and the repository's
3 GiB, no-swap, one-worker cap. Reproduce with checksum-pinned CryptoVerif 2.12
and its matching `default.ocvl`:

```bash
security/assurance/bounded.sh env CRYPTOVERIF=/path/to/cryptoverif2.12/cryptoverif security/formal/run-cryptoverif-proofs.sh
python3 -m unittest discover -s security/formal/tests -p 'test_cryptoverif_runner.py' -v
```

Complete statements, bounds and residual assumptions are in
`security/formal/cryptoverif/README.md`. No full-system, complete concrete-KEM,
QROM or protocol-composition theorem is supplied.

The final hardened gate also exited zero: `runner.log` records all five expected
proved query results and the explicit legacy non-proof, after the local source
guard passed. The six model logs above are from that final run.
`negative-gates.log` records eleven passing synthetic runner/source-guard tests;
they are not computational proofs. The second internal review round inspected 4cc4dd6 and found no new game
soundness error. It confirmed the equation and unchanged bound; subsequent
wording/provenance edits address its residual comments. It did not rerun the
prover and is not an independent external audit or an additional proof.
