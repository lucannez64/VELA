# Computational proof-runner repair

The previous hosted formal-rekey job on fbe35c0 failed with exit 126 before
running CryptoVerif: Git recorded `run-cryptoverif-proofs.sh` as mode 100644.
The repaired runner is recorded as 100755. It also requires successful process
termination and an explicit recognized verdict; timeouts, crashes and missing
verdicts cannot count as the expected legacy non-proof.

`runner.log` and the six model logs record a successful local run using the
pinned CryptoVerif 2.12 installation. Five models prove their queries; the legacy
v1 baseline explicitly cannot prove bit secrecy. That is not an attack trace.
The run used `vela-heavy`, which serializes heavy commands across all worktrees,
then the repository's 3 GiB/no-swap/one-worker cap. No cap was raised.

`negative-gates.log` records six regression tests of the actual shell runner
using a tiny fake verifier, including exit 124, exit 137 after a proved banner,
missing verdict, an error banner, expected complete verdicts and the Git-tracked
executable bit. These synthetic tests are not computational security proofs.
They run in CI before installing/running CryptoVerif.

Commands from repository root:

```bash
CRYPTOVERIF=/path/to/cryptoverif2.12/cryptoverif security/formal/run-cryptoverif-proofs.sh
python3 -m unittest discover -s security/formal/tests -p 'test_cryptoverif_runner.py' -v
```

Model statements and remaining construction/correspondence gaps are in
`security/formal/cryptoverif/README.md`. Hosted reproduction of the repair is
pending; this directory does not establish complete computational Rust
refinement or whole-system security.
