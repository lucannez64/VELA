# Extended sharing formalization, 2026-10-23

Baseline HEAD: `148ff3261b62bd60df0d99d354e093500779fdce`, plus the changes
identified by the package manifest. Local results; no new CI success or
independent review is claimed.

- `share-state-fstar.log`: ten new transaction/recovery postconditions plus
  eight existing share-admission postconditions checked without `--lax`.
- `share-facts-fstar.log`: fresh extraction/checking of those 18 postconditions
  and the actual `admission_facts` constructor. Both modules report all
  verification conditions discharged. Imported libraries emit existing
  warnings; they and the String compatibility view remain trusted.
- `m28_share_journal.log`: seven named properties verified, no warnings or
  falsifications; full proof output retained.
- `share-journal-stronger-goals-unfinished.log`: stronger all-pairs monotonicity
  and generation-uniqueness search, stopped without verdicts; NOT proof evidence.
- `desktop-core-tests.log`: 464 passed, zero failed, eight existing ignored.
  This command used `--offline` without `--locked` to add the direct policy
  dependency to the desktop lockfile; the only change is that dependency edge.
- `desktop-core-locked-tests.log`: a subsequent run with the updated lockfile
  and `--locked` also passed all 464 tests (eight existing ignored).
- `crypto-tests.log`: all 121 core unit tests passed with `--locked`.
- `trusted-library-inventory.txt`: installed hax-lib 0.3.7 proof-library hashes
  and assumption sites; not a complete TCB review.
- `extractions/`: newly checked policy/constructor modules and String model.
  Other policy modules retain their evidence in `../refinement-5g/`.

Reproduce with the pinned tools on PATH:

```bash
security/assurance/bounded.sh libVELA/vela-crypto/verify-share-facts-fstar.sh
python3 security/assurance/check-proof-boundary.py
VELA_PROOF_OUT=/tmp/vela-journal security/formal/run-share-journal-proofs.sh
security/assurance/bounded.sh env CARGO_PROFILE_DEV_CODEGEN_BACKEND=llvm \
  cargo +nightly test --manifest-path desktopVELA/Cargo.toml \
  -p vela-desktop-core --locked --lib
```

Runs used a 3 GiB process-tree cap per command, no swap, one worker and the
bounded runners' timeouts. No engine rebuild was needed. Proof-tool versions
are in `../refinement-5g/versions.txt`; the standard test compiler is in
`../sharing-fixes/versions.txt`. See the
[remaining obligations](../../../08-formalization-status.md).
