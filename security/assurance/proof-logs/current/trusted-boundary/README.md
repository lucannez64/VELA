# Selected-boundary verification, 2026-10-23

Trust boundary: OS/compiler and primitive security, as selected by the maintainer
and specified in `../../../09-target-contract.md`. VELA constructions and
application behavior remain obligations; this is not full-system completion.
Implementation baseline HEAD is `148ff3261b62bd60df0d99d354e093500779fdce` plus
the reviewed changes identified by the current artifact manifest.

## Checked results

- `refinement/*.log`: fresh hax extraction and F* checking for all eight policy
  crates after structural-equality refactoring. The previous eighteen opaque
  PartialEq assumptions are gone. Three new finite-domain tests exhaustively
  compare structural mode/scope/route/channel/merge equality against the actual
  Rust derived equality across all 37 value pairs. Other unit and bounded tests
  in those runners passed as well.
- `share-facts-and-signatures-fstar.log`: the policy's 19 postconditions and six
  actual crypto functions are checked without lax mode. These are the decoded-
  field fact constructor, raw-observation -> policy composition, exact prefix
  reader, AND gate and its rejection theorems. The policy also checks the
  permit revision getter.
  Imported libraries and the explicitly defined String view remain trusted.
- `m28_share_journal.log`: seven exact named journal properties verified.
- `m29_signed_share_commit.log`: eleven exact named composed-model properties
  verified, including helper lemmas. Independent signing-component compromise,
  pin preservation, durable sender provenance and honest crash/recovery/update
  reachability share one state machine. No KEM confidentiality claim is made.
- `uncertain-write-before-fix.log`: intentionally failing regression against
  recovery before the additional journal re-arm. The final suite passes after
  the fix; `../../../uncertain-write-counterexample.patch` recreates the previous
  ordering from the fixed source. The test checks visible/uncertain-write
  ordering, not physical power loss.
- `full-run/summary.txt`: the complete integrated assurance command passed all
  29 steps, including all models, F* and the boundary gate. This run preceded
  the final uncertain-write fix and chosen-message strengthening. The affected
  desktop regression and strict M28/M29 gates were rerun afterward; their current
  logs above supersede those steps' earlier snapshots. Final correspondence is
  separately checked against the manifest's source. No immutable hosted CI run
  is claimed.
- `proof-search-heap-limit.txt`: truncated exploratory failure diagnostic before
  lemma reuse was restricted. This is NOT proof evidence; the final complete
  M29 run succeeded within the same capped heap. Proof hints hide irrelevant
  proved lemmas and add trace observations, without adding guards/assumptions.
- `crypto-tests.log`: 122 passed, zero failures.
- `desktop-core-tests.log`: 465 passed, zero failures, eight existing ignored.
- `apple-bridge-tests.log`: 15 passed, zero failures.
- `android-bridge-tests.log`: 25 passed, zero failures.
- `extractions/`: current checked modules and the String compatibility model.
- `versions.txt`: baseline revision and actual standard-test compiler/Cargo.
  Proof tools retain the pinned versions in `../refinement-5g/versions.txt`.

The inventory has 117 explicitly selected entry points and 114 explicit
postconditions in ten extracted Rust modules plus one String model. Three
selected functions have no explicit ensures. The static boundary gate checks
local assumption/admit drift, postcondition counts and trivial preconditions.
Zero local assumption declarations does not mean the imported library or proof
system has no assumptions.

## Reproduction

With pinned tools on PATH, one worker and bounded memory:

```bash
# Regenerate/check every policy first; the rekey extraction is source-tree ignored.
security/assurance/run-all.sh --with-fstar --out /tmp/vela-assurance
# Focused composed-model and crypto contract checks:
VELA_PROOF_OUT=/tmp/vela-journal security/formal/run-share-journal-proofs.sh
security/assurance/bounded.sh libVELA/vela-crypto/verify-share-facts-fstar.sh
python3 security/assurance/check-proof-boundary.py
```

Local proof/test commands used 3 GiB cgroup caps, zero swap and one worker.
Tamarin uses one GHC worker with a 1500 MiB heap and 180-second per-theory cap;
the journal runner gives derivation checks 30 seconds instead of the shorter
default. Both theories pass the strict named-verdict/warning gate. M29 also
reports a precomputation chain-budget message; derivation checks complete and
all named lemmas are verified. This is not a claim of proof-search completeness.

All current generated postconditions have trivial preconditions. There are no
local assume val or admit bodies. No engine rebuild or higher-memory experiment
was needed. Hosted CI and independent review remain pending. Actual I/O/handler/
native-client refinement, full wire round trips, quantitative reductions and
cross-protocol composition remain open in the formalization ledger.
