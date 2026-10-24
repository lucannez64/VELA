# iOS decode-failure fixture correction

[Hosted job on 093d6ab](https://github.com/lucannez64/VELA/actions/runs/40115734342/job/120936501517)
compiled the Swift changes and executed 90 tests: 89 passed, one failed.
`testFailedDecodeDoesNotAdvanceBaseline` stopped at fixture creation (`seal failed`)
because the production Rust sealing API intentionally validates VaultStore JSON.
It never reached decoding or a rollback-floor assertion.

The corrected test seals two individually valid empty VaultStores under distinct
chunk IDs, explicitly checks successful admission of each, then serves both as
one sync batch. Their concatenation is invalid JSON. Only a DecodingError counts
as the expected failure; earlier errors fail the test. Both chunk floors and the
manifest floor must remain absent. Production code and proof contracts are unchanged.

No Swift compiler is installed on the local Linux host; this test correction
requires hosted macOS execution. Static correspondence/manifest checks were run
locally. No Rust/F* or Android rerun is required by this Swift-test-only change.
