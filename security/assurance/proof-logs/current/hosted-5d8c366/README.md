# Hosted snapshot 5d8c366

[Security workflow 40106877914](https://github.com/lucannez64/VELA/actions/runs/40106877914)
passed all five security jobs; T3 reported all fifteen PR checks passed.
`workflow.json` records the exact head SHA and job conclusions/URLs.
The downloaded `proof-boundary.log` records 13 artifacts / 245 Rust
postconditions / zero local assume-val declarations. `vela-share-policy.log`
records the successful fresh sharing extraction/check after the inbox overflow
correction. `Vela_share_policy.fst` is the uploaded CI extraction, byte-identical
to the current sharing artifact; it was not edited.

This supersedes the previous failed refinement on e3d994c. It predates the
additional twenty chunk lemmas and the local mobile/epoch candidate. Those
changes require their own hosted reproduction. The evidence establishes scoped
model/contract results, not full-system correctness or an external audit.
