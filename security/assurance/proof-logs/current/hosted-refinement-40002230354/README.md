# Successful hosted refinement job

Commit: b27dcd6ad9c6fd46fa18429e32b1e1df67a8e673.
Run: https://github.com/lucannez64/VELA/actions/runs/40002230354.
Job: https://github.com/lucannez64/VELA/actions/runs/40002230354/job/120580997746.
Conclusion: success, completed 2026-10-23 18:55:22 UTC.

The job freshly extracted and checked all eight policy crates and the eleven
crypto contracts. proof-boundary.log records 119 explicit postconditions and
zero local assume val declarations across twelve inventoried artifacts.
Imported models, String correspondence, extraction, compilers and proof tools
remain trusted. These scoped results do not prove complete Rust handlers,
native callers, concrete I/O refinement or computational constructions.

Timing from job metadata:

- Prerequisite packages: 12 seconds.
- Cold toolchain installation: 32 minutes 19 seconds.
- Completed-toolchain cache save: 36 seconds (successful).
- Eight policy crates: 2 minutes 7 seconds.
- Crypto fact/signature/wire contracts and assumption audit: 1 minute 15 seconds.

The official prebuilt F★ release uses its bundled Z3 4.13.3 automatically;
share-facts.log shows that executable path. Its bytes are pinned by the F★
archive SHA-256. The separately installed Z3 4.13.3 CLI is also retained and
version-logged. This distinction matters when reproducing solver binaries.

This is a successful refinement *job*, not a completed successful whole
security workflow. The formal-rekey job's misleadingly named 'Prove Path-ORAM'
step was still installing ProVerif/OCaml at the observation time; it runs no
proof commands. The workflow is corrected to name that installation explicitly
and save its completed toolchain before the remaining tests/proofs. A separate
Path-ORAM step now executes the actual bounded solver checks directly, while
the integrated corpus runner retains its self-contained repeat of that gate.

For comparison, local-oram-timing.log records a separate bounded local run of
the three actual M22 symbolic checks in about 0.1 seconds: two equivalences
verified and the expected baseline attack. It is local timing, not hosted
proof timing or a runtime guarantee for arbitrary ORAM models.

The raw hosted logs and job metadata were downloaded through the GitHub API.
Older duplicate security runs 40001489467 and 40001512894 on 591565c were
requested to cancel; the current b27dcd6 workflow was retained. Future PR and
manual security runs for the same branch now share a concurrency group, with
superseded non-main runs canceled automatically.
