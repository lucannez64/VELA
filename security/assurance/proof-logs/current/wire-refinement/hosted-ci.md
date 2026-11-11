# Hosted CI and integration record

Draft PR: https://github.com/lucannez64/VELA/pull/175
Initial PR head: ae977657d48219605e8de8e1b5bdb26dc16535f2.
The initial hosted run did not pass. It is failure evidence, not a proof result.

- Security run https://github.com/lucannez64/VELA/actions/runs/39968161356:
  refinement and sharing jobs could not execute bounded.sh (Git mode 100644).
  Script modes have been corrected in the index, including nested runners.
- The same run's correspondence gate detected main's desktop import refactor
  in GitHub's synthetic merge. Main 7d61d1e was integrated explicitly. Its
  import alias/dependency changes preserve the sharing lock, journal caller
  logic and share policy dependency. Reviewed hashes must describe this merge.
- Its static scan reported RUSTSEC-2026-0385 in ctutils 0.4.2; affected production
  lockfiles were updated to the patched 0.4.4 without an advisory exception.
- Server image run https://github.com/lucannez64/VELA/actions/runs/39968161232
  could not resolve vela-client-share-policy because its directory was absent
  from both Docker build stages. Both COPY lists have been repaired.

- The iOS walkthrough reached unlock, then looked for a vault-list row while
  InstrumentRootView had reset to its default Overview tab. The UI test now
  waits for the unlocked dock and selects Vault before checking persistence.
  This test correction requires rerunning on the hosted simulator.

A new successful hosted run remains required after these corrections. The
updated dependency also requires fresh local checking; earlier proof/test logs
remain evidence for their original sources and lockfiles.
