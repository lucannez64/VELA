# Fresh local refinement run, 2026-10-23

All eight runners completed successfully, including tests, fresh extraction and
F* checking without `--lax`. Each log ends with the checker success message,
elapsed seconds, cgroup memory peak in bytes and exit status zero. See
`harness.sh.txt` for the exact local invocation. Previous extraction directories
were moved aside before running; `extractions/` snapshots the newly checked files
and the Cargo lockfiles. Imported hax proof libraries remain trusted.

One crate ran at a time, with a 5 GiB cgroup limit, zero swap and one worker.
Measurements include tests, Cargo, extraction and F*; they are not F*-only RAM
requirements or guaranteed minima. Existing dependencies/build caches were used.

| Crate | Seconds | Peak bytes | Peak GiB |
|---|---:|---:|---:|
| `vela-enrollment-policy` | 13 | 877252608 | 0.82 |
| `vela-recovery-policy` | 13 | 893698048 | 0.83 |
| `vela-rekey-policy` | 59 | 1909305344 | 1.78 |
| `vela-session-policy` | 13 | 880033792 | 0.82 |
| `vela-share-policy` | 12 | 789348352 | 0.74 |
| `vela-client-recovery-policy` | 23 | 946503680 | 0.88 |
| `vela-sync-policy` | 12 | 868012032 | 0.81 |
| `vela-client-share-policy` | 31 | 2215952384 | 2.06 |

CI has not yet run this package.
