# Integrated producer and nonce proof replay

The parent ran the historical session verifier followed by the producer,
per-request trace and nonce composition in one focused F* invocation. All VCs
discharged. After comment corrections requested by internal producer review,
`final-focused.log` records fresh extraction and all six focused modules
verified together (`--cache_off`, F* 2025.10.06, Z3 4.13.3, hax 0.3.7,
nightly-2025-11-08). The unchanged historical extraction was checked by the
first run. `artifact-hashes.txt` identifies the final inputs. Imported hax/F*
models emit the retained warnings; no zero-warning claim is made.

Both runs pass 18 crate unit tests and 13 policy driver tests; warm repeats
are not counted as additional test coverage. `producer-consumers.log` records
3 challenge-model, 5 handler and 13 policy-driver tests on the integrated
producer body, before subsequent scope-comment-only corrections. It does not
rerun the 68-test integration suite, whose runtime-gate snapshot has separate
evidence. Heavy commands were serialized with the 3 GiB/no-swap/one-worker cap.

The focused extraction has 16 selections / 12 explicit Rust postconditions
(8 conditional); the base 249 census and historical 19/21 extraction are
unchanged. The producer adds 23 handwritten lemmas, the composition 60.
These are distinct counts. The source guard checks 2 extracted + 4 proof
modules. Aggregate verification includes composition in the same invocation,
without an additional hax pass or a second F* check of its dependencies.

The byte path and abstract-purpose nonce world remain separate theorems. Store
linearizability, get_del/set_ex/Option/Vec round trips, observation origins,
handler effects, SQL/PASETO/JTI behavior, revocation and crash/multi-node
composition remain outside this result. This is local replay and internal
review evidence, not a hosted verdict, external audit or full-system proof.

## Final current-set replay after composition review

`current-composition.log` checks the current six-module set with corrected
scope comments and reporting echoes. All VCs discharge with `--cache_off`;
the source guard reports 2 extracted and 4 proof modules. There are **124**
handwritten lemma declarations (13 bounded challenge + 23 producer + 28
per-request + 60 composition). This final run reuses unchanged, freshly
regenerated artifacts from the preceding focused run, rather than repeating
hax extraction. `artifact-hashes.txt` now pins this final source set; the older
logs above are retained as their original snapshots. Proof bodies are unchanged.
The historical `login-nonce-composition/` logs and mutations are explicitly
labeled as the d58e5bd run; they are not presented as current-head evidence.
