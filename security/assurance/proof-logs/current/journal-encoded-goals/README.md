# Encoded journal all-pairs goals and non-vacuity

The parent integrates delegated 9bfa67a/ebb9022 as 66e979f/b0f4963.
`parent-verify.log` records a fresh check through the shared verify.sh:
F★ 2025.10.06 / Z3 4.13.3, cache off, z3rlimit100, full argv and source hash.
Module SHA-256: `463e9107143b232a9f18aeebccecdd76d114f22491b9dc84163719de26690dbb`.
All VCs discharge with no warnings or local proof escapes. Eight source-guard
regressions pass in `parent-guard-tests.log`; those are drift checks, not a
soundness certificate. The delegated run is retained separately under
`security/formal/m28-trace-equivalence/evidence/journal-encoded-goals/`.

The direct inductions prove two all-pairs goals over the initialized, typed,
single-slot core encoding: ordered EClear events have strictly increasing pins
under a supplied strict order, and a journal generation occurs at one index.
Projection transfers those results to the lifted encoding; the generic hp
schema is not used to assume them. A checked unary proper-subterm order and
nine-event core/lift trace with journals at2/6 and clears at4/8 establish
non-vacuity of the encoded goals. This is not Tamarin's full term algebra.

The source embeddings remain open: global freshness/interleavings, typed vs
single-sort terms, attacker In/Out derivability and actual source-rule mapping.
The Tamarin instrumented model retains its separate two-commit witness; no
Tamarin verdict is transferred to the original source here. Rust/filesystem
refinement and whole-system composition are not established.

The Tamarin theory body after its initial comment is byte-identical to5d8c366;
no rule, restriction, guard or lemma changed. The unchanged ten/eleven Tamarin
proofs were not rerun for comment and F★ changes. The handwritten module adds
zero Rust postconditions (local mobile candidate249 remains separate).
Hosted reproduction of this stronger module is pending. All heavy work used
the serialized3GiB/no-swap/one-worker wrapper. No external audit is claimed.

## Review precision correction

Internal review found no kernel soundness blocker. It required two precision
fixes: the distinct pin occurrences instantiate pin monotonicity, while the
journal-uniqueness same-generation antecedent is reachable reflexively. The
parent now explicitly invokes both core/lift uniqueness wrappers at 2=2;
journals at2/6 have different generations, and a same-generation pair at
distinct indices is forbidden by the theorem. Both lifted wrapper names are
now required by the source guard, with a regression for removing either.
`parent-final-verify.log` records the corrected module
`739c530661a3bbbd49051fb8490f81ed0c42b6b49c4809e3e32dd6dcdbc2e16c`:
all VCs discharged, no warnings. `parent-final-guard-tests.log` records nine
passing guard tests. Earlier logs above remain the463e9107 snapshot. Neither
correction changes Tamarin rules or Rust contracts.
