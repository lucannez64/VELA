# Universal chunk-admission proof: integration evidence

The parent ports the handwritten proof, boundary test and verifier from
`f6cc0b2` independently of its unmerged mobile-runtime ancestor `57d8bf6`.
The historical Rust extraction remains byte-identical (SHA-256
`e23bc7556ebb25eaf091ae5f8dd3718f490330e7efd9ea9245714655b1f14add`).
This increment changes no production Rust decision and adds **zero Rust
postconditions**. Twenty handwritten F★ lemmas are a separate proof inventory.

The proof characterizes the actual extracted planner against a separately
stated predicate over raw clocks/options and caller-supplied flags. Acceptance
requires both flags, a positive server clock and the optional baseline floor;
its permit carries exactly that clock. Rejection, arbitrary baseline floors,
clock extremes and concrete accept/reject witnesses are checked. Integer-epoch
interpretation/equality and authenticated-open-to-flag correspondence are not
proved here. Negative epoch *integers* are not inputs to this Boolean API.

The parent verifier imports only `proofs/fstar/extraction`, with pinned tool
version, cache-off checking, source hashes and argv. It refuses an unexpected
module/count/name, proof escapes and source-option pragmas; only the exact
hax-generated fuel/budget header is allowlisted in the extraction. Six Python
regressions exercise those checks, which are drift guards rather than proof
soundness certificates. It cannot accidentally import a future same-named
focused epoch module from `extraction-epoch`.

The original delegated evidence files retain their names and contents. Their
[report](delegated-README.md), `environment.log`, `artifact-hashes.txt`,
`policy-tests.log`, `fstar-chunk.log` and `fstar-full-verify.log` describe the
`f6cc0b2` snapshot including the *unmerged* focused epoch kernel and six Rust
tests. They do not establish that the mobile runtime has landed. Parent runs
are archived separately and describe the five-test current crate plus the
historical 11 Rust contracts and 20 handwritten lemmas only. Parent comment
corrections clarify conditional AAD/epoch flags; the theorem bodies are
unchanged from the reviewed delegated proof.

Remaining obligations include observation origins, authenticated opening,
context binding, raw epoch interpretation, baseline persistence and all native/
desktop glue. The mobile patch has separate unresolved review findings and is
not integrated by this proof. No external audit, runtime byte-to-proof
refinement or whole-system theorem is claimed.

## Fresh parent result

`parent-full-verify.log` records five policy tests, fresh hax extraction
(`unchanged file`), the existing eleven-contract check and the separate
20-lemma F★ check: all verification conditions discharged. It includes six
source-guard regression tests, F★ 2025.10.06, explicit Z3 4.13.3 selection,
full argv and hashes. The handwritten module hash is
`b6aa6204fc78dc1cdb7a389d453d6a71ba97b25a03c553d88a5d4f928121eb84`;
comment-only corrections distinguish a false epoch flag from an integer epoch.
`parent-sources.txt` pins the integrated source set. The command was:

```bash
# Pinned hax/F★ paths, CARGO_HOME=/tmp/vela-hax-cargo,
# OPAMROOT=$HOME/.local/opt/vela-tools/opam:
~/.local/opt/vela-tools/bin/vela-heavy libVELA/vela-sync-policy/verify-fstar.sh
```

All heavy work remained serialized under the 3 GiB/no-swap/one-worker limit.
The hax installation/cache key is unchanged. Hosted reproduction of this
additional lemma invocation remains pending.
