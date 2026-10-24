# Hosted enrollment fact-construction refinement

Source commit: fbe35c0d8afcbf53658c5db7a66023a52528b016.
[Refinement job](https://github.com/lucannez64/VELA/actions/runs/40039992434/job/120708563220)
completed successfully. The complete workflow failed in formal-rekey before
CryptoVerif ran, because its runner lacked executable permission. No complete
workflow success or hosted computational-proof success is attributed to this run.

GitHub artifacts `assurance-refinement-logs` (12538912197) and
`assurance-refinement-extractions` (12538907540) provide these raw logs and the
exact enrollment extraction. The extraction is copied verbatim into
`serverVELA/vela-enrollment-policy/proofs/fstar/extraction/`; it was not edited.
All ten other uploaded Rust extraction modules match their existing source-tree
files byte for byte. The local defined String/Vec models were unchanged.

`vela-enrollment-policy.log` records fresh hax extraction, F★ success, two unit
tests and five finite observation-enumeration tests. The module has 29 explicit
postconditions: the previous nine plus five actual fact constructors and fifteen
negative composition theorems. All selected Rust preconditions remain trivial;
no local assume val declaration was added. The complete checked inventory is
152 postconditions across 159 selected functions, with seven selected spec/
comparison functions lacking explicit ensures. Other policy/crypto logs here
record the successful fresh checks, with the pinned-tool activation log.

The new contracts specify facts from supplied observations for open, claim,
inspection, completion and result. The real handler calls those constructors,
but SQL/store behavior, observation provenance, signature-verifier correctness,
session identity origins, UI comparison and handler/database trace refinement
remain open. `ClaimKeySource::StoredClaim` is the handler's structural provenance
assertion, not a proved database or UI invariant. This is not full formalization.

Reproduce with the pinned activated tools and resource cap:

```bash
security/assurance/bounded.sh serverVELA/vela-enrollment-policy/verify-fstar.sh
python3 security/assurance/check-proof-boundary.py
```

The recorded hosted check is authoritative for this snapshot; local artifact
comparison and hash checks do not substitute for a semantic proof.
