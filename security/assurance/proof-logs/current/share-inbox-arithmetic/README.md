# Sharing inbox arithmetic: refinement failure and correction

The [refinement job on e3d994c](https://github.com/lucannez64/VELA/actions/runs/40103412073)
failed on `send_facts`: adding unrestricted `existing_inbox_bytes` and
`capsule_len` could overflow i64. Rust tests covered only ordinary bound classes,
so they passed while the universal F★ range obligation failed. The downloaded
crate log is retained as `hosted-e3d994c-failure.log`.

The constructor now bounds the capsule length before subtracting it from the
inbox limit, then compares the existing count with the remaining capacity.
It rejects negative counts. The postcondition uses the nonnegative inputs'
mathematical sum represented in i128 (the sum of two i64 values fits i128),
so verification relates the guarded subtraction to the intended sum bound.
No input precondition, admitted theorem or proof timeout increase was added.
For well-formed nonnegative observations behavior is unchanged. Observations
with invalid negative counts fail closed; extreme values no longer panic or
wrap. Capsule-size validity is still a separate predicate.

`parent-fstar.log` records a fresh extraction/check through the pinned
hax 0.3.7 / F★ 2025.10.06 / Z3 4.13.3 environment:

```bash
# Pinned tools on PATH, CARGO_HOME=/tmp/vela-hax-cargo,
# OPAMROOT=$HOME/.local/opt/vela-tools/opam:
~/.local/opt/vela-tools/bin/vela-heavy serverVELA/vela-share-policy/verify-fstar.sh
```

All 23 selected sharing postconditions check, with zero local assume-val
entries in the global drift gate. The constructor enumeration now includes
negative counts, i64::MIN/MAX and ordinary quota boundaries; its sum oracle
uses i128. Four policy unit tests and three enumeration tests pass. Imported
hax-library warnings and assumptions remain outside the zero-local-assumption
claim. Generated output was not edited; `sources.txt` pins the exact artifacts.

`parent-handler-tests.log` records the depth-3 sharing state-machine conformance
test and five sharing-related integration tests, all passed. These were run
with default Cargo home and the warm parent target, separately from the hax
cache. All heavy commands ran serialized under vela-heavy's 3 GiB/no-swap/
one-worker cap. CI now prints the failing crate log's tail before exiting;
full logs remain uploaded as artifacts.

The extracted corpus is now 245 postconditions / 252 selected functions.
Hosted reproduction of this correction remains pending. The previous 231
contracts remain the hosted snapshot; no whole-system theorem follows from
these constructor proofs. SQL/session/verifier origins, other handler checks
(including the sender-pair quota), concurrent effects and full traces remain
unproved. Internal/local verification is not an external audit.
