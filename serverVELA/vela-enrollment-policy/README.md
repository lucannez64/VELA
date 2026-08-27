# Verified permanent-device enrollment policy

This crate is the pure production policy for the v3 enrollment rendezvous.
Tamarin M13 proves the protocol lifecycle; hax extracts the Rust decisions to
F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `plan_open` | Only an authenticated device-scoped, user/opener-bound, expiring grant can open. |
| `plan_claim` | Only one valid public-key claim may move a live open grant to claimed. |
| `authorize_inspection` | Only the exact user and device that opened a claimed ceremony may inspect it. |
| `plan_completion` | Completion requires the opener, an active opener and epoch, the stored/displayed claim identity, and a primary signature over that stored claim. |
| `authorize_result` | Pending or enrolled status is returned only after proof under the claimed verification key. |
| theorem helpers | Completion replay, cross-device inspection, claim substitution, and unproved result collection are impossible. |

The proof boundary excludes HTTP parsing, signature security, clocks, SQL, and
sled serializability. Production turns those observations into policy facts,
enrolls keys only from the immutable stored claim, and consumes grant+claim in
one sled transaction. Handler, bounded-model, and concurrency tests cover that
boundary.

## Run

Use the hax 0.3.7, Rust nightly 2025-11-08, F* 2025.10.06, and Z3 4.13.3
toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md). Then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner extracts nine production/theorem entry points and asks F* to
discharge every postcondition without `--lax`.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-enrollment-proofs.sh
```
