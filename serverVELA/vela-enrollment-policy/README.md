# Verified permanent-device enrollment policy

This crate is the pure production policy for the v3 enrollment rendezvous.
Tamarin M13 proves the protocol lifecycle; hax extracts the Rust decisions to
F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `open_facts` | Device scope, user/opener binding and positive TTL are exactly the observed session/request values. |
| `plan_open` | Only an authenticated device-scoped, user/opener-bound, expiring grant can open. |
| `claim_facts` | Phase, liveness, single-claim and exact `hybrid_ek`/`hybrid_vk` lengths are exactly the store and decoded-length observations. |
| `plan_claim` | Only one valid public-key claim may move a live open grant to claimed. |
| `inspect_facts` | Phase, claim presence and the user/opener bindings are exactly the store and session observations. |
| `authorize_inspection` | Only the exact user and device that opened a claimed ceremony may inspect it. |
| `completion_facts` | Phase, bindings, opener `revoked` status, stored-claim provenance, signature result and account epoch are exactly the observed values. |
| `plan_completion` | Completion requires the opener, an active opener and epoch, the stored/displayed claim identity, and a primary signature over that stored claim. |
| `result_facts` | Phase, claimed-key presence and proof validity are exactly the store and signature observations. |
| `authorize_result` | Pending or enrolled status is returned only after proof under the claimed verification key. |
| theorem helpers | Grant opening, claim, inspection, completion replay, cross-device inspection, claim substitution, unproved result collection, revocation and stale epochs are impossible. |

The proof boundary excludes HTTP parsing, signature security, clocks, SQL, and
sled serializability. Production turns those observations into policy facts,
enrolls keys only from the immutable stored claim, and consumes grant+claim in
one sled transaction. Handler, bounded-model, and concurrency tests cover that
boundary. The observation structs contain only booleans, integers and enums
(no `String`, `Vec` or serde types) so hax can extract them; they do not
establish that the SQL/storage/signature observations themselves are correct.

## Run

Use the hax 0.3.7, Rust nightly 2025-11-08, F* 2025.10.06, and Z3 4.13.3
toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md). Then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner extracts twenty-nine production/theorem entry points — five fact
constructors, five decisions and nineteen negative theorems — and asks F* to
discharge every postcondition without `--lax`.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-enrollment-proofs.sh
```
