# 15. Possession recovery and enrollment observations

The recovery crate now checks 71 postconditions over 71 selected entry points,
including 29 new contracts for possession initiation, possession recovery and
recovered-device enrollment. With the web-session increment, the corpus is
212 postconditions / 219 directly selected functions. This is a local proof
increment; the previous hosted baseline on `5fa4e9f` covered 173 postconditions.

| Constructor | Observation-to-fact contract |
|---|---|
| `proof_initiate_facts` | Account/share availability, decoded commitment length, rotation column, observed attempt-slot freshness and positive TTL determine phase and initiation facts |
| `possession_recover_facts` | Actual take outcome determines challenge phase/consumption; supplied envelope identity comparisons, verifier result, account/commitment presence and normalized live epoch determine release facts |
| `enrollment_facts` | Presence, consumption and equality of observed/consumed grants determine phase and one-shot facts; decoded possession marker, credential comparison, commitment length, key lengths, rotation state and epochs determine enrollment authority |

The parent strengthened the delegated enrollment constructor: it receives the
two decoded public-key lengths and derives exact 1600/2624-byte validity in
verified Rust. Preliminary handler checks use those same policy constants.
Correct length is not a proof of cryptographic key validity.

Three composition theorems characterize authorization exactly over their
observations. Twenty-three negative theorems cover missing accounts/shares/
commitments/grants, rotation, stale epochs, replay, grant replacement, invalid
key lengths and mismatched attempt identities. All are selected in the same
fresh extraction/checking run, including the reused epoch-normalization helper.
The seven pre-existing selected helper/spec functions without explicit postconditions
elsewhere in the corpus are unchanged; there are zero local `assume val`.

The production handlers now call these constructors. Two concrete tightenings:

- An empty decoded possession commitment yields the existing uniform unavailable
  response instead of a challenge that can never verify.
- Proof-attempt insertion uses `set_ex_nx`, so a stale empty-slot observation
  cannot overwrite a winning challenge. A real-store regression checks this
  interleaving; the store operation's atomicity is still trusted.

The handler order retains the existing grant-before-account-observation rule,
so an absent grant does not expose account/rotation state. Consumption remains
single-use; a race-replaced grant is rejected and restored through the existing
path. This description is a code review, not a proved database trace.

The [evidence](proof-logs/current/recovery-possession-enrollment/README.md)
separates the delegated boolean-key-validity snapshot from the parent's exact
key-length version. The latter passed fresh hax/F★ checking, six policy tests
and seven observation tests. The parent also ran the complete 60-test server
integration suite and an additional empty-commitment regression. Earlier
insertion, recovery and enrollment logs are retained with their own provenance.
Three bounded lifecycle tests also passed, with account presence included in
the enrollment enumeration.

## Unproved correspondence

SQL execution and row decoding; base64/JSON and UUID operations; the hybrid
possession verifier; nonce/randomness and clocks; rate limiting; and store
get/get_del/exists/set_ex_nx semantics remain outside these pure proofs.
`user_matches = grant_present` in enrollment relies on the caller looking up
the exact `(user_id, grant_id)` key: the stored grant value has no embedded user
identity. That store-key binding is a remaining proof obligation, not derived
from the boolean's name. Supplied identity/credential comparisons also need
source correspondence. Early returns, grant restoration, SQL mutation, token
issuance and all concurrent/crash/failure traces remain unproved.

Epoch normalization still maps absent/nonpositive live epochs to one; its
proof is not an epoch-freshness theorem. Commitment presence requires nonzero
length, not a scheme-specific format proof. Neither these observation contracts
nor the passing integration tests establish full F-1/F-2 or a whole-system
security theorem.
