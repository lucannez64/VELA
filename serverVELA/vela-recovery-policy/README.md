# Verified account-recovery policy

This crate is the pure production policy for WebAuthn-gated recovery and
recovered-device enrollment. Tamarin M14 proves the lifecycle; hax extracts the
Rust decisions to F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `initiate_facts` | Phase, account/share/credential presence, attempt-slot freshness and positive TTL are exactly the SQL, credential-option and store observations. |
| `plan_initiation` | A fresh, expiring challenge starts only for an existing recovery-ready account with both share and credential. |
| `plan_registration` | Recovery-credential registration requires device scope, the same account, one consumed challenge, a valid credential, and cross-account uniqueness. |
| `recover_facts` | Phase, one-shot consumption, user/attempt/credential bindings, assertion and user-verification results, share/rekey observations and the normalized epoch are exactly the attempt, WebAuthn and row observations. |
| `plan_recovery` | Share release requires the exact user, attempt, current credential, one-shot challenge, verified WebAuthn assertion, user verification, active epoch, and stored share. |
| `credential_update_facts` | Assertion validity, credential identity and metadata-update need are exactly the observed values. |
| `plan_credential_update` | Authenticator metadata updates only after a valid assertion under the still-current credential. |
| `observed_recovery_epoch` | A missing or non-positive stored epoch normalizes to the initial epoch. |
| `proof_initiate_facts` | Phase, account/share presence, commitment presence (decoded length), the rekey column, attempt-slot freshness and positive TTL are exactly the row and store observations. |
| `plan_proof_initiation` (M18) | A possession-proof challenge is issued only when the share *and* a non-empty staged RMS commitment exist on a non-rotating account. |
| `possession_recover_facts` | Phase and one-shot consumption come from whether the exact attempt key was removed; decoded envelope identity, the verification result, the rekey column, decoded commitment length/epoch and the normalized live epoch map field-by-field. |
| `plan_possession_recovery` (M18) | An enrollment grant issues only from a consumed, attempt-bound, verified possession-proof observation with a non-empty commitment at the live epoch on an active account; its decision type grants enrollment, not share release. |
| `plan_enrollment_preflight` | Before the single-use grant is spent, the production rejection is universally checked against an independent ranked table of account/epoch/rotation/commitment/credential guards, with the earliest applicable rank winning. The commitment guard applies only to possession grants and the credential guard only to WebAuthn grants, so they are disjoint; the table places commitment before credential only as a total-order convenience. `Ready` implies every positive readiness guard and exactly the observed grant's epoch/possession, and their conjunction implies `Ready`. A missing-grant observation yields `GrantUnavailable`; the handler skips querying the account (inspected glue), and `NotQueried` and `AccountUnavailable` are explicit unknowns, never observed absence. |
| `enrollment_facts` | Grant presence/consumption/replacement, decoded grant possession marker, decoded credential-id equality, decoded commitment length, decoded key lengths, the rekey column and the normalized grant/account epochs map field-by-field. |
| `plan_enrollment` | A recovered device requires the actual consumed grant to match the preflight-observed grant, loaded under the request's user/grant store key, current credential (or staged commitment for possession grants), valid keys, and exact active grant/account epoch. |
| `plan_publication_stage` | A server share is staged only for the current active account epoch with a nonempty share and split id. |
| `plan_publication_finalize` | First promotion requires an empty active slot plus the exact pending epoch, split id, and stored share; an exact already-active retry is handled idempotently by the server. |
| `driver::begin_redemption` / `driver::step` | The post-preflight redemption flow is a pure total transition driver. Its Rust postconditions keep every driver state sound and make every emitted effect agree with the state it produces. An `Insert` effect is emitted only after a matched consumption observation and a matching real `plan_enrollment` + rekey permit; `Complete` only from an `Inserted` observation; restoration never follows success. |
| theorem helpers | Replaced credentials, challenge/grant replay, cross-user grants, rotated grants and epochs, competing splits, retired epochs, unproven possession claims, stale commitments, commitment-less possession grants and accounts, unassigned grants, concurrent grant replacement, invalid key lengths and absent user rows cannot authorize recovery authority. Observation theorems additionally reject missing shares/credentials, colliding attempt ids, expired initiation TTLs, unverified assertions, missing/replayed attempts, cross-user observations and rekeying accounts. |

The proof boundary excludes WebAuthn cryptography, HTTP, clocks, SQL, sled, and
the cloud provider's durability guarantee. The observation structs contain only
booleans, integers, `Option`, `usize` lengths and enums (no `String`, `Vec` or
serde types) so hax can extract them. They do not establish that the SQL rows,
store lookups, WebAuthn verifier, signature results, decoded grants or
commitments themselves are correct; those producers remain explicit glue.
Production binds serialized challenge state and enrollment grants to the
credential id, conditionally updates that credential, atomically redeems
one-shot artifacts, and guards device insertion by epoch and credential id
(possession grants instead require the staged RMS commitment to still exist).
Challenge and proof-state insertion now use insert-if-absent, so an observed
free slot is never authorization to overwrite a concurrent winner.

### Post-preflight redemption driver

The handler's post-preflight control flow now goes through the pure
`driver` module: consumption observation, final enrollment/rekey permit,
guarded insert observation, live authority recheck, restoration/terminal
outcome and success. The extracted `driver::step` is the object of the
hand-written unbounded trace induction in
[`proofs/fstar/driver-lemmas`](proofs/fstar/driver-lemmas/Vela_recovery_policy_driver_lemmas.fst).
The induction is over every event list, not just handler-shaped prefixes. It
proves, per driver instance:

- an `Insert` effect is emitted only when the driver recorded a matched
  consumption observation and a real `plan_enrollment` permit plus a rekey
  permit at the same epoch;
- at most one insert success (`Complete`) can occur, and after a success every
  later event is inert;
- no restoration effect is emitted after a success;
- `Complete` is only emitted in response to an `Inserted` observation, never
  `Skipped` or `Failed`;
- no insert outcome restores the grant: restoration after an insert attempt
  happens only from the recheck stage, which only a definite zero-row
  (`Skipped`) insert reaches;
- an insert error (`Failed`) is final: it fails without restoration and every
  later event, of any number, is inert;
- reachable witnesses exercise success, terminal insert error, terminal
  credential revocation, policy denial and the retryable rotation conflict.

These are per-request properties over *observations*. They are not a theorem
about two concurrent requests sharing one grant, and they do not prove that
the atomic `get_del`, the guarded SQL insert, the live recheck query or
`restore_enroll_grant` have their intended effects.

An earlier version of this driver restored the grant after an insert error.
Because an error can hide a committed INSERT, a second redemption of the
restored grant could then insert a second device row. The driver now treats
the error as terminal: the grant stays consumed and the user restarts recovery.
The restore on a definite zero-row insert remains, because no row was written.

## Run

Use the pinned hax/F*/Z3 toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md), then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner extracts ninety production/theorem entry points and asks F* to
discharge every verification condition without `--lax`. The checked-in
extraction is the fresh output of `verify-fstar.sh` for these sources; hosted CI
must still re-extract and check the entry points. Every selected function has an
explicit postcondition (90/90); the constructors cover the decoded possession
and enrollment state rather than only the boolean facts. The eleven new checked
lemmas connect the preflight decision to an independent ranked table/fold and
to positive readiness guards, and prove parametric adjacent precedence and
disjointness facts. They sit alongside the preflight decision and seven
rejection/unknown negative theorems.

`verify-fstar.sh` also invokes `verify-fstar-driver.sh`, which re-extracts the
six focused driver entry points into `proofs/fstar/extraction-driver/` (same F*
module name as the historical artifact, therefore a separate checker
invocation) and checks them together with the nineteen hand-written
trace/reachability lemmas. The historical `proofs/fstar/extraction/` artifact
is not modified by that gate.


One fail-closed tightening accompanies the decoded commitment observation: a
row whose `recovery_auth_hash` decodes to zero bytes no longer yields a
possession challenge (the old handler would issue one that could never verify).
Every other recovery status class, message and precedence is preserved.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-recovery-proofs.sh
./run-recovery-publication-proofs.sh
./run-pair-selection-proofs.sh
```

The enrollment constructor accepts the two decoded public-key lengths and
computes their exact 1600/2624-byte validity inside the checked kernel. The
server's preliminary checks share these policy constants. It does not accept
a caller-supplied `public_keys_valid` boolean as an observation. The policy
still proves no cryptographic validity of correctly sized key bytes.

Enrollment now runs a checked preflight kernel before redemption. Its production
predicate is the historical nested status/message if-chain; a separate ranked
table and first-applicable fold state the ordering specification without calling
that predicate. A universal checked lemma proves the production rejection always
equals the first applicable table entry, and further checked lemmas prove
parametric adjacent-precedence/overlap facts and the commitment/credential
disjointness. The kernel decides account presence, normalized epoch equality,
rotation, and credential or commitment authority, and it receives `NotQueried`
for a missing grant so the handler's 401 precedes any account query. A second
independent statement of positive readiness guards is connected to `Ready` in
both directions, including the permit's epoch/possession fields. Its
`ReadyToConsume` permit only allows attempting the atomic `get_del`; it never
asserts that consumption occurred and it does not authorize the device insert.
After redemption, `plan_enrollment` still requires the actual consumed grant to
equal the preflight-observed grant and builds the final `EnrollmentPermit` from
those actual observations. A terminal policy denial and an insert-time
credential/commitment revocation leave the grant consumed; storage failures and
retryable rotation races restore it as documented.

Enrollment's `user_matches` observation is a store-key binding, not an
independently checked identity comparison: the stored grant has no embedded
user id. Possession initiation/recovery have live policy gates for empty
commitments and failed proof observations.

### Grant deletion and restaging limits

The stored enrollment grant carries only `key_epoch`, `credential_id` and the
possession marker. It has no embedded user id, commitment digest/generation,
or split id. Consequently:

- `user_matches` is the binding implied by the `(user_id, grant)` store key,
  not an independently decoded identity comparison.
- The commitment guard and the credential-replacement guard are disjoint by
  grant type: a possession grant can only fail the commitment guard and a
  WebAuthn grant can only fail the credential guard. Their table order is
  therefore not a live overlap; the checked disjointness lemma records this.
  The preflight specification proves the decision and its precedence, not the
  handler's SQL/store effects or the effectful `get_del`.
- Early authority rejections (credential replacement, or a missing possession
  commitment) run before consumption, so the same grant remains redeemable
  within its TTL if the expected credential or commitment is restored.
- The possession check is presence-only. Re-staging *any* non-empty commitment
  revives the same grant; it is not bound to the commitment that verified the
  original proof.
- The integration tests demonstrate both restaging cases. These are documented
  limitations, not proofs of permanent revocation or exact commitment binding.
  Stronger behavior would require binding the grant value to the user id,
  commitment digest and split/epoch generation, and consuming the grant (or
  bumping a revocation generation) on authority revocation.

`PossessionGrantPermit::releases_server_share()` is false by definition of
the enrollment-only permit. It does not prove that the effectful handler never
invokes another release API; that absence is inspected, not formally refined.

The independent ordering theorem concerns supplied observations. The handler
skips account lookup for missing grants by inspected control flow; this is not
an SQL trace theorem. The post-insert concurrent recheck decision and its
historical revocation-before-rotation priority are modeled by
`driver::on_recheck`, but the query's rows, the SQL guard's authority and the
store effects remain outside the policy proof.

`restore_enroll_grant` is an unconditional `set_ex` with a fresh full TTL. It
now runs only on paths where nothing was inserted: a consumed grant that does
not match the preflight, a rekey rejection, or a definite zero-row insert
followed by an absent account, a failed recheck query or an ongoing rotation.
An insert error is terminal and never restores (the committed-but-errored
duplicate path is closed). The store effects themselves remain unproved.
