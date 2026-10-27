# 8. Formalization obligations and current boundary

**Full-system formalization is not complete.** This document separates checked
results from remaining obligations. Decision proofs and a symbolic journal
model do not establish the entire implementation's security.

## Selected trusted boundary

The maintainer has selected OS/compiler and primitive-security trust. The
[target contract](09-target-contract.md) defines the resulting application and
construction obligations. Verifying external primitive implementations and OS/
compiler internals is excluded; VELA's hybrid combiners, encodings, handler
logic and native caller behavior remain in scope. This selection does not
turn any open obligation below into a proved result.

## Current hosted baseline

All fifteen PR checks passed on `c8a377de98c3e7b0ea06070818062acf8cb97e8a`,
including the [security workflow](https://github.com/lucannez64/VELA/actions/runs/40154658518)
and [iOS workflow](https://github.com/lucannez64/VELA/actions/runs/40154658482).
The base inventory remains 249 Rust postconditions /256 selections across
fourteen artifacts, plus twenty handwritten chunk lemmas, six epoch lemmas and
the encoded journal development. Focused driver contracts and trace/composition
proofs are counted separately below, with their preconditions and assumptions.
Android and iOS bounded sync conformance tests have also passed in hosted CI.
Historical evidence keeps each snapshot's original counts and scope.

The next login/challenge-purpose driver is work in progress and is not covered
by that hosted baseline. The focused drivers' source gates now reject nested-
comment escape attempts, axioms, expected-failure annotations, bare declarations
and unreviewed source options. This gate is tested against known bypass shapes;
it is not a proof checker and does not validate the specification's intent.

## Enrollment-redemption driver (hosted on aaf708f)

Every decision the enrollment handler makes after preflight (consumed grant,
final enrollment/rekey permits, insert outcome, live authority recheck,
restore or terminal failure) now goes through the pure `driver` module in
`vela-recovery-policy`. Six extracted Rust contracts and 23 handwritten F*
lemmas over the extracted `step` prove, for every event list of one request:
inserts need a matched consumption and both permits at the preflight epoch;
at most one success; no restore after success; and no restore after any
insert outcome. This work found a duplicate-enrollment bug: the handler
restored the grant after an insert error, although the INSERT may have
committed, so one grant could enroll two devices. Insert errors are now
terminal. The store/SQL effects, the handler glue around the driver and
concurrent requests remain unproved; the driver is counted outside the
249-contract inventory because its step contracts carry a soundness
precondition that the trace lemmas discharge. The [aaf708f security workflow](https://github.com/lucannez64/VELA/actions/runs/40122568372)
reproduced it with byte-identical extractions, and all fifteen PR checks passed.
[Evidence](proof-logs/current/recovery-redemption-driver/README.md).

## Concurrent redemption composition (hosted on edaee5a)

A further F* module composes the extracted driver across any number of
concurrent requests sharing one grant, with an atomic store `get_del`, grant
expiry, restores exactly when the driver asks, and inserts whose errors may
or may not have committed. For every schedule, one grant writes at most one
device row. Witnesses show success, a two-request race, a retry after a
rotation restore, and the committed-error case are all reachable. Putting
back the pre-`aaf708f` restore-after-error behavior breaks the proof. Store
linearizability, effect fidelity of the handler and grant issuance are
assumptions. [Evidence](proof-logs/current/recovery-redemption-composition/README.md).

## Device revocation driver (hosted on bd765ab)

`POST /device/revoke`, `POST /auth/logout` and the middleware's revocation
admission checks now delegate every decision to an extracted driver in
`vela-session-policy`: 13 Rust contracts, 28 per-request F* lemmas and a
56-lemma concurrent composition. Per request, every database record of a
revocation is preceded by the token lockout in the same trace, the web-session
cascade only follows a successful or repeated revoke, and storage failures are
terminal. For any interleaving of revoke, logout, login and token use: no
cross-account revocation, no revocation by a device already revoked when its
request started, and no token of a revoked device is admitted. The counters
behind these three results are incremented on the driver's own decisions, and
three mutations of the extracted driver each break the proof. Store/SQL
atomicity, PASETO and rate limits, in-flight handlers of a revoked actor and
effect fidelity remain assumptions. The [bd765ab workflow](https://github.com/lucannez64/VELA/actions/runs/40230607902) reproduced
it. [Evidence](proof-logs/current/revocation-driver/README.md).

## Handler-to-driver link (pilot: account deletion, hosted on f947ef7)

The drivers above prove what each request *decides*; until now, that a handler
performs exactly the driver's effects, in order, and nothing else was a manual
review obligation ("effect fidelity"). `DELETE /account` now closes most of it
mechanically. `vela-session-policy::deletion_interpreter` defines the loop once,
as the `deletion_interpreter!` macro. The crate expands it into the synchronous
`run_deletion`, generic over an executor trait with one typed method per
effect; the handler expands the same macro text with `.await` over an async
executor that holds all of the request's I/O. For every executor, F* proves
that `run_deletion` calls exactly the method for the effect the driver just
emitted (with that effect's table argument), calls nothing after the verdict,
reaches a verdict within its 14-turn budget, and ends in `run_from_actor actor
evs` for the observations the executor returned; the deletion trace theorems
therefore hold for the handler's final state. Two mutations of the extracted
loop (a wrong executor method; a call after the verdict) are rejected. A
source test pins the handler to one `await` expansion and forbids direct driver
calls. What remains assumed: each executor method performs the I/O its name
says and reports it honestly, the macro expansion in the server (it differs
only by `.await`), and the store/SQL semantics. The [f947ef7 workflow](https://github.com/lucannez64/VELA/actions/runs/40488103343)
reproduced it. [Evidence](proof-logs/current/deletion-interpreter/README.md).

## Handler-to-driver interpreters (hosted on 6be552c)

The same construction now covers the login, device-revocation, logout,
pairing and sharing handlers. Each policy crate defines one interpreter macro
per driver; the server expands it once with `.await` over an async executor
that holds the request's I/O, and F* proves the synchronous expansion for
every executor (exact executor calls, verdict within the budget, final state
covered by the driver's per-request theorem):

| Handler(s) | Interpreter | Budget | Evidence |
|---|---|---|---|
| `POST /auth/verify` | `login_interpreter!` | 6 | [login](proof-logs/current/login-interpreter/README.md) |
| `POST /device/revoke`, `POST /auth/logout` | `revocation_interpreter!`, `logout_interpreter!` | 4, 1 | [revocation](proof-logs/current/revocation-interpreter/README.md) |
| enrollment package store/fetch, grant open, claim, completion, result | `pairing_interpreter!` | 5 | [pairing](proof-logs/current/pairing-interpreter/README.md) |
| send, linked-item update/revoke, inbox delete, share-key registration | `share_interpreter!` | 3 | [sharing](proof-logs/current/share-interpreter/README.md) |
| `PUT /vault/chunk/:id`, `GET /vault/chunk/:id` | `upload_interpreter!`, `read_interpreter!` | 7, 2 | [vault](proof-logs/current/vault-upload-interpreter/README.md) |
| `POST /recovery/enroll-device` | `redemption_interpreter!` | 5 | [redemption](proof-logs/current/redemption-interpreter/README.md) |
| `/recovery/initiate-proof`, `/recovery/recover/proof` | `possession_initiation_interpreter!`, `possession_recover_interpreter!` | 3, 6 | [possession](proof-logs/current/possession-interpreter/README.md) |
| WebAuthn registration start/finish, `/recovery/initiate`, `/recovery/recover` | `registration_start_interpreter!`, `registration_interpreter!`, `auth_start_interpreter!`, `auth_finish_interpreter!` | 3, 5, 3, 8 | [WebAuthn](proof-logs/current/webauthn-interpreter/README.md) (hosted on 36b877e) |
| `POST /device/enroll` | `enroll_interpreter!` | 5 | [enroll](proof-logs/current/enroll-interpreter/README.md) |
| `POST /send`, `GET /send/:id`, `DELETE /send/:id` | `send_interpreter!` | 3 | [send](proof-logs/current/send-interpreter/README.md) |

Each crate's mutations (a wrong executor method, a call after the verdict,
and for logout a skipped or doubled marker write) are rejected. The pairing
driver gained one additive event (`AccountChecked`) so its `step` covers the
completion's account preflight; `on_completion_account` is unchanged and still
guards the ceremony and stage. The vault driver gained two storage-failure
events (attempt lookup, epoch lookup) that were early returns before, and two
invariant corrections found while proving its loop: a web session may hold a
shadow route only until the shadow-authority check refuses it (it was claimed
never to, which a reachable state contradicted), and the read invariant no
longer restates the row decoder's `version >= 0` check. The server-side executor traits for pairing and
sharing give unimplemented methods a refusing observation, so an effect a
handler does not expect fails closed rather than panicking. `plan_admission`
(middleware) is a single pure decision with no effect loop and is exempt.
Still outside: request parsing and rate limits before a driver begins,
response rendering after its verdict (including pairing's restore of a taken
ceremony on `RestoreAndFail`, which the verdict authorizes), and each executor
method's I/O. In the recovery loops an executor method may also abort (return
no observation) on a storage error the old handler returned on; the loop then
performs nothing more and the request fails with that error, and the proofs
cover that exit. Every server handler that runs a decision driver now
reaches it only through a proved interpreter; `plan_admission` (a single pure
decision) is the one exempt call site. The [6be552c workflow](https://github.com/lucannez64/VELA/actions/runs/40538488807) reproduced every
proved interpreter in the table.

## Account deletion driver (hosted on cdffe46)

`DELETE /account` now takes every decision from an extracted driver in
`vela-session-policy` (11 contracts, 37 per-request lemmas, 5 bridge lemmas and
an 18-lemma composition). Per request, both store-side lockouts (device tokens,
then web sessions) precede the transaction and every SQL delete, the seven
tables are deleted once each in a fixed order before `users`, the transaction
commits only after the `users` row was deleted, a response implies a commit,
and success and failure exclude each other. For any interleaving of deletions
and token use on two accounts: no cross-account deletion, no second commit for
an account already gone, and no token of a locked-out account admitted by the
extracted `plan_admission`. The counters are keyed on driver decisions. The
three mutations are rejected before the composition is reached (two by the
per-request theorem, one by the extracted admission contract), so they show
the driver lemmas are load-bearing, not the composition counters themselves. Store-side lockout
failures are still ignored (historical behaviour): a failed sentinel write
leaves that token usable until the commit removes the account row. SQL
transaction atomicity, store linearizability and effect fidelity remain
assumptions. No new bug was found. The [cdffe46 workflow](https://github.com/lucannez64/VELA/actions/runs/40408500479)
reproduced it. [Evidence](proof-logs/current/deletion-driver/README.md).

## Vault upload driver (hosted on cdffe46)

`PUT /vault/chunk/:id` and `GET /vault/chunk/:id` now take their decisions from
an extracted driver in `vela-rekey-policy` (14 functions, 42 per-request
lemmas, 67 composition lemmas). Per request, a success always follows a guarded
write that matched, a write is emitted only for an authenticated writer on a
clean route (the live ACTIVE epoch, or the next epoch while FREEZING for the
starting device), a shadow write is answered only after its activity refresh,
an active write only after publication, and at most one success or failure is
produced. Under any interleaving of uploads with rotations on two accounts,
no driver emits an active write permit for a route that was not ACTIVE when
it was resolved, and no web session receives a shadow write permit; three
mutations break these results. A store-world composition (hosted on
727d447) models the three guarded SQL statements as atomic steps evaluated
against the live account row and the shared chunk store, with rotations
starting, committing or aborting between any two steps. For every schedule:
no active row is committed except at the live epoch of an ACTIVE account, no
shadow row except at the next epoch of a FREEZING account by the starting
device with the matching rotation id (never a web session), and no success is
answered without its own committed write. These counters read the live state
at the commit step; four mutations (guard without epoch, guard without
starter, driver sending the read epoch for a shadow write, success after a
skipped write) break them, three with concrete counterexample schedules. SQL
linearizability remains an assumption. The server does not enforce Lamport-clock
monotonicity on upload; clock rollback is refused by the client download
policy (docs 17/18). No bug was found. The [cdffe46 workflow](https://github.com/lucannez64/VELA/actions/runs/40408500479)
reproduced it. [Evidence](proof-logs/current/vault-upload-driver/README.md).

## Device pairing driver (hosted on 54b38b3)

The invitation and rendezvous handlers (`/device/enrollment-package`,
`/device/enrollment-grant/*`) now delegate every post-validation decision to an
extracted driver in `vela-enrollment-policy`: 30 Rust contracts, 43
per-request lemmas with four trace theorems, and a 67-lemma concurrent
composition. Per request, a claim is written only under the claim policy, the
ceremony is taken only after the completion policy accepted the stored claim,
an active opener, a verified signature and matching user and opener, and a
device is inserted only after a take whose bytes matched. For any interleaving
of claims, completions and package redemptions on one grant: at most one
claim, at most one enrolled device, no cross-account or unsigned enrollment,
no take without a claim and at most one redemption per stored package
version. The counters are keyed on the driver's own effects, and six mutations
of the extracted driver each break the composition. This work found and fixed
U-19 (an insert error re-armed the ceremony); that fix is proved per request,
while the composition models successful inserts only. Store/SQL atomicity,
signature cryptography (M13), TTLs and effect fidelity remain assumptions, and
U-20 stays open. The [54b38b3 workflow](https://github.com/lucannez64/VELA/actions/runs/40402764401) reproduced
it. [Evidence](proof-logs/current/pairing-driver/README.md).

## Device-enroll and send-link drivers

`POST /device/enroll` and the send-link handlers (`POST /send`,
`GET /send/:id`, `DELETE /send/:id`) now delegate every decision to extracted
drivers in `vela-enrollment-policy` and `vela-share-policy`, and reach them
only through proved interpreter loops. Per enroll request: at most one insert
decision, and an insert only after an enroll-purpose challenge was consumed,
the enrolling device was active and authenticated, the new key lengths and
signature verified, the rekey permit was held and the account epoch matched;
an ambiguous insert error is terminal (U-19). Per send request: an
owner-bound create permit is the only route to an insert, with TTL between
5 minutes and 30 days and 1 to 1000 views; at most one delivery, only after
a consume; only the owner deletes. For any interleaving of creates, fetches
and deletes on one store, a single-use link is fetched at most once, never
after its deletion, and never deleted by a non-owner. The counters are keyed
on the drivers' own decisions, and eight mutations of the extracted drivers
each fail. The challenge store, SQL semantics, signature cryptography and
each executor method's I/O remain assumptions; `GET /sends` stays a read-only
authorization check. Evidence: [enroll driver](proof-logs/current/enroll-driver/README.md),
[send driver](proof-logs/current/send-driver/README.md).

## WebAuthn recovery drivers (hosted on a79cba7)

The WebAuthn recovery path (`/recovery/webauthn/register/{start,finish}`,
`/recovery/initiate`, `/recovery/recover`) now delegates every decision to four
extracted drivers in `vela-recovery-policy`: 27 Rust contracts, 4 per-request
trace theorems with 24 reachability witnesses, and a 47-lemma concurrent
composition. Per request, a grant is issued only after the attempt-bound
challenge was consumed with a matching user, attempt and credential, a valid
user-verified assertion, any needed credential update stored, and a live row
with an active epoch, the same credential and a share; `ReleaseGrant` is the
only effect that releases the share. For any interleaving of finish requests on
one challenge and a budget of `k`: at most one grant, at most `k` counted
attempts and no release from a forbidden live-row observation. The counters
are keyed on the driver's own effects, and three mutations of the extracted
driver (budget, retry, live guard) each break the composition. WebAuthn
verification, store/SQL atomicity, rate-limit windows, decodes and effect
fidelity remain assumptions; concurrent registration starts are not claimed
to converge. The [a79cba7 workflow](https://github.com/lucannez64/VELA/actions/runs/40366675615) reproduced
it. [Evidence](proof-logs/current/webauthn-recovery-driver/README.md).

## Possession-recovery driver (hosted on 7a6d108)

The possession-proof recovery handlers (`/recovery/initiate-proof`,
`/recovery/recover/proof`) now delegate every post-validation decision to
extracted drivers in `vela-recovery-policy`: 11 Rust contracts, 35
per-request F* lemmas and a 40-lemma concurrent composition. For any event
list, one request grants at most once, and only after a consumed, matching,
verified proof at the live epoch, never while frozen or after revocation;
the recovery share is never an effect. For any number of interleaved
requests sharing one proof state and an attempt budget of `k`, at most one
grant is issued and no more than `k` attempts are counted. Grants are
counted from the driver's own effects, and a mutated rate-limit decision
breaks the proof. Store linearizability (`get_del`, `set_ex_nx`), effect
fidelity, the hybrid verifier, real rate-limit windows and TTLs are
assumptions; initiation and recovery are not composed in one world. The
[7a6d108 workflow](https://github.com/lucannez64/VELA/actions/runs/40149234823) reproduced it. [Evidence](proof-logs/current/possession-recovery-driver/README.md).

## Sharing driver (hosted on e89ebed)

The sharing handlers (send, linked-item update and revoke, inbox delete, share
key registration) now delegate every post-validation decision to an extracted
driver in `vela-share-policy`: 11 Rust contracts, 34 per-request F* lemmas
and a 45-lemma concurrent composition over a shared link, inbox and any number
of requests from the sender, recipient and a third party. Two results depend
on the driver and are mutation-checked: revocation is final (no update
commits after a revoke), and the driver never authorizes a non-sender's
update or revoke. Recipient-only inbox deletion and the inbox quota bound rest
on the modelled SQL guards and on transactions serializing. The parent review
found that the delegated sender-only theorem was true by construction and
repaired it. The SQL statements are unchanged. SQL semantics, observation
origins and handler effect fidelity remain assumptions. The [e89ebed workflow](https://github.com/lucannez64/VELA/actions/runs/40147963623)
reproduced it. [Evidence](proof-logs/current/share-driver/README.md).

## Additional checked results

- **Ten production transaction/recovery postconditions.** Desktop sharing now
  calls `initial_acceptance_is_authorized`, `next_store_generation` and
  `recovery_should_apply` directly. Seven negative theorems cover stale
  generations, pending-journal overwrite, generation overflow, local-edit
  overwrite, tombstoned-item resurrection, existing-pin restart and missing
  payloads. These prove decisions over supplied observations, not I/O.
- **The actual share-fact constructor.** A new F* postcondition specifies every
  `share_envelope::admission_facts` output, including failed-open cases,
  account/key/lineage comparisons and revision fields. It is conditional on
  the `OpenedShare` observation and independent context; opening, parsing,
  crypto correctness and context origins remain unproved. A local defined
  String view is manually trusted; see the
  [proof boundary](../../libVELA/vela-crypto/proofs/fstar/README.md).
- **Ten Tamarin journal properties.** M28 checks matching content/pins on
  opening, journal-before-vault writes, vault-before-cleanup, snapshot-generation
  provenance, one application per transaction, strict revision advance at each
  commit, a crash/recovery witness, the exact all-pairs goals
  `committed_pins_never_decrease` and `a_generation_commits_at_most_once`, and
  a two-successive-commit witness. The all-pairs goals are stated over emitted
  actions only and are nonvacuous: the witness makes both antecedents
  reachable. Their proofs use a conservative `Chain` ghost fact, described
  below. F★ checks lifting/projection between typed single-slot encodings;
  their bridge to actual Tamarin traces remains unproved. Atomic durable
  single-file replacement is assumed. Product-state rules write the two files
  separately; no atomic two-file write is assumed. Crashes preserve durable
  state; retained stale snapshots overapproximate volatile behavior. Local
  edits/deletions and independent processes are outside M28. The journal runner
  also rejects lemma/restriction atoms whose fact name or arity is not emitted
  in a rule action list (`check-action-atoms.py`); this is a source guard
  against vacuity, not a soundness certificate.
- **Additional production composition and parsing.** The actual
  `plan_observed_share` composition proves raw decoded-field authorization,
  including rejection, pin matching and permit revision. The real prefix reader
  uses a checked exact-prefix/suffix function. The hybrid signature path uses a
  checked AND gate with two rejection theorems; its permit revision getter is
  also checked. These are conditional contracts, not complete parser/crypto/I/O
  verification.
- **Composed M29 model.** Eleven lemmas now pass in one system joining dual
  signature checks, immutable pin frames, separate durable writes and crash
  recovery. Provenance is retained if either signing component remains
  unrevealed, with explicit honest-key premises. See
  [the mapping](../formal/signed-share-commit-correspondence.md).
- **Reduced assumption boundary.** Structural Rust matches replaced the 18
  opaque derived-enum equality uses. Fresh checking of all eight policy crates
  succeeded with zero local assume val declarations. The inventory now has
  **249 explicit postconditions / 256 selected functions** in eleven Rust modules,
  plus defined String and Vec compatibility models. Seven selected functions have
  no explicit ensures. Imported library assumptions and proof tools remain
  trusted; the drift checker is not a proof checker.

The enrollment ceremony now computes every policy fact through five pure
constructors (`open_facts`, `claim_facts`, `inspect_facts`, `completion_facts`,
`result_facts`) with hax postconditions, plus fifteen negative theorems. The
handlers read grant/claim presence, decoded key lengths, session/grant identity
equality, the opener's `revoked` column, the primary/collector signature result,
and the account epoch/rotation state. These twenty entry points are listed in
`serverVELA/vela-enrollment-policy/verify-fstar.sh` and were extracted and checked
in the [successful hosted refinement job](https://github.com/lucannez64/VELA/actions/runs/40039992434/job/120708563220)
on fbe35c0. That hosted inventory was 152 postconditions / 159 selected functions.
The exact CI extraction and logs are retained in the
[enrollment evidence](proof-logs/current/hosted-enrollment-40039992434/README.md). The observations themselves (SQL queries, store calls, signature
verifier, session ids) remain unverified glue; `claim_key_source: StoredClaim`
records the structural fact that the handler never accepts claim keys from the
request body.

The sharing handlers now compute `plan_send`, `plan_ek_registration` and
`plan_link_mutation` facts through three pure constructors (`send_facts`,
`ek_registration_facts`, `link_mutation_facts`) with hax postconditions, plus
eleven observation-based negative theorems. Send records the session user-id
presence, the recipient share-key row, the decoded capsule length and the inbox
byte total. EK registration records the selected device row, an explicit
comparison of that row's user id with the caller, the `revoked` column, whether
a binding already exists, the bytewise freshness result and the hybrid verifier
outcome. Linked update/revocation records the stored sender and tombstone state;
both handlers now call the verified mutation policy instead of relying only on
the SQL predicate. These fourteen selected entry points are listed in
`serverVELA/vela-share-policy/verify-fstar.sh` and now freshly checked locally,
bringing the corpus to 245/252. Hosted checking exposed an unrestricted i64
inbox-sum overflow; the corrected constructor uses guarded subtraction and a
widened mathematical-sum postcondition, rejecting negative counts. Hosted
reproduction passed on 5d8c366 and the later fdee2bc baseline. See the
[local evidence](proof-logs/current/share-inbox-arithmetic/README.md). Rate limiting, base64
decoding and the recipient/capsule/quota/timestamp upper-bound returns still
happen before the policy runs, and the SQL/session/verifier observations remain
unverified glue. `identical_timestamp_can_be_fresher` stays outside the selected
set, as before this increment.

[Current evidence](proof-logs/current/trusted-boundary/README.md) supersedes
prior extraction snapshots for all eight policy crates. CI includes the new
checks. The [hosted refinement job](proof-logs/current/hosted-refinement-40002230354/README.md)
passed on `b27dcd6`, and the [complete security workflow](https://github.com/lucannez64/VELA/actions/runs/40008926193)
passed on `e690dfc`. The parser/transcript and new enrollment contracts also passed hosted
refinement on fbe35c0. That full workflow failed before CryptoVerif ran because
of its runner permission error; a successful refinement job is not a successful
whole-workflow result.
The subsequent [complete security workflow](https://github.com/lucannez64/VELA/actions/runs/40041986647)
passed on 40c9f30 for that earlier 152-postcondition/pre-correction-model snapshot.
Those later computational and recovery increments now have hosted reproduction
on fdee2bc; see the current baseline above. Their semantic scope is unchanged.

The I/O-contract review also found and fixed an uncertain-write recovery gap:
readable pending metadata now receives a successful durability re-arm before
vault application. Its regression fails on the previous ordering and passes
with the fix. This does not close the concrete I/O refinement obligation.

A [written hybrid-signature EUF-CMA reduction](10-signature-reduction.md) now
specifies the exact byte-message game, a lossless projection to either
component, and disclosure of the other key. Its computational byte-message games now have CryptoVerif proofs under the
assumptions in the model README; complete Rust wrapper and game-composition
correspondence remains open.

Five freshly extracted wire contracts prove exact big-endian decoding, byte
decomposition, encoding round-trip and injectivity for all u64 values. The
production share-envelope integer writer/reader use this checked codec. This
is extended by the [concrete byte-frame refinement](11-parser-refinement.md),
including LP bounds, grouped cursor operations and exact frame field values.
The [received-byte transcript increment](12-authenticated-transcript.md) adds
checked body slicing and exact domain concatenation, used by the production
sender and opener. UTF-8/object conversion, encoder inverse and complete
authenticated-opening composition remain unproved.

The production byte parser now refines a functional VSE2 grammar for all input
slices. Cursor contracts cover fixed/LP fields and atomic grouped reads. Three
accessor kernels preserve opened fields/bytes; Rust module privacy and two
compile-fail checks prevent safe external construction/mutation of opened
observations. These results do not establish crypto-wrapper correctness or
context origins; see [the exact boundary](11-parser-refinement.md).

## Computational proof of the hybrid KEM combiner

CryptoVerif 2.12 proves idealized v2-combiner IND-CCA2 games, manually
mapped to `kem.rs`: from uniform prime-order GDH with ML-KEM correctness and its secret key
disclosed, and from ML-KEM IND-CCA2 plus the library collision bounds with the
DH secret exponent disclosed. Both use a random oracle. Together they give
the scoped model-level surviving-component claim (COMP-5), rather than a
complete theorem for the concrete X25519 construction. The legacy v1
combiner does not prove in the first game, as expected. A third game proves
`seal_share` IND-CCA2 as public-key encryption from an IND-CCA2 KEM and an
IND-CPA + INT-CTXT AEAD (KEM-DEM). Two more games machine-check the hybrid
signature reduction: the AND signature is EUF-CMA under the surviving ML-DSA-87
or Ed25519 assumption, with the other secret key leaked, under the documented
independent-key and fixed-length encoding assumptions in the model README. The X25519
cofactor, correspondence to the actual clamped scalar distribution, SHA-256 step and multi-user
security are open, as listed in
[the model README](../formal/cryptoverif/README.md). CI expects nine proved models and one explicitly unproved legacy baseline;
the repaired runner rejects process errors/timeouts and missing verdicts.

The nonuniform GDH companion now exposes collision and rerandomization losses
in a separate checked game. It assumes an unspecified nonuniform exponent
distribution; the conditional HPKE/Curve25519 constants are documented, not a
machine proof of the Rust clamp, subgroup handling or wire encoding. Its full
seven-model gate passed locally and in the [350cd57 hosted workflow](proof-logs/current/hosted-350cd57/README.md).
The [collision-side-condition note](proof-logs/current/x25519-nonuniform-gdh/COLLISION-SIDE-CONDITIONS.md)
separates pre-challenge freshness charges from post-challenge GDH queries; it
is a paper explanation alongside the retained tool debug trace.

## Recovery observation increment

The [recovery fact refinement](13-recovery-fact-refinement.md) adds 21 locally
checked postconditions, bringing recovery to 42 and the corpus to 173/180.
Initiation, credential-update and share-release constructors specify every
field from supplied observations; an epoch helper preserves the existing
missing/non-positive-to-initial normalization. This does not prove epoch freshness.
The handlers call the constructors, and challenge insertion now uses atomic
insert-if-absent so a stale freshness observation cannot overwrite a winner.
A real-store regression covers that interleaving; it is not an I/O refinement
proof. SQL/store/WebAuthn origins, early-return paths and complete state effects
remain open. [Hosted CI on `b8221e7`](https://github.com/lucannez64/VELA/actions/runs/40046015273)
reproduced all 173 postconditions, including these 21 recovery additions.

## Web-session observation increment

The [web-session refinement](14-session-observation-refinement.md) adds ten
locally checked contracts: constructors compute account bindings from optional
u128 identities, enforce grant nonce length, preserve the other observations,
and compose with the existing policies. Six rejection theorems cover absent
accounts, cross-account exchange, wrong nonce length and unsuccessful challenge/
signature observations. Handlers call the compositions and use the actual
verifier Result. The corpus is now 183/190; source decoding, actual SQL/store
semantics and complete handler traces remain open. Hosted reproduction of this
increment passed in the [350cd57 hosted workflow](proof-logs/current/hosted-350cd57/README.md).

## Possession and enrollment observation increment

The [remaining recovery constructors](15-recovery-possession-enrollment.md)
added 29 checked contracts: recovery reached 71 and the corpus 212/219.
The [enrollment preflight increment](16-enrollment-preflight.md) adds eight
contracts, initially bringing recovery to 79 and the corpus to 220/227.
Eleven additional independent ordering/readiness contracts now bring recovery
to 90 and the corpus to 231/238. The
parent strengthened enrollment to derive key validity from actual decoded
lengths (1600/2624) inside the verified constructor. Possession state insertion
uses atomic insert-if-absent, and empty commitments fail unavailable. Fresh
F★ checking and handler regressions pass locally. The observation snapshot was
reproduced on `350cd57`; the later preflight/ordering increment passed in the
[368bcc0 hosted workflow](proof-logs/current/hosted-368bcc0/README.md).
Grant store-key user binding, decoders, verifiers, storage effects, restoration
and complete handler traces remain open.

## Remaining obligations for the six requested areas

| Area | Status | Required to close |
|---|---|---|
| F-1: handler facts | Partial: observation constructors and policy checks hosted on fdee2bc; origins and full handlers remain open | Maintain the sharing contracts reproduced on 5d8c366; verify the observation producers (SQL rows, store lookups, signature verifier, session ids) themselves; complete UTF-8/object and authenticated-open composition after the checked byte-frame parser; prove independent context origins; cover remaining token, epoch, recovery and handler fact construction |
| F-2: state transitions | Partial: preflight ordering/readiness checked against an independent specification; enrollment-redemption decisions extracted into a driver with unbounded per-request trace lemmas (hosted aaf708f) and a concurrent at-most-one-device-per-grant composition (hosted edaee5a); sharing decisions extracted into a driver with per-request and concurrent composition proofs (hosted e89ebed); possession-proof recovery decisions likewise (hosted 7a6d108); device revocation, logout and revocation admission likewise (hosted bd765ab); WebAuthn recovery registration, initiation and release likewise (hosted a79cba7); device pairing likewise (hosted 54b38b3, found U-19); device enrollment and send links likewise; account deletion likewise (hosted cdffe46); vault chunk upload and read likewise (hosted cdffe46), including no stale or unauthorized row committed under concurrent rotations against a modelled atomic SQL guard (hosted 727d447); sharing handlers: every sequence up to depth 3 (CI) / 4 (local) matches the M19b/M21 state machine against the real router and database, with mutation checks; possession-proof recovery handlers: every sequence up to depth 4 (CI) matches the M18/M26a chain, with mutation checks (WebAuthn path not driven); device invitation/rendezvous handlers: every sequence up to depth 3 (CI, 5,220 traces) / 4 (local, 88,741) matches the M13 ceremony, with a mutation check ([evidence](proof-logs/current/pairing-conformance/README.md)); challenge consumers (`/auth/verify`, `/device/enroll`, `/web-session/:id/token`): every sequence up to depth 3 (CI, 7,240 traces) / 4 (local, 137,561) keeps each nonce single-use across all three, plus a 16-way concurrent race test and a mutation check ([evidence](proof-logs/current/challenge-single-use/README.md); each nonce is now bound to one purpose, see U-16); account deletion: every sequence up to depth 3 (CI, 2,380 traces) leaves no row in any of the eight tables and no sled key of the deleted account, and its tokens and devices stop working everywhere; this found and fixed two residues (send links and pending web sessions survived deletion) ([evidence](proof-logs/current/account-deletion-conformance/README.md); deletion now runs in one transaction, see U-17); device revocation and logout: every sequence up to depth 3 (CI, 11,155 traces) shows a revoked device loses every token and cannot log in again, logout ends only its own token, revoked devices cannot revoke and no cross-account revocation succeeds, with mutation checks ([evidence](proof-logs/current/device-revocation-conformance/README.md); revoking a device now also ends the web sessions it approved, see U-18) ; every server handler that runs one of these drivers reaches it only through a proved interpreter loop: for every executor the loop performs exactly the driver's effects, stops at its verdict within a budget and ends in a state the per-request theorems cover (hosted 6be552c/36b877e) | Verify the executor methods themselves (each effect's SQL/store I/O and the honesty of its observation) against a store/SQL model; state request cancellation (a dropped handler future) as a trace prefix; compose the drivers that share state (login, revocation, deletion, pairing, recovery) in one concurrent world; machine-check the remaining handler/database transitions outside the drivers |
| F-3: persistence/recovery | Partial: M28 and composed M29 | Prove the actual journal implementation refines M28; formalize collection equality and filesystem outcomes; compose local edits/deletions and RMS migration; cover or explicitly exclude independent processes |
| F-4: construction security | Partial: CryptoVerif proofs for idealized v2 KEM games, modular KEM-DEM, AND-signature, v2 possession-proof and authenticated-share games under the explicit assumptions | Close the combiner gaps listed in `security/formal/cryptoverif/README.md` (concrete X25519 clamping/cofactor/encoding correspondence after conditional nonuniform distribution accounting, SHA-256 step, quantum-query and multi-user composition; KEM-DEM is proved modularly); computational games and reductions for envelope framing and KDF use beyond the random-oracle model, under named primitive assumptions (share tags and the v2 possession proof are now proved in CryptoVerif with KDFs as random oracles; legacy v1 possession commitments are not covered); verify application randomness/error/erasure handling. Primitive internals and leakage resistance are trusted under the selected boundary |
| F-5: native clients/composition | [Shared chunk kernel](17-universal-chunk-admission.md) and [integer-epoch kernel](18-mobile-sync-admission.md) checked; mobile runtime fixes internally reviewed and hosted on fdee2bc; bounded Android (millions of traces) and iOS (1,110 traces, passing in macOS CI) conformance of the download gates against the Rust rules; native trace refinement remains open | Verify Kotlin/Swift callers, persistence and FFI; formalize enrollment UI trust; compose recovery, enrollment, sync, sharing and revocation in one argument |
| F-6: trusted base | Partial | Maintain zero local extraction assumptions and review imported model contracts; verify/review std/hax model correspondence and the String/Vec models; retain extraction/compiler correctness explicitly as trusted under the chosen boundary; review solver/library/OS interface assumptions; reproduce in CI and obtain independent review |

Every complete scoped proof must still choose a logic/kernel, machine model
and interface to physical execution. An assumed OS operation in a model is
not a proof that a deployed filesystem implements that operation.

## All-pairs journal goals

The journal gate now verifies ten M28 lemmas. The two previously open all-pairs
statements are included with their exact conclusions and no added premise:

- `committed_pins_never_decrease`: for every two `JournalCleared(slot, tx, g,
  r)` events in the same slot, an earlier event has `r1 << r2`.
- `a_generation_commits_at_most_once`: two `JournalDurable` events in the same
  slot with the same generation occur at the same time.

Both formulas mention only emitted rule actions. The witness
`two_successive_commits_advance` exhibits two successive real commits with
concrete generations
`successor('initial')` and `successor(successor('initial'))`, two cleanups and
a strict revision advance, so neither goal is vacuous. The existing
crash/recovery witness remains reachable.

The [local proof evidence](proof-logs/current/journal-all-pairs/README.md)
retains complete proof trees and records the rejected, vacuous predecessor.
Hosted reproduction of this journal increment passed on [5fa4e9f](https://github.com/lucannez64/VELA/actions/runs/40065136343).

The proofs use a linear `Chain(slot, generation, pin)` ghost fact added to
`Initialize`, `PersistJournal` and `ClearJournal`. It follows the durable
phase, advancing when the journal becomes pending and remaining unchanged
through cleanup. No guard or security restriction was added.

The [F★ encoding proof](../formal/m28-trace-equivalence/README.md) checks
step/trace lifting, projection and Chain well-formedness for typed,
initialized, single-slot machines. It is not an equivalence proof of the
`.spthy` sources: original Tamarin traces must still embed into the core
encoding, and their lifts must still yield admissible instrumented Tamarin
traces. Input derivability, global freshness, term representation and slot
projection remain source-bridge obligations. The generic F★ transfer theorem
requires a safety proof argument. New direct encoded inductions now establish
both all-pairs goals without using that hp argument; lifted results follow by
projection. Pin increase requires a supplied strict-order record, while journal
generation uniqueness is order-independent. A checked unary free-term order
and nine-event two-commit core/lift witness establish encoded non-vacuity.
This unary instance does not formalize Tamarin's full strict-subterm algebra.
No source embedding or actual Tamarin theorem is obtained. The handwritten
proof adds zero Rust postconditions and does not change the ten/eleven Tamarin
verdicts. The previous [encoding equivalence evidence](proof-logs/current/journal-encoding-equivalence/README.md)
was reproduced on 368bcc0; the new all-pairs/order/witness check needs its own
hosted result. See the [new proof](../formal/m28-trace-equivalence/README.md) and
[parent reproduction](proof-logs/current/journal-encoded-goals/README.md).

The journal runner first runs `check-action-atoms.py` on M28 and M29. It strips
comments and string literals, collects each rule's action name/arity, and
rejects lemma or restriction atoms whose fact is not an emitted action. The
regression fixture `tests/vacuous-action-atom.spthy` is rejected for
`DiskClean/5`; the real models pass. This catches the historical vacuity shape
but does not certify soundness. Tests cover both explicit trace qualifiers
(`all-traces` and `exists-trace`), wrong arities, comments, and malformed input.
The default journal proof timeout is 600 seconds per model; the memory cap
and single-worker setting are unchanged.

A matching hash, finite tests, unproved annotation, ideal primitive, new axiom
or mocked database cannot substitute for these obligations. No unsupported
computational reduction, full Rust/Kotlin/Swift refinement or whole-system
completion claim is supplied here. The Tamarin↔F★ source bridge and real
Rust/filesystem refinement of M28 remain open.

## Login driver increment

The [published login proof](proof-logs/current/login-driver/README.md) and
[release-build runtime gates](proof-logs/current/login-driver-runtime-gates/README.md)
passed hosted checks on `5ae87da`, including the
[refinement job](https://github.com/lucannez64/VELA/actions/runs/40196922149/job/121179647957).
That hosted result predates the producer and nonce-composition additions below,
which then passed on `8d3610d` in the
[security workflow](https://github.com/lucannez64/VELA/actions/runs/40200134577).
The raw-world bridge then passed on `dd0cab1`, and the take adapter below on
`ca061a3`.

The [producer proof](proof-logs/current/login-tag-producer/README.md) checks the
actual raw-slice conversion and pure issuer/classifier composition. The
[concurrent nonce module](proof-logs/current/login-nonce-composition/README.md)
checks at most one accepted request, Respond effect and successful issuance
observation for any interleaved schedule under its atomic-take interface.
The focused extraction now has 16 selections / 12 explicit postconditions;
8 require a sound driver state, established initially and preserved. Producer
and composition add 23 and 60 handwritten lemmas respectively. The subsequent
[raw-world bridge](proof-logs/current/login-raw-nonce-bridge/README.md) adds 44,
proving per-action and arbitrary-schedule projection from modeled raw bytes
through the actual classifier to the abstract purpose world. These remain
separate from the unchanged base 249 postconditions / 256 selections census.
The historical session artifact remains 19 postconditions / 21 selections.

The [take adapter](proof-logs/current/challenge-take-adapter/README.md) then
moves the server's `Option<Vec<u8>>` conversion and purpose decision into the
extracted `classify_taken_challenge`, which `take_challenge` calls right after
`get_del`; 26 handwritten lemmas prove it equals an independent literal-byte
specification for every result and purpose (absent is `Missing`; accepted
exactly on the expected literal; every other present value is
`WrongPurpose`), and an accept-absent mutant is rejected. It adds no Rust
postcondition; the focused gate now checks 17 selections in 8 modules
(194 handwritten lemmas). The [ca061a3 workflow](https://github.com/lucannez64/VELA/actions/runs/40210079502) checked all 8 modules
in one invocation.

The [store world](proof-logs/current/challenge-store-world/README.md) then
joins the two: a world whose nonce is the store's actual `Option<Vec<u8>>`
value, taken by the extracted adapter, commutes with the raw world for every
action and schedule, so at most one admission, response and token per nonce
holds over the real result type (10 lemmas; a take that keeps the value
breaks the proof). The [28c72c3 workflow](https://github.com/lucannez64/VELA/actions/runs/40215378476) reproduced it.

The real store's take semantics (linearizability, durability, key binding),
the imported hax `Vec` model, SQL/store/verifier origins, effect fidelity,
revocation/issuance linearization, exceptions, crashes and whole-system
composition remain open. Neither proof establishes sled linearizability.
See the [detailed scope](19-login-producer-composition.md). No external audit
is claimed.
