# Recovery observation-to-fact refinement

At this increment, recovery had 42 checked postconditions (then 71, now 90; see
[the later increment](15-recovery-possession-enrollment.md)), including
21 new contracts for initiation, credential metadata update, share release and
epoch normalization. The actual handlers call the checked fact constructors.
This is a conditional mapping over observations, not complete handler/I/O or
WebAuthn refinement. [Local evidence](proof-logs/current/recovery-fact-refinement/README.md)
records the checks; hosted reproduction is pending.

## Exact checked boundary

`initiate_facts` maps account/share/credential presence, attempt-slot freshness
and TTL to every initiation fact, deriving Ready versus Unavailable from the
availability observations. `credential_update_facts` preserves assertion
validity, credential equality and the authenticator's metadata-update flag.
`recover_facts` maps Consumed versus Missing to the challenge phase and one-shot
flag, and preserves user/attempt equality, credential binding, assertion/user
verification, share presence and clear rekey-state observations. Composition and
negative contracts specify the resulting authorization decisions.

`observed_recovery_epoch` preserves the existing handler behavior: absent or
non-positive epochs become INITIAL_EPOCH, and positive values are retained.
Its positivity theorem does not establish a current/stale-epoch distinction.

The handlers compute the inputs from SQL rows, decoded passkey options,
`exists`/`get_del`, request/challenge IDs, WebAuthn results and credential IDs.
These producers and their timing are not verified by the fact constructors.
Several errors still return before the constructors run, so negative constructor
proofs do not establish those full handler traces. JSON/base64 parsing, rate
limiting, randomness, credential writes, share decoding and grant storage are
also outside this increment.

## Freshness observation and actual insertion

A store `exists` observation can become stale before insertion. The final
challenge write now uses the existing `set_ex_nx` compare-and-swap operation;
a collision returns Conflict instead of overwriting an existing challenge.
Both an observed collision and a collision after the policy check return 409.
Other existing recovery error classes and precedence are retained.

A deterministic real-store regression gives two requests the same empty-slot
observation, stores the first challenge, rejects the second and verifies that
the winner's bytes remain intact. This exercises the production storage helper.
The store's atomicity contract remains trusted, and this finite interleaving
regression is not a proof of every concurrent handler/database trace.

## Evidence and remaining work

Fresh extraction and F★ checking use the pinned hax 0.3.7, Rust
nightly-2025-11-08, F★ 2025.10.06 and Z3 4.13.3, through the shared heavy-command
lock and 3 GiB/no-swap/one-worker cap. The generated module was not hand-edited.
At this recovery increment, the inventory was 173 postconditions / 180 selected functions, retaining
seven selected spec/comparison functions without ensures and zero local
assume val declarations. Imported models and the toolchain remain trusted.

SQL/store/WebAuthn observation provenance, early-return equivalence, complete
state effects and native/protocol composition remain open under the
[selected boundary](09-target-contract.md). This does not close F-1 or establish
full-system formalization.
