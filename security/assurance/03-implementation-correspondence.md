# 3. Implementation correspondence

This document explains how the symbolic models relate to the Rust that
ships, what hax/F\* verifies, and where correspondence is only claimed.

## 3.1 The assurance stack

```
  ┌──────────────────────────────────────────────────────────────┐
  │ Tamarin / ProVerif models  (security/formal/*.spthy, *.pv)    │  protocol properties
  └───────────────▲──────────────────────────────────────────────┘
                  │  (1) MANUAL correspondence: policy rules ↔ model rules
  ┌───────────────┴──────────────────────────────────────────────┐
  │ Pure Rust policy crates  (vela-*-policy)                       │  hax → F*: every input,
  │   facts (bools/ints/enums) ──► decision / unforgeable permit  │  postconditions proved
  └───────────────▲──────────────────────────────────────────────┘
                  │  (2) UNVERIFIED glue: handlers compute facts and act on permits
  ┌───────────────┴──────────────────────────────────────────────┐
  │ Axum handlers, SQL (Turso), sled, clients, FFI bridges         │  [EXEC] model tests,
  │ vela-crypto (RustCrypto primitives, Shamir, ORAM, AEAD)        │  races, [EXPLOIT], unit
  └──────────────────────────────────────────────────────────────┘
```

Two seams in this stack are **not** formally verified:

1. **Model ↔ policy.** No tool checks that a policy crate's Rust spec
   predicate is the same as the corresponding Tamarin rule guard. The
   relationship is maintained by hand. The new network models have a detailed
   [mapping table](../formal/network-boundary-correspondence.md) and reviewed
   artifact hashes checked by `check-correspondence.py`. This detects drift
   in listed files but is not a semantic equivalence proof. Names line up on purpose (for example,
   M11c `ACTIVE`-at-permit-epoch and `authorize_active_mutation`), but this
   is a reviewable claim, not a theorem.
2. **Facts ↔ reality.** A policy function takes facts such as
   `signature_verified: bool` or `device_active: bool`. Handler code computes
   those facts with SQL queries and calls into `vela-crypto`. If a handler
   computes a fact wrongly, the verified decision is made over false inputs.
   **This glue is the most valuable place for an auditor to look.**

## 3.2 What hax/F\* verifies

hax 0.3.7 extracts selected Rust functions into F\*. F\* 2025.10.06 with
Z3 4.13.3 then discharges their `hax_lib::ensures` postconditions **without
`--lax`**, for every input, including Rust integer-overflow semantics.

Each crate follows the same pattern:

- **Planning functions** (`plan_*`, `authorize_*`) map a facts struct to a
  decision. Positive outcomes carry a permit type with private fields, so
  handler code can only obtain a permit through the policy. Postcondition:
  `decision_matches_spec(facts, decision)`, where the spec is a separate
  Rust predicate in the same crate.
- **Negative theorems** (`*_can_*`) take an arbitrary facts struct, falsify
  one required fact, call the real decision function, and are proved to
  return `false` or `Reject`. Example from `vela-share-policy`:

  ```rust
  #[cfg_attr(hax, hax_lib::ensures(|result| result == false))]
  pub fn forged_ek_binding_can_register(mut facts: EkRegistrationFacts) -> bool {
      facts.signature_verified = false;
      ek_registration_is_authorized(facts)
  }
  ```

### Crate inventory (225 policy postconditions / 228 selected policy functions)

| Crate | Entry points | Models | Production call sites |
|---|---:|---|---|
| `serverVELA/vela-rekey-policy` | 12: `next_epoch`, `resolve_write_epoch`, `plan_start`, `authorize_attempt`, `authorize_shadow`, `plan_commit`, `plan_abort`, `plan_timeout`, `authorize_commit_replay`, `plan_active_mutation`, `authorize_active_mutation`, `stale_permit_authorizes_successor` | M11, M11c | `vault/rekey.rs`, `middleware.rs`, `device/enroll.rs`, `device/rendezvous.rs`, `recovery/mod.rs`, `recovery/enroll_device.rs` |
| `serverVELA/vela-session-policy` | 21: two observation constructors, two observation/decision compositions, six new negative theorems, and the prior 11: `parse_scope_claim`, `plan_grant`, `plan_device_token`, `plan_web_session_token`, `plan_renewal`, `authorize_route`, `clamp_web_ttl`, `web_session_expired`, plus 3 negative theorems | M12, M20 | `middleware.rs` (`DeviceSession` extractor), `auth/token.rs`, `web_session/mod.rs` |
| `serverVELA/vela-enrollment-policy` | 29 checked in hosted F★: 5 decisions, 5 fact constructors and 19 negative theorems | M13 | `device/rendezvous.rs` |
| `serverVELA/vela-recovery-policy` | 90: the prior 42, 29 possession/enrollment observation contracts, 8 preflight contracts and 11 independent ordering/readiness contracts; plus, counted separately, a redemption driver with 6 contracts, 23 trace lemmas and a concurrent one-device-per-grant composition, and possession-recovery drivers with 11 contracts, 35 trace lemmas and a concurrent one-grant-per-proof composition | M14, M16, M18 (server side) | `recovery/{initiate,recover,possess,webauthn,enroll_device,mod}.rs` |
| `serverVELA/vela-share-policy` | 23 locally checked postconditions: three observation constructors (`ek_registration_facts`, `send_facts`, `link_mutation_facts`), three decisions and seventeen negative theorems (24 selected entry points); plus, counted separately, a handler driver with 11 contracts, 34 per-request lemmas and a 45-lemma concurrent composition | M19b, M21 | `share/mod.rs` |
| `libVELA/vela-client-recovery-policy` | 18: `plan_reconstruction`, `plan_adoption`, `plan_publication_resume`, `plan_contact_delivery`, plus 14 negative theorems | M15, M17, M18 (client side) | `vela-crypto/src/recovery.rs`, `desktopVELA/vela-desktop-core/src/recovery.rs`, Android and Apple bridges |
| `libVELA/vela-sync-policy` | 15 Rust postconditions (11 historical plus 4 focused epoch contracts), [20 chunk lemmas](17-universal-chunk-admission.md) and [6 epoch lemmas](18-mobile-sync-admission.md) counted separately: `plan_epoch_adoption`, `plan_chunk_download`, `classify_merge_action`, plus 8 negative theorems | M23 | `desktopVELA/vela-desktop-core/src/sync.rs`; mobile downloads use admitted Rust bridge paths; runtime fixes tested/reviewed and hosted on fdee2bc, native trace refinement open |

The eighth crate, `libVELA/vela-client-share-policy`, selects 19 postconditions:
share admission, ten transaction/recovery functions/theorems, and the actual
permit-revision getter. Desktop sharing calls the corresponding decisions.
Twenty-four crypto postconditions cover fact construction, decoded-field/policy
composition, hybrid verification gates, fixed-width arithmetic, exact LP/u64
splitting, stateful/grouped cursors, full byte-frame grammar refinement and
read-only accessor kernels, exact signed-body slicing and domain concatenation.
The latter uses a defined Vec compatibility model with a checked sequence
concatenation contract; its std correspondence remains trusted. See
[the parser boundary](11-parser-refinement.md) for the remaining UTF-8,
authenticated-open, encoder and I/O obligations.

All eight policy crates were freshly extracted and checked after replacing
derived-enum equality uses with structural matches. No local `assume val`
declarations remain. The [current evidence](proof-logs/current/trusted-boundary/README.md)
and [crypto contract boundary](../../libVELA/vela-crypto/proofs/fstar/README.md)
record their assumptions. Current code has 256 selected functions and 249
explicit postconditions; selected functions and predicates are different counts.
The enrollment fact-construction increment adds five observation-to-fact
constructors and fifteen negative theorems (twenty selected entry points) that
passed hosted extraction and F★ checking on fbe35c0. The earlier hosted 159/152 counts include
them; recovery extended the inventory to 180/173, reproduced in hosted CI on 5fa4e9f. The local web-session increment extended this to 190/183, and the [possession/enrollment increment](15-recovery-possession-enrollment.md) to 219/212. The [preflight increment](16-enrollment-preflight.md) first brought this to 227/220; the independent ordering proof brings it to 238/231. The [exact CI evidence](proof-logs/current/hosted-enrollment-40039992434/README.md)
preserves the regenerated enrollment artifact without editing its body.

The share fact-construction increment adds three observation constructors and
eleven observation-based negative theorems (fourteen postconditions). It brings
`serverVELA/vela-share-policy/verify-fstar.sh` to 24 selected entry points and,
after the local inbox-arithmetic correction, the corpus to 252 selected functions
and 245 explicit postconditions. The corrected constructors were freshly
extracted and F★-checked locally, then reproduced in hosted CI on fdee2bc. `identical_timestamp_can_be_fresher` remains
outside the selected set, as before this increment.

The CI `refinement` job installs pinned tools, runs all eight crates and the constructor,
retaining logs. The complete [security workflow](https://github.com/lucannez64/VELA/actions/runs/40008926193)
passed on `e690dfc` for the preceding 119-postcondition snapshot. The parser/transcript and enrollment increments subsequently passed the hosted
refinement job on fbe35c0; its full security workflow failed before computational
proof execution because of the runner's executable bit.
The repair subsequently passed the complete workflow on 40c9f30. The computational corrections, 173-postcondition recovery inventory and journal increment passed hosted CI on 5fa4e9f. The new [web-session observation increment](14-session-observation-refinement.md) is checked locally and awaits hosted reproduction.

Every crate has a `verify-fstar.sh` runner, and most have a README that
states its proof boundary (for example
[`vela-rekey-policy/README.md`](../../serverVELA/vela-rekey-policy/README.md)).

### Trusted in the F\* layer

| Item | Why it is trusted |
|---|---|
| **hax frontend and engine 0.3.7** | Extraction soundness. hax is research-grade. A translation bug could make F\* prove something about code that differs from the Rust |
| **hax `core_models` / `rust_primitives` F\* libraries** | Models of Rust integers, slices, and `Option`. Shipped by hax, not reviewed here |
| **Structural equality and local declarations** | The earlier 18 opaque PartialEq assumptions have been eliminated. Current extracted modules contain no local assume val/admit bodies; the drift gate enforces this reviewed state. Imported hax libraries still include trusted models/assumptions and emit float/loop warnings |
| **F\* 2025.10.06 and Z3 4.13.3** | Standard trusted computing base for F\* |
| **The spec predicates** | `*_matches_spec` predicates are written in Rust by the same authors. F\* proves code = spec, not spec = intent |

### Extraction artifacts

The [local run snapshots](proof-logs/current/refinement-5g/extractions/)
contain fresh checked `.fst` files for all eight crates and their Cargo
lockfiles, covered by [`MANIFEST.sha256`](MANIFEST.sha256). The source-tree
extractions were regenerated too. Rekey's source-tree extraction remains
ignored by its restored `.gitignore`; its snapshot is included in the evidence.
Historical CI did not regenerate or check extractions. The new CI gate removes
previous `.fst`/`.fsti` output before extracting; [the hosted refinement job](proof-logs/current/hosted-refinement-40002230354/README.md)
passed on `b27dcd6`.
The earlier eight-policy and crypto snapshots remain in
`proof-logs/current/trusted-boundary/extractions/`. Current snapshots of all
thirteen artifacts (eight policy modules, three crypto modules and String/Vec
models) are in `proof-logs/current/authenticated-transcript/extractions/`.
Its fresh crypto checking log supersedes the earlier parser snapshot. The
defined Vec subset exposes checked sequence-concatenation refinements;
correspondence to Rust std remains trusted.
Always re-extract after changing Rust sources. `check-proof-boundary.py` records
249 explicit postconditions; seven selected functions have no `ensures`. It
detects added extraction assumptions, not semantic correspondence.

## 3.3 Executable refinement evidence (CI-gated)

The table distinguishes finite policy enumeration from concrete handler,
database and FFI execution. Coverage is limited to each listed property:

| Test | What it checks |
|---|---|
| `serverVELA/vela-server/tests/rekey_state_model.rs` | Fixed-point state exploration (epoch ≤3, 4 attempts, 2 devices, 2 chunks). All 24 upload orderings run against the real Axum handlers and Turso. Start-vs-write and timeout-vs-commit races |
| `…/tests/session_capability_model.rs` | Finite grant, renewal and route fact combinations against the pure session policy; no HTTP/database execution |
| `…/tests/enrollment_ceremony_model.rs` | Finite enrollment fact combinations against pure policy constructors; no handler execution or concurrent completion race |
| `…/tests/recovery_lifecycle_model.rs` | Finite recovery phases/facts against pure recovery policy constructors; no HTTP/database execution |
| `…/tests/integration.rs::recovery_publication_finalizes_exactly_the_current_staged_split` | The SQL pending-row compare and atomic promotion |
| `libVELA/vela-client-recovery-policy/tests/bounded_refinement.rs` | Exhausts the reducer's Boolean state space |
| `vela-crypto rekey::tests::fleet_wire_matrix_is_cross_client_and_epoch_compatible` | Every producer × consumer across desktop, web, Android, and Apple at epochs 1–4. Exact epoch AAD; legacy rejected after epoch 1 |
| Android, Apple, and WASM bridge `--lib` tests | Same wire contract through each FFI |
| `security/exploits/run-exploits.sh` | 9 live exploits (S-1/2/4, IDOR/XFF, P-1, S-3/RT-1, RT-2, RT-4, RT-5, RT-6, RT-7) against an isolated server |

The desktop [sharing-boundary fixes](07-boundary-review.md) add an encrypted
write-ahead record for pins and pending item changes, generation-checked
snapshots and serialized callers. Thirteen new regressions exercise rejection,
concurrent acceptance, corruption, interrupted commits, recovery conflict
handling and RMS rotation. These are executable implementation checks, not a
formal refinement of the filesystem or journal into M19c's atomic rule.

## 3.4 ProVerif extraction (M22)

`libVELA/vela-crypto/proofs/proverif/extraction/lib.pvl` is produced by
hax's experimental ProVerif backend. It contains exactly one function:

```
letfun vela_crypto__oram__uuse_trivial_oram_with_threshold(chunk_count, threshold) =
       core_models__cmp__f_le(chunk_count, threshold).
```

The ORAM transcripts in `m22{a,b,c}.pv` are written by hand to match
`PathOram::prepare_access` and the trivial sweep. The correspondence of
those transcripts to `libVELA/vela-crypto/src/oram.rs` is **manual**. M24
checks the real ORAM statistically.

## 3.5 Components with no formal correspondence

This is a Rust correspondence boundary. The [CryptoVerif games](../formal/cryptoverif/README.md)
provide computational model proofs for the idealized KEM, modular KEM-DEM and
AND signature. They do not close the manual mapping to the concrete Rust,
its failure paths, encoding, randomness or the real X25519 scalar distribution.


| Component | Covered by |
|---|---|
| `vela-crypto` primitives and constructions: hybrid KEM combiner, hybrid signatures, AEAD wrappers and AAD encoding, BLAKE3 context registry, Shamir and its share tags, link encryption, Argon2id parameters | Scoped CryptoVerif games for KEM/KEM-DEM/AND signatures, v2 possession and authenticated Shamir reconstruction; concrete Rust/hash/encoding correspondence remains manual. Remaining constructions have unit/interop tests and dependency audit (`cargo audit`, `cargo deny`) |
| Device authentication (`/auth/challenge`, `/auth/verify`) and PASETO v4 issuance and validation | Unit and integration tests; RT exploit suite |
| Rate limiting (sled TTL counters) | RT-7 exploit regression |
| Desktop IPC peer checks (`ipc_peer`, `ipc_gate`), native host, extension | M6 abstracts them as `BrowserSpawned`; audit D-4, E-1, E-2 |
| Android and iOS sync admission | **Not** routed through `vela-sync-policy`. Kotlin and Swift sync engines implement the rules natively (contract test `EpochSyncContractTest.kt`) |
| Hardware keystore integration (TPM, Secure Enclave, StrongBox, Windows Hello, LocalAuthentication) | Audit D-3 and D-5 fixes; manual |
| WebAuthn verification | `webauthn-rs` 0.5.4 (trusted library) |
| One-off share links (`/send`), audit log, breach monitoring, importers | Tests only |

## 3.6 Tracing a claim end to end

Use AUTH-7 (share-key registration) as a worked example of how to audit a
claim across layers:

1. **Model:** `m19b_share_channel.spthy`, rule `RegisterShareKey` requires
   `!DevKey(U, X)`. Lemma `registrations_require_enrolled_device_signature`.
2. **Policy:** `vela-share-policy::plan_ek_registration`. F\* proves it
   matches `ek_registration_decision_matches_spec`, and
   `forged_/replayed_/foreign_device_/revoked_device_ek_can_register` are
   all `false`.
3. **Glue:** `serverVELA/vela-server/src/share/mod.rs` around lines 640–770
   builds `ek_registration_facts` from the decoded share-EK length, the hybrid
   verifier result, the selected device row (including comparing `d.user_id` to
   the caller), the `revoked` column, whether a binding already exists, and the
   bytewise `signed_at_is_fresher` result. The constructor's F\* postcondition
   states each fact in terms of those observations.
4. **Questions the proofs cannot answer:** Is the SQL join really
   ownership-scoped? The policy now receives both row presence and an explicit
   owner comparison, but the SELECT itself is still unverified glue. Is the
   signature verification hybrid-AND? Does the bytewise freshness comparison
   match chronological order for every RFC 3339 string the handler accepts? The
   handler stores the client-supplied string as-is, while M25 assumes a
   canonical rendering (see [Q-6](06-engaging-researchers.md#priority-questions)).
5. **Executable:** exploit `test_rt5_share_ek_hijack.py`.

## Device revocation driver

`vela-session-policy::revocation_driver` holds the revoke, logout and
revocation-admission decisions called by `device/revoke.rs`, `auth/logout.rs`
and `middleware.rs` (13 contracts, 28 per-request and 56 composition lemmas;
[evidence](proof-logs/current/revocation-driver/README.md)). Handler effect
fidelity and store/SQL semantics are assumed.

## Account deletion driver

`vela-session-policy::deletion_driver` holds every decision of
`DELETE /account` (`account/delete.rs`): actor and scope refusal, scan and
lockout classification, the fixed table order, the `users`-row existence check
and commit or rollback (11 contracts, 37 per-request, 5 bridge and 18
composition lemmas; [evidence](proof-logs/current/deletion-driver/README.md)).
The SQL transaction's atomicity, store linearizability and handler effect
fidelity are assumed.

## Handler-to-driver interpreters

`DELETE /account`, `POST /auth/verify`, `POST /device/revoke`,
`POST /auth/logout`, the pairing handlers in `device/invitation.rs` and
`device/rendezvous.rs`, the sharing handlers in `share/mod.rs` and the vault chunk handlers in
`vault/chunk.rs`, `recovery/enroll_device.rs`, `recovery/possess.rs` and the WebAuthn recovery
handlers in `recovery/{webauthn,initiate,recover}.rs` each run
their policy crate's interpreter macro, the same loop F* checks for every
executor ([deletion](proof-logs/current/deletion-interpreter/README.md),
[login](proof-logs/current/login-interpreter/README.md),
[revocation](proof-logs/current/revocation-interpreter/README.md),
[pairing](proof-logs/current/pairing-interpreter/README.md),
[sharing](proof-logs/current/share-interpreter/README.md),
[vault](proof-logs/current/vault-upload-interpreter/README.md),
[redemption](proof-logs/current/redemption-interpreter/README.md),
[possession](proof-logs/current/possession-interpreter/README.md),
[WebAuthn](proof-logs/current/webauthn-interpreter/README.md)). The handler's
review surface is reduced to the executor methods in `account/delete.rs`, one
per effect; `security/formal/tests/test_handler_interpreters.py` refuses a
handler that calls the driver outside the macro.

## Vault upload driver

`vela-rekey-policy::vault_upload_driver` holds the authentication, epoch-route,
shadow-authority, quota, write-classification and publication decisions of
`put_chunk` and the read scope of `get_chunk` (`vault/chunk.rs`; 14 extracted
functions, 42 per-request and 67 composition lemmas;
[evidence](proof-logs/current/vault-upload-driver/README.md)). The guarded SQL
statements are modelled as atomic steps against the live account row; their
linearizability, quota accounting and handler effect fidelity are assumed.

## Device pairing driver

`vela-enrollment-policy::pairing_driver` holds every post-validation decision
of the invitation (`device/invitation.rs`) and rendezvous
(`device/rendezvous.rs`) handlers: package store/redeem, grant open, claim,
completion and result (30 contracts, 43 per-request and 67 composition lemmas;
[evidence](proof-logs/current/pairing-driver/README.md)). Store/SQL atomicity,
signature verification and handler effect fidelity are assumed.

## WebAuthn recovery drivers

`vela-recovery-policy::webauthn_driver` holds every decision of the WebAuthn
registration (`recovery/webauthn.rs`), initiation (`recovery/initiate.rs`) and
share-release (`recovery/recover.rs`) handlers (27 contracts, 4 trace theorems,
24 per-request witnesses and 47 composition lemmas;
[evidence](proof-logs/current/webauthn-recovery-driver/README.md)). The
WebAuthn verifier result, store/SQL semantics and handler effect fidelity are
assumed.

## Login driver and challenge-purpose recognition

The [login increment](proof-logs/current/login-driver/README.md) checks the
actual extracted `login_driver::step` by induction over arbitrary per-request
event lists. A response requires accepted challenge, valid verifier and tracked
JTI observations, and occurs at most once. The [producer proof](proof-logs/current/login-tag-producer/README.md)
now checks the actual raw-slice conversion, composed literal-byte acceptance,
and the pure issuer → convert → classify path. Store/take round trips and
Option/Vec glue remain outside that result.

The [nonce composition](proof-logs/current/login-nonce-composition/README.md)
checks any finite number of interleaved login requests and schedule length,
with at most one admission, response and successful issuance observation per
nonce. It assumes an atomic, purpose-correct take on one key, paired effects
and observations, and faithful handler execution. The [raw-byte bridge](proof-logs/current/login-raw-nonce-bridge/README.md)
now proves that a modeled raw-slice take using the extracted converter and
classifier projects to the abstract world for every action and schedule.
Literal-byte correctness follows from the producer proof. This removes the
purpose-oracle premise inside the pure model. The [take adapter](proof-logs/current/challenge-take-adapter/README.md)
now proves the actual `Option<Vec<u8>>` decision the handler calls equals a
literal-byte specification; the real store's take semantics and a joined
Option-to-raw-world theorem remain unproved.
The handler enforces effects in release builds; its wiring is reviewed and
tested, not a handler/SQL/store refinement theorem.

The focused extraction has 16 selections / 12 explicit postconditions (8
conditional on a sound driver state), separate from the unchanged 249-policy
postcondition census. The producer adds 23 handwritten lemmas and composition
60; the raw-world projection adds 44. These are not Rust postconditions.
Full lifecycle, storage, revocation,
issuance, exception and crash composition remain open. See the
[scope note](19-login-producer-composition.md).
