# 5. Known limitations

This document lists what is **not** established. We would rather over-list
here than have a researcher find an unstated gap. IDs are stable so you can
cite them.

## Unproved properties

| ID | Property | Status |
|---|---|---|
| **U-1** | **End-to-end secrecy of the RMS and vault plaintext against a malicious server** (CONF-1, CONF-2) | No theory models the whole system with the server as attacker. Secrecy is argued from the architecture. Individual theories either model the server as an honest enforcer (M11–M21, M26) or make capsule contents opaque by assumption (M19b, M21) |
| **U-2** | **Device authentication beyond the challenge proof** | M27 locally proves signature provenance, challenge single use and registered-user binding. PASETO parsing, TTL, JTI revocation, device-revocation cascade and concurrent issuance remain unproved. An in-flight request can pass lookup before revocation and mint later. Fresh device-token admissions now recheck the durable matching active-device row, so a late token cannot bypass a completed revocation when the temporary sentinel expires; this is regression-tested, not an unbounded middleware proof. |
| **U-3** | **Computational security of the complete constructions**, including AEAD AAD encodings, BLAKE3 contexts, Shamir share tags, link-key/passphrase mixing and possession proofs | Scoped exceptions: CryptoVerif models cover the v2 KEM combiner, modular KEM-DEM, AND signatures, v2 RMS possession proofs and authenticated Shamir reconstruction under the [listed assumptions](../formal/cryptoverif/README.md), including ideal KDF/tag abstractions. Concrete hash/context/encoding correspondence, other constructions and full composition remain unproved. See [Q-1](06-engaging-researchers.md#priority-questions) |
| **U-4** | **Enrollment beyond both-key fingerprint binding** | M13b locally proves secrecy against key substitution under an ideal authentic human comparison. It does not prove primary-to-joiner authentication, correct adoption, human behavior, finite fingerprint collision resistance, or full composition with M13. |
| **U-5** | **Recovery with a network adversary** | M14 is ordering-only. M15 and M18 add adversarial cloud storage and contact responses, but WebAuthn is an idealised honest rule |
| **U-6** | **Long-term key compromise and post-compromise security** | M8/M10 model local client-key corruption; new M19c/M27 model device-key reveals and M19c models recipient decryption-key reveal. RMS compromise followed by rotation and cross-protocol compromise composition remain unproved. |
| **U-7** | **Sync rollback with advancing clocks** | M23 models only the bootstrap clock. Monotonic advancement from admitted revisions is future work (stated in the model) |
| **U-8** | **Mobile sync admission** | Android and iOS downloads now call admitted Rust bridge paths using the shared chunk policy and integer epoch kernel. These pure kernels are checked; Kotlin/Swift/JNI/C/JSON wiring, authenticated-open composition, baseline storage and complete native traces remain unproved. The runtime fixes have JVM/bridge tests and hosted build validation, not native-client refinement |
| **U-9** | **The 25-domain-per-unlock cap, audit entries, and toasts** (CONF-7) | Quantitative. Tamarin cannot count, so these are argued and tested, not proved |
| **U-10** | **ORAM beyond the abstract transcript** | M22 covers one tree, two rounds, and read/write-agnostic accesses. Stash overflow, timing, and the `/vault/events` side channel are outside it. Stash bounds are statistical (M24). Leaf uniformity is assumed |
| **U-11** | **Composition** | M26 is an abstract re-statement of three subsystems around one epoch token, bounded by fuel. It is not a composition of the actual M18, M19, and M20 theories. There is no general composition theorem |
| **U-12** | **One-off share links, audit log, breach monitoring, importers, autofill, passkey provider integration** | Tests and audit only |
| **U-14** | **First-contact sender authenticity and persistent share state** | Signed v2 envelopes and M19c establish provenance relative to an honest pinned key, with key-reveal exceptions. A malicious server can supply its own key at first contact (TOFU); account-to-key authenticity needs independent confirmation. Recipient key-directory substitution, crash/concurrent pin persistence and mobile native glue remain unproved. Legacy unsigned item capsules are rejected. |
| **U-15** | **Mixed-version deployment and migration** | Current signed item envelopes and KEM blobs use explicit v2 formats. Old unsigned item capsules are rejected; no seamless migration or mixed-client interoperability theorem is provided. Legacy trusted-contact handling is a separate scoped path in `recovery.rs`. |
| **U-16** | **Closed: challenges are bound to one purpose** | `/auth/challenge?purpose=` (`login`, `enroll` or `web_token`; default `login`) stores the purpose with the nonce; `/auth/verify`, `/device/enroll` and `/web-session/:id/token` accept only their own purpose, and a wrong-endpoint presentation spends the nonce. Desktop enrollment and the web vault request their purposes. Covered by the bounded model, a 16-way race test and mutation checks ([evidence](proof-logs/current/challenge-single-use/README.md)). Deployed clients older than this change that enroll via `/device/enroll` or mint web tokens must be updated. |
| **U-17** | **Closed: account deletion is one transaction** | All SQL deletions in `DELETE /account` commit together; a database error part-way rolls them back (fault-injection test `failed_account_deletion_rolls_back_every_table`). Store-side token revocations run first and stay in place on rollback (they only lock out). A process crash relies on SQLite/Turso transaction atomicity; backups and replicas are not covered. |
| **U-18** | **Closed: revocation cascades to approved web sessions** | Revoking a device now revokes the web sessions it approved, and a grant requires the approving device to be unrevoked, so a stolen device's browser session ends with the device (regression test `revoking_a_device_revokes_the_web_sessions_it_approved`). Still open: revoking the account's last device is allowed, and the cascade is tested, not proved. |
| **U-19** | **Closed: an ambiguous device insert no longer re-arms pairing** | `POST /device/enrollment-grant/:id/complete` used to restore the consumed grant and claim when the guarded device `INSERT` returned an error. An error does not prove the row was not written, so a retry could enroll a second device from one ceremony. The extracted pairing driver now treats an insert error as terminal and restores only after a definite zero-row insert (rotation); regression test `an_ambiguous_insert_error_consumes_the_ceremony`, per-request lemma in the pairing driver proof. |
| **U-20** | **Closed: a lost pairing result is recovered from the device row** | If the result write failed after the device row committed, the new device never learned its `device_id`: `/result` reported not-found because the claim was consumed. The enrolled row now records `enrollment_grant_id` (unique), and when both the result and the claim are gone `/result` reads that row back and answers only under the same result-signature check, by the key the device claimed with. Proved in the pairing driver (`enrolled_device_return_requires_proof`, `enrolled_device_absent_is_not_enrolled`) and the pairing composition; tests cover a lost result, a wrong signing key (401) and a consumed claim with no row (404). |
| **U-21** | **Closed: a failed registration left an account without a device** | `POST /account/register` inserted the `users` and `devices` rows with two independent statements, so a device-insert failure left a device-less account behind. Both now run in one transaction that rolls back on any failure; regression test `failed_registration_rolls_back_the_account`, ordering and rollback proved in the registration driver. |
| **U-22** | **Closed: a challenge issue could replace a live challenge** | `GET /auth/challenge` stored the nonce with an unconditional set, so a nonce collision would silently replace another live challenge and its purpose. It now uses set-if-absent and fails closed on collision. Proved in the challenge-issue driver (`f_stored_fresh` is required for issue) and the challenge composition; the store's set-if-absent atomicity is assumed. |
| **U-23** | **Closed: a revoked linked share stayed fetchable from the inbox** | Revoking a linked share sets `revoked = 1` and then deletes the recipient's inbox copy in a separate cleanup step whose failure is ignored. `GET /share/inbox` read `share_inbox` without checking `shared_items`, so a failed or interrupted cleanup left the revoked capsule fetchable. The inbox now skips any item whose linked share is revoked; regression test `a_revoked_share_leaves_the_inbox_even_if_cleanup_never_ran`. Found by the cancellation analysis. |
| **U-24** | **Closed: a lost recovery redemption reply is recovered from the device row** | `POST /recovery/enroll-device` consumes the grant and commits the device row before answering, so a dropped connection left the client without its `device_id` and a retry failed on the consumed grant. The recovered-device row now records `recovery_grant_id` (unique), and a request whose preflight finds no live grant runs a `Replay` ceremony whose only effect is a non-consuming lookup of the row that exact grant created. It answers `200` with that row's `device_id` only when the stored key material equals the request's `hybrid_ek`/`hybrid_vk`; a different key, a missing row and every other preflight rejection keep the historical status and message (`401 "recovery grant expired or already used"`). A replay never consumes, inserts or restores anything, and the unique grant index refuses a second device per grant. Proved in the redemption driver (`replay_never_inserts`, `replay_complete_only_from_a_matching_row`, `replay_refusal_is_grant_unavailable`, included in the per-request and concurrent theorems), the fetch-model lemma `replay_finds_the_inserted_device` and its different-key counterpart, and the replay request in the redemption composition; regression test `enroll_device_recovers_the_device_after_a_lost_reply` (a retry after the first reply is discarded returns the same id, a different key is refused, one row total), plus the replay conformance test against turso/sled. |
| **U-25** | **Closed: one web-session grant could mint many tokens** | `POST /web-session/:id/token` minted a fresh token for every valid proof made with a new `web_token` challenge, so whoever held the browser's signing key could keep minting tokens for one approval. The handler now takes a first-writer claim on `web_session:token_issued:<id>` (kept for the longest session lifetime) before signing, and a second request gets 409; regression test `web_session_issues_at_most_one_token_per_grant`, proved per request in the web-session driver. If the token reply is lost, the user starts a new web session. |
| **U-26** | **Closed: a token could be released after its web session was locked out** | A `POST /web-session/:id/token` request that had already read the granted row could still return a token after a concurrent `DELETE /web-session/:id` or approver-device revocation wrote the session's lockout sentinel. The token effect now re-checks `device:revoked:<session_id>` at issue and fails closed, including on a storage error; regression test `web_session_token_is_not_issued_after_its_lockout`. Found by the web-session composition, which assumes this re-check. |
| **U-27** | **Partly closed: the web client still trusts the first epoch the server reports** | `webVELA` now downloads every chunk through the wasm export `decrypt_admitted_vault_chunk_json` (`libVELA/vela-wasm-bridge/src/lib.rs:339`, export `:499`; `webVELA/src/main.ts:483`), which refuses unsealed legacy blobs, requires the manifest epoch to equal the first epoch this tab admitted (`plan_sync_epoch_match`), refuses a lower per-chunk revision (`plan_chunk_download`) from tab-local state, and returns plaintext only after a real AAD-bound open; the unguarded `decrypt_vault_chunk_json` export is removed, and `webVELA/src/api.ts:158-166` pins the manifest epoch for reads and uploads. Residual: no client-authenticated epoch exists — the rw grant envelope carries only chunk keys (`EPHEMERAL_WEB_ACCESS_DESIGN.md:443-447`, `FeatureRepositories.kt:295`, `AccountViewModel.swift:303`), the approver sends `key_epoch` only to the server (`web_session/mod.rs:652`), and the capsule is sealed to an ephemeral public key the server itself relays, so the browser cannot distinguish an approver capsule from a server-made one. A fresh tab therefore trusts the first manifest epoch and a malicious server can still serve a pre-rotation epoch-1 **sealed** blob (bound to chunk id and revision, not epoch) as first contact; the floor and per-chunk clocks are memory-only, so every reload is a new first contact. A mid-session epoch change fails closed (reload and re-approve). Evidence: [web-download-admission](proof-logs/current/web-download-admission/README.md). |
| **U-28** | **Closed: desktop no longer admits unbound legacy chunks at epoch 1** | Every production writer seals through `seal_fleet_chunk` (desktop, Android, Apple, web), and the desktop download path now opens through the shared `vela_crypto::rekey::open_sealed_fleet_chunk`: it refuses a blob without the `VAE1` header before the AEAD open and only then verifies the chunk id/revision AAD. Android, Apple and desktop call that one gate. The unsealed shape remains readable only on the explicit migration paths (`open_fleet_chunk`/`open_epoch_chunk`: re-key rotation re-seal, enrollment import, desktop-only audit log). Regression tests `a_legacy_unsealed_chunk_is_refused_on_download` and `a_legacy_chunk_relabelled_to_a_newer_revision_is_refused` fail against the pre-fix open. N1, F2. |
| **U-29** | **Closed: the desktop rollback gate consumes observed facts** | `reject_rollback` no longer passes constants: the download path opens the sealed chunk first, derives `aad_binding_verified` from that open's success and `key_epoch_positive` from the real epoch, then runs `plan_chunk_download` before any plaintext merge or baseline write. A failed open or a zero/negative epoch is a false fact and the kernel rejects it; the rollback error text is unchanged. Test `download_gate_receives_false_facts_when_the_open_fails_or_the_epoch_is_zero` fails against the pre-fix literals; `a_server_serving_an_older_revision_is_refused` covers the unchanged refusal. N1, F3. |
| **U-13** | **Availability and liveness** | Only `exists-trace` reachability witnesses. No progress guarantees under an adversarial scheduler or a malicious server |

The [formalization obligation ledger](08-formalization-status.md) records the
remaining work across all six requested areas. New sharing contracts and M28
reduce selected gaps; the computational model proofs above do not establish a
full-system theorem.

Tamarin checks the M28 all-pairs pin/generation results for rules
instrumented with linear `Chain` ghost state. The F★
[source bridge](../formal/share-journal-correspondence.md#ghost-state-correspondence-and-source-bridge)
proves that the original and instrumented rule sets have the same traces, and
that every slot embeds into the single-slot encodings. It also proves all ten
M28 lemmas on those traces. The limit is that the bridge's source semantics is
an F★ transcription of Tamarin's semantics, trusted rather than derived from
Tamarin. Only the rule text is drift-checked against the `.spthy`.
Rust/filesystem refinement of M28 is not machine-checked.

New login/revocation refinements retain two explicit limits: a request already
past the durable lookup can finish after revocation, and token renewal still
happens before other handlers finish. Logout/schema/revoke suppress renewal;
other error paths can lose a replacement header and require re-authentication.
A successful login response is not a proof of atomic issuance/revocation.

## Trusted components

| ID | Component | What we assume |
|---|---|---|
| **T-1** | Cryptographic primitives and crates: `ml-kem`, `fips204`, `x25519-dalek`, `ed25519-dalek`, `chacha20poly1305`, `blake3`, `hkdf`, `argon2`, `pasetors`, `webauthn-rs` | Correct and secure as specified. This package supplies no machine-checked implementation proof for these pinned dependencies; upstream assurance has not been established by this review |
| **T-2** | **Server state enforcement** | Lifecycle properties (single grant, epoch guards, revocation) hold only if the server runs the shipped code. A malicious server can break authorization and availability properties by design. The goal is that it still cannot break confidentiality (U-1) |
| **T-3** | Storage atomicity: Turso/SQLite transactions and sled atomic operations | Linear facts in the models assume these really are atomic. Race tests give evidence, not proof |
| **T-4** | Hardware keystores and OS user-presence APIs (TPM, Secure Enclave, StrongBox, Windows Hello, LocalAuthentication) | Keys do not leave, and presence checks are real (see audit D-3 and D-5, where both assumptions were initially false) |
| **T-5** | OS process isolation and kernel peer credentials for IPC | `ipc_peer`/`ipc_gate` answers are truthful. Same-UID code other than a browser-spawned host cannot impersonate one |
| **T-6** | Client RNG (`OsRng`, `getrandom`) | Fresh values are uniform. M22 and every `Fr(…)` depend on this |
| **T-7** | TLS 1.3 and Web PKI | Needed for availability and metadata protection. Confidentiality claims are designed not to depend on it |
| **T-8** | Cloud providers (iCloud, Google Drive) | Durable (M16, M17). Not trusted for secrecy |
| **T-9** | Verification toolchain: Tamarin, Maude, ProVerif, CryptoVerif/default.ocvl, hax, F\*, Z3, and hax's `core_models` | Sound. hax is research-grade. The prior 18 local PartialEq assumptions are removed; imported models and the defined String/Vec models remain trusted ([§3.2](03-implementation-correspondence.md#trusted-in-the-f-layer)) |
| **T-10** | Specification predicates in the policy crates | They express the intended property. F\* proves code = spec, not spec = intent |
| **T-11** | Build and distribution pipeline: GitHub Actions, release signing, app stores, extension stores | Out of the assurance scope. No reproducible-build attestation |

## Attacks outside the models

| ID | Attack class | Notes |
|---|---|---|
| **O-1** | Malware, keyloggers, memory scraping, or debuggers on an unlocked client | SPEC §9 non-goal. The audit D-4 residual (same-UID theft of named domains during an unlock) is accepted and bounded |
| **O-2** | Side channels: timing, cache, power, EM on client crypto; the server observing timing and volume | Non-goal. No timing audit yet. The `ml-dsa` crate was avoided because of RUSTSEC-2025-0144 |
| **O-3** | Coercion; social engineering of the trusted contact or of a fingerprint comparison | Non-goal |
| **O-4** | A malicious server denying service, dropping writes, or forking views between devices | Rollback is partly covered (INT-1). Fork consistency across devices is **not** claimed |
| **O-5** | Supply-chain compromise of dependencies, toolchains, or vendored `gpui-ce` | `cargo audit` and `cargo deny` only |
| **O-6** | Implementation bugs outside the policy crates: parsing, serialization, FFI memory safety (see C-4), UI confusion, autofill origin mapping (see A-2) | The share byte-frame parser has scoped refinement evidence; other parsing, serialization, UI and FFI paths remain unproved. Fuzzing exists for some parsers (`.github/workflows/fuzz.yml`) |
| **O-7** | Compromise of a browser that has been granted a web session | Bounded by AUTH-6 and COMP-6, but chunk keys already copied stay valid until rotation (audit D-2 residual) |
| **O-8** | Quantum-adversary and quantum-random-oracle composition | The computational games model ordinary oracle queries and the stated leaked-key cases. No QROM or complete quantum-adversary theorem for the concrete hybrid is supplied (COMP-5) |
| **O-9** | The WASM fallback with a PIN when no desktop app is present | Explicitly weaker (SPEC §7.4) |

## Gaps in the assurance itself

These are problems with the evidence, not with the protocol. We are fixing
them. Each is an easy place for a reviewer to find an over-claim.

| ID | Gap | Impact | Planned fix |
|---|---|---|---|
| **G-1** | **Hosted baseline passed on c8a377d:** the 249-contract base inventory plus separately scoped driver/composition proofs and mobile conformance tests; all fifteen PR checks passed | Conditional proofs and green CI do not establish whole-handler/client correctness; the new login/durable-admission increment needs its own evidence | [Security workflow](https://github.com/lucannez64/VELA/actions/runs/40154658518) and [current ledger](08-formalization-status.md); older snapshots keep their original provenance |
| **G-2** | **Closed: credential-release theories run in CI** | CONF-6/7/8, AUTH-9 and COMP-7 are now CI-witnessed | `run-all.sh` passed in the [368bcc0 hosted workflow](proof-logs/current/hosted-368bcc0/README.md): 83 verified plus exactly the five named intended falsifications |
| **G-3** | **Partly pinned environment** | Historical CI used unsupported Maude 3.2 and unpinned ProVerif | Current proof gates pin Tamarin 1.12.0, Maude 3.5.1, ProVerif 2.05, CryptoVerif 2.12, hax/F*/Z3 and Rust 1.99.1; every workflow action is pinned to a commit SHA, the scanners to exact versions (cargo-audit, cargo-deny, cargo-fuzz, semgrep), the hax engine's OCaml resolution to a committed opam lock, and hosted proof jobs to the digest-pinned proof image (§4.2). Ubuntu packages on hosted proof/security jobs come from one immutable `snapshot.ubuntu.com` date and every proof/security runner image is fixed. Remaining non-hermetic inputs are the rustup installer script, opam package metadata at install time, and the build box's local toolchain; see [env-pins](proof-logs/current/env-pins/README.md) |
| **G-4** | **Historical documentation drift** | The original package predated the new protocols | This update removes the unsupported GL20 citation and the claimed reduction, records current counts and preserves old CI results as historical evidence |
| **G-5** | **Model ↔ policy correspondence remains manual** | Matching hashes do not establish semantic equivalence | A per-rule table and source/model drift gate now cover the new enrollment/share/login boundaries; other families and mobile call sites remain manual |
| **G-6** | **No independent review.** `SECURITY_AUDIT.md` and `SECURITY_REDTEAM.md` were done by the project on its own code. iOS was outside the audit scope. No third party has reviewed the models or proofs | Self-assessment bias | This package and [§6](06-engaging-researchers.md) |
| **G-7** | **Private reporting enabled as checked 2026-10-23** | GitHub is the only published private contact; no independent email/PGP fallback is supplied | GitHub API returned `enabled: true`; maintainers should provide a fallback address they control |

## Remediated implementation findings

The [boundary review](07-boundary-review.md) reproduced three sharing
caller/storage failures at the baseline. The desktop now rejects repeated
acceptance, serializes store changes with generation checks, and journals pins
with pending content before vault writes. Regression tests cover the fixes;
filesystem correctness and concurrent independent processes are not proved.
These implementation tests do not turn the pure-policy proofs into an
end-to-end sharing theorem.

## Accepted residual risks (from the audits)

- **D-2:** chunk keys granted to an RW web session stay valid until the next
  rotation.
- **D-4:** same-UID code during an unlock can obtain credentials for domains
  it names. This is bounded by the 25-domain cap, an audit entry, and a toast.
- **C-1/P-1:** key material briefly exists as a string during enrollment-code
  import (superseded by enrollment v3, which uses device-generated keys).
- **RT lower-severity items:** device-ID existence oracle via distinct 401
  messages, web-session metadata in `/devices`, `MAX_ACCOUNTS` and quota
  TOCTOU, and unvalidated `TRUSTED_PROXY_CIDRS` breadth (SECURITY_REDTEAM.md
  summary). Check the current code for their status before you report them
  again.
