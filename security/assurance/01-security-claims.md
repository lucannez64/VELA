# 1. Security claims

This document lists what VELA claims, with stable IDs you can cite in
reports. Each claim names its evidence (see the tags in
[README](README.md#evidence-levels)) and the model or test that backs it.
A claim with only **[ARG]** has no machine-checked support. Treat it as an
open target.

The normative design text is [`SPEC.md`](../../SPEC.md). If this document and
the SPEC disagree, report it. We will treat the gap as a bug in one of them.

## 1.0 System and parties

| Party | Role | Trust in the claims below |
|---|---|---|
| Client device (desktop, Android, iOS) | Holds the Root Master Seed (RMS), device identity keys, and vault plaintext while unlocked | Trusted while uncompromised |
| Hardware keystore (TPM, Secure Enclave, StrongBox/Keystore) | Wraps the RMS at rest, gated by user presence | Trusted |
| VELA server | Relays and stores ciphertext; verifies signatures; enforces lifecycle state | **Untrusted for confidentiality.** Trusted for availability and for enforcing authorization state unless a claim says otherwise |
| Cloud provider (iCloud, Google Drive) | Stores recovery Share 1 | Untrusted (adversary-readable and replayable) |
| Trusted contact | Holds a recipient-bound sealed Share 3 | Trusted not to collude with a second share holder |
| Browser extension and web vault | Requests individual credentials; temporary web sessions | Untrusted environment |
| Network | Carries all traffic over TLS 1.3 | Untrusted (Dolev-Yao) |

**Assets:** the RMS; vault plaintext; device identity private keys (hybrid
ML-DSA-87 + Ed25519); share decapsulation keys; passkey private keys stored
as vault items; recovery shares; session and enrollment capabilities.

**Primitives** (SPEC §3): hybrid ML-KEM-1024 + X25519 combined with
HKDF-SHA256; hybrid ML-DSA-87 + Ed25519 signatures (both must verify);
XChaCha20-Poly1305; BLAKE3 `derive_key` with registered context strings;
Shamir 2-of-3 over GF(2^8) with authenticated shares; Path ORAM; PASETO v4
public tokens; WebAuthn for recovery; Argon2id for local passwords and link
passphrases.

## 1.1 Confidentiality

| ID | Claim | Adversary | Evidence |
|---|---|---|---|
| **CONF-1** | The server never learns the RMS, vault plaintext, device identity private keys, or share decapsulation keys. | Malicious server, network | **[ARG]**. Architectural: no protocol message carries these in the clear. No end-to-end secrecy theory covers the full system (see [§5 U-1](05-known-limitations.md#unproved-properties)) |
| **CONF-2** | Vault chunks are confidential and bound to their chunk id, Lamport clock, and key epoch, so a server cannot decrypt or silently substitute them. | Malicious server | **[ARG]** for AEAD confidentiality; **[EXEC]** for the cross-client epoch/AAD wire matrix (`rekey::tests::fleet_wire_matrix_…`) |
| **CONF-3** | The server cannot tell which logical chunk a client accesses, including repeated accesses to the same chunk, in trivial mode (≤4 chunks) and in Path ORAM mode. | Honest-but-curious server observing access transcripts | **[SYM]** M22b/M22c (ProVerif observational equivalence). M22a shows that the old static-position design leaks. **[STAT]** M24 stash bounds |
| **CONF-4** | The server cannot learn item count or item types beyond the padded chunk count. | Honest-but-curious server | **[ARG]**. 1 MB padding (SPEC §5.2) |
| **CONF-5** | A shared item is readable only by the holder of the recipient's registered share decapsulation key. | Malicious server with database write access, stolen web-session token | **[SYM]** M19b (binding integrity; capsule contents opaque by assumption, see [§2](02-formal-models.md)); M19a demonstrates the pre-fix substitution attack; **[REF]** `vela-share-policy`; **[EXPLOIT]** RT-5. Sender authenticity is not claimed ([U-14](05-known-limitations.md#unproved-properties)) |
| **CONF-6** | A passkey private key stored in the vault never leaves the core: not to the browser, the page, or over IPC. Only per-assertion signatures for an exactly matching RP ID leave. | Co-resident same-UID process, compromised browser | **[SYM-local]** M7, M8, M10 (`credential_never_leaks`) |
| **CONF-7** | A legacy (password) credential is released only for an origin a human approved, bound to the (client, origin, item) triple, at most once per grant. One unlock releases at most 25 distinct domains, and each release is audited. | Co-resident same-UID process without a browser-spawned host | **[SYM-local]** M6, M8, M10 (agreement and injectivity; the 25-domain cap is argued, not modelled) |
| **CONF-8** | For plain-form sites, in-core login keeps the credential out of the browser domain entirely. | Adversary controlling the browser domain | **[SYM-local]** M9a; M9b and M9c are falsified baselines for rejected designs |
| **CONF-9** | A single recovery share, or two shares from different accounts, epochs, or splits, reveals nothing usable and cannot reconstruct an RMS. | Cloud provider, server, or contact acting alone | **[ARG]** for Shamir information-theoretic secrecy; **[SYM]** M15, M18 for pair-binding |
| **CONF-10** | One-off share links: the server stores only ciphertext. The key travels in the URL fragment, and an optional Argon2id passphrase is mixed in. | Malicious server | **[ARG]** |
| **CONF-11** | The device audit log is end-to-end encrypted under an RMS-derived key. | Malicious server | **[ARG]** |
| **CONF-12** | A read-write web session receives per-chunk vault keys, never the RMS. | Compromised browser after an approved RW grant | **[ARG]**. Audit fix D-2. Residual risk: copied chunk keys stay valid until the next rotation (COMP-2) |

## 1.2 Authentication and authorization

| ID | Claim | Evidence |
|---|---|---|
| **AUTH-1** | A device authenticates only by signing a fresh, single-use, 60-second server challenge under the transcript `vela auth challenge v1 ‖ device_id ‖ challenge`. Both ML-DSA-87 and Ed25519 must verify. | **[ARG]** plus unit tests. Not modelled symbolically ([§5 U-2](05-known-limitations.md#unproved-properties)) |
| **AUTH-2** | Permanent-device enrollment (v3): a grant is bound to its opener; the first claimant fixes the joining keys; the opener inspects and signs exactly those keys; completion yields exactly one device per grant; revocation, expiry, or epoch commit invalidates the grant. | **[SYM]** M13 (16 lemmas, **ordering-only**: no network adversary); **[REF]** `vela-enrollment-policy`; **[EXEC]** `enrollment_ceremony_model`; **[EXPLOIT]** P-1 |
| **AUTH-3** | Recovery: Share 2 is released only after a WebAuthn assertion with user verification, bound to user, attempt, credential, and epoch. Each recovery mints one single-use enrollment grant that enrolls at most one device. | **[SYM]** M14 (18), M18; **[REF]** `vela-recovery-policy`; **[EXEC]** `recovery_lifecycle_model`; **[EXPLOIT]** S-3/RT-1 |
| **AUTH-4** | Recovery by possession proof (no WebAuthn) issues a grant only after two shares were reconstructed and the possession commitment matches. It never releases Share 2. | **[SYM]** M18 `possession_grant_requires_full_pair_adoption`, M26a; **[REF]** `vela-recovery-policy` |
| **AUTH-5** | Web sessions: a grant is bound to the approving account, nonce, mode, epoch, and hard cap. RW tokens require a browser-key proof. RO grants never yield tokens. Renewal preserves scope, epoch, and cap. No use happens after revocation or expiry. | **[SYM]** M12 (14); **[REF]** `vela-session-policy`; **[EXEC]** `session_capability_model`; **[EXPLOIT]** S-1, S-2, S-4, RT-2 |
| **AUTH-6** | A web-session token reaches vault routes only. It can never reach permanent-account routes (recovery, enrollment, share-key registration, account deletion, web-session grant). | **[SYM]** M20 (7); **[REF]** `authorize_route`; **[EXPLOIT]** RT-4, RT-5, RT-6 |
| **AUTH-7** | A share encapsulation key registers only under a binding signed by an enrolled, active, caller-owned device, with a strictly fresher `signed_at`. | **[SYM]** M19b (device-key theft not modelled); **[REF]** `plan_ek_registration`; **[EXPLOIT]** RT-5 |
| **AUTH-8** | Only the original sender can update or revoke a linked share. | **[SYM]** M21 `only_sender_can_revoke_link` |
| **AUTH-9** | The browser↔desktop IPC accepts only a same-UID, browser-spawned native host. Every request is signed by a client key paired through a human-compared fingerprint, and request nonces are honoured at most once (injective agreement). | **[SYM-local]** M6 (17); OS peer checks are **[ARG]** |

## 1.3 Integrity, consistency, and freshness

| ID | Claim | Evidence |
|---|---|---|
| **INT-1** | Rollback: a client admits a downloaded chunk only at the clock it already recorded, and adopts a new epoch only when it is exactly `local + 1` with a capsule bound to that transition. | **[SYM]** M23 (11; **bootstrap clock only**, see [§5](05-known-limitations.md)); **[REF]** `vela-sync-policy` (**desktop only**) |
| **INT-2** | A replayed share capsule cannot revert a newer edit, because the authenticated `updated_at` inside the capsule must be strictly newer. | **[ARG]** plus test `a_replayed_share_capsule_cannot_revert_a_newer_item`. The AEAD carries no AAD here, and capsules carry no sender authentication, so this covers replay only, not forgery ([U-14](05-known-limitations.md#unproved-properties)) |
| **INT-3** | Tampered or mixed Shamir shares fail to authenticate instead of producing a wrong RMS. | **[SYM]** M15, M18 (authentication abstracted as origin checks); **[ARG]** for the tag construction (audit C-3) |
| **INT-4** | Rekey capsules authenticate `{epoch, rotation_id, rms}`. A relabelled or stale capsule cannot be adopted. | **[SYM]** M11b (4) |
| **INT-5** | Epoch rotation commits only when every live chunk and every active device is represented at the target epoch. Commit, abort, and timeout are mutually exclusive. Commit advances exactly once. | **[SYM]** M11 (15); **[REF]** `vela-rekey-policy`; **[EXEC]** `rekey_state_model` (24 orderings, races) |
| **INT-6** | Recovery publication: setup reports ready only after the exact staged server share and the durable cloud candidate are finalized under one account, epoch, and split. Same-epoch races have a single winner. | **[SYM]** M16 (14); **[REF]**; **[EXEC]** integration test |
| **INT-7** | Crash consistency: a client can crash after any publication effect and resume the same split without mixing shares. A finalized publication cannot be abandoned. | **[SYM]** M17 (14); **[REF]** `vela-client-recovery-policy`; **[EXEC]** `bounded_refinement` |
| **INT-8** | Linked-share revocation is final: no read of a link happens after its revocation. | **[SYM]** M21 (3) |
| **INT-9** | Sync merge never resurrects a tombstoned item or overwrites a conflicted local edit. | **[REF]** `classify_merge_action` negative theorems (desktop only) |

## 1.4 Compromise resilience

| ID | Claim | Evidence |
|---|---|---|
| **COMP-1** | No single custodian (cloud, server, or contact) can recover the account. Any two distinct custodians can. | **[SYM]** M18 (safety and three availability witnesses) |
| **COMP-2** | Rotating the RMS (epoch N → N+1) bounds future damage. Old recovery shares (including copies held by contacts), outstanding web sessions and their chunk keys, possession grants, enrollment grants, and share-key update authority stop working for new data. | **[SYM]** M11c, M14, M18 `rotation_blocks_…`, M26 (`*_cannot_outlive_their_rotation`); **[REF]** `stale_permit_authorizes_successor` |
| **COMP-3** | Rotation does **not** provide retroactive secrecy. An attacker holding RMS_N and pre-rotation ciphertext keeps reading it. Device identity keys are not rotated. | Stated non-claim (`docs/VAULT_REKEYING_DESIGN.md` §3) |
| **COMP-4** | Compromise of the server **and** the cloud provider does not allow recovery by API without the user's WebAuthn credential or the trusted contact's cooperation. | **[SYM]** M14, M18 (server modelled as an enforcing party; see [§5 T-2](05-known-limitations.md#trusted-components)) |
| **COMP-5** | Hybrid KEM and signatures stay secure if either the post-quantum or the classical component holds. | **[ARG]** only. See open question [Q-1](06-engaging-researchers.md#priority-questions) on the KEM combiner |
| **COMP-6** | A stolen web-session token is bounded: 15-minute sliding lifetime, 8-hour cap (24-hour cap for web sessions), JTI revocation, and no permanent-account powers. | **[SYM]** M12, M20; **[EXPLOIT]** RT-4 to RT-6 |
| **COMP-7** | A compromised browser extension, or same-UID malware without a browser-spawned host, gets at most the credentials a human approves during an unlock (working-set bound). It never gets the vault key or passkey private keys. | **[SYM-local]** M3, M6–M10. M1 and M2 are falsified baselines showing that weaker designs leak everything |

## 1.5 Explicit non-claims

VELA does **not** claim the following. Reports about them are welcome, but
they are design limits, not bugs:

- Protection against client malware, keyloggers, memory scraping, or cold-boot
  attacks on an unlocked device (SPEC §9).
- Side-channel resistance of client cryptography. Shamir GF(2^8) is written in
  constant time and `fips204` is chosen for constant-time ML-DSA, but no
  timing audit has been done.
- Network-layer denial of service, or server availability against a
  malicious operator.
- Resistance to coercion.
- Retroactive secrecy after RMS compromise (COMP-3).
- Hiding of timing or traffic volume from the server, or of activity
  (`/vault/events` reveals that a write happened).
- The security of the software-only WASM fallback with a PIN (SPEC §7.4) at
  the level of the native clients.
