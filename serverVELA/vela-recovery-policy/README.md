# Verified account-recovery policy

This crate is the pure production policy for WebAuthn-gated recovery and
recovered-device enrollment. Tamarin M14 proves the lifecycle; hax extracts the
Rust decisions to F* and checks their postconditions for every input.

| Production decision | Universally checked property |
|---|---|
| `plan_initiation` | A fresh, expiring challenge starts only for an existing recovery-ready account with both share and credential. |
| `plan_registration` | Recovery-credential registration requires device scope, the same account, one consumed challenge, a valid credential, and cross-account uniqueness. |
| `plan_recovery` | Share release requires the exact user, attempt, current credential, one-shot challenge, verified WebAuthn assertion, user verification, active epoch, and stored share. |
| `plan_credential_update` | Authenticator metadata updates only after a valid assertion under the still-current credential. |
| `plan_enrollment` | A recovered device requires a consumed user-bound grant, current credential, valid keys, and exact active grant/account epoch. |
| `plan_publication_stage` | A server share is staged only for the current active account epoch with a nonempty share and split id. |
| `plan_publication_finalize` | First promotion requires an empty active slot plus the exact pending epoch, split id, and stored share; an exact already-active retry is handled idempotently by the server. |
| `plan_proof_initiation` (M18) | A possession-proof challenge is issued only when the share *and* its staged RMS commitment exist. |
| `plan_possession_recovery` (M18) | An enrollment grant issues only from a consumed, attempt-bound, cryptographically verified possession proof on an active matching epoch — and never releases the server share. |
| theorem helpers | Replaced credentials, challenge/grant replay, cross-user grants, rotated grants, competing splits, retired epochs, unproven possession claims, stale commitments, and commitment-less possession grants cannot authorize recovery authority. |

The proof boundary excludes WebAuthn cryptography, HTTP, clocks, SQL, sled, and
the cloud provider's durability guarantee.
Production binds serialized challenge state and enrollment grants to the
credential id, conditionally updates that credential, atomically redeems
one-shot artifacts, and guards device insertion by epoch and credential id
(possesson grants instead require the staged RMS commitment to still exist).

## Run

Use the pinned hax/F*/Z3 toolchain documented in
[`../vela-rekey-policy/README.md`](../vela-rekey-policy/README.md), then run:

```bash
export PATH="$(opam var bin --switch vela-hax):$(opam var bin --switch vela-fstar):$HOME/.local/bin:$PATH"
./verify-fstar.sh
```

The runner extracts twenty-one production/theorem entry points and asks F* to
discharge every verification condition without `--lax`.

Run the protocol model separately:

```bash
cd ../../security/formal
./run-recovery-proofs.sh
./run-recovery-publication-proofs.sh
./run-pair-selection-proofs.sh
```
