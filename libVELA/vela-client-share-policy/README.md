# Client share admission policy

This crate decides whether a received signed envelope may be accepted as a
first contact or applied as an update. `vela-crypto::share_envelope::admit`
computes its facts after decryption, parsing, signature verification and
recipient binding. Accepted updates must match the pinned sender/account and
lineage, with a strictly greater revision. First contact is TOFU; this policy
does not authenticate an account-to-key association supplied by the server.

## Proof boundary

`plan_share_admission` has a `hax_lib::ensures` postcondition tying its result
to `admission_matches_spec`. Seven negative theorem functions target rejection
of unauthenticated, misaddressed, misattributed, foreign-signer, cross-lineage,
stale-revision and first-contact-restart cases. Proofs cover decisions for the
supplied facts, not the code computing facts or persisting pins.

The executable tests enumerate all Boolean combinations and representative
revision pairs including zero and u64 limits. They do not exhaust all u64
pairs and are not a substitute for discharging the F* postconditions.

The network model is
[`m19c_share_sender_authentication.spthy`](../../security/formal/m19c_share_sender_authentication.spthy).
It idealizes cryptography, allows any positive sender revision, and models
recipient pin updates atomically. See the
[correspondence table](../../security/formal/network-boundary-correspondence.md)
and the [assurance package](../../security/assurance/README.md) for current
verification status and key-compromise assumptions.

## Reproduction

```bash
cargo test --manifest-path libVELA/vela-client-share-policy/Cargo.toml
# From repo root, with hax 0.3.7 / nightly-2025-11-08,
# F* 2025.10.06, Z3 4.13.3 and jq on PATH:
security/assurance/bounded.sh libVELA/vela-client-share-policy/verify-fstar.sh
```

The runner extracts the nineteen selected entry points afresh and invokes F*
without `--lax`. It fails if a tool is missing, extraction fails, or checking
fails. A fresh local run passed all nineteen entry points; see the
[logs and checked extraction](../../security/assurance/proof-logs/current/refinement-5g/).
This proves the stated policy postconditions subject to the documented tool
and library assumptions.

The transaction/recovery extension verifies the acceptance precondition,
generation advance and replay decision now used by desktop sharing, plus seven
negative theorems. These additional postconditions do not cover the filesystem
or caller-supplied observations. See the
[formalization ledger](../../security/assurance/08-formalization-status.md).

The permitted revision getter is now checked as well. Policy equality uses
structural pattern matching, so the fresh extracted module needs no local
opaque derived PartialEq assumption.
