# Agent guide

The entrypoint for automated agents (Claude Code, Codex, opencode and
similar). It is an index: the files it names own the details.

## What VELA is

A local-first, zero-knowledge password vault. Vault data and root secrets
stay on client devices; the server stores encrypted blobs and verifies device
authentication. `README.md` has the layout, `SPEC.md` the protocol,
`ROADMAP.md` what stands between the tree and 1.0.

## Rules that are checked

These fail CI (`.github/workflows/security.yml`) and
`scripts/pre-push-checks.sh`. The check's message names the fix.

- Crate layers (`security/formal/check-crate-boundaries.py`): policy crates
  and `vela-core` are leaves, `vela-crypto` uses only client policy crates,
  nothing depends on a bridge, server and client crates do not mix, vault
  primitives (KEM, AEAD, KDF, signatures, Argon2) live in `vela-crypto`, and
  `unsafe` stays in the bridges, `vela-crypto` and `vela-server`.
- Bridges are thin: an export decodes, calls one reviewed core function and
  encodes (`security/formal/check-bridge-thinness.py`).
- Secret-bearing types erase on drop (`check-secret-erasure.py`).
- No proof escapes in F* (`check-no-proof-escapes.py`).
- Reviewed sources match their models (`check-correspondence.py`). A hash
  mismatch means re-review the mapping, never refresh the hash blindly.
- Every proof in `docs/feature-map.md` exists (`scripts/check-feature-map.py`).

Run all fast gates in a few seconds with `scripts/pre-push-checks.sh`;
`scripts/pre-push-checks.sh --install` runs them on every push.

## Rules that are not checked yet

- Policy crate sources and some manifests are hash-pinned by reviewed proofs
  (`security/formal/correspondence.json`, proof-log `source-hashes.txt`). Do
  not touch them for cosmetic reasons; a change there reruns proofs.
- After changing a file listed in `security/assurance/MANIFEST.sha256`,
  regenerate it with `security/assurance/make-manifest.sh` and check that
  the diff lists only your files.

## Verifying a change

- Rust: check only the crate you changed (`cargo check`/`cargo test
  --manifest-path <crate>/Cargo.toml`) while iterating. Proof runs (hax, F*,
  ProVerif, Tamarin, CryptoVerif) are heavy: see the `heavy-work` skill.
- Desktop behaviour: `docs/feature-map.md` names each feature (D1, D2, ...)
  and the screenshot or e2e test that proves it. Run the journeys with the
  `desktop-uitest` skill and look at the screenshots. A feature marked
  `none` has no automated proof; say so instead of claiming it works.
- Commands per platform: `README.md` "Verification Commands".
