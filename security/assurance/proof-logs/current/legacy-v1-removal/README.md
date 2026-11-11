# Removal of the legacy v1 trusted-contact envelope path (C17)

Step C17 of `security/assurance/20-formalization-plan.md`. Base commit
`69be7cb`. Maintainer decision recorded in
`security/assurance/09-target-contract.md` under "Scope decisions"
(2026-11-04): the legacy v1 KEM decapsulation path used for old
trusted-contact envelopes is removed; envelopes in that format stop opening
and their owners must re-share. The separate v1 possession-commitment check is
not part of this decision and is reported below.

Files changed:

- `libVELA/vela-crypto/src/kem.rs`
- `libVELA/vela-crypto/src/recovery.rs`
- `security/formal/cryptoverif/README.md`
- this README

## Callers found before the change

The v1 envelope path was reachable through exactly one production caller.

- `libVELA/vela-crypto/src/kem.rs:178` `decapsulate_legacy_v1`, and its
  test-only producer `encapsulate_legacy_v1` at `:187`, plus the private
  `combine_v1` helper.
- `libVELA/vela-crypto/src/recovery.rs:229-239` `open_for_recipient`: the only
  production caller. The first envelope byte selected the combiner; version 2
  used `kem::decapsulate`, and version 1 was accepted **only** for the
  `CONTACT_DELIVERY_DOMAIN` delivery direction. Version 1 in the response
  direction already failed as unsupported.
- `libVELA/vela-apple-bridge/src/lib.rs:683-686` and `:1383-1409`
  `vela_ffi_open_contact_share_json` -> `open_contact_share_json`, which calls
  either `open_contact_share` (delivery) or `open_contact_share_response`.
  FFI errors become `{"error": "<message>"}` (`json_result`/`error_json` at
  `:1544-1560`) and `iosVELA/Shared/VelaCoreFFI.swift` maps that to an
  `NSError` (lines 13 and 24).
- `desktopVELA/vela-desktop-core/src/recovery.rs:1282-1284` calls
  `open_contact_share_response` (recovery-response direction only, which was
  already always v2) and wraps failures as
  `"The trusted-contact response could not be authenticated: {e}"`.
- No call into this path exists in `androidVELA`, `iosVELA` app code, or
  `webVELA`. Android's `FeatureRepositories.kt:341` admits only signed share
  envelopes through a different (`identityAdmitShare`) path. iOS stores
  Share 3 as raw text (`AccountViewModel.swift:401-455, 560-563`); the Apple
  bridge export is present but the iOS app does not call it.

## What changed

- `kem.rs`: deleted `decapsulate_legacy_v1`, `encapsulate_legacy_v1`, the
  private `combine_v1` helper, the `HKDF_SALT_V1` constant, the "Combiner v1
  (legacy)" module section, and the `v1_and_v2_combiners_disagree` test.
- `recovery.rs` `open_for_recipient` (`:220`): the envelope version byte is
  still the explicit format marker. Version 2 (`CONTACT_ENVELOPE_VERSION`)
  decapsulates with v2. A version byte of 1
  (`CONTACT_ENVELOPE_VERSION_LEGACY_KEM`, `:144`) is now refused **before**
  the capsule or ciphertext is touched, with the single distinct error
  `LEGACY_V1_ENVELOPE_RETIRED` (`:147`):
  `this trusted-contact share uses the retired v1 format; ask the contact to share again`.
  Any other version still returns `unsupported contact envelope version {n}`.
  The refusal applies to both delivery and response directions.
- Replaced the old `legacy_kem_envelopes_open_only_as_held_deliveries` test
  with `v1_envelopes_are_refused_and_v2_still_opens`
  (`recovery.rs:785-830`). It checks that a v2 envelope still opens and is
  written with version 2, that relabelling a valid v2 delivery or response
  envelope to version 1 produces exactly the retired-format error, and that
  version 3 is still reported as unsupported.
- `security/formal/cryptoverif/README.md`: the "Legacy handling remains
  separate" bullet now says the v1 envelope path is removed from the code and
  that the v1 possession commitment is the only remaining legacy path.
  `kem_v1_x25519_baseline.ocv` is kept unchanged as the documented
  unproved-query negative control.

## User-visible behavior

Any client that tries to open a v1 delivery envelope now gets the one message
above instead of a share. Through the Apple bridge it arrives as a JSON
`error` field (then an `NSError` on iOS). On desktop, the response opener adds
its existing prefix, so a v1 byte in that position reads as
`The trusted-contact response could not be authenticated: Invalid parameter: this trusted-contact share uses the retired v1 format; ask the contact to share again`.
No code path retries or falls back to the old combiner.

## Tests

Run through `vela-heavy` from `libVELA/vela-crypto` with
`CARGO_TARGET_DIR=<worktree>/target-c17` and `VELA_STEP_TIMEOUT=3600`:

```text
cargo test
  unittests:            130 passed; 0 failed
  oram_stash_bounds:      4 passed; 0 failed
  doc-tests:              2 passed; 0 failed
cargo test v1_envelopes_are_refused_and_v2_still_opens -- --nocapture
  recovery::tests::v1_envelopes_are_refused_and_v2_still_opens ... ok
```

`vela-crypto` was the only crate whose code changed, so no other crate test was
run. The Apple bridge and desktop code were read but not modified.

## Possession-commitment report (out of scope, kept)

- The v1 possession commitment is the 32-byte branch of
  `rms_possession_verify_ex` in `libVELA/vela-crypto/src/recovery.rs:494-523`,
  gated by `allow_legacy_v1` (`:501`). `rms_possession_verify` (`:481-490`)
  calls it with `true`, so its callers keep accepting v1 commitments.
- Production use: `serverVELA/vela-server/src/recovery/possess.rs:98-116`
  `verify_possession_proof` passes `state.config.allow_legacy_possession_v1`
  (`:321`), which is `true` unless `VELA_ALLOW_LEGACY_POSSESSION_V1_OFF` is set
  (`config.rs:205`; field at `:46`).
- Test use: `recovery.rs:934-964` `legacy_v1_possession_still_verifies`, plus
  v2 possession tests; the Apple bridge tests call the default
  `rms_possession_verify` (`vela-apple-bridge/src/lib.rs:2352-2367`).
- It is still needed as long as any account has a 32-byte commitment staged
  mid-recovery; the server's default gate is the migration switch. Closing it
  is a separate operational decision (flip the env flag once all staged
  commitments are v2), not part of C17.

## Unverified / follow-ups

- Not verified: whether any deployed client still holds a v1 delivery envelope
  and exercises the Apple bridge error path end to end; the refusal is covered
  at the `vela-crypto` boundary only.
- Not verified: client UI rendering of the new message; no UI test was run.
- `docs/vela-atlas.html:366` still describes the v1 combiner as the built
  construction. That documentation drift was outside this step's file scope
  and is left for a follow-up.
