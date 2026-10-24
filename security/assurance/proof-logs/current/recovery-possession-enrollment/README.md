# Recovery possession/enrollment: local evidence

The delegated increment `49b0e0a`, integrated as `de28258`, added 29 contracts.
The parent then replaced the caller-supplied key-validity observation with two
actual decoded lengths. `fstar.log` and `Vela_recovery_policy.fst` record the
parent's fresh run of all 71 contracts (six unit tests, seven observation tests).
The exact artifact SHA-256 is
`209f0d4dd7ac06231390c5444679deec32ec1c36bad96a1c15bba6c9eacb1ef1`.
Generated bodies were not edited. Hosted reproduction is pending.

Pinned hax 0.3.7 / Rust nightly-2025-11-08 / F★ 2025.10.06 / Z3 4.13.3:

```bash
vela-heavy env CARGO_HOME=/tmp/vela-hax-cargo \
  OPAMROOT="$HOME/.local/opt/vela-tools/opam" \
  PATH="/tmp/vela-fstar-prebuilt/fstar/bin:$HOME/.local/opt/vela-tools/bin:$HOME/.local/opt/vela-tools/opam/vela-hax/bin:$PATH" \
  serverVELA/vela-recovery-policy/verify-fstar.sh
vela-heavy env CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-700776df/target \
  cargo test --manifest-path serverVELA/Cargo.toml -p vela-server --test integration
vela-heavy env CARGO_TARGET_DIR=/home/hirew/.t3/worktrees/VELA/t3-700776df/target \
  cargo test --manifest-path serverVELA/Cargo.toml -p vela-server --test integration \
  possession_initiation_rejects_an_empty_decoded_commitment
```

The two integration logs record the existing 60-test suite and the subsequently
added empty-commitment regression separately. All heavy commands were serialized
under the shared 3 GiB/no-swap/one-worker cap; existing dependencies were reused.
`delegated/` preserves the earlier proof artifact (SHA-256 `ae460bda…cb1f`) and
its test logs, before the parent length correction. Its tests include two
real-store insertion regressions and possession/recovery/enrollment filters.
Those are historical results for their own source snapshot.

See [the boundary](../../../15-recovery-possession-enrollment.md): observation
origins, store-key user binding, concrete side effects, exceptions and concurrent
traces remain open. This is internal evidence, not an external audit or a
whole-system proof.

`lifecycle-model-tests.log` records three passing bounded M14 checks. The
enrollment enumeration now includes the new `account_present` input as a
ninth independent boolean (512 masks), so its coverage tracks the tightened
policy. This is executable enumeration, not a proof of SQL/HTTP trace refinement.
