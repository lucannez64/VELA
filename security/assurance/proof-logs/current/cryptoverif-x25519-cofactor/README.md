# X25519 cofactor-8 and the `kem.rs` reject check (plan step C2, local evidence)

Local evidence for `security/formal/cryptoverif/kem_v2_x25519_cofactor_sha256.ocv`
and `security/formal/cryptoverif/x25519_cofactor_projection.ocv`. This is
local CryptoVerif 2.12 output, not hosted-CI evidence.

Base commit: `ba4785e` (`Keep into_opened_share_item provable after the C16
erasure change`).

## What `kem.rs` does with a received X25519 key

Code: `libVELA/vela-crypto/src/kem.rs`.

- **Encapsulation** (`encapsulate`, lines 129-154): the X25519 ephemeral
  secret is `EphemeralSecret::random_from_rng(OsRng)` (line 134); the
  ephemeral public key is derived at line 135; the recipient key comes from
  `HybridPublicKey::from_bytes` (lines 217-233), which copies the 32 X25519
  bytes into `X25519PublicKey::from(pk_arr)` (line 231) without validation.
  The DH result is computed at line 136 and rejected at lines 137-141 when
  `!x25519_ss.was_contributory()` with `InvalidParameter("recipient X25519
  key is a low-order point")`.
- **Decapsulation** (`decapsulate`, lines 157-169): the ML-KEM half is
  decapsulated first (line 158); the X25519 DH result is computed at line 159
  from `sk.x25519_sk.diffie_hellman(&capsule.x25519_epk)` and rejected at
  lines 160-162 when `!x25519_ss.was_contributory()` with
  `VelaError::KemError`. `HybridCapsule::from_bytes` (lines 337-356) likewise
  accepts any 32 X25519 bytes (line 351).
- **Uniform error**: `open_share` (lines 304-306) maps every decapsulation
  failure, including a low-order reject, to the same
  `VelaError::DecryptionFailed` (C15). The test at lines 468-482 checks that
  `X25519PublicKey::from([0u8; 32])` is rejected in both encapsulation and
  decapsulation; lines 498-535 check that a low-order ephemeral gives the same
  uniform error as the other failure causes.
- **Crate behaviour**: `libVELA/vela-crypto/Cargo.lock` pins
  `x25519-dalek` 2.0.1 (lines 1255-1258) and `curve25519-dalek` 4.1.3
  (lines 236-239).
  - `StaticSecret::diffie_hellman` / `EphemeralSecret::diffie_hellman` call
    `their_public.0.mul_clamped(secret)` (`x25519.rs:80-82`, `:143-145`,
    `:204-206`).
  - `mul_clamped` calls `clamp_integer` (`montgomery.rs:128-140`;
    `scalar.rs:1386-1391`): clear bits 0, 1 and 2 (so the scalar is a
    multiple of 8), clear bit 255 and set bit 254. For a random 32-byte
    secret the clamped value is `n = 2^254 + 8r` with `r ∈ [0, 2^251)`.
  - The received `PublicKey::from([u8; 32])` is just
    `PublicKey(MontgomeryPoint(bytes))`, with no curve-point or canonicality
    check (`x25519.rs:34-40`). Multiplication interprets the bytes with
    `FieldElement::from_bytes` (`montgomery.rs:163`), which ignores bit 255
    and reduces modulo `p = 2^255-19` in the field backend
    (`backend/serial/u64/field.rs:338-360`): non-canonical `u` encodings and
    the ignored high bit are accepted.
  - The crate does **not** reject low-order inputs. It returns the 32-byte
    shared secret; `was_contributory()` is `!shared_secret.is_identity()`
    (`x25519.rs:324-326`), i.e. the shared secret is not all zero.
    `SharedSecret` wraps a `MontgomeryPoint` (`x25519.rs:275`), whose identity
    is `u = 0`.
  - Because the clamped scalar is a multiple of 8, `[n]P` depends only on the
    prime-order component of `P`; the small-order component is killed. The
    returned secret is zero exactly when that prime-order component is the
    identity. Thus the `kem.rs` check rejects exactly the inputs in the
    small-order subgroup (curve order dividing 8, twist order dividing 4),
    including `u = 0`, `u = 1`, the order-8 `u` values, and any non-canonical
    `u + p`/high-bit aliases of them. Other off-curve/twist inputs are
    accepted: X25519 performs no curve-membership check.
  - For a clamped scalar divisible by the prime order `q` (a weak key), every
    input would give zero and be rejected. This cannot happen for the modelled
    set: clamped values are multiples of 8 in `[2^254, 2^255-8]`; a common
    multiple of 8 and `q` (or the twist order `q'`) is a multiple of `8q`
    (`8q'`), and both `8q` and `8q'` exceed `2^255-8`.

## Models

### `x25519_cofactor_projection.ocv` (exact bridge)

Uses CryptoVerif 2.12's shipped `DH_X25519` macro (`default.ocvl:3385-3394`,
based on `DH_subgroup_with_is_neutral` and `is_neutral_DH_proba_collision`;
justified in <https://hal.inria.fr/hal-02100345>, the WireGuard proof). The
macro fixes the cofactor `k = 8`: `G` is the full group, `Z` is the set of
private keys (multiples of 8), `subG = {X^8}` is the prime-order subgroup,
`pow_k(Y) = Y^8`, `exp_div_k(X,y) = X^(y/8)`, and `is_zero_G`/`is_zero_subG`
are the zero-`u`/neutral predicates.

The file proves the equivalence for `N` independent sessions (probability
**0**, exact)

```text
for every Y: G and x: Z,
  exp(Y, x)            = subGtoG(exp_div_k(pow_k(Y), x))
  is_zero_G(exp(Y,x))  = is_zero_G(subGtoG(pow_k(Y)))
```

The first equality is the `DH_subgroup` equation (`default.ocvl:2851`).
The second follows from `is_zero_G(subGtoG(e)) = is_zero_subG(e)` and
`is_zero_subG(exp_div_k(e,x)) = is_zero_subG(e)`
(`default.ocvl:2883-2889`). Machine-checked consequence: only the
prime-order projection `pow_k(Y)` enters the shared secret and the zero/reject
test; the small-order component is irrelevant.

### `kem_v2_x25519_cofactor_sha256.ocv` (IND-CCA2 game)

A point is modelled as `(eq, et)`: `eq ∈ G` is the prime-order projection and
`et ∈ T` the explicit small-order component. `T` has a distinguished identity
`t0`; honest recipient/challenge points are `(exp(g,x), t0)`. Exponents are
the same `[nonuniform]` clamped-style type as the existing nonuniform game.
Decapsulation takes arbitrary attacker-supplied `eq` and `et` and applies

```text
if is_neutral(exp(eq, x)) then reject else H(..., exp(eq, x), eq, et, pk, ...)
```

`is_neutral` is from `DH_basic_with_is_neutral`; its equation
`is_neutral(exp(eq,x)) = is_neutral(eq)` rewrites the code's zero-shared-secret
test to a test on the public projection. The proof log records this at
`kem_v2_x25519_cofactor_sha256.log:147` ("Replaced `is_neutral(exp(eq, x))`
with `is_neutral(eq)`"). A neutral `eq` (low-order/cofactor-only input) is
rejected. A public low-order point `low` with `is_neutral(low) = true` and a
non-identity small-order component `t1` is available to the adversary, so the
reject branch is reachable. The model's key-collision statement is the same
`exp(g,x) = Y` bound as `DH_proba_collision_minimal`, declared directly
because that macro would re-expand `DH_basic` (already expanded by
`DH_basic_with_is_neutral`); it is not weakened.

The reject branch is modelled as no oracle output. The real code returns the
uniform `DecryptionFailed` error; both are the same deterministic public event
for IND-CCA2, so this does not change the game.

## Machine-checked results

Main model (`kem_v2_x25519_cofactor_sha256.log`):

```text
RESULT Proved bit secrecy of b up to probability
  4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH)
  + (2 * Qd + 2 * qH) * PCollKey + 6 * PhashCt
RESULT time_1 = (1 + Qd) * time(mlpkgen) + time(mlencap_ct)
  + time(mlencap_ss) + (1 + Qd) * time(SHAct) + (1 + Qd) * time(SHAek)
  + Qd * time(mldecap) + time + 3 * time(exp)
All queries proved.
```

This is exactly the existing nonuniform SHA-256 bound. The reject check adds
no probability term. Substituting the HPKE/Curve25519 distribution constants
used in `security/formal/cryptoverif/README.md` (`pDistRerandom = 2^-125`,
`PCollKey = 2^-250`) gives

```text
4·2^-125 + 2·pGDH(t, 2·qH) + (2·Qd + 2·qH)·2^-250 + 6·PhashCt.
```

Bridge (`x25519_cofactor_projection.log`):

```text
RESULT Proved indistinguishability between game 1 and game 2
All queries proved.
```

The bridge has no probability term: the equivalence is exact.

## Full runner

`runner.log` is the full `security/formal/run-cryptoverif-proofs.sh`
transcript, run through `vela-heavy` with CryptoVerif 2.12. All 14 proved
models prove; the legacy baseline remains the expected unproved control:

- `kem_v2_x25519_gdh`: proved
- `kem_v2_x25519_gdh_sha256`: proved
- `kem_v2_x25519_gdh_nonuniform`: proved
- `kem_v2_x25519_gdh_nonuniform_sha256`: proved
- `kem_v2_x25519_cofactor_sha256`: proved
- `x25519_cofactor_projection`: proved
- `kem_v2_mlkem_cca`: proved
- `kem_v2_mlkem_cca_sha256`: proved
- `kem_v1_x25519_baseline`: unproved (expected control)
- `kem_dem_seal_share`: proved
- `hybrid_sig_mldsa_euf`: proved
- `hybrid_sig_ed25519_euf`: proved
- `possession_proof_mldsa`: proved
- `possession_proof_ed25519`: proved
- `shamir_share_tags`: proved

`runner-tests.log` is `python3 security/formal/tests/test_cryptoverif_runner.py
-v`: 18 tests pass, including the new bound/projection drift checks and the
retained-log checks.

## What is machine-checked vs argued

Machine-checked:

- The projection identities above, in the shipped `DH_X25519` (k = 8)
  structure, with probability 0.
- IND-CCA2 of the combiner in the `(eq, et)` model under
  `pGDH`/`pDistRerandom`/`PCollKey`, with the reject branch and SHA-256
  bridge, at the bound shown.
- The reject test depends only on public data, so it contributes no term.
- The runner rejects process failures, missing verdicts, missing query
  witnesses, drift in the cofactor bound, drift in the projection result, and
  manual/admitted proof syntax.

Argued, not machine-checked:

- That Rust samples the clamped distribution represented by the abstract
  `[nonuniform]` type `Z`, and that `clamp_integer` realizes it.
- That the wire bytes map to `(eq, et)` and that the abstract `G` is the
  prime-order quotient used by the game. The bridge proves the cofactor
  component is killed in the `DH_X25519` representation; transporting that to
  the abstract `G` uses the standard group isomorphism.
- That `is_neutral(exp(eq,x)) = is_neutral(eq)` holds for the concrete
  exponent distribution (the model takes it as the `DH_basic_with_is_neutral`
  equation). The clamped set contains no multiple of the prime order, as
  noted above, but the integer-range fact is not formalized.
- The concrete hash functions: HKDF-SHA256 is a random oracle; SHA-256 is the
  `FixedCollisionResistant_hash_1` assumption with symbolic `PhashCt`/
  `PhashEk`; `PhashEk` is declared but not charged in this single-recipient
  game.
- X25519 encoding aliases (non-canonical `u`, ignored high bit, `u(P)=u(-P)`)
  remain plan step C3a/C3b and are not covered. The cofactor model has no
  coordinate encoding; the factor two in `PCollKey = 2^-250` is still imported
  from the HPKE analysis.
- The encapsulation-side reject check is the same predicate applied to the
  recipient key. In the IND-CCA2 game the recipient key is honest
  `(exp(g,x), t0)`, which is non-neutral, so that check always passes; the
  game does not model encapsulating to an attacker-supplied low-order key.

## Commands

```bash
export CRYPTOVERIF=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif
export CRYPTOVERIF_LIB=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl
export VELA_PROOF_OUT=$PWD/security/assurance/proof-logs/current/cryptoverif-x25519-cofactor
export VELA_STEP_TIMEOUT=3600
~/.local/opt/vela-tools/bin/vela-heavy security/formal/run-cryptoverif-proofs.sh \
  > "$VELA_PROOF_OUT/runner.log" 2>&1
python3 security/formal/tests/test_cryptoverif_runner.py -v
python3 security/formal/check-cryptoverif-cofactor.py bound \
  security/assurance/proof-logs/current/cryptoverif-x25519-cofactor/kem_v2_x25519_cofactor_sha256.log
python3 security/formal/check-cryptoverif-cofactor.py projection \
  security/assurance/proof-logs/current/cryptoverif-x25519-cofactor/x25519_cofactor_projection.log
```

## Files

- `security/formal/cryptoverif/kem_v2_x25519_cofactor_sha256.ocv`
- `security/formal/cryptoverif/x25519_cofactor_projection.ocv`
- `security/formal/check-cryptoverif-cofactor.py`
- `security/formal/run-cryptoverif-proofs.sh`
- `security/formal/tests/test_cryptoverif_runner.py`
- `security/formal/cryptoverif/README.md`
- this directory: model copies, proof logs, `runner.log`, `runner-tests.log`,
  `versions.txt`

## Unverified / next steps

- C3a/C3b: non-canonical Montgomery `u` aliases, the ignored high bit, and the
  `u(P)=u(-P)` transcript ambiguity. The factor two in `PCollKey` should be
  derived there rather than imported.
- A machine-checked correspondence from `clamp_integer`/`StaticSecret` bytes
  to the abstract `Z` distribution (or at least a test showing the sampled
  set), and from the Rust wire format to `(eq, et)`.
- An encapsulation-side low-order-recipient-key game if that call pattern is
  reachable with attacker-chosen recipient keys (the tested paths use honest
  published keys).
- Hosted reproduction of the full runner.
