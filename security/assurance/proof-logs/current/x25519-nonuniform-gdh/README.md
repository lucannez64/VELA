# X25519 nonuniform-exponent KEM combiner model (local evidence)

Local result for `security/formal/cryptoverif/kem_v2_x25519_gdh_nonuniform.ocv`,
the nonuniform/clamped-style exponent companion to
`kem_v2_x25519_gdh.ocv`. This directory records one full local runner pass; it
is not hosted-CI evidence.

## Environment and command

- CryptoVerif 2.12, local binary:
  `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif`
- Library: `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl`
- Serialized through `~/.local/opt/vela-tools/bin/vela-heavy` (global
  `flock`, 3 GiB, no swap, one worker); each model is wrapped in
  `timeout 600` by the runner.

```bash
export CRYPTOVERIF=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif
export CRYPTOVERIF_LIB=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl
export VELA_PROOF_OUT=/tmp/vela-nonuniform/full
vela-heavy security/formal/run-cryptoverif-proofs.sh
```

`runner.log` is the full-run transcript; `kem_v2_x25519_gdh_nonuniform.log`
is that model's proof log.

## Verdicts

The full runner reported six proved models and the explicit unproved legacy
baseline:

- `kem_v2_x25519_gdh`: proved
- `kem_v2_x25519_gdh_nonuniform`: proved
- `kem_v2_mlkem_cca`: proved
- `kem_v1_x25519_baseline`: unproved (expected control)
- `kem_dem_seal_share`: proved
- `hybrid_sig_mldsa_euf`: proved
- `hybrid_sig_ed25519_euf`: proved

The new game's machine-checked statement is:

```text
RESULT Proved bit secrecy of b up to probability
  4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH)
  + (2 * Qd + 2 * qH) * PCollKey
RESULT time_1 = (1 + Qd) * time(mlpkgen) + time(mlencap_ct)
  + time(mlencap_ss) + Qd * time(mldecap) + time + 3 * time(exp)
All queries proved.
```

The log shows two collision expansions, `Qd * PCollKey` (decapsulation-query
key collision) and `qH * PCollKey` (hash-query key collision). The final
machine-checked coefficient is `2 * Qd + 2 * qH`; no `1/|Z|` term remains.

## Derived Curve25519 instance

The model is symbolic in `PCollKey` and `pDistRerandom`. For the clamped
X25519 exponent distribution (`n = 2^254 + 8r`, `r` uniform in `[0,2^251)`;
after dividing out the cofactor, `m = 2^251 + r` uniform in
`[2^251, 2^252-1]`), the shipped CryptoVerif 2.12 HPKE model
`examples/hpke/common.dhkem.ocvl` states:

- `PColl1Rand(Z) = 2^-251`
- `PCollKey = 2^-250` (two scalars per `u`-coordinate, because `u(P) = u(-P)`)
- `PDistRerandom = 2^-125`

Substitution gives:

```text
4 * 2^-125 + 2 * pGDH(t, 2*qH) + (2*Qd + 2*qH) * 2^-250
```

`default.ocvl` mentions `2^-126` for the rerandomization term; using `2^-125`
is conservative. These values instantiate the distribution terms; they do not
prove that the implementation clamps, or that the clamped distribution is the
one modelled.

## Remaining gaps (not closed by this run)

- The cofactor-8 subgroup, non-contributory/low-order decapsulation inputs and
  the `kem.rs` reject check are not modelled; `G` is still prime-order.
- Non-canonical X25519 `u`-coordinate encodings/aliases are not modelled; the
  wire-encoding-to-group-element map is an argued correspondence.
- The model does not prove clamping correctness or that the Rust/HPKE-style
  key derivation samples the assumed distribution.
- HKDF-SHA256 remains an ideal random oracle; the SHA-256 bridge over
  `ct_mlkem`/`pk_mlkem` remains outside the game.
- ML-KEM is public and its secret key is disclosed; correctness is an
  equation, not a concrete decapsulation-failure loss.
- One recipient, one challenge; multi-user/multi-challenge, QROM and Rust
  composition remain open.
