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

The proof applies the `PCollKey` collision statement twice, at
`kem_v2_x25519_gdh_nonuniform.log:18/248` (`Qd * PCollKey`) and `:25/400`
(`qH * PCollKey`). These are **not** blanket bounds on adaptive collisions with
the published `epk`: the `Qd` charge covers a pre-challenge decapsulation lookup
(freshness) plus a guard-excluded decapsulation-side lookup of the challenge
entry, while the `qH` charge covers only pre-challenge random-oracle entries.
The final machine-checked coefficient is
`2 * Qd + 2 * qH`; the factor two is the bit-secrecy/advantage conversion. No
`1/|Z|`, `PColl1Rand`, `PColl2Rand`, or `EpsRand` term remains.

The case analysis and the retained debug transcript are in
[COLLISION-SIDE-CONDITIONS.md](COLLISION-SIDE-CONDITIONS.md) and
`kem_v2_x25519_gdh_nonuniform.debug.log`.

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
is conservative. `PCollKey = 2^-250` instantiates the explicit collision
parameter; it is not by itself a semantic independence assumption. The
arithmetic domination `2^-250 >= 2^-251` is not the justification of the two
collision applications. The `[large,nonuniform]` type-level default
`PColl1Rand(Z) <= 2^-160` is also not used in the displayed bound. The
game-specific justification is in
[COLLISION-SIDE-CONDITIONS.md](COLLISION-SIDE-CONDITIONS.md).

These values instantiate the distribution terms; they do not prove that the
implementation clamps, or that the clamped distribution is the one modelled.
The bound is conditional on the X25519 GDH assumption and on the
single-challenge game described above.

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
- The collision side conditions are justified by a paper-level query-order case
  analysis for this game, not reified in CryptoVerif. The `Qd`/`qH`
  `PCollKey` charges must not be read as an unconditional adaptive-key-collision
  bound. Post-challenge adaptive hash inputs that also test the challenge DH
  value are handled by the GDH/CDH term, not by `PCollKey`; multi-challenge
  reuse of a published `epk` needs a new analysis. See
  [COLLISION-SIDE-CONDITIONS.md](COLLISION-SIDE-CONDITIONS.md).

## Parent reproduction

After integrating the game as `f80af64`, the parent reran the full real gate
through `vela-heavy` with the same pinned binary/library. `runner.log` and all
seven per-model logs now record that parent run from
`/tmp/vela-parent-cv-nonuniform`; `delegate-runner.log` preserves the earlier
child summary. All six positive verdicts and the expected legacy nonproof
passed. Eleven runner/sourceguard tests also passed (`runner-tests.log`).
Hosted reproduction of this increment remains pending.
