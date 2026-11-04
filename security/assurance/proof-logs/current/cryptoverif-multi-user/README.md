# Multi-user, multi-challenge KEM combiner (local evidence)

Local machine-checked evidence for plan step C6: the v2 combiner

```text
ss = HKDF-SHA256(ss_mlkem ‖ ss_x25519 ‖ x25519_epk ‖ x25519_pk
                 ‖ SHA-256(ct_mlkem) ‖ SHA-256(pk_mlkem))
```

(`libVELA/vela-crypto/src/kem.rs::combine_v2`, lines 171-193) is
IND-CCA2 in a **multi-user, multi-challenge, left-or-right** game, on both
surviving-component sides, with the SHA-256 bridge machine-checked and the
`PhashEk` term charged.

This directory is local evidence. It is not hosted-CI evidence and not an
independent audit. The parent plan integrates this result.

## Models

| Model | Side | Based on |
|---|---|---|
| `security/formal/cryptoverif/kem_v2_x25519_gdh_multi_sha256.ocv` | uniform prime-order GDH; ML-KEM secret keys disclosed | `kem_v2_x25519_gdh_sha256.ocv` |
| `security/formal/cryptoverif/kem_v2_x25519_gdh_nonuniform_multi_sha256.ocv` | nonuniform/clamped-style GDH; ML-KEM secret keys disclosed | `kem_v2_x25519_gdh_nonuniform_sha256.ocv` |
| `security/formal/cryptoverif/kem_v2_mlkem_cca_multi_sha256.ocv` | ML-KEM IND-CCA2; all DH exponents disclosed | `kem_v2_mlkem_cca_sha256.ocv` |

The exact sources used for the recorded run are copied under `models/`.

## Game

All three models share the same game skeleton:

- `N` honestly generated recipient key pairs. The adversary receives every
  public key `pk_i = (mlpkgen(skm_i), exp(g, x_i))` (and, on the GDH side,
  every `skm_i`; on the ML-KEM side, every `x_i`).
- `Qc` challenge encapsulations, each addressed by an honest recipient
  public key. A challenge returns `(ctm, epk, key)` where `key = H(...)`
  for the single global challenge bit `b = 1` and a fresh random key for
  `b = 0`. `Qc` is the **total** over all recipients: choose
  `Qc = N·Qe` to read `Qe` challenges per recipient, and the adversary may
  put all `Qc` challenges on one recipient. This covers adaptive challenge
  scheduling across users.
- `Qd` adaptive decapsulation queries per recipient, each rejecting that
  recipient's own challenge capsules. `#Odecap` in the printed bound is
  the total number of decapsulation calls, so `#Odecap ≤ N·Qd`.
- `qH` random-oracle queries to the HKDF random oracle `H`.

The goal is `query secret b [cv_bit]`: the adversary must not distinguish
the all-real challenge keys from the all-random challenge keys. This is the
multi-user/multi-challenge left-or-right IND-CCA2 statement itself; no
single-user-to-multi-user hybrid is used in the proof. In particular, the
bounds below are the directly printed game bounds, not a single-user bound
multiplied by `N·Qc`.

## Environment and command

- CryptoVerif 2.12, local binary
  `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif`,
  SHA-256 `582f31b301d5efbe8428924c3559454a9a63591bec41f4cf19cd28082933e130`.
- Library `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl`,
  SHA-256 `f60c0fa4701257a57415fc256b440cffd4d2851bf25af66e62c009c0ac9e08fd`.
- CryptoVerif is a local command, not a `vela-heavy` gate. The runner wraps
  each model in `security/assurance/bounded.sh timeout 600` (3 GiB, no
  swap, one worker).

```bash
export CRYPTOVERIF=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif
export CRYPTOVERIF_LIB=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl
export VELA_PROOF_OUT=/tmp/vela-cv-multi/full
security/formal/run-cryptoverif-proofs.sh
```

`runner.log` is the full console transcript of the 16-model run;
`kem_v2_*_multi_sha256.log` are the per-model CryptoVerif logs.

## Verdicts and machine-checked bounds

The full runner proved all 16 models; the legacy `kem_v1_x25519_baseline`
remained the expected unproved negative control. The three new results are:

```text
kem_v2_x25519_gdh_multi_sha256:
  (2·N + 2·Qc)·pDistRerandom + 2·N·Qc·pGDH(t, 2·qH)
  + (2·N²·Qc² + 4·N² + 2·Qc² + 2·#Odecap·Qc + 2·N²·Qc + 2·qH·Qc)/|Z|
  + 8·PhashCt + 6·PhashEk

kem_v2_x25519_gdh_nonuniform_multi_sha256:
  (2·N + 2·Qc)·pDistRerandom + 2·pGDH(t, 2·qH)
  + (8·N² + 4·Qc² + 2·#Odecap·Qc + 2·Qc·qH)·PCollKey
  + 8·PhashCt + 6·PhashEk

kem_v2_mlkem_cca_multi_sha256:
  2·qH·Qc/|mlss| + 2·Penc(t, N, Qc, #Odecap)
  + (2·N²·Qc² + 3·N² + 8·#Odecap·Qc + 2·N²·Qc + 2·qH·Qc)/|Z|
  + (2·Qc²·N² + 6·#Odecap·Qc·N)·Pctxtcoll
  + 6·PhashCt + 4·PhashEk + 8·N²·Pkeycoll
```

`#Odecap ≤ N·Qd`; substituting the upper bound yields a loss expressed only
in the game parameters. The printed `time_1` is a proof-step time index, not
an extra assumption. The uniform GDH application is explicitly over the `N`
static exponents and `Qc` ephemeral exponents (the proof log shows
`N * Qc * pGDH(...)`). The nonuniform model uses `GDH_RSR_minimal`'s
multi-pair assumption, whose stated bound carries one `pGDH` term plus
`(na + nb)·pDistRerandom`; the final bound therefore has `2·pGDH(...)` and
the `(2·N + 2·Qc)·pDistRerandom` term. The ML-KEM assumption is applied as
`Penc(t, N, Qc, #Odecap)`, i.e. the library multi-user/multi-challenge KEM
assumption, not `N` independent single-user calls.

### What is machine-checked

- The complete game definitions, including `N` honest recipients, `Qc`
  challenge encapsulations, per-recipient adaptive decapsulation and the
  challenge-capsule rejection.
- The CryptoVerif proof and the exact probability expressions above,
  including the multi-user GDH accounting (the uniform model's `N·Qc`
  factor and the nonuniform model's multi-pair `GDH_RSR_minimal`
  accounting), the multi-user `Penc(t, N, Qc, #Odecap)` argument, and the
  `PhashEk` terms.
- That the proof applies the `SHAek` fixed-collision statement when
  relating recipient public keys in the random-oracle input, and that the
  final bound contains `6·PhashEk` (GDH games) or `4·PhashEk` (ML-KEM
  game). The single-recipient SHA-256 games never charge this term.
- Output-drift detection for all six SHA-256 models through
  `security/formal/check-cryptoverif-sha256-bound.py`; the runner and the
  retained-log tests reject changed coefficients, a missing `PhashEk` term,
  and a missing multi-user factor (see `security/formal/tests/test_cryptoverif_runner.py`).

### What is argued, not machine-checked

- **Model-to-code correspondence.** The map from Rust byte strings to the
  modelled `mlct`/`mlpk`/group-element types, the concrete 1568-byte ML-KEM
  encodings, and the fact that `as_ref()`/`to_bytes()` hash exactly the
  bytes modelled by `SHAct`/`SHAek`. The models prove the hashed game, not
  that `kem.rs` implements it.
- **Primitive assumptions.** Concrete SHA-256 collision resistance
  (`PhashCt`, `PhashEk`) is left symbolic; no numeric SHA-256 or ML-KEM
  probability is derived. HKDF-SHA256 is a random oracle; ML-KEM
  correctness is an equation (GDH side) or the `IND_CCA2_KEM` library
  assumption (ML-KEM side). Concrete X25519/ML-KEM implementations remain
  trusted under the selected boundary.
- **Honest key generation only.** Each recipient key pair is generated
  honestly and independently. Malicious key generation, adaptive
  corruptions, and a per-user adversarial key-registration model are not
  covered. The disclosed-component games represent the programme's
  surviving-component claims, not arbitrary corruption semantics.
- **Distribution instantiation.** For the nonuniform GDH game, the
  Curve25519 instantiation `PCollKey = 2^-250` and
  `pDistRerandom = 2^-125` is imported from the CryptoVerif 2.12 HPKE
  material. The model exposes them symbolically; it does not prove that the
  Rust implementation samples the clamped distribution, that clamping is
  correct, or that the cofactor-8 subgroup, non-contributory inputs, the
  `kem.rs` reject check, or Montgomery encoding aliases are covered.
- **Scope.** QROM/quantum-oracle-query composition (plan step C7b), the
  KEM-DEM/application composition (C8), and the concrete X25519 combiner
  theorem (C5) remain outside this result. The multi-user game is a
  model-level computational statement.
- **Bound reading.** `Qc` is total challenges; the per-recipient reading
  `Qe` requires `Qc = N·Qe`. `#Odecap` is the actual number of
  decapsulation calls; `N·Qd` is its upper bound.

## SHA-256 and `PhashEk`

`combine_v2` hashes the recipient ML-KEM encapsulation key
(`kem.rs:178`) and feeds the 32-byte digest to the KDF. In the
single-recipient games (`cryptoverif-sha256-bridge/`) the `SHAek` collision
assumption is declared but never used: there is only one recipient public
key, so no proof step relates two distinct `mlpk` values. The multi-user
games have `N` public keys; when the proof must separate two recipients in
the random-oracle input, it applies the `SHAek` fixed-collision statement.
The resulting `PhashEk` term is therefore part of the machine-checked
multi-user bound. It is not a claim that SHA-256 has any particular concrete
collision probability.

## Model source hashes

The copies under `models/` are the exact sources of the recorded run:

```text
0d54e6be58598302c920aa9fbfd2d5ae08899f0228deb8295df8cc4c4764dc05  kem_v2_x25519_gdh_multi_sha256.ocv
479a0ee4491ebea4b31535045c02296bc35c01ae20bfc1d0561f402937bb47b1  kem_v2_x25519_gdh_nonuniform_multi_sha256.ocv
c7f904dd1c55d3157c77454faac689f61ff0152e7ee347cc131e0b446eeac5fa  kem_v2_mlkem_cca_multi_sha256.ocv
```

## Bound drift check

`security/formal/check-cryptoverif-sha256-bound.py MODEL LOG` pins the exact
printed probability expressions in the runner, including the multi-user
`N`/`Qc` factors and `PhashEk` coefficients.
`security/formal/tests/test_cryptoverif_runner.py` exercises a changed
coefficient on `kem_v2_x25519_gdh_multi_sha256` and checks the retained logs
in this directory. This is output-drift detection, not validation of the
assumptions or of model-to-Rust correspondence.
