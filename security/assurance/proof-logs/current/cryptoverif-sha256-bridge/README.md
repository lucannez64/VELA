# SHA-256 bridge for the v2 KEM combiner (local evidence)

Local result for the machine-checked SHA-256 bridge over
`ct_mlkem`/`pk_mlkem`. The new models are variants of the three existing KEM
games and keep the same disclosures and IND-CCA2 conclusion:

| Model | Based on |
|---|---|
| `security/formal/cryptoverif/kem_v2_x25519_gdh_sha256.ocv` | `kem_v2_x25519_gdh.ocv` |
| `security/formal/cryptoverif/kem_v2_x25519_gdh_nonuniform_sha256.ocv` | `kem_v2_x25519_gdh_nonuniform.ocv` |
| `security/formal/cryptoverif/kem_v2_mlkem_cca_sha256.ocv` | `kem_v2_mlkem_cca.ocv` |

The existing games are unchanged. This directory is local evidence; it is not
hosted-CI evidence and it is not an independent audit.

## Code correspondence

`libVELA/vela-crypto/src/kem.rs::combine_v2` builds the KDF input as:

```text
ct_hash = SHA-256(capsule.mlkem_ct.as_ref() as &[u8])        kem.rs:202
ek_hash = SHA-256(recipient.mlkem_ek.to_bytes().as_ref())    kem.rs:203
ikm     = mlkem_ss ‖ x25519_ss
          ‖ capsule.x25519_epk.as_bytes()                    kem.rs:206-208
          ‖ recipient.x25519_pk.as_bytes()                   kem.rs:209
          ‖ ct_hash ‖ ek_hash                                kem.rs:210-211
ss      = HKDF-SHA256(salt = b"vela hybrid kem v2", ikm, info = b"vela hybrid kem v2")
                                                             kem.rs:213-215
```

`mlkem_ct.as_ref()` is the ML-KEM-1024 ciphertext bytes (1568 bytes) and
`mlkem_ek.to_bytes()` is the 1568-byte encapsulation key. There is no
additional domain tag around either SHA-256 call; the two 32-byte digests are
simply appended in the order ciphertext then public key. The v2 label is the
HKDF salt and info, not a SHA-256 prefix. The models keep exactly that order:
`H(hk, mlkem_ss, x25519_ss, epk, pk, SHAct(ctm), SHAek(pkm))`.

## Environment and command

- CryptoVerif 2.12 (pinned in `security/assurance/04-reproducibility.md`),
  local binary `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif`,
  SHA-256 `582f31b301d5efbe8428924c3559454a9a63591bec41f4cf19cd28082933e130`.
- Library `~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl`,
  SHA-256 `f60c0fa4701257a57415fc256b440cffd4d2851bf25af66e62c009c0ac9e08fd`.
- All 13 models ran through `security/formal/run-cryptoverif-proofs.sh`; each
  model is wrapped by `security/assurance/bounded.sh timeout 600` (3 GiB,
  no swap, one worker). CryptoVerif itself is a local command, not a
  `vela-heavy` gate.

```bash
export CRYPTOVERIF=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif
export CRYPTOVERIF_LIB=$HOME/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl
export VELA_PROOF_OUT=/tmp/vela-cv-sha256/full-fixed
security/formal/run-cryptoverif-proofs.sh
```

`runner.log` is the full transcript; the per-model logs are the other `*.log`
files. The three new model sources are copied verbatim under `models/`.

## Verdicts

The full runner reported 12 proved models and the one expected unproved legacy
control:

- `kem_v2_x25519_gdh`: proved
- `kem_v2_x25519_gdh_sha256`: proved (new)
- `kem_v2_x25519_gdh_nonuniform`: proved
- `kem_v2_x25519_gdh_nonuniform_sha256`: proved (new)
- `kem_v2_mlkem_cca`: proved
- `kem_v2_mlkem_cca_sha256`: proved (new)
- the remaining signature/possession/Shamir models: proved
- `kem_v1_x25519_baseline`: unproved (expected control)

Machine-checked probability expressions (the printed time arguments are proof
step indices, not separate assumptions):

```text
kem_v2_x25519_gdh_sha256:
  4·pDistRerandom + 2·pGDH(t, 2·qH) + (2·Qd + 2·qH)/|Z| + 6·PhashCt

kem_v2_x25519_gdh_nonuniform_sha256:
  4·pDistRerandom + 2·pGDH(t, 2·qH)
  + (2·Qd + 2·qH)·PCollKey + 6·PhashCt

kem_v2_mlkem_cca_sha256:
  2·qH/|mlss| + 2·Penc(t, 1, 1, Qd) + (8·Qd + 2·qH)/|Z|
  + 4·PhashCt + 6·Qd·Pctxtcoll
```

Each printed bound contains one summed `PhashCt` term: three proof stages charge
one `PhashCt` each in the two GDH games and two in the ML-KEM game, and the
bit-secrecy/advantage conversion doubles the sum. `PhashEk`
is declared and the pk hash is present in the oracle input, but no `PhashEk`
term appears: the game has one fixed recipient public key, so the proof never
relates two distinct pk values. A multi-recipient game would need that term.

The nonuniform Curve25519 instantiation from the existing README is unchanged:
substituting `PCollKey = 2^-250`, `pDistRerandom = 2^-125` gives
`4·2^-125 + 2·pGDH(t,2·qH) + (2·Qd+2·qH)·2^-250` plus the SHA-256 terms.
`PhashCt` is left symbolic; no numeric SHA-256 collision probability is
asserted.

## Assumptions exercised by the models

- **SHA-256 on `ct_mlkem` and on `pk_mlkem` is a fixed (unkeyed)
  collision-resistant hash.** Each call is modelled by CryptoVerif's
  `FixedCollisionResistant_hash_1`; SHA-256 is public, so the model needs no
  key or hash oracle. The collision statements are
  `Pr[SHAct(x)=SHAct(y) and x≠y] <= PhashCt` and the analogous `PhashEk`.
  This is the idealization of the two concrete SHA-256 calls at
  `kem.rs:202-203`.
- **HKDF-SHA256 over the concatenated input is a random oracle** `H` with
  `qH` queries (`ROM_hash_6`). The HKDF salt/info labels are absorbed into the
  oracle idealization; they are not separately modelled as domain separation.
- **X25519** is either uniform prime-order GDH (`DH_good_group` + `GDH`) or
  nonuniform/clamped-style GDH (`DH_basic` +
  `DH_proba_collision_minimal` + `GDH_RSR_minimal`, with `PCollKey` and
  `pDistRerandom`). The ML-KEM secret key is disclosed in both GDH games.
- **ML-KEM** is either public with only a correctness equation (GDH games,
  secret key disclosed) or an IND-CCA2 KEM with the library's public-key and
  ciphertext collision bounds (`IND_CCA2_KEM`; DH exponent disclosed).
- One recipient, one challenge, honest key generation, `Qd` decapsulation
  queries excluding the challenge capsule, `qH` random-oracle queries.

## What remains argued (not machine-checked)

- The map from Rust byte strings to the modelled types: `mlct`/`mlpk` values,
  the concrete 1568-byte encodings, and the fact that `as_ref()`/`to_bytes()`
  produce exactly the bytes hashed by SHA-256. The models prove the hashed
  game, not that the Rust hashing call sites match the model.
- The assumption that concrete SHA-256 has the modelled fixed collision
  resistance, and the numeric value of `PhashCt`/`PhashEk` for SHA-256. No
  birthday bound or concrete collision probability is derived here.
- `PhashEk` is available but not charged in these single-recipient games; the
  pk-collision-resistant bridge for multiple recipients remains outside the
  proved statement.
- X25519 cofactor-8 behavior, non-contributory/low-order inputs, the `kem.rs`
  reject check, and non-canonical Montgomery encodings are not modelled.
- HKDF-SHA256 is a random oracle; the concrete HKDF construction is not proved
  to realize it. ML-KEM correctness is an equation, not a concrete
  decapsulation-failure analysis.
- Multi-user/multi-challenge composition, QROM, malicious key generation and
  the KEM-DEM/application composition remain open, as in the existing games.

## Bound drift check

`security/formal/check-cryptoverif-sha256-bound.py MODEL LOG` pins the exact
probability expressions above (time indices excepted). The runner invokes it
for all three new models; `security/formal/tests/test_cryptoverif_runner.py`
exercises a changed-coefficient rejection and the retained logs in this
directory. This is output-drift detection, not a validation of the assumptions
or of model-to-Rust correspondence.

## Model source hashes

The copies under `models/` are the exact sources the recorded run used:

```text
00ce7ec3bf1e977df04bc93546e683c5d8336c1193eb21a09dc5c69514a49cde  kem_v2_x25519_gdh_sha256.ocv
57213d48d33d8672f6d367c5eefa1170a2581a834bed69f4520e770486051390  kem_v2_x25519_gdh_nonuniform_sha256.ocv
49a3ab90099a100c2641792989703e1e298a07ce2108aff799e437eac4a5c399  kem_v2_mlkem_cca_sha256.ocv
```

