# Computational proofs of the hybrid KEM combiner (CryptoVerif 2.12)

These are the first computational, not symbolic, proofs in VELA. They cover
the KEM combiner in `libVELA/vela-crypto/src/kem.rs` (`combine_v2`):

```text
ss = HKDF-SHA256(ss_mlkem ‖ ss_x25519 ‖ x25519_epk ‖ x25519_pk ‖ SHA-256(ct_mlkem) ‖ SHA-256(pk_mlkem))
```

| Model | Result | Statement |
|---|---|---|
| `kem_v2_x25519_gdh.ocv` | proved | IND-CCA2 of the hybrid KEM from **Gap-DH on X25519 alone**. ML-KEM is an arbitrary function and the adversary holds its secret key. Bound: `4·pDistRerandom + 2·pGDH(t, 2·qH) + (2·Qd + 2·qH)/|Z|` |
| `kem_v2_mlkem_cca.ocv` | proved | IND-CCA2 of the hybrid KEM from **IND-CCA2 of ML-KEM alone**. The adversary holds the X25519 secret key. Bound: `2·Penc(t, 1, 1, Qd) + 6·Qd·Pctxtcoll + 2·qH/|mlss| + (8·Qd + 2·qH)/|Z|` |
| `kem_dem_seal_share.ocv` | proved | `seal_share`/`open_share` (KEM ‖ XChaCha20-Poly1305, no AAD) is **IND-CCA2 public-key encryption**, assuming an IND-CCA2 KEM (the two rows above) and IND-CPA + INT-CTXT for the AEAD with a fresh random nonce. Bound: `2·Pkem + 2·Pencctxt + 4·Penc + 10·Qd·Pctxtcoll` (Penc per message, from the log) |
| `kem_v1_x25519_baseline.ocv` | not proved (expected) | The legacy combiner `HKDF(ss_mlkem ‖ ss_x25519)` in the first game. Consistent with the known attack when ML-KEM is broken; CryptoVerif reports proof failure, not an attack trace |

Together the two proved theorems give the hybrid claim (COMP-5): the combined
KEM is IND-CCA2 if **either** ML-KEM is IND-CCA2 **or** Gap-DH holds on X25519.

Run: `security/formal/run-cryptoverif-proofs.sh` (CI step "Prove the hybrid
KEM combiner in the computational model"). Logs: `security/assurance/proof-logs/current/cryptoverif/`.

## Assumptions and gaps (read before citing)

- **HKDF-SHA256 is a random oracle** on the concatenated input.
- **SHA-256 collision resistance** for `ct_mlkem` and `pk_mlkem`: the models
  feed those values to the oracle directly instead of their hashes. The step
  is argued, not modelled.
- **X25519 as a prime-order group** (`DH_good_group` + `GDH`). The real curve
  has cofactor 8; `kem.rs` rejects non-contributory (low-order) results.
  CryptoVerif's `DH_X25519` modelling of the cofactor is not used here.
- **One recipient key, one challenge.** Multi-user, multi-challenge security
  follows by a standard hybrid argument that is not machine-checked.
- **KEM-DEM is proved modularly.** `kem_dem_seal_share.ocv` assumes an
  abstract IND-CCA2 KEM; the combiner theorems discharge that assumption one
  component at a time. The two steps are composed by hand (the abstract KEM
  is instantiated with the proved combiner), not in a single CryptoVerif run.
  Envelope encodings above `seal_share` (share envelope v2, contact
  envelopes with AAD) are not covered here.
- **Legacy path.** `decapsulate_legacy_v1` remains for trusted-contact
  envelopes written before v2 (`recovery.rs`, version byte 1). Those
  envelopes do not get this guarantee.
- Primitive implementations (`ml-kem`, `x25519-dalek`, `hkdf`, `sha2`) are
  trusted under the selected boundary (`09-target-contract.md`).
