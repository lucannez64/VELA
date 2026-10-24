# Computational construction models (CryptoVerif 2.12)

These are scoped computational model proofs, separate from the symbolic
Tamarin/ProVerif results and from a complete Rust refinement theorem. The KEM
models follow `libVELA/vela-crypto/src/kem.rs::combine_v2`:

```text
ss = HKDF-SHA256(ss_mlkem ‖ ss_x25519 ‖ x25519_epk ‖ x25519_pk ‖ SHA-256(ct_mlkem) ‖ SHA-256(pk_mlkem))
```

| Model | Local result | Statement and bound |
|---|---|---|
| `kem_v2_x25519_gdh.ocv` | proved | Single-recipient IND-CCA2 in a **uniform prime-order GDH model**, with public ML-KEM functions, a correctness equation and the ML-KEM secret key disclosed. No ML-KEM secrecy assumption. Bound: `4·pDistRerandom + 2·pGDH(t, 2·qH) + (2·Qd + 2·qH)/|Z|` |
| `kem_v2_mlkem_cca.ocv` | proved | Single-recipient IND-CCA2 under **ML-KEM IND-CCA2 and the library collision bounds**, with the DH secret exponent disclosed. Bound: `2·Penc(t, 1, 1, Qd) + 6·Qd·Pctxtcoll + 2·qH/|mlss| + (8·Qd + 2·qH)/|Z|` |
| `kem_dem_seal_share.ocv` | proved | Modular IND-CCA2 public-key encryption for an abstract IND-CCA2 KEM plus IND-CPA/INT-CTXT AEAD and a fresh random nonce. The bound includes `2·Pkem`, `2·Pencctxt`, two separate `2·Penc` terms and `10·Qd·Pctxtcoll`; full time/message-length arguments are in the log |
| `hybrid_sig_mldsa_euf.ocv` | proved | AND-signature EUF-CMA under the ML-DSA-87 assumption, with the Ed25519 secret key disclosed. Bound: `Pmldsa(t, Qs)` |
| `hybrid_sig_ed25519_euf.ocv` | proved | AND-signature EUF-CMA under the Ed25519 assumption, with the ML-DSA secret key disclosed. Bound: `Ped(t, Qs)` |
| `kem_v1_x25519_baseline.ocv` | explicitly unproved | Legacy combiner without transcript binding. An unproved-query control, not a CryptoVerif attack trace |

The two KEM games support a model-level surviving-component claim subject to
all their assumptions. They do not prove the complete concrete X25519
construction secure under a single unqualified primitive assumption. In
particular, collision and finite-domain terms in the displayed bounds must be
bounded; they are not set to zero. `IND_CCA2_KEM` supplies public-key and
encapsulation-ciphertext collision bounds; the displayed one-recipient result
contains `Pctxtcoll` even though `Pkeycoll` does not occur in its final bound.

The signature games machine-check the reduction described in
[the signature note](../../assurance/10-signature-reduction.md), under independent
keys, the surviving component's assumption and a bijective fixed-length pair
encoding. Use the bound for a component whose assumption holds; take the minimum
only for a common game where both bounds are justified, such as the
no-secret-disclosure game. A disclosed component cannot supply its own
unforgeability bound.

Run `security/formal/run-cryptoverif-proofs.sh`. The CI step is configured to run
this gate. The [review-correction evidence](../../assurance/proof-logs/current/computational-review-corrections/README.md)
contains local results for the strengthened correctness-equation games. Earlier
logs in `proof-logs/current/cryptoverif/` and `cryptoverif-runner-repair/` predate
that correction and do not establish the strengthened statement. Hosted
reproduction is a separate result; a configured gate is not evidence it passed.

## Assumptions and open correspondence

- **HKDF-SHA256 is a random oracle** on the concatenated input, not a proved
  instantiation of that idealization by the concrete HKDF implementation.
- **SHA-256 collision resistance** for `ct_mlkem` and `pk_mlkem` bridges the
  real hashed fields to the raw fields supplied to the modeled oracle. This
  bridge is a written argument, not part of these machine-checked games.
- **Uniform prime-order DH.** `DH_good_group` with bounded `Z` models uniform
  prime-field exponents. Real X25519 uses clamped, nonuniform scalars and has
  cofactor 8. The code's non-contributory-result check and transcript binding
  do not prove either abstraction bridge. These are distinct open obligations.
  The symbolic `pDistRerandom` term has no concrete Curve25519 instantiation
  here. The shipped HPKE development uses a different `DH_basic`/nonuniform
  exponent model with `GDH_RSR_minimal` and explicit distribution/collision
  constants; its Curve25519 analysis cannot simply be transferred to this game.
- **Other-component disclosure, not arbitrary corruption semantics.** The
  GDH game exposes the ML-KEM secret key and gives public algorithms satisfying
  decapsulation correctness for honest encapsulations. It assumes no ML-KEM
  secrecy. This is perfect correctness in the model; no separate concrete
  decapsulation-failure loss is instantiated. The opposite game discloses the
  DH exponent. Keys are still honestly
  and independently generated; malicious key generation and adaptive multi-user
  corruptions are not covered.
- **One recipient key and one challenge.** Multi-user/multi-challenge and
  quantum-oracle-query composition are not machine-checked by these games.
- **KEM-DEM is modular.** The encryption game assumes an abstract IND-CCA2 KEM;
  instantiating it with a combiner theorem is a manual composition step. The
  model uses no AAD. Signed share-envelope and contact-envelope/AAD encodings
  above this transport are not covered by that encryption theorem.
- **Legacy attack argument needs an extra capability.** If an attacker can
  find a different ML-KEM ciphertext decapsulating to the challenge ML-KEM
  secret, keeping its DH ephemeral key breaks the unbound v1 combiner. Secret
  key disclosure alone does not grant that ciphertext-collision/second-preimage
  capability. The baseline has correctness but does not supply such an
  algorithm, and its failed proof is not evidence of that attack.
- **Legacy handling remains separate.** `decapsulate_legacy_v1` supports old
  trusted-contact envelopes in `recovery.rs`; the v2 result does not cover it.
- Primitive implementations remain trusted under
  [the selected boundary](../../assurance/09-target-contract.md). Concrete
  randomness, errors, encoding, Rust execution and protocol composition still
  require correspondence proofs.

The runner rejects process failures, missing verdicts, missing expected query
results and local manual/admitted proof syntax. The lexical source check is a
drift guard, not a proof that every equation, collision axiom, primitive
assumption or encoding faithfully represents the implementation.
