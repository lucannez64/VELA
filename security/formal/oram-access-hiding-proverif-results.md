# M22 Path-ORAM access-pattern hiding assurance record

Formal verification that the server cannot learn **which** chunk a client
accessed — the access-pattern property that Dolev-Yao tools like Tamarin
cannot express, checked instead with ProVerif's **observational equivalence**
(the right tool for indistinguishability).

## Tooling

- **ProVerif 2.05** (opam switch `vela-proverif`) — typed pi calculus with
  `equivalence` (bisimulation-style observational equivalence).
- **hax 0.3.7 `pro-verif` backend** (experimental) — extracts the pure Rust
  ORAM decision logic from `libVELA/vela-crypto/src/oram.rs` into
  `proofs/proverif/extraction/lib.pvl`, concatenated ahead of each model.
  hax 0.3.7 does not ship this backend's prelude, so the minimal missing
  definitions are vendored in `security/formal/hax_pv_prelude.pvl`
  (`core_models__cmp__f_le(nat, nat): bitstring`, uninterpreted — ProVerif's
  symbolic model has no nat arithmetic).

## The property

The server observes: path requests (`GET /vault/oram/{tree}/path/{leaf}`),
write-backs (`PUT …/path/{leaf}`, opaque AEAD blobs), and chunk ids in the
plaintext sync manifest. Access-pattern hiding means the transcript is
independent of *which* chunk the user opened:

```
access(chunkA) ≈_obs access(chunkB)
```

expressed as a ProVerif `equivalence` between the two worlds.

## Results

| Theory | Design | Verdict |
|---|---|---|
| `m22a_static_position_baseline.pv` | fixed leaf per chunk (no remap) | equivalence **FALSE** — attack demonstrated |
| `m22b_trivial_oram_hiding.pv` | ≤4 chunks: whole-tree sweep | equivalence **TRUE** — transcripts literally identical |
| `m22c_path_oram_hiding.pv` | fresh-leaf remap per access, incl. repeated access to the same chunk | equivalence **TRUE** — repeated accesses unlinkable |

The falsified baseline pins down exactly which structural fact carries the
guarantee: `prepare_access`'s fresh-random leaf assignment. Without it, the
server computes `pos(known_chunk)` from plaintext manifest ids and matches it
against observed paths; with it, every request carries a fresh unrelated leaf.
Trivial mode hides by construction (the sweep is identical regardless of the
target), and the extracted threshold policy
(`use_trivial_oram_with_threshold`, uninterpreted in the symbolic model)
cannot affect the guarantee because both modes are proven independently.

## Scope notes

- Symbolic AEAD: bucket ciphertexts are opaque constructors; the model proves
  pattern-independence given authenticated encryption, not the encryption
  itself (covered by the XChaCha20-Poly1305 construction and its tests).
- Stash/position-map state beyond the remap step is abstracted; the stash
  merge appears only as an opaque input to the client-side AEAD.
- Statistical leakage of real Path ORAM (e.g., stash overflow) is outside any
  symbolic tool; VELA bounds it operationally via the trivial-mode threshold.

## Verification output

```text
m22a_static_position_baseline: equivalence FALSE (baseline attack demonstrated, as expected)
m22b_trivial_oram_hiding: equivalence TRUE (verified)
m22c_path_oram_hiding: equivalence TRUE (verified)
m22 oram access-hiding formal proof gate: 2 equivalences proved, 1 baseline falsified, 0 errors
```

Toolchain: proverif 2.05, hax 0.3.7 (pro-verif backend, experimental).

Reproduce with:

```sh
./security/formal/run-oram-access-hiding-proofs.sh
```

Requires the `vela-proverif` opam switch (see runner header for the two
install commands). Extracted policy regenerates with:

```sh
cd libVELA/vela-crypto
cargo hax into -i '-** +vela_crypto::oram::use_trivial_oram_with_threshold' pro-verif
```

## Post-review revision (2026-08-26)

`m22b_trivial_oram_hiding.pv` now folds the selected chunk's payload into the
opaque `aead_stash` write-back (chunkA in world A, chunkB in world B), so the
equivalence models `access(chunkA) ~ access(chunkB)` rather than a trivial
self-equivalence. Re-verified locally: m22a FALSE (baseline attack), m22b TRUE,
m22c TRUE (proverif).
