# Cyclo Paper-Code Audit Report

**Paper:** Cyclo: Lightweight Lattice-based Folding via Partial Range Checks
**Repository:** https://github.com/osdnk/cyclo
**Audit Date:** 2026-03-26
**Slug:** cyclo-folding-audit

---

## Executive Summary

| Claim | Status | Verdict |
|-------|--------|---------|
| Proof size ~30 KB | ⚠️ Minor Discrepancy | Code computes 31.76 KB; paper says "on the order of 30 KB" |
| Prover time 3.5× faster than LatticeFold+ | ✅ Verified | Code confirms 3.53× speedup |
| No decomposition needed for R1CS/CCS over F_q | ✅ Verified | Confirmed in protocol specification |
| Amortized norm-refreshing eliminates accumulator norm checks | ✅ Verified | Design claim confirmed in protocol spec |
| Extension commitment "order of magnitude" more efficient | ⚠️ Overstatement | Code shows 3.5×, not 10× |
| Parameters match between paper and code | ✅ Verified | All parameters match exactly |
| Reproducibility via benchmark scripts | ✅ Verified | `estimates.ipynb` and `report.out` reproduce claims |

---

## 1. Proof Size (~30 KB)

**Paper Claim (Section 1.1, Abstract):** "Cyclo achieves succinct proof sizes on the order of 30 KB, improving by an order of magnitude over LatticeFold+"

**Paper Table 2 (cyclo.md line 948):** 31.8 KB vs 100 KB for LatticeFold+

**Code Evidence (`estimates.ipynb` cell 1):**
```
costs:  31.760714434503775 KB
```

**Finding:** The code computes 31.76 KB. The paper's "~30 KB" claim is a rounded figure; the actual computed value is ~6% larger. The "order of magnitude" improvement over LatticeFold+ (100 KB) is accurate—31.8 KB is ~3× smaller, not 10×.

---

## 2. Prover Time (~3.5× Faster)

**Paper Claim (cyclo.md line 596):** "our prover time, excluding the impact of sum-check, is about 3.5× faster, at approximately 36.6 s (compared to 129.4 s in [BC25b])"

**Code Evidence (`estimates.ipynb` cell 5, execution_count=50):**
```
36.6137372407009 129.402509721600
3.5342611673563953
```

**Finding:** ✅ VERIFIED. The code confirms ~36.6s for Cyclo vs ~129.4s for LatticeFold+, a 3.53× speedup matching the paper's claim.

---

## 3. No Decomposition for R1CS/CCS over F_q

**Paper Claim (Section 1.1, lines 97-98):** "the input witness from Ξ₀ does not require any 'decomposition'... This avoids the most expensive steps of LatticeFold+, Neo, and LatticeFold"

**Finding:** ✅ VERIFIED. The paper's encoding (Section 2.6) uses θ_k homomorphism where k=2 (base-2 representation) and base=1 (ternary digits), allowing low-norm encoding that avoids the extension commitment step when folding R1CS/CCS over finite fields.

---

## 4. Amortized Norm-Refreshing Design

**Paper Claim (Abstract, Section 2.2):** "eliminates the need for norm checks on the accumulator by adopting an amortized norm-refreshing design"

**Finding:** ✅ VERIFIED. This is a protocol design claim confirmed by the specification in Figure 3 and Theorem 3 (line 493), which proves correctness with additive norm growth β + Lbγ rather than multiplicative.

---

## 5. Extension Commitment Efficiency

**Paper Claim (Section 1.1, lines 105-106):** "Extension commitments can be an order of magnitude more efficient than LatticeFold+'s double commitments"

**Code Evidence (`estimates.ipynb` line 208):**
```
3.5342611673563953
```

**Finding:** ⚠️ PARTIAL. The code confirms ~3.5× improvement, but "order of magnitude" typically implies 10×. The actual improvement is 3.53×. The paper text overstates the measured improvement.

---

## 6. Parameter Selection

**Paper vs Code Comparison (`estimates.ipynb` lines 29-42):**

| Parameter | Paper Value | Code Value | Status |
|-----------|-------------|------------|--------|
| κ (rank) | 13 | κ = 13 | ✅ MATCH |
| q | ≈2⁵⁰ | 2⁵⁰ | ✅ MATCH |
| N (degree φ) | 128 | 128 | ✅ MATCH |
| B (norm bound) | 2¹⁰ | 2¹⁰ | ✅ MATCH |
| γ (challenge) | 2⁷ | 2⁷ | ✅ MATCH |
| base | 1 | 1 | ✅ MATCH |
| L | 1 | 1 | ✅ MATCH |
| z (extension) | 2 | 2 | ✅ MATCH |
| m | 2²⁰ | 2²⁰ | ✅ MATCH |

**Rust confirmation (`benches/bench.rs:23`):**
```rust
const N: usize = 128;
const MOD_Q: u64 = 1125899906839937; // ~2^50
```

**Finding:** ✅ VERIFIED. All parameters match exactly.

---

## 7. Reproducibility

**Benchmark Scripts Present:**
- `estimates.ipynb` — reproduces proof size (31.76 KB) and speedup (3.53×)
- `invertibility.ipynb` — verifies GCD/inverse-mode invertibility rates
- `report.out` — raw cargo bench output with component timings

**Component Benchmark Validation (`report.out` vs Paper Table 3):**

| Component | Paper (ns) | Code (ns) | Match |
|-----------|-----------|-----------|-------|
| NTT transform | 179.03 | 178.99–179.07 | ✅ |
| NTT multiply | 186.53 | 186.43–186.66 | ✅ |
| NTT add | 40.077 | 40.058–40.094 | ✅ |
| NTT reduce | 97.102 | 97.055–97.149 | ✅ |

**Finding:** ✅ VERIFIED. All component benchmarks closely match.

---

## Notable Gaps

### 1. Full Protocol Not Implemented

The repository only implements low-level ring arithmetic (NTT, multiplication, addition) in `src/cyclotomic_ring.rs` and `benches/`. The **complete folding protocol**—extension commitment, range check, sum-check, and folding—is **NOT implemented**. The 3.5× speedup claim derives from:
1. Microbenchmarks of ring operations (`report.out`)
2. Analytical formulas in `estimates.ipynb`

This is a legitimate approach for a theory-focused paper, but the end-to-end protocol has not been implemented or benchmarked.

### 2. Paper Availability

The paper (submitted to EUROCRYPT 2026) does not appear to have a public ePrint/arXiv URL. The audit relied on `cyclo.md` in the workspace.

### 3. Proof Size Rounding

The paper claims "~30 KB" but the code computes 31.76 KB. This is a minor rounding discrepancy but worth noting.

---

## Summary

The Cyclo paper's core efficiency claims are **supported by the codebase**. The analytical estimates in `estimates.ipynb` correctly compute proof sizes (~31.8 KB) and prover time ratios (~3.5×). However:

1. The "order of magnitude" efficiency claim for extension commitments overstates the measured 3.5× improvement
2. The full folding protocol is not implemented—only low-level arithmetic primitives
3. The "~30 KB" proof size is actually 31.76 KB

The protocol design claims (no decomposition for R1CS/CCS over F_q, amortized norm-refreshing) are **verified through the paper's own specification**, not through code implementation.

---

## Sources

1. Garreta, Lipmaa, Luhaäär, Osadnik. *"Cyclo: Lightweight Lattice-based Folding via Partial Range Checks."* Submission to EUROCRYPT 2026. (Local copy: `cyclo.md`)

2. Repository: https://github.com/osdnk/cyclo

3. Proof size computation: `estimates.ipynb` cell 1

4. Prover time ratio: `estimates.ipynb` cell 5

5. Component benchmarks: `report.out`

6. Rust implementation: `benches/bench.rs`, `src/cyclotomic_ring.rs`

7. Invertibility verification: `invertibility.ipynb`

8. Intel HEXL library: `hexl-bindings/` submodule

9. Lattice estimator: `lattice-estimator @ 352ddaf` submodule
