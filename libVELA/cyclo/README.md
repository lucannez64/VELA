# zig-ring-arithmetic

A Zig implementation of the **Cyclo** lattice-based folding protocol — a lightweight construction for succinct zero-knowledge proofs based on the Ring Short Integer Solution (Ring-SIS) problem.

This library implements the core arithmetic and protocol described in:

> *Cyclo: Lightweight Lattice-based Folding via Partial Range Checks*
> Garreta, Lipmaa, Luhaäär, and Osadnik

The paper is included in this repository as [`cyclo.md`](cyclo.md) and [`cyclo.pdf`](cyclo.pdf).

---

## What is Cyclo?

Cyclo is a folding scheme for lattice-based proof systems. Unlike pairing-based SNARKs, Cyclo's security relies only on the hardness of Ring-SIS — a well-studied lattice assumption that is believed to be resistant to quantum attacks.

**Key properties:**
- Security from Ring-SIS (quantum-resistant)
- Supports R1CS and CCS (Customizable Constraint Systems) circuits
- Efficient polynomial arithmetic via NTT acceleration
- Fiat-Shamir compiled to non-interactive proofs
- Automatic parameter generation targeting 128-bit security

---

## Prerequisites

- **Zig 0.15.2+** — [ziglang.org](https://ziglang.org/download/)
- **Rust (stable)** — required to compile the NTT shim at build time

---

## Building

```sh
zig build
```

This compiles the library and runs `cargo build` for the internal NTT shim automatically. The shim is a thin Rust wrapper around the `tfhe-ntt` library that provides SIMD-accelerated Number Theoretic Transforms.

---

## Running

```sh
# Basic demo: prove y = (x+z)^2 + z + 1
zig build run

# Anonymous electronic voting example
zig build run-vote

# Anonymous ticket spend (Ring-SIS commitment based)
zig build run-ticket

# Merkle tree spend proof with Griffin hash
zig build run-griffin

# Group governance circuit
zig build run-group-governance

# Benchmark: schoolbook vs NTT multiplication
zig build bench
```

---

## Testing

```sh
# Full test suite
zig build test

# Filter to specific tests
zig build test -- --test-filter "NTT"
zig build test -- --test-filter "Ring"

# With deterministic seed
zig build test -- --seed 0xdeadbeef
```

---

## Library Usage

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .zig_ring_arithmetic = .{
        .path = "path/to/zig-ring-arithmetic",
    },
},
```

Then import in your `build.zig`:

```zig
const ring_arith = b.dependency("zig_ring_arithmetic", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("zig_ring_arithmetic", ring_arith.module("zig_ring_arithmetic"));
```

---

## Core Concepts

### Ring Arithmetic

The fundamental algebraic structure is the cyclotomic ring **Z_q[X]/(X^N + 1)**, parameterized by degree `N` and modulus `q`:

```zig
const std = @import("std");
const lib = @import("zig_ring_arithmetic");
const Ring = lib.Ring;

const Q = 1125899906839937;
const R = Ring(128, Q);

const a = R.fromCoeffs(&[_]i64{ 1, 2, 3, 0, 0, ... });
const b = R.fromCoeffs(&[_]i64{ 0, 1, 0, 1, 0, ... });
const c = a.mul(b);  // negacyclic convolution mod X^128 + 1
const d = a.add(b);
const e = a.sub(b);
```

The ring supports:
- Addition, subtraction, negation
- Schoolbook and NTT-accelerated multiplication
- Scalar multiplication, inner products
- Decomposition into small-coefficient representations
- Dual basis transforms (for Ajtai commitments)

### NTT Acceleration

For large rings, polynomial multiplication is accelerated via Number Theoretic Transform:

```zig
const lib = @import("zig_ring_arithmetic");
const NttMul = lib.NttMul;
const NttDomain = lib.NttDomain;

var plan = NttMul(128, Q).init();
defer plan.deinit();

const a_ntt = NttDomain(128, Q).init(&plan, a);
const b_ntt = NttDomain(128, Q).init(&plan, b);
const c_ntt = a_ntt.mul(b_ntt, &plan);
const c = c_ntt.toRing(&plan);
```

NTT mode is supported for:
- Native 64-bit arithmetic (`Q = 0`)
- Prime moduli satisfying `Q ≡ 1 mod 2N`

### Proving with R1CS

Define a circuit as an R1CS relation and generate a proof:

```zig
const lib = @import("zig_ring_arithmetic");
const CycloProtocol = lib.CycloProtocol;
const autoParams = lib.autoParams;

const Q = 1125899906839937;
const Protocol = CycloProtocol(128, Q);

// Build relation: a * b = c for each constraint
var relation = Protocol.R1csRelation{ ... };

// Auto-generate secure parameters
const params = try autoParams(allocator, relation.numConstraints(), relation.numVariables());

// Prove
const statement = Protocol.Statement{
    .relation = relation,
    .public_assignment = public_inputs,
};
const witness = Protocol.Witness{
    .private_assignment = private_inputs,
};
var proof = try Protocol.proveFromStatement(allocator, statement, witness, params);
defer proof.deinit(allocator);

// Verify
const ok = try Protocol.verifyFromStatement(allocator, statement, &proof, params);
```

### Ajtai Commitments

The library provides Ajtai-style lattice commitments:

```zig
const AjtaiMatrix = lib.AjtaiMatrix;

// Commit to a vector of ring elements
const matrix = AjtaiMatrix(128, Q, rows, cols).fromSeed(seed);
const commitment = matrix.commit(witness_vector);

// Verify commitment opens to the same witness
const ok = matrix.verify(commitment, witness_vector);
```

---

## Examples

### Electronic Voting

[`examples/electronic_vote.zig`](examples/electronic_vote.zig) demonstrates privacy-preserving anonymous voting:

- Voters hold `(ballot, secret, serial)` tuples
- An issuer publishes commitments derived from a seed via SHAKE-256
- A voter proves:
  - Their commitment is correctly derived from their values
  - Their ballot is binary (0 or 1)
  - Their nullifier is correctly computed (preventing double-voting)
  - The tally equals the sum of all valid ballots
- **Circuit**: 9 public inputs, 30 private, 10 constraints

### Anonymous Ticket Spend

[`examples/anonymous_ticket_spend.zig`](examples/anonymous_ticket_spend.zig) demonstrates an anonymous ticket system:

- Tickets have (serial, secret, class, expiry) attributes
- An Ajtai commitment replaces a Merkle tree for membership proofs
- A spender proves ticket validity and authorization without revealing identity
- Double-spend prevention via nullifiers
- **Circuit**: 6 public inputs, 11 private, 12 constraints

### Griffin Merkle Spend

[`examples/griffin_merkle_spend.zig`](examples/griffin_merkle_spend.zig) demonstrates a Merkle tree membership proof using the Griffin hash function:

- Griffin permutation: 3-state, 6-round, x³ S-box
- 2-level Merkle tree with 37 constraints per hash node
- Proves set membership without revealing the leaf
- **Circuit**: 6 public inputs, 32 private, 74 constraints (2 Griffin hashes)

### Group Governance

[`examples/group_governance.zig`](examples/group_governance.zig) demonstrates anonymous group decision-making:

- Members prove membership and cast votes without revealing identity
- Threshold-based governance logic encoded as R1CS constraints

---

## Project Structure

```
zig-ring-arithmetic/
├── src/
│   ├── root.zig           # Main library (~12k lines)
│   │                        Ring, NttDomain, Fq2, AjtaiMatrix,
│   │                        CycloProtocol, SumCheckProver, autoParams, ...
│   ├── ring_ntt.zig       # NTT acceleration (Rust FFI wrapper)
│   ├── main.zig           # Demo program
│   ├── bench.zig          # Multiplication benchmarks
│   ├── test_matrix.zig    # Matrix-vector multiplication tests
│   └── compat_msvc.zig    # Windows compatibility
├── examples/
│   ├── electronic_vote.zig
│   ├── anonymous_ticket_spend.zig
│   ├── griffin_merkle_spend.zig
│   ├── group_governance.zig
│   └── bisect_test.zig    # Binary search for failure thresholds
├── ntt_shim/              # Rust subproject (tfhe-ntt wrapper)
│   ├── Cargo.toml
│   └── src/lib.rs
├── build.zig
├── build.zig.zon
├── cyclo.md               # Full protocol paper
└── cyclo.pdf
```

---

## Key Types Reference

| Type | Description |
|------|-------------|
| `Ring(N, Q)` | Polynomial ring Z_q[X]/(X^N + 1) |
| `NttMul(N, Q)` | NTT multiplication plan (holds precomputed twiddle factors) |
| `NttDomain(N, Q)` | Polynomial in NTT representation |
| `NttDomainFq2(N, Q, beta)` | Extension field NTT domain |
| `Fq2(q, beta)` | Quadratic field extension F_q^2 |
| `RingWithOps(N, F, ops)` | Generic ring over arbitrary field `F` |
| `AjtaiMatrix(N, Q, rows, cols)` | Ajtai commitment matrix |
| `ExtensionCommitment(...)` | Decomposition-based commitment for norm reduction |
| `CycloProtocol(N, Q)` | Main Cyclo prover/verifier |
| `CycloR1csRelation` | R1CS constraint system (a·b = c) |
| `CycloCcsRelation` | Generalized CCS constraint system |
| `SumCheckProver(Q, deg)` | Multivariate sum-check prover |
| `RangeTestSumCheck(Q, b)` | Range bound verifier |
| `LatticeEstimator` | BKZ-based security estimator |
| `autoParams()` | Automatic secure parameter generation |

---

## Parameter Generation

The library can automatically size cryptographic parameters to achieve a target security level:

```zig
const params = try autoParams(allocator, num_constraints, num_variables);
// Returns parameters targeting 128-bit security against BKZ attacks
```

For manual control, use the `PRESET_128` constant or construct `CycloParams` directly.

The `LatticeEstimator` evaluates BKZ attack cost using the standard core-SVP methodology, accounting for ring degree, modulus, and witness norm bounds.

---

## Security Notes

- Security is based on the hardness of **Ring-SIS** (Ring Short Integer Solution)
- Parameters are sized against **BKZ attacks** using conservative cost models
- The Fiat-Shamir transform uses **SHAKE-256** for transcript hashing
- All proofs are **deterministically reproducible** given the same randomness seed
- This is a **research implementation** — it has not undergone security audits and should not be used in production systems without independent review

---

## License

See [LICENSE](LICENSE) if present, or contact the authors.
