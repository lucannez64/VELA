# Collision side conditions for the nonuniform X25519 KEM game

Round-2 response to the medium review of
`security/formal/cryptoverif/kem_v2_x25519_gdh_nonuniform.ocv`.

**Verdict.** For the single-recipient, single-challenge game as written, the two
`PCollKey` charges are conservative upper bounds on the branches CryptoVerif
removes. The justification is a case split on when a decapsulation or hash query
was made, plus the challenge-pair `yield` guard and the freshness of the
challenge scalar. It is **not** the claim that `PCollKey` bounds an adaptive
collision with the published `epk = g^y`.

The concrete X25519 clamp/cofactor/encoding bridge remains open. This note
narrows the collision claim; it does not close the concrete distribution
instantiation.

## Machine-checked statement

The retained proof log gives:

```text
RESULT Proved bit secrecy of b up to probability
  4 * pDistRerandom + 2 * pGDH(time_1, 2 * qH)
  + (2 * Qd + 2 * qH) * PCollKey
RESULT time_1 = (1 + Qd) * time(mlpkgen) + time(mlencap_ct)
  + time(mlencap_ss) + Qd * time(mldecap) + time + 3 * time(exp)
All queries proved.
```

The proof applies the collision statement

```text
collision x <-R Z; forall Y: G;
  return(exp(g, x) = Y) <=(PCollKey)=> return(false)
  if Y independent-of x
```

twice:

| log line | instantiation | printed probability | branch removed |
|---|---|---|---|
| `kem_v2_x25519_gdh_nonuniform.log:18`, `:248` | `x -> y`, `Y -> epkq` | `PCollKey * Qd` | challenge lookup over decapsulation entries; decapsulation lookup over the challenge entry |
| `kem_v2_x25519_gdh_nonuniform.log:25`, `:400` | `x -> y`, `Y -> exp(g, y-indep)` | `PCollKey * qH` | challenge lookup over random-oracle entries |

The factor two between these two charges and the final `2*Qd + 2*qH`
coefficient is the bit-secrecy/advantage conversion in the printed `Adv[...]`
formula, not a third collision event.

## Why the naive independence reading is wrong

If one reads the first instantiation as an unconditional statement about the
adversary's decapsulation input, it is false: after the challenge, the adversary
sees `epk = g^y` and may submit `epkq = epk`. The CryptoVerif side condition
`epkq independent-of y` is syntactic and does not by itself establish semantic
independence. We do not use it that way.

The actual argument for this game uses the query-order facts below. The debug
log retained here contains the guard facts and the instantiated collisions; it
is not a replacement for the case analysis.

## The `Qd * PCollKey` charge

Let the unique challenge call generate `y`, `epk = g^y`, `ctm`, `pkm`, `ssm`
and the challenge Diffie-Hellman value `D = g^(x*y)`. For a decapsulation query
`i` with inputs `(ctq_i, epkq_i)`, the oracle's guard is

```text
if defined(ctm, epk) && ctq_i = ctm && epkq_i = epk then yield else ...
```

so a query that is made after the challenge and matches both challenge
components produces no table entry.

The challenge lookup executes inside the unique challenge call, before the
challenge returns. Therefore every decapsulation entry it can see was created by
a query made before the challenge. Such a query saw `defined(ctm, epk)` false,
so its guard did not yield. The removed branch matches a decapsulation entry
only if `ctq_i = ctm` and `epkq_i = epk`; in particular it requires
`epkq_i = g^y`. At the time query `i` was made, `y` did not exist; `epkq_i` is
fixed by the pre-challenge transcript and is independent of the not-yet-sampled
`y`. Conditioned on that transcript, the probability that `epkq_i = g^y` is at
most `PCollKey`, by the collision statement with `x = y` and `Y = epkq_i`. The
other equalities in the branch (`ctq_i = ctm`, `ssm = mldecap(...)`,
`D = exp(epkq_i, x)`, etc.) can only shrink the event. A union bound over the at
most `Qd` pre-challenge queries gives `Qd * PCollKey`.

The second removed branch, the decapsulation oracle's lookup of the challenge
entry, is empty: if the decapsulation query is made before the challenge, the
challenge entry is undefined; if it is made after the challenge, either it
matches both `ctq_i = ctm` and `epkq_i = epk`, in which case the guard yields
and the entry is not defined, or at least one component differs and the branch
condition fails. It is covered by the same `Qd * PCollKey` budget.

Debug evidence for the guard facts:

```text
debug.log:1301  Obtained a contradiction.
debug.log:1302  Found a usable term: not(((ctq[ri_5] = ctm) && (epkq[ri_5] = epk)))
...
debug.log:1609  Obtained a contradiction.
debug.log:1610  Found a usable term: not(((ctq[ri_5] = ctm) && (epkq[ri_5] = epk)))
debug.log:1614  Applied collision ... with x_1 -> y, Y -> epkq Probability: PCollKey * Qd
```

Thus the first charge is conservative: the post-challenge adaptive
`epkq = epk` case is excluded by the guard, and the pre-challenge case is
bounded by freshness plus `PCollKey`. No unconditional adaptive-collision
statement is used.

## The `qH * PCollKey` charge

The challenge's lookup over random-oracle entries is a snapshot taken during the
unique challenge call, before `epk` is returned. Only random-oracle queries made
before that call can be in the snapshot; later queries cannot be seen by this
lookup.

A matching entry `j` must satisfy `x3_j = epk = g^y` (it also requires
`x1_j = ssm`, `x2_j = D`, `x4_j = X`, `x5_j = ctm`, `x6_j = pkm`). The third
input `x3_j` was fixed before `y` was sampled and is independent of `y`; the
other equalities only shrink the event. Therefore, for each of the at most `qH`
pre-challenge queries,

```text
Pr[x3_j = g^y] <= PCollKey,
```

and a union bound gives `qH * PCollKey`. The debug log shows the independent-copy
instantiation directly:

```text
debug.log:1892  Occ = 106 :
debug.log:1893  Substitutions:
debug.log:1894  (epkq = exp(g, y))
debug.log:1895  (ctq = mlencap_ct(pkm, s))
...
debug.log:1901  Applied collision ... with x_1 -> y,
                Y -> exp(g, y-indep) Probability: PCollKey * qH
```

The surrounding `epkq = exp(g, y)` substitution is the else-find/guard context.
The branch removed by this charge is the challenge's random-oracle lookup,
whose condition includes `x3 = epk`; in the instantiated collision the
right-hand side is the independent copy `exp(g, y-indep)`, which is the
freshness form of that equality. This is not an adaptive `epkq` collision. The
transformation header in the same debug log is
`debug.log:2928` (`Applying simplify [probability qH * PCollKey]`), and
`debug.log:2935` records that it removes `branch 1 in find at 42`, i.e. the
challenge's random-oracle lookup. The corresponding `Qd` transformation is at
`debug.log:2776-2779` (`Applying expand [probability Qd * PCollKey]`, removing
branch 1 in finds 183 and 51).

A random-oracle query made *after* the challenge may of course choose
`x3 = epk` with probability one. That query is not in the challenge's snapshot,
so it is not what the `qH * PCollKey` term bounds. It remains in the game until
the GDH step, where the matching condition also contains the CDH test
`x2 = g^(x*y)`. The GDH equivalence replaces that test by `false` (visible in
Game 12 as `(m_2: G <- x2; false)`) and charges `pGDH(time_1, 2*qH)`. The branch
is then removed for free. The adaptive published-`epk` hash query is therefore
handled by the GDH/CDH term, not by `PCollKey`.

## `PCollKey`, `PColl1Rand`, and the clamped set

For the clamped Curve25519 distribution the HPKE material states
`PColl1Rand(Z) = 2^-251` and `PCollKey = 2^-250` (two scalars per `u`-coordinate
because `u(P) = u(-P)`). Equivalently, the abstract injective-group collision
bound is `2^-251`, and the factor two to `2^-250` is a conservative encoding
allowance for `u(P) = u(-P)`. The arithmetic fact `2^-250 >= 2^-251` is a
consistency check for the instantiation; it is **not** a justification of
semantic independence, and it is not used as one above.

The model's type is `[large,bounded,nonuniform]`, which carries a separate
type-level default collision estimate `PColl1Rand(Z) <= 2^-160`
(`tysize_LARGE = 160`). The final `RESULT` contains no `PColl1Rand`,
`PColl2Rand`, `EpsRand`, `EpsFind`, or `1/|Z|` term; the only collision term in
the final bound is the explicit `PCollKey`. A grep of the retained proof log
for `PColl1Rand|PColl2Rand|EpsRand|EpsFind|1 / |Z|` returns no hit. The two
collision applications above are therefore the only place where the concrete
`2^-250` enters the displayed bound.

## What this does not establish

- It does not show that CryptoVerif mechanically verifies the semantic
  independence side condition. The tool accepts the syntactic condition; the
  missing semantic argument is the query-order case split in this note.
- It does not bound a post-challenge adaptive collision with the published
  `epk` by `PCollKey`. Such a collision is either excluded by the guard or
  handled by the GDH/CDH term, as described above.
- It does not close the concrete X25519 bridge: clamping correctness, the
  cofactor-8 subgroup, the `kem.rs` reject check, non-canonical `u`-coordinate
  encodings, the SHA-256 transcript bridge, and multi-user/multi-challenge
  composition remain open or argued outside the game.
- The freshness argument is specific to the single challenge and its pre-return
  lookup snapshot. A replicated challenge (or a decapsulation oracle that can
  return the challenge key after the challenge) needs a new case analysis.

## Reproduction and provenance

The retained `kem_v2_x25519_gdh_nonuniform.debug.log` was produced from the
unmodified model by prepending exactly these two debug settings:

```text
set debugSimplify = true.
set debugElsefindFacts = true.
```

Command (bounded by the required global lock/cap):

```bash
~/.local/opt/vela-tools/bin/vela-heavy timeout 600 \
  ~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/cryptoverif \
  -lib ~/.local/opt/vela-tools/src/cv/x/cryptoverif2.12/default.ocvl \
  /tmp/vela-nonuniform-round2/model-debug.ocv \
  > /tmp/vela-nonuniform-round2/debug.log 2>&1
```

Hashes at the time of the run:

```text
model:                     d85cef886c776209a68a430ad51007e3c1caa3a07e03bc5833eb9094370c5726
debug model (no settings): d85cef886c776209a68a430ad51007e3c1caa3a07e03bc5833eb9094370c5726
debug log:                 798a0449f252160acf34d83a9f455291f919f7df1dc69550f17d95280f887a75
cryptoverif binary:        582f31b301d5efbe8428924c3559454a9a63591bec41f4cf19cd28082933e130
default.ocvl:              f60c0fa4701257a57415fc256b440cffd4d2851bf25af66e62c009c0ac9e08fd
```

Stripping the two `set` lines from the debug model gives byte-for-byte the
repository model (matching SHA-256), so the debug run did not change the game.
The machine verdict remains the one in
`kem_v2_x25519_gdh_nonuniform.log`; the debug log is supporting evidence for
which collisions and side conditions were used, not a separate proof verdict.

## Bottom line

For **this** game, the two `PCollKey` charges are conservative: the `Qd` charge
covers a pre-challenge lookup bounded by freshness/`PCollKey` plus a
guard-excluded decapsulation-side lookup of the challenge entry; the `qH` charge
is a bound on pre-challenge random-oracle inputs guessing `epk`, while
post-challenge adaptive inputs remain until the GDH step. The final
machine-checked bound stands, but the concrete clamp/cofactor/encoding
instantiation and the formal reification of the query-order side condition
remain open.
