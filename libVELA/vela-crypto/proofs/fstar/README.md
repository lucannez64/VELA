# Checked share-admission fact construction

From repository root with the pinned hax/F*/Z3 tools on PATH:

```bash
security/assurance/bounded.sh libVELA/vela-crypto/verify-share-facts-fstar.sh
```

The runner checks 19 selected policy postconditions and 24 crypto contracts.
The crypto scope includes fact construction, decoded-observation/policy
composition, hybrid verification gates, fixed-width arithmetic, exact LP/u64
splitting, mutable/grouped cursor readers, the full raw byte-frame parser's
refinement to a functional grammar, three opened-share accessors, exact signed-body slicing and domain concatenation.

The production opener uses the checked byte parser. OpenedShare fields are
private, with compiler-negative tests for construction/mutation. Its read-only
methods delegate to the checked free-function kernels. See the
[precise boundary](../../../../security/assurance/11-parser-refinement.md).

There is no lax checking, admitted body or local assumption declaration in
these generated modules. Imported models remain trusted. UTF-8 conversion,
encoder inverse, complete authenticated-opening composition, primitive wrappers,
recipient-key provenance, context origins and persistent effects still need
separate refinement. These checks do not establish complete authenticated
opening or computational construction security.

## Explicit compatibility model

`models/Alloc.String.fst` copies the hax-lib 0.3.7 `Alloc.String` model verbatim
and adds the defined view:

```fstar
let impl_String__as_str (self: t_String) : string = self._0
```

Upstream source is `proof-libs/fstar/core/Alloc.String.fst` from the pinned
hax-lib 0.3.7 crate (hax project: https://github.com/cryspen/hax). The base
model represents owned strings as a wrapper around an F* string; the extra
view unwraps it for borrowed comparisons. The pinned upstream prelude lacks
this function: extraction without `.as_str()` produced an owned/borrowed type
mismatch, and extraction with it needed the view. The definition adds no axiom,
but its correspondence to Rust standard-library String semantics is manually
trusted. A matching Rust String implementation has not been formally verified.
The local model directory has include precedence and is covered by the artifact
manifest and assumption gate. Do not silently patch generated extractions.

These checks depend on all documented hax/F*/Z3 and imported-library
assumptions. They are a checked fact-construction contract, not a whole-handler
or computational-security proof.

## Defined Vec subset

`models/Alloc.Vec.fst` retains the pinned hax sequence representation and the
empty constructor, length, slice view and sequence-append extension body. The
upstream extension's Pure postcondition True hides the output bytes. This
subset gives its capacity requirement as an argument refinement and its exact
concatenation, length and prefix/suffix as result refinements, discharged using
F★ sequence lemmas. No axiom is added. Its correspondence to Rust std, allocation
and termination behavior remain trusted or excluded as documented in the
[transcript mapping](../../../../security/assurance/12-authenticated-transcript.md).
The source/extraction gate counts 24 crypto postconditions separately from
these library refinements.
