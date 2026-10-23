# Checked share-admission fact construction

From repository root with the pinned hax/F*/Z3 tools on PATH:

```bash
security/assurance/bounded.sh libVELA/vela-crypto/verify-share-facts-fstar.sh
```

The runner checks 19 selected policy postconditions and six crypto contracts:
the actual fact constructor, decoded-observation/policy composition, exact
prefix reader, and the hybrid verification AND gate with two rejection theorems.
The production `admit` path calls the checked composition; Reader calls the
checked prefix function; signing verification calls the checked gate.

There is no lax checking, admitted body or local assumption declaration in
these generated modules. Imported models remain trusted. In particular,
`Some(OpenedShare)` must come from correct authenticated opening; the proof
does not establish that the complete parser, KEM, signature wrapper or recipient
key digest check justifies that observation. Context origins, pin copying and
persistent effects also need separate refinement. Prefix splitting is checked;
a complete wire-format round-trip/injectivity proof is still missing. The
AND gate is checked, but does not supply a computational-security reduction.

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
