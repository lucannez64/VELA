# Focused-driver source policy

The existing enrollment-redemption, possession-recovery and sharing driver gates
now use one lexer-aware source check instead of a grep limited to assume/admit.
It strips nested F* comments, respects strings, rejects proof escapes (including
axioms and expected-failure attributes), bare declarations and unreviewed source
options. Only the exact hax fuel/solver-budget header and the reviewed balanced
fuel-only composition scopes are allowed. These options set proof-search budgets;
they do not permit admitting goals.

All six current extracted driver modules and six handwritten per-request/
composition modules pass unchanged. Eight Python regression tests exercise real
artifacts, mixed/nested comment bypasses, axioms, source admission options,
repeated headers, balanced scopes and malformed comments/strings. CI runs the
regressions. No F* source or Rust semantics changed; existing proof results retain
their scope. This source gate does not constitute a soundness certificate, a
semantic correspondence proof, or a complete defense against all tool misuse.
