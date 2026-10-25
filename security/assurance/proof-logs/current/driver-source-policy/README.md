# Focused-driver source policy

The existing enrollment-redemption, possession-recovery and sharing driver gates
now use one lexer-aware source check instead of a grep limited to assume/admit.
It strips nested F* comments, handles strings and closed character literals, rejects proof escapes (including
axioms and expected-failure attributes), bare declarations and unreviewed source
options. Only the exact hax fuel/solver-budget header and the reviewed balanced
fuel-only composition scopes are allowed. These options set proof-search budgets;
they do not permit admitting goals.

All six current extracted driver modules and six handwritten per-request/
composition modules pass unchanged. Twelve Python regression tests exercise real
artifacts, mixed/nested comment bypasses, axioms, source admission options,
repeated headers, balanced scopes, malformed comments/strings, char-literal
quote-parity bypasses, unexpected sibling modules/interfaces, verifier-cwd imports,
and UTF-8 under a C locale. The guard explicitly checks every local source include
directory and refuses unlisted F* sources; imported proof-library directories remain
trusted. CI runs the
regressions. No F* source or Rust semantics changed; existing proof results retain
their scope. This source gate does not constitute a soundness certificate, a
semantic correspondence proof, or a complete defense against all tool misuse.


Focused internal review found no blockers in the initial change, then identified
three completeness issues: extra composition/interface files could bypass argv
scanning, character literals could shift the string lexer, and locale-dependent
reads rejected Unicode comments. These are corrected with local include-directory
inventory checks, character-literal handling and explicit UTF-8. The regression
suite now covers each reported case. This is still not a full F* parser or a
semantic proof certificate.
