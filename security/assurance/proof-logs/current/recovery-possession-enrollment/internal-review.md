# Internal recovery review and response

A read-only delegated review of `de28258` and `ae3528b`, against `5fa4e9f`,
found no live behavior bug in the reviewed paths. This is internal model/code
review, not an external audit or an independent proof rerun.

Parent responses:

- Historical crate-level logs now explicitly name the delegated worktree and
  distinguish its six-observation-test snapshot from the parent's seven-test
  snapshot. The old gate-failure handoff is marked superseded; totals are 212/219.
- The 42-contract document is labelled as a historical increment. Store-key user
  binding is distinguished from an independently verified identity comparison
  in source comments and the crate README.
- The final possession insert and race recheck now reject empty commitment
  text, matching the canonical storage path's non-empty commitment condition.
- Final policy denial leaves a consumed grant consumed. It does not restore
  a full TTL as though authorization denial were a transient storage failure.
- Enrollment's negative policy branches are precluded by the current handler's
  early returns; that asymmetry is documented, not claimed as handler refinement.
- The no-share-release permit accessor is definitionally false; it is not a
  theorem about effects performed by the handler.
- Boundary tests pin the normative key sizes. Server compilation checks recovery
  policy lengths against the enrollment policy and actual crypto wire constants.

`review-policy-tests.log` records six policy and seven observation tests after
the constant-tripwire changes. `review-integration-tests.log` records three
passing possession/grant HTTP tests after the SQL/recheck/terminal-denial
changes. The existing 71 F★ contracts' executable policy definitions are
unchanged by this follow-up (the policy-source edit is documentation only).

The full-state gaps in document 15 remain open, including early-return/effect
traces, source decoding, SQL/store semantics, grant restoration and permanent
revocation across deletion/restaging. No full F-1/F-2 closure is claimed.
