# Hosted evidence: 350cd57

The [security workflow](https://github.com/lucannez64/VELA/actions/runs/40089709666)
passed on `350cd57001cc0a7c3c250ef33193f99ad670eec3`.
`workflow.json` records GitHub's head SHA, conclusion and all five security job
conclusions/URLs. T3 also reported all fifteen PR checks passed at this head.

`security-excerpt.log` is a selected excerpt of `gh run view --log`, preserving
step labels and timestamps, not a full proof transcript. It records the
13-artifact / 212-postcondition / zero-local-assume-val census, six positive
CryptoVerif game verdicts plus the explicit legacy nonproof, the share-journal
gate pass and static scan pass. The full logs and uploaded proof artifacts are
available from the linked workflow. To recover the complete console output:

```bash
gh run view 40089709666 --repo lucannez64/VELA --log
```

This snapshot includes the web-session/possession observation and nonuniform
GDH increments. It predates both the handwritten journal encoding check and
the enrollment preflight/independent-ordering increments. It does not validate
the newer 231-postcondition corpus. Passing the hosted gates establishes only
the documented scoped results, not whole-system correctness or an external
audit. No proof-tool execution was repeated to produce this evidence index.
