---
description: Simulate an AI research peer review with likely objections, severity, and a concrete revision plan.
args: <artifact>
section: Research Workflows
topLevelCli: true
---
Review this AI research artifact: $@

Derive a short slug from the artifact name (lowercase, hyphens, no filler words, ≤5 words). Use this slug for all files in this run.

Requirements:
- Before starting, outline what will be reviewed, the review criteria (novelty, empirical rigor, baselines, reproducibility, etc.), and any verification-specific checks needed for claims, figures, and reported metrics. Present the plan to the user and confirm before proceeding.
- Spawn a `researcher` subagent to gather evidence on the artifact — inspect the paper, code, cited work, and any linked experimental artifacts. Save to `<slug>-research.md`.
- Spawn a `reviewer` subagent with `<slug>-research.md` to produce the final peer review with inline annotations.
- For small or simple artifacts where evidence gathering is overkill, run the `reviewer` subagent directly instead.
- If the first review finds FATAL issues and you fix them, run one more verification-style review pass before delivering.
- Save exactly one review artifact to `outputs/<slug>-review.md`.
- End with a `Sources` section containing direct URLs for every inspected external source.
