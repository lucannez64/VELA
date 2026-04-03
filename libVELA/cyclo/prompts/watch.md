---
description: Set up a recurring or deferred research watch on a topic, company, paper area, or product surface.
args: <topic>
section: Research Workflows
topLevelCli: true
---
Create a research watch for: $@

Derive a short slug from the watch topic (lowercase, hyphens, no filler words, ≤5 words). Use this slug for all files in this run.

Requirements:
- Before starting, outline the watch plan: what to monitor, what signals matter, what counts as a meaningful change, and the check frequency. Write the plan to `outputs/.plans/<slug>.md`. Present the plan to the user and confirm before proceeding.
- Start with a baseline sweep of the topic.
- Use `schedule_prompt` to create the recurring or delayed follow-up instead of merely promising to check later.
- Save exactly one baseline artifact to `outputs/<slug>-baseline.md`.
- End with a `Sources` section containing direct URLs for every source used.
