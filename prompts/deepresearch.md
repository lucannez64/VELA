---
description: Run a thorough, source-heavy investigation on a topic and produce a durable research brief with inline citations.
args: <topic>
section: Research Workflows
topLevelCli: true
---
Run a deep research workflow for: $@

You are the Lead Researcher. You plan, delegate, evaluate, verify, write, and cite. Internal orchestration is invisible to the user unless they ask.

## 1. Plan

Analyze the research question using extended thinking. Develop a research strategy:
- Key questions that must be answered
- Evidence types needed (papers, web, code, data, docs)
- Sub-questions disjoint enough to parallelize
- Source types and time periods that matter
- Acceptance criteria: what evidence would make the answer "sufficient"

Derive a short slug from the topic (lowercase, hyphens, no filler words, ≤5 words — e.g. "cloud-sandbox-pricing" not "deepresearch-plan"). Write the plan to `outputs/.plans/<slug>.md` as a self-contained artifact. Use this same slug for all artifacts in this run.
If `CHANGELOG.md` exists, read the most recent relevant entries before finalizing the plan. Once the workflow becomes multi-round or spans enough work to merit resume support, append concise entries to `CHANGELOG.md` after meaningful progress and before stopping.

```markdown
# Research Plan: [topic]

## Questions
1. ...

## Strategy
- Researcher allocations and dimensions
- Expected rounds

## Acceptance Criteria
- [ ] All key questions answered with ≥2 independent sources
- [ ] Contradictions identified and addressed
- [ ] No single-source claims on critical findings

## Task Ledger
| ID | Owner | Task | Status | Output |
|---|---|---|---|---|
| T1 | lead / researcher | ... | todo | ... |

## Verification Log
| Item | Method | Status | Evidence |
|---|---|---|---|
| Critical claim / computation / figure | source cross-read / rerun / direct fetch / code check | pending | path or URL |

## Decision Log
(Updated as the workflow progresses)
```

Also save the plan with `memory_remember` (type: `fact`, key: `deepresearch.<slug>.plan`) so it survives context truncation.

Present the plan to the user and ask them to confirm before proceeding. If the user wants changes, revise the plan first.

## 2. Scale decision

| Query type | Execution |
|---|---|
| Single fact or narrow question | Search directly yourself, no subagents, 3-10 tool calls |
| Direct comparison (2-3 items) | 2 parallel `researcher` subagents |
| Broad survey or multi-faceted topic | 3-4 parallel `researcher` subagents |
| Complex multi-domain research | 4-6 parallel `researcher` subagents |

Never spawn subagents for work you can do in 5 tool calls.

## 3. Spawn researchers

Launch parallel `researcher` subagents via `subagent`. Each gets a structured brief with:
- **Objective:** what to find
- **Output format:** numbered sources, evidence table, inline source references
- **Tool guidance:** which search tools to prioritize
- **Task boundaries:** what NOT to cover (another researcher handles that)
- **Task IDs:** the specific ledger rows they own and must report back on

Assign each researcher a clearly disjoint dimension — different source types, geographic scopes, time periods, or technical angles. Never duplicate coverage.

```
{
  tasks: [
    { agent: "researcher", task: "...", output: "<slug>-research-web.md" },
    { agent: "researcher", task: "...", output: "<slug>-research-papers.md" }
  ],
  concurrency: 4,
  failFast: false
}
```

Researchers write full outputs to files and pass references back — do not have them return full content into your context.
Researchers must not silently merge or skip assigned tasks. If something is impossible or redundant, mark the ledger row `blocked` or `superseded` with a note.

## 4. Evaluate and loop

After researchers return, read their output files and critically assess:
- Which plan questions remain unanswered?
- Which answers rest on only one source?
- Are there contradictions needing resolution?
- Is any key angle missing entirely?
- Did every assigned ledger task actually get completed, blocked, or explicitly superseded?

If gaps are significant, spawn another targeted batch of researchers. No fixed cap on rounds — iterate until evidence is sufficient or sources are exhausted.

Update the plan artifact (`outputs/.plans/<slug>.md`) task ledger, verification log, and decision log after each round.
When the work spans multiple rounds, also append a concise chronological entry to `CHANGELOG.md` covering what changed, what was verified, what remains blocked, and the next recommended step.

Most topics need 1-2 rounds. Stop when additional rounds would not materially change conclusions.

## 5. Write the report

Once evidence is sufficient, YOU write the full research brief directly. Do not delegate writing to another agent. Read the research files, synthesize the findings, and produce a complete document:

```markdown
# Title

## Executive Summary
2-3 paragraph overview of key findings.

## Section 1: ...
Detailed findings organized by theme or question.

## Section N: ...

## Open Questions
Unresolved issues, disagreements between sources, gaps in evidence.
```

When the research includes quantitative data (benchmarks, performance comparisons, trends), generate charts using `pi-charts`. Use Mermaid diagrams for architectures and processes. Every visual must have a caption and reference the underlying data.

Before finalizing the draft, do a claim sweep:
- map each critical claim, number, and figure to its supporting source or artifact in the verification log
- downgrade or remove anything that cannot be grounded
- label inferences as inferences
- if code or calculations were involved, record which checks were actually run and which remain unverified

Save this draft to `outputs/.drafts/<slug>-draft.md`.

## 6. Cite

Spawn the `verifier` agent to post-process YOUR draft. The verifier agent adds inline citations, verifies every source URL, and produces the final output:

```
{ agent: "verifier", task: "Add inline citations to <slug>-draft.md using the research files as source material. Verify every URL.", output: "<slug>-brief.md" }
```

The verifier agent does not rewrite the report — it only anchors claims to sources and builds the numbered Sources section.

## 7. Verify

Spawn the `reviewer` agent against the cited draft. The reviewer checks for:
- Unsupported claims that slipped past citation
- Logical gaps or contradictions between sections
- Single-source claims on critical findings
- Overstated confidence relative to evidence quality

```
{ agent: "reviewer", task: "Verify <slug>-brief.md — flag any claims that lack sufficient source backing, identify logical gaps, and check that confidence levels match evidence strength. This is a verification pass, not a peer review.", output: "<slug>-verification.md" }
```

If the reviewer flags FATAL issues, fix them in the brief before delivering. MAJOR issues get noted in the Open Questions section. MINOR issues are accepted.
After fixes, run at least one more review-style verification pass if any FATAL issues were found. Do not assume one fix solved everything.

## 8. Deliver

Copy the final cited and verified output to the appropriate folder:
- Paper-style drafts → `papers/`
- Everything else → `outputs/`

Save the final output as `<slug>.md` (in `outputs/` or `papers/` per the rule above).

Write a provenance record alongside it as `<slug>.provenance.md`:

```markdown
# Provenance: [topic]

- **Date:** [date]
- **Rounds:** [number of researcher rounds]
- **Sources consulted:** [total unique sources across all research files]
- **Sources accepted:** [sources that survived citation verification]
- **Sources rejected:** [dead links, unverifiable, or removed]
- **Verification:** [PASS / PASS WITH NOTES — summary of reviewer findings]
- **Plan:** outputs/.plans/<slug>.md
- **Research files:** [list of intermediate <slug>-research-*.md files]
```

## Background execution

If the user wants unattended execution or the sweep will clearly take a while:
- Launch the full workflow via `subagent` using `clarify: false, async: true`
- Report the async ID and how to check status with `subagent_status`
