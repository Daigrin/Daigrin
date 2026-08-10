---
description: "Daily cross-agent learning: consolidate lessons from .github/LESSONS.md, review recent sessions, and update agent/instruction files so agents learn from each other"
name: guardian-learn
argument-hint: "[YYYY-MM-DD to learn from, default: today]"
agent: Guardian Engineer
---

# Guardian Daily Learning Cycle

Date to process: ${input:date:today's date}

Run the daily self-improvement loop for this repo's custom agents. This is how agents learn from each other: experiences are recorded in [.github/LESSONS.md](.github/LESSONS.md), and this cycle folds them back into the agent files.

## Steps

1. **Read the lessons log** — open [.github/LESSONS.md](.github/LESSONS.md). Collect every entry dated for the target day (plus any `pending` entries from earlier days).

2. **Read the current agent files** — [.github/agents/guardian-engineer.agent.md](.github/agents/guardian-engineer.agent.md), [.github/agents/guardian-auditor.agent.md](.github/agents/guardian-auditor.agent.md), and [.github/copilot-instructions.md](.github/copilot-instructions.md).

3. **Consolidate** — for each lesson, decide where it belongs:
   - Behavioral rule for one agent → that agent's `.agent.md` (Approach, Constraints, or Review Checklist section)
   - Project-wide convention → `copilot-instructions.md`
   - Test-related → [guardian-testing.instructions.md](.github/instructions/guardian-testing.instructions.md)
   - Duplicate or already-covered → mark `superseded`, don't re-add

4. **Apply updates** — edit the target files. Keep additions short (one or two lines per lesson). Preserve YAML frontmatter exactly; only touch body sections.

5. **Prime-directive check** — verify no lesson weakens SafetyPolicy gates, audit coverage, least-force termination, or the write-surface restriction. Refuse and flag any that do, and mark the lesson `rejected: violates prime directive` in LESSONS.md.

6. **Mark lessons applied** — update each processed entry's **Applied to** field with the file(s) changed.

7. **Validate** — check YAML frontmatter of every edited agent/instruction file still parses (no tabs, quoted colons). If guardian.py-adjacent behavior guidance changed, run `python3 -m pytest test_guardian.py test_guardian_audit.py -q` to confirm nothing drifted.

## Output

A learning report: lessons processed, files updated (one line per change), lessons rejected or superseded with reasons, and validation results.
