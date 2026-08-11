---
description: "Run the Guardian Auditor on a diff, working tree, or file set and return a compliance verdict"
name: guardian-audit
argument-hint: "[diff | working-tree | path ...]"
agent: Guardian Auditor
---

# Guardian Compliance Audit

Audit target: ${input:scope:working-tree}

## Steps

1. **Determine scope from the argument** — if the user provided `diff`, inspect a diff; if they provided one or more paths, audit only those paths; otherwise default to the working-tree diff from `git diff`.
2. **Run the full 8-point Guardian Auditor checklist** — review the selected scope for prime-directive compliance and cite `file:line` for every finding.
3. **Separate violations from observations** — violations are mandatory fixes; observations are non-blocking follow-ups.
4. **Return the verdict in the Auditor output format** — `PASS`, `PASS WITH OBSERVATIONS`, or `FAIL`.

## Constraints

- Read-only audit only: do not modify files, except for an allowed append to [.github/LESSONS.md](.github/LESSONS.md) when the learning protocol calls for it.
- Do not weaken SafetyPolicy gates, audit requirements, or write-surface restrictions.
