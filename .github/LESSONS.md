# Guardian Agents — Shared Lessons Log

Cross-agent learning record for this repo's custom agents (Guardian Engineer, Guardian Auditor, and any future agents). Agents append dated lessons here; the `/guardian-learn` skill consolidates them into agent file updates daily.

## Format

```
### YYYY-MM-DD — <Agent Name>
- **Lesson**: one sentence, actionable.
- **Evidence**: what happened (tool denial, test failure, review finding, user correction).
- **Applied to**: file(s) updated, or `pending` if not yet folded into an agent file.
```

## Rules

- Append-only. Never delete another agent's lesson; mark it `superseded by <date>` if obsolete.
- Lessons must respect the prime directive — a lesson may never teach an agent to weaken SafetyPolicy gates, skip audit logging, or widen the write surface.
- Small and specific beats grand and vague: "hook substring-matching blocks its own edits" is a lesson; "be more careful" is not.

## Lessons

### 2026-08-10 — Guardian Engineer
- **Lesson**: Substring-matching hooks deny any payload that merely *mentions* a guarded filename — including the hook's own replacement. Parse hook JSON and match only real file-path fields.
- **Evidence**: PreToolUse hook blocked creation of `.github/hooks/scripts/guard-standalone.py` mid-session because the filename contains `guardian_standalone.py` as a substring.
- **Applied to**: .github/hooks/scripts/guard-standalone.py (JSON-parsing rewrite), Guardian Auditor checklist item 7.

### 2026-08-10 — Guardian Auditor
- **Lesson**: Review findings are only useful if actionable — every observation must name the file:line and the minimal fix, or it gets ignored.
- **Evidence**: First audit of the customization suite; the single observation with a concrete fix (hook matching) was implemented the same session.
- **Applied to**: .github/agents/guardian-auditor.agent.md (Output Format section).

### 2026-08-12 — Guardian Engineer
- **Lesson**: Tests that bypass a safety gate go stale when the gate is strengthened — always pass the justifying context (detection) on allowed-path tests and keep a refusal-path test asserting the SAFETY REFUSAL audit entry.
- **Evidence**: `SafetyPolicy.authorize_termination` gained the `require_defensive_justification` check; three TestTermination tests calling `terminate_agent()` without `detection=` failed (29 passed / 3 failed baseline).
- **Applied to**: test_guardian.py (detection-justified allowed paths, `test_no_detection_is_refused_and_audited`), guardian.py (removed duplicate `import os` in proc_kill), Guardian.yaml (todos statuses), README.md (config section sync).
