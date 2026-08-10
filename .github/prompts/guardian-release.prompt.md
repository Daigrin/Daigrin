---
description: "Run the Guardian release pipeline: tests, standalone build regeneration, README sync, and signature DB verification"
name: guardian-release
argument-hint: "[release notes or version tag, optional]"
agent: Guardian Engineer
---

# Guardian Release Pipeline

Prepare the Daigrin Guardian codebase for release. Follow the steps in order and stop immediately if any step fails — report the failure instead of proceeding.

Release notes / version (if provided): ${input:notes:}

## Steps

1. **Audit working tree** — run `git status --short`. If there are unrelated uncommitted changes, list them and ask whether to include or stash before proceeding.

2. **Run the full test suite** — `python3 -m pytest test_guardian.py test_guardian_audit.py -q`. All tests must pass, including refusal-path tests. Do not continue on failure.

3. **Regenerate the standalone build** — run `python3 build_standalone.py` so guardian_standalone.py is regenerated from guardian.py + guardian_audit.py. Never hand-edit the standalone file. Confirm the regenerated file's embedded config matches Guardian.yaml.

4. **README sync** — compare README.md against Guardian.yaml and the current pipeline behavior in guardian.py. Update any drifted config keys, CLI flags (`--once`, `--dry-run`, `--pattern`, `--norton-mode`, `--norton-compat-check`), or pipeline-stage descriptions. Every config section (`core_directives`, `threat_detection`, `risk_assessment`, `agent_termination`, `system_protection`, `self_scaling`, `adaptive_learning`, `integrations.norton`, `updates`) must be documented.

5. **Verify signature DB integrity** — confirm threat_signatures.json (if present) is valid JSON with a `signatures` list of non-empty strings, and that norton_signatures.json parses under the configured `signature_keys`. Report signature counts.

6. **Prime-directive review** — diff the pending changes and confirm: no weakened SafetyPolicy gates, termination still detection-justified and high/critical-only, all actions audited via `log_action()`, writes still limited to quarantine/, backups/, threat_signatures.json.

## Output

A release-readiness report: test pass/fail counts, files changed (with one-line reasons), signature counts loaded, directive-review verdict, and — if all green — the suggested commit message.
