---
description: "Use when: writing or editing Guardian tests — refusal-path coverage requirements, mock patterns for proc_kill/input()/os.kill, audit-log redirection, dry-run conventions"
applyTo: "test_*.py"
---

# Guardian Testing Conventions

## Coverage Requirements

- Every behavior change needs **both** an allowed-path test and a **refusal-path** test where a safety gate exists (SafetyPolicy blocks, disabled config sections, confirmation declined).
- Test the gate, not just the outcome: when `authorize_termination` or `authorize_write` refuses, assert the audit trail contains the `SAFETY REFUSAL` entry.

## Mock Patterns

- **Process killing**: patch `proc_kill` (the thin `os.kill` wrapper), never `os.kill` directly — this keeps termination tests honest about the code path.
- **Confirmation prompts**: patch `builtins.input` to return `"y"` / `"n"`; test both branches of `require_confirmation`.
- **Process scanning**: patch `AgentProcess.scan` to return synthetic `AgentProcess` objects instead of relying on real processes.
- **Time/network**: patch `time.sleep` in retry tests; never make real HTTP calls — mock `urllib.request.urlopen` for Norton live-mode tests.

## Audit-Log Isolation

- Redirect the audit trail per test via the `log_path` parameter or by patching `AUDIT_LOG_PATH` to a `tmp_path` file. Never let tests write to the repo-root guardian_audit.log.
- Use `run_cycle(..., audit_log=tmp_path / "audit.log")` for cycle-level tests.

## Conventions

- Use `dry_run=True` for termination-flow tests unless the test specifically targets the kill path.
- Build configs with the minimal section needed — don't load Guardian.yaml in unit tests; construct `Config(raw={...})` dicts directly.
- Signature-DB tests write to `tmp_path`, never the repo-root threat_signatures.json.
