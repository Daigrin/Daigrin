# Daigrin Guardian — Project Instructions

Guardian is a **defensive-only** security supervisor for AI agent processes. Pipeline: monitor → detect → assess inaction risk → escalate → terminate → protect → update, with audit logging throughout.

## Prime Directive (applies to every change)

**Always protect. Never harm anyone or anything.** Moral model: Superman-style restraint — protect the innocent, least force first, truthfulness, accountability, restraint.

- Never add offensive capabilities (exploitation, payloads, exfiltration, persistence).
- Never weaken `SafetyPolicy` gates: termination must be detection-justified, scope-limited to the managed process pattern, and forbidden against guardian/self processes.
- Automatic termination stays gated at high/critical inaction risk; lower severities get monitoring and alerts only.
- Every detection, escalation, termination, update, protection action, and refusal must go through `log_action()` — never swallow audit entries.
- Defensive writes are limited to `quarantine/`, `backups/`, and `threat_signatures.json`.

## Architecture & Conventions

- **Behavior is config-driven**: check the relevant Guardian.yaml section (`core_directives`, `threat_detection`, `risk_assessment`, `agent_termination`, `system_protection`, `self_scaling`, `adaptive_learning`, `integrations.norton`, `updates`) before changing code.
- **Source of truth**: edit guardian.py and guardian_audit.py. **Never hand-edit guardian_standalone.py** — regenerate it with `python3 build_standalone.py`.
- **Tests**: `python3 -m pytest test_guardian.py test_guardian_audit.py -q`. Every behavior change needs tests, including refusal paths (safety blocks), not just allowed paths.
- **Docs**: keep README.md in sync when config keys, CLI flags, or pipeline behavior change.

## Key Files

- guardian.py — main supervisor (monitoring, detection, risk, termination, updates)
- guardian_audit.py — audit trail (`log_action`, `read_audit_trail`)
- build_standalone.py — regenerates guardian_standalone.py (inlined audit + embedded config)
- Guardian.yaml — full configuration, including core directives and Norton integration

## Agent Learning Loop

- .github/LESSONS.md is the shared cross-agent lessons log (append-only; format documented in the file).
- Custom agents record lessons as they work and consume relevant ones before acting.
- Run `/guardian-learn` daily to consolidate pending lessons into the agent and instruction files.
