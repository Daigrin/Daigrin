---
description: "Use when: editing guardian*.py — core Guardian safety, audit, and config-driven rules"
applyTo: "guardian*.py"
---

# Guardian Core Conventions

- **Audit coverage**: every detection, escalation, termination, update, protection action, and refusal calls `log_action()` with `agent_id`, `risk_level`, and `details` when applicable; no bare log writes, no swallowed audit failures.
- **Risk ordering**: use `RISK_ORDER` / `Config.risk_at_least()` for comparisons; never compare risk strings directly; honor `risk_assessment.escalate_on`.
- **SafetyPolicy gates**: terminations go through `authorize_termination()`; writes go through `authorize_write()` and stay limited to `quarantine/`, `backups/`, and `threat_signatures.json`; refusals are logged through `_refuse()` as `SAFETY REFUSAL` entries.
- **Config-driven behavior**: check the relevant `Guardian.yaml` section before hardcoding behavior; new behavior gets a config key with a safe default.
- **Generated file**: never hand-edit `guardian_standalone.py`; regenerate it via `build_standalone.py`.
