# Daigrin

Daigrin is a concise, developer-focused coding assistant that provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when needed.

## Guardian configuration

The agent configuration lives at [Guardian.yaml](Guardian.yaml). It defines:

- **Tasks** — code generation, completion, review, debugging, testing, refactoring, documentation, with per-task confidence thresholds.
- **Guardian agent** — `guardian_agent.enabled` gates the supervisor, while `monitoring` controls system-call, network, and agent-interaction monitoring.
- **Threat detection** — `threat_detection.algorithms` enables the machine-learning, signature, anomaly, and behavioral detectors used in `guardian.py`.
- **Risk assessment** — `risk_assessment.assess_inaction_risk` evaluates the danger of doing nothing and `escalate_on` controls when Guardian logs an escalation and sends a non-critical alert.
- **Termination + protection** — `agent_termination` governs confirmation and critical auto-termination; `system_protection` and `core_directives` keep termination detection-justified, scope-limited, least-force, and protective-only.
- **Adaptive learning + scaling** — optional `adaptive_learning` can absorb bounded high/critical signatures into `threat_signatures.json`, and `self_scaling` can split Guardian into bounded worker processes during spikes.
- **Norton integration** — optional `integrations.norton` settings load or fetch Norton signature feeds, with `--norton-mode` and `--norton-compat-check` CLI support.
- **Updates** — `updates.verify_signatures` enforces the SHA-256 `.sig` convention before applying an update, rejected payloads are quarantined under `quarantine/`, and `rollback_on_failure` snapshots bytes to `backups/` before an apply attempt.

## CLI highlights

`guardian.py` supports:

- `--once` — run a single monitor cycle
- `--dry-run` — detect and log without killing
- `--pattern` — choose the managed process substring
- `--norton-mode {local,live}` — override Norton signature sourcing
- `--norton-compat-check` — print Norton compatibility diagnostics and exit
