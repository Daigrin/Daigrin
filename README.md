# Daigrin

Daigrin is a concise, developer-focused coding assistant that provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when needed.

## Guardian configuration

The agent configuration lives at [Guardian.yaml](Guardian.yaml). It defines:

- **Tasks** — code generation, completion, review, debugging, testing, refactoring, documentation, with per-task confidence thresholds.
- **Guardian agent** (`guardian_agent`) — monitoring of system calls, network connections, and agent interactions; `threat_detection` via machine-learning, signature, anomaly, and behavioral algorithms; `risk_assessment` with `assess_inaction_risk` scoring the risk of *inaction* (low/medium/high/critical) and escalating at `high`; `agent_termination` with confirmation required and `auto_terminate_on_critical` bypassing it at critical risk; `system_protection` blocking sensitive resource access and preventing system changes.
- **Updates** (`updates`) — `auto_update: true` makes [guardian.py](guardian.py) automatically sweep the `inbox` (`updates/inbox` by default) every `check_interval` (45m) while the monitor runs (and once per `--once` invocation; `--no-updates` opts out). Every candidate goes through the same authorization pipeline: `verify_signatures` requires a matching `<file>.sig` (unsigned or tampered updates are quarantined, never applied) and `rollback_on_failure` snapshots the previous version into `backups/` before staging; threat intelligence comes from centralized servers, cloud services, peer-to-peer networks, and local sources; delivered over HTTPS, SFTP, or SSH (ftp removed because it sends credentials in plaintext); as executables, scripts, configs, or database updates.

The guardian implementation in [guardian.py](guardian.py) additionally honors optional `core_directives` (prime directive / safety policy), `adaptive_learning`, `self_scaling`, `integrations.norton`, and `integrations.glm` sections, which are off/absent in this config.

### Optional: GLM machine-learning detector (`integrations.glm`)

Set `integrations.glm.enabled: true` in Guardian.yaml to route the `machine_learning` detector through a [GLM model](https://open.bigmodel.cn/) (Zhipu AI, e.g. `glm-4.6`) via its OpenAI-compatible API:

- **`model`** — e.g. `glm-4.6`
- **`endpoint`** — OpenAI-compatible completions URL (`https://open.bigmodel.cn/api/paas/v4/chat/completions`)
- **`api_key_env`** — name of the env var holding the API key (default `GLM_API_KEY`); never store the key in the config file
- **`min_confidence`** — float 0–1; GLM scores below this are not treated as detections (default `0.8`)
- **`fallback_to_heuristic`** — if `true` (default), any API error or missing key falls back to the built-in `ml_scan` heuristic so monitoring is never degraded
- **`--glm-test [CMDLINE]`** — ad-hoc CLI flag: loads config, scores CMDLINE (or a default probe) via `glm_scan`, prints the Detection as JSON (or `null` if disabled/clean), and exits
