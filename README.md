# Daigrin

Daigrin is a concise, developer-focused coding assistant that provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when needed.

## Guardian configuration

The agent configuration lives at [Guardian.yaml](Guardian.yaml). It defines:

- **Tasks** — code generation, completion, review, debugging, testing, refactoring, documentation, with per-task confidence thresholds.
- **Guardian agent** (`guardian_agent`) — monitoring of system calls, network connections, and agent interactions; `threat_detection` via machine-learning, signature, anomaly, and behavioral algorithms; `risk_assessment` with `assess_inaction_risk` scoring the risk of *inaction* (low/medium/high/critical) and escalating at `high`; `agent_termination` with confirmation required and `auto_terminate_on_critical` bypassing it at critical risk; `system_protection` blocking sensitive resource access and preventing system changes.
- **Updates** (`updates`) — `auto_update: true` makes [guardian.py](guardian.py) automatically sweep the `inbox` (`updates/inbox` by default) every `check_interval` (45m) while the monitor runs (and once per `--once` invocation; `--no-updates` opts out). Every candidate goes through the same authorization pipeline: `verify_signatures` requires a matching `<file>.sig` (unsigned or tampered updates are quarantined, never applied) and `rollback_on_failure` snapshots the previous version into `backups/` before staging; threat intelligence comes from centralized servers, cloud services, peer-to-peer networks, and local sources; delivered over HTTPS, SFTP, or SSH (ftp removed because it sends credentials in plaintext); as executables, scripts, configs, or database updates.

The guardian implementation in [guardian.py](guardian.py) additionally honors optional `core_directives` (prime directive / safety policy) and `adaptive_learning` sections (off/absent in this config), plus `self_scaling` and `integrations.norton`/`integrations.glm`, documented below.

### Self-scaling (`self_scaling`)

When the threat load spikes, the guardian splits into extra processes — **"Spawns"** — as many as it needs, not a fixed number. Each cycle the detections are counted; once they reach `split_threshold`, the guardian creates spawns until the total guardian count matches the detection count, so a small incident gets a small response and a large one scales out:

- **`enabled`** — turn self-scaling on/off (default `false`; `true` in this config)
- **`split_threshold`** — detections in one cycle that trigger a split (default `3`)
- **`min_agents`** / **`max_agents`** — total guardian count is clamped to this range; `max_agents: 8` here means 1 supervisor plus up to 7 spawns, never more
- **`cooldown_cycles`** — cycles to wait between splits so load bursts don't thrash

Spawns run `guardian.py --once --pattern <pattern>` (plus `--dry-run` when the parent is in dry-run), and every split is written to the audit trail as an `escalation` entry with the threat count and active spawns.

### Optional: GLM machine-learning detector (`integrations.glm`)

Set `integrations.glm.enabled: true` in Guardian.yaml to route the `machine_learning` detector through a [GLM model](https://open.bigmodel.cn/) (Zhipu AI, e.g. `glm-4.6`) via its OpenAI-compatible API:

- **`model`** — e.g. `glm-4.6`
- **`endpoint`** — OpenAI-compatible completions URL (`https://open.bigmodel.cn/api/paas/v4/chat/completions`)
- **`api_key_env`** — name of the env var holding the API key (default `GLM_API_KEY`); never store the key in the config file
- **`min_confidence`** — float 0–1; GLM scores below this are not treated as detections (default `0.8`)
- **`fallback_to_heuristic`** — if `true` (default), any API error or missing key falls back to the built-in `ml_scan` heuristic so monitoring is never degraded
- **`--glm-test [CMDLINE]`** — ad-hoc CLI flag: loads config, scores CMDLINE (or a default probe) via `glm_scan`, prints the Detection as JSON (or `null` if disabled/clean), and exits

## Benchmark harnesses

The [benchmarks/](benchmarks/) package scores Guardian's *defensive* performance — detection and guardrail behavior — without ever executing attack payloads or generating exploits (consistent with the prime directive):

```sh
python3 -m benchmarks list                 # available suites
python3 -m benchmarks all                  # run all suites with curated samples
python3 -m benchmarks cybergym-defense --dataset my_samples.jsonl --json
```

| Suite | What it scores | Dataset input |
|---|---|---|
| `cybergym-defense` | Detection of exploit-style cmdlines (CyberGym measures *offensive* PoC generation, which Guardian refuses by design; this scores the defender side instead) | JSONL `{"id", "label", "text"}` cmdlines (default: [datasets/cybergym_defense.jsonl](benchmarks/datasets/cybergym_defense.jsonl)) |
| `malskill` | Detection of malicious agent skills (MalSkillBench / MaliciousAgentSkillsBench style) | JSONL, or a skill tree with `malware/` and `benign/` dirs of skill packages |
| `gabench-guardrail` | Guardrail behavior: malicious scenarios must be detected **and** acted on; benign ones left alone (GABench-style), replayed through `run_cycle` in dry-run | JSONL scenarios with optional `expected_action` meta |

Each suite reports detection rate (recall), false-positive rate, precision, accuracy, and F1. Curated sample datasets ship under [benchmarks/datasets/](benchmarks/datasets/); Guardian scores 100% detection / 0% false positives on all three curated sets. Point `--dataset` at a real benchmark export (e.g. MalSkillBench's `Dataset/Skills/`) for a full run.
