# Daigrin

Daigrin is a concise, developer-focused coding assistant that provides clear, actionable answers, prefers examples and code snippets, and asks clarifying questions when needed.

## Guardian — a cyber-security agent for everyone

**Guardian is a defensive-only security supervisor built to help people — that is its number-one priority.** It runs on **any OS and any device** with Python 3 (Linux, macOS, Windows, and low-power or embedded devices), needs **no third-party dependencies** (it vendors a tiny YAML fallback), and works with **any security software** you already use — not just one vendor.

Guardian protects you by watching your device, detecting threats and intrusions, assessing the risk of doing nothing, stopping what must be stopped (least force first, never harming the innocent or itself), finding where each threat came from, and reporting everything to a tamper-evident audit trail.

### Download and run

Guardian is downloadable and runs out of the box:

```bash
# 1. Get it (clone or download the source)
git clone https://github.com/Daigrin/Daigrin.git && cd Daigrin

# 2. Run a single read-only scan — no install, no dependencies needed
python3 guardian.py --once --dry-run

# Or install it as a proper command (optional, needs pip)
pip install .
guardian --once --dry-run
```

- `--dry-run` observes and reports without stopping anything (safe first look).
- Remove `--dry-run` to let Guardian act, and drop `--once` to keep it watching.
- Optional extras: `pip install .[yaml]` (full PyYAML), `pip install .[tray]` (system-tray UI).

### Any OS, any device

| Capability | Linux | macOS | Windows | Notes |
|---|---|---|---|---|
| Process scan | `ps` | `ps` | `tasklist` | read-only |
| Network scan | `ss`, `netstat` | `netstat` | `netstat` | read-only, graceful fallback |
| Stop a threat | SIGTERM→SIGKILL | SIGTERM→SIGKILL | terminate / `taskkill` | least force first |
| Provenance | `/proc` | partial | partial | best-effort per platform |

Where a platform lacks a capability, Guardian degrades gracefully and **logs what it could not do** — it never fails silently.

### Works with any security software

Guardian doesn't replace your antivirus — it stands beside it. Point `integrations:` in [Guardian.yaml](Guardian.yaml) at any product's local signature export or live API and Guardian will merge that threat intelligence into its own detections:

```yaml
integrations:
  norton:      { enabled: true, mode: local, signature_feed: norton_signatures.json }
  defender:    { enabled: true, signature_feed: defender_signatures.json }
  crowdstrike: { enabled: true, mode: live, live: { endpoint: "https://…", api_key_env: CS_API_KEY } }
```

Fetching is read-only (a plain GET); nothing is ever sent to the vendor.

## Guardian configuration

The agent configuration lives at [Guardian.yaml](Guardian.yaml). It defines:

- **Tasks** — code generation, completion, review, debugging, testing, refactoring, documentation, with per-task confidence thresholds.
- **Guardian agent** (`guardian_agent`) — monitoring of system calls, network connections, and agent interactions; `threat_detection` via machine-learning, signature, anomaly, and behavioral algorithms; `risk_assessment` with `assess_inaction_risk` scoring the risk of *inaction* (low/medium/high/critical) and escalating at `high`; `agent_termination` with confirmation required and `auto_terminate_on_critical` bypassing it at critical risk; `system_protection` blocking sensitive resource access and preventing system changes.
- **Threat quarantine** (`guardian_agent.threat_quarantine`) — with `always: true`, every detected threat is quarantined to `directory` (`quarantine/`) even when its risk is below the termination threshold: the threat's executable is copied for offline study (never executed) and a `threat_pid<N>.json` evidence record captures the full cmdline, identity, and provenance. `trace_provenance()` walks the parent-PID chain to pinpoint exactly where the threat came from, and `study_and_report` reports each quarantined threat — with its origin — through the audit trail and the alert channel.
- **Intrusion & surveillance defense** (`guardian_agent.intrusion_detection`) — the same detect → stop → find → report pipeline aimed outward at anyone trying to hack the machine or surveil it. With `scan_network_connections: true`, [guardian.py](guardian.py) reads live sockets via `ss` (read-only, never probes the network): `flag_listeners` flags unexpected listening sockets as possible backdoors (ports in `allowed_listeners`, loopback-only listeners, and wildcard listeners whose observed traffic is all loopback are exempt; one finding per port), and established connections to `suspicious_remote_ports` (4444, 1337, 31337 by default) are flagged as reverse-shell/C2 channels at critical inaction risk. Processes named in `surveillance_tools` (tcpdump, keyloggers, port scanners, …) are flagged as surveillance. Every finding is recorded in an `intrusion_<kind>_pid<N>.json` evidence record in the quarantine directory with its traced origin — the remote endpoint plus the owning process's provenance chain (`trace_intrusion_origin()`) — and reported through the audit trail and alert channel. When inaction risk reaches `stop_on` (high), the guardian stops the intrusion by terminating the local process that owns the malicious socket or runs the surveillance tool (`stop_intrusion()`) — the only force it ever uses, gated by SafetyPolicy (evidence required, never guardian/self processes, least-force first), with `require_confirmation` for high risk and `auto_stop_on_critical` bypassing confirmation at critical. It never sends traffic to the attacker.
- **Updates** (`updates`) — `auto_update: true` makes [guardian.py](guardian.py) automatically sweep the `inbox` (`updates/inbox` by default) every `check_interval` (45m) while the monitor runs (and once per `--once` invocation; `--no-updates` opts out). Every candidate goes through the same authorization pipeline: `verify_signatures` requires a matching `<file>.sig` (unsigned or tampered updates are quarantined, never applied) and `rollback_on_failure` snapshots the previous version into `backups/` before staging; threat intelligence comes from centralized servers, cloud services, peer-to-peer networks, and local sources; delivered over HTTPS, SFTP, or SSH (ftp removed because it sends credentials in plaintext); as executables, scripts, configs, or database updates.

The guardian implementation in [guardian.py](guardian.py) additionally honors optional `core_directives` (prime directive / safety policy), `adaptive_learning`, `self_scaling`, and `integrations.<product>` sections (any security vendor — `norton`, `defender`, `crowdstrike`, …), which are off/absent in this config.
