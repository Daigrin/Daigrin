"""Guardian agent — runnable supervisor.

Loads Guardian.yaml, monitors agent processes, detects threats, assesses the
risk of inaction, terminates malicious agents, enforces system protection,
checks for threat-intel updates, and logs everything to the audit trail.

Usage:
    python3 guardian.py                     # run the monitor loop
    python3 guardian.py --once              # single scan cycle and exit
    python3 guardian.py --dry-run           # detect and log without killing
    python3 guardian.py --config FILE       # alternate config file
"""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
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

    def authorize_intrusion_stop(self, intr: "Intrusion", *, detection: Optional["Detection"],
                                 risk: Optional[str] = None) -> bool:
        """Stopping an intrusion is allowed only if defensive, justified, and
        never aimed at the guardian itself or unrelated processes."""
        if not self.enabled():
            return True
        if detection is None and self.section().get("require_defensive_justification", True):
            return self._refuse("stop_intrusion", "no detection justifies this action",
                                pid=intr.pid, process=intr.process,
                                remote=intr.conn.remote if intr.conn else "")
        if self.section().get("scope_limited", True):
            if "guardian" in intr.process.lower():
                return self._refuse("stop_intrusion", "refusing to harm a guardian process (self or sibling)",
                                    pid=intr.pid, process=intr.process)
        if "least_force_first" in self.principles() and risk is not None:
            # Least-force principle: stopping requires high or critical risk;
            # lower severities are handled with monitoring and alerts only.
            if RISK_ORDER.index(risk) < RISK_ORDER.index("high"):
                return self._refuse("stop_intrusion", "least-force principle: risk below high does not justify stopping",
                                    pid=intr.pid, process=intr.process, risk=risk)
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
        # core_directives is a top-level section (the prime directive governs
        # the whole program, not just the guardian_agent subtree).
        if name == "core_directives":
            section = self.raw.get(name, {})
            return section if isinstance(section, dict) else {}
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
    ppid: int = 0
    user: str = ""
    exe: str = ""
    cwd: str = ""

    @classmethod
    def scan(cls, pattern: str = "agent") -> list["AgentProcess"]:
        """Find running processes whose command line matches a pattern."""
        try:
            out = subprocess.run(
                ["ps", "-eo", "pid=,ppid=,user=,comm=,args="],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout
        except (subprocess.SubprocessError, FileNotFoundError):
            return []
        procs = []
        for line in out.splitlines()[1:]:
            parts = line.split(None, 4)
            if len(parts) < 5:
                continue
            pid_s, ppid_s, user, name, cmdline = parts
            if pattern.lower() in cmdline.lower() and "guardian" not in cmdline.lower():
                try:
                    procs.append(cls(pid=int(pid_s), ppid=int(ppid_s), user=user,
                                     name=name, cmdline=cmdline))
                except ValueError:
                    continue
        return procs

    def identity(self) -> dict[str, Any]:
        return {"pid": self.pid, "ppid": self.ppid, "name": self.name,
                "user": self.user, "cmdline": self.cmdline,
                "exe": self.exe, "cwd": self.cwd}


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


def ml_scan(proc: AgentProcess) -> Optional[Detection]:
    """ML-based detection placeholder.

    A real deployment would score cmdline features with a trained model.
    Heuristic stand-in: high token entropy / heavy encoding is suspicious.
    """
    encoded_markers = sum(proc.cmdline.count(m) for m in ("base64", "eval", "exec", "fromhex", "\\x"))
    if encoded_markers >= 2:
        return Detection("machine_learning", f"Heuristic score high ({encoded_markers} obfuscation markers)", proc.cmdline[:80], "medium")
    return None


DETECTORS = {
    "signature_based": signature_scan,
    "anomaly_based": anomaly_scan,
    "behavioral_based": behavioral_scan,
    "machine_learning": ml_scan,
}


# --------------------------------------------------------------------------
# Intrusion & surveillance detection (network-facing defense)
# --------------------------------------------------------------------------

# Process names excluded from surveillance flagging: the defender must never
# mistake itself (or its own observations) for the surveillor.
SURVEILLANCE_EXCLUDED = ("guardian", "sshd")


@dataclass
class NetworkConnection:
    """One live socket observed on this machine (read-only snapshot)."""
    state: str            # LISTEN, ESTAB, ...
    local: str            # "10.0.0.5:22"
    remote: str           # "203.0.113.9:4444" or "*:*"
    process: str = ""     # owning process name, if visible
    pid: int = 0          # owning PID, if visible (0 = kernel/unknown)

    @classmethod
    def scan(cls) -> list["NetworkConnection"]:
        """List live TCP sockets via ss without touching anything (defensive read)."""
        try:
            out = subprocess.run(
                ["ss", "-tunap"],
                capture_output=True, text=True, check=True, timeout=10,
            ).stdout
        except (subprocess.SubprocessError, FileNotFoundError) as e:
            log_action("detection", f"Network connection scan unavailable: {e}",
                       details={"source": "ss -tunap"})
            return []
        return cls.parse_ss(out)

    @classmethod
    def parse_ss(cls, out: str) -> list["NetworkConnection"]:
        conns = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            state = parts[1] if parts[0] in ("tcp", "udp") else parts[0]
            # Row layout is fixed from the right: [.., local, remote, process?]
            proc_field = parts[-1] if "users:" in parts[-1] else ""
            local, remote = (parts[-3], parts[-2]) if proc_field else (parts[-2], parts[-1])
            process, pid = "", 0
            if proc_field:
                m = re.search(r'"([^"]+)"', proc_field)
                if m:
                    process = m.group(1)
                m = re.search(r"pid=(\d+)", proc_field)
                if m:
                    pid = int(m.group(1))
            conns.append(cls(state=state, local=local, remote=remote,
                             process=process, pid=pid))
        return conns

    def identity(self) -> dict[str, Any]:
        return {"state": self.state, "local": self.local, "remote": self.remote,
                "process": self.process, "pid": self.pid}


def _split_host_port(endpoint: str) -> tuple[str, int]:
    """Split 'host:port' (IPv4 or [v6], %-scoped) into (host, port).

    Interface scopes are stripped (127.0.0.53%lo -> 127.0.0.53); port is 0
    when unknown.
    """
    text = endpoint.strip()
    if text.startswith("[") and "]:" in text:  # [::1]:443 / [fe80::1%eth0]:80
        host, _, port_s = text[1:].partition("]:")
    else:
        host, _, port_s = text.rpartition(":")
    host = host.strip("[]").split("%", 1)[0]
    try:
        return host, int(port_s)
    except ValueError:
        return host, 0


def _is_loopback_host(host: str) -> bool:
    """True for loopback/wildcard bind addresses (127.0.0.1, ::1, *).

    Loopback listeners serve local processes, not remote attackers, so they
    are weak intrusion signals; wildcard binds (0.0.0.0) accept remote
    connections and are *not* exempted.
    """
    if host == "*":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped  # ::ffff:127.0.0.1 is loopback too
    return addr.is_loopback


@dataclass
class Intrusion:
    """A detected hacking or surveillance attempt against this machine."""
    kind: str                     # listener | reverse_shell | surveillance
    conn: Optional[NetworkConnection]
    detection: Detection
    process: str = ""             # owning process name (surveillance tool or socket owner)
    pid: int = 0

    def describe(self) -> str:
        where = f"{self.conn.local} <- {self.conn.remote}" if self.conn else "local process"
        return f"{self.kind} via {self.process or 'unknown'} (pid={self.pid}) [{where}]"


def detect_intrusions(config: Config,
                      conns: Optional[list[NetworkConnection]] = None,
                      procs: Optional[list[AgentProcess]] = None) -> list[Intrusion]:
    """Find hacking attempts and surveillance aimed at this machine.

    Read-only detection: inspects live sockets and the process table, never
    probes the network or touches the suspected processes.
    """
    ids = config.section("intrusion_detection")
    if not ids.get("enabled", False):
        return []
    findings: list[Intrusion] = []
    if ids.get("scan_network_connections", True):
        conns = NetworkConnection.scan() if conns is None else conns
        findings.extend(_detect_network_intrusions(ids, conns))
    procs = _scan_all_processes() if procs is None else procs
    findings.extend(_detect_surveillance(ids, procs))
    return findings


def _scan_all_processes() -> list[AgentProcess]:
    """Full process-table read (no pattern filter) for surveillance spotting."""
    try:
        out = subprocess.run(
            ["ps", "-eo", "pid=,ppid=,user=,comm=,args="],
            capture_output=True, text=True, check=True, timeout=10,
        ).stdout
    except (subprocess.SubprocessError, FileNotFoundError) as e:
        log_action("detection", f"Process table scan unavailable: {e}",
                   details={"source": "ps -eo"})
        return []
    procs = []
    for line in out.splitlines()[1:]:
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        pid_s, ppid_s, user, name, cmdline = parts
        try:
            procs.append(AgentProcess(pid=int(pid_s), ppid=int(ppid_s), user=user,
                                      name=name, cmdline=cmdline))
        except ValueError:
            continue
    return procs


def _listener_is_local_only(host: str, port: int,
                            conns: list["NetworkConnection"]) -> bool:
    """True when the listener cannot or does not talk to remote peers.

    Loopback binds (127.0.0.1, ::1) are always local-only. Wildcard binds
    (*, 0.0.0.0, ::) are treated as local-only when every observed connection
    on that port involves loopback addresses — the common local dev-server /
    IPC pattern — which keeps least-force restraint (no false stops) while
    still flagging wildcard listeners with real remote exposure.
    """
    if host != "*" and _is_loopback_host(host):
        return True
    peers = [c for c in conns if c.state != "LISTEN"
             and (_split_host_port(c.local)[1] == port
                  or _split_host_port(c.remote)[1] == port)]
    if not peers:
        return False  # wildcard bind with no observed traffic: unknown exposure
    for c in peers:
        for endpoint in (c.local, c.remote):
            ehost, _ = _split_host_port(endpoint)
            if ehost == "*" or ehost == "0.0.0.0" or ehost == "::":
                continue  # unconnected wildcard endpoint, not a remote peer
            if not _is_loopback_host(ehost):
                return False
    return True


def _detect_network_intrusions(ids: dict[str, Any],
                               conns: list[NetworkConnection]) -> list[Intrusion]:
    findings = []
    allowed_ports = {int(p) for p in ids.get("allowed_listeners", [])}
    suspicious_ports = {int(p) for p in ids.get("suspicious_remote_ports", [])}
    flagged_listener_ports: set[int] = set()  # one finding per listening port
    for conn in conns:
        if "guardian" in conn.process.lower():
            continue  # never flag ourselves
        host, port = _split_host_port(conn.local)
        if conn.state == "LISTEN" and ids.get("flag_listeners", True) \
                and port not in allowed_ports and port > 0 \
                and port not in flagged_listener_ports \
                and not _listener_is_local_only(host, port, conns):
            det = Detection("intrusion_detection",
                            f"Unexpected listening socket on port {port} "
                            f"(possible backdoor) owned by {conn.process or 'unknown'}",
                            conn.local, "high")
            findings.append(Intrusion("listener", conn, det, conn.process, conn.pid))
            flagged_listener_ports.add(port)
            continue
        rhost, rport = _split_host_port(conn.remote)
        if conn.state == "ESTAB" and rport in suspicious_ports:
            det = Detection("intrusion_detection",
                            f"Connection to suspicious remote port {rport} "
                            f"({rhost}): possible reverse shell or C2 channel",
                            conn.remote, "critical")
            findings.append(Intrusion("reverse_shell", conn, det, conn.process, conn.pid))
    return findings


def _detect_surveillance(ids: dict[str, Any], procs: list[AgentProcess]) -> list[Intrusion]:
    findings = []
    tools = [str(t).lower() for t in ids.get("surveillance_tools", [])]
    for proc in procs:
        if any(excluded in proc.cmdline.lower() for excluded in SURVEILLANCE_EXCLUDED):
            continue  # never flag the defender or the login session
        # Match the invoked program (argv[0] basename) or comm, not free
        # substrings: "vim tcpdump-notes.txt" must not be flagged.
        try:
            argv0 = Path(shlex.split(proc.cmdline)[0]).name.lower()
        except (ValueError, IndexError):
            argv0 = ""
        for tool in tools:
            if tool and tool in (proc.name.lower(), argv0):
                det = Detection("intrusion_detection",
                                f"Surveillance tool running: {proc.name} (pid={proc.pid}) "
                                f"may be watching or recording this machine",
                                tool, "high")
                findings.append(Intrusion("surveillance", None, det, proc.name, proc.pid))
                break
    return findings


def assess_intrusion_risk(intr: Intrusion, config: Config) -> str:
    """Escalate base risk based on what inaction against the intrusion allows."""
    ra = config.section("risk_assessment")
    if not ra.get("assess_inaction_risk", False):
        return intr.detection.base_risk
    # An open reverse shell/C2 channel means the attacker is already inside.
    if intr.kind == "reverse_shell":
        return "critical"
    return intr.detection.base_risk


def _proc_ppid(pid: int) -> int:
    """Read a process's parent PID from /proc (0 if unreadable)."""
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
        # Field 4 is ppid; the comm (field 2) may contain spaces/parens, so
        # anchor after the last ')'.
        return int(stat[stat.rindex(")") + 1:].split()[1])
    except (OSError, ValueError, IndexError):
        return 0


def trace_intrusion_origin(intr: Intrusion) -> dict[str, Any]:
    """Find where the intrusion came from: remote endpoint + owning process.

    For socket-based intrusions the origin is the remote host and the local
    process holding the socket (with its provenance chain). For surveillance
    tools it is the tool's process and how it was launched.
    """
    origin: dict[str, Any] = {"kind": intr.kind, "process": intr.process, "pid": intr.pid}
    if intr.conn is not None:
        rhost, rport = _split_host_port(intr.conn.remote)
        origin["remote_host"] = rhost
        origin["remote_port"] = rport
        origin["local"] = intr.conn.local
    if intr.pid > 0:
        proc = AgentProcess(pid=intr.pid, name=intr.process,
                            cmdline=intr.process, ppid=_proc_ppid(intr.pid))
        prov = trace_provenance(proc)
        origin["exe"] = prov.get("exe", "")
        origin["cwd"] = prov.get("cwd", "")
        origin["ancestors"] = prov.get("ancestors", [])
    return origin


def quarantine_intrusion(intr: Intrusion, risk: str, config: Config,
                         *, dry_run: bool = False,
                         safety: Optional[SafetyPolicy] = None) -> Optional[Path]:
    """Always preserve evidence of the intrusion, trace its origin, and report.

    Writes an intrusion evidence record (connection/process identity, remote
    endpoint, provenance) into the quarantine directory — never touches the
    attacker or the network. Reporting goes through the audit trail and the
    alert channel, exactly like process-threat quarantine.
    """
    tq = config.section("threat_quarantine")
    if not tq.get("enabled", True):
        return None
    quarantine_dir = Path(str(tq.get("directory", "quarantine")))
    policy = safety or SafetyPolicy(config)
    origin = trace_intrusion_origin(intr)
    evidence: dict[str, Any] = {
        "detection": {"algorithm": intr.detection.algorithm,
                      "description": intr.detection.description,
                      "matched": intr.detection.matched,
                      "base_risk": intr.detection.base_risk,
                      "inaction_risk": risk},
        "intrusion": {"kind": intr.kind, "process": intr.process, "pid": intr.pid,
                      "connection": intr.conn.identity() if intr.conn else None},
        "origin": origin,
    }
    remote = f"{origin.get('remote_host', '')}:{origin.get('remote_port', '')}".strip(":")
    origin_desc = (f"remote {remote}" if remote else
                   f"local process {intr.process} (pid={intr.pid})")
    record = quarantine_dir / f"intrusion_{intr.kind}_pid{intr.pid}.json"
    if dry_run:
        log_action("protection",
                   f"DRY RUN: would quarantine intrusion evidence: {intr.describe()}; "
                   f"origin: {origin_desc}",
                   agent_id=str(intr.pid), risk_level=risk,
                   details={"quarantine_dir": str(quarantine_dir), "evidence": evidence})
        return None
    quarantine_dir.mkdir(exist_ok=True)
    if not policy.authorize_write(record):
        return None  # refused: nothing written; refusal already audited
    record.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
    log_action("protection",
               f"Quarantined intrusion evidence: {intr.describe()}; origin: {origin_desc}",
               agent_id=str(intr.pid), risk_level=risk,
               details={"evidence_record": str(record), "origin": origin,
                        "evidence": evidence})
    if tq.get("study_and_report", True):
        send_alert(f"Intrusion recorded: {intr.detection.description}; "
                   f"origin: {origin_desc}",
                   risk_level=risk, agent_id=str(intr.pid),
                   kind=intr.kind, origin=origin)
    return record


def stop_intrusion(intr: Intrusion, risk: str, config: Config, *,
                   dry_run: bool = False,
                   safety: Optional[SafetyPolicy] = None) -> bool:
    """Stop an active intrusion: least-force, evidence-gated, never self-harm.

    The only force used is ending the local process that owns the malicious
    socket or runs the surveillance tool. No packets are sent and nothing is
    written outside defensive artifacts — consistent with the prime directive.
    """
    policy = safety or SafetyPolicy(config)
    if not policy.authorize_intrusion_stop(intr, detection=intr.detection, risk=risk):
        return False
    if intr.pid <= 0:
        log_action("termination",
                   f"Cannot stop intrusion {intr.kind}: no owning process to stop",
                   agent_id=str(intr.pid), risk_level=risk,
                   details={"kind": intr.kind})
        return False
    ids = config.section("intrusion_detection")
    needs_confirm = ids.get("require_confirmation", True)
    if ids.get("auto_stop_on_critical") and risk == "critical":
        needs_confirm = False
    if needs_confirm and not dry_run:
        answer = input(f"Stop intrusion from PID {intr.pid} ({intr.process})? "
                       f"risk={risk} [y/N] ")
        if answer.strip().lower() != "y":
            log_action("termination", f"Intrusion stop declined for PID {intr.pid}",
                       agent_id=str(intr.pid), risk_level=risk)
            return False
    if dry_run:
        return True
    try:
        proc_kill(intr.pid)
    except ProcessLookupError:
        return True  # already gone
    except PermissionError as e:
        log_action("termination", f"Failed to stop intrusion PID {intr.pid}: {e}",
                   agent_id=str(intr.pid), risk_level=risk)
        return False
    log_action("termination",
               f"Stopped intrusion {intr.kind} by terminating PID {intr.pid} ({intr.process})",
               agent_id=str(intr.pid), risk_level=risk,
               details={"connection": intr.conn.identity() if intr.conn else None})
    return True


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
    """Split the guardian into bounded worker processes when workload spikes."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.active_children: list[subprocess.Popen] = []
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

        self.active_children = [p for p in self.active_children if p.poll() is None]
        if self.cooldown_left > 0:
            self.cooldown_left -= 1
            return 0
        if threat_count < threshold:
            return 0

        desired_total = min(max_agents, max(min_agents, threat_count))
        spawn_count = max(0, desired_total - (1 + len(self.active_children)))
        if spawn_count <= 0:
            return 0

        spawned = 0
        for _ in range(spawn_count):
            cmd = [sys.executable, "guardian.py", "--once", "--pattern", scan_pattern]
            if dry_run:
                cmd.append("--dry-run")
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.active_children.append(proc)
            spawned += 1

        self.cooldown_left = cooldown_cycles
        log_action("escalation", f"Self-scaling spawned {spawned} guardian worker(s)",
                   details={"active_children": len(self.active_children),
                            "threat_count": threat_count, "threshold": threshold})
        return spawned


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
        result = (detector(proc, signatures) if detector is signature_scan else detector(proc))
        if result:
            findings.append(result)
    return findings


# --------------------------------------------------------------------------
# Threat quarantine, provenance, reporting
# --------------------------------------------------------------------------

def trace_provenance(proc: AgentProcess, *, max_depth: int = 8) -> dict[str, Any]:
    """Trace where a threat came from: exe, cwd, and the ancestor chain.

    Walks parent PIDs via ps until init (ppid 0/1), a cycle, missing parent,
    or max_depth. Each hop records pid/name/cmdline so the report identifies
    the exact origin process (e.g. the shell or service that spawned it).
    """
    prov: dict[str, Any] = {"pid": proc.pid, "ppid": proc.ppid, "name": proc.name,
                            "user": proc.user, "cmdline": proc.cmdline, "ancestors": []}
    try:
        prov["exe"] = os.readlink(f"/proc/{proc.pid}/exe")
    except OSError:
        prov["exe"] = ""
    try:
        prov["cwd"] = os.readlink(f"/proc/{proc.pid}/cwd")
    except OSError:
        prov["cwd"] = ""

    ppid = proc.ppid
    seen = {proc.pid}
    for _ in range(max_depth):
        if ppid in (0, 1) or ppid in seen:
            break
        seen.add(ppid)
        try:
            out = subprocess.run(
                ["ps", "-o", "ppid=,comm=,args=", "-p", str(ppid)],
                capture_output=True, text=True, timeout=5,
            ).stdout.strip()
        except (subprocess.SubprocessError, FileNotFoundError):
            break
        first = out.splitlines()[0] if out else ""  # one row per queried PID
        parts = shlex.split(first) if first else []
        if len(parts) < 2:
            break  # parent gone (exited between scan and trace)
        parent_ppid_s, parent_name = parts[0], parts[1]
        parent_cmdline = parts[2] if len(parts) > 2 else parent_name
        try:
            parent_ppid = int(parent_ppid_s)
        except ValueError:
            break
        prov["ancestors"].append({"pid": ppid, "name": parent_name,
                                  "cmdline": parent_cmdline})
        ppid = parent_ppid
    return prov


def quarantine_threat(proc: AgentProcess, det: Detection, risk: str, config: Config,
                      *, dry_run: bool = False,
                      safety: Optional[SafetyPolicy] = None) -> Optional[Path]:
    """Always quarantine a detected threat, study it, trace its origin, report it.

    Copies the threat's executable into the quarantine directory when it exists
    on disk (studied offline without executing it); otherwise quarantines the
    evidence record (cmdline, identity, provenance). Every decision — including
    safety refusals — is audited, and the report goes to the alert channel.
    """
    tq = config.section("threat_quarantine")
    if not tq.get("enabled", True):
        return None
    quarantine_dir = Path(str(tq.get("directory", "quarantine")))
    policy = safety or SafetyPolicy(config)
    prov = trace_provenance(proc)
    evidence: dict[str, Any] = {
        "detection": {"algorithm": det.algorithm, "description": det.description,
                      "matched": det.matched, "base_risk": det.base_risk,
                      "inaction_risk": risk},
        "process": proc.identity(),
        "provenance": prov,
    }
    exe = prov.get("exe") or ""
    if exe and Path(exe).is_file():
        evidence["threat_sha256"] = sha256_of(Path(exe))
    origin = prov["ancestors"][-1] if prov["ancestors"] else None
    origin_desc = (f"pid={origin['pid']} ({origin['name']})" if origin
                   else "origin unknown (no living ancestors)")

    target: Optional[Path] = None
    if dry_run:
        log_action("protection",
                   f"DRY RUN: would quarantine threat from pid={proc.pid} ({proc.name}); "
                   f"origin: {origin_desc}",
                   agent_id=str(proc.pid), risk_level=risk,
                   details={"quarantine_dir": str(quarantine_dir), "evidence": evidence})
    else:
        quarantine_dir.mkdir(exist_ok=True)
        if exe and Path(exe).is_file():
            target = quarantine_dir / f"pid{proc.pid}-{Path(exe).name}"
            if policy.authorize_write(target):
                shutil.copy2(exe, target)  # study the binary; never execute it
            else:
                target = None
        record = quarantine_dir / f"threat_pid{proc.pid}.json"
        if policy.authorize_write(record):
            record.write_text(json.dumps(evidence, indent=2), encoding="utf-8")
        log_action("protection",
                   f"Quarantined threat from pid={proc.pid} ({proc.name}) for analysis; "
                   f"origin: {origin_desc}",
                   agent_id=str(proc.pid), risk_level=risk,
                   details={"quarantined_to": str(target) if target else None,
                            "evidence_record": str(record),
                            "origin": origin, "evidence": evidence})

    if tq.get("study_and_report", True):
        send_alert(f"Threat quarantined from pid={proc.pid} ({proc.name}): "
                   f"{det.description}; origin: {origin_desc}",
                   risk_level=risk, agent_id=str(proc.pid),
                   algorithm=det.algorithm, origin=origin,
                   quarantined_to=str(target) if target else None)
    return target


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
            # Evidence hash before the move so the quarantined threat can be
            # studied and its origin reported precisely.
            evidence_hash = sha256_of(file_path) if file_path.exists() else None
            tq = config.section("threat_quarantine")
            quarantine_dir = Path(str(tq.get("directory", "quarantine"))) if tq.get("enabled", True) \
                else Path("quarantine")
            quarantine_dir.mkdir(exist_ok=True)
            target = quarantine_dir / file_path.name
            if not dry_run and file_path.exists():
                file_path.replace(target)
            log_action("update", f"Rejected unsigned update, quarantined: {file_path.name}",
                       details={"quarantined_to": str(target),
                                "sha256": evidence_hash,
                                "source": str(file_path)})
            if tq.get("study_and_report", True):
                send_alert(f"Malicious update quarantined: {file_path.name} "
                           f"(sha256={evidence_hash}); origin: updates inbox "
                           f"({file_path.parent})",
                           risk_level="high", source=str(file_path),
                           quarantined_to=str(target))
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
    for proc in AgentProcess.scan(scan_pattern):
        protected = check_protection(proc, config)
        terminated = False
        for det in detect_threats(proc, config, signatures):
            detections_seen.append(det)
            risk = assess_inaction_risk(det, config)
            log_action("detection", f"{det.description} (pid={proc.pid} {proc.name})",
                       agent_id=str(proc.pid), risk_level=risk,
                       details={"algorithm": det.algorithm, "matched": det.matched,
                                "sensitive_path": protected})
            quarantine_threat(proc, det, risk, config, dry_run=dry_run)
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

    # Intrusion & surveillance defense: find hacking/surveillance aimed at this
    # machine, record + report it, and stop it when inaction risk is high.
    ids = config.section("intrusion_detection")
    stop_on = str(ids.get("stop_on", escalate_on))
    stopped_pids: set[int] = set()
    for intr in detect_intrusions(config):
        risk = assess_intrusion_risk(intr, config)
        log_action("detection", f"INTRUSION: {intr.detection.description}",
                   agent_id=str(intr.pid), risk_level=risk,
                   details={"algorithm": intr.detection.algorithm, "kind": intr.kind,
                            "matched": intr.detection.matched,
                            "connection": intr.conn.identity() if intr.conn else None})
        quarantine_intrusion(intr, risk, config, dry_run=dry_run)
        if intr.pid in stopped_pids:
            continue  # already stopped this process this cycle
        if config.risk_at_least(risk, stop_on):
            log_action("escalation", f"Intrusion inaction risk {risk} >= {stop_on}, escalating",
                       agent_id=str(intr.pid), risk_level=risk)
            if risk != "critical":
                send_alert(f"INTRUSION: {intr.detection.description}",
                           risk_level=risk, agent_id=str(intr.pid), kind=intr.kind)
            if stop_intrusion(intr, risk, config, dry_run=dry_run):
                acted += 1
                stopped_pids.add(intr.pid)

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
    args = parser.parse_args(argv)

    config = Config.load(args.config)
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
