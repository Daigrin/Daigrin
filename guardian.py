"""Guardian agent — runnable supervisor.

Loads Guardian.yaml, monitors agent processes, detects threats, assesses the
risk of inaction, terminates malicious agents, enforces system protection,
checks for threat-intel updates, and logs everything to the audit trail.

Usage:
    python3 guardian.py                     # run the monitor loop
    python3 guardian.py --once              # single scan cycle (dry check)
    python3 guardian.py --config FILE       # alternate config file
"""

import argparse
import hashlib
import json
import shlex
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from guardian_audit import log_action

CONFIG_PATH = Path("Guardian.yaml")
RISK_ORDER = ("low", "medium", "high", "critical")

# Sensitive paths the guardian protects from modification by managed agents.
SENSITIVE_PATHS = ("/etc", "/bin", "/sbin", "/usr/bin", "/boot", str(Path.home() / ".ssh"))

# Suspicious commands/patterns used by the signature-based detector.
DEFAULT_SIGNATURES = (
    "rm -rf /",
    "mkfs",
    ":(){ :|:& };:",  # fork bomb
    "nc -l",  # netcat listener
    "/dev/tcp/",  # bash reverse shell
    "base64 -d",
    "chmod 777 /",
    "curl",  # paired with pipe-to-shell below
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
        for line in out.splitlines()[1:]:
            parts = line.split(None, 2)
            if len(parts) < 3:
                continue
            pid_s, name, cmdline = parts
            if pattern.lower() in cmdline.lower() and "guardian" not in cmdline.lower():
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

def terminate_agent(proc: AgentProcess, risk: str, config: Config, *, dry_run: bool = False) -> bool:
    """Terminate a malicious agent process, honoring confirmation policy."""
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
    except (ProcessLookupError, PermissionError) as e:
        log_action("termination", f"Failed to terminate PID {proc.pid}: {e}",
                   agent_id=str(proc.pid), risk_level=risk)
        return False
    log_action("termination", f"Terminated PID {proc.pid} ({proc.name})",
               agent_id=str(proc.pid), risk_level=risk,
               details={"cmdline": proc.cmdline})
    return True


def proc_kill(pid: int) -> None:
    """Send SIGKILL to a process (isolated for testability)."""
    import os
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
            log_action("update", f"Rejected unsigned update, quarantined: {file_path.name}",
                       details={"quarantined_to": str(target)})
            return False
    log_action("update", f"Applied update {file_path.name}",
               details={"sha256": sha256_of(file_path) if file_path.exists() else None,
                        "rollback_on_failure": upd.get("rollback_on_failure", False)})
    return True


# --------------------------------------------------------------------------
# Main loop
# --------------------------------------------------------------------------

def run_cycle(config: Config, signatures: list[str], *, dry_run: bool = False,
              scan_pattern: str = "agent", audit_log: Optional[Path] = None) -> int:
    """One monitor cycle. Returns the number of threats acted on."""
    if audit_log is not None:
        import guardian_audit
        previous = guardian_audit.AUDIT_LOG_PATH
        guardian_audit.AUDIT_LOG_PATH = audit_log
        try:
            return run_cycle(config, signatures, dry_run=dry_run, scan_pattern=scan_pattern)
        finally:
            guardian_audit.AUDIT_LOG_PATH = previous

    acted = 0
    escalate_on = config.section("risk_assessment").get("escalate_on", "high")
    for proc in AgentProcess.scan(scan_pattern):
        protected = check_protection(proc, config)
        for det in detect_threats(proc, config, signatures):
            risk = assess_inaction_risk(det, config)
            log_action("detection", f"{det.description} (pid={proc.pid} {proc.name})",
                       agent_id=str(proc.pid), risk_level=risk,
                       details={"algorithm": det.algorithm, "matched": det.matched,
                                "sensitive_path": protected})
            if config.risk_at_least(risk, escalate_on):
                log_action("escalation", f"Inaction risk {risk} >= {escalate_on}, escalating",
                           agent_id=str(proc.pid), risk_level=risk)
                if terminate_agent(proc, risk, config, dry_run=dry_run):
                    acted += 1
    return acted


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian agent supervisor")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    parser.add_argument("--once", action="store_true", help="run a single scan cycle and exit")
    parser.add_argument("--dry-run", action="store_true", help="detect and log without killing")
    parser.add_argument("--interval", type=float, default=5.0, help="seconds between scans")
    parser.add_argument("--pattern", default="agent", help="process cmdline pattern to monitor")
    args = parser.parse_args(argv)

    config = Config.load(args.config)
    if not config.enabled:
        print("guardian_agent.enabled is false; nothing to do.", file=sys.stderr)
        return 1

    signatures = load_signatures()
    log_action("update" if False else "detection",  # lifecycle marker in the trail
               f"Guardian started (pattern={args.pattern!r}, dry_run={args.dry_run})",
               details={"signatures_loaded": len(signatures)})

    if args.once:
        acted = run_cycle(config, signatures, dry_run=args.dry_run, scan_pattern=args.pattern)
        print(f"Scan complete: {acted} threat(s) acted on.")
        return 0

    print(f"Guardian running: scanning every {args.interval}s for {args.pattern!r} processes. Ctrl-C to stop.")
    try:
        while True:
            run_cycle(config, signatures, dry_run=args.dry_run, scan_pattern=args.pattern)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\nGuardian stopped.")
        return 0


if __name__ == "__main__":
    sys.exit(main())
