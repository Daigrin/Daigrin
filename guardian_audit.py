"""Audit logging for the Guardian agent.

Logs all Guardian actions (detections, escalations, terminations, updates)
to a JSON Lines audit trail. Configured via Guardian.yaml.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

AUDIT_LOG_PATH = Path("guardian_audit.log")

RISK_LEVELS = ("low", "medium", "high", "critical")
ACTION_TYPES = ("detection", "escalation", "termination", "update", "protection")


def log_action(
    action_type: str,
    description: str,
    *,
    agent_id: Optional[str] = None,
    risk_level: Optional[str] = None,
    details: Optional[dict[str, Any]] = None,
    log_path: Optional[Path] = None,
) -> dict[str, Any]:
    """Append one entry to the audit trail and return it.

    Args:
        action_type: One of ACTION_TYPES (detection, escalation, ...).
        description: Human-readable summary of what happened.
        agent_id: Identifier of the agent the action concerns, if any.
        risk_level: One of RISK_LEVELS, if applicable.
        details: Arbitrary extra context (e.g. matched signature, syscall).
        log_path: Audit trail file; defaults to the module-level AUDIT_LOG_PATH,
            read at call time so callers can redirect the trail.

    Raises:
        ValueError: If action_type or risk_level is not recognized.
    """
    if action_type not in ACTION_TYPES:
        raise ValueError(f"action_type must be one of {ACTION_TYPES}")
    if risk_level is not None and risk_level not in RISK_LEVELS:
        raise ValueError(f"risk_level must be one of {RISK_LEVELS}")
    if log_path is None:
        log_path = AUDIT_LOG_PATH

    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action_type": action_type,
        "description": description,
        "agent_id": agent_id,
        "risk_level": risk_level,
        "details": details or {},
    }
    with log_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
    return entry


def read_audit_trail(
    log_path: Path = AUDIT_LOG_PATH,
    *,
    action_type: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Read the audit trail, optionally filtering by action type or risk."""
    if not log_path.exists():
        return []
    entries = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue  # corrupt line (crash mid-write); never hide the rest of the trail
    if action_type is not None:
        entries = [e for e in entries if e["action_type"] == action_type]
    if risk_level is not None:
        entries = [e for e in entries if e["risk_level"] == risk_level]
    return entries
