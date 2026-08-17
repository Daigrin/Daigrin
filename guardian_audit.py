"""Audit logging for the Guardian agent.

Logs all Guardian actions (detections, escalations, terminations, updates)
to a JSON Lines audit trail. Configured via Guardian.yaml.
"""

import atexit
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, TextIO

AUDIT_LOG_PATH = Path("guardian_audit.log")

RISK_LEVELS = ("low", "medium", "high", "critical")
ACTION_TYPES = ("detection", "escalation", "termination", "update", "protection")

# Rotation defaults; guardian.py injects Guardian.yaml `audit:` values via
# configure_rotation() so this module stays usable standalone.
DEFAULT_MAX_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_BACKUP_COUNT = 5

_handle: Optional[TextIO] = None
_handle_path: Optional[Path] = None
_max_bytes = DEFAULT_MAX_BYTES
_backup_count = DEFAULT_BACKUP_COUNT


def configure_rotation(max_bytes: Optional[int] = None,
                       backup_count: Optional[int] = None) -> None:
    """Set size-based rotation limits for the audit trail."""
    global _max_bytes, _backup_count
    if max_bytes is not None:
        _max_bytes = max(0, int(max_bytes))
    if backup_count is not None:
        _backup_count = max(0, int(backup_count))


def _get_handle(log_path: Path) -> TextIO:
    """Return a persistent append handle for ``log_path``, reopening on change."""
    global _handle, _handle_path
    if _handle is not None and _handle_path != log_path:
        close_audit_log()
    if _handle is None:
        _handle = log_path.open("a", encoding="utf-8")
        _handle_path = log_path
    return _handle


def close_audit_log() -> None:
    """Close the persistent audit handle (also registered with atexit)."""
    global _handle, _handle_path
    if _handle is not None:
        _handle.close()
        _handle = None
        _handle_path = None


atexit.register(close_audit_log)


def _rotate_if_needed(log_path: Path, incoming_bytes: int) -> None:
    """Rotate ``log_path`` when the next write would exceed the size cap.

    ``log -> log.1 -> ... -> log.<backup_count>``; the oldest backup is
    dropped. Entries already written are preserved — rotation happens between
    writes, never mid-entry.
    """
    if _max_bytes <= 0 or _backup_count <= 0:
        return
    try:
        size = log_path.stat().st_size
    except OSError:
        return
    if size + incoming_bytes <= _max_bytes:
        return
    close_audit_log()
    for i in range(_backup_count - 1, 0, -1):
        src = log_path.with_name(f"{log_path.name}.{i}")
        dst = log_path.with_name(f"{log_path.name}.{i + 1}")
        if src.exists():
            src.replace(dst)
    oldest = log_path.with_name(f"{log_path.name}.1")
    log_path.replace(oldest)


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
    line = json.dumps(entry) + "\n"
    _rotate_if_needed(log_path, len(line.encode("utf-8")))
    f = _get_handle(log_path)
    f.write(line)
    f.flush()  # match prior durability: entry survives an immediate crash
    return entry


def read_audit_trail(
    log_path: Path = AUDIT_LOG_PATH,
    *,
    action_type: Optional[str] = None,
    risk_level: Optional[str] = None,
) -> list[dict[str, Any]]:
    """Read the audit trail, optionally filtering by action type or risk.

    Streams line-by-line and only JSON-parses lines whose raw text matches the
    requested filters, so cost scales with matches rather than total log size.
    """
    if not log_path.exists():
        return []
    type_marker = f'"action_type": "{action_type}"' if action_type is not None else None
    risk_marker = f'"risk_level": "{risk_level}"' if risk_level is not None else None
    entries = []
    with log_path.open(encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            if type_marker is not None and type_marker not in line:
                continue
            if risk_marker is not None and risk_marker not in line:
                continue
            entries.append(json.loads(line))
    return entries
