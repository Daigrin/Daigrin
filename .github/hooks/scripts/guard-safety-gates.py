#!/usr/bin/env python3
"""PreToolUse hook: block edits that weaken Guardian audit/safety gates."""
import json
import sys
from pathlib import Path

PATH_FIELDS = ("filePath", "file", "path", "notebookPath", "targetFile")
CONTENT_FIELDS = ("content", "contents", "text", "newContent", "new_content", "fileContents")
OLD_FIELDS = ("old_string", "oldString", "oldText", "old_text")
NEW_FIELDS = ("new_string", "newString", "newText", "new_text")
GUARDED = {"guardian.py", "guardian_audit.py"}
REQUIRED_STRINGS = (
    "authorize_termination",
    "authorize_write",
    "SAFETY REFUSAL",
    "least_force_first",
    "verify_signatures",
)


def allow():
    print(json.dumps({"continue": True}))



def deny(reason: str):
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))



def tool_input(payload):
    candidate = payload.get("tool_input") or payload.get("toolInput") or {}
    return candidate if isinstance(candidate, dict) else {}



def target_path(data):
    for field in PATH_FIELDS:
        value = data.get(field)
        if isinstance(value, str):
            # Only operate on repo files; ignore any directory components.
            return Path(Path(value).name)
    return None



def proposed_content(data, current: str):
    for field in CONTENT_FIELDS:
        value = data.get(field)
        if isinstance(value, str):
            return value
    old_value = next((data.get(field) for field in OLD_FIELDS if isinstance(data.get(field), str)), None)
    new_value = next((data.get(field) for field in NEW_FIELDS if isinstance(data.get(field), str)), None)
    if old_value is None or new_value is None:
        return None
    if old_value not in current:
        return None
    return current.replace(old_value, new_value, 1)



def main():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        allow()
        return

    data = tool_input(payload)
    path = target_path(data)
    if path is None or path.name not in GUARDED or not path.exists():
        allow()
        return

    current = path.read_text(encoding="utf-8")
    proposed = proposed_content(data, current)
    if proposed is None:
        allow()
        return

    current_logs = current.count("log_action(") + current.count("log_action (")
    proposed_logs = proposed.count("log_action(") + proposed.count("log_action (")
        deny(f"Refusing to remove Guardian audit coverage from {path.name}: log_action() count would drop from {current_logs} to {proposed_logs}.")
        return

    for token in REQUIRED_STRINGS:
        if token in current and token not in proposed:
            deny(f"Refusing to remove Guardian safety gate '{token}' from {path.name}.")
            return

    allow()


if __name__ == "__main__":
    main()
