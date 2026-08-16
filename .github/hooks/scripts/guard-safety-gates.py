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
            return Path(value)
    return None



def iter_replacements(data):
    """Yield (old, new) pairs from every recognized edit field, in order."""
    field_pairs = (
        ("old_string", "new_string"),
        ("oldString", "newString"),
        ("oldText", "newText"),
        ("old_text", "new_text"),
    )

    pairs = []
    for old_field, new_field in field_pairs:
        old_value = data.get(old_field)
        new_value = data.get(new_field)
        if isinstance(old_value, str) and isinstance(new_value, str):
            pairs.append((old_value, new_value))

    edits = data.get("edits")
    if isinstance(edits, list):
        for edit in edits:
            if isinstance(edit, dict):
                for old_field, new_field in field_pairs:
                    old_value = edit.get(old_field)
                    new_value = edit.get(new_field)
                    if isinstance(old_value, str) and isinstance(new_value, str):
                        pairs.append((old_value, new_value))
                        break
    return pairs



def proposed_content(data, current: str):
    """Reconstruct the post-edit file, or None if the proposal is ambiguous.

    Whole-file content fields take precedence (they describe the final state
    directly). Otherwise apply every recognized old/new replacement in order.
    """
    for field in CONTENT_FIELDS:
        value = data.get(field)
        if isinstance(value, str):
            return value

    proposed = current
    applied_any = False
    for old_value, new_value in iter_replacements(data):
        if old_value not in proposed:
            return None
        proposed = proposed.replace(old_value, new_value, 1)
        applied_any = True
    return proposed if applied_any else None



def log_action_calls(text: str) -> int:
    """Count call-like occurrences of log_action, tolerant of one space before '('."""
    return text.count("log_action(") + text.count("log_action (")



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

    current_logs = log_action_calls(current)
    proposed_logs = log_action_calls(proposed)
    if proposed_logs < current_logs:
        deny(f"Refusing to remove Guardian audit coverage from {path.name}: log_action() count would drop from {current_logs} to {proposed_logs}.")
        return

    for token in REQUIRED_STRINGS:
        if token in current and token not in proposed:
            deny(f"Refusing to remove Guardian safety gate '{token}' from {path.name}.")
            return

    allow()


if __name__ == "__main__":
    main()
