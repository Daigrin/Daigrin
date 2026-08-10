#!/usr/bin/env python3
"""PreToolUse hook: block direct edits to the generated standalone build.

Reads the hook JSON payload on stdin, extracts the target file path from
well-known tool-input fields, and denies only when the target IS the
generated file -- mentions of the name elsewhere (searches, README text,
echo commands) are allowed through.
"""
import json
import sys

GENERATED = "guardian" + "_standalone.py"

DENY = {
    "hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": (
            GENERATED + " is generated. Edit guardian.py / "
            "guardian_audit.py instead, then run: python3 build_standalone.py"
        ),
    }
}

# Fields known to carry a target file path across edit-style tools.
PATH_FIELDS = ("filePath", "file", "path", "notebookPath", "targetFile")


def target_paths(payload):
    tool_input = payload.get("tool_input") or payload.get("toolInput") or {}
    if not isinstance(tool_input, dict):
        return []
    return [
        tool_input[f] for f in PATH_FIELDS
        if isinstance(tool_input.get(f), str)
    ]


def main():
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        print(json.dumps({"continue": True}))
        return

    for path in target_paths(payload):
        if path.rsplit("/", 1)[-1] == GENERATED:
            print(json.dumps(DENY))
            return
    print(json.dumps({"continue": True}))


if __name__ == "__main__":
    main()
