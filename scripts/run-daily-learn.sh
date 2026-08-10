#!/bin/sh
# Daily trigger for the /guardian-learn cycle. Invoked by cron.
#
# What it does:
#   1. Drops a marker file (.daily-learn-request) with today's date so the next
#      agent session in this repo knows a learning cycle is due.
#   2. If a graphical/session VS Code CLI is reachable, opens the workspace
#      with the /guardian-learn prompt so the cycle runs interactively.
#
# The marker approach means the learning cycle is never silently skipped:
# agents check for it at session start (see .github/copilot-instructions.md).

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MARKER="$REPO_ROOT/.daily-learn-request"
TODAY="$(date +%F)"

# 1. Drop/refresh the marker (idempotent: just the date inside).
echo "$TODAY" > "$MARKER"
echo "$(date -Is) marker written for $TODAY"

# 2. Best-effort: open VS Code with the prompt if a CLI is available.
if command -v code >/dev/null 2>&1; then
    code "$REPO_ROOT" --command "workbench.action.chat.open" 2>/dev/null || true
    echo "$(date -Is) VS Code open attempted"
else
    echo "$(date -Is) 'code' CLI not found; marker only"
fi
