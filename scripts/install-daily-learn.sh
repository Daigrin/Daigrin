#!/bin/sh
# Install (or remove) a daily cron entry that opens VS Code in this repo and
# runs the /guardian-learn consolidation cycle.
#
# Usage:
#   ./scripts/install-daily-learn.sh install [HH:MM]   # default 09:00
#   ./scripts/install-daily-learn.sh uninstall
#   ./scripts/install-daily-learn.sh status
#
# The cron entry writes a marker file (.daily-learn-request) that the repo's
# agents check at session start; it also tries to open VS Code with the
# /guardian-learn prompt pre-filled when a display/session is available.

set -eu

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MARKER="$REPO_ROOT/.daily-learn-request"
CRON_TAG="# guardian-daily-learn"

cmd_status() {
    if crontab -l 2>/dev/null | grep -q "$CRON_TAG"; then
        echo "installed:"
        crontab -l | grep "$CRON_TAG"
    else
        echo "not installed"
    fi
}

cmd_uninstall() {
    crontab -l 2>/dev/null | grep -v "$CRON_TAG" | crontab - || true
    echo "removed daily-learn cron entry"
}

cmd_install() {
    time_spec="${1:-09:00}"
    hour="${time_spec%%:*}"
    minute="${time_spec##*:}"
    case "$hour$minute" in
        *[!0-9]*) echo "invalid time '$time_spec' (use HH:MM)" >&2; exit 1 ;;
    esac

    runner="$REPO_ROOT/scripts/run-daily-learn.sh"
    line="$minute $hour * * * $runner >> $REPO_ROOT/.daily-learn.log 2>&1 $CRON_TAG"

    { crontab -l 2>/dev/null | grep -v "$CRON_TAG" || true; echo "$line"; } | crontab -
    echo "installed: /guardian-learn will be requested daily at $time_spec"
    echo "marker file: $MARKER   log: $REPO_ROOT/.daily-learn.log"
}

case "${1:-status}" in
    install)   cmd_install "${2:-}" ;;
    uninstall) cmd_uninstall ;;
    status)    cmd_status ;;
    *) echo "usage: $0 {install [HH:MM]|uninstall|status}" >&2; exit 1 ;;
esac
