"""Guardian tray — system-tray companion for the Guardian supervisor.

Shows what the Guardian agents are doing (live) and what they did (audit
trail) from a tray icon with a right-click command menu and a small
Tk dashboard window.

Read-only by design (prime directive): the tray never modifies the audit
log or the guardian process. "Run dry-run scan" executes guardian.py with
--once --dry-run, which detects and logs without killing anything.

Usage:
    python3 guardian_tray.py                  # tray icon + right-click menu
    python3 guardian_tray.py --dashboard-only # dashboard window, no tray
    python3 guardian_tray.py --audit FILE     # alternate audit log path

Dependencies: pystray, Pillow (tray mode); tkinter (dashboard, stdlib).
"""

import argparse
import subprocess
import sys
import threading
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from guardian_audit import read_audit_trail

POLL_SECONDS = 5
DASHBOARD_REFRESH_MS = 3000
RECENT_WINDOW = 25

RISK_COLORS = {
    "low": "#9e9e9e",
    "medium": "#f0ad4e",
    "high": "#ff7f50",
    "critical": "#ff3b30",
}

STATUS = {  # (fill color, label)
    "idle": ("#4caf50", "Idle — monitoring"),
    "active": ("#f0ad4e", "Active — processing detections"),
    "critical": ("#ff3b30", "CRITICAL — critical-risk action taken"),
    "stopped": ("#9e9e9e", "No guardian activity seen"),
}


def load_state(audit_path: Path) -> dict[str, Any]:
    """Summarize the audit trail into tray/dashboard state (read-only)."""
    entries = read_audit_trail(audit_path)
    now = time.time()
    status = "stopped"
    last_ts: Optional[float] = None
    if entries:
        try:
            last_ts = datetime.fromisoformat(entries[-1]["timestamp"]).timestamp()
        except (KeyError, ValueError):
            pass
        age = (now - last_ts) if last_ts else float("inf")
        if age <= POLL_SECONDS * 3:
            status = "active" if age <= POLL_SECONDS else "idle"
        else:
            status = "idle"
        recent = entries[-RECENT_WINDOW:]
        if any(e.get("risk_level") == "critical" for e in recent):
            status = "critical"

    counts = Counter(e.get("action_type", "unknown") for e in entries)
    risk_counts = Counter(
        e.get("risk_level") for e in entries if e.get("risk_level")
    )
    return {
        "status": status,
        "total_entries": len(entries),
        "counts": dict(counts),
        "risk_counts": dict(risk_counts),
        "recent": entries[-RECENT_WINDOW:][::-1],  # newest first
        "last_ts": last_ts,
    }


def make_icon_image(color: str, size: int = 64):
    """Draw the Guardian shield glyph filled with the status color."""
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    # Shield outline: rounded top, pointed bottom.
    margin = size // 8
    w = size - 2 * margin
    top, mid, bottom = margin, size // 2, size - margin
    d.polygon(
        [
            (margin, top + w // 6),
            (margin + w // 2, top),
            (margin + w, top + w // 6),
            (margin + w, mid),
            (margin + w // 2, bottom),
            (margin, mid),
        ],
        fill=color,
        outline="#222222",
    )
    # Inner "G" bar.
    d.rectangle(
        [margin + w // 3, top + w // 4, margin + 2 * w // 3, top + w // 4 + 4],
        fill="#ffffff",
    )
    return img


class GuardianTray:
    """System-tray icon with right-click command menu."""

    def __init__(self, audit_path: Path, dashboard: bool = True) -> None:
        import pystray

        self.audit_path = audit_path
        self.state = load_state(audit_path)
        self._dashboard_open = False
        self._want_dashboard = dashboard

        menu = pystray.Menu(
            pystray.MenuItem(
                lambda item: f"Status: {STATUS[self.state['status']][1]}",
                None,
                enabled=False,
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open dashboard", self._on_dashboard, default=True),
            pystray.MenuItem("Recent activity…", self._on_recent),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Run dry-run scan", self._on_dry_run),
            pystray.MenuItem("Open audit log", self._on_open_log),
            pystray.MenuItem("Refresh", self._on_refresh),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", self._on_quit),
        )
        self.icon = pystray.Icon(
            "guardian", make_icon_image(STATUS["stopped"][0]), "Guardian", menu
        )

    # -- menu handlers (all run on pystray's thread) --

    def _on_dashboard(self, icon=None, item=None) -> None:
        if self._dashboard_open:
            return
        self._dashboard_open = True
        threading.Thread(target=self._run_dashboard, daemon=True).start()

    def _run_dashboard(self) -> None:
        try:
            run_dashboard(self.audit_path)
        finally:
            self._dashboard_open = False

    def _on_recent(self, icon, item) -> None:
        lines = [
            f"[{e.get('risk_level') or '-':>8}] {e.get('action_type')}: {e.get('description')}"
            for e in self.state["recent"][:10]
        ]
        self.icon.notify("\n".join(lines) or "No activity yet.", "Guardian — recent activity")

    def _on_dry_run(self, icon, item) -> None:
        try:
            out = subprocess.run(
                [sys.executable, "guardian.py", "--once", "--dry-run"],
                capture_output=True, text=True, timeout=60,
            )
            msg = (out.stdout or out.stderr).strip() or "Scan finished."
        except (subprocess.SubprocessError, OSError) as e:
            msg = f"Scan failed to start: {e}"
        self.icon.notify(msg[-240:], "Guardian — dry-run scan")
        self._on_refresh()

    def _on_open_log(self, icon, item) -> None:
        opener = "xdg-open" if sys.platform.startswith("linux") else "open"
        try:
            subprocess.Popen([opener, str(self.audit_path.resolve())])
        except OSError as e:
            self.icon.notify(f"Cannot open log: {e}", "Guardian")

    def _on_refresh(self, icon=None, item=None) -> None:
        self.state = load_state(self.audit_path)
        self._apply_status()

    def _on_quit(self, icon, item) -> None:
        self.icon.stop()

    # -- main loop --

    def _apply_status(self) -> None:
        color, label = STATUS[self.state["status"]]
        self.icon.icon = make_icon_image(color)
        self.icon.title = (
            f"Guardian: {label} | {self.state['total_entries']} audit entries"
        )

    def _poll(self) -> None:
        while True:
            time.sleep(POLL_SECONDS)
            previous = self.state["status"]
            self.state = load_state(self.audit_path)
            self._apply_status()
            if self.state["status"] == "critical" and previous != "critical":
                self.icon.notify(
                    "A critical-risk action was taken. Check the dashboard.",
                    "Guardian — CRITICAL",
                )

    def run(self) -> None:
        threading.Thread(target=self._poll, daemon=True).start()
        self._apply_status()
        if self._want_dashboard:
            self._on_dashboard()
        self.icon.run()


def run_dashboard(audit_path: Path) -> None:
    """Small Tk window: status, counters, and the recent-activity feed."""
    import tkinter as tk

    root = tk.Tk()
    root.title("Guardian Dashboard")
    root.geometry("640x460")

    status_var = tk.StringVar()
    counts_var = tk.StringVar()
    risk_var = tk.StringVar()

    header = tk.Frame(root)
    header.pack(fill="x", padx=10, pady=(10, 4))
    status_lbl = tk.Label(header, textvariable=status_var, font=("TkDefaultFont", 12, "bold"))
    status_lbl.pack(anchor="w")
    tk.Label(header, textvariable=counts_var, justify="left").pack(anchor="w")
    tk.Label(header, textvariable=risk_var, justify="left").pack(anchor="w")

    feed = tk.Text(root, wrap="word", state="disabled", font=("TkFixedFont", 9))
    feed.pack(fill="both", expand=True, padx=10, pady=(4, 10))
    for risk, color in RISK_COLORS.items():
        feed.tag_configure(risk, foreground=color)

    def refresh() -> None:
        state = load_state(audit_path)
        color, label = STATUS[state["status"]]
        status_var.set(f"● {label}")
        status_lbl.configure(fg=color)
        counts_var.set(
            "Actions: "
            + ", ".join(f"{k}={v}" for k, v in sorted(state["counts"].items()))
            + f"  (total {state['total_entries']})"
        )
        risk_var.set(
            "Risk: "
            + (", ".join(f"{k}={v}" for k, v in sorted(state["risk_counts"].items())) or "none recorded")
        )
        feed.configure(state="normal")
        feed.delete("1.0", "end")
        for e in state["recent"]:
            ts = str(e.get("timestamp", ""))[:19].replace("T", " ")
            risk = e.get("risk_level") or ""
            line = f"{ts}  [{e.get('action_type','?'):<11}] {e.get('description','')}\n"
            feed.insert("end", line, risk if risk in RISK_COLORS else ())
        feed.configure(state="disabled")
        root.after(DASHBOARD_REFRESH_MS, refresh)

    refresh()
    root.mainloop()


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Guardian tray companion")
    parser.add_argument("--audit", type=Path, default=Path("guardian_audit.log"))
    parser.add_argument("--dashboard-only", action="store_true",
                        help="open the dashboard window without the tray icon")
    args = parser.parse_args(argv)

    if args.dashboard_only:
        run_dashboard(args.audit)
        return 0
    try:
        import pystray  # noqa: F401
        import PIL  # noqa: F401
    except ImportError:
        print("Tray mode needs pystray and Pillow: pip install pystray Pillow",
              file=sys.stderr)
        return 1
    GuardianTray(args.audit).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
