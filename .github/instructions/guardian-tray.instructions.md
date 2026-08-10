---
description: "Use when: editing guardian_tray.py or its tests — UI code conventions: read-only audit access, thread safety between pystray/Tk/main threads, headless-testability, notification rate limits"
applyTo: "**/guardian_tray.py, **/test_guardian_tray.py"
---

# Guardian Tray Conventions

## Prime Directive Applies to UI

- The tray is **read-only** on Guardian state: never write to guardian_audit.log, threat_signatures.json, or Guardian.yaml from tray code. The single permitted action is `guardian.py --once --dry-run` (detect-and-log only — never add a "terminate now" button; termination stays an operator decision in the guardian process).
- Status colors must never be alarmist: only a `critical` risk_level in the recent window turns the icon red.

## Threading

- Three threads coexist: pystray's event loop, Tk's mainloop (dashboard), and the poller. Shared state lives in `GuardianTray.state` and is only replaced wholesale (never mutated in place) so no locks are needed — keep it that way.
- Tk widgets may only be touched from the thread running `mainloop()`; schedule updates with `root.after()`.

## Testability

- All logic that can be headless must be headless: state summarization (`load_state`), icon rendering (`make_icon_image`), and menu-label lambdas. UI event handlers stay thin wrappers.
- Tests use tmp_path audit logs via `log_action(..., log_path=...)`; never touch the repo-root audit log.

## UX

- Notifications (`icon.notify`) are for critical transitions and on-demand summaries only — no polling-driven popups.
- Keep the menu flat; submenus only if entries exceed ~8 items.
