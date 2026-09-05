# Guardian PreToolUse Hooks

Safety hooks that intercept agent tool calls before execution. Each reads a JSON
payload on stdin and emits either `{"continue": true}` (allow) or a
`hookSpecificOutput.permissionDecision: "deny"` response.

## Hooks

| Hook | Guards | Denies when |
|---|---|---|
| `scripts/guard-safety-gates.py` | `guardian.py` (audit + safety gates) | A proposed edit would reduce `log_action()` call count or remove any required safety token (`authorize_termination`, `authorize_write`, `SAFETY REFUSAL`, `least_force_first`, `verify_signatures`) |
| `scripts/guard-standalone.py` | `guardian_standalone.py` (generated) | Any edit-style tool targets the generated file directly. Edit `guardian.py`/`guardian_audit.py` and run `build_standalone.py` instead |

## Threat model

These hooks defend against **accidental or adversarial edits routed through
recognized tool payloads** — whole-file `content` fields, old/new replacement
pairs (all alias families: `old_string`/`new_string`, `oldString`/`newString`,
`oldText`/`newText`, `old_text`/`new_text`), and list-shaped `edits`.
Reconstruction must always cover the **full post-edit state**; applying only a
subset of replacements is a bypass (see `.github/LESSONS.md`, 2026-08-12).

## Fail-open posture (deliberate)

Malformed JSON, unrecognized payload shapes, and genuinely ambiguous
replacements (old text not present) **allow** rather than deny. Rationale:
hooks must not brick unrelated tooling; the guarded invariants are also
enforced by `test_hooks.py` in CI. Manufactured ambiguity (e.g. duplicated
replacement pairs) must NOT reach the fail-open path.

## Accepted risks

- **Shell commands**: `command`/`query` fields are not parsed; `sed -i`/`>>`
  in a bash payload can touch guarded files. Accepted — shell parsing is
  fragile and high-false-positive. CI tests are the backstop.
- **Heuristic counting**: `log_action` counting is substring-based; comment
  mentions can mask a real deletion (tracked as `expectedFailure` tests,
  AST-based fix planned).

## Testing

`test_hooks.py` runs both hooks via subprocess with JSON payloads; it is wired
into `.github/workflows/guardian.yml`. Every bypass fix must land with a deny
regression test, and every fail-open behavior with an allow test.
