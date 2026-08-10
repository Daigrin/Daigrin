---
description: "Add a threat signature to Guardian: update the signature DB, add detector tests, and validate with a dry-run scan for false positives"
name: threat-signature
argument-hint: "Describe the threat pattern (e.g. 'reverse shell via bash /dev/tcp')"
agent: Guardian Engineer
---

# Add a Threat Signature

Threat to detect: ${input:threat:Describe the threat pattern or command}

## Steps

1. **Classify the threat** — decide whether it belongs in the static signature DB (exact command substring) or needs a detector-code change (behavioral pattern, anomaly heuristic). Prefer the signature DB when a stable substring exists.

2. **Add the signature** — append to threat_signatures.json under `signatures` (create the file if missing). Keep entries as short, distinctive command substrings; avoid patterns so broad they match benign admin commands.

3. **Add tests** in test_guardian.py:
   - Detection test: a synthetic `AgentProcess` whose cmdline contains the pattern produces a `signature_based` Detection at `high` base risk.
   - Refusal/false-positive test: at least one benign cmdline that must NOT match.
   - If detector code changed, also test the risk escalation in `assess_inaction_risk`.

4. **Run the tests** — `python3 -m pytest test_guardian.py test_guardian_audit.py -q`. All must pass.

5. **Validate with a dry run** — `python3 guardian.py --once --dry-run`. Report how many processes were scanned and confirm zero false-positive detections on the current process list.

6. **Audit check** — confirm the dry run wrote a `detection` lifecycle entry to guardian_audit.log and, if adaptive learning is enabled, that no benign signatures were absorbed.

## Output

Signature added (exact string), test names created, pytest results, dry-run scan summary, and any false-positive concerns with a recommended narrower pattern.
