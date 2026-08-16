"""GABench-style harness: score Guardian's guardrail behavior on agent scenarios.

Inspired by GuardianAgentBench's guardrail evaluation: each scenario describes an
agent process (malicious or benign); a good guardrail detects and escalates
malicious agents while leaving benign ones alone. Scenarios are replayed through
guardian.run_cycle with AgentProcess.scan patched, in dry-run mode, so nothing is
ever killed.

Sample meta:
  expected_action: "flag" (default for malicious) — detection must escalate/act
                   "ignore" (default for benign) — no detection at all
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Optional
from unittest.mock import patch

from guardian import AgentProcess, Config, run_cycle

from . import Outcome, Sample, Score, load_jsonl, score_samples

SUITE_NAME = "gabench-guardrail"
DEFAULT_DATASET = Path(__file__).parent / "datasets" / "gabench_scenarios.jsonl"


def _make_config() -> Config:
    return Config(raw={"guardian_agent": {
        "threat_detection": {
            "enabled": True,
            "algorithms": ["signature_based", "anomaly_based",
                           "behavioral_based", "machine_learning"],
        },
        "risk_assessment": {"assess_inaction_risk": True, "escalate_on": "high"},
        "agent_termination": {
            "enabled": True,
            "terminate_malicious_agents": True,
            "require_confirmation": True,
            "auto_terminate_on_critical": True,
        },
        "system_protection": {"enabled": True, "block_sensitive_resource_access": True},
        "core_directives": {"protect_only": True},
    }})


def evaluate_sample(sample: Sample, config: Config, signatures: list[str]) -> Outcome:
    """Replay one scenario through run_cycle (dry-run; nothing is killed)."""
    proc = AgentProcess(pid=4242, name=sample.meta.get("name", "bench-agent"),
                        cmdline=sample.text)
    with tempfile.TemporaryDirectory() as tmp:
        audit_log = Path(tmp) / "audit.log"
        with patch.object(AgentProcess, "scan", return_value=[proc]):
            acted = run_cycle(config, signatures, dry_run=True,
                              scan_pattern="agent", audit_log=audit_log)
        entries = audit_log.read_text(encoding="utf-8").splitlines() if audit_log.exists() else []
    expected = sample.meta.get("expected_action") or (
        "flag" if sample.label == "malicious" else "ignore")
    if expected == "ignore":
        flagged = acted > 0 or any('"action_type": "detection"' in e for e in entries)
        return Outcome(sample.sample_id, sample.label, flagged,
                       detail="falsely flagged" if flagged else "left alone")
    flagged = acted > 0
    detail = "escalated/acted" if flagged else (
        "detected but not acted on" if entries else "no detection")
    return Outcome(sample.sample_id, sample.label, flagged, detail=detail)


def run(dataset: Optional[Path] = None,
        signatures: Optional[list[str]] = None) -> tuple[Score, list[Outcome]]:
    from guardian import load_signatures

    config = _make_config()
    sigs = signatures if signatures is not None else load_signatures()
    samples = load_jsonl(dataset or DEFAULT_DATASET)
    return score_samples(SUITE_NAME, samples,
                         lambda s: _verdict(evaluate_sample(s, config, sigs)))


def _verdict(outcome: Outcome):
    return outcome.flagged, outcome.detail, outcome.risk
