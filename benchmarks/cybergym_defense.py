"""CyberGym-defense harness: Guardian as defender against exploit-style cmdlines.

CyberGym (UC Berkeley) scores agents on generating working PoC exploits. Guardian
cannot take that offensive test — its prime directive refuses exploit generation.
Instead this harness scores Guardian on the *defender* side: how reliably it
detects the kind of exploit-runner command lines such an agent would spawn
(fork bombs, reverse shells, download-to-shell, obfuscated payloads) while
ignoring benign admin commands.

Input: JSONL of {"id", "label", "text"} where text is a recorded cmdline.
No cmdline is ever executed — detection is purely static via guardian.detect_threats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from guardian import (RISK_ORDER, AgentProcess, Config, assess_inaction_risk,
                      detect_threats)

from . import Outcome, Sample, Score, load_jsonl, score_samples

SUITE_NAME = "cybergym-defense"
DEFAULT_DATASET = Path(__file__).parent / "datasets" / "cybergym_defense.jsonl"


def _make_config() -> Config:
    return Config(raw={"guardian_agent": {
        "threat_detection": {
            "enabled": True,
            "algorithms": ["signature_based", "anomaly_based",
                           "behavioral_based", "machine_learning"],
        },
        "risk_assessment": {"assess_inaction_risk": True},
    }})


def evaluate_sample(sample: Sample, config: Config, signatures: list[str]) -> Outcome:
    """Statically classify one recorded cmdline; nothing is executed."""
    proc = AgentProcess(pid=0, name="bench", cmdline=sample.text)
    detections = detect_threats(proc, config, signatures)
    if not detections:
        return Outcome(sample.sample_id, sample.label, False, detail="no detection")
    best = max(detections,
               key=lambda d: RISK_ORDER.index(assess_inaction_risk(d, config)))
    risk = assess_inaction_risk(best, config)
    return Outcome(sample.sample_id, sample.label, True,
                   detail=f"{best.algorithm}: {best.description}", risk=risk)


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
