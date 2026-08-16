"""MalSkill harness: score Guardian's detectors over malicious agent-skill packages.

Targets the MalSkillBench / MaliciousAgentSkillsBench layout: one directory per
skill containing SKILL.md plus any scripts/. Each skill's text content (markdown
instructions + script bodies) is fed to Guardian's detectors as the cmdline of a
synthetic process — approximating an agent asked to act on that skill. Scores
true-positive rate on malicious skills and false-positive rate on benign ones.

Content is only read and classified — scripts are never executed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from guardian import (RISK_ORDER, AgentProcess, Config, assess_inaction_risk,
                      detect_threats)

from . import Outcome, Sample, Score, load_jsonl, score_samples

SUITE_NAME = "malskill"
DEFAULT_DATASET = Path(__file__).parent / "datasets" / "malskill_samples.jsonl"
_TEXT_SUFFIXES = {".md", ".sh", ".py", ".ps1", ".js", ".ts", ".txt", ".json", ".yaml", ".yml"}
_MAX_CHARS_PER_FILE = 4000
_MAX_TOTAL_CHARS = 20000


def _make_config() -> Config:
    return Config(raw={"guardian_agent": {
        "threat_detection": {
            "enabled": True,
            "algorithms": ["signature_based", "anomaly_based",
                           "behavioral_based", "machine_learning"],
        },
        "risk_assessment": {"assess_inaction_risk": True},
    }})


def load_skill_dir(root: Path) -> list[Sample]:
    """Load a MalSkillBench-style tree: malware/ and benign/ subdirs of skill dirs."""
    samples: list[Sample] = []
    for label, dirname in (("malicious", "malware"), ("benign", "benign")):
        base = root / dirname
        if not base.is_dir():
            continue
        for skill_dir in sorted(p for p in base.iterdir() if p.is_dir()):
            text = _skill_text(skill_dir)
            if text:
                samples.append(Sample(sample_id=f"{dirname}/{skill_dir.name}",
                                      label=label, text=text))
    return samples


def _skill_text(skill_dir: Path) -> str:
    chunks: list[str] = []
    total = 0
    for path in sorted(skill_dir.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in _TEXT_SUFFIXES:
            continue
        try:
            chunk = path.read_text(encoding="utf-8", errors="replace")[:_MAX_CHARS_PER_FILE]
        except OSError:
            continue
        chunks.append(f"# file: {path.relative_to(skill_dir)}\n{chunk}")
        total += len(chunk)
        if total >= _MAX_TOTAL_CHARS:
            break
    return "\n".join(chunks)[:_MAX_TOTAL_CHARS]


def evaluate_sample(sample: Sample, config: Config, signatures: list[str]) -> Outcome:
    """Classify one skill's text; content is never executed."""
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
    source = dataset or DEFAULT_DATASET
    samples = load_skill_dir(source) if source.is_dir() else load_jsonl(source)
    return score_samples(SUITE_NAME, samples,
                         lambda s: _verdict(evaluate_sample(s, config, sigs)))


def _verdict(outcome: Outcome):
    return outcome.flagged, outcome.detail, outcome.risk
