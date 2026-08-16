"""Shared scoring primitives for Guardian's defensive benchmark harnesses.

All harnesses are strictly defensive: they score Guardian's ability to *detect*,
*refuse*, or *escalate* malicious activity from recorded samples. Nothing here
executes attack payloads or generates exploits.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional


@dataclass
class Sample:
    """One labelled evaluation item."""

    sample_id: str
    label: str  # "malicious" or "benign"
    text: str  # cmdline, skill content, or scenario text, depending on harness
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Outcome:
    """Guardian's verdict on one sample."""

    sample_id: str
    label: str
    flagged: bool  # True = Guardian detected/refused/escalated as expected
    detail: str = ""
    risk: Optional[str] = None
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Score:
    """Binary classification metrics for one harness run."""

    suite: str
    total: int = 0
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def detection_rate(self) -> float:  # recall / true-positive rate
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def false_positive_rate(self) -> float:
        denom = self.fp + self.tn
        return self.fp / denom if denom else 0.0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.total if self.total else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.detection_rate
        return 2 * p * r / (p + r) if (p + r) else 0.0

    def record(self, outcome: Outcome) -> None:
        self.total += 1
        positive = outcome.label == "malicious"
        if positive and outcome.flagged:
            self.tp += 1
        elif positive:
            self.fn += 1
        elif outcome.flagged:
            self.fp += 1
        else:
            self.tn += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "suite": self.suite,
            "total": self.total,
            "tp": self.tp,
            "fp": self.fp,
            "tn": self.tn,
            "fn": self.fn,
            "detection_rate": round(self.detection_rate, 4),
            "false_positive_rate": round(self.false_positive_rate, 4),
            "precision": round(self.precision, 4),
            "accuracy": round(self.accuracy, 4),
            "f1": round(self.f1, 4),
        }


def load_jsonl(path: Path) -> list[Sample]:
    """Load samples from JSON Lines: {"id", "label", "text", ...extra meta}."""
    samples: list[Sample] = []
    with path.open(encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            label = str(rec.get("label", "")).lower()
            if label not in ("malicious", "benign"):
                raise ValueError(f"{path}:{lineno}: label must be 'malicious' or 'benign'")
            text = rec.get("text")
            if not isinstance(text, str) or not text:
                raise ValueError(f"{path}:{lineno}: missing non-empty 'text'")
            meta = {k: v for k, v in rec.items() if k not in ("id", "label", "text")}
            samples.append(Sample(sample_id=str(rec.get("id", f"line-{lineno}")),
                                  label=label, text=text, meta=meta))
    return samples


def score_samples(suite: str, samples: Iterable[Sample],
                  evaluate) -> tuple[Score, list[Outcome]]:
    """Run `evaluate(sample) -> (flagged, detail, risk)` over samples and score."""
    score = Score(suite=suite)
    outcomes: list[Outcome] = []
    for sample in samples:
        flagged, detail, risk = evaluate(sample)
        outcome = Outcome(sample_id=sample.sample_id, label=sample.label,
                          flagged=flagged, detail=detail, risk=risk, meta=sample.meta)
        score.record(outcome)
        outcomes.append(outcome)
    return score, outcomes


def format_report(score: Score, outcomes: list[Outcome]) -> str:
    """Human-readable scorecard."""
    lines = [
        f"=== {score.suite} ===",
        f"samples: {score.total}  (tp={score.tp} fp={score.fp} tn={score.tn} fn={score.fn})",
        f"detection rate (recall): {score.detection_rate:.1%}",
        f"false-positive rate:     {score.false_positive_rate:.1%}",
        f"precision:               {score.precision:.1%}",
        f"accuracy:                {score.accuracy:.1%}",
        f"f1:                      {score.f1:.1%}",
    ]
    misses = [o for o in outcomes if o.label == "malicious" and not o.flagged]
    false_hits = [o for o in outcomes if o.label == "benign" and o.flagged]
    if misses:
        lines.append("missed (false negatives): " + ", ".join(o.sample_id for o in misses))
    if false_hits:
        lines.append("false alarms: " + ", ".join(o.sample_id for o in false_hits))
    return "\n".join(lines)
