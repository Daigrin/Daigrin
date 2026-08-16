"""CLI for Guardian's defensive benchmark harnesses.

Usage:
    python3 -m benchmarks list                          # available suites
    python3 -m benchmarks <suite> [--dataset PATH] [--json]
    python3 -m benchmarks all [--json]

Suites: cybergym-defense, malskill, gabench-guardrail. All are defensive-only:
samples are recorded text classified statically or replayed in dry-run mode.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import format_report
from . import cybergym_defense, gabench, malskill

SUITES = {
    cybergym_defense.SUITE_NAME: cybergym_defense.run,
    malskill.SUITE_NAME: malskill.run,
    gabench.SUITE_NAME: gabench.run,
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="benchmarks",
                                     description="Guardian defensive benchmark harnesses")
    parser.add_argument("suite", choices=[*SUITES, "all", "list"])
    parser.add_argument("--dataset", type=Path, default=None,
                        help="override dataset path (JSONL, or skill-tree dir for malskill)")
    parser.add_argument("--json", action="store_true", help="emit scores as JSON")
    args = parser.parse_args(argv)

    if args.suite == "list":
        for name in SUITES:
            print(name)
        return 0

    names = list(SUITES) if args.suite == "all" else [args.suite]
    reports = []
    for name in names:
        score, outcomes = SUITES[name](dataset=args.dataset)
        reports.append((score, outcomes))

    if args.json:
        print(json.dumps([s.to_dict() for s, _ in reports], indent=2))
    else:
        print("\n\n".join(format_report(s, o) for s, o in reports))
    return 0


if __name__ == "__main__":
    sys.exit(main())
