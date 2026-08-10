"""Tests for guardian_tray — state summarization and icon rendering only.

The tray/dashboard UI itself is not exercised (needs a display); everything
below runs headless against synthetic audit logs in tmp_path.
"""

import json
from pathlib import Path

import pytest

from guardian_audit import log_action
from guardian_tray import STATUS, load_state


@pytest.fixture
def audit(tmp_path: Path) -> Path:
    return tmp_path / "audit.log"


class TestLoadState:
    def test_empty_log_is_stopped(self, audit):
        state = load_state(audit)
        assert state["status"] == "stopped"
        assert state["total_entries"] == 0
        assert state["recent"] == []

    def test_fresh_entries_report_active_or_idle(self, audit):
        log_action("detection", "scan cycle ran", log_path=audit)
        state = load_state(audit)
        assert state["status"] in ("active", "idle")
        assert state["total_entries"] == 1

    def test_critical_entry_escalates_status(self, audit):
        log_action("termination", "killed malicious agent", risk_level="critical",
                   log_path=audit)
        state = load_state(audit)
        assert state["status"] == "critical"

    def test_counts_and_risk_aggregation(self, audit):
        log_action("detection", "d1", risk_level="high", log_path=audit)
        log_action("detection", "d2", risk_level="high", log_path=audit)
        log_action("update", "u1", log_path=audit)
        state = load_state(audit)
        assert state["counts"]["detection"] == 2
        assert state["counts"]["update"] == 1
        assert state["risk_counts"]["high"] == 2

    def test_recent_is_newest_first(self, audit):
        log_action("detection", "first", log_path=audit)
        log_action("detection", "last", log_path=audit)
        state = load_state(audit)
        assert state["recent"][0]["description"] == "last"

    def test_malformed_timestamp_does_not_crash(self, audit):
        audit.write_text(json.dumps({
            "timestamp": "not-a-date", "action_type": "detection",
            "description": "x", "agent_id": None, "risk_level": None,
            "details": {},
        }) + "\n", encoding="utf-8")
        state = load_state(audit)
        assert state["total_entries"] == 1
        assert state["status"] in {s for s in STATUS}


class TestIcon:
    def test_make_icon_image_renders(self):
        pytest.importorskip("PIL")
        from guardian_tray import make_icon_image

        for color, _label in STATUS.values():
            img = make_icon_image(color)
            assert img.size == (64, 64)
            assert img.mode == "RGBA"
