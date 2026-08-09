import json
import tempfile
import unittest
from pathlib import Path

from guardian_audit import log_action, read_audit_trail


class TestAuditLogging(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.log_path = Path(self.tmp.name) / "audit.log"

    def tearDown(self):
        self.tmp.cleanup()

    def test_log_action_writes_jsonl_entry(self):
        entry = log_action(
            "detection",
            "Suspicious syscall pattern detected",
            agent_id="agent-7",
            risk_level="high",
            details={"syscall": "ptrace"},
            log_path=self.log_path,
        )
        self.assertEqual(entry["action_type"], "detection")
        self.assertEqual(entry["risk_level"], "high")

        lines = self.log_path.read_text().splitlines()
        self.assertEqual(len(lines), 1)
        stored = json.loads(lines[0])
        self.assertEqual(stored["agent_id"], "agent-7")
        self.assertEqual(stored["details"]["syscall"], "ptrace")

    def test_appends_multiple_entries(self):
        log_action("detection", "one", log_path=self.log_path)
        log_action("termination", "two", log_path=self.log_path)
        self.assertEqual(len(read_audit_trail(self.log_path)), 2)

    def test_rejects_invalid_action_type(self):
        with self.assertRaises(ValueError):
            log_action("bogus", "nope", log_path=self.log_path)

    def test_rejects_invalid_risk_level(self):
        with self.assertRaises(ValueError):
            log_action("detection", "nope", risk_level="extreme", log_path=self.log_path)

    def test_filters_by_action_type_and_risk(self):
        log_action("detection", "d1", risk_level="low", log_path=self.log_path)
        log_action("detection", "d2", risk_level="critical", log_path=self.log_path)
        log_action("update", "u1", log_path=self.log_path)

        self.assertEqual(len(read_audit_trail(self.log_path, action_type="detection")), 2)
        self.assertEqual(len(read_audit_trail(self.log_path, risk_level="critical")), 1)
        self.assertEqual(len(read_audit_trail(self.log_path, action_type="update")), 1)

    def test_missing_log_returns_empty(self):
        self.assertEqual(read_audit_trail(Path(self.tmp.name) / "nope.log"), [])


if __name__ == "__main__":
    unittest.main()
