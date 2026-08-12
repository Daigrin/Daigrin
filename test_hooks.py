import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SAFETY_HOOK = ROOT / ".github" / "hooks" / "scripts" / "guard-safety-gates.py"
STANDALONE_HOOK = ROOT / ".github" / "hooks" / "scripts" / "guard-standalone.py"
REQUIRED_STRINGS = (
    "authorize_termination",
    "authorize_write",
    "SAFETY REFUSAL",
    "least_force_first",
    "verify_signatures",
)


def run_hook(script_path, payload, *, cwd=None, stdin_text=None):
    proc = subprocess.run(
        ["python3", str(script_path)],
        input=json.dumps(payload) if stdin_text is None else stdin_text,
        text=True,
        capture_output=True,
        cwd=cwd,
        check=False,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"{script_path} exited with {proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(
            f"{script_path} returned non-JSON output:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        ) from exc


def fixture_guardian_file(dir, log_calls=3) -> Path:
    directory = Path(dir)
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "guardian.py"
    calls = "\n".join(
        f'    log_action("detection", "call {index}")'
        for index in range(1, log_calls + 1)
    )
    path.write_text(
        "from guardian_audit import log_action\n\n"
        "def authorize_termination():\n"
        "    return True\n\n"
        "def authorize_write():\n"
        "    return True\n\n"
        'SAFETY_REFUSAL = "SAFETY REFUSAL"\n'
        "least_force_first = True\n"
        "verify_signatures = True\n\n"
        "def guard():\n"
        f"{calls}\n",
        encoding="utf-8",
    )
    return path


class HookAssertions(unittest.TestCase):
    def assertAllowed(self, result):
        self.assertTrue(result.get("continue"), result)

    def assertDenied(self, result):
        self.assertEqual(
            result.get("hookSpecificOutput", {}).get("permissionDecision"),
            "deny",
            result,
        )


class TestGuardSafetyGates(HookAssertions):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_safety(self, payload, *, stdin_text=None):
        return run_hook(SAFETY_HOOK, payload, cwd=self.dir, stdin_text=stdin_text)

    def test_denies_whole_file_content_that_drops_log_action_calls(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8").replace(
            '    log_action("detection", "call 3")\n', "", 1
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertDenied(result)

    def test_denies_whole_file_content_that_removes_required_strings(self):
        replacements = {
            "authorize_termination": "authorize_stop",
            "authorize_write": "authorize_files",
            "SAFETY REFUSAL": "SAFETY BLOCKED",
            "least_force_first": "least_force_policy",
            "verify_signatures": "verify_hashes",
        }
        for token, replacement in replacements.items():
            with self.subTest(token=token):
                path = fixture_guardian_file(self.dir)
                proposed = path.read_text(encoding="utf-8").replace(token, replacement, 1)
                result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
                self.assertDenied(result)

    def test_denies_single_replacement_that_removes_log_action_call(self):
        fixture_guardian_file(self.dir)
        result = self.run_safety(
            {
                "tool_input": {
                    "path": "guardian.py",
                    "old_string": '    log_action("detection", "call 3")\n',
                    "new_string": "",
                }
            }
        )
        self.assertDenied(result)

    def test_denies_single_replacement_that_renames_authorize_termination(self):
        fixture_guardian_file(self.dir)
        result = self.run_safety(
            {
                "tool_input": {
                    "path": "guardian.py",
                    "old_string": "authorize_termination",
                    "new_string": "authorize_stop",
                }
            }
        )
        self.assertDenied(result)

    def test_denies_multi_edit_bypass_attempt_in_edits_list(self):
        fixture_guardian_file(self.dir)
        result = self.run_safety(
            {
                "tool_input": {
                    "path": "guardian.py",
                    "edits": [
                        {
                            "old_string": "least_force_first = True",
                            "new_string": "least_force_first = True  # retained",
                        },
                        {
                            "old_string": '    log_action("detection", "call 3")\n',
                            "new_string": "",
                        },
                    ],
                }
            }
        )
        self.assertDenied(result)

    def test_denies_sequential_top_level_replacements_when_second_violates(self):
        fixture_guardian_file(self.dir)
        result = self.run_safety(
            {
                "tool_input": {
                    "path": "guardian.py",
                    "old_string": "least_force_first = True",
                    "new_string": "least_force_first = True  # retained",
                    "oldText": '    log_action("detection", "call 3")\n',
                    "newText": "",
                }
            }
        )
        self.assertDenied(result)

    def test_denies_net_decrease_attack_that_readds_one_call_elsewhere(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8")
        proposed = proposed.replace('    log_action("detection", "call 2")\n', "", 1)
        proposed = proposed.replace('    log_action("detection", "call 3")\n', "", 1)
        proposed = proposed.replace(
            "def guard():\n",
            'def guard():\n    log_action("detection", "replacement")\n',
            1,
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertDenied(result)

    def test_denies_drop_even_when_spaced_comment_is_added(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8")
        proposed = proposed.replace('    log_action("detection", "call 2")\n', "", 1)
        proposed = proposed.replace(
            '    log_action("detection", "call 3")\n',
            "    # log_action (\n",
            1,
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertDenied(result)

    def test_allows_edits_to_non_guarded_files(self):
        for name in ("guardian_tray.py", "README.md", "test_guardian.py"):
            with self.subTest(name=name):
                result = self.run_safety({"tool_input": {"path": name, "content": "anything"}})
                self.assertAllowed(result)

    def test_allows_mentions_only_in_query_and_command_fields(self):
        result = self.run_safety(
            {
                "tool_input": {
                    "query": "find guardian.py references to log_action(",
                    "command": "echo guardian.py log_action(",
                }
            }
        )
        self.assertAllowed(result)

    def test_allows_malformed_json(self):
        result = self.run_safety({}, stdin_text="{not json")
        self.assertAllowed(result)

    def test_allows_missing_or_invalid_tool_input(self):
        payloads = (
            {},
            {"tool_input": {}},
            {"tool_input": []},
            {"toolInput": {"path": 7}},
            {"tool_input": {"path": ["guardian.py"]}},
        )
        for payload in payloads:
            with self.subTest(payload=payload):
                result = self.run_safety(payload)
                self.assertAllowed(result)

    def test_allows_guarded_path_that_does_not_exist(self):
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": "missing"}})
        self.assertAllowed(result)

    def test_allows_ambiguous_replacement_when_old_string_is_missing(self):
        fixture_guardian_file(self.dir)
        result = self.run_safety(
            {
                "tool_input": {
                    "path": "guardian.py",
                    "old_string": "does-not-exist",
                    "new_string": "replacement",
                }
            }
        )
        self.assertAllowed(result)

    def test_allows_whole_file_content_that_keeps_or_increases_guards(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8").replace(
            "def guard():\n",
            'def guard():\n    log_action("detection", "call 0")\n',
            1,
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertAllowed(result)

    def test_directory_prefixed_guarded_basenames_are_still_denied(self):
        cases = (
            ("./guardian.py", fixture_guardian_file(self.dir)),
            ("src/guardian.py", fixture_guardian_file(self.dir / "src")),
        )
        for payload_path, path in cases:
            with self.subTest(path=payload_path):
                proposed = path.read_text(encoding="utf-8").replace(
                    '    log_action("detection", "call 3")\n', "", 1
                )
                result = self.run_safety({"tool_input": {"path": payload_path, "content": proposed}})
                self.assertDenied(result)

    def test_directory_prefixed_non_guarded_basenames_are_allowed(self):
        for name in ("./README.md", "src/README.md"):
            with self.subTest(path=name):
                target = self.dir / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("placeholder\n", encoding="utf-8")
                result = self.run_safety({"tool_input": {"path": name, "content": "updated"}})
                self.assertAllowed(result)

    @unittest.expectedFailure
    def test_known_limitation_comment_mentions_can_mask_real_log_action_drop(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8").replace(
            '    log_action("detection", "call 3")\n',
            "    # log_action(\n",
            1,
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertDenied(result)

    @unittest.expectedFailure
    def test_known_limitation_multi_space_variants_can_evade_tolerant_counter(self):
        path = fixture_guardian_file(self.dir)
        proposed = path.read_text(encoding="utf-8")
        proposed = proposed.replace(
            '    log_action("detection", "call 2")\n',
            '    log_action  ("detection", "call 2")\n',
            1,
        )
        proposed = proposed.replace(
            '    log_action("detection", "call 3")\n',
            "    # log_action(\n    # log_action (\n",
            1,
        )
        result = self.run_safety({"tool_input": {"path": "guardian.py", "content": proposed}})
        self.assertDenied(result)


class TestGuardStandalone(HookAssertions):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def run_standalone(self, payload, *, stdin_text=None):
        return run_hook(STANDALONE_HOOK, payload, cwd=self.dir, stdin_text=stdin_text)

    def test_denies_guardian_standalone_targets(self):
        for path in ("guardian_standalone.py", "src/guardian_standalone.py"):
            with self.subTest(path=path):
                result = self.run_standalone({"tool_input": {"path": path}})
                self.assertDenied(result)

    def test_allows_mentions_only_in_command_and_query_fields(self):
        result = self.run_standalone(
            {
                "tool_input": {
                    "command": "cat guardian_standalone.py",
                    "query": "guardian_standalone.py",
                }
            }
        )
        self.assertAllowed(result)

    def test_allows_malformed_json(self):
        result = self.run_standalone({}, stdin_text="{not json")
        self.assertAllowed(result)

    def test_allows_edits_to_guardian_py(self):
        result = self.run_standalone({"tool_input": {"path": "guardian.py"}})
        self.assertAllowed(result)

    def test_allows_edits_to_guard_standalone_hook_itself(self):
        result = self.run_standalone(
            {"tool_input": {"path": ".github/hooks/scripts/guard-standalone.py"}}
        )
        self.assertAllowed(result)


if __name__ == "__main__":
    unittest.main()
