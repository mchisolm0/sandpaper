import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


SCRIPT = Path(__file__).with_name("friction.py")
spec = importlib.util.spec_from_file_location("friction", SCRIPT)
friction = importlib.util.module_from_spec(spec)
spec.loader.exec_module(friction)


class RedactionTest(unittest.TestCase):
    def test_secrets_are_redacted(self):
        cases = {
            "github token": ("git push https://ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/a/b", "ghp_"),
            "url credentials": ("psql postgres://admin:hunter2@db.internal:5432/app", "hunter2"),
            "auth header": ("curl -H 'Authorization: Bearer abc.def.ghi' https://api.example.com", "abc.def"),
            "api key header": ("curl -H 'X-Api-Key: plainvalue' https://api.example.com", "plainvalue"),
            "env assignment": ("DEPLOY_PW=s3cr3t-value ./deploy.sh", "s3cr3t"),
            "plain env assignment": ("export SOMETHING=opaque ; run", "opaque"),
            "secret flag": ("mytool --password 'pa ss' --verbose", "pa ss"),
            "json key": ('{"client_secret": "shh-its-secret", "ok": 1}', "shh-its"),
            "query param": ("GET /cb?code=1&access_token=qwerty123 HTTP/1.1", "qwerty123"),
            "anthropic key": ("sk-ant-api03-AAAABBBBCCCCDDDDEEEEFFFF", "AAAABBBB"),
            "aws key": ("aws configure set key AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7"),
            "jwt": ("token is eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJ"),
            "opaque blob": ("key 7fQpZ2mLx9RtV4sKcN8bJ3hW6yE1aU5o", "7fQpZ2mLx9"),
            "private key": ("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk\n-----END OPENSSH PRIVATE KEY-----", "b3Blbn"),
            "truncated private key": ("-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA", "MIIEow"),
            "json basic auth": ('{"Authorization": "Basic dXNlcjpwYXNzd29yZA=="}', "dXNlcjpw"),
            "escaped quote": ('{"password": "pa\\"ss-tail"}', "ss-tail"),
            "secret array": ('{"api_keys": ["first-key-1", "second-key-2"]}', "second-key"),
            "token after underscore": ("mcp__apikey_ghp_abcdefghijklmnopqrstuvwx", "ghp_"),
        }
        for name, (text, secret) in cases.items():
            with self.subTest(name):
                self.assertNotIn(secret, friction.redact(text))

    def test_secret_env_values_are_redacted_anywhere(self):
        with mock.patch.dict(os.environ, {"SERVICE_TOKEN": "literal-token-value"}):
            self.assertEqual(friction.redact("echo literal-token-value"), "echo [REDACTED]")

    def test_diagnostic_text_survives(self):
        for text in (
            "rg -n 'fn main' src/",
            "commit ee6c97236d1a1b5f1c8e0e5c2b9a4d7f3e2c1b0a on branch t3/24da13e8",
            "session 98b96543-1c57-433b-8814-da77292bef88",
            "error: cannot find module '/Users/mcc/code/Project2/src/components/Thing'",
            "ls: cannot access '/nonexistent': No such file or directory",
            "ssh git@github.com",
            '{"author": "Matt", "count": 12}',
        ):
            with self.subTest(text):
                self.assertEqual(friction.redact(text), text)

    def test_secrets_propagate_across_related_fields(self):
        command, output = friction.clip_fields([("login password=hunter2", 200, False),
                                                ("failed using hunter2, retried hunter2", 200, True)])
        self.assertNotIn("hunter2", command + output)
        found = set()
        self.assertEqual(friction.redact_value({"token": ["aaa-111-bbb"], "ok": ["x"]}, found),
                         {"token": "[REDACTED]", "ok": ["x"]})
        self.assertIn("aaa-111-bbb", found)

    def test_line_longer_than_redaction_window_is_omitted(self):
        text = "Authorization: Bearer " + "x" * friction.REDACT_WINDOW
        self.assertIn("omitted", friction.clip(text, 100, tail=True))

    def test_clip_redacts_before_truncating(self):
        text = "x" * 5000 + "\nAuthorization: Bearer abcdefghijkl\nfailed"
        clipped = friction.clip(text, 100, tail=True)
        self.assertTrue(clipped.startswith("["))
        self.assertTrue(clipped.endswith("failed"))
        self.assertNotIn("abcdefghijkl", clipped)


class ClassificationTest(unittest.TestCase):
    def test_low_signal(self):
        for command, output, expected in (
            ("rg -n needle src", "", True),
            ("grep needle file", "", True),
            ("cd src && rg needle", "", True),
            ("cd missing && rg needle", "cd: no such file", False),
            ("rg needle 2>/dev/null", "", True),
            ("grep needle < /missing", "bash: /missing: No such file or directory", False),
            ("! grep -q needle file", "", False),
            ("pnpm test", "", False),
        ):
            with self.subTest(command):
                self.assertEqual(friction.low_signal(command, 1, output), expected)


class HookTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.home = Path(directory.name)
        self.env = {**os.environ, "HOME": directory.name, "FRICTION_DIR": str(self.home / "reports")}

    def run_script(self, *args, event=None, check=True):
        return subprocess.run([sys.executable, str(SCRIPT), *args], input=json.dumps(event) if event else None,
                              text=True, env=self.env, capture_output=True, check=check)

    def records(self):
        path = self.home / "reports/events.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def claude_failure(self, call, command, error):
        return {"hook_event_name": "PostToolUseFailure", "session_id": "session", "tool_use_id": call,
                "cwd": str(SCRIPT.parent), "tool_name": "Bash", "tool_input": {"command": command},
                "error": error, "is_interrupt": False, "duration_ms": 217}

    def test_install_check_uninstall_preserves_other_settings(self):
        settings = self.home / ".claude/settings.json"
        settings.parent.mkdir()
        settings.write_text('{"theme":"dark","hooks":{"SessionStart":[{"hooks":[{"command":"other"}]}]}}')
        self.run_script("install", "all")
        self.run_script("check", "all")
        self.assertEqual(json.loads(settings.read_text())["theme"], "dark")
        self.run_script("uninstall", "all")
        self.assertIn("SessionStart", json.loads(settings.read_text())["hooks"])
        self.assertFalse((self.home / ".config/opencode/plugins/friction.ts").exists())

    def test_opencode_plugin_follows_installed_major_version(self):
        bin_dir = self.home / "bin"
        bin_dir.mkdir()
        fake = bin_dir / "opencode"
        self.env["PATH"] = f"{bin_dir}{os.pathsep}{self.env['PATH']}"
        plugin = self.home / ".config/opencode/plugins/friction.ts"
        for version, marker in (("1.18.32", "tool.execute.after"), ("2.0.23", "setup:")):
            fake.write_text(f"#!/bin/sh\necho {version}\n")
            fake.chmod(0o755)
            self.run_script("install", "opencode")
            self.assertIn(marker, plugin.read_text())
        plugin.write_text(plugin.read_text().replace("Date.now()", "Date.now() /* older template */"))
        self.run_script("install", "opencode")
        self.assertNotIn("older template", plugin.read_text())
        plugin.write_text(f"// calls {SCRIPT.resolve()} too, but is someone else's plugin\n")
        self.assertNotEqual(self.run_script("install", "opencode", check=False).returncode, 0)

    def test_failure_event_then_linked_note(self):
        event = self.claude_failure("call", "API_TOKEN=abc123secret pnpm build",
                                    "Exit code 2\nbuild failed with token abc123secret")
        output = self.run_script("claude", event=event).stdout
        self.run_script("claude", event=event)
        [captured] = self.records()
        self.assertEqual((captured["schema"], captured["kind"], captured["signal"]), (1, "event", "high"))
        self.assertEqual(captured["category"], "exit-2")
        self.assertEqual(captured["harness"]["name"], "claude-code")
        self.assertEqual(captured["tool"]["exit_code"], 2)
        self.assertEqual(captured["tool"]["duration_ms"], 217)
        self.assertEqual(captured["tool"]["input"], "API_TOKEN=[REDACTED] pnpm build")
        self.assertIn("build failed", captured["tool"]["output_tail"])
        self.assertIsNotNone(captured["context"]["commit"])
        self.assertTrue(captured["host"]["name"])
        self.assertNotIn("abc123secret", json.dumps(captured))
        self.assertIn(f"--event {captured['id']}", output)

        self.run_script("report", "--event", captured["id"], "--expected", "build passes",
                        "--actual", "missing env", "--noticed", "token was stale")
        [_, linked] = self.records()
        self.assertEqual((linked["kind"], linked["event"], linked["noticed"]), ("note", captured["id"], "token was stale"))
        rejected = self.run_script("report", "--event", "0000000000000000", "--expected", "x", "--actual", "y", check=False)
        self.assertEqual(rejected.returncode, 2)

    def test_search_without_match_is_low_signal(self):
        output = self.run_script("claude", event=self.claude_failure("rg", "rg -n needle src", "Exit code 1")).stdout
        self.run_script("claude", event=self.claude_failure("cd", "cd missing && rg needle", "Exit code 1\ncd: no such directory"))
        self.run_script("opencode", event={
            "hook_event_name": "PostToolUse", "session_id": "session", "tool_use_id": "oc", "tool_name": "shell",
            "tool_input": {"command": "cd . && rg needle"}, "tool_response": {"exit_code": 1, "output": ""}})
        low, high, compound = self.records()
        self.assertEqual((low["signal"], high["signal"], compound["signal"]), ("low", "high", "low"))
        self.assertEqual(output, "")

    def test_manual_report_captures_context(self):
        self.run_script("report", "--expected", "docs match", "--actual", "flag renamed")
        captured, linked = self.records()
        self.assertEqual((captured["source"], captured["tool"], linked["event"]), ("manual", None, captured["id"]))

    def test_codex_wrapper_restores_command_exit_and_duration(self):
        call = {"session_id": "session", "tool_use_id": "call", "tool_name": "Bash", "cwd": str(SCRIPT.parent)}
        pre = json.loads(self.run_script("codex-shell", event={
            **call, "hook_event_name": "PreToolUse", "tool_input": {"command": "make test"}}).stdout)
        wrapped = pre["hookSpecificOutput"]["updatedInput"]["command"]
        key = friction.event_key("codex", call)
        marker = wrapped.split("__FRICTION_EXIT_")[1].split(":")[0]
        self.run_script("codex", event={**call, "hook_event_name": "PostToolUse", "model": "gpt-test",
                                        "tool_input": {"command": wrapped},
                                        "tool_response": f"make: *** [test] Error 3\n__FRICTION_EXIT_{marker}:3\n"})
        [captured] = self.records()
        self.assertTrue(marker.startswith(key))
        self.assertEqual(captured["tool"]["input"], "make test")
        self.assertEqual(captured["tool"]["exit_code"], 3)
        self.assertIsInstance(captured["tool"]["duration_ms"], int)
        self.assertEqual(captured["tool"]["output_tail"], "make: *** [test] Error 3")
        self.assertEqual(captured["harness"]["model"], "gpt-test")


if __name__ == "__main__":
    unittest.main()
