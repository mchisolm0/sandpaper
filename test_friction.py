import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("friction.py")


class FrictionTest(unittest.TestCase):
    def test_install_record_uninstall(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            env = {**os.environ, "HOME": directory, "FRICTION_DIR": str(home / "reports")}
            settings = home / ".claude/settings.json"
            settings.parent.mkdir()
            settings.write_text('{"theme":"dark","hooks":{"SessionStart":[{"hooks":[{"command":"other"}]}]}}')

            def run(*args, event=None):
                return subprocess.run([sys.executable, str(SCRIPT), *args], input=json.dumps(event) if event else None,
                                      text=True, env=env, capture_output=True, check=True)

            run("install", "all")
            run("check", "all")
            self.assertEqual(json.loads(settings.read_text())["theme"], "dark")
            self.assertIn("SessionStart", json.loads(settings.read_text())["hooks"])
            event = {"hook_event_name": "PostToolUseFailure", "session_id": "session", "tool_use_id": "call",
                     "tool_name": "Bash", "tool_input": {"command": "echo SECRET_TOKEN"}, "error": "SECRET_TOKEN permission denied"}
            run("claude", event=event)
            run("claude", event=event)
            report = (home / "reports/friction.md").read_text()
            self.assertEqual(report.count("\n## "), 1)
            self.assertNotIn("SECRET_TOKEN", report)
            run("uninstall", "all")
            self.assertIn("SessionStart", json.loads(settings.read_text())["hooks"])
            self.assertFalse((home / ".config/opencode/plugins/friction.ts").exists())


if __name__ == "__main__":
    unittest.main()
