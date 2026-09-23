#!/usr/bin/env python3
"""Normalize agent tool failures without persisting tool inputs or output."""

import hashlib
import argparse
import json
import os
from pathlib import Path
import re
import shlex
import sqlite3
import sys
from datetime import datetime, timezone


def object_value(value):
    return value if isinstance(value, dict) else {}


def event_key(source, event):
    ids = [event.get("session_id"), event.get("tool_use_id")]
    if not all(isinstance(value, str) and value for value in ids):
        raise ValueError("missing call identity")
    return hashlib.sha256(json.dumps([source, *ids]).encode()).hexdigest()


def shell_wrapper_parts(key):
    # Two subshells isolate the observer trap from the command's traps and exits.
    prefix = f"(\ntrap 'printf \"\\n__FRICTION_EXIT_{key}:%s\\n\" \"$?\"' EXIT\n(\neval "
    return prefix, "\n)\n)"


def wrap_codex_shell(event):
    if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") != "Bash":
        return None
    inputs = object_value(event.get("tool_input"))
    command = inputs.get("command")
    if not isinstance(command, str) or os.name != "posix":
        raise ValueError("shell wrapper requires a POSIX command")
    prefix, suffix = shell_wrapper_parts(event_key("codex", event))
    if command.startswith(prefix):
        return None
    return {"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "allow",
        "updatedInput": {**inputs, "command": prefix + shlex.quote(command) + suffix},
    }}


def exit_status(response):
    # ponytail: recognize known result formats; add adapters as tools expose new ones.
    if isinstance(response, dict):
        code = response.get("exit_code", response.get("exitCode"))
        if type(code) is int:
            return code
        return exit_status(response.get("metadata"))
    if isinstance(response, str):
        match = re.search(r"^(?:Exit code|Process exited with code) (-?\d+)\b", response, re.M)
        if match:
            return int(match[1])
    return None


def expected_exit(command, code):
    # Only plain searches/comparisons: never hide a failure in a compound command.
    if code != 1 or not isinstance(command, str) or re.search(r"[\n;&|<>`$()]", command):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    return bool(words) and Path(words[0]).name in {"rg", "grep", "egrep", "fgrep", "diff", "cmp", "test", "["}


def failure(source, event):
    if not isinstance(event, dict):
        raise ValueError("expected object")
    expected_event = "PostToolUseFailure" if source == "claude" else "PostToolUse"
    if event.get("hook_event_name") != expected_event:
        return None
    if event.get("is_interrupt") is True:
        return None
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise ValueError("missing tool name")
    inputs = object_value(event.get("tool_input"))
    command = inputs.get("command", inputs.get("cmd"))
    marker_code = None
    if source == "codex" and tool == "Bash":
        key = event_key(source, event)
        prefix, suffix = shell_wrapper_parts(key)
        if isinstance(command, str) and command.startswith(prefix) and command.endswith(suffix):
            original = shlex.split(command[len(prefix):-len(suffix)])
            if len(original) == 1:
                command = original[0]
        response = event.get("tool_response")
        if isinstance(response, str):
            marker = re.search(r"\n__FRICTION_EXIT_" + key + r":([0-9]{1,3})\s*\Z", response)
            if marker:
                marker_code = int(marker[1])
    # A failed manual report must not recursively create another report.
    if isinstance(command, str) and re.search(r"\bfriction\.py\b", command):
        return None
    response = event.get("error") if source == "claude" else event.get("tool_response")
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except ValueError:
            pass
    result = object_value(response)
    code = exit_status(response)
    if code is None:
        code = marker_code
    shell = tool.lower() in {"bash", "powershell", "exec_command", "shell", "shell_command"}
    if shell and expected_exit(command, code):
        return None
    failed = source == "claude" or result.get("isError") is True or result.get("success") is False
    failed = failed or bool(result.get("error")) or result.get("status") in {"error", "failed"}
    if shell and code is not None:
        failed = failed or code != 0
    if isinstance(response, str) and code is None:
        failed = failed or bool(re.match(r"(?:Error:|error:|apply_patch verification failed:)", response))
    if not failed:
        return None
    category = "tool-error"
    if shell and code is not None and code != 0:
        category = f"exit-{code}"
    else:
        message = response if isinstance(response, str) else result.get("error", "")
        if isinstance(message, str):
            for pattern, name in (
                (r"timed out|timeout", "timeout"),
                (r"permission denied|not permitted", "permission-denied"),
                (r"unauthorized|authentication|invalid api key", "authentication"),
                (r"rate limit|too many requests", "rate-limit"),
                (r"no such file|file not found", "missing-file"),
                (r"verification failed|failed to find expected", "patch-mismatch"),
            ):
                if re.search(pattern, message, re.I):
                    category = name
                    break
    # Custom tool names can contain sensitive data too; retain only known names.
    known_tools = {"bash", "powershell", "exec_command", "shell", "shell_command", "apply_patch", "read", "write", "edit", "glob", "grep"}
    label = tool.lower() if tool.lower() in known_tools else "mcp-tool" if tool.startswith("mcp__") else "other-tool"
    return event_key(source, event), label, category


def record(source, event):
    incident = failure(source, event)
    if incident is None:
        return None
    key, tool, category = incident
    state = output_dir()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    # Serialize automatic writers and deduplicate repeated delivery across processes.
    # ponytail: a crash after append can duplicate; use a transactional report store if needed.
    with sqlite3.connect(state / "friction-hooks.sqlite3", timeout=20) as db:
        db.execute("CREATE TABLE IF NOT EXISTS reported (id TEXT PRIMARY KEY)")
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM reported WHERE id = ?", (key,)).fetchone():
            return None
        append_report(f"{source}: {tool} completes without unexpected failure",
                      f"Automatic observation: {category}; event {key}. Tool input and output omitted.")
        db.execute("INSERT INTO reported VALUES (?)", (key,))
    return (
        f"Friction recorded {source} {tool} failure {category}, event {key[:12]}. "
        "If this exposed an environment or instruction problem, add a sanitized explanation "
        "with friction.py report --expected TEXT --actual TEXT. Do not copy secrets or raw output. "
        "Continue the task."
    )


def output_dir():
    return Path(os.environ.get("FRICTION_DIR", Path.home() / ".local/state/friction")).expanduser()


def append_report(expected, actual):
    if not expected.strip() or not actual.strip():
        raise ValueError("expected and actual must be nonempty")
    directory = output_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    report = directory / "friction.md"
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    entry = f"\n## {timestamp}\n\n### Expected\n\n    {expected.replace(chr(10), chr(10) + '    ')}\n\n### Actual\n\n    {actual.replace(chr(10), chr(10) + '    ')}\n"
    with report.open("a", encoding="utf-8") as handle:
        handle.write(entry)
    return report


def hook_command(agent):
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} {agent}"


def hook_specs(agent):
    if agent == "claude":
        return [("PostToolUseFailure", None, "claude")]
    return [("PostToolUse", None, "codex"), ("PreToolUse", "^Bash$", "codex-shell")]


def config_path(agent):
    home = Path.home()
    return home / (".claude/settings.json" if agent == "claude" else ".codex/hooks.json")


def edit_hooks(agent, action):
    path = config_path(agent)
    data = json.loads(path.read_text()) if path.exists() else {}
    hooks = data.setdefault("hooks", {})
    changed = False
    present = []
    for event, matcher, adapter in hook_specs(agent):
        command = hook_command(adapter)
        entries = hooks.setdefault(event, [])
        found = any(hook.get("command") == command for entry in entries
                    for hook in entry.get("hooks", []))
        present.append(found)
        if action == "install" and not found:
            entry = {"hooks": [{"type": "command", "command": command, "timeout": 40}]}
            if matcher:
                entry["matcher"] = matcher
            entries.append(entry)
            changed = True
        if action == "uninstall" and found:
            for entry in entries:
                entry["hooks"] = [hook for hook in entry.get("hooks", []) if hook.get("command") != command]
            hooks[event] = [entry for entry in entries if entry.get("hooks")]
            changed = True
    if changed:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2) + "\n")
    return all(present)


def edit_opencode(action):
    target = Path.home() / ".config/opencode/plugins/friction.ts"
    script = str(Path(__file__).resolve())
    content = Path(__file__).with_name("opencode-friction.ts").read_text().replace("__FRICTION_SCRIPT__", json.dumps(script))
    installed = target.exists() and target.read_text() == content
    if action == "install" and not installed:
        if target.exists() or target.is_symlink():
            raise ValueError(f"existing plugin differs: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    elif action == "uninstall" and installed:
        target.unlink()
    return installed


def command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["report", "install", "check", "uninstall"])
    parser.add_argument("agent", nargs="?", choices=["claude", "codex", "opencode", "all"])
    parser.add_argument("--expected")
    parser.add_argument("--actual")
    args = parser.parse_args(sys.argv[1:])
    if args.action == "report":
        print(append_report(args.expected or "", args.actual or ""))
        return
    if not args.agent:
        parser.error("agent required")
    agents = ["claude", "codex", "opencode"] if args.agent == "all" else [args.agent]
    failed = False
    for agent in agents:
        installed = edit_opencode(args.action) if agent == "opencode" else edit_hooks(agent, args.action)
        status = "registered" if args.action == "install" or installed else "missing"
        if args.action == "uninstall":
            status = "removed" if installed else "absent"
        print(f"{agent}: {status}")
        failed |= args.action == "check" and not installed
    if failed:
        sys.exit(1)


def main():
    if len(sys.argv) > 1 and sys.argv[1] in {"report", "install", "check", "uninstall"}:
        return command_line()
    source = sys.argv[1] if len(sys.argv) == 2 else ""
    if source not in {"claude", "codex", "codex-shell", "opencode"}:
        raise ValueError("unknown adapter")
    os.umask(0o077)
    event = json.load(sys.stdin)
    if not isinstance(event, dict):
        raise ValueError("expected object")
    if source == "codex-shell":
        output = wrap_codex_shell(event)
        if output:
            print(json.dumps(output))
        return
    reminder = record(source, event)
    if reminder:
        if source == "opencode":
            print(json.dumps(reminder))
        else:
            print(json.dumps({"hookSpecificOutput": {
                "hookEventName": event["hook_event_name"], "additionalContext": reminder,
            }}))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, OSError, RuntimeError, sqlite3.Error):
        # Never print payloads, subprocess output, or exceptions containing credentials.
        print("FRICTION: automatic recording failed. Run friction.py report manually.", file=sys.stderr)
        sys.exit(1)
