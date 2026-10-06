#!/usr/bin/env python3
"""Record agent tool failures as redacted JSONL events that agents can annotate by event id."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone

SCHEMA = 1
INPUT_LIMIT = 2000
OUTPUT_LIMIT = 2000
PROBE_SECONDS = 2
VERSION_TTL_SECONDS = 600
SHELL_TOOLS = {"bash", "powershell", "exec_command", "shell", "shell_command"}
# Exit 1 from these means "no match" or "differs", so it is recorded as low signal.
EXPECTED_EXIT_1 = {"rg", "grep", "egrep", "fgrep", "diff", "cmp", "test", "["}
# Only these get a --version probe: rerunning an arbitrary failed command could have side effects.
VERSIONED_TOOLS = {"git", "gh", "rg", "grep", "jq", "make", "node", "bun", "deno", "pnpm", "npm", "npx", "yarn",
                   "python", "python3", "uv", "pip", "cargo", "rustc", "docker", "tsc", "mise", "curl"}
HARNESSES = {"claude": "claude-code", "codex": "codex", "opencode": "opencode"}
HARNESS_BINARIES = {"claude-code": "claude", "codex": "codex", "opencode": "opencode"}

REDACTED = "[REDACTED]"
# Names that mark the next value as secret: API_KEY=..., --token ..., "password": ...
_NAME = (r"[\w.-]{0,80}?(?:secret|token|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|private[_-]?key"
         r"|credentials?|auth(?!or)|cookie|session[_-]?key|signature)[\w.-]{0,80}")
# Anchors name matching to word starts, which keeps long unbroken runs fast.
_START = r"(?<![\w.-])"
# Skips values an earlier rule already replaced.
_VALUE = r"(?!\[REDACTED)(?:\"[^\"\n]*\"|'[^'\n]*'|[^\s\"'&;|,)}\]]+)"
_BLOB = r"A-Za-z0-9+_-"
# Each rule replaces its `s` group. Values from rules marked True are also redacted literally in later
# text, so a secret labeled in a command (API_KEY=x) is caught when the output echoes it unlabeled.
REDACTIONS = [(re.compile(pattern), harvest) for pattern, harvest in (
    (r"(?s)(?P<s>-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\Z))", False),
    (r"(?i)\b(?:(?:proxy-)?authorization|x-[a-z-]*(?:key|token)|api-key|(?:set-)?cookie)\s*:\s*(?P<s>[^\"'\n]+)", True),
    (r"(?i)\b[a-z][a-z0-9+.-]*://(?P<s>[^/\s:@\"']+:[^/\s@\"']*)@", True),
    (r"(?i)\bbearer\s+(?P<s>[\w.~+/=-]{8,})", True),
    (r"(?P<s>\b(?:gh[pousr]_\w{20,}|github_pat_\w{20,}|sk-[\w-]{20,}|xox[abeoprs]-[\w-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}"
     r"|AIza[\w-]{30,}|glpat-[\w-]{20,}|npm_\w{30,}|[sr]k_live_\w{16,}|hf_\w{30,}|tskey-[\w-]{16,}"
     r"|eyJ[\w-]{8,}\.[\w-]{8,}\.[\w-]{8,}))", True),
    (rf"(?i){_START}{_NAME}[\"']?\s*[:=]\s*(?P<s>{_VALUE})", True),
    (rf"(?i){_START}--?{_NAME}\s+(?P<s>{_VALUE})", True),
    # Every shell env assignment, secret-looking name or not: FOO=bar cmd, export foo=bar. Not harvested,
    # since values like NODE_ENV=test are common words.
    (rf"(?<![\w-])(?:export\s+\w+|[A-Z_][A-Z0-9_]*)=(?P<s>{_VALUE})", False),
    # Unknown token formats: long opaque runs mixing upper, lower, and digits. Hex hashes and UUIDs survive.
    (rf"(?<![{_BLOB}])(?=[{_BLOB}]*[A-Z])(?=[{_BLOB}]*[a-z])(?=[{_BLOB}]*[0-9])(?P<s>[{_BLOB}]{{32,}}={{0,2}})(?![{_BLOB}])",
     True),
)]


def redact(text, found=None):
    """Redact secrets in text. found: optional set that collects secret values to reuse on related text."""
    found = set() if found is None else found
    # Literal values of secret-named env vars catch tokens echoed in output in any format.
    found.update(value for name, value in os.environ.items()
                 if len(value) >= 8 and not value.startswith("/") and re.fullmatch(_NAME, name, re.I))
    for value in sorted(found, key=len, reverse=True):
        text = text.replace(value, REDACTED)

    for pattern, harvest in REDACTIONS:
        def replace(match):
            value = match["s"].strip("\"'")
            if harvest and len(value) >= 8:
                found.add(value)
            whole, start = match[0], match.start()
            return whole[:match.start("s") - start] + REDACTED + whole[match.end("s") - start:]
        text = pattern.sub(replace, text)
    return text


def clip(text, limit, tail=False, found=None):
    """Redact, then truncate to limit characters. tail keeps the end, where errors usually are."""
    if not isinstance(text, str) or not text.strip():
        return None
    # Redact a bounded window so huge outputs stay fast; the cut is far from what survives truncation.
    text = redact(text[-limit * 8:] if tail else text[:limit * 8], found)
    if len(text) <= limit:
        return text
    marker = f"[{len(text) - limit} chars truncated]"
    return f"{marker}\n{text[-limit:]}" if tail else f"{text[:limit]}\n{marker}"


def object_value(value):
    return value if isinstance(value, dict) else {}


def event_key(source, event):
    ids = [event.get("session_id"), event.get("tool_use_id")]
    if not all(isinstance(value, str) and value for value in ids):
        raise ValueError("missing call identity")
    return hashlib.sha256(json.dumps([source, *ids]).encode()).hexdigest()


def now_ms():
    return int(time.time() * 1000)


def shell_wrapper(key, start="START"):
    # Two subshells isolate the observer trap from the command's traps and exits.
    # The marker carries the start time so the post hook can compute duration without extra state.
    prefix = f"(\ntrap 'printf \"\\n__FRICTION_EXIT_{key}_{start}:%s\\n\" \"$?\"' EXIT\n(\neval "
    return prefix, "\n)\n)"


def unwrap_codex_shell(key, command):
    """Return (original command, start ms) for a command wrapped by wrap_codex_shell, else None."""
    prefix, suffix = (re.escape(part) for part in shell_wrapper(key))
    match = re.fullmatch(prefix.replace("START", r"(\d+)") + r"(.*)" + suffix, command, re.S)
    if not match:
        return None
    try:
        original = shlex.split(match[2])
    except ValueError:
        original = []
    return (original[0] if len(original) == 1 else match[2]), int(match[1])


def wrap_codex_shell(event):
    if event.get("hook_event_name") != "PreToolUse" or event.get("tool_name") != "Bash":
        return None
    inputs = object_value(event.get("tool_input"))
    command = inputs.get("command")
    if not isinstance(command, str) or os.name != "posix":
        raise ValueError("shell wrapper requires a POSIX command")
    key = event_key("codex", event)
    if unwrap_codex_shell(key, command):
        return None
    prefix, suffix = shell_wrapper(key, now_ms())
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


def response_text(response):
    """The human-readable part of a tool result, for the output tail."""
    if isinstance(response, str):
        return re.sub(r"\AExit code -?\d+\n?", "", response)
    result = object_value(response)
    parts = [result[name] for name in ("output", "stdout", "stderr", "error") if isinstance(result.get(name), str)]
    if parts:
        # Empty output stays empty: low-signal detection treats "printed nothing" as meaningful.
        return "\n".join(part for part in parts if part)
    return json.dumps(response, ensure_ascii=False) if response else None


def command_names(command):
    """argv[0] basenames of each simple command in a shell string, in order; None if it does not parse."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=True)
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return None
    names, start = [], True
    for token in tokens:
        if token in {"|", "||", "&&", ";", "&", "|&"}:
            start = True
        elif start and not re.fullmatch(r"\w+=.*|[({!]|time|env|sudo", token, re.S):
            names.append(Path(token).name)
            start = False
    return names


def low_signal(command, code, output):
    # Exit 1 from a trailing search or comparison. In a compound command, only trust it when the
    # command printed nothing, since an earlier step (cd, a build) can also exit 1 with an error.
    if code != 1 or not isinstance(command, str) or "\n" in command:
        return False
    names = command_names(command)
    if not names or names[-1] not in EXPECTED_EXIT_1:
        return False
    return len(names) == 1 or not (output or "").strip()


def categorize(shell, code, message):
    if shell and code is not None and code != 0:
        return f"exit-{code}"
    if isinstance(message, str):
        for pattern, name in (
            (r"timed out|timeout", "timeout"),
            (r"permission denied|not permitted", "permission-denied"),
            (r"unauthorized|authentication|invalid api key", "authentication"),
            (r"rate limit|too many requests", "rate-limit"),
            (r"no such file|file not found|does not exist", "missing-file"),
            (r"verification failed|failed to find expected", "patch-mismatch"),
        ):
            if re.search(pattern, message, re.I):
                return name
    return "tool-error"


def observe(source, event):
    """Normalize a hook payload into failure fields for capture(), or None when the call succeeded."""
    if not isinstance(event, dict):
        raise ValueError("expected object")
    expected_event = "PostToolUseFailure" if source == "claude" else "PostToolUse"
    if event.get("hook_event_name") != expected_event or event.get("is_interrupt") is True:
        return None
    tool = event.get("tool_name")
    if not isinstance(tool, str) or not tool:
        raise ValueError("missing tool name")
    key = event_key(source, event)
    inputs = object_value(event.get("tool_input"))
    command = inputs.get("command", inputs.get("cmd"))
    duration = event.get("duration_ms")
    response = event.get("error") if source == "claude" else event.get("tool_response")
    marker_code = None
    if source == "codex" and tool == "Bash" and isinstance(command, str):
        unwrapped = unwrap_codex_shell(key, command)
        if unwrapped:
            command, started = unwrapped
            duration = duration if type(duration) is int else now_ms() - started
        if isinstance(response, str):
            marker = re.search(r"\n__FRICTION_EXIT_" + key + r"_\d+:([0-9]{1,3})\s*\Z", response)
            if marker:
                marker_code = int(marker[1])
                response = response[:marker.start()]
    # A failed manual report must not recursively create another report.
    if isinstance(command, str) and re.search(r"\bfriction\.py\b", command):
        return None
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except ValueError:
            pass
    result = object_value(response)
    code = exit_status(response)
    if code is None:
        code = marker_code
    shell = tool.lower() in SHELL_TOOLS
    failed = source == "claude" or result.get("isError") is True or result.get("success") is False
    failed = failed or bool(result.get("error")) or result.get("status") in {"error", "failed"}
    if shell and code is not None:
        failed = failed or code != 0
    if isinstance(response, str) and code is None:
        failed = failed or bool(re.match(r"(?:Error:|error:|apply_patch verification failed:)", response))
    if not failed:
        return None
    output = response_text(response)
    if not shell:
        command = inputs or None
    elif not isinstance(command, str):
        command = None
    return {
        "key": key, "tool": tool, "command": command, "exit_code": code,
        "duration_ms": duration if type(duration) is int else None, "output": output,
        "category": categorize(shell, code, response if isinstance(response, str) else result.get("error")),
        "signal": "low" if shell and low_signal(command, code, output) else "high",
        "cwd": event.get("cwd"), "session_id": event.get("session_id"), "turn_id": event.get("turn_id"),
        "model": event.get("model"), "agent": event.get("agent_type", event.get("agent")),
        "permission_mode": event.get("permission_mode"), "transcript_path": event.get("transcript_path"),
        "harness_version": event.get("harness_version"),
    }


def run_probes(commands, cwd):
    """Run metadata commands in parallel under one deadline. Failed or missing commands are omitted."""
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    running, results = {}, {}
    for name, args in commands.items():
        try:
            running[name] = subprocess.Popen(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                             text=True, start_new_session=True)
        except OSError:
            pass
    deadline = time.monotonic() + PROBE_SECONDS
    for name, process in running.items():
        try:
            stdout, _ = process.communicate(timeout=max(0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            continue
        if process.returncode == 0 and stdout.strip():
            results[name] = stdout.strip()
    return results


def version_of(text):
    line = text.splitlines()[0] if text else ""
    match = re.search(r"\d+(?:\.\d+)+[\w.+-]*", line)
    return match[0] if match else line[:80] or None


def transcript_model(path):
    # Claude Code hook payloads omit the model; the transcript's latest assistant message has it.
    try:
        with open(path, "rb") as handle:
            handle.seek(max(0, os.fstat(handle.fileno()).st_size - 262144))
            tail = handle.read().decode("utf-8", "replace")
    except (OSError, TypeError):
        return None
    models = [model for model in re.findall(r'"model":"([^"]+)"', tail) if not model.startswith("<")]
    return models[-1] if models else None


def harness_name(source):
    if source in HARNESSES:
        return HARNESSES[source]
    # Manual reports infer the harness from its environment. Nested harnesses are best effort.
    if os.environ.get("CODEX_THREAD_ID"):
        return "codex"
    if os.environ.get("OPENCODE"):
        return "opencode"
    agent = re.match(r"[a-z-]+", os.environ.get("AI_AGENT", ""))
    return agent[0] if agent else "claude-code" if os.environ.get("CLAUDECODE") else None


def harness_version(name):
    # Prefer versions the harness exports; AI_AGENT can be inherited from an outer harness, so check its name.
    agent = re.fullmatch(r"([a-z-]+)_(\d+(?:-\d+)*)_\w+", os.environ.get("AI_AGENT", ""))
    if agent and agent[1] == name:
        return agent[2].replace("-", ".")
    return os.environ.get("CODEX_VERSION") if name == "codex" else None


def version_keys(names, cwd):
    """Cache keys for each binary found on PATH. They include cwd because version managers like mise
    resolve per directory behind one shim, and the binary mtime so upgrades miss the cache."""
    keys = {}
    for name in names:
        path = shutil.which(name)
        if path:
            keys[name] = f"{cwd}\0{path}\0{os.stat(path).st_mtime_ns}"
    return keys


def save_versions(cache, path):
    # Best effort: a lost cache write only costs a re-probe next time.
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
        temporary.write_text(json.dumps(cache))
        os.replace(temporary, path)
    except OSError:
        pass


def repo_name(remote, toplevel):
    match = re.search(r"([^/:]+/[^/]+?)(?:\.git)?/?\Z", remote or "")
    return match[1] if match else Path(toplevel).name


def capture(source, failure):
    """Build one schema-v1 event. Hook observations and manual reports both go through here."""
    cwd = failure.get("cwd") or os.getcwd()
    command = failure.get("command")
    shell = isinstance(command, str)
    harness = harness_name(source)
    version = failure.get("harness_version") or harness_version(harness)
    probes = {
        "repo": ["git", "rev-parse", "--show-toplevel", "HEAD", "--abbrev-ref", "HEAD"],
        "remote": ["git", "config", "--get", "remote.origin.url"],
        "tailscale": ["tailscale", "status", "--self", "--json"],
    }
    tools = []
    # Low-signal events stay cheap; version probes can cost a few hundred milliseconds, so they are cached.
    if failure["signal"] == "high":
        names = (command_names(command) or []) if shell else []
        tools = list(dict.fromkeys(name for name in names if name in VERSIONED_TOOLS))[:3]
    binaries = tools + ([HARNESS_BINARIES[harness]] if harness in HARNESS_BINARIES and not version else [])
    keys = version_keys(binaries, cwd)
    cache_path = output_dir() / "versions.json"
    try:
        cache = json.loads(cache_path.read_text())
    except (OSError, ValueError):
        cache = {}
    now = time.time()
    cache = {key: entry for key, entry in cache.items() if isinstance(entry, list) and len(entry) == 2
             and isinstance(entry[0], (int, float)) and now - entry[0] < VERSION_TTL_SECONDS} \
        if isinstance(cache, dict) else {}
    versions = {name: cache[key][1] for name, key in keys.items() if key in cache}
    probes.update({f"version:{name}": [name, "--version"] for name in keys if name not in versions})
    results = run_probes(probes, cwd if os.path.isdir(cwd) else None)
    fresh = {name: version_of(results.get(f"version:{name}")) for name in keys if name not in versions}
    if fresh:
        save_versions({**cache, **{keys[name]: [now, found] for name, found in fresh.items()}}, cache_path)
        versions.update(fresh)
    repo = results.get("repo", "").splitlines()
    try:
        host = json.loads(results.get("tailscale", "")).get("Self", {}).get("DNSName", "").split(".")[0]
    except (ValueError, AttributeError):
        host = ""
    session = failure.get("session_id") or os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CODEX_THREAD_ID")
    launcher = "t3-code" if any(name.startswith("T3CODE_") for name in os.environ) else os.environ.get("TERM_PROGRAM")
    tool = None
    if failure.get("tool"):
        tool_input = command if shell else json.dumps(command, ensure_ascii=False, sort_keys=True) if command else None
        secrets = set()
        tool = {
            "name": failure["tool"],
            "input": clip(tool_input, INPUT_LIMIT, found=secrets),
            "exit_code": failure.get("exit_code"),
            "duration_ms": failure.get("duration_ms"),
            "output_tail": clip(failure.get("output"), OUTPUT_LIMIT, tail=True, found=secrets),
            "versions": {name: versions.get(name) for name in tools},
        }
    return {
        "schema": SCHEMA,
        "kind": "event",
        "id": failure["key"][:16],
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "source": "manual" if source == "manual" else "hook",
        "signal": failure["signal"],
        "category": failure["category"],
        "harness": {
            "name": harness,
            "version": version or versions.get(HARNESS_BINARIES.get(harness)),
            "launcher": launcher,
            "session_id": session,
            "turn_id": failure.get("turn_id"),
            "model": failure.get("model") or transcript_model(failure.get("transcript_path")),
            "agent": failure.get("agent"),
            "permission_mode": failure.get("permission_mode"),
        },
        "tool": tool,
        "context": {
            "cwd": clip(cwd, INPUT_LIMIT),
            "repo": repo_name(results.get("remote"), repo[0]) if len(repo) == 3 else None,
            "branch": repo[2] if len(repo) == 3 else None,
            "commit": repo[1] if len(repo) == 3 else None,
        },
        "host": {
            "name": host or socket.gethostname().split(".")[0],
            "via": "tailscale" if host else "hostname",
            "os": sys.platform,
            "arch": os.uname().machine,
        },
    }


def note(event_id, expected, actual, noticed):
    if not expected.strip() or not actual.strip():
        raise ValueError("expected and actual must be nonempty")
    return {
        "schema": SCHEMA, "kind": "note", "event": event_id,
        "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "expected": clip(expected, INPUT_LIMIT), "actual": clip(actual, INPUT_LIMIT),
        "noticed": clip(noticed, INPUT_LIMIT),
    }


def output_dir():
    return Path(os.environ.get("FRICTION_DIR", Path.home() / ".local/state/friction")).expanduser()


def write(records, key=None, event_id=None):
    """Append JSONL records under the SQLite lock.

    key: new event key to deduplicate on; returns False when it was already recorded.
    event_id: existing event a note must attach to; raises ValueError when it is unknown.
    """
    state = output_dir()
    state.mkdir(parents=True, exist_ok=True, mode=0o700)
    # ponytail: a crash after append can duplicate; use a transactional report store if needed.
    with sqlite3.connect(state / "friction-hooks.sqlite3", timeout=20) as db:
        db.execute("CREATE TABLE IF NOT EXISTS reported (id TEXT PRIMARY KEY)")
        db.execute("BEGIN IMMEDIATE")
        if key and db.execute("SELECT 1 FROM reported WHERE id = ?", (key,)).fetchone():
            return False
        if event_id and not db.execute("SELECT 1 FROM reported WHERE substr(id, 1, 16) = ?", (event_id,)).fetchone():
            raise ValueError(f"unknown event {event_id}")
        with (state / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records))
        if key:
            db.execute("INSERT INTO reported VALUES (?)", (key,))
    return True


def script_command():
    return f"{shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))}"


def record(source, event):
    failure = observe(source, event)
    if failure is None:
        return None
    captured = capture(source, failure)
    if not write([captured], key=failure["key"]) or failure["signal"] == "low":
        return None
    return (
        f"Friction event {captured['id']}: {source} {failure['tool']} {failure['category']}, recorded with "
        "the command, output tail, and environment. If this failure was unexpected, attach a note to the "
        f"same event: {script_command()} report --event {captured['id']} --expected TEXT --actual TEXT "
        "--noticed TEXT. Skip it if the failure was expected. Do not paste secrets. Continue the task."
    )


def report(expected, actual, noticed=None, event_id=None):
    """Attach a note to an existing event, or capture a new manual event with the note."""
    if event_id:
        write([note(event_id, expected, actual, noticed)], event_id=event_id)
        return event_id
    key = uuid.uuid4().hex
    captured = capture("manual", {"key": key, "category": "manual", "signal": "high"})
    write([captured, note(captured["id"], expected, actual, noticed)], key=key)
    return captured["id"]


def hook_command(agent):
    return f"{script_command()} {agent}"


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
    script = json.dumps(str(Path(__file__).resolve()))
    # OpenCode 2 only loads plugins with a default {id, setup} export; 1.x expects named hook factories.
    version = run_probes({"opencode": ["opencode", "--version"]}, None).get("opencode", "")
    major = re.search(r"(\d+)\.\d+", version)
    template = "opencode-friction.ts" if major and int(major[1]) < 2 else "opencode-friction-v2.ts"
    content = Path(__file__).with_name(template).read_text().replace("__FRICTION_SCRIPT__", script)
    existing = target.read_text() if target.exists() else None
    installed = existing == content
    # Any plugin that calls this script is ours to replace or remove, whatever template or version wrote it.
    ours = existing is not None and script in existing
    if action == "install" and not installed:
        if (existing is not None and not ours) or (existing is None and target.is_symlink()):
            raise ValueError(f"existing plugin differs: {target}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
    elif action == "uninstall" and ours:
        target.unlink()
        return True
    return installed


def command_line():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["report", "install", "check", "uninstall"])
    parser.add_argument("agent", nargs="?", choices=["claude", "codex", "opencode", "all"])
    parser.add_argument("--event", help="event id from a friction reminder; omit to capture a new event")
    parser.add_argument("--expected")
    parser.add_argument("--actual")
    parser.add_argument("--noticed")
    args = parser.parse_args(sys.argv[1:])
    if args.action == "report":
        os.umask(0o077)
        event_id = report(args.expected or "", args.actual or "", args.noticed, args.event)
        print(f"Friction note recorded for event {event_id}: {output_dir() / 'events.jsonl'}")
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
    except ValueError as error:
        if len(sys.argv) > 1 and sys.argv[1] == "report":
            # Manual report errors are argument problems the caller can fix, e.g. an unknown event id.
            print(f"friction: {error}", file=sys.stderr)
            sys.exit(2)
        print("FRICTION: automatic recording failed. Run friction.py report manually.", file=sys.stderr)
        sys.exit(1)
    except Exception:
        # Fail open: never block the tool call, and never print payloads or exceptions that may hold credentials.
        print("FRICTION: automatic recording failed. Run friction.py report manually.", file=sys.stderr)
        sys.exit(1)
