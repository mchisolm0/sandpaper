# Friction logger proof of concept

A local failure log for Claude Code, Codex, and OpenCode. Hooks record a tool
category and failure category, then ask the agent to explain actionable friction.
The report does not store tool input, tool output, host name, or working directory.

Requires Python 3.9+. The OpenCode adapter uses its plugin API and Node runtime.
This proof of concept was built against Claude Code 2.1.280, Codex CLI 0.155.1,
and OpenCode 1.18.32 on Linux. Registration and isolated payload tests are not
proof of delivery in live sessions; macOS and other versions are untested.

```sh
python3 friction.py install all
python3 friction.py check all
python3 friction.py report --expected 'What should have happened' --actual 'Sanitized explanation'
python3 friction.py uninstall all
```

Codex skips new hooks until you review and trust their definitions with `/hooks`
in an interactive Codex session. `check` verifies registration, not trust or
live delivery. Do not use the CLI's hook-trust bypass for routine sessions.
Fresh Codex CLI sessions, native subagents, and subagents launched through the
conversation collaboration tool passed live failure checks on this Linux setup.

Set `FRICTION_DIR` to change the output directory. The default is
`~/.local/state/friction`. Reports go to `friction.md`; a SQLite file there
deduplicates hook deliveries. Keep this directory private. Reports are plain
text, so never put secrets in manual explanations.

The installer adds only its own hooks to `~/.claude/settings.json` and
`~/.codex/hooks.json`, and writes `~/.config/opencode/plugins/friction.ts`.
Uninstall removes only those entries. It refuses to overwrite a different
OpenCode plugin at that path.

Detection is best effort. Expected exit 1 from simple search and comparison
commands is ignored. Interruptions are ignored. OpenCode adds reminders to
completed nonzero tool results; its other error path uses an experimental prompt
hook. A crash between report append and deduplication can leave a duplicate entry.

Run `python3 -m unittest test_friction.py` for the isolated check.
