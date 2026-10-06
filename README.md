# Friction logger proof of concept

A local failure log for Claude Code, Codex, and OpenCode. Hooks record each
failed tool call as a redacted JSONL event with enough context to diagnose it,
then ask the agent to attach a short note to that same event.

Requires Python 3.9+. The OpenCode adapter uses its plugin API and Node runtime.
This proof of concept was built against Claude Code 2.1.285, Codex CLI 0.159.0,
and OpenCode 1.18.32 on Linux. Registration and isolated payload tests are not
proof of delivery in live sessions; macOS and other versions are untested.

```sh
python3 friction.py install all
python3 friction.py check all
# Attach a note to an event from a hook reminder
python3 friction.py report --event ID --expected 'What should have happened' --actual 'What happened' --noticed 'Likely cause'
# Or capture a new event when no hook fired, e.g. a misleading instruction
python3 friction.py report --expected '...' --actual '...'
python3 friction.py uninstall all
```

Codex skips new hooks until you review and trust their definitions with `/hooks`
in an interactive Codex session. `check` verifies registration, not trust or
live delivery. Do not use the CLI's hook-trust bypass for routine sessions.

## Output

Set `FRICTION_DIR` to change the output directory. The default is
`~/.local/state/friction`. Records go to `events.jsonl`, one JSON object per
line. A SQLite file there deduplicates hook deliveries and serializes writers,
and `versions.json` caches tool versions for ten minutes. Keep this directory
private: redaction is best effort.

Every record has `schema` (currently `1`) and `kind`. An `event` looks like:

```json
{
  "schema": 1, "kind": "event", "id": "187b14e0c6adf944", "ts": "2026-10-06T05:38:56.813Z",
  "source": "hook", "signal": "high", "category": "exit-2",
  "harness": {"name": "claude-code", "version": "2.1.285", "launcher": "t3-code", "session_id": "...",
              "turn_id": null, "model": "claude-opus-5-5", "agent": null, "permission_mode": "default"},
  "tool": {"name": "Bash", "input": "API_TOKEN=[REDACTED] pnpm build", "exit_code": 2, "duration_ms": 217,
           "output_tail": "build failed", "versions": {"pnpm": "11.28.3"}},
  "context": {"cwd": "/home/me/repo", "repo": "owner/repo", "branch": "main", "commit": "ee6c972..."},
  "host": {"name": "nobara", "via": "tailscale", "os": "linux", "arch": "x86_64"}
}
```

- `source` is `hook` or `manual`. Manual events have `tool: null`.
- `signal` is `low` for exit 1 from a trailing `rg`, `grep`, `diff`, `cmp`, or
  `test`. In a compound command it is low only when nothing was printed. Low
  events are recorded without prompting the agent or probing tool versions.
- `category` is `exit-N`, `tool-error`, `timeout`, `permission-denied`,
  `authentication`, `rate-limit`, `missing-file`, `patch-mismatch`, or `manual`.
- `host.name` is the Tailscale machine name when available, else the hostname.
- `tool.versions` only covers an allowlist of well-known tools, since rerunning
  an arbitrary failed command with `--version` could have side effects.
- Any field can be `null` when the harness does not provide it.

A `note` links to its event by id:

```json
{"schema": 1, "kind": "note", "event": "187b14e0c6adf944", "ts": "...",
 "expected": "build passes", "actual": "missing env", "noticed": "token was stale"}
```

Group by `id`/`event` to join them, e.g.
`jq -s 'group_by(.id // .event)' events.jsonl`.

## Hook payloads

| Field | Claude Code | Codex | OpenCode plugin |
| --- | --- | --- | --- |
| Trigger | `PostToolUseFailure` | `PostToolUse`, all calls | nonzero exit or error state |
| `tool.input` | `tool_input.command`, else `tool_input` | same; Bash is unwrapped first | tool args |
| `exit_code` | `Exit code N` in `error` | `exit_code`, `Exit code N`, or wrapper marker | `metadata.exit` |
| `duration_ms` | `duration_ms` | `duration_ms`, else wrapper start time | timed in plugin |
| `output_tail` | `error` | `tool_response` | tool output or error |
| `harness.version` | `AI_AGENT` | `CODEX_VERSION`, else `codex --version` | `opencode --version` |
| `harness.model` | transcript tail | `model` | `chat.params` |
| `harness.agent` | `agent_type` (subagents) | none | `chat.params` agent |

Codex Bash commands are wrapped by a `PreToolUse` hook so the exit status and
start time are recoverable from the result. Manual reports infer the harness
from `CODEX_THREAD_ID`, `OPENCODE`, or `AI_AGENT`; nested harnesses are best
effort.

## Redaction

Tool input, output, the working directory, and notes are redacted before they
are written, then truncated to 2000 characters (output keeps the tail). Rules:

- Private key blocks, `Authorization`/`Cookie`/`X-*-Key` header values,
  credentials in URLs, and bearer tokens.
- Known token formats: GitHub, OpenAI and Anthropic, Slack, AWS, Google,
  GitLab, npm, Stripe, Hugging Face, Tailscale, and JWTs.
- Values after secret-looking names: `API_KEY=x`, `--token x`,
  `"password": "x"`, `?access_token=x`.
- Every shell env assignment value: `FOO=bar cmd`, `export foo=bar`.
- Opaque runs of 32+ characters that mix upper case, lower case, and digits.
  Hex hashes and UUIDs are kept.
- Values of secret-named environment variables in the hook's environment, and
  secrets found in the tool input, are also replaced wherever they appear in
  the output.

## Behavior

The installer adds only its own hooks to `~/.claude/settings.json` and
`~/.codex/hooks.json`, and writes `~/.config/opencode/plugins/friction.ts`.
Uninstall removes only those entries. It refuses to overwrite a different
OpenCode plugin at that path.

Hooks fail open: any error prints one line without payload content and exits
nonzero, which harnesses treat as non-blocking. Metadata probes (git,
Tailscale, versions) run in parallel under a two second deadline. Detection is
best effort. Interruptions are ignored. OpenCode adds reminders to completed
nonzero tool results; its other error path uses an experimental prompt hook. A
crash between append and deduplication can leave a duplicate record.

Earlier versions wrote `friction.md`. It is left in place and no longer
written.

Run `python3 -m unittest test_friction.py` for the isolated check.
