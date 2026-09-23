import type { Plugin } from "@opencode-ai/plugin";
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);

export const Friction: Plugin = async ({ directory }) => {
  const reminders = new Map<string, string>();
  const pending = new Map<string, Promise<void>>();
  const record = async (sessionID: string, callID: string, tool: string, input: unknown, response: unknown) => {
    try {
      const process = run("python3", [__FRICTION_SCRIPT__, "opencode"], {
        cwd: directory, timeout: 40_000,
      });
      process.child.stdin?.end(JSON.stringify({
        hook_event_name: "PostToolUse", session_id: sessionID, tool_use_id: callID,
        tool_name: tool, tool_input: input, tool_response: response,
      }));
      const { stdout } = await process;
      const reminder: unknown = stdout.trim() ? JSON.parse(stdout) : undefined;
      return typeof reminder === "string" ? reminder : undefined;
    } catch {
      return "FRICTION: automatic recording failed. Run friction.py report manually, then continue.";
    }
  };
  return {
    "tool.execute.after": async ({ tool, sessionID, callID, args }, output) => {
      const exitCode = output.metadata?.exit;
      if (typeof exitCode !== "number" || exitCode === 0 || output.metadata?.interrupted === true) return;
      const reminder = await record(sessionID, callID, tool, args, { exit_code: exitCode });
      if (reminder) output.output += `\n${reminder}`;
    },
    event: async ({ event }) => {
      if (event.type === "session.deleted") {
        reminders.delete(event.properties.info.id);
        return;
      }
      if (event.type !== "message.part.updated") return;
      const part = event.properties.part;
      if (part.type !== "tool") return;
      const state = part.state;
      if (state.status !== "error") return;
      if (state.metadata?.interrupted === true) return;
      const recording = (async () => {
        const reminder = await record(part.sessionID, part.callID, part.tool, state.input,
          { status: state.status, error: state.error });
        if (reminder) reminders.set(part.sessionID, reminder);
      })();
      const waiting = Promise.all([pending.get(part.sessionID), recording]).then(() => {});
      pending.set(part.sessionID, waiting);
      await waiting;
      if (pending.get(part.sessionID) === waiting) pending.delete(part.sessionID);
    },
    "experimental.chat.system.transform": async ({ sessionID }, output) => {
      if (!sessionID) return;
      // Event handlers run concurrently with prompt construction.
      await pending.get(sessionID);
      const reminder = reminders.get(sessionID);
      if (reminder) {
        output.system.push(reminder);
        reminders.delete(sessionID);
      }
    },
  };
};
