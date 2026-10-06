import { execFile } from "node:child_process";
import { promisify } from "node:util";

const run = promisify(execFile);
// friction.py redacts and keeps only a short tail; this just bounds the stdin payload.
const OUTPUT_TAIL = 65_536;

// OpenCode 2 passes a richer plugin context than @opencode-ai/plugin publishes types for (checked
// against 2.0.23), so this declares only the parts used here.
type ToolCall = { tool: string; sessionID: string; agent: string; id: string; input: unknown };
type ToolResult = ToolCall & (
  | {
    status: "completed";
    result: {
      output?: { exit?: number; output?: string };
      content: { type: "text"; text: string }[];
      metadata?: { exit?: number; interrupted?: boolean };
    };
  }
  | { status: "error"; error: { message: string } }
);
type Hook<Event> = (event: Event) => void | Promise<void>;
type Context = {
  app: { version: string };
  location: { directory: string };
  tool: {
    hook(name: "execute.before", callback: Hook<ToolCall>): Promise<unknown>;
    hook(name: "execute.after", callback: Hook<ToolResult>): Promise<unknown>;
  };
  session: { get(input: { sessionID: string }): Promise<{ model?: { id: string; providerID: string } } | undefined> };
};

export default {
  id: "friction",
  setup: async (ctx: Context) => {
    const started = new Map<string, number>();
    const record = async (call: ToolResult, response: unknown) => {
      const start = started.get(call.id);
      started.delete(call.id);
      try {
        const session = await ctx.session.get({ sessionID: call.sessionID }).catch(() => undefined);
        const process = run("python3", [__FRICTION_SCRIPT__, "opencode"], {
          cwd: ctx.location.directory, timeout: 40_000,
        });
        process.child.stdin?.end(JSON.stringify({
          hook_event_name: "PostToolUse", session_id: call.sessionID, tool_use_id: call.id,
          cwd: ctx.location.directory, tool_name: call.tool, tool_input: call.input, tool_response: response,
          duration_ms: start === undefined ? undefined : Date.now() - start, agent: call.agent,
          model: session?.model && `${session.model.providerID}/${session.model.id}`, harness_version: ctx.app.version,
        }));
        const { stdout } = await process;
        const reminder: unknown = stdout.trim() ? JSON.parse(stdout) : undefined;
        return typeof reminder === "string" ? reminder : undefined;
      } catch {
        return "FRICTION: automatic recording failed. Run friction.py report manually, then continue.";
      }
    };
    await ctx.tool.hook("execute.before", ({ id }) => {
      started.set(id, Date.now());
    });
    await ctx.tool.hook("execute.after", async (call) => {
      if (call.status === "error") {
        const reminder = await record(call, { status: "error", error: call.error.message });
        if (reminder) call.error.message += `\n${reminder}`;
        return;
      }
      const exit = call.result.output?.exit ?? call.result.metadata?.exit;
      if (typeof exit !== "number" || exit === 0 || call.result.metadata?.interrupted === true) {
        started.delete(call.id);
        return;
      }
      // OpenCode reports empty output as a placeholder; friction.py treats empty output as a signal.
      const output = call.result.output?.output === "(no output)" ? "" : call.result.output?.output ?? "";
      const reminder = await record(call, { exit_code: exit, output: output.slice(-OUTPUT_TAIL) });
      if (reminder) call.result.content.push({ type: "text", text: reminder });
    });
  },
};
