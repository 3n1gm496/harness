import type { AgentAdapter, Gate, HostSession, ResultRewrite } from "@harness/enforcement-core";
import type { ExtensionAPI, PiExtensionContext } from "./pi-types.js";

/**
 * Adapter PI: traduce gli eventi nativi della Extension API di PI nelle
 * primitive neutre di `@harness/enforcement-core` e riporta indietro le
 * decisioni del motore nel formato che PI si aspetta.
 *
 * È l'unico punto del sistema che conosce PI. Portare l'enforcement su un altro
 * coding agent significa scrivere un adapter analogo — il motore non cambia.
 */
export class PiAdapter implements AgentAdapter {
	constructor(private readonly pi: ExtensionAPI) {}

	onSessionStart(handler: (session: HostSession) => void | Promise<void>): void {
		this.pi.on("session_start", (_event, ctx) => handler(toSession(ctx)));
	}

	onToolCall(handler: (call: import("@harness/enforcement-core").ToolCall, session: HostSession) => Gate | Promise<Gate>): void {
		this.pi.on("tool_call", async (event, ctx) => {
			const gate = await handler(
				{ toolName: event.toolName, callId: event.toolCallId, input: event.input },
				toSession(ctx),
			);
			return gate.allow ? undefined : { block: true, reason: gate.reason };
		});
	}

	onToolResult(
		handler: (
			result: import("@harness/enforcement-core").ToolResult,
			session: HostSession,
		) => ResultRewrite | Promise<ResultRewrite>,
	): void {
		this.pi.on("tool_result", async (event, ctx) => {
			const rewrite = await handler(
				{
					toolName: event.toolName,
					callId: event.toolCallId,
					input: event.input,
					content: event.content,
					isError: event.isError,
				},
				toSession(ctx),
			);
			return rewrite ? { content: rewrite.content } : undefined;
		});
	}

	onShellCommand(
		handler: (
			command: import("@harness/enforcement-core").ShellCommand,
			session: HostSession,
		) => Gate | Promise<Gate>,
	): void {
		this.pi.on("user_bash", async (event, ctx) => {
			const gate = await handler({ command: event.command, cwd: event.cwd }, toSession(ctx));
			if (gate.allow) return undefined;
			return { result: { output: gate.reason, exitCode: 1, cancelled: false, truncated: false } };
		});
	}

	onSessionEnd(handler: () => void | Promise<void>): void {
		this.pi.on("session_shutdown", () => handler());
	}
}

/** Proietta il contesto PI sul contesto di sessione neutro. */
function toSession(ctx: PiExtensionContext): HostSession {
	return { cwd: ctx.cwd, hasUI: ctx.hasUI, ui: ctx.ui };
}
