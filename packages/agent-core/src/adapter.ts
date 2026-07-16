import type {
	AgentAdapter,
	Gate,
	HostSession,
	ResultRewrite,
	ShellCommand,
	ToolCall,
	ToolResult,
} from "@harness/enforcement-core";

/**
 * Adapter di enforcement per l'agente nativo. È l'immagine speculare del
 * `PiAdapter`: mentre quello traduce gli eventi di un agente di terze parti,
 * questo espone al NOSTRO loop le stesse primitive neutre di
 * `@harness/enforcement-core`. Il motore registra i suoi handler via i metodi
 * `on*`; il loop dell'agente li invoca tramite l'API `driver` (gate/rewrite)
 * nei punti giusti — prima di eseguire un tool, dopo averne il risultato, per
 * i comandi shell digitati dall'utente.
 *
 * Non c'è alcun agente esterno: qui l'agente e l'host sono la stessa cosa, e
 * questo adapter è il ponte formale che tiene il motore *identico* a come
 * governa qualunque altro adapter (stessa policy firmata, stesso audit).
 */
export class HarnessAgentAdapter implements AgentAdapter {
	private readonly sessionStartHandlers: Array<(session: HostSession) => void | Promise<void>> = [];
	private readonly toolCallHandlers: Array<(call: ToolCall, session: HostSession) => Gate | Promise<Gate>> = [];
	private readonly toolResultHandlers: Array<
		(result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>
	> = [];
	private readonly shellHandlers: Array<(command: ShellCommand, session: HostSession) => Gate | Promise<Gate>> = [];
	private readonly sessionEndHandlers: Array<() => void | Promise<void>> = [];

	onSessionStart(handler: (session: HostSession) => void | Promise<void>): void {
		this.sessionStartHandlers.push(handler);
	}
	onToolCall(handler: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>): void {
		this.toolCallHandlers.push(handler);
	}
	onToolResult(handler: (result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>): void {
		this.toolResultHandlers.push(handler);
	}
	onShellCommand(handler: (command: ShellCommand, session: HostSession) => Gate | Promise<Gate>): void {
		this.shellHandlers.push(handler);
	}
	onSessionEnd(handler: () => void | Promise<void>): void {
		this.sessionEndHandlers.push(handler);
	}

	// ---- Driver invocato dal loop dell'agente --------------------------------

	async emitSessionStart(session: HostSession): Promise<void> {
		for (const handler of this.sessionStartHandlers) await handler(session);
	}

	/** Valuta una tool call: il PRIMO deny vince (fail-closed su qualunque handler). */
	async gateToolCall(call: ToolCall, session: HostSession): Promise<Gate> {
		for (const handler of this.toolCallHandlers) {
			const gate = await handler(call, session);
			if (!gate.allow) return gate;
		}
		return { allow: true };
	}

	/** Applica in sequenza le riscritture del risultato (es. redaction dei segreti). */
	async rewriteResult(result: ToolResult, session: HostSession): Promise<ResultRewrite> {
		let current = result;
		let last: ResultRewrite;
		for (const handler of this.toolResultHandlers) {
			const rewrite = await handler(current, session);
			if (rewrite) {
				last = rewrite;
				current = { ...current, content: rewrite.content };
			}
		}
		return last;
	}

	/** Valuta un comando shell digitato dall'utente: il primo deny vince. */
	async gateShell(command: ShellCommand, session: HostSession): Promise<Gate> {
		for (const handler of this.shellHandlers) {
			const gate = await handler(command, session);
			if (!gate.allow) return gate;
		}
		return { allow: true };
	}

	async emitSessionEnd(): Promise<void> {
		for (const handler of this.sessionEndHandlers) await handler();
	}
}
