import type { HostSession } from "@harness/enforcement-core";
import type { HarnessAgentAdapter } from "./adapter.js";
import { ContextManager, type ContextOptions, DEFAULT_CONTEXT_OPTIONS } from "./context.js";
import type { LlmClient } from "./llm.js";
import { DEFAULT_SYSTEM_PROMPT } from "./system-prompt.js";
import { ToolRegistry } from "./tools/registry.js";
import type { ToolContext } from "./tools/types.js";
import { ToolInputError } from "./tools/types.js";
import type { AssistantBlock, Message, ToolResultBlock, ToolUseBlock, UserBlock } from "./types.js";

/**
 * Il loop reason-act-observe dell'agente nativo. Questo È l'agente: assembla il
 * prompt, chiama il modello (via gateway), esegue i tool nativi che il modello
 * richiede e reinietta i risultati, iterando finché il modello non termina il
 * turno.
 *
 * Ogni tool call passa PRIMA per il gate di enforcement (policy firmata,
 * sandbox, kill switch): una call negata non viene eseguita — al modello torna
 * un tool_result d'errore con la motivazione, così può correggersi. Ogni
 * risultato passa per la redaction. L'audit è prodotto dagli stessi handler del
 * motore. In breve: la governance è identica a quella di qualunque altro
 * adapter, ma l'agente è nostro.
 */

/** Eventi strutturati emessi durante un run, per osservabilità/UI. */
export type AgentEvent =
	| { type: "assistant_text"; text: string }
	| { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
	| { type: "tool_denied"; id: string; name: string; reason: string }
	| { type: "tool_result"; id: string; name: string; isError: boolean; content: string }
	| { type: "usage"; inputTokens: number; outputTokens: number }
	| { type: "compaction"; removedMessages: number };

export interface AgentOptions {
	/** Client LLM (già puntato al gateway con il device token). */
	llm: LlmClient;
	/** Modello da usare (es. un id `claude-...`). */
	model: string;
	/** Adapter di enforcement con gli handler del motore già registrati. */
	adapter: HarnessAgentAdapter;
	/** Registro dei tool (default: i tool nativi). */
	tools?: ToolRegistry;
	/** System prompt (default: {@link DEFAULT_SYSTEM_PROMPT}). */
	systemPrompt?: string;
	/** Directory di lavoro della sessione (default: process.cwd()). */
	cwd?: string;
	/** Max token per singola risposta del modello (default 4096). */
	maxTokens?: number;
	/** Tetto di iterazioni tool per singolo run (anti-loop, default 50). */
	maxIterations?: number;
	/** Se true usa lo streaming e invoca `onText` con i delta (default false). */
	stream?: boolean;
	/** Callback per il testo del modello (delta in streaming, o blocco intero). */
	onText?: (text: string) => void;
	/** Callback per gli eventi strutturati. */
	onEvent?: (event: AgentEvent) => void;
	/** Opzioni di gestione del contesto. */
	context?: ContextOptions;
	/** true se c'è una UI umana (per le notifiche del motore). */
	hasUI?: boolean;
}

export interface AgentResult {
	/** Testo finale dell'assistente (concatenazione dei blocchi di testo dell'ultimo turno). */
	text: string;
	/** Numero di iterazioni del loop (chiamate al modello). */
	iterations: number;
	/** Token totali consumati nel run. */
	usage: { inputTokens: number; outputTokens: number };
	/** true se il loop si è fermato per aver raggiunto `maxIterations`. */
	stoppedOnLimit: boolean;
}

export class Agent {
	private readonly llm: LlmClient;
	private readonly model: string;
	private readonly adapter: HarnessAgentAdapter;
	private readonly tools: ToolRegistry;
	private readonly cwd: string;
	private readonly maxTokens: number;
	private readonly maxIterations: number;
	private readonly stream: boolean;
	private readonly onText: ((text: string) => void) | undefined;
	private readonly onEvent: ((event: AgentEvent) => void) | undefined;
	private readonly context: ContextManager;
	private readonly session: HostSession;
	private readonly systemPrompt: string;
	private started = false;

	constructor(options: AgentOptions) {
		this.llm = options.llm;
		this.model = options.model;
		this.adapter = options.adapter;
		this.tools = options.tools ?? new ToolRegistry();
		this.cwd = options.cwd ?? process.cwd();
		this.maxTokens = options.maxTokens ?? 4096;
		this.maxIterations = options.maxIterations ?? 50;
		this.stream = options.stream ?? false;
		this.onText = options.onText;
		this.onEvent = options.onEvent;
		this.context = new ContextManager(
			options.context ?? DEFAULT_CONTEXT_OPTIONS,
			options.systemPrompt ?? DEFAULT_SYSTEM_PROMPT,
		);
		this.systemPrompt = options.systemPrompt ?? DEFAULT_SYSTEM_PROMPT;
		this.session = { cwd: this.cwd, hasUI: options.hasUI ?? false };
	}

	/** Notifica il motore dell'inizio sessione (una volta sola). */
	async start(): Promise<void> {
		if (this.started) return;
		this.started = true;
		await this.adapter.emitSessionStart(this.session);
	}

	/** Chiude la sessione: il motore fa flush dell'audit e ferma i loop. */
	async stop(): Promise<void> {
		await this.adapter.emitSessionEnd();
	}

	/**
	 * Esegue un turno completo a partire da un input utente: cicla modello↔tool
	 * finché il modello non termina (nessuna tool call) o si raggiunge il tetto
	 * di iterazioni. Restituisce il testo finale.
	 */
	async run(userInput: string, signal?: AbortSignal): Promise<AgentResult> {
		await this.start();
		this.context.add({ role: "user", content: userInput });

		const usage = { inputTokens: 0, outputTokens: 0 };
		let iterations = 0;
		let finalText = "";
		let stoppedOnLimit = false;

		for (;;) {
			if (iterations >= this.maxIterations) {
				stoppedOnLimit = true;
				break;
			}
			iterations++;

			const removed = await this.context.maybeCompact(this.llm, this.model);
			if (removed > 0) this.onEvent?.({ type: "compaction", removedMessages: removed });

			const request = {
				model: this.model,
				maxTokens: this.maxTokens,
				system: this.systemPrompt,
				messages: this.context.messages,
				tools: this.tools.definitions(),
			};
			const response = this.stream ? await this.llm.stream(request, this.onText) : await this.llm.complete(request);

			usage.inputTokens += response.usage.inputTokens;
			usage.outputTokens += response.usage.outputTokens;
			this.onEvent?.({
				type: "usage",
				inputTokens: response.usage.inputTokens,
				outputTokens: response.usage.outputTokens,
			});

			const assistantBlocks = response.content;
			this.context.add({ role: "assistant", content: assistantBlocks });

			const text = textOf(assistantBlocks);
			if (text) {
				finalText = text;
				if (!this.stream) this.onText?.(text);
				this.onEvent?.({ type: "assistant_text", text });
			}

			const toolUses = assistantBlocks.filter((b): b is ToolUseBlock => b.type === "tool_use");
			if (toolUses.length === 0) break; // fine turno: nessuna azione richiesta

			const results: UserBlock[] = [];
			for (const toolUse of toolUses) {
				results.push(await this.runTool(toolUse, signal));
			}
			this.context.add({ role: "user", content: results });
		}

		return { text: finalText, iterations, usage, stoppedOnLimit };
	}

	/** Esegue una singola tool call attraverso il gate di enforcement. */
	private async runTool(toolUse: ToolUseBlock, signal?: AbortSignal): Promise<ToolResultBlock> {
		this.onEvent?.({ type: "tool_use", id: toolUse.id, name: toolUse.name, input: toolUse.input });

		// 1) Gate di enforcement: policy firmata, sandbox, kill switch, path.
		const gate = await this.adapter.gateToolCall(
			{ toolName: toolUse.name, callId: toolUse.id, input: toolUse.input },
			this.session,
		);
		if (!gate.allow) {
			this.onEvent?.({ type: "tool_denied", id: toolUse.id, name: toolUse.name, reason: gate.reason });
			return errorResult(toolUse.id, gate.reason);
		}

		// 2) Esecuzione del tool nativo.
		const tool = this.tools.get(toolUse.name);
		const ctx: ToolContext = signal ? { cwd: this.cwd, signal } : { cwd: this.cwd };
		let content: string;
		let isError: boolean;
		if (!tool) {
			content = `tool sconosciuto: ${toolUse.name}`;
			isError = true;
		} else {
			try {
				const result = await tool.execute(toolUse.input, ctx);
				content = result.content;
				isError = result.isError;
			} catch (error) {
				content =
					error instanceof ToolInputError
						? `input non valido: ${error.message}`
						: `errore interno del tool: ${error instanceof Error ? error.message : String(error)}`;
				isError = true;
			}
		}

		// 3) Redaction/riscrittura del risultato via enforcement.
		const rewrite = await this.adapter.rewriteResult(
			{
				toolName: toolUse.name,
				callId: toolUse.id,
				input: toolUse.input,
				content: [{ type: "text", text: content }],
				isError,
			},
			this.session,
		);
		if (rewrite) content = textFromBlocks(rewrite.content);

		this.onEvent?.({ type: "tool_result", id: toolUse.id, name: toolUse.name, isError, content });
		return { type: "tool_result", tool_use_id: toolUse.id, content, is_error: isError };
	}
}

function errorResult(toolUseId: string, message: string): ToolResultBlock {
	return { type: "tool_result", tool_use_id: toolUseId, content: message, is_error: true };
}

function textOf(blocks: AssistantBlock[]): string {
	return blocks
		.filter((b): b is { type: "text"; text: string } => b.type === "text")
		.map((b) => b.text)
		.join("")
		.trim();
}

function textFromBlocks(blocks: Array<{ type: string; text?: string }>): string {
	return blocks
		.filter((b) => b.type === "text" && typeof b.text === "string")
		.map((b) => b.text ?? "")
		.join("");
}

/** Riesporta per comodità dei consumatori del package. */
export type { Message };
