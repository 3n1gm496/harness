import type { HostSession } from "@harness/enforcement-core";
import type { HarnessAgentAdapter } from "./adapter.js";
import { ContextManager, type ContextOptions, DEFAULT_CONTEXT_OPTIONS } from "./context.js";
import type { LlmClient } from "./llm.js";
import { DEFAULT_SYSTEM_PROMPT } from "./system-prompt.js";
import { ToolRegistry } from "./tools/registry.js";
import { createTaskTool } from "./tools/task-tool.js";
import type { NativeTool, ToolContext } from "./tools/types.js";
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

/**
 * Eventi strutturati emessi durante un run, per osservabilità/UI. `depth` è la
 * profondità dell'agente che ha emesso l'evento: 0 (o assente) per l'agente
 * principale, >0 per i sotto-agenti, così una UI può indentare l'attività
 * annidata. Gli eventi dei figli sono inoltrati al callback del padre.
 */
export type AgentEvent =
	| { type: "assistant_text"; text: string; depth?: number }
	| { type: "tool_use"; id: string; name: string; input: Record<string, unknown>; depth?: number }
	| { type: "tool_denied"; id: string; name: string; reason: string; depth?: number }
	| { type: "tool_result"; id: string; name: string; isError: boolean; content: string; depth?: number }
	| { type: "usage"; inputTokens: number; outputTokens: number; depth?: number }
	| { type: "compaction"; removedMessages: number; depth?: number };

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
	/** Abilita il tool `task` per delegare sotto-compiti ad agenti figli (default false). */
	subAgents?: boolean;
	/** Profondità massima di annidamento dei sotto-agenti (default 2). */
	maxDepth?: number;
	/** Profondità corrente (uso interno: i figli la incrementano). */
	depth?: number;
	/**
	 * Se emettere gli eventi di ciclo-vita della sessione al motore (default
	 * true). I sotto-agenti la impostano a false: condividono l'adapter col
	 * padre e non devono ri-aprire né chiudere la sessione condivisa (chiuderla
	 * farebbe il flush/shutdown del FleetState mentre il padre lavora ancora).
	 */
	emitLifecycle?: boolean;
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
	private readonly baseTools: NativeTool[];
	private readonly depth: number;
	private readonly maxDepth: number;
	private readonly subAgents: boolean;
	private readonly contextOptions: ContextOptions;
	private readonly emitLifecycle: boolean;
	private readonly hasUI: boolean;
	private started = false;

	constructor(options: AgentOptions) {
		this.llm = options.llm;
		this.model = options.model;
		this.adapter = options.adapter;
		this.cwd = options.cwd ?? process.cwd();
		this.maxTokens = options.maxTokens ?? 4096;
		this.maxIterations = options.maxIterations ?? 50;
		this.stream = options.stream ?? false;
		this.onText = options.onText;
		this.onEvent = options.onEvent;
		this.contextOptions = options.context ?? DEFAULT_CONTEXT_OPTIONS;
		this.context = new ContextManager(this.contextOptions, options.systemPrompt ?? DEFAULT_SYSTEM_PROMPT);
		this.systemPrompt = options.systemPrompt ?? DEFAULT_SYSTEM_PROMPT;
		this.hasUI = options.hasUI ?? false;
		this.session = { cwd: this.cwd, hasUI: this.hasUI };
		this.depth = options.depth ?? 0;
		this.maxDepth = options.maxDepth ?? 2;
		this.subAgents = options.subAgents ?? false;
		this.emitLifecycle = options.emitLifecycle ?? true;

		// Registro dei tool: base + (se abilitato e non oltre la profondità) il
		// tool `task` per delegare a un agente figlio. La lista base è conservata
		// per costruire i figli senza propagare `task` in modo incontrollato.
		this.baseTools = (options.tools ?? new ToolRegistry()).list();
		if (this.subAgents && this.depth < this.maxDepth) {
			const taskTool = createTaskTool((_description, prompt) => this.spawnSubAgent(prompt));
			this.tools = new ToolRegistry([...this.baseTools, taskTool]);
		} else {
			this.tools = new ToolRegistry(this.baseTools);
		}
	}

	/** Notifica il motore dell'inizio sessione (una volta sola; saltato dai figli). */
	async start(): Promise<void> {
		if (this.started || !this.emitLifecycle) return;
		this.started = true;
		await this.adapter.emitSessionStart(this.session);
	}

	/** Chiude la sessione: il motore fa flush dell'audit e ferma i loop (saltato dai figli). */
	async stop(): Promise<void> {
		if (!this.emitLifecycle) return;
		await this.adapter.emitSessionEnd();
	}

	/**
	 * Costruisce ed esegue un agente figlio a profondità+1, condividendo motore
	 * di enforcement, LLM, tool e cwd. Il figlio non emette il ciclo-vita della
	 * sessione (adapter condiviso) e non fa streaming del proprio testo — il
	 * padre ne riceve solo il risultato finale. Gli eventi strutturati vengono
	 * inoltrati per l'osservabilità.
	 */
	private async spawnSubAgent(prompt: string): Promise<string> {
		const childDepth = this.depth + 1;
		const parentOnEvent = this.onEvent;
		// Gli eventi del figlio (e dei suoi discendenti) sono inoltrati al padre,
		// marcati con la profondità di chi li ha emessi: un evento già marcato da
		// un livello più profondo conserva il suo `depth`; uno non marcato prende
		// quello di questo figlio.
		const forwardEvent = parentOnEvent
			? (event: AgentEvent): void => parentOnEvent(event.depth === undefined ? { ...event, depth: childDepth } : event)
			: undefined;
		const child = new Agent({
			llm: this.llm,
			model: this.model,
			adapter: this.adapter,
			tools: new ToolRegistry(this.baseTools),
			systemPrompt: this.systemPrompt,
			cwd: this.cwd,
			maxTokens: this.maxTokens,
			maxIterations: this.maxIterations,
			context: this.contextOptions,
			hasUI: this.hasUI,
			subAgents: this.subAgents,
			maxDepth: this.maxDepth,
			depth: childDepth,
			emitLifecycle: false,
			...(forwardEvent ? { onEvent: forwardEvent } : {}),
			// Il testo del figlio viene mostrato (indentato) via evento, non
			// mandato allo stdout principale: al padre torna comunque solo il
			// risultato finale come tool_result.
			...(forwardEvent
				? { onText: (text: string) => forwardEvent({ type: "assistant_text", text, depth: childDepth }) }
				: {}),
		});
		const result = await child.run(prompt);
		return result.text;
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

			const removed = await this.context.maybeCompact(this.llm, this.model, this.tools.definitions());
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
