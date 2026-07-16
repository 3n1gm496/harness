import type { LlmClient } from "./llm.js";
import type { Message, ToolDefinition, UserBlock } from "./types.js";

/**
 * Gestione della finestra di contesto. Un agente reale accumula una
 * conversazione che cresce a ogni tool call; senza gestione, prima o poi supera
 * la finestra del modello. Qui teniamo la conversazione e, quando la stima dei
 * token supera un budget, comprimiamo il prefisso più vecchio in una sintesi
 * generata dal modello stesso — preservando l'integrità dell'accoppiamento
 * tool_use/tool_result (si taglia solo all'inizio di un turno utente "pulito").
 */

export interface ContextOptions {
	/** Soglia di token stimati oltre la quale scatta la compaction (default 150k). */
	budgetTokens: number;
	/** Numero minimo di messaggi recenti mai compattati (default 8). */
	keepRecentMessages: number;
}

export const DEFAULT_CONTEXT_OPTIONS: ContextOptions = {
	budgetTokens: 150_000,
	keepRecentMessages: 8,
};

export class ContextManager {
	readonly messages: Message[] = [];

	constructor(
		private readonly options: ContextOptions = DEFAULT_CONTEXT_OPTIONS,
		private readonly system?: string,
	) {}

	add(message: Message): void {
		this.messages.push(message);
	}

	/** Stima grossolana dei token (≈4 caratteri per token) su system + messaggi. */
	estimateTokens(): number {
		let chars = this.system?.length ?? 0;
		for (const message of this.messages) chars += messageChars(message);
		return Math.ceil(chars / 4);
	}

	/**
	 * Numero di token di input della conversazione corrente. Usa il conteggio
	 * ESATTO del provider (`count_tokens`) quando disponibile, altrimenti la
	 * stima euristica. La chiamata esatta si fa solo quando la stima si avvicina
	 * al budget (soglia 80%), per non aggiungere un round-trip di rete a ogni
	 * turno. Un conteggio esatto implausibile (0 su contesto non vuoto, es. un
	 * provider che non lo espone) ricade sulla stima.
	 */
	async tokenCount(llm: LlmClient, model: string, tools?: ToolDefinition[]): Promise<number> {
		const estimate = this.estimateTokens();
		if (estimate < this.options.budgetTokens * 0.8) return estimate;
		try {
			const exact = await llm.countTokens({
				model,
				maxTokens: 1,
				messages: this.messages,
				...(this.system !== undefined ? { system: this.system } : {}),
				...(tools && tools.length > 0 ? { tools } : {}),
			});
			if (typeof exact === "number" && exact > 0) return exact;
		} catch {
			// count_tokens non disponibile/errore: si ricade sulla stima.
		}
		return estimate;
	}

	/**
	 * Se sopra budget, comprime il prefisso più vecchio in una sintesi.
	 * Restituisce il numero netto di messaggi rimossi (0 se non ha compattato).
	 * Un fallimento della sintesi NON perde contesto: si salta la compaction e
	 * si lascia che l'eventuale limite del provider emerga come errore esplicito.
	 */
	async maybeCompact(llm: LlmClient, model: string, tools?: ToolDefinition[]): Promise<number> {
		if ((await this.tokenCount(llm, model, tools)) < this.options.budgetTokens) return 0;
		const cut = this.findCleanCut();
		if (cut <= 0) return 0;
		const prefix = this.messages.slice(0, cut);
		let summary: string;
		try {
			summary = await summarize(llm, model, prefix);
		} catch {
			return 0;
		}
		this.messages.splice(0, cut, {
			role: "user",
			content: `[Sintesi automatica del contesto precedente, generata per restare nella finestra del modello]\n\n${summary}`,
		});
		return cut - 1;
	}

	/**
	 * Trova il punto di taglio: il più recente inizio di turno utente "pulito"
	 * (un messaggio user senza blocchi tool_result) non oltre la soglia dei
	 * messaggi recenti da preservare. Tagliare qui non spezza mai una coppia
	 * tool_use → tool_result.
	 */
	private findCleanCut(): number {
		const target = this.messages.length - this.options.keepRecentMessages;
		const upper = Math.min(target, this.messages.length - 1);
		for (let i = upper; i > 0; i--) {
			if (isFreshUserTurn(this.messages[i] as Message)) return i;
		}
		return 0;
	}
}

/** Un turno utente "pulito": role user e nessun blocco tool_result. */
function isFreshUserTurn(message: Message): boolean {
	if (message.role !== "user") return false;
	if (typeof message.content === "string") return true;
	return !message.content.some((block) => (block as UserBlock).type === "tool_result");
}

function messageChars(message: Message): number {
	if (typeof message.content === "string") return message.content.length;
	let chars = 0;
	for (const block of message.content) {
		if (block.type === "text") chars += block.text.length;
		else if (block.type === "tool_use") chars += JSON.stringify(block.input).length + block.name.length;
		else if (block.type === "tool_result") chars += block.content.length;
	}
	return chars;
}

const SUMMARY_SYSTEM =
	"Sei un compressore di contesto per un agente di coding. Riassumi la conversazione preservando: " +
	"obiettivo dell'utente, decisioni prese, file letti/modificati con i percorsi, risultati importanti dei comandi, " +
	"e ciò che resta da fare. Sii conciso ma non perdere fatti operativi. Rispondi solo con la sintesi.";

async function summarize(llm: LlmClient, model: string, messages: Message[]): Promise<string> {
	const transcript = messages.map(renderMessage).join("\n\n");
	const response = await llm.complete({
		model,
		maxTokens: 1024,
		system: SUMMARY_SYSTEM,
		messages: [{ role: "user", content: `Conversazione da riassumere:\n\n${transcript}` }],
	});
	const text = response.content
		.filter((b): b is { type: "text"; text: string } => b.type === "text")
		.map((b) => b.text)
		.join("");
	return text.trim() === "" ? "(nessuna sintesi disponibile)" : text.trim();
}

/** Rende un messaggio in testo leggibile per il prompt di sintesi. */
function renderMessage(message: Message): string {
	const role = message.role === "user" ? "UTENTE" : "ASSISTENTE";
	if (typeof message.content === "string") return `${role}: ${message.content}`;
	const parts: string[] = [];
	for (const block of message.content) {
		if (block.type === "text") parts.push(block.text);
		else if (block.type === "tool_use") parts.push(`[tool ${block.name}(${JSON.stringify(block.input)})]`);
		else if (block.type === "tool_result")
			parts.push(`[risultato tool${block.is_error ? " ERRORE" : ""}: ${truncate(block.content, 500)}]`);
	}
	return `${role}: ${parts.join("\n")}`;
}

function truncate(value: string, max: number): string {
	return value.length <= max ? value : `${value.slice(0, max)}…`;
}
