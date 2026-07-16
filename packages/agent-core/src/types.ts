/**
 * Tipi del protocollo dell'agente nativo. Sono modellati sulla Messages API di
 * Anthropic (l'unico provider con tool-use nativo che il gateway inoltra oggi),
 * ma restano interni: il resto del package non parla mai direttamente il formato
 * di wire, e un secondo provider (OpenAI) si aggiungerebbe con un traduttore in
 * `llm.ts`, non cambiando questi tipi.
 */

/** Blocco di testo prodotto dal modello o inviato dall'utente. */
export interface TextBlock {
	type: "text";
	text: string;
}

/** Richiesta di esecuzione di un tool emessa dal modello. */
export interface ToolUseBlock {
	type: "tool_use";
	id: string;
	name: string;
	input: Record<string, unknown>;
}

/** Blocchi che il modello può produrre in una risposta. */
export type AssistantBlock = TextBlock | ToolUseBlock;

/** Risultato di un tool restituito al modello nel turno utente successivo. */
export interface ToolResultBlock {
	type: "tool_result";
	tool_use_id: string;
	content: string;
	is_error?: boolean;
}

/** Blocchi che un turno "user" può contenere. */
export type UserBlock = TextBlock | ToolResultBlock;

/** Un messaggio nella conversazione. */
export interface Message {
	role: "user" | "assistant";
	content: string | AssistantBlock[] | UserBlock[];
}

/** Schema JSON di un tool esposto al modello (subset usato dai nostri tool). */
export interface ToolSchema {
	type: "object";
	properties: Record<string, unknown>;
	required?: string[];
	additionalProperties?: boolean;
}

/** Definizione di un tool nel formato che il modello si aspetta. */
export interface ToolDefinition {
	name: string;
	description: string;
	input_schema: ToolSchema;
}

/** Richiesta di completamento verso il modello. */
export interface LlmRequest {
	model: string;
	maxTokens: number;
	system?: string;
	messages: Message[];
	tools?: ToolDefinition[];
	temperature?: number;
	/**
	 * Uso interno (impostato dal client quando `promptCache` è attivo): suggerisce
	 * al provider di marcare il prefisso stabile (system + tool) per il prompt
	 * caching. Ignorato dai provider che non lo supportano.
	 */
	cacheHint?: boolean;
}

/** Consumo di token riportato dal provider. */
export interface LlmUsage {
	inputTokens: number;
	outputTokens: number;
}

/** Risposta normalizzata del modello. */
export interface LlmResponse {
	content: AssistantBlock[];
	/** `end_turn`, `tool_use`, `max_tokens`, `stop_sequence`, … o null se sconosciuto. */
	stopReason: string | null;
	usage: LlmUsage;
	model: string;
}
