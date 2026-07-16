import type { AssistantBlock, LlmRequest, LlmResponse } from "./types.js";

/**
 * Client LLM dell'agente nativo. NON parla mai direttamente col provider: si
 * rivolge sempre al gateway (`@harness/llm-gateway`), che inietta le credenziali
 * del provider e non le espone mai al client. Il client presenta solo il proprio
 * device token; il gateway lo introspeziona sul control plane a ogni richiesta.
 *
 * Formato di wire: Messages API di Anthropic (`/anthropic/v1/messages` sul
 * gateway). Supporta sia la modalità non-streaming (deterministica, usata dai
 * test e dai run non interattivi) sia lo streaming SSE (usato dalla CLI per
 * mostrare il testo mentre viene generato). Entrambe convergono sullo stesso
 * {@link LlmResponse}.
 */

export interface LlmClientOptions {
	/** URL base del gateway, es. `http://localhost:8081` (senza `/anthropic`). */
	gatewayUrl: string;
	/** Device token del client gestito (auth verso il gateway). */
	deviceToken: string;
	/** Versione dell'API Anthropic (default `2023-06-01`). */
	anthropicVersion?: string;
	/** Header `anthropic-beta` opzionale (prompt caching, ecc.). */
	anthropicBeta?: string;
	/** `fetch` iniettabile (per i test). */
	fetchImpl?: typeof fetch;
	/** Timeout della singola chiamata in ms (default 300s: le generazioni lunghe con tool-use possono durare). */
	timeoutMs?: number;
}

/** Errore di comunicazione col gateway/provider, con lo status HTTP se disponibile. */
export class LlmError extends Error {
	constructor(
		message: string,
		readonly status: number,
	) {
		super(message);
		this.name = "LlmError";
	}
}

export class LlmClient {
	private readonly endpoint: string;
	private readonly deviceToken: string;
	private readonly anthropicVersion: string;
	private readonly anthropicBeta: string | undefined;
	private readonly fetchImpl: typeof fetch;
	private readonly timeoutMs: number;

	constructor(options: LlmClientOptions) {
		this.endpoint = `${options.gatewayUrl.replace(/\/+$/, "")}/anthropic/v1/messages`;
		this.deviceToken = options.deviceToken;
		this.anthropicVersion = options.anthropicVersion ?? "2023-06-01";
		this.anthropicBeta = options.anthropicBeta;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.timeoutMs = options.timeoutMs ?? 300_000;
	}

	private headers(): Record<string, string> {
		const headers: Record<string, string> = {
			"content-type": "application/json",
			// Il gateway accetta il device token come x-api-key o Bearer; usiamo
			// x-api-key per coerenza con il formato Anthropic che gli SDK adottano.
			"x-api-key": this.deviceToken,
			"anthropic-version": this.anthropicVersion,
		};
		if (this.anthropicBeta) headers["anthropic-beta"] = this.anthropicBeta;
		return headers;
	}

	private wireBody(request: LlmRequest, stream: boolean): string {
		const body: Record<string, unknown> = {
			model: request.model,
			max_tokens: request.maxTokens,
			messages: request.messages,
			stream,
		};
		if (request.system !== undefined) body.system = request.system;
		if (request.tools && request.tools.length > 0) body.tools = request.tools;
		if (request.temperature !== undefined) body.temperature = request.temperature;
		return JSON.stringify(body);
	}

	/** Completamento non-streaming: attende l'intera risposta e la normalizza. */
	async complete(request: LlmRequest): Promise<LlmResponse> {
		const response = await this.fetchImpl(this.endpoint, {
			method: "POST",
			headers: this.headers(),
			body: this.wireBody(request, false),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (!response.ok) {
			throw new LlmError(await errorText(response), response.status);
		}
		const data = (await response.json()) as WireMessage;
		return normalizeMessage(data);
	}

	/**
	 * Completamento in streaming: invoca `onTextDelta` per ogni frammento di
	 * testo man mano che arriva, e restituisce la risposta completa alla fine.
	 */
	async stream(request: LlmRequest, onTextDelta?: (delta: string) => void): Promise<LlmResponse> {
		const response = await this.fetchImpl(this.endpoint, {
			method: "POST",
			headers: this.headers(),
			body: this.wireBody(request, true),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (!response.ok) {
			throw new LlmError(await errorText(response), response.status);
		}
		if (!response.body) throw new LlmError("risposta in streaming senza body", response.status);
		return assembleFromSse(response.body as ReadableStream<Uint8Array>, onTextDelta);
	}
}

async function errorText(response: Response): Promise<string> {
	try {
		const data = (await response.json()) as { error?: { message?: string } | string };
		const message = typeof data.error === "string" ? data.error : data.error?.message;
		if (message) return `gateway/provider HTTP ${response.status}: ${message}`;
	} catch {
		// corpo non-JSON: si ricade sul messaggio generico
	}
	return `gateway/provider HTTP ${response.status}`;
}

// ---- Normalizzazione della risposta non-streaming ---------------------------

interface WireContentBlock {
	type: string;
	text?: string;
	id?: string;
	name?: string;
	input?: Record<string, unknown>;
}

interface WireMessage {
	content?: WireContentBlock[];
	stop_reason?: string | null;
	model?: string;
	usage?: { input_tokens?: number; output_tokens?: number };
}

function normalizeMessage(data: WireMessage): LlmResponse {
	const content: AssistantBlock[] = [];
	for (const block of data.content ?? []) {
		if (block.type === "text") {
			content.push({ type: "text", text: block.text ?? "" });
		} else if (block.type === "tool_use" && typeof block.id === "string" && typeof block.name === "string") {
			content.push({ type: "tool_use", id: block.id, name: block.name, input: block.input ?? {} });
		}
	}
	return {
		content,
		stopReason: data.stop_reason ?? null,
		usage: {
			inputTokens: data.usage?.input_tokens ?? 0,
			outputTokens: data.usage?.output_tokens ?? 0,
		},
		model: data.model ?? "",
	};
}

// ---- Parsing dello stream SSE (Messages API streaming) ----------------------

interface SseEvent {
	type?: string;
	index?: number;
	message?: WireMessage;
	content_block?: WireContentBlock;
	delta?: { type?: string; text?: string; partial_json?: string; stop_reason?: string | null };
	usage?: { output_tokens?: number };
	error?: { message?: string; type?: string };
}

/**
 * Consuma uno stream SSE della Messages API e ricostruisce la risposta.
 * Esportata per test diretti del parser (indipendenti dalla rete).
 */
export async function assembleFromSse(
	stream: ReadableStream<Uint8Array>,
	onTextDelta?: (delta: string) => void,
): Promise<LlmResponse> {
	const blocks: (AssistantBlock | undefined)[] = [];
	const partialJson = new Map<number, string>();
	let stopReason: string | null = null;
	let usage = { inputTokens: 0, outputTokens: 0 };
	let model = "";

	await readSseEvents(stream, (event) => {
		switch (event.type) {
			case "message_start": {
				model = event.message?.model ?? "";
				usage = {
					inputTokens: event.message?.usage?.input_tokens ?? 0,
					outputTokens: event.message?.usage?.output_tokens ?? 0,
				};
				break;
			}
			case "content_block_start": {
				const index = event.index ?? 0;
				const cb = event.content_block;
				if (cb?.type === "text") {
					blocks[index] = { type: "text", text: cb.text ?? "" };
				} else if (cb?.type === "tool_use" && typeof cb.id === "string" && typeof cb.name === "string") {
					blocks[index] = { type: "tool_use", id: cb.id, name: cb.name, input: {} };
					partialJson.set(index, "");
				}
				break;
			}
			case "content_block_delta": {
				const index = event.index ?? 0;
				const block = blocks[index];
				if (event.delta?.type === "text_delta" && block?.type === "text") {
					const text = event.delta.text ?? "";
					block.text += text;
					if (text) onTextDelta?.(text);
				} else if (event.delta?.type === "input_json_delta") {
					partialJson.set(index, (partialJson.get(index) ?? "") + (event.delta.partial_json ?? ""));
				}
				break;
			}
			case "content_block_stop": {
				const index = event.index ?? 0;
				const block = blocks[index];
				if (block?.type === "tool_use") {
					const raw = partialJson.get(index) ?? "";
					block.input = parseToolInput(raw);
				}
				break;
			}
			case "message_delta": {
				if (event.delta?.stop_reason) stopReason = event.delta.stop_reason;
				if (event.usage?.output_tokens !== undefined) usage.outputTokens = event.usage.output_tokens;
				break;
			}
			case "error": {
				throw new LlmError(event.error?.message ?? "errore nello stream del provider", 0);
			}
		}
	});

	return {
		content: blocks.filter((b): b is AssistantBlock => b !== undefined),
		stopReason,
		usage,
		model,
	};
}

/** Gli input dei tool arrivano come JSON accumulato; vuoto significa oggetto vuoto. */
function parseToolInput(raw: string): Record<string, unknown> {
	if (raw.trim() === "") return {};
	try {
		const parsed = JSON.parse(raw);
		return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
	} catch {
		// Un input JSON malformato dal modello non deve crashare il loop: si passa
		// un oggetto vuoto e il tool riporterà l'errore di validazione dei campi.
		return {};
	}
}

/**
 * Legge uno stream SSE riga per riga e invoca `onEvent` per ogni evento
 * completo (separato da riga vuota). Robusto a chunk che spezzano un evento a
 * metà (accumula in un buffer fino al delimitatore `\n\n`).
 */
async function readSseEvents(stream: ReadableStream<Uint8Array>, onEvent: (event: SseEvent) => void): Promise<void> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			buffer += decoder.decode(value, { stream: true });
			buffer = drainEvents(buffer, onEvent);
		}
		buffer += decoder.decode();
		drainEvents(`${buffer}\n\n`, onEvent);
	} finally {
		reader.releaseLock();
	}
}

/** Estrae e consuma tutti gli eventi completi presenti nel buffer; ritorna il resto non consumato. */
function drainEvents(buffer: string, onEvent: (event: SseEvent) => void): string {
	let rest = buffer;
	for (;;) {
		const boundary = rest.indexOf("\n\n");
		if (boundary === -1) return rest;
		const rawEvent = rest.slice(0, boundary);
		rest = rest.slice(boundary + 2);
		const data = extractData(rawEvent);
		if (data === undefined || data === "[DONE]") continue;
		let parsed: SseEvent;
		try {
			parsed = JSON.parse(data) as SseEvent;
		} catch {
			// Evento non-JSON (commento SSE, ping senza data): ignorato.
			continue;
		}
		// L'errore di onEvent (es. un evento `error` del provider) DEVE propagare:
		// va tenuto fuori dal try/catch del parse, che altrimenti lo ingoierebbe.
		onEvent(parsed);
	}
}

/** Concatena i valori delle righe `data:` di un evento SSE. */
function extractData(rawEvent: string): string | undefined {
	let data = "";
	let seen = false;
	for (const line of rawEvent.split("\n")) {
		if (line.startsWith("data:")) {
			data += line.slice(5).replace(/^ /, "");
			seen = true;
		}
	}
	return seen ? data : undefined;
}
