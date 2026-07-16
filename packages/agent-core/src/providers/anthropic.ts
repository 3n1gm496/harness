import type { AssistantBlock, LlmRequest, LlmResponse } from "../types.js";
import { LlmError } from "./errors.js";
import { readSseEvents } from "./sse.js";
import type { ProviderHeaderOptions, WireProvider } from "./types.js";

/**
 * Provider Anthropic (Messages API), inoltrato dal gateway su
 * `/anthropic/v1/messages`. È il provider "nativo": i tipi neutri dell'agente
 * sono già modellati su questo formato, quindi la traduzione è quasi diretta.
 */
export const anthropicProvider: WireProvider = {
	name: "anthropic",

	endpoint(gatewayBaseUrl) {
		return `${trimSlash(gatewayBaseUrl)}/anthropic/v1/messages`;
	},

	countTokensEndpoint(gatewayBaseUrl) {
		return `${trimSlash(gatewayBaseUrl)}/anthropic/v1/messages/count_tokens`;
	},

	headers(options: ProviderHeaderOptions) {
		const headers: Record<string, string> = {
			"content-type": "application/json",
			// Il gateway accetta il device token come x-api-key o Bearer.
			"x-api-key": options.deviceToken,
			"anthropic-version": options.anthropicVersion,
		};
		if (options.anthropicBeta) headers["anthropic-beta"] = options.anthropicBeta;
		return headers;
	},

	body(request: LlmRequest, stream: boolean) {
		const body: Record<string, unknown> = {
			model: request.model,
			max_tokens: request.maxTokens,
			messages: request.messages,
			stream,
		};
		if (request.system !== undefined) body.system = request.system;
		if (request.tools && request.tools.length > 0) body.tools = request.tools;
		if (request.temperature !== undefined) body.temperature = request.temperature;
		return body;
	},

	countTokensBody(request: LlmRequest) {
		const body: Record<string, unknown> = { model: request.model, messages: request.messages };
		if (request.system !== undefined) body.system = request.system;
		if (request.tools && request.tools.length > 0) body.tools = request.tools;
		return body;
	},

	parseCountTokens(json: unknown): number {
		const data = json as { input_tokens?: number };
		return typeof data.input_tokens === "number" ? data.input_tokens : 0;
	},

	parse(json: unknown): LlmResponse {
		return normalizeMessage(json as WireMessage);
	},

	assembleStream(stream, onTextDelta) {
		return assembleFromSse(stream, onTextDelta);
	},
};

function trimSlash(url: string): string {
	return url.replace(/\/+$/, "");
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
		usage: { inputTokens: data.usage?.input_tokens ?? 0, outputTokens: data.usage?.output_tokens ?? 0 },
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

	await readSseEvents(stream, (raw) => {
		const event = raw as SseEvent;
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
				if (block?.type === "tool_use") block.input = parseToolInput(partialJson.get(index) ?? "");
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
		return {};
	}
}
