import type { AssistantBlock, LlmRequest, LlmResponse, Message, ToolDefinition } from "../types.js";
import { readSseEvents } from "./sse.js";
import type { ProviderHeaderOptions, WireProvider } from "./types.js";

/**
 * Provider OpenAI (Chat Completions), inoltrato dal gateway su
 * `/openai/v1/chat/completions`. La forma di wire differisce da Anthropic
 * (ruolo `tool`, `tool_calls` con `arguments` come stringa JSON): qui c'è la
 * traduzione da/verso i tipi neutri dell'agente. Il loop e i tool non cambiano.
 */
export const openaiProvider: WireProvider = {
	name: "openai",

	endpoint(gatewayBaseUrl) {
		return `${gatewayBaseUrl.replace(/\/+$/, "")}/openai/v1/chat/completions`;
	},

	headers(options: ProviderHeaderOptions) {
		// Il gateway accetta il device token come Bearer o x-api-key.
		return { "content-type": "application/json", authorization: `Bearer ${options.deviceToken}` };
	},

	body(request: LlmRequest, stream: boolean) {
		const body: Record<string, unknown> = {
			model: request.model,
			max_tokens: request.maxTokens,
			messages: toOpenAiMessages(request.system, request.messages),
			stream,
		};
		if (request.tools && request.tools.length > 0) body.tools = request.tools.map(toOpenAiTool);
		if (request.temperature !== undefined) body.temperature = request.temperature;
		// Con include_usage l'ultimo chunk di streaming riporta il consumo di token.
		if (stream) body.stream_options = { include_usage: true };
		return body;
	},

	parse(json: unknown): LlmResponse {
		return normalizeCompletion(json as WireCompletion);
	},

	assembleStream(stream, onTextDelta) {
		return assembleFromOpenAiSse(stream, onTextDelta);
	},
};

// ---- Traduzione neutro → OpenAI ---------------------------------------------

interface OpenAiToolCall {
	id: string;
	type: "function";
	function: { name: string; arguments: string };
}
interface OpenAiMessage {
	role: "system" | "user" | "assistant" | "tool";
	content: string | null;
	tool_calls?: OpenAiToolCall[];
	tool_call_id?: string;
}

function toOpenAiTool(tool: ToolDefinition): unknown {
	return {
		type: "function",
		function: { name: tool.name, description: tool.description, parameters: tool.input_schema },
	};
}

/**
 * Traduce la cronologia neutra in messaggi OpenAI. I risultati dei tool
 * (blocchi `tool_result` in un turno utente) diventano messaggi separati con
 * ruolo `tool`, che devono seguire il messaggio assistant con i `tool_calls`
 * corrispondenti — l'ordine della cronologia neutra lo garantisce già.
 */
export function toOpenAiMessages(system: string | undefined, messages: Message[]): OpenAiMessage[] {
	const out: OpenAiMessage[] = [];
	if (system !== undefined && system !== "") out.push({ role: "system", content: system });

	for (const message of messages) {
		if (message.role === "user") {
			if (typeof message.content === "string") {
				out.push({ role: "user", content: message.content });
				continue;
			}
			const texts: string[] = [];
			for (const block of message.content) {
				if (block.type === "tool_result") {
					out.push({ role: "tool", tool_call_id: block.tool_use_id, content: block.content });
				} else if (block.type === "text") {
					texts.push(block.text);
				}
			}
			if (texts.length > 0) out.push({ role: "user", content: texts.join("\n") });
		} else {
			// assistant
			if (typeof message.content === "string") {
				out.push({ role: "assistant", content: message.content });
				continue;
			}
			const texts: string[] = [];
			const toolCalls: OpenAiToolCall[] = [];
			for (const block of message.content) {
				if (block.type === "text") {
					texts.push(block.text);
				} else if (block.type === "tool_use") {
					toolCalls.push({
						id: block.id,
						type: "function",
						function: { name: block.name, arguments: JSON.stringify(block.input ?? {}) },
					});
				}
			}
			const msg: OpenAiMessage = { role: "assistant", content: texts.join("") || null };
			if (toolCalls.length > 0) msg.tool_calls = toolCalls;
			out.push(msg);
		}
	}
	return out;
}

// ---- Normalizzazione OpenAI → neutro ----------------------------------------

interface WireCompletion {
	model?: string;
	choices?: Array<{
		message?: { content?: string | null; tool_calls?: OpenAiToolCall[] };
		finish_reason?: string | null;
	}>;
	usage?: { prompt_tokens?: number; completion_tokens?: number };
}

function normalizeCompletion(data: WireCompletion): LlmResponse {
	const choice = data.choices?.[0];
	const content: AssistantBlock[] = [];
	const text = choice?.message?.content;
	if (typeof text === "string" && text !== "") content.push({ type: "text", text });
	for (const call of choice?.message?.tool_calls ?? []) {
		content.push({
			type: "tool_use",
			id: call.id,
			name: call.function.name,
			input: parseArgs(call.function.arguments),
		});
	}
	return {
		content,
		stopReason: mapFinishReason(choice?.finish_reason ?? null),
		usage: {
			inputTokens: data.usage?.prompt_tokens ?? 0,
			outputTokens: data.usage?.completion_tokens ?? 0,
		},
		model: data.model ?? "",
	};
}

/** Mappa i finish_reason di OpenAI sui nomi Anthropic (cosmetico: il loop guarda i tool). */
function mapFinishReason(reason: string | null): string | null {
	switch (reason) {
		case "tool_calls":
			return "tool_use";
		case "stop":
			return "end_turn";
		case "length":
			return "max_tokens";
		default:
			return reason;
	}
}

function parseArgs(raw: string): Record<string, unknown> {
	if (!raw || raw.trim() === "") return {};
	try {
		const parsed = JSON.parse(raw);
		return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
	} catch {
		return {};
	}
}

// ---- Streaming SSE (Chat Completions) ---------------------------------------

interface OpenAiStreamChunk {
	choices?: Array<{
		delta?: {
			content?: string | null;
			tool_calls?: Array<{ index: number; id?: string; function?: { name?: string; arguments?: string } }>;
		};
		finish_reason?: string | null;
	}>;
	usage?: { prompt_tokens?: number; completion_tokens?: number };
}

export async function assembleFromOpenAiSse(
	stream: ReadableStream<Uint8Array>,
	onTextDelta?: (delta: string) => void,
): Promise<LlmResponse> {
	let text = "";
	const toolCalls = new Map<number, { id: string; name: string; args: string }>();
	let finishReason: string | null = null;
	let usage = { inputTokens: 0, outputTokens: 0 };

	await readSseEvents(stream, (raw) => {
		const chunk = raw as OpenAiStreamChunk;
		if (chunk.usage) {
			usage = { inputTokens: chunk.usage.prompt_tokens ?? 0, outputTokens: chunk.usage.completion_tokens ?? 0 };
		}
		const choice = chunk.choices?.[0];
		if (!choice) return;
		if (choice.finish_reason) finishReason = choice.finish_reason;
		const delta = choice.delta;
		if (typeof delta?.content === "string" && delta.content !== "") {
			text += delta.content;
			onTextDelta?.(delta.content);
		}
		for (const tc of delta?.tool_calls ?? []) {
			const existing = toolCalls.get(tc.index) ?? { id: "", name: "", args: "" };
			if (tc.id) existing.id = tc.id;
			if (tc.function?.name) existing.name = tc.function.name;
			if (tc.function?.arguments) existing.args += tc.function.arguments;
			toolCalls.set(tc.index, existing);
		}
	});

	const content: AssistantBlock[] = [];
	if (text !== "") content.push({ type: "text", text });
	for (const index of [...toolCalls.keys()].sort((a, b) => a - b)) {
		const call = toolCalls.get(index) as { id: string; name: string; args: string };
		content.push({ type: "tool_use", id: call.id, name: call.name, input: parseArgs(call.args) });
	}
	return { content, stopReason: mapFinishReason(finishReason), usage, model: "" };
}
