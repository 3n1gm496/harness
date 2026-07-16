import { anthropicProvider } from "./providers/anthropic.js";
import { LlmError } from "./providers/errors.js";
import { openaiProvider } from "./providers/openai.js";
import type { ProviderName, WireProvider } from "./providers/types.js";
import type { LlmRequest, LlmResponse } from "./types.js";

/**
 * Client LLM dell'agente nativo. NON parla mai direttamente col provider: si
 * rivolge sempre al gateway (`@harness/llm-gateway`), che inietta le credenziali
 * del provider e non le espone mai al client. Il client presenta solo il proprio
 * device token; il gateway lo introspeziona sul control plane a ogni richiesta.
 *
 * Il formato di wire è mediato da un {@link WireProvider} (Anthropic o OpenAI):
 * l'agente lavora sempre sui tipi neutri, il provider traduce. Supporta
 * non-streaming (deterministico) e streaming SSE, più il conteggio esatto dei
 * token quando il provider lo espone.
 */

export interface LlmClientOptions {
	/** URL base del gateway, es. `http://localhost:8081` (senza suffisso di provider). */
	gatewayUrl: string;
	/** Device token del client gestito (auth verso il gateway). */
	deviceToken: string;
	/** Provider di wire (default `anthropic`). */
	provider?: ProviderName;
	/** Versione dell'API Anthropic (default `2023-06-01`). */
	anthropicVersion?: string;
	/** Header `anthropic-beta` opzionale (prompt caching, ecc.). */
	anthropicBeta?: string;
	/** `fetch` iniettabile (per i test). */
	fetchImpl?: typeof fetch;
	/** Timeout della singola chiamata in ms (default 300s). */
	timeoutMs?: number;
}

const PROVIDERS: Record<ProviderName, WireProvider> = {
	anthropic: anthropicProvider,
	openai: openaiProvider,
};

export class LlmClient {
	private readonly provider: WireProvider;
	private readonly gatewayUrl: string;
	private readonly deviceToken: string;
	private readonly anthropicVersion: string;
	private readonly anthropicBeta: string | undefined;
	private readonly fetchImpl: typeof fetch;
	private readonly timeoutMs: number;

	constructor(options: LlmClientOptions) {
		this.provider = PROVIDERS[options.provider ?? "anthropic"];
		this.gatewayUrl = options.gatewayUrl;
		this.deviceToken = options.deviceToken;
		this.anthropicVersion = options.anthropicVersion ?? "2023-06-01";
		this.anthropicBeta = options.anthropicBeta;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.timeoutMs = options.timeoutMs ?? 300_000;
	}

	private headers(): Record<string, string> {
		return this.provider.headers({
			deviceToken: this.deviceToken,
			anthropicVersion: this.anthropicVersion,
			...(this.anthropicBeta !== undefined ? { anthropicBeta: this.anthropicBeta } : {}),
		});
	}

	/** Completamento non-streaming: attende l'intera risposta e la normalizza. */
	async complete(request: LlmRequest): Promise<LlmResponse> {
		const response = await this.fetchImpl(this.provider.endpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.body(request, false)),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (!response.ok) throw new LlmError(await errorText(response), response.status);
		return this.provider.parse(await response.json());
	}

	/**
	 * Completamento in streaming: invoca `onTextDelta` per ogni frammento di
	 * testo man mano che arriva, e restituisce la risposta completa alla fine.
	 */
	async stream(request: LlmRequest, onTextDelta?: (delta: string) => void): Promise<LlmResponse> {
		const response = await this.fetchImpl(this.provider.endpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.body(request, true)),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (!response.ok) throw new LlmError(await errorText(response), response.status);
		if (!response.body) throw new LlmError("risposta in streaming senza body", response.status);
		return this.provider.assembleStream(response.body as ReadableStream<Uint8Array>, onTextDelta);
	}

	/**
	 * Conteggio esatto dei token di input, se il provider lo espone (Anthropic).
	 * Restituisce `undefined` se non supportato: il chiamante ricade sulla stima.
	 */
	async countTokens(request: LlmRequest): Promise<number | undefined> {
		if (!this.provider.countTokensEndpoint || !this.provider.countTokensBody || !this.provider.parseCountTokens) {
			return undefined;
		}
		const response = await this.fetchImpl(this.provider.countTokensEndpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.countTokensBody(request)),
			signal: AbortSignal.timeout(this.timeoutMs),
		});
		if (!response.ok) throw new LlmError(await errorText(response), response.status);
		return this.provider.parseCountTokens(await response.json());
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

export { assembleFromSse } from "./providers/anthropic.js";
// Riesportazioni per compatibilità con i consumatori esistenti.
export { LlmError } from "./providers/errors.js";
export type { ProviderName } from "./providers/types.js";
