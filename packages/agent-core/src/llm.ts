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
	/**
	 * Attiva il prompt caching (Anthropic): marca il prefisso stabile della
	 * richiesta (system + tool) con `cache_control` e invia l'header beta, così i
	 * token del prefisso vengono riusati tra i turni del loop (che condividono lo
	 * stesso system e gli stessi tool). Trasparente per i provider che non lo
	 * supportano.
	 */
	promptCache?: boolean;
	/** `fetch` iniettabile (per i test). */
	fetchImpl?: typeof fetch;
	/** Timeout della singola chiamata (per tentativo) in ms (default 300s). */
	timeoutMs?: number;
	/**
	 * Numero massimo di RITENTATIVI (oltre al primo tentativo) su errori
	 * transitori del gateway/provider — 429, 5xx, `overloaded`, timeout, errori di
	 * rete (default 2). I 4xx non ritentabili (400/401/403/404) falliscono subito.
	 */
	maxRetries?: number;
	/** Base del backoff esponenziale con jitter, in ms (default 500). */
	retryBaseMs?: number;
}

/** Valore dell'header beta che abilita il prompt caching della Messages API. */
const PROMPT_CACHING_BETA = "prompt-caching-2024-07-31";

/** Status HTTP considerati transitori e quindi ritentabili. */
const RETRYABLE_STATUS = new Set([408, 425, 429, 500, 502, 503, 504, 529]);
/** Tetto del backoff per singola attesa. */
const MAX_BACKOFF_MS = 20_000;

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
	private readonly promptCache: boolean;
	private readonly fetchImpl: typeof fetch;
	private readonly timeoutMs: number;
	private readonly maxRetries: number;
	private readonly retryBaseMs: number;

	constructor(options: LlmClientOptions) {
		this.provider = PROVIDERS[options.provider ?? "anthropic"];
		this.gatewayUrl = options.gatewayUrl;
		this.deviceToken = options.deviceToken;
		this.anthropicVersion = options.anthropicVersion ?? "2023-06-01";
		this.anthropicBeta = options.anthropicBeta;
		this.promptCache = options.promptCache ?? false;
		this.fetchImpl = options.fetchImpl ?? fetch;
		this.timeoutMs = options.timeoutMs ?? 300_000;
		this.maxRetries = Math.max(0, options.maxRetries ?? 2);
		this.retryBaseMs = Math.max(1, options.retryBaseMs ?? 500);
	}

	/**
	 * Esegue la richiesta con retry su errori transitori (429/5xx/`overloaded`,
	 * timeout, errori di rete) e backoff esponenziale con jitter, rispettando
	 * `Retry-After` se presente. Ogni tentativo ha il proprio timeout. Solo la
	 * fase iniziale (fino agli header) è ritentata: una volta che lo stream del
	 * corpo è partito non si ritenta (non sarebbe idempotente rispetto al testo
	 * già consegnato).
	 */
	private async fetchWithRetry(url: string, init: RequestInit): Promise<Response> {
		let attempt = 0;
		for (;;) {
			try {
				const response = await this.fetchImpl(url, { ...init, signal: AbortSignal.timeout(this.timeoutMs) });
				if (RETRYABLE_STATUS.has(response.status) && attempt < this.maxRetries) {
					const retryAfter = response.headers.get("retry-after");
					await response.body?.cancel().catch(() => {});
					await sleep(this.backoffMs(attempt, retryAfter));
					attempt++;
					continue;
				}
				return response;
			} catch (error) {
				if (attempt < this.maxRetries && isRetryableError(error)) {
					await sleep(this.backoffMs(attempt, null));
					attempt++;
					continue;
				}
				throw error;
			}
		}
	}

	/** Attesa di backoff: `Retry-After` (secondi) se presente, altrimenti esponenziale + jitter. */
	private backoffMs(attempt: number, retryAfter: string | null): number {
		if (retryAfter) {
			const seconds = Number(retryAfter);
			if (Number.isFinite(seconds) && seconds >= 0) return Math.min(seconds * 1000, MAX_BACKOFF_MS);
		}
		const base = this.retryBaseMs * 2 ** attempt;
		const jitter = Math.random() * this.retryBaseMs;
		return Math.min(base + jitter, MAX_BACKOFF_MS);
	}

	/** Header beta effettivo: unisce quello dell'utente con quello del caching, se attivo. */
	private effectiveBeta(): string | undefined {
		const parts = new Set<string>();
		if (this.anthropicBeta) for (const p of this.anthropicBeta.split(",")) parts.add(p.trim());
		if (this.promptCache) parts.add(PROMPT_CACHING_BETA);
		return parts.size > 0 ? [...parts].join(",") : undefined;
	}

	private headers(): Record<string, string> {
		const beta = this.effectiveBeta();
		return this.provider.headers({
			deviceToken: this.deviceToken,
			anthropicVersion: this.anthropicVersion,
			...(beta !== undefined ? { anthropicBeta: beta } : {}),
		});
	}

	/** Applica l'hint di caching alla richiesta prima di passarla al provider. */
	private withCacheHint(request: LlmRequest): LlmRequest {
		return this.promptCache ? { ...request, cacheHint: true } : request;
	}

	/** Completamento non-streaming: attende l'intera risposta e la normalizza. */
	async complete(request: LlmRequest): Promise<LlmResponse> {
		const response = await this.fetchWithRetry(this.provider.endpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.body(this.withCacheHint(request), false)),
		});
		if (!response.ok) throw new LlmError(await errorText(response), response.status);
		return this.provider.parse(await response.json());
	}

	/**
	 * Completamento in streaming: invoca `onTextDelta` per ogni frammento di
	 * testo man mano che arriva, e restituisce la risposta completa alla fine.
	 */
	async stream(request: LlmRequest, onTextDelta?: (delta: string) => void): Promise<LlmResponse> {
		const response = await this.fetchWithRetry(this.provider.endpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.body(this.withCacheHint(request), true)),
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
		const response = await this.fetchWithRetry(this.provider.countTokensEndpoint(this.gatewayUrl), {
			method: "POST",
			headers: this.headers(),
			body: JSON.stringify(this.provider.countTokensBody(request)),
		});
		if (!response.ok) throw new LlmError(await errorText(response), response.status);
		return this.provider.parseCountTokens(await response.json());
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Un errore di `fetch` è ritentabile se è di rete (TypeError di undici) o un
 * timeout del tentativo (TimeoutError da AbortSignal.timeout). Un abort esplicito
 * di altro tipo non viene ritentato.
 */
function isRetryableError(error: unknown): boolean {
	if (!(error instanceof Error)) return false;
	if (error.name === "TimeoutError") return true;
	// undici lancia un TypeError ("fetch failed") sugli errori di connessione.
	return error.name === "TypeError";
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
