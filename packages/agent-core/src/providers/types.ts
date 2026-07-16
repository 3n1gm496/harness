import type { LlmRequest, LlmResponse } from "../types.js";

/** Nome del provider LLM raggiungibile attraverso il gateway. */
export type ProviderName = "anthropic" | "openai";

/** Opzioni per la costruzione degli header di richiesta. */
export interface ProviderHeaderOptions {
	deviceToken: string;
	anthropicVersion: string;
	anthropicBeta?: string;
}

/**
 * Contratto di un provider di wire. L'agente lavora sempre sui tipi neutri
 * ({@link LlmRequest}/{@link LlmResponse}, modellati su Anthropic); ogni provider
 * traduce da/verso il proprio formato. Aggiungere un provider = implementare
 * questa interfaccia, senza toccare il loop né i tipi interni.
 */
export interface WireProvider {
	readonly name: ProviderName;
	/** URL completo dell'endpoint di inferenza sul gateway. */
	endpoint(gatewayBaseUrl: string): string;
	/** Header della richiesta (auth col device token, versioni, ecc.). */
	headers(options: ProviderHeaderOptions): Record<string, string>;
	/** Corpo della richiesta nel formato di wire del provider. */
	body(request: LlmRequest, stream: boolean): unknown;
	/** Normalizza una risposta non-streaming. */
	parse(json: unknown): LlmResponse;
	/** Ricostruisce la risposta da uno stream SSE, con delta di testo opzionali. */
	assembleStream(stream: ReadableStream<Uint8Array>, onTextDelta?: (delta: string) => void): Promise<LlmResponse>;
	/** Endpoint per il conteggio esatto dei token, se il provider lo espone. */
	countTokensEndpoint?(gatewayBaseUrl: string): string;
	/** Corpo della richiesta di conteggio token. */
	countTokensBody?(request: LlmRequest): unknown;
	/** Estrae il numero di token di input dalla risposta di conteggio. */
	parseCountTokens?(json: unknown): number;
}
