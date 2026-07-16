import { readFileSync, statSync } from "node:fs";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";
import { type Logger, MetricsRegistry, peerCertFingerprint } from "@harness/shared";
import { type GatewayRateLimiter, InMemoryGatewayRateLimiter } from "./rate-limit.js";

/**
 * Gateway LLM: i client si autenticano con il token di device (verificato via
 * introspezione sul control plane) e il gateway inoltra le richieste al
 * provider iniettando le credenziali, che così non risiedono mai sui client.
 *
 * Route:
 *   /anthropic/*  →  ANTHROPIC_BASE_URL con header x-api-key
 *   /openai/*     →  OPENAI_BASE_URL con header Authorization: Bearer
 */
/**
 * Credenziale verso un provider upstream. Il gateway supporta due modalità,
 * così l'accesso NON è legato esclusivamente a una API key metered:
 *
 *  - `apiKey`  — chiave API classica (fatturata a token). Per Anthropic va
 *                nell'header `x-api-key`; per OpenAI come `Authorization: Bearer`.
 *  - `authToken` / `authTokenFile` — token di **account/sessione** (es. OAuth
 *                ottenuto dal login ufficiale del provider, tipicamente legato a
 *                un abbonamento e non al credito API): inviato come
 *                `Authorization: Bearer` e SENZA `x-api-key`. Con `authTokenFile`
 *                il token viene riletto dal file a ogni richiesta (cache per
 *                mtime), così un processo esterno può rinnovarlo senza riavviare
 *                il gateway. `betaHeader` aggiunge l'header `anthropic-beta`
 *                eventualmente richiesto dal flusso OAuth.
 *
 * Precedenza: `authTokenFile` > `authToken` > `apiKey`. Almeno una fonte deve
 * essere presente.
 */
export interface ProviderCredential {
	baseUrl: string;
	apiKey?: string;
	authToken?: string;
	authTokenFile?: string;
	betaHeader?: string;
}

export interface GatewayOptions {
	controlPlaneUrl: string;
	/** Token gateway emesso dal control plane per l'introspezione. */
	gatewayToken: string;
	providers: {
		anthropic?: ProviderCredential;
		openai?: ProviderCredential;
	};
	/** Richieste al minuto per device (default 60). */
	rateLimitPerMinute?: number;
	/** TTL della cache di introspezione in millisecondi (default 60s). */
	introspectionTtlMs?: number;
	/**
	 * Timeout della chiamata upstream in millisecondi (default 120s): senza,
	 * una connessione upstream appesa (provider irraggiungibile, rete che non
	 * chiude) resta appesa per sempre, tenendo occupata la richiesta client.
	 */
	upstreamTimeoutMs?: number;
	/**
	 * Limiter opzionale (iniettabile): se assente, il gateway ne crea uno
	 * in-memory (per-istanza). Il CLI passa un limiter Postgres condiviso quando
	 * è configurato `DATABASE_URL`, così N istanze del gateway condividono la
	 * soglia invece di applicarne una a testa (N×soglia effettiva).
	 */
	rateLimiter?: GatewayRateLimiter;
	log?: (entry: Record<string, unknown>) => void;
	/** Logger strutturato (in aggiunta o al posto di `log`). */
	logger?: Logger;
	/** Certificato e chiave PEM: se presenti il gateway parla HTTPS. */
	tls?: { cert: string; key: string };
}

interface IntrospectionEntry {
	active: boolean;
	deviceId?: string;
	expiresAt: number;
}

/**
 * Solo gli endpoint di inferenza sono inoltrabili: il device token non deve
 * diventare una chiave passe-partout verso l'intera API del provider
 * (billing, gestione file, admin, …).
 */
const ALLOWED_UPSTREAM_PATHS: Record<"anthropic" | "openai", RegExp[]> = {
	anthropic: [/^\/v1\/messages$/, /^\/v1\/messages\/count_tokens$/],
	openai: [/^\/v1\/chat\/completions$/, /^\/v1\/completions$/, /^\/v1\/embeddings$/, /^\/v1\/responses$/],
};

const MAX_BODY_BYTES = 32 * 1_048_576;
/** Tetto di byte accumulati (dal solo inizio del body) per il best-effort di estrazione del "model" nel log. */
const MODEL_PEEK_BYTES = 65_536;

export function createGatewayServer(options: GatewayOptions): Server | HttpsServer {
	const introspectionCache = new Map<string, IntrospectionEntry>();
	const rateLimiter = options.rateLimiter ?? new InMemoryGatewayRateLimiter();
	const rateLimit = options.rateLimitPerMinute ?? 60;
	const ttl = options.introspectionTtlMs ?? 60_000;
	const upstreamTimeoutMs = options.upstreamTimeoutMs ?? 120_000;
	const log =
		options.log ?? ((entry) => options.logger?.info("gateway_request", entry) ?? console.log(JSON.stringify(entry)));
	const metrics = new MetricsRegistry();
	metrics.counter("harness_gateway_requests_total", "Richieste al gateway per provider ed esito");
	metrics.histogram("harness_gateway_upstream_duration_seconds", "Durata delle chiamate upstream in secondi");
	metrics.gauge("harness_up", "1 se il processo è vivo");
	metrics.setGauge("harness_up", 1);

	async function introspect(deviceToken: string, presentedFingerprint?: string): Promise<IntrospectionEntry> {
		// La cache è per (token, fingerprint): lo stesso token con un cert diverso
		// non deve riusare un esito positivo precedente.
		const cacheKey = `${deviceToken}|${presentedFingerprint ?? ""}`;
		const cached = introspectionCache.get(cacheKey);
		if (cached && cached.expiresAt > Date.now()) {
			// LRU: rinfresca la posizione (riposiziona in coda).
			introspectionCache.delete(cacheKey);
			introspectionCache.set(cacheKey, cached);
			return cached;
		}
		// Cap difensivo con eviction LRU: token invalidi spammati non fanno
		// crescere la cache senza limite, ma un clear() totale azzererebbe anche
		// le voci dei device legittimi provocando un thundering herd di
		// re-introspezioni verso il control plane — si elimina solo la più vecchia.
		if (introspectionCache.size >= 5_000) {
			const oldest = introspectionCache.keys().next().value;
			if (oldest !== undefined) introspectionCache.delete(oldest);
		}
		const response = await fetch(`${options.controlPlaneUrl}/api/introspect`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${options.gatewayToken}`,
				"content-type": "application/json",
			},
			body: JSON.stringify({ deviceToken, presentedFingerprint }),
			signal: AbortSignal.timeout(10_000),
		});
		if (!response.ok) throw new Error(`introspezione fallita: HTTP ${response.status}`);
		const data = (await response.json()) as { active: boolean; deviceId?: string };
		const entry: IntrospectionEntry = {
			active: data.active,
			// I token rifiutati restano in cache per poco: una revoca deve
			// propagarsi in fretta, un token invalido non deve martellare il CP.
			expiresAt: Date.now() + (data.active ? ttl : Math.min(ttl, 10_000)),
		};
		if (data.deviceId !== undefined) entry.deviceId = data.deviceId;
		introspectionCache.set(cacheKey, entry);
		return entry;
	}

	const listener = (req: IncomingMessage, res: ServerResponse): void => {
		void handle(req, res).catch((error) => {
			log({ ts: new Date().toISOString(), level: "error", error: String(error) });
			sendJson(res, 502, { error: "errore del gateway" });
		});
	};
	if (options.tls) {
		// requestCert: i device legati a un certificato mTLS lo presentano; il
		// binding è verificato dal control plane via introspezione.
		return createHttpsServer({ ...options.tls, requestCert: true, rejectUnauthorized: false }, listener);
	}
	return createServer(listener);

	async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
		const url = new URL(req.url ?? "/", "http://localhost");
		if (req.method === "GET" && url.pathname === "/healthz") {
			sendJson(res, 200, { ok: true });
			return;
		}
		if (req.method === "GET" && url.pathname === "/metrics") {
			const body = metrics.render();
			res.writeHead(200, {
				"content-type": "text/plain; version=0.0.4; charset=utf-8",
				"content-length": Buffer.byteLength(body),
				"cache-control": "no-store",
			});
			res.end(body);
			return;
		}
		if (req.method === "GET" && url.pathname === "/readyz") {
			// Pronto se il control plane (da cui dipende l'introspezione) risponde.
			try {
				const probe = await fetch(`${options.controlPlaneUrl}/healthz`, { signal: AbortSignal.timeout(5_000) });
				sendJson(res, probe.ok ? 200 : 503, { ready: probe.ok, controlPlane: probe.status });
			} catch (error) {
				sendJson(res, 503, { ready: false, error: String(error) });
			}
			return;
		}

		const providerMatch = /^\/(anthropic|openai)(\/.*)$/.exec(url.pathname);
		if (!providerMatch) {
			sendJson(res, 404, { error: "route non trovata: usare /anthropic/* o /openai/*" });
			return;
		}
		const providerName = providerMatch[1] as "anthropic" | "openai";
		const upstreamPath = providerMatch[2] as string;
		const provider = options.providers[providerName];
		if (!provider) {
			sendJson(res, 503, { error: `provider ${providerName} non configurato sul gateway` });
			return;
		}
		if (!ALLOWED_UPSTREAM_PATHS[providerName].some((pattern) => pattern.test(upstreamPath))) {
			sendJson(res, 403, { error: `endpoint non consentito dal gateway: ${upstreamPath}` });
			return;
		}

		// Il device token può arrivare come Bearer o come x-api-key (per gli SDK
		// che usano il formato Anthropic).
		const deviceToken = bearerToken(req) ?? headerValue(req, "x-api-key");
		if (!deviceToken) {
			sendJson(res, 401, { error: "token device mancante" });
			return;
		}
		const introspection = await introspect(deviceToken, peerCertFingerprint(req));
		if (!introspection.active || !introspection.deviceId) {
			sendJson(res, 401, { error: "device non autorizzato (token non valido, revocato o sospeso)" });
			return;
		}
		if (!(await rateLimiter.check(introspection.deviceId, rateLimit))) {
			sendJson(res, 429, { error: "rate limit superato" });
			return;
		}

		const started = Date.now();
		let token: string;
		try {
			token = resolveProviderToken(provider);
		} catch (error) {
			log({ ts: new Date().toISOString(), level: "error", error: `credenziale provider non disponibile: ${error}` });
			sendJson(res, 503, { error: `credenziale del provider ${providerName} non disponibile` });
			return;
		}
		const useOAuth = Boolean(provider.authToken || provider.authTokenFile);
		const headers: Record<string, string> = {
			"content-type": headerValue(req, "content-type") ?? "application/json",
		};
		if (providerName === "anthropic") {
			// OAuth/sessione → Authorization: Bearer (SENZA x-api-key). API key → x-api-key.
			if (useOAuth) headers.authorization = `Bearer ${token}`;
			else headers["x-api-key"] = token;
			const version = headerValue(req, "anthropic-version");
			if (version) headers["anthropic-version"] = version;
			// Header beta: unione tra quello del client (prompt caching, ecc.) e
			// quello eventualmente richiesto dal flusso OAuth del provider.
			const beta = mergeCsv(headerValue(req, "anthropic-beta"), provider.betaHeader);
			if (beta) headers["anthropic-beta"] = beta;
		} else {
			// OpenAI usa Authorization: Bearer sia per la API key sia per il token OAuth.
			headers.authorization = `Bearer ${token}`;
		}

		// Il body viene inoltrato in streaming (mai bufferizzato per intero in
		// memoria): il cap di dimensione resta applicato via un contatore sullo
		// stream, e i primi byte vengono anche accumulati (fino a un tetto
		// ridotto) solo per estrarre il nome del modello nel log — un
		// best-effort che non richiede di attendere l'intero body.
		const peek: Buffer[] = [];
		let peekBytes = 0;
		let totalBytes = 0;
		async function* relayBody(): AsyncGenerator<Buffer> {
			for await (const chunk of req) {
				const buffer = chunk as Buffer;
				totalBytes += buffer.length;
				if (totalBytes > MAX_BODY_BYTES) throw new Error("body troppo grande");
				if (peekBytes < MODEL_PEEK_BYTES) {
					peek.push(buffer);
					peekBytes += buffer.length;
				}
				yield buffer;
			}
		}

		// Un solo AbortController combina il timeout upstream e la disconnessione
		// del client: se il client abbandona (a metà stream o prima), la fetch
		// upstream viene abortita subito invece di restare in corso (per un
		// provider LLM è anche un leak di costo — la generazione continuerebbe a
		// essere fatturata a token con nessuno in ascolto). Il segnale di
		// disconnessione è la chiusura di `res` PRIMA che la risposta sia
		// completata (`writableEnded`): la chiusura di `req` non va usata, perché
		// scatta già quando il body della richiesta è stato letto per intero (una
		// richiesta normale), abortendo erroneamente ogni upstream.
		const upstreamAbort = new AbortController();
		const timeout = setTimeout(
			() => upstreamAbort.abort(new DOMException("timeout", "TimeoutError")),
			upstreamTimeoutMs,
		);
		const onClientDisconnect = () => {
			if (!res.writableEnded) upstreamAbort.abort(new DOMException("client disconnesso", "AbortError"));
		};
		res.on("close", onClientDisconnect);
		const cleanup = () => {
			clearTimeout(timeout);
			res.off("close", onClientDisconnect);
		};

		let upstream: Response;
		try {
			upstream = await fetch(`${provider.baseUrl}${upstreamPath}${url.search}`, {
				method: req.method ?? "POST",
				headers,
				body: hasRequestBody(req) ? relayBody() : null,
				// Node (undici) richiede duplex:"half" quando il body è uno stream.
				duplex: "half",
				signal: upstreamAbort.signal,
			} as RequestInit & { duplex: "half" });
		} catch (error) {
			cleanup();
			if (upstreamAbort.signal.aborted && !res.headersSent) {
				const reason = upstreamAbort.signal.reason as Error | undefined;
				if (reason?.name === "TimeoutError") {
					metrics.incCounter("harness_gateway_requests_total", { provider: providerName, status: "504" });
					sendJson(res, 504, { error: `upstream non ha risposto entro ${upstreamTimeoutMs}ms` });
					return;
				}
				// Client disconnesso prima degli header: niente da rispondere.
				return;
			}
			if (error instanceof Error && error.name === "TimeoutError") {
				metrics.incCounter("harness_gateway_requests_total", { provider: providerName, status: "504" });
				sendJson(res, 504, { error: `upstream non ha risposto entro ${upstreamTimeoutMs}ms` });
				return;
			}
			throw error;
		}

		const durationMs = Date.now() - started;
		metrics.incCounter("harness_gateway_requests_total", { provider: providerName, status: String(upstream.status) });
		metrics.observe("harness_gateway_upstream_duration_seconds", durationMs / 1000, { provider: providerName });
		log({
			ts: new Date().toISOString(),
			deviceId: introspection.deviceId,
			provider: providerName,
			path: upstreamPath,
			model: extractModel(Buffer.concat(peek)),
			status: upstream.status,
			durationMs,
		});

		res.writeHead(upstream.status, {
			"content-type": upstream.headers.get("content-type") ?? "application/json",
			"cache-control": "no-store",
		});
		if (!upstream.body) {
			cleanup();
			res.end();
			return;
		}
		// Inoltro dello stream di risposta con gestione degli errori: una volta
		// scritti gli header, un errore sullo stream upstream (il timeout che
		// scatta a metà streaming, un reset del provider) NON deve propagarsi come
		// evento 'error' non gestito su un Readable — ucciderebbe l'intero
		// processo, buttando giù ogni altra richiesta in volo. `pipeline` cattura
		// l'errore in modo strutturato; noi chiudiamo la risposta troncata e
		// logghiamo, senza rilanciare (non c'è più modo di cambiare lo status).
		try {
			await pipeline(Readable.fromWeb(upstream.body as import("node:stream/web").ReadableStream), res);
		} catch (error) {
			log({
				ts: new Date().toISOString(),
				level: "error",
				deviceId: introspection.deviceId,
				provider: providerName,
				error: `stream upstream interrotto: ${String(error)}`,
			});
			if (!res.writableEnded) res.destroy();
		} finally {
			cleanup();
		}
	}
}

/**
 * Risolve il token da presentare all'upstream secondo la precedenza
 * authTokenFile > authToken > apiKey. Lancia se nessuna fonte è disponibile o
 * se il file è illeggibile/vuoto.
 */
function resolveProviderToken(provider: ProviderCredential): string {
	if (provider.authTokenFile) {
		const token = readTokenFile(provider.authTokenFile);
		if (token === "") throw new Error("file del token vuoto");
		return token;
	}
	if (provider.authToken) return provider.authToken;
	if (provider.apiKey) return provider.apiKey;
	throw new Error("nessuna credenziale configurata (apiKey/authToken/authTokenFile)");
}

/** Cache del token letto da file, invalidata sul cambio di mtime (rotazione esterna). */
const tokenFileCache = new Map<string, { mtimeMs: number; token: string }>();

function readTokenFile(path: string): string {
	const stat = statSync(path);
	const cached = tokenFileCache.get(path);
	if (cached && cached.mtimeMs === stat.mtimeMs) return cached.token;
	const token = readFileSync(path, "utf8").trim();
	tokenFileCache.set(path, { mtimeMs: stat.mtimeMs, token });
	return token;
}

/** Unisce due liste comma-separated (deduplicando, ignorando i vuoti). */
function mergeCsv(a: string | undefined, b: string | undefined): string | undefined {
	const parts = new Set<string>();
	for (const raw of [a, b]) {
		if (!raw) continue;
		for (const p of raw.split(",")) {
			const trimmed = p.trim();
			if (trimmed !== "") parts.add(trimmed);
		}
	}
	return parts.size > 0 ? [...parts].join(",") : undefined;
}

function bearerToken(req: IncomingMessage): string | undefined {
	const header = req.headers.authorization;
	if (!header?.startsWith("Bearer ")) return undefined;
	return header.slice("Bearer ".length).trim();
}

function headerValue(req: IncomingMessage, name: string): string | undefined {
	const value = req.headers[name];
	return typeof value === "string" ? value : undefined;
}

/** true se la richiesta dichiara (o può portare) un body da inoltrare. */
function hasRequestBody(req: IncomingMessage): boolean {
	const method = req.method ?? "GET";
	if (method === "GET" || method === "HEAD") return false;
	const contentLength = req.headers["content-length"];
	if (contentLength !== undefined) return Number(contentLength) > 0;
	return req.headers["transfer-encoding"] !== undefined;
}

// Regex invece di JSON.parse: il prefisso accumulato per il peek può essere un
// JSON troncato (il body intero supera MODEL_PEEK_BYTES), quindi non è detto
// che sia parsabile — ma il campo "model" compare quasi sempre nei primi byte.
const MODEL_FIELD_PATTERN = /"model"\s*:\s*"([^"\\]{1,200})"/;

function extractModel(peekedPrefix: Buffer): string | undefined {
	const text = peekedPrefix.toString("utf8", 0, Math.min(peekedPrefix.length, MODEL_PEEK_BYTES));
	return MODEL_FIELD_PATTERN.exec(text)?.[1];
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
	const body = JSON.stringify(payload);
	res.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"content-length": Buffer.byteLength(body),
		"cache-control": "no-store",
		"x-content-type-options": "nosniff",
	});
	res.end(body);
}
