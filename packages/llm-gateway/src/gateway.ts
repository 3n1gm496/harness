import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { Readable } from "node:stream";
import { type Logger, MetricsRegistry, peerCertFingerprint } from "@harness/shared";

/**
 * Gateway LLM: i client si autenticano con il token di device (verificato via
 * introspezione sul control plane) e il gateway inoltra le richieste al
 * provider iniettando le credenziali, che così non risiedono mai sui client.
 *
 * Route:
 *   /anthropic/*  →  ANTHROPIC_BASE_URL con header x-api-key
 *   /openai/*     →  OPENAI_BASE_URL con header Authorization: Bearer
 */
export interface GatewayOptions {
	controlPlaneUrl: string;
	/** Token gateway emesso dal control plane per l'introspezione. */
	gatewayToken: string;
	providers: {
		anthropic?: { baseUrl: string; apiKey: string };
		openai?: { baseUrl: string; apiKey: string };
	};
	/** Richieste al minuto per device (default 60). */
	rateLimitPerMinute?: number;
	/** TTL della cache di introspezione in millisecondi (default 60s). */
	introspectionTtlMs?: number;
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

export function createGatewayServer(options: GatewayOptions): Server | HttpsServer {
	const introspectionCache = new Map<string, IntrospectionEntry>();
	const rateBuckets = new Map<string, { windowStart: number; count: number }>();
	const rateLimit = options.rateLimitPerMinute ?? 60;
	const ttl = options.introspectionTtlMs ?? 60_000;
	const log = options.log ?? ((entry) => options.logger?.info("gateway_request", entry) ?? console.log(JSON.stringify(entry)));
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
		if (cached && cached.expiresAt > Date.now()) return cached;
		// Cap difensivo: token invalidi spammati non devono far crescere la
		// cache senza limite.
		if (introspectionCache.size > 5_000) introspectionCache.clear();
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

	function checkRateLimit(deviceId: string): boolean {
		const now = Date.now();
		const bucket = rateBuckets.get(deviceId);
		if (!bucket || now - bucket.windowStart >= 60_000) {
			rateBuckets.set(deviceId, { windowStart: now, count: 1 });
			return true;
		}
		bucket.count += 1;
		return bucket.count <= rateLimit;
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
		if (!checkRateLimit(introspection.deviceId)) {
			sendJson(res, 429, { error: "rate limit superato" });
			return;
		}

		const body = await readBody(req);
		const started = Date.now();
		const headers: Record<string, string> = {
			"content-type": headerValue(req, "content-type") ?? "application/json",
		};
		if (providerName === "anthropic") {
			headers["x-api-key"] = provider.apiKey;
			const version = headerValue(req, "anthropic-version");
			if (version) headers["anthropic-version"] = version;
			// Le funzionalità beta (prompt caching, ecc.) viaggiano in questo header.
			const beta = headerValue(req, "anthropic-beta");
			if (beta) headers["anthropic-beta"] = beta;
		} else {
			headers.authorization = `Bearer ${provider.apiKey}`;
		}

		const upstream = await fetch(`${provider.baseUrl}${upstreamPath}${url.search}`, {
			method: req.method ?? "POST",
			headers,
			body: body.length > 0 ? body : null,
		});

		const durationMs = Date.now() - started;
		metrics.incCounter("harness_gateway_requests_total", { provider: providerName, status: String(upstream.status) });
		metrics.observe("harness_gateway_upstream_duration_seconds", durationMs / 1000, { provider: providerName });
		log({
			ts: new Date().toISOString(),
			deviceId: introspection.deviceId,
			provider: providerName,
			path: upstreamPath,
			model: extractModel(body),
			status: upstream.status,
			durationMs,
		});

		res.writeHead(upstream.status, {
			"content-type": upstream.headers.get("content-type") ?? "application/json",
			"cache-control": "no-store",
		});
		if (upstream.body) {
			Readable.fromWeb(upstream.body as import("node:stream/web").ReadableStream).pipe(res);
		} else {
			res.end();
		}
	}
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

async function readBody(req: IncomingMessage): Promise<Buffer> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buffer = chunk as Buffer;
		total += buffer.length;
		if (total > 32 * 1_048_576) throw new Error("body troppo grande");
		chunks.push(buffer);
	}
	return Buffer.concat(chunks);
}

function extractModel(body: Buffer): string | undefined {
	try {
		const parsed = JSON.parse(body.toString("utf8")) as { model?: unknown };
		return typeof parsed.model === "string" ? parsed.model : undefined;
	} catch {
		return undefined;
	}
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
