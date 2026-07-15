import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { type Logger, MetricsRegistry, peerCertFingerprint } from "@harness/shared";
import { sessionCookieValue } from "./cookies.js";
import { type CompiledRoute, compileRoutes, matchRoute, type RouteContext } from "./http-router.js";
import { buildRoutes } from "./routes.js";
import type { ControlPlaneService } from "./service.js";
import { ServiceError } from "./services/context.js";

/** Esito di una sonda di readiness (backend raggiungibile, stato coerente). */
export type ReadinessProbe = () => Promise<{ ready: boolean; detail?: Record<string, unknown> }>;

export interface ControlPlaneServerOptions {
	/** Certificato e chiave PEM: se presenti il server parla HTTPS con HSTS. */
	tls?: { cert: string; key: string };
	/** Logger strutturato: se presente registra una entry per richiesta. */
	logger?: Logger;
	/** Callback legacy per il log delle richieste (una entry per risposta). */
	log?: (entry: Record<string, unknown>) => void;
	/** Sonda di readiness per `/readyz` (default: sempre pronto). */
	readiness?: ReadinessProbe;
}

const MAX_BODY_BYTES = 1_048_576;

interface Infra {
	metrics: MetricsRegistry;
	readiness: ReadinessProbe;
}

/**
 * Server HTTP del control plane, senza dipendenze esterne. Le route applicative
 * sono dichiarate in `routes.ts` e risolte da un dispatcher generico; qui
 * restano la creazione del server (TLS/HSTS), l'osservabilità (log strutturato,
 * metriche Prometheus su `/metrics`, readiness su `/readyz`) e la meccanica di
 * autenticazione/serializzazione condivisa.
 */
export function createControlPlaneServer(
	service: ControlPlaneService,
	options: ControlPlaneServerOptions = {},
): Server | HttpsServer {
	const routes = compileRoutes(buildRoutes());
	const metrics = new MetricsRegistry();
	metrics.counter("harness_http_requests_total", "Richieste HTTP totali per metodo ed esito");
	metrics.histogram("harness_http_request_duration_seconds", "Durata delle richieste HTTP in secondi");
	metrics.gauge("harness_http_requests_in_flight", "Richieste HTTP attualmente in elaborazione");
	metrics.gauge("harness_up", "1 se il processo è vivo");
	metrics.setGauge("harness_up", 1);
	// Metriche di flotta: le stesse informazioni che la dashboard UI calcola
	// per gli operatori (device attivi/stale/sospesi, kill switch, versione di
	// config), ma in Prometheus — così un alert può scattare su "troppi device
	// stale" o "kill switch attivo" senza dover guardare la UI.
	metrics.gauge("harness_fleet_devices", "Device per stato operativo (active|stale|suspended)");
	metrics.gauge("harness_fleet_kill_switch", "1 se il kill switch globale dell'organizzazione è attivo");
	metrics.gauge("harness_fleet_config_version", "Versione corrente della configurazione dell'organizzazione");
	const infra: Infra = { metrics, readiness: options.readiness ?? (async () => ({ ready: true })) };

	const listener = (req: IncomingMessage, res: ServerResponse): void => {
		const started = Date.now();
		const method = req.method ?? "GET";
		metrics.addGauge("harness_http_requests_in_flight", 1);
		if (options.tls) {
			res.setHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
		}
		res.on("finish", () => {
			const durationMs = Date.now() - started;
			const path = (req.url ?? "/").split("?")[0] ?? "/";
			metrics.addGauge("harness_http_requests_in_flight", -1);
			metrics.incCounter("harness_http_requests_total", { method, status: String(res.statusCode) });
			metrics.observe("harness_http_request_duration_seconds", durationMs / 1000, { method });
			const entry = { method, path, status: res.statusCode, durationMs };
			options.logger?.info("http_request", entry);
			options.log?.({ ts: new Date().toISOString(), ...entry });
		});
		void dispatch(routes, service, req, res, infra).catch((error) => {
			const status = error instanceof ServiceError ? error.status : 500;
			const message = error instanceof Error ? error.message : "errore interno";
			if (!(error instanceof ServiceError)) {
				options.logger?.error("unhandled_error", { error: String(error) });
				if (!options.logger) console.error("[control-plane] errore:", error);
			}
			sendJson(res, status, { error: message });
		});
	};
	if (options.tls) {
		// requestCert richiede (senza imporre) il certificato client, così i
		// device legati a un fingerprint possono presentarlo; il binding vero e
		// proprio è verificato a livello applicativo in authenticateDevice.
		return createHttpsServer({ ...options.tls, requestCert: true, rejectUnauthorized: false }, listener);
	}
	return createServer(listener);
}

async function dispatch(
	routes: CompiledRoute[],
	service: ControlPlaneService,
	req: IncomingMessage,
	res: ServerResponse,
	infra: Infra,
): Promise<void> {
	const url = new URL(req.url ?? "/", "http://localhost");
	const method = req.method ?? "GET";
	const path = url.pathname;

	// Endpoint di osservabilità: dipendono da stato locale al server (registro
	// metriche, sonda readiness), quindi non passano dalla tabella di route.
	if (method === "GET" && path === "/metrics") {
		refreshFleetGauges(service, infra.metrics);
		const body = infra.metrics.render();
		res.writeHead(200, {
			"content-type": "text/plain; version=0.0.4; charset=utf-8",
			"content-length": Buffer.byteLength(body),
			"cache-control": "no-store",
		});
		res.end(body);
		return;
	}
	if (method === "GET" && path === "/readyz") {
		const result = await infra.readiness();
		sendJson(res, result.ready ? 200 : 503, {
			ready: result.ready,
			...(result.detail ? { detail: result.detail } : {}),
		});
		return;
	}

	const matched = matchRoute(routes, method, path);
	if (!matched) {
		sendJson(res, 404, { error: "non trovato" });
		return;
	}

	const bearer = bearerToken(req);
	const fp = peerCertFingerprint(req);
	let cachedBody: Record<string, unknown> | undefined;
	const ctx: RouteContext = {
		req,
		res,
		url,
		params: matched.params,
		bearer,
		fp,
		service,
		json: async () => {
			if (cachedBody === undefined) cachedBody = await readJsonBody(req);
			return cachedBody;
		},
	};

	// Autenticazione dichiarata dalla route, risolta prima dell'handler.
	switch (matched.route.def.auth) {
		case "admin":
			// Il bearer resta il percorso per API/CLI, invariato. La UI browser
			// (A2) non tocca più il bearer dopo il login: si autentica col cookie
			// di sessione httpOnly, con CSRF obbligatorio sulle richieste mutanti
			// (il cookie da solo verrebbe comunque allegato dal browser a una
			// richiesta cross-site, mitigato da SameSite=Strict ma in profondità).
			if (bearer) {
				ctx.identity = service.auth.authenticateAdmin(bearer);
			} else {
				const requireCsrf = method !== "GET" && method !== "HEAD";
				const csrfHeader = req.headers["x-csrf-token"];
				ctx.identity = service.auth.authenticateSession(
					sessionCookieValue(req),
					typeof csrfHeader === "string" ? csrfHeader : undefined,
					requireCsrf,
				);
			}
			break;
		case "device":
			ctx.device = service.auth.authenticateDevice(bearer, fp);
			break;
		case "gateway":
			service.auth.authenticateGateway(bearer);
			break;
		case "none":
			break;
	}

	const result = await matched.route.def.handler(ctx);
	if (matched.route.def.raw) return; // l'handler ha già scritto la risposta
	sendJson(res, 200, result);
}

/**
 * Aggiorna i gauge di flotta a ogni scrape (non su un timer: un servizio
 * scrape-driven come Prometheus non ha bisogno di uno stato aggiornato più
 * spesso di quanto lo legga). `/metrics` non richiede autenticazione (come
 * `/healthz`/`/readyz`, per lo scraping automatico): l'identità "viewer"
 * sintetica riusa lo stesso calcolo con ruolo minimo dell'API amministrativa,
 * senza introdurre un secondo percorso di calcolo che potrebbe divergere.
 */
function refreshFleetGauges(service: ControlPlaneService, metrics: MetricsRegistry): void {
	const summary = service.org.fleetSummary({ name: "metrics-scrape", role: "viewer" });
	metrics.setGauge("harness_fleet_devices", summary.active, { state: "active" });
	metrics.setGauge("harness_fleet_devices", summary.stale, { state: "stale" });
	metrics.setGauge("harness_fleet_devices", summary.suspended, { state: "suspended" });
	metrics.setGauge("harness_fleet_kill_switch", summary.killSwitch ? 1 : 0);
	metrics.setGauge("harness_fleet_config_version", summary.configVersion);
}

function bearerToken(req: IncomingMessage): string | undefined {
	const header = req.headers.authorization;
	if (!header?.startsWith("Bearer ")) return undefined;
	return header.slice("Bearer ".length).trim();
}

async function readJsonBody(req: IncomingMessage): Promise<Record<string, unknown>> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of req) {
		const buffer = chunk as Buffer;
		total += buffer.length;
		if (total > MAX_BODY_BYTES) throw new ServiceError(413, "body troppo grande");
		chunks.push(buffer);
	}
	if (total === 0) return {};
	try {
		const parsed: unknown = JSON.parse(Buffer.concat(chunks).toString("utf8"));
		if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
			throw new ServiceError(400, "il body deve essere un oggetto JSON");
		}
		return parsed as Record<string, unknown>;
	} catch (error) {
		if (error instanceof ServiceError) throw error;
		throw new ServiceError(400, "JSON non valido");
	}
}

function sendJson(res: ServerResponse, status: number, payload: unknown): void {
	const body = JSON.stringify(payload);
	res.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"content-length": Buffer.byteLength(body),
		"x-content-type-options": "nosniff",
		"cache-control": "no-store",
	});
	res.end(body);
}
