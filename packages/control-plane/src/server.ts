import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { peerCertFingerprint } from "@harness/shared";
import type { ControlPlaneService } from "./service.js";
import { ServiceError } from "./services/context.js";
import { type CompiledRoute, type RouteContext, compileRoutes, matchRoute } from "./http-router.js";
import { buildRoutes } from "./routes.js";

export interface ControlPlaneServerOptions {
	/** Certificato e chiave PEM: se presenti il server parla HTTPS con HSTS. */
	tls?: { cert: string; key: string };
	/** Logger strutturato delle richieste (una entry per risposta). */
	log?: (entry: Record<string, unknown>) => void;
}

const MAX_BODY_BYTES = 1_048_576;

/**
 * Server HTTP del control plane, senza dipendenze esterne. Le route sono
 * dichiarate in `routes.ts` e risolte da un dispatcher generico: qui restano
 * solo la creazione del server (TLS/HSTS, logging) e la meccanica di
 * autenticazione/serializzazione condivisa da tutte le route.
 */
export function createControlPlaneServer(
	service: ControlPlaneService,
	options: ControlPlaneServerOptions = {},
): Server | HttpsServer {
	const routes = compileRoutes(buildRoutes());

	const listener = (req: IncomingMessage, res: ServerResponse): void => {
		const started = Date.now();
		if (options.tls) {
			res.setHeader("strict-transport-security", "max-age=31536000; includeSubDomains");
		}
		if (options.log) {
			res.on("finish", () => {
				options.log?.({
					ts: new Date().toISOString(),
					method: req.method,
					path: (req.url ?? "/").split("?")[0],
					status: res.statusCode,
					durationMs: Date.now() - started,
				});
			});
		}
		void dispatch(routes, service, req, res).catch((error) => {
			const status = error instanceof ServiceError ? error.status : 500;
			const message = error instanceof Error ? error.message : "errore interno";
			if (!(error instanceof ServiceError)) console.error("[control-plane] errore:", error);
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
): Promise<void> {
	const url = new URL(req.url ?? "/", "http://localhost");
	const method = req.method ?? "GET";
	const matched = matchRoute(routes, method, url.pathname);
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
			ctx.identity = service.authenticateAdmin(bearer);
			break;
		case "device":
			ctx.device = service.authenticateDevice(bearer, fp);
			break;
		case "gateway":
			service.authenticateGateway(bearer);
			break;
		case "none":
			break;
	}

	const result = await matched.route.def.handler(ctx);
	if (matched.route.def.raw) return; // l'handler ha già scritto la risposta
	sendJson(res, 200, result);
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
