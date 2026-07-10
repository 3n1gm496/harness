import { readFileSync } from "node:fs";
import type { IncomingMessage, Server, ServerResponse } from "node:http";
import { createServer } from "node:http";
import { createServer as createHttpsServer, type Server as HttpsServer } from "node:https";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { ControlPlaneService } from "./service.js";
import { ServiceError } from "./service.js";

export interface ControlPlaneServerOptions {
	/** Certificato e chiave PEM: se presenti il server parla HTTPS con HSTS. */
	tls?: { cert: string; key: string };
	/** Logger strutturato delle richieste (una entry per risposta). */
	log?: (entry: Record<string, unknown>) => void;
}

const MAX_BODY_BYTES = 1_048_576;

/**
 * Rate limit per-IP sull'enrollment: i token hanno 256 bit di entropia e sono
 * monouso, quindi il brute force è impraticabile, ma un endpoint di
 * autenticazione non va comunque lasciato senza freni.
 */
const ENROLL_RATE_LIMIT_PER_MINUTE = 20;
const enrollBuckets = new Map<string, { windowStart: number; count: number }>();

function checkEnrollRateLimit(ip: string): boolean {
	const now = Date.now();
	if (enrollBuckets.size > 10_000) enrollBuckets.clear(); // cap difensivo
	const bucket = enrollBuckets.get(ip);
	if (!bucket || now - bucket.windowStart >= 60_000) {
		enrollBuckets.set(ip, { windowStart: now, count: 1 });
		return true;
	}
	bucket.count += 1;
	return bucket.count <= ENROLL_RATE_LIMIT_PER_MINUTE;
}

/**
 * Server HTTP del control plane, senza dipendenze esterne.
 * Espone le API device (/api/enroll, /api/device/*), le API amministrative
 * (/api/admin/*), l'introspezione per il gateway e la UI statica su /.
 */
export function createControlPlaneServer(
	service: ControlPlaneService,
	options: ControlPlaneServerOptions = {},
): Server | HttpsServer {
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
		void handle(service, req, res).catch((error) => {
			const status = error instanceof ServiceError ? error.status : 500;
			const message = error instanceof Error ? error.message : "errore interno";
			if (!(error instanceof ServiceError)) console.error("[control-plane] errore:", error);
			sendJson(res, status, { error: message });
		});
	};
	return options.tls ? createHttpsServer(options.tls, listener) : createServer(listener);
}

async function handle(service: ControlPlaneService, req: IncomingMessage, res: ServerResponse): Promise<void> {
	const url = new URL(req.url ?? "/", "http://localhost");
	const method = req.method ?? "GET";
	const path = url.pathname;
	const bearer = bearerToken(req);

	// ---- API device ---------------------------------------------------------

	if (method === "POST" && path === "/api/enroll") {
		if (!checkEnrollRateLimit(req.socket.remoteAddress ?? "sconosciuto")) {
			sendJson(res, 429, { error: "troppi tentativi di enrollment, riprovare tra un minuto" });
			return;
		}
		const body = await readJsonBody(req);
		const enrollToken = requireString(body, "enrollToken");
		const deviceName = optionalString(body, "deviceName") ?? "";
		sendJson(res, 200, service.enrollDevice(enrollToken, deviceName));
		return;
	}

	if (method === "GET" && path === "/api/device/config") {
		const device = service.authenticateDevice(bearer);
		sendJson(res, 200, { token: service.issueConfigBundle(device) });
		return;
	}

	if (method === "POST" && path === "/api/device/audit") {
		const device = service.authenticateDevice(bearer);
		const body = await readJsonBody(req);
		const events: unknown[] = Array.isArray(body.events) ? body.events : [];
		sendJson(res, 200, { accepted: service.ingestAudit(device, events) });
		return;
	}

	if (method === "POST" && path === "/api/device/rotate-token") {
		const device = service.authenticateDevice(bearer);
		sendJson(res, 200, { deviceToken: service.rotateDeviceToken(device) });
		return;
	}

	// ---- Introspezione per il gateway LLM ------------------------------------

	if (method === "POST" && path === "/api/introspect") {
		service.authenticateGateway(bearer);
		const body = await readJsonBody(req);
		const deviceToken = requireString(body, "deviceToken");
		sendJson(res, 200, service.introspectDeviceToken(deviceToken));
		return;
	}

	// ---- API amministrative ---------------------------------------------------

	if (path.startsWith("/api/admin/")) {
		const identity = service.authenticateAdmin(bearer);

		if (method === "GET" && path === "/api/admin/overview") {
			sendJson(res, 200, service.overview(identity));
			return;
		}
		if (method === "GET" && path === "/api/admin/org/config") {
			sendJson(res, 200, service.getOrgConfig(identity));
			return;
		}
		if (method === "PUT" && path === "/api/admin/org") {
			service.updateOrg(identity, await readJsonBody(req));
			sendJson(res, 200, { ok: true });
			return;
		}
		if (method === "POST" && path === "/api/admin/groups") {
			const body = await readJsonBody(req);
			sendJson(res, 200, service.createGroup(identity, requireString(body, "name")));
			return;
		}
		const groupMatch = /^\/api\/admin\/groups\/([^/]+)$/.exec(path);
		if (groupMatch) {
			const groupId = decodeURIComponent(groupMatch[1] as string);
			if (method === "PUT") {
				service.updateGroup(identity, groupId, await readJsonBody(req));
				sendJson(res, 200, { ok: true });
				return;
			}
			if (method === "DELETE") {
				service.deleteGroup(identity, groupId);
				sendJson(res, 200, { ok: true });
				return;
			}
		}
		if (method === "POST" && path === "/api/admin/enroll-tokens") {
			const body = await readJsonBody(req);
			const groupId = requireString(body, "groupId");
			const ttlMinutes = typeof body.ttlMinutes === "number" ? body.ttlMinutes : 60;
			sendJson(res, 200, { enrollToken: service.createEnrollToken(identity, groupId, ttlMinutes) });
			return;
		}
		const deviceMatch = /^\/api\/admin\/devices\/([^/]+)$/.exec(path);
		if (deviceMatch && method === "PUT") {
			service.updateDevice(identity, decodeURIComponent(deviceMatch[1] as string), await readJsonBody(req));
			sendJson(res, 200, { ok: true });
			return;
		}
		const effectiveMatch = /^\/api\/admin\/devices\/([^/]+)\/effective-policy$/.exec(path);
		if (effectiveMatch && method === "GET") {
			sendJson(res, 200, service.effectivePolicy(identity, decodeURIComponent(effectiveMatch[1] as string)));
			return;
		}
		if (method === "GET" && path === "/api/admin/audit/verify") {
			const deviceId = url.searchParams.get("deviceId") ?? undefined;
			sendJson(res, 200, await service.verifyAudit(identity, deviceId));
			return;
		}
		if (method === "GET" && path === "/api/admin/admin-tokens") {
			sendJson(res, 200, { tokens: service.listAdminTokens(identity) });
			return;
		}
		const adminTokenMatch = /^\/api\/admin\/admin-tokens\/([^/]+)$/.exec(path);
		if (adminTokenMatch && method === "DELETE") {
			service.revokeAdminToken(identity, decodeURIComponent(adminTokenMatch[1] as string));
			sendJson(res, 200, { ok: true });
			return;
		}
		if (method === "GET" && path === "/api/admin/audit") {
			const deviceId = url.searchParams.get("deviceId");
			const limit = Number(url.searchParams.get("limit") ?? "100");
			if (deviceId) {
				sendJson(res, 200, { events: await service.readDeviceAudit(identity, deviceId, limit) });
			} else {
				sendJson(res, 200, { events: await service.readAdminAudit(identity, limit) });
			}
			return;
		}
		if (method === "POST" && path === "/api/admin/admin-tokens") {
			const body = await readJsonBody(req);
			const role = requireString(body, "role") as "admin" | "operator" | "viewer";
			const ttlDays = typeof body.ttlDays === "number" ? body.ttlDays : 90;
			sendJson(res, 200, { token: service.createAdminToken(identity, requireString(body, "name"), role, ttlDays) });
			return;
		}
		if (method === "POST" && path === "/api/admin/gateway-tokens") {
			const body = await readJsonBody(req);
			sendJson(res, 200, { token: service.createGatewayToken(identity, requireString(body, "name")) });
			return;
		}
	}

	// ---- UI statica -----------------------------------------------------------

	if (method === "GET" && (path === "/" || path === "/index.html")) {
		const dir = dirname(fileURLToPath(import.meta.url));
		const html = readFileSync(join(dir, "..", "public", "index.html"), "utf8");
		res.writeHead(200, {
			"content-type": "text/html; charset=utf-8",
			"x-content-type-options": "nosniff",
			"content-security-policy":
				"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:",
		});
		res.end(html);
		return;
	}

	if (method === "GET" && path === "/healthz") {
		sendJson(res, 200, { ok: true });
		return;
	}

	sendJson(res, 404, { error: "non trovato" });
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

function requireString(body: Record<string, unknown>, key: string): string {
	const value = body[key];
	if (typeof value !== "string" || value === "") throw new ServiceError(400, `campo mancante: ${key}`);
	return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
	const value = body[key];
	return typeof value === "string" ? value : undefined;
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
