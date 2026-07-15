import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { peerCertFingerprint } from "@harness/shared";
import { buildSessionCookie, clearSessionCookie, isSecureRequest, sessionCookieValue } from "./cookies.js";
import type { RouteContext, RouteDef } from "./http-router.js";
import { generateOpenApiDocument } from "./openapi.js";
import { clientIp } from "./rate-limit.js";
import { ServiceError } from "./services/context.js";

/** Durata del cookie di sessione della UI, in secondi (coerente col TTL lato AuthService). */
const SESSION_COOKIE_MAX_AGE_SECONDS = 12 * 60 * 60;

function requireString(body: Record<string, unknown>, key: string): string {
	const value = body[key];
	if (typeof value !== "string" || value === "") throw new ServiceError(400, `campo mancante: ${key}`);
	return value;
}

function optionalString(body: Record<string, unknown>, key: string): string | undefined {
	const value = body[key];
	return typeof value === "string" ? value : undefined;
}

/**
 * Tabella dichiarativa delle route del control plane. Ogni voce dichiara
 * metodo, pattern del path, modalità di autenticazione e handler. Il dispatcher
 * (`http-router.ts`) risolve l'autenticazione prima di invocare l'handler, che
 * riceve già `ctx.identity` o `ctx.device` popolati.
 */
export function buildRoutes(): RouteDef[] {
	return [
		// ---- API device -----------------------------------------------------
		{
			method: "POST",
			path: "/api/enroll",
			auth: "none",
			handler: async (ctx: RouteContext) => {
				if (!(await ctx.service.devices.checkEnrollRateLimit(clientIp(ctx.req)))) {
					throw new ServiceError(429, "troppi tentativi di enrollment, riprovare tra un minuto");
				}
				const body = await ctx.json();
				const enrollToken = requireString(body, "enrollToken");
				const deviceName = optionalString(body, "deviceName") ?? "";
				// Il device può legarsi al proprio certificato client già all'enrollment,
				// presentandolo via mTLS oppure indicandone il fingerprint nel body.
				const certFingerprint = peerCertFingerprint(ctx.req) ?? optionalString(body, "certFingerprint");
				// Chiave pubblica di firma propria del device (provenance dell'audit),
				// generata dal client all'enrollment: opzionale per retrocompatibilità.
				const deviceSigningPublicKeyPem = optionalString(body, "deviceSigningPublicKeyPem");
				return ctx.service.devices.enrollDevice(enrollToken, deviceName, certFingerprint, deviceSigningPublicKeyPem);
			},
		},
		{
			method: "GET",
			path: "/api/device/config",
			auth: "device",
			handler: (ctx) => ({ token: ctx.service.devices.issueConfigBundle(ctx.device!) }),
		},
		{
			method: "POST",
			path: "/api/device/audit",
			auth: "device",
			handler: async (ctx) => {
				const body = await ctx.json();
				const events: unknown[] = Array.isArray(body.events) ? body.events : [];
				// Firma del batch (JWS con la chiave di firma propria del device):
				// verificata dal service se il device ne ha registrata una.
				const signature = optionalString(body, "signature");
				return { accepted: ctx.service.devices.ingestAudit(ctx.device!, events, signature) };
			},
		},
		{
			method: "POST",
			path: "/api/device/rotate-token",
			auth: "device",
			handler: (ctx) => ({ deviceToken: ctx.service.auth.rotateDeviceToken(ctx.device!) }),
		},
		{
			method: "POST",
			path: "/api/device/bind-cert",
			auth: "device",
			handler: (ctx) => {
				// Trust on first use: già autenticato col token (se legato, il
				// fingerprint combacia); lega il device al certificato presentato.
				ctx.service.auth.bindDeviceCertificate(ctx.device!, ctx.fp);
				return { ok: true };
			},
		},

		// ---- Introspezione per il gateway LLM -------------------------------
		{
			method: "POST",
			path: "/api/introspect",
			auth: "gateway",
			handler: async (ctx) => {
				const body = await ctx.json();
				const deviceToken = requireString(body, "deviceToken");
				// Il gateway inoltra il fingerprint del cert presentato dal device.
				const presentedFingerprint = optionalString(body, "presentedFingerprint");
				return ctx.service.auth.introspectDeviceToken(deviceToken, presentedFingerprint);
			},
		},

		// ---- API amministrative (auth: admin) -------------------------------
		{
			method: "GET",
			path: "/api/admin/overview",
			auth: "admin",
			handler: (ctx) => ctx.service.org.overview(ctx.identity!),
		},
		{
			method: "GET",
			path: "/api/admin/fleet-summary",
			auth: "admin",
			handler: (ctx) => ctx.service.org.fleetSummary(ctx.identity!),
		},
		{
			method: "GET",
			path: "/api/admin/devices",
			auth: "admin",
			handler: (ctx) => {
				const filterParam = ctx.url.searchParams.get("filter");
				const filter =
					filterParam === "active" || filterParam === "stale" || filterParam === "suspended" ? filterParam : "all";
				const q = ctx.url.searchParams.get("q");
				return ctx.service.org.listDevices(ctx.identity!, {
					offset: Number(ctx.url.searchParams.get("offset") ?? "0"),
					limit: Number(ctx.url.searchParams.get("limit") ?? "25"),
					filter,
					...(q ? { q } : {}),
				});
			},
		},
		{
			method: "GET",
			path: "/api/admin/org/config",
			auth: "admin",
			handler: (ctx) => ctx.service.org.getOrgConfig(ctx.identity!),
		},
		{
			method: "PUT",
			path: "/api/admin/org",
			auth: "admin",
			handler: async (ctx) => {
				ctx.service.org.updateOrg(ctx.identity!, await ctx.json());
				return { ok: true };
			},
		},
		{
			method: "POST",
			path: "/api/admin/groups",
			auth: "admin",
			handler: async (ctx) => ctx.service.groups.createGroup(ctx.identity!, requireString(await ctx.json(), "name")),
		},
		{
			method: "PUT",
			path: "/api/admin/groups/:id",
			auth: "admin",
			handler: async (ctx) => {
				ctx.service.groups.updateGroup(ctx.identity!, ctx.params.id!, await ctx.json());
				return { ok: true };
			},
		},
		{
			method: "DELETE",
			path: "/api/admin/groups/:id",
			auth: "admin",
			handler: (ctx) => {
				ctx.service.groups.deleteGroup(ctx.identity!, ctx.params.id!);
				return { ok: true };
			},
		},
		{
			method: "POST",
			path: "/api/admin/enroll-tokens",
			auth: "admin",
			handler: async (ctx) => {
				const body = await ctx.json();
				const groupId = requireString(body, "groupId");
				const ttlMinutes = typeof body.ttlMinutes === "number" ? body.ttlMinutes : 60;
				return { enrollToken: ctx.service.devices.createEnrollToken(ctx.identity!, groupId, ttlMinutes) };
			},
		},
		{
			method: "PUT",
			path: "/api/admin/devices/:id",
			auth: "admin",
			handler: async (ctx) => {
				ctx.service.devices.updateDevice(ctx.identity!, ctx.params.id!, await ctx.json());
				return { ok: true };
			},
		},
		{
			method: "DELETE",
			path: "/api/admin/devices/:id",
			auth: "admin",
			handler: (ctx) => {
				ctx.service.devices.deleteDevice(ctx.identity!, ctx.params.id!);
				return { ok: true };
			},
		},
		{
			method: "GET",
			path: "/api/admin/devices/:id/effective-policy",
			auth: "admin",
			handler: (ctx) => ctx.service.devices.effectivePolicy(ctx.identity!, ctx.params.id!),
		},
		{
			method: "GET",
			path: "/api/admin/signing-keys",
			auth: "admin",
			handler: (ctx) => ({ keys: ctx.service.signingKeys.listSigningKeys(ctx.identity!) }),
		},
		{
			method: "POST",
			path: "/api/admin/signing-keys",
			auth: "admin",
			handler: (ctx) => ctx.service.signingKeys.addSigningKey(ctx.identity!),
		},
		{
			method: "POST",
			path: "/api/admin/signing-keys/:id/promote",
			auth: "admin",
			handler: (ctx) => {
				ctx.service.signingKeys.promoteSigningKey(ctx.identity!, ctx.params.id!);
				return { ok: true };
			},
		},
		{
			method: "DELETE",
			path: "/api/admin/signing-keys/:id",
			auth: "admin",
			handler: (ctx) => {
				ctx.service.signingKeys.retireSigningKey(ctx.identity!, ctx.params.id!);
				return { ok: true };
			},
		},
		{
			method: "GET",
			path: "/api/admin/audit/verify",
			auth: "admin",
			handler: async (ctx) => {
				const deviceId = ctx.url.searchParams.get("deviceId") ?? undefined;
				return ctx.service.auditLog.verifyAudit(ctx.identity!, deviceId);
			},
		},
		{
			method: "GET",
			path: "/api/admin/audit/anchor",
			auth: "admin",
			handler: (ctx) => ctx.service.auditLog.exportAuditAnchor(ctx.identity!),
		},
		{
			method: "GET",
			path: "/api/admin/audit",
			auth: "admin",
			handler: async (ctx) => {
				const deviceId = ctx.url.searchParams.get("deviceId");
				const limit = Number(ctx.url.searchParams.get("limit") ?? "100");
				const events = deviceId
					? await ctx.service.auditLog.readDeviceAudit(ctx.identity!, deviceId, limit)
					: await ctx.service.auditLog.readAdminAudit(ctx.identity!, limit);
				return { events };
			},
		},
		{
			method: "GET",
			path: "/api/admin/admin-tokens",
			auth: "admin",
			handler: (ctx) => ({ tokens: ctx.service.auth.listAdminTokens(ctx.identity!) }),
		},
		{
			method: "POST",
			path: "/api/admin/admin-tokens",
			auth: "admin",
			handler: async (ctx) => {
				const body = await ctx.json();
				const role = requireString(body, "role") as "admin" | "operator" | "viewer";
				const ttlDays = typeof body.ttlDays === "number" ? body.ttlDays : 90;
				return { token: ctx.service.auth.createAdminToken(ctx.identity!, requireString(body, "name"), role, ttlDays) };
			},
		},
		{
			method: "DELETE",
			path: "/api/admin/admin-tokens/:id",
			auth: "admin",
			handler: async (ctx) => {
				await ctx.service.auth.revokeAdminToken(ctx.identity!, ctx.params.id!);
				return { ok: true };
			},
		},
		{
			method: "POST",
			path: "/api/admin/gateway-tokens",
			auth: "admin",
			handler: async (ctx) => ({
				token: ctx.service.auth.createGatewayToken(ctx.identity!, requireString(await ctx.json(), "name")),
			}),
		},

		// ---- Sessione della UI amministrativa (A2) --------------------------
		// Sostituisce il bearer token in `localStorage`: la UI POSTa il token
		// amministrativo una sola volta al login, riceve un cookie httpOnly (mai
		// letto da JS) più un CSRF token nel body (allegato dal JS come header
		// sulle richieste mutanti). Il bearer resta invariato per API/CLI.
		{
			method: "POST",
			path: "/api/admin/session/login",
			auth: "none",
			handler: async (ctx) => {
				const body = await ctx.json();
				const { sessionId, csrfToken, identity } = await ctx.service.auth.createAdminSession(
					optionalString(body, "token"),
				);
				ctx.res.setHeader(
					"set-cookie",
					buildSessionCookie(sessionId, SESSION_COOKIE_MAX_AGE_SECONDS, isSecureRequest(ctx.req)),
				);
				return { name: identity.name, role: identity.role, csrfToken };
			},
		},
		{
			method: "GET",
			path: "/api/admin/session/me",
			auth: "none",
			// Usato dopo un reload di pagina: il cookie httpOnly sopravvive, il
			// CSRF token tenuto in memoria JS no — questo endpoint lo riconsegna
			// senza richiedere un nuovo login, se la sessione è ancora valida.
			// Risponde sempre 200 (anche senza sessione): è un probe, non una
			// route protetta, per non generare un 401 atteso a ogni caricamento
			// di pagina senza sessione (il caso più comune, prima del login).
			handler: (ctx) => ctx.service.auth.probeSession(sessionCookieValue(ctx.req)),
		},
		{
			method: "POST",
			path: "/api/admin/session/logout",
			auth: "none",
			handler: async (ctx) => {
				const sessionId = sessionCookieValue(ctx.req);
				if (sessionId) {
					// Richiede il CSRF token anche sul logout (difesa in profondità,
					// come ogni mutazione): impedisce un logout forzato via CSRF. Se la
					// sessione è già invalida (401) il logout è idempotente e prosegue;
					// un CSRF errato su sessione valida (403) viene propagato.
					try {
						const csrf = ctx.req.headers["x-csrf-token"];
						await ctx.service.auth.authenticateSession(sessionId, typeof csrf === "string" ? csrf : undefined, true);
					} catch (error) {
						if (error instanceof ServiceError && error.status === 403) throw error;
					}
					await ctx.service.auth.destroySession(sessionId);
				}
				ctx.res.setHeader("set-cookie", clearSessionCookie(isSecureRequest(ctx.req)));
				return { ok: true };
			},
		},

		// ---- Salute e UI statica --------------------------------------------
		{ method: "GET", path: "/healthz", auth: "none", handler: () => ({ ok: true }) },
		{ method: "GET", path: "/api/openapi.json", auth: "none", handler: () => generateOpenApiDocument() },
		{ method: "GET", path: "/", auth: "none", raw: true, handler: serveIndexHtml },
		{ method: "GET", path: "/index.html", auth: "none", raw: true, handler: serveIndexHtml },
		{
			method: "GET",
			path: "/app.css",
			auth: "none",
			raw: true,
			handler: (ctx) => serveStaticAsset(ctx, "app.css", "text/css; charset=utf-8"),
		},
		{
			method: "GET",
			path: "/app.js",
			auth: "none",
			raw: true,
			handler: (ctx) => serveStaticAsset(ctx, "app.js", "text/javascript; charset=utf-8"),
		},
	];
}

/**
 * CSP dell'unica pagina statica servita: nessun `'unsafe-inline'` (A2), grazie
 * a script e stile esternalizzati in `app.js`/`app.css` e alla rimozione di
 * ogni `onclick=` inline (l'HTML delega gli eventi via `addEventListener`).
 * `frame-ancestors 'none'` (più `X-Frame-Options: DENY` per i browser datati)
 * blocca l'inclusione in un iframe: anti-clickjacking sulla UI amministrativa.
 */
const CSP = "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'";

function serveIndexHtml(ctx: RouteContext): void {
	const html = readPublicFile("index.html");
	ctx.res.writeHead(200, {
		"content-type": "text/html; charset=utf-8",
		"x-content-type-options": "nosniff",
		"content-security-policy": CSP,
		"x-frame-options": "DENY",
	});
	ctx.res.end(html);
}

function serveStaticAsset(ctx: RouteContext, filename: string, contentType: string): void {
	const body = readPublicFile(filename);
	ctx.res.writeHead(200, {
		"content-type": contentType,
		"x-content-type-options": "nosniff",
		"cache-control": "no-cache",
	});
	ctx.res.end(body);
}

function readPublicFile(filename: string): string {
	const dir = dirname(fileURLToPath(import.meta.url));
	return readFileSync(join(dir, "..", "public", filename), "utf8");
}
