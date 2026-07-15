import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { peerCertFingerprint } from "@harness/shared";
import type { RouteContext, RouteDef } from "./http-router.js";
import { ServiceError } from "./services/context.js";
import { clientIp } from "./rate-limit.js";

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
					filterParam === "active" || filterParam === "stale" || filterParam === "suspended"
						? filterParam
						: "all";
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
			handler: (ctx) => {
				ctx.service.auth.revokeAdminToken(ctx.identity!, ctx.params.id!);
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

		// ---- Salute e UI statica --------------------------------------------
		{ method: "GET", path: "/healthz", auth: "none", handler: () => ({ ok: true }) },
		{ method: "GET", path: "/", auth: "none", raw: true, handler: serveIndexHtml },
		{ method: "GET", path: "/index.html", auth: "none", raw: true, handler: serveIndexHtml },
	];
}

function serveIndexHtml(ctx: RouteContext): void {
	const dir = dirname(fileURLToPath(import.meta.url));
	const html = readFileSync(join(dir, "..", "public", "index.html"), "utf8");
	ctx.res.writeHead(200, {
		"content-type": "text/html; charset=utf-8",
		"x-content-type-options": "nosniff",
		"content-security-policy":
			"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:",
	});
	ctx.res.end(html);
}
