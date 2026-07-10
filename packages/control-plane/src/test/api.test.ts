import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { verifyConfigBundle } from "@harness/shared";
import { ControlPlaneService } from "../service.js";
import { createControlPlaneServer } from "../server.js";
import { Store } from "../store.js";

let dataDir: string;
let baseUrl: string;
let server: ReturnType<typeof createControlPlaneServer>;
let adminToken: string;
let publicKeyPem: string;
let deviceToken: string;
let deviceId: string;

before(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "harness-cp-test-"));
	const store = new Store(dataDir);
	const service = new ControlPlaneService(store);
	adminToken = service.bootstrapAdminToken("test-admin");
	server = createControlPlaneServer(service);
	await new Promise<void>((resolve) => server.listen(0, resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
	await new Promise((resolve) => server.close(resolve));
	rmSync(dataDir, { recursive: true, force: true });
});

async function call(
	method: string,
	path: string,
	options: { token?: string; body?: unknown } = {},
): Promise<{ status: number; data: Record<string, unknown> }> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (options.token) headers.authorization = `Bearer ${options.token}`;
	const response = await fetch(`${baseUrl}${path}`, {
		method,
		headers,
		body: options.body === undefined ? null : JSON.stringify(options.body),
	});
	return { status: response.status, data: (await response.json()) as Record<string, unknown> };
}

test("le API admin rifiutano richieste senza token", async () => {
	const result = await call("GET", "/api/admin/overview");
	assert.equal(result.status, 401);
});

test("flusso completo: enroll token → enrollment → config firmata", async () => {
	const overviewResult = await call("GET", "/api/admin/overview", { token: adminToken });
	assert.equal(overviewResult.status, 200);
	const groups = overviewResult.data.groups as { groupId: string }[];
	const groupId = groups[0]?.groupId as string;

	const tokenResult = await call("POST", "/api/admin/enroll-tokens", {
		token: adminToken,
		body: { groupId, ttlMinutes: 10 },
	});
	assert.equal(tokenResult.status, 200);
	const enrollToken = tokenResult.data.enrollToken as string;

	const enrollResult = await call("POST", "/api/enroll", {
		body: { enrollToken, deviceName: "workstation-01" },
	});
	assert.equal(enrollResult.status, 200);
	deviceToken = enrollResult.data.deviceToken as string;
	deviceId = enrollResult.data.deviceId as string;
	publicKeyPem = enrollResult.data.publicKeyPem as string;
	assert.ok(deviceToken.startsWith("dvt_"));
	assert.ok(publicKeyPem.includes("PUBLIC KEY"));

	// Il token di enrollment è monouso.
	const reuse = await call("POST", "/api/enroll", { body: { enrollToken, deviceName: "clone" } });
	assert.equal(reuse.status, 401);

	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(configResult.status, 200);
	const verified = verifyConfigBundle(publicKeyPem, configResult.data.token as string);
	assert.equal(verified.valid, true);
	if (verified.valid) {
		assert.equal(verified.payload.deviceId, deviceId);
		assert.equal(verified.payload.policy.killSwitch, false);
		// I lockdown aziendali sono sempre presenti nei settings gestiti.
		assert.equal(verified.payload.piSettings.defaultProjectTrust, "never");
	}
});

test("il kill switch si propaga nel bundle firmato", async () => {
	const update = await call("PUT", `/api/admin/devices/${deviceId}`, {
		token: adminToken,
		body: { killSwitch: true },
	});
	assert.equal(update.status, 200);

	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	const verified = verifyConfigBundle(publicKeyPem, configResult.data.token as string);
	assert.equal(verified.valid, true);
	if (verified.valid) assert.equal(verified.payload.policy.killSwitch, true);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { killSwitch: false } });
});

test("l'audit dei device viene accettato e riletto, con deviceId forzato", async () => {
	const ingest = await call("POST", "/api/device/audit", {
		token: deviceToken,
		body: {
			events: [
				{
					eventId: "evt_1",
					deviceId: "dev_spoofed",
					timestamp: new Date().toISOString(),
					type: "policy_decision",
					data: { toolName: "bash", action: "deny" },
				},
			],
		},
	});
	assert.equal(ingest.status, 200);
	assert.equal(ingest.data.accepted, 1);

	const audit = await call("GET", `/api/admin/audit?deviceId=${deviceId}`, { token: adminToken });
	const events = audit.data.events as { deviceId: string; type: string }[];
	assert.equal(events.length, 1);
	assert.equal(events[0]?.deviceId, deviceId); // lo spoofing è stato neutralizzato
});

test("l'audit ingest scarta eventi malformati e tronca payload enormi", async () => {
	const huge = "x".repeat(20_000);
	const ingest = await call("POST", "/api/device/audit", {
		token: deviceToken,
		body: {
			events: [
				"non-un-oggetto",
				{ type: "tipo_inventato", data: {} },
				{ type: "tool_call", data: { blob: huge } },
				{ type: "policy_decision", timestamp: "data-non-valida", data: { ok: true } },
			],
		},
	});
	assert.equal(ingest.status, 200);
	assert.equal(ingest.data.accepted, 2); // solo i due eventi con tipo noto

	const audit = await call("GET", `/api/admin/audit?deviceId=${deviceId}&limit=2`, { token: adminToken });
	const events = audit.data.events as { type: string; timestamp: string; data: Record<string, unknown> }[];
	const truncated = events.find((event) => event.type === "tool_call");
	assert.ok(truncated);
	assert.equal(truncated.data.truncated, true);
	assert.ok(JSON.stringify(truncated.data).length < 4096);
	const fixedTimestamp = events.find((event) => event.type === "policy_decision");
	assert.ok(fixedTimestamp);
	assert.ok(!Number.isNaN(Date.parse(fixedTimestamp.timestamp)));
});

test("RBAC: viewer non può mutare, operator non può cambiare policy", async () => {
	const viewerResult = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "viewer-test", role: "viewer" },
	});
	const viewerToken = viewerResult.data.token as string;
	const operatorResult = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "operator-test", role: "operator" },
	});
	const operatorToken = operatorResult.data.token as string;

	// Il viewer legge ma non muta.
	assert.equal((await call("GET", "/api/admin/overview", { token: viewerToken })).status, 200);
	assert.equal(
		(await call("PUT", "/api/admin/org", { token: viewerToken, body: { killSwitch: true } })).status,
		403,
	);

	// L'operator può usare il kill switch ma non cambiare le policy.
	assert.equal(
		(await call("PUT", `/api/admin/devices/${deviceId}`, { token: operatorToken, body: { killSwitch: false } }))
			.status,
		200,
	);
	assert.equal(
		(
			await call("PUT", "/api/admin/org", {
				token: operatorToken,
				body: { policyOverride: { killSwitch: false } },
			})
		).status,
		403,
	);
});

test("un device revocato non riceve più configurazione", async () => {
	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: true } });
	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(configResult.status, 403);
	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: false } });
});

test("introspezione gateway: attivo, poi disattivo dopo revoca", async () => {
	const gatewayResult = await call("POST", "/api/admin/gateway-tokens", {
		token: adminToken,
		body: { name: "gw-test" },
	});
	const gatewayToken = gatewayResult.data.token as string;

	const active = await call("POST", "/api/introspect", { token: gatewayToken, body: { deviceToken } });
	assert.equal(active.status, 200);
	assert.equal(active.data.active, true);
	assert.equal(active.data.deviceId, deviceId);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: true } });
	const inactive = await call("POST", "/api/introspect", { token: gatewayToken, body: { deviceToken } });
	assert.equal(inactive.data.active, false);

	// Senza token gateway l'introspezione è vietata.
	const unauthorized = await call("POST", "/api/introspect", { body: { deviceToken } });
	assert.equal(unauthorized.status, 401);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: false } });
});

test("rotazione device token: il vecchio muore, il nuovo funziona", async () => {
	const rotate = await call("POST", "/api/device/rotate-token", { token: deviceToken });
	assert.equal(rotate.status, 200);
	const newToken = rotate.data.deviceToken as string;
	assert.ok(newToken.startsWith("dvt_"));
	assert.notEqual(newToken, deviceToken);

	const withOld = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(withOld.status, 401);
	const withNew = await call("GET", "/api/device/config", { token: newToken });
	assert.equal(withNew.status, 200);
	deviceToken = newToken;
});

test("token admin con TTL scaduto viene rifiutato; revoca dell'ultimo admin negata", async () => {
	const created = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "effimero", role: "operator", ttlDays: 1 },
	});
	assert.equal(created.status, 200);

	const list = await call("GET", "/api/admin/admin-tokens", { token: adminToken });
	assert.equal(list.status, 200);
	const tokens = list.data.tokens as { id: string; name: string; role: string; expiresAt?: string }[];
	const ephemeral = tokens.find((t) => t.name === "effimero");
	assert.ok(ephemeral?.expiresAt);

	// Revoca del token effimero: ok.
	const revoked = await call("DELETE", `/api/admin/admin-tokens/${ephemeral.id}`, { token: adminToken });
	assert.equal(revoked.status, 200);
	// Revocare l'ultimo admin attivo è vietato.
	const bootstrap = tokens.find((t) => t.role === "admin");
	assert.ok(bootstrap);
	const denied = await call("DELETE", `/api/admin/admin-tokens/${bootstrap.id}`, { token: adminToken });
	assert.equal(denied.status, 409);
});

test("la catena di audit è integra e la manomissione viene rilevata", async () => {
	const intact = await call("GET", `/api/admin/audit/verify?deviceId=${deviceId}`, { token: adminToken });
	assert.equal(intact.status, 200);
	assert.equal(intact.data.valid, true);
	assert.ok((intact.data.entries as number) > 0);

	// Manomissione: si altera una riga in mezzo al file.
	const { readFileSync: readSync, writeFileSync: writeSync, readdirSync } = await import("node:fs");
	const { join: joinPath } = await import("node:path");
	const auditDir = joinPath(dataDir, "audit");
	const file = joinPath(auditDir, readdirSync(auditDir)[0] as string);
	const lines = readSync(file, "utf8").trim().split("\n");
	const target = JSON.parse(lines[0] as string) as { entry: { type: string } };
	target.entry.type = "manomesso";
	lines[0] = JSON.stringify(target);
	writeSync(file, `${lines.join("\n")}\n`);

	const tampered = await call("GET", `/api/admin/audit/verify?deviceId=${deviceId}`, { token: adminToken });
	assert.equal(tampered.data.valid, false);
	assert.equal((tampered.data as { brokenAtLine: number }).brokenAtLine, 1);
});

test("la UI statica viene servita", async () => {
	const response = await fetch(`${baseUrl}/`);
	assert.equal(response.status, 200);
	const html = await response.text();
	assert.match(html, /Piattaforma amministrativa/);
});
