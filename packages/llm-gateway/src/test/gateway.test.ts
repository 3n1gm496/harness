import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { ControlPlaneService, Store, createControlPlaneServer } from "@harness/control-plane";
import { createGatewayServer } from "../gateway.js";

let dataDir: string;
let controlPlane: ReturnType<typeof createControlPlaneServer>;
let upstream: Server;
let gateway: Server;
let gatewayUrl: string;
let deviceToken: string;
let deviceId: string;
let service: ControlPlaneService;
let adminToken: string;
let lastUpstreamApiKey: string | undefined;

before(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "harness-gw-test-"));
	const store = new Store(dataDir);
	service = new ControlPlaneService(store);
	adminToken = service.bootstrapAdminToken("test");
	controlPlane = createControlPlaneServer(service);
	await new Promise<void>((resolve) => controlPlane.listen(0, resolve));
	const controlPlaneUrl = `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`;

	// Upstream finto che restituisce l'eco della richiesta.
	upstream = createServer((req, res) => {
		lastUpstreamApiKey = req.headers["x-api-key"] as string | undefined;
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ echo: true, path: req.url }));
	});
	await new Promise<void>((resolve) => upstream.listen(0, resolve));
	const upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

	const identity = service.authenticateAdmin(adminToken);
	const groupId = service.overview(identity).groups[0]?.groupId as string;
	const enrollToken = service.createEnrollToken(identity, groupId, 10);
	const enrollment = service.enrollDevice(enrollToken, "gw-client");
	deviceToken = enrollment.deviceToken;
	deviceId = enrollment.deviceId;
	const gatewayToken = service.createGatewayToken(identity, "gw");

	gateway = createGatewayServer({
		controlPlaneUrl,
		gatewayToken,
		providers: { anthropic: { baseUrl: upstreamUrl, apiKey: "sk-ant-segretissima" } },
		rateLimitPerMinute: 5,
		introspectionTtlMs: 50,
		log: () => {},
	});
	await new Promise<void>((resolve) => gateway.listen(0, resolve));
	gatewayUrl = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;
});

after(async () => {
	for (const server of [gateway, upstream, controlPlane]) {
		await new Promise((resolve) => server.close(resolve));
	}
	rmSync(dataDir, { recursive: true, force: true });
});

test("richiesta senza token rifiutata", async () => {
	const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, { method: "POST", body: "{}" });
	assert.equal(response.status, 401);
});

test("richiesta con device token valido inoltrata con la chiave iniettata", async () => {
	const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
		method: "POST",
		headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
		body: JSON.stringify({ model: "claude-test", messages: [] }),
	});
	assert.equal(response.status, 200);
	const data = (await response.json()) as { echo: boolean; path: string };
	assert.equal(data.echo, true);
	assert.equal(data.path, "/v1/messages");
	// La chiave del provider è stata iniettata dal gateway, mai vista dal client.
	assert.equal(lastUpstreamApiKey, "sk-ant-segretissima");
});

test("il token può arrivare anche come x-api-key", async () => {
	const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
		method: "POST",
		headers: { "x-api-key": deviceToken, "content-type": "application/json" },
		body: "{}",
	});
	assert.equal(response.status, 200);
});

test("provider non configurato → 503", async () => {
	const response = await fetch(`${gatewayUrl}/openai/v1/chat/completions`, {
		method: "POST",
		headers: { authorization: `Bearer ${deviceToken}` },
		body: "{}",
	});
	assert.equal(response.status, 503);
});

test("device revocato → 401 dopo la scadenza della cache", async () => {
	const identity = service.authenticateAdmin(adminToken);
	service.updateDevice(identity, deviceId, { revoked: true });
	await new Promise((resolve) => setTimeout(resolve, 80)); // oltre il TTL di introspezione
	const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
		method: "POST",
		headers: { authorization: `Bearer ${deviceToken}` },
		body: "{}",
	});
	assert.equal(response.status, 401);
	service.updateDevice(identity, deviceId, { revoked: false });
	await new Promise((resolve) => setTimeout(resolve, 80));
});

test("rate limit per device → 429", async () => {
	let got429 = false;
	for (let i = 0; i < 10; i += 1) {
		const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}` },
			body: "{}",
		});
		if (response.status === 429) {
			got429 = true;
			break;
		}
	}
	assert.equal(got429, true);
});
