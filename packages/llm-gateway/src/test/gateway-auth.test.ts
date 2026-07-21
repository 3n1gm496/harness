import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { createGatewayServer, type ProviderCredential } from "../gateway.js";

/**
 * Verifica le modalità di credenziale verso il provider: API key (x-api-key),
 * token di account/sessione OAuth (Authorization: Bearer, senza x-api-key) e
 * token letto da file con rotazione. Usa control plane e upstream finti.
 */

const DEVICE_TOKEN = "device-abc";
let controlPlane: Server;
let upstream: Server;
let controlPlaneUrl: string;
let upstreamUrl: string;
let dir: string;
let seen: {
	xApiKey: string | undefined;
	authorization: string | undefined;
	anthropicBeta: string | undefined;
	path: string | undefined;
};

before(async () => {
	dir = mkdtempSync(join(tmpdir(), "harness-gwauth-"));
	controlPlane = createServer((req, res) => {
		if (req.method === "POST" && req.url === "/api/introspect") {
			let raw = "";
			req.on("data", (c) => {
				raw += c;
			});
			req.on("end", () => {
				const { deviceToken } = JSON.parse(raw || "{}");
				const active = deviceToken === DEVICE_TOKEN;
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ active, deviceId: active ? "dev-1" : undefined }));
			});
			return;
		}
		res.writeHead(404).end();
	});
	upstream = createServer((req, res) => {
		seen = {
			xApiKey: req.headers["x-api-key"] as string | undefined,
			authorization: req.headers.authorization as string | undefined,
			anthropicBeta: req.headers["anthropic-beta"] as string | undefined,
			path: req.url,
		};
		req.on("data", () => {});
		req.on("end", () => {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ ok: true }));
		});
	});
	await new Promise<void>((r) => controlPlane.listen(0, "127.0.0.1", r));
	await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
	controlPlaneUrl = `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`;
	upstreamUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;
});

after(async () => {
	for (const s of [controlPlane, upstream]) await new Promise((r) => s.close(r));
	rmSync(dir, { recursive: true, force: true });
});

/** Avvia un gateway con la credenziale data, fa una richiesta Anthropic e restituisce lo status. */
async function callAnthropic(
	cred: Omit<ProviderCredential, "baseUrl">,
	extraHeaders: Record<string, string> = {},
): Promise<number> {
	const gateway = createGatewayServer({
		controlPlaneUrl,
		gatewayToken: "gw-tok",
		providers: { anthropic: { baseUrl: upstreamUrl, ...cred } },
		log: () => {},
	});
	await new Promise<void>((r) => gateway.listen(0, "127.0.0.1", r));
	const url = `http://127.0.0.1:${(gateway.address() as AddressInfo).port}`;
	try {
		const res = await fetch(`${url}/anthropic/v1/messages`, {
			method: "POST",
			headers: { "x-api-key": DEVICE_TOKEN, ...extraHeaders },
			body: "{}",
		});
		return res.status;
	} finally {
		await new Promise((r) => gateway.close(r));
	}
}

test("api-key mode: upstream riceve x-api-key con la chiave iniettata, nessun Authorization", async () => {
	const status = await callAnthropic({ apiKey: "sk-ant-metered" });
	assert.equal(status, 200);
	assert.equal(seen.xApiKey, "sk-ant-metered");
	assert.equal(seen.authorization, undefined);
});

test("oauth mode: upstream riceve Authorization Bearer col token di sessione, NIENTE x-api-key", async () => {
	const status = await callAnthropic(
		{ authToken: "oauth-session-token", betaHeader: "oauth-2025-04-20" },
		{ "anthropic-beta": "prompt-caching-2024-07-31" },
	);
	assert.equal(status, 200);
	assert.equal(seen.authorization, "Bearer oauth-session-token");
	assert.equal(seen.xApiKey, undefined);
	// L'header beta unisce quello del client e quello richiesto dall'OAuth.
	assert.match(seen.anthropicBeta ?? "", /prompt-caching-2024-07-31/);
	assert.match(seen.anthropicBeta ?? "", /oauth-2025-04-20/);
});

test("token-file mode: legge il token dal file e ne segue la rotazione (cambio mtime)", async () => {
	const tokenFile = join(dir, "token");
	writeFileSync(tokenFile, "token-v1\n");
	let status = await callAnthropic({ authTokenFile: tokenFile });
	assert.equal(status, 200);
	assert.equal(seen.authorization, "Bearer token-v1");

	// Rotazione esterna del token (nuovo contenuto → nuovo mtime).
	await new Promise((r) => setTimeout(r, 10));
	writeFileSync(tokenFile, "token-v2\n");
	status = await callAnthropic({ authTokenFile: tokenFile });
	assert.equal(status, 200);
	assert.equal(seen.authorization, "Bearer token-v2");
});

test("nessuna credenziale configurata → 503 (non si inoltra senza auth)", async () => {
	const status = await callAnthropic({});
	assert.equal(status, 503);
});

test("keyless (backend locale): inoltra SENZA header di auth, non 503", async () => {
	const status = await callAnthropic({ noAuth: true });
	assert.equal(status, 200);
	assert.equal(seen.xApiKey, undefined);
	assert.equal(seen.authorization, undefined);
});
