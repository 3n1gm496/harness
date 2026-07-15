import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { ControlPlaneService, createControlPlaneServer, Store } from "@harness/control-plane";
import { createGatewayServer } from "../gateway.js";
import { PostgresGatewayRateLimiter } from "../rate-limit.js";

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
	adminToken = service.auth.bootstrapAdminToken("test");
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

	const identity = service.auth.authenticateAdmin(adminToken);
	const groupId = service.org.overview(identity).groups[0]?.groupId as string;
	const enrollToken = service.devices.createEnrollToken(identity, groupId, 10);
	const enrollment = service.devices.enrollDevice(enrollToken, "gw-client");
	deviceToken = enrollment.deviceToken;
	deviceId = enrollment.deviceId;
	const gatewayToken = service.auth.createGatewayToken(identity, "gw");

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

test("endpoint fuori dall'allowlist di inferenza → 403", async () => {
	for (const path of ["/anthropic/v1/files", "/anthropic/v1/organizations/me", "/anthropic/v1/messagesX"]) {
		const response = await fetch(`${gatewayUrl}${path}`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}` },
			body: "{}",
		});
		assert.equal(response.status, 403, `atteso 403 per ${path}`);
	}
});

test("l'header anthropic-beta viene inoltrato al provider", async () => {
	let seenBeta: string | undefined;
	const original = upstream.listeners("request");
	upstream.removeAllListeners("request");
	upstream.on("request", (req, res) => {
		seenBeta = req.headers["anthropic-beta"] as string | undefined;
		res.writeHead(200, { "content-type": "application/json" });
		res.end("{}");
	});
	try {
		await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: {
				authorization: `Bearer ${deviceToken}`,
				"anthropic-beta": "prompt-caching-2024-07-31",
			},
			body: "{}",
		});
		assert.equal(seenBeta, "prompt-caching-2024-07-31");
	} finally {
		upstream.removeAllListeners("request");
		for (const listener of original) upstream.on("request", listener as () => void);
	}
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
	const identity = service.auth.authenticateAdmin(adminToken);
	service.devices.updateDevice(identity, deviceId, { revoked: true });
	await new Promise((resolve) => setTimeout(resolve, 80)); // oltre il TTL di introspezione
	const response = await fetch(`${gatewayUrl}/anthropic/v1/messages`, {
		method: "POST",
		headers: { authorization: `Bearer ${deviceToken}` },
		body: "{}",
	});
	assert.equal(response.status, 401);
	service.devices.updateDevice(identity, deviceId, { revoked: false });
	await new Promise((resolve) => setTimeout(resolve, 80));
});

test("le risposte in streaming (SSE) vengono inoltrate chunk per chunk", async () => {
	// Upstream che emette eventi SSE ritardati, come farebbe un provider in stream.
	const sse = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "text/event-stream" });
		let n = 0;
		const timer = setInterval(() => {
			res.write(`data: {"chunk":${n}}\n\n`);
			if (++n === 4) {
				clearInterval(timer);
				res.end("data: [DONE]\n\n");
			}
		}, 10);
	});
	await new Promise<void>((resolve) => sse.listen(0, resolve));
	const sseUrl = `http://127.0.0.1:${(sse.address() as AddressInfo).port}`;

	const identity = service.auth.authenticateAdmin(adminToken);
	const gatewayToken = service.auth.createGatewayToken(identity, "gw-sse");
	const streamGateway = createGatewayServer({
		controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
		gatewayToken,
		providers: { anthropic: { baseUrl: sseUrl, apiKey: "k" } },
		log: () => {},
	});
	await new Promise<void>((resolve) => streamGateway.listen(0, resolve));
	const streamUrl = `http://127.0.0.1:${(streamGateway.address() as AddressInfo).port}`;

	try {
		const response = await fetch(`${streamUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
			body: JSON.stringify({ model: "x", stream: true }),
		});
		assert.equal(response.headers.get("content-type"), "text/event-stream");
		let full = "";
		for await (const chunk of response.body as AsyncIterable<Uint8Array>) {
			full += Buffer.from(chunk).toString("utf8");
		}
		assert.equal((full.match(/"chunk":/g) ?? []).length, 4);
		assert.ok(full.includes("[DONE]"));
	} finally {
		await new Promise((resolve) => streamGateway.close(resolve));
		await new Promise((resolve) => sse.close(resolve));
	}
});

test("il body viene inoltrato in streaming: un payload grande arriva integro e il model resta nel log", async () => {
	let receivedLength = 0;
	const original = upstream.listeners("request");
	upstream.removeAllListeners("request");
	upstream.on("request", (req, res) => {
		const chunks: Buffer[] = [];
		req.on("data", (c: Buffer) => chunks.push(c));
		req.on("end", () => {
			receivedLength = Buffer.concat(chunks).length;
			res.writeHead(200, { "content-type": "application/json" });
			res.end("{}");
		});
	});

	const logged: Record<string, unknown>[] = [];
	const identity = service.auth.authenticateAdmin(adminToken);
	const gwToken = service.auth.createGatewayToken(identity, "gw-stream-body");
	const streamBodyGateway = createGatewayServer({
		controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
		gatewayToken: gwToken,
		providers: { anthropic: { baseUrl: `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`, apiKey: "k" } },
		log: (entry) => logged.push(entry),
	});
	await new Promise<void>((resolve) => streamBodyGateway.listen(0, resolve));
	const gwUrl = `http://127.0.0.1:${(streamBodyGateway.address() as AddressInfo).port}`;
	try {
		// Filler ben oltre il tetto di peek (64 KiB) per il model: il body
		// intero non viene mai bufferizzato in memoria dal gateway, solo
		// inoltrato in streaming, ma il campo "model" (nei primi byte) resta
		// comunque nel log.
		const filler = "x".repeat(200_000);
		const payload = JSON.stringify({ model: "claude-big", messages: [], filler });
		const response = await fetch(`${gwUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
			body: payload,
		});
		assert.equal(response.status, 200);
		assert.equal(receivedLength, Buffer.byteLength(payload), "l'upstream deve ricevere il body per intero");
		assert.equal(logged.at(-1)?.model, "claude-big");
	} finally {
		await new Promise((resolve) => streamBodyGateway.close(resolve));
		upstream.removeAllListeners("request");
		for (const listener of original) upstream.on("request", listener as () => void);
	}
});

test("timeout upstream: una connessione appesa risponde 504 entro la soglia configurata", async () => {
	// Upstream che accetta la connessione ma non risponde mai (rete/provider
	// appeso): senza timeout la richiesta resterebbe appesa per sempre.
	const hangingSockets: import("node:net").Socket[] = [];
	const hanging = createServer((_req, _res) => {
		/* non risponde mai */
	});
	hanging.on("connection", (socket) => hangingSockets.push(socket));
	await new Promise<void>((resolve) => hanging.listen(0, resolve));
	const hangingUrl = `http://127.0.0.1:${(hanging.address() as AddressInfo).port}`;

	const identity = service.auth.authenticateAdmin(adminToken);
	const gwToken = service.auth.createGatewayToken(identity, "gw-timeout");
	const timeoutGateway = createGatewayServer({
		controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
		gatewayToken: gwToken,
		providers: { anthropic: { baseUrl: hangingUrl, apiKey: "k" } },
		upstreamTimeoutMs: 150,
		log: () => {},
	});
	await new Promise<void>((resolve) => timeoutGateway.listen(0, resolve));
	const gwUrl = `http://127.0.0.1:${(timeoutGateway.address() as AddressInfo).port}`;
	try {
		const started = Date.now();
		const response = await fetch(`${gwUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
			body: "{}",
		});
		assert.equal(response.status, 504);
		assert.ok(Date.now() - started < 5_000, "il timeout deve scattare in fretta, non attendere un default lungo");
	} finally {
		await new Promise((resolve) => timeoutGateway.close(resolve));
		for (const socket of hangingSockets) socket.destroy();
		await new Promise((resolve) => hanging.close(resolve));
	}
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

test("un errore dello stream upstream DOPO gli header non fa crashare il processo del gateway", async () => {
	// Upstream che invia gli header + un chunk e poi RESETTA la connessione a
	// metà stream (reset del provider, o il timeout upstream che scatta mentre
	// la risposta è già in corso). Prima del fix questo emetteva un evento
	// 'error' non gestito su un Readable → crash dell'intero processo, buttando
	// giù ogni altra richiesta in volo. Se il processo crashasse, morirebbe il
	// test runner stesso: il fatto che il test prosegua e una richiesta
	// successiva riesca è la prova che il gateway è sopravvissuto.
	const faulty = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "text/event-stream" });
		res.write('data: {"chunk":0}\n\n');
		// Reset duro della connessione TCP dopo il primo chunk.
		setTimeout(() => res.socket?.destroy(), 20);
	});
	await new Promise<void>((resolve) => faulty.listen(0, resolve));
	const faultyUrl = `http://127.0.0.1:${(faulty.address() as AddressInfo).port}`;

	// Upstream "sano" per la richiesta di controllo post-crash.
	const healthy = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ ok: true }));
	});
	await new Promise<void>((resolve) => healthy.listen(0, resolve));
	const healthyUrl = `http://127.0.0.1:${(healthy.address() as AddressInfo).port}`;

	const identity = service.auth.authenticateAdmin(adminToken);
	const gwToken = service.auth.createGatewayToken(identity, "gw-faulty-stream");
	let faultyGateway = createGatewayServer({
		controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
		gatewayToken: gwToken,
		providers: { anthropic: { baseUrl: faultyUrl, apiKey: "k" } },
		log: () => {},
	});
	await new Promise<void>((resolve) => faultyGateway.listen(0, resolve));
	let gwUrl = `http://127.0.0.1:${(faultyGateway.address() as AddressInfo).port}`;
	try {
		// La richiesta verso l'upstream difettoso: il client riceve una risposta
		// troncata o un errore di rete, ma NON deve far crashare il gateway.
		try {
			const response = await fetch(`${gwUrl}/anthropic/v1/messages`, {
				method: "POST",
				headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
				body: JSON.stringify({ model: "x", stream: true }),
			});
			// Gli header sono già passati (200) prima del reset: consumiamo il body,
			// che si interrompe. L'errore lato client è atteso e innocuo.
			await response.text().catch(() => {});
		} catch {
			// Anche un errore di fetch lato client è accettabile: l'importante è
			// che il PROCESSO del gateway non sia morto.
		}

		// Piccola attesa perché un eventuale crash asincrono (evento 'error' non
		// gestito) si manifesti prima del controllo.
		await new Promise((resolve) => setTimeout(resolve, 50));

		// Prova del nove: il gateway è ancora vivo e serve una nuova richiesta.
		faultyGateway.close();
		faultyGateway = createGatewayServer({
			controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
			gatewayToken: gwToken,
			providers: { anthropic: { baseUrl: healthyUrl, apiKey: "k" } },
			log: () => {},
		});
		await new Promise<void>((resolve) => faultyGateway.listen(0, resolve));
		gwUrl = `http://127.0.0.1:${(faultyGateway.address() as AddressInfo).port}`;
		const probe = await fetch(`${gwUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
			body: JSON.stringify({ model: "x" }),
		});
		assert.equal(probe.status, 200, "il gateway deve essere ancora vivo dopo l'errore dello stream");
	} finally {
		await new Promise((resolve) => faultyGateway.close(resolve));
		await new Promise((resolve) => faulty.close(resolve));
		await new Promise((resolve) => healthy.close(resolve));
	}
});

test("la disconnessione del client a metà stream aborta la richiesta upstream", async () => {
	// Upstream che streamma lentamente e registra quando la SUA connessione
	// viene chiusa: se il gateway aborta la fetch upstream alla disconnessione
	// del client, l'upstream vede la connessione chiudersi presto invece di
	// continuare a generare (per un provider LLM: fine del leak di costo).
	let upstreamClosedEarly = false;
	let upstreamFinished = false;
	const slow = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "text/event-stream" });
		let n = 0;
		const timer = setInterval(() => {
			if (!res.write(`data: {"chunk":${n}}\n\n`)) return;
			if (++n >= 50) {
				clearInterval(timer);
				upstreamFinished = true;
				res.end();
			}
		}, 20);
		res.on("close", () => {
			clearInterval(timer);
			if (!upstreamFinished) upstreamClosedEarly = true;
		});
	});
	await new Promise<void>((resolve) => slow.listen(0, resolve));
	const slowUrl = `http://127.0.0.1:${(slow.address() as AddressInfo).port}`;

	const identity = service.auth.authenticateAdmin(adminToken);
	const gwToken = service.auth.createGatewayToken(identity, "gw-client-abort");
	const abortGateway = createGatewayServer({
		controlPlaneUrl: `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`,
		gatewayToken: gwToken,
		providers: { anthropic: { baseUrl: slowUrl, apiKey: "k" } },
		log: () => {},
	});
	await new Promise<void>((resolve) => abortGateway.listen(0, resolve));
	const gwUrl = `http://127.0.0.1:${(abortGateway.address() as AddressInfo).port}`;
	try {
		const controller = new AbortController();
		const response = await fetch(`${gwUrl}/anthropic/v1/messages`, {
			method: "POST",
			headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
			body: JSON.stringify({ model: "x", stream: true }),
			signal: controller.signal,
		});
		// Legge un chunk, poi il client abbandona.
		const reader = (response.body as ReadableStream<Uint8Array>).getReader();
		await reader.read();
		controller.abort();
		await reader.cancel().catch(() => {});

		// Attende che la chiusura si propaghi dal client → gateway → upstream.
		await new Promise((resolve) => setTimeout(resolve, 300));
		assert.equal(upstreamClosedEarly, true, "l'upstream deve vedere la connessione chiusa presto (fetch abortita)");
		assert.equal(upstreamFinished, false, "l'upstream non deve aver completato la generazione");
	} finally {
		await new Promise((resolve) => abortGateway.close(resolve));
		await new Promise((resolve) => slow.close(resolve));
	}
});

const PG_URL = process.env.HARNESS_TEST_PG_URL;

test("rate limit del gateway condiviso su Postgres tra istanze diverse (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	// Chiave univoca per non collidere con residui di altri test sullo stesso DB.
	const deviceKey = `dev-${Math.random().toString(36).slice(2)}`;
	const a = new PostgresGatewayRateLimiter(url);
	const b = new PostgresGatewayRateLimiter(url);
	try {
		// Soglia 5 condivisa: due istanze (a, b) che puntano allo stesso DB devono
		// condividere il conteggio — un limiter per-istanza lascerebbe passare 5
		// richieste per ciascuna (10 in tutto), il bug che il backend chiude.
		const results: boolean[] = [];
		for (let i = 0; i < 5; i += 1) results.push(await a.check(deviceKey, 5));
		for (let i = 0; i < 5; i += 1) results.push(await b.check(deviceKey, 5));
		assert.equal(results.filter(Boolean).length, 5, "solo 5 richieste totali passano, condivise tra le due istanze");
	} finally {
		await a.close();
		await b.close();
	}
});
