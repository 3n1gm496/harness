#!/usr/bin/env node
// Demo LIVE dell'agente nativo di Harness, end-to-end e su HTTP reale.
//
// Catena esercitata (nessun mock del nostro codice):
//   Agent (@harness/agent-core)
//     → LlmClient  → HTTP → GATEWAY REALE (@harness/llm-gateway)
//                              → introspezione del device token (control plane finto)
//                              → inoltro al provider (upstream Anthropic finto),
//                                iniettando la API key del provider
//
// Cosa dimostra:
//   1. l'agente guida un compito multi-step (read → edit → bash) su file veri;
//   2. l'enforcement blocca un comando pericoloso PRIMA dell'esecuzione;
//   3. la redaction nasconde un segreto letto da un file;
//   4. la delega a un sotto-agente (`task`) sotto lo stesso enforcement;
//   5. le credenziali del provider NON lasciano mai il gateway (il device token
//      non arriva all'upstream; l'upstream vede solo la API key iniettata).
//
// Esce 0 se tutte le asserzioni passano, 1 altrimenti (usato anche come gate CI).

import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEnforcedAgent, LlmClient } from "../../packages/agent-core/dist/index.js";
import { FleetState } from "../../packages/enforcement-core/dist/index.js";
import { createGatewayServer } from "../../packages/llm-gateway/dist/index.js";

const PROVIDER_API_KEY = "UPSTREAM-PROVIDER-SECRET"; // credenziale che deve restare nel gateway
const DEVICE_TOKEN = "device-token-abc"; // ciò che il client presenta
const GATEWAY_TOKEN = "gateway-introspection-token";

// ---- SSE Anthropic (streaming) ---------------------------------------------
const sse = (o) => `event: ${o.type}\ndata: ${JSON.stringify(o)}\n\n`;
function toolSse(id, name, input) {
	return [
		sse({ type: "message_start", message: { model: "demo", usage: { input_tokens: 5, output_tokens: 0 } } }),
		sse({ type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name } }),
		sse({
			type: "content_block_delta",
			index: 0,
			delta: { type: "input_json_delta", partial_json: JSON.stringify(input) },
		}),
		sse({ type: "content_block_stop", index: 0 }),
		sse({ type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 12 } }),
		sse({ type: "message_stop" }),
	].join("");
}
function textSse(text) {
	return [
		sse({ type: "message_start", message: { model: "demo", usage: { input_tokens: 6, output_tokens: 0 } } }),
		sse({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
		sse({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }),
		sse({ type: "content_block_stop", index: 0 }),
		sse({ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 9 } }),
		sse({ type: "message_stop" }),
	].join("");
}

// Copione delle risposte del modello, nell'ordine in cui il loop le richiederà.
const SCRIPT = [
	toolSse("c1", "read_file", { path: "greeting.txt" }),
	toolSse("c2", "edit_file", { path: "greeting.txt", old_string: "ciao mondo", new_string: "Salve, mondo" }),
	toolSse("c3", "bash", { command: "cat greeting.txt" }),
	toolSse("c4", "bash", { command: "rm -rf /" }), // sarà BLOCCATO dall'enforcement
	toolSse("c5", "read_file", { path: ".env" }), // segreto → redatto
	toolSse("c6", "task", {
		description: "conta righe",
		prompt: "conta le righe di greeting.txt con wc -l e riporta il numero",
	}),
	// --- sotto-agente ---
	toolSse("g1", "bash", { command: "wc -l greeting.txt" }),
	textSse("greeting.txt ha 1 riga."),
	// --- ritorno al padre ---
	textSse("Ho reso il saluto formale, verificato il contenuto, e delegato il conteggio righe."),
];

function log(section, msg) {
	process.stdout.write(`\x1b[36m${section}\x1b[0m ${msg}\n`);
}

async function main() {
	const dir = mkdtempSync(join(tmpdir(), "harness-native-demo-"));
	writeFileSync(join(dir, "greeting.txt"), "ciao mondo\n");
	writeFileSync(join(dir, ".env"), "API_KEY=supersegretissimo-1234567890\n");

	let upstreamCalls = 0;
	let upstreamSawApiKey;
	let upstreamSawDeviceToken = false;
	let introspections = 0;

	// 1) Upstream Anthropic finto: verifica la credenziale e serve il copione.
	const upstream = createServer((req, res) => {
		if (req.method === "POST" && req.url === "/v1/messages") {
			upstreamSawApiKey = req.headers["x-api-key"];
			// Il device token non deve MAI raggiungere l'upstream.
			if (JSON.stringify(req.headers).includes(DEVICE_TOKEN)) upstreamSawDeviceToken = true;
			const body = SCRIPT[Math.min(upstreamCalls, SCRIPT.length - 1)];
			upstreamCalls++;
			req.on("data", () => {});
			req.on("end", () => {
				res.writeHead(200, { "content-type": "text/event-stream" });
				res.end(body);
			});
			return;
		}
		res.writeHead(404).end();
	});

	// 2) Control plane finto: introspezione del device token + healthz.
	const controlPlane = createServer((req, res) => {
		if (req.method === "POST" && req.url === "/api/introspect") {
			introspections++;
			let raw = "";
			req.on("data", (c) => {
				raw += c;
			});
			req.on("end", () => {
				const { deviceToken } = JSON.parse(raw || "{}");
				const active = deviceToken === DEVICE_TOKEN;
				res.writeHead(200, { "content-type": "application/json" });
				res.end(JSON.stringify({ active, deviceId: active ? "dev-demo-1" : undefined }));
			});
			return;
		}
		if (req.url === "/healthz") {
			res.writeHead(200, { "content-type": "application/json" });
			res.end(JSON.stringify({ ok: true }));
			return;
		}
		res.writeHead(404).end();
	});

	await listen(upstream);
	await listen(controlPlane);
	const upstreamUrl = `http://127.0.0.1:${upstream.address().port}`;
	const controlPlaneUrl = `http://127.0.0.1:${controlPlane.address().port}`;

	// 3) GATEWAY REALE davanti a upstream+CP finti.
	const gateway = createGatewayServer({
		controlPlaneUrl,
		gatewayToken: GATEWAY_TOKEN,
		providers: { anthropic: { baseUrl: upstreamUrl, apiKey: PROVIDER_API_KEY } },
	});
	await listen(gateway);
	const gatewayUrl = `http://127.0.0.1:${gateway.address().port}`;
	log("[setup]", `upstream=${upstreamUrl}  control-plane=${controlPlaneUrl}  gateway=${gatewayUrl}`);

	// 4) Stato di flotta con policy applicata (sandbox non richiesta in demo).
	const state = new FleetState(
		{ controlPlaneUrl, deviceId: "dev-demo-1", deviceToken: DEVICE_TOKEN, publicKeyPem: "x", publicKeyPems: ["x"] },
		join(dir, "agent.json"),
	);
	state.setPolicyForTesting({
		version: 1,
		killSwitch: false,
		tools: { defaultAction: "allow", allow: [], deny: [] },
		bash: { mode: "denylist", allow: [], deny: ["\\brm\\s+-rf\\b"], allowSubstitution: false },
		paths: { workspaceOnly: true, deny: [], allow: [] },
		redaction: { enabled: true, patterns: [] },
		sandbox: { required: false, markerPath: "/x", markerValue: "" },
	});

	// 5) L'AGENTE REALE, governato, che parla col gateway reale.
	const llm = new LlmClient({ gatewayUrl, deviceToken: DEVICE_TOKEN, promptCache: true });
	const events = [];
	const agent = createEnforcedAgent(state, {
		llm,
		model: "demo",
		cwd: dir,
		stream: true,
		subAgents: true,
		onText: (t) => process.stdout.write(t),
		onEvent: (e) => {
			events.push(e);
			const pad = "  ".repeat(e.depth ?? 0);
			if (e.type === "tool_use") log(`${pad}[tool]`, `${e.name} ${JSON.stringify(e.input)}`);
			else if (e.type === "tool_denied") log(`${pad}[DENY]`, `${e.name}: ${e.reason}`);
			else if (e.type === "tool_result")
				log(`${pad}[result]`, e.isError ? `errore: ${e.content.split("\n")[0]}` : "ok");
		},
	});

	log("[run]", "prompt: «Rendi formale greeting.txt, verifica e delega il conteggio righe»");
	const result = await agent.run("Rendi formale il saluto in greeting.txt, verifica e delega il conteggio delle righe");
	await agent.stop();
	process.stdout.write("\n");

	// ---- Asserzioni (la demo è anche un test) --------------------------------
	log(
		"[check]",
		`verifica degli esiti… (${result.iterations} iterazioni, ${result.usage.inputTokens}+${result.usage.outputTokens} token)`,
	);

	// (a) L'agente ha davvero modificato il file.
	assert.equal(readFileSync(join(dir, "greeting.txt"), "utf8"), "Salve, mondo\n", "il file doveva essere reso formale");

	// (b) Il comando pericoloso è stato BLOCCATO (non eseguito).
	const denied = events.find((e) => e.type === "tool_denied");
	assert.ok(denied, "rm -rf doveva essere bloccato dall'enforcement");

	// (c) Il segreto del .env è stato redatto nel risultato del tool.
	const envResult = events.find((e) => e.type === "tool_result" && e.name === "read_file" && e.id === "c5");
	assert.ok(envResult, "manca il risultato della lettura di .env");
	assert.ok(!envResult.content.includes("supersegretissimo"), "il segreto doveva essere redatto");

	// (d) La delega al sotto-agente ha prodotto un risultato (evento a profondità 1).
	const childActivity = events.find((e) => (e.depth ?? 0) === 1);
	assert.ok(childActivity, "il sotto-agente doveva produrre attività a profondità 1");

	// (e) Le credenziali del provider non lasciano il gateway.
	assert.equal(upstreamSawApiKey, PROVIDER_API_KEY, "l'upstream doveva vedere la API key iniettata dal gateway");
	assert.equal(upstreamSawDeviceToken, false, "il device token NON doveva raggiungere l'upstream");
	assert.ok(introspections > 0, "il gateway doveva introspezionare il device token sul control plane");

	log("[ok]", `tutte le asserzioni superate — ${upstreamCalls} chiamate al modello, ${introspections} introspezioni`);
	log(
		"[ok]",
		`credenziali provider confinate nel gateway; device token introspezionato; enforcement + redaction attivi`,
	);

	gateway.close();
	upstream.close();
	controlPlane.close();
	rmSync(dir, { recursive: true, force: true });
}

function listen(server) {
	return new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
}

main().catch((error) => {
	process.stderr.write(`\x1b[31mDEMO FALLITA:\x1b[0m ${error?.stack ?? error}\n`);
	process.exit(1);
});
