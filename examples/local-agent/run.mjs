#!/usr/bin/env node
// Demo del percorso GRATUITO: l'agente contro un backend OpenAI-compatibile
// LOCALE e SENZA CHIAVE (keyless), attraverso il gateway reale.
//
//   Agent (provider "openai") → GATEWAY REALE (OPENAI_NO_AUTH) → backend locale
//
// Qui il "backend locale" è uno stub che parla la Chat Completions API in
// streaming (SSE), esattamente come farebbe Ollama / llama.cpp / LM Studio /
// vLLM sul tuo PC. Sostituendo lo stub con `http://localhost:11434` (Ollama)
// hai lo stesso identico flusso — a costo zero, senza API key.
//
// Dimostra: (1) tool-use reale sotto enforcement su un modello locale;
// (2) il gateway keyless NON invia alcun header di auth all'upstream;
// (3) la governance (device token introspezionato, policy, audit) resta identica.
//
// Esce 0 se tutte le asserzioni passano, 1 altrimenti (gate CI).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEnforcedAgent, LlmClient } from "../../packages/agent-core/dist/index.js";
import { ControlPlaneService, createControlPlaneServer, Store } from "../../packages/control-plane/dist/index.js";
import { FleetState } from "../../packages/enforcement-core/dist/index.js";
import { createGatewayServer } from "../../packages/llm-gateway/dist/index.js";

const sse = (o) => `data: ${JSON.stringify(o)}\n\n`;

// Stub del modello locale OpenAI-compatibile (streaming Chat Completions).
function toolCallStream() {
	return [
		sse({
			choices: [
				{
					delta: {
						role: "assistant",
						tool_calls: [{ index: 0, id: "call_1", type: "function", function: { name: "read_file", arguments: "" } }],
					},
				},
			],
		}),
		sse({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '{"path":"nota.txt"}' } }] } }] }),
		sse({ choices: [{ finish_reason: "tool_calls", delta: {} }] }),
		sse({ choices: [], usage: { prompt_tokens: 12, completion_tokens: 8 } }),
		"data: [DONE]\n\n",
	].join("");
}
function textStream(text) {
	return [
		sse({ choices: [{ delta: { role: "assistant", content: text } }] }),
		sse({ choices: [{ finish_reason: "stop", delta: {} }] }),
		sse({ choices: [], usage: { prompt_tokens: 20, completion_tokens: 10 } }),
		"data: [DONE]\n\n",
	].join("");
}

function log(section, msg) {
	process.stdout.write(`\x1b[36m${section}\x1b[0m ${msg}\n`);
}

async function main() {
	const dir = mkdtempSync(join(tmpdir(), "harness-local-demo-"));
	writeFileSync(join(dir, "nota.txt"), "il numero magico è 42\n");

	let calls = 0;
	let sawAuthHeader = true;
	const backend = createServer((req, res) => {
		if (req.method === "POST" && req.url === "/v1/chat/completions") {
			// Un backend locale keyless NON deve ricevere alcun header di auth.
			sawAuthHeader = req.headers.authorization !== undefined || req.headers["x-api-key"] !== undefined;
			req.on("data", () => {});
			req.on("end", () => {
				res.writeHead(200, { "content-type": "text/event-stream" });
				res.end(calls++ === 0 ? toolCallStream() : textStream("Il numero magico nel file è 42."));
			});
			return;
		}
		res.writeHead(404).end();
	});
	await new Promise((r) => backend.listen(0, "127.0.0.1", r));
	const backendUrl = `http://127.0.0.1:${backend.address().port}`;

	// Control plane reale: enroll device + gateway token.
	const store = new Store(dir);
	const service = new ControlPlaneService(store);
	const adminToken = service.auth.bootstrapAdminToken("local-demo");
	const controlPlane = createControlPlaneServer(service);
	await new Promise((r) => controlPlane.listen(0, "127.0.0.1", r));
	const controlPlaneUrl = `http://127.0.0.1:${controlPlane.address().port}`;
	const identity = service.auth.authenticateAdmin(adminToken);
	const groupId = service.org.overview(identity).groups[0].groupId;
	const enroll = service.devices.enrollDevice(
		service.devices.createEnrollToken(identity, groupId, 10),
		"local-demo-device",
	);
	const gatewayToken = service.auth.createGatewayToken(identity, "local-demo-gw");

	// GATEWAY REALE in modalità KEYLESS verso il backend locale.
	const gateway = createGatewayServer({
		controlPlaneUrl,
		gatewayToken,
		providers: { openai: { baseUrl: backendUrl, noAuth: true } },
		log: () => {},
	});
	await new Promise((r) => gateway.listen(0, "127.0.0.1", r));
	const gatewayUrl = `http://127.0.0.1:${gateway.address().port}`;
	log("[setup]", `backend-locale=${backendUrl} (keyless)  gateway=${gatewayUrl}`);

	const state = new FleetState(
		{
			controlPlaneUrl,
			deviceId: enroll.deviceId,
			deviceToken: enroll.deviceToken,
			publicKeyPem: enroll.publicKeyPem,
			publicKeyPems: [enroll.publicKeyPem],
		},
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

	// Agente col provider "openai" → modello locale, via gateway keyless.
	const llm = new LlmClient({ gatewayUrl, deviceToken: enroll.deviceToken, provider: "openai" });
	const events = [];
	const agent = createEnforcedAgent(state, {
		llm,
		model: "qwen2.5:3b",
		cwd: dir,
		stream: true,
		onText: (t) => process.stdout.write(t),
		onEvent: (e) => {
			events.push(e);
			if (e.type === "tool_use") log("[tool]", `${e.name} ${JSON.stringify(e.input)}`);
			else if (e.type === "tool_result") log("[result]", e.isError ? `errore: ${e.content.split("\n")[0]}` : "ok");
		},
	});

	log("[run]", "prompt: «leggi nota.txt e dimmi il numero magico» (modello LOCALE, zero costo)");
	const result = await agent.run("Leggi nota.txt con read_file e dimmi il numero magico.");
	await agent.stop();
	process.stdout.write("\n");

	log("[check]", "verifica…");
	// (a) Il tool è stato eseguito sotto enforcement e ha letto il file.
	const readEvent = events.find((e) => e.type === "tool_result" && e.name === "read_file");
	assert.ok(readEvent && !readEvent.isError, "read_file avrebbe dovuto essere eseguito");
	// (b) Il modello ha prodotto la risposta finale.
	assert.match(result.text, /42/, "la risposta finale doveva contenere il numero letto");
	// (c) KEYLESS: il backend locale non ha ricevuto alcun header di auth.
	assert.equal(sawAuthHeader, false, "il backend keyless NON doveva ricevere header di auth");

	log("[ok]", "percorso GRATUITO verificato: agente + tool-use + enforcement su modello locale, senza API key.");

	gateway.close();
	controlPlane.close();
	backend.close();
	rmSync(dir, { recursive: true, force: true });
}

main().catch((error) => {
	process.stderr.write(`\x1b[31mDEMO FALLITA:\x1b[0m ${error?.stack ?? error}\n`);
	process.exit(1);
});
