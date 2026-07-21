#!/usr/bin/env node
// Smoke test contro un provider LLM REALE, end-to-end sull'intero stack:
//   Agent → LlmClient → GATEWAY REALE → API REALE del provider
// con un control plane reale in-process (enroll device + gateway token).
//
// Consuma una piccola quantità di token/quota (poche risposte cortissime).
//
// Config via ambiente:
//   HARNESS_LIVE_PROVIDER   anthropic | openai        (default anthropic)
//   HARNESS_LIVE_MODEL      id del modello            (default per provider)
//   Credenziale (una):
//     anthropic: ANTHROPIC_AUTH_TOKEN (OAuth) | ANTHROPIC_API_KEY
//     openai:    OPENAI_AUTH_TOKEN (OAuth)    | OPENAI_API_KEY
//   ANTHROPIC_AUTH_BETA     header beta OAuth (opzionale, es. oauth-2025-04-20)
//
// Esce 0 se il giro completa, 1 altrimenti.

import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createEnforcedAgent, LlmClient } from "../packages/agent-core/dist/index.js";
import { ControlPlaneService, createControlPlaneServer, Store } from "../packages/control-plane/dist/index.js";
import { FleetState } from "../packages/enforcement-core/dist/index.js";
import { createGatewayServer } from "../packages/llm-gateway/dist/index.js";

const PROVIDER = process.env.HARNESS_LIVE_PROVIDER === "openai" ? "openai" : "anthropic";
const DEFAULT_MODEL = PROVIDER === "openai" ? "gpt-4o-mini" : "claude-haiku-4-5-20251001";
const MODEL = process.env.HARNESS_LIVE_MODEL ?? DEFAULT_MODEL;
const BASE_URL =
	PROVIDER === "openai"
		? (process.env.OPENAI_BASE_URL ?? "https://api.openai.com")
		: (process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com");

function credential() {
	if (PROVIDER === "openai") {
		if (process.env.OPENAI_AUTH_TOKEN) return { authToken: process.env.OPENAI_AUTH_TOKEN };
		if (process.env.OPENAI_API_KEY) return { apiKey: process.env.OPENAI_API_KEY };
	} else {
		if (process.env.ANTHROPIC_AUTH_TOKEN) {
			const c = { authToken: process.env.ANTHROPIC_AUTH_TOKEN };
			if (process.env.ANTHROPIC_AUTH_BETA) c.betaHeader = process.env.ANTHROPIC_AUTH_BETA;
			return c;
		}
		if (process.env.ANTHROPIC_API_KEY) return { apiKey: process.env.ANTHROPIC_API_KEY };
	}
	return undefined;
}

function log(section, msg) {
	process.stdout.write(`\x1b[36m${section}\x1b[0m ${msg}\n`);
}

async function main() {
	const cred = credential();
	if (!cred) {
		process.stderr.write(
			`Nessuna credenziale per ${PROVIDER}. Imposta ${PROVIDER === "openai" ? "OPENAI_AUTH_TOKEN o OPENAI_API_KEY" : "ANTHROPIC_AUTH_TOKEN o ANTHROPIC_API_KEY"}.\n`,
		);
		process.exit(2);
	}
	const mode = cred.authToken ? "OAuth (Authorization: Bearer)" : "API key";
	log("[setup]", `provider=${PROVIDER} model=${MODEL} auth=${mode} base=${BASE_URL}`);

	const dir = mkdtempSync(join(tmpdir(), "harness-live-provider-"));

	// 1) Control plane reale in-process: enroll device + gateway token.
	const store = new Store(dir);
	const service = new ControlPlaneService(store);
	const adminToken = service.auth.bootstrapAdminToken("live-smoke");
	const controlPlane = createControlPlaneServer(service);
	await new Promise((r) => controlPlane.listen(0, "127.0.0.1", r));
	const controlPlaneUrl = `http://127.0.0.1:${controlPlane.address().port}`;

	const identity = service.auth.authenticateAdmin(adminToken);
	const groupId = service.org.overview(identity).groups[0].groupId;
	const enrollToken = service.devices.createEnrollToken(identity, groupId, 10);
	const enrollment = service.devices.enrollDevice(enrollToken, "live-smoke-device");
	const gatewayToken = service.auth.createGatewayToken(identity, "live-smoke-gw");

	// 2) Gateway REALE verso l'API reale del provider.
	const gateway = createGatewayServer({
		controlPlaneUrl,
		gatewayToken,
		providers: { [PROVIDER]: { baseUrl: BASE_URL, ...cred } },
		log: () => {},
	});
	await new Promise((r) => gateway.listen(0, "127.0.0.1", r));
	const gatewayUrl = `http://127.0.0.1:${gateway.address().port}`;

	// 3) Stato di flotta con policy permissiva (sandbox non richiesta per lo smoke).
	const state = new FleetState(
		{
			controlPlaneUrl,
			deviceId: enrollment.deviceId,
			deviceToken: enrollment.deviceToken,
			publicKeyPem: enrollment.publicKeyPem,
			publicKeyPems: [enrollment.publicKeyPem],
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

	writeFileSync(join(dir, "nota.txt"), "il numero magico è 42\n");
	const llm = new LlmClient({
		gatewayUrl,
		deviceToken: enrollment.deviceToken,
		provider: PROVIDER,
		promptCache: PROVIDER === "anthropic",
	});

	let ok = true;
	try {
		// --- Test A: risposta testuale semplice (streaming reale) ---
		const events = [];
		const agentA = createEnforcedAgent(state, {
			llm,
			model: MODEL,
			cwd: dir,
			maxTokens: 64,
			stream: true,
			onEvent: (e) => events.push(e),
		});
		log("[test A]", "prompt di sola risposta testuale…");
		const a = await agentA.run("Rispondi esattamente con la parola: PRONTO. Nient'altro.");
		await agentA.stop();
		log("[test A]", `risposta="${a.text.trim().slice(0, 60)}" · ${a.usage.inputTokens}+${a.usage.outputTokens} token`);
		assert.ok(a.usage.outputTokens > 0, "il provider non ha restituito token di output");
		assert.ok(a.text.trim().length > 0, "risposta vuota");

		// --- Test B: tool-use reale (il modello deve leggere il file) ---
		const agentB = createEnforcedAgent(state, { llm, model: MODEL, cwd: dir, maxTokens: 256, stream: true });
		log("[test B]", "prompt che richiede un tool (read_file)…");
		const b = await agentB.run("Leggi il file nota.txt con lo strumento read_file e dimmi qual è il numero magico.");
		await agentB.stop();
		log("[test B]", `risposta="${b.text.trim().slice(0, 80)}"`);
		assert.match(b.text, /42/, "il modello non ha riportato il contenuto letto dal tool");

		log("[ok]", "smoke con provider reale superato (streaming + tool-use + auth end-to-end).");
	} catch (error) {
		ok = false;
		process.stderr.write(`\x1b[31m[FALLITO]\x1b[0m ${error?.message ?? error}\n`);
	} finally {
		gateway.close();
		controlPlane.close();
		rmSync(dir, { recursive: true, force: true });
	}
	process.exit(ok ? 0 : 1);
}

main().catch((error) => {
	process.stderr.write(`${error?.stack ?? error}\n`);
	process.exit(1);
});
