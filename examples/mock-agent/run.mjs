// Esempio end-to-end SENZA PI: dimostra che il core di enforcement è
// agent-agnostic (`@harness/enforcement-core`). Un "coding agent" finto
// (MockAgent) viene arruolato in un control plane reale, scarica la policy
// firmata e ogni sua azione passa dal motore di enforcement — esattamente come
// farebbe PI, ma qui PI non esiste: è solo un altro adapter.
//
//   npm run example:mock-agent
//
// Flusso: avvia un control plane in-process → arruola un device via HTTP →
// FleetState scarica il bundle firmato → attachEnforcement aggancia il motore
// all'adapter mock → l'agente emette una sequenza di azioni e vediamo le
// decisioni (allow/deny/redaction).

import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlPlaneService, createControlPlaneServer, Store } from "@harness/control-plane";
import { attachEnforcement, FleetState } from "@harness/enforcement-core";

// --- Adapter neutro per un agente finto (non PI) ---------------------------
// Implementa il contratto AgentAdapter: il motore registra i propri handler
// tramite gli on*, il MockAgent li invoca quando "emette" un evento.
class MockAgentAdapter {
	#toolCall;
	#toolResult;
	#shell;
	#sessionStart;
	#sessionEnd;
	onSessionStart(h) {
		this.#sessionStart = h;
	}
	onToolCall(h) {
		this.#toolCall = h;
	}
	onToolResult(h) {
		this.#toolResult = h;
	}
	onShellCommand(h) {
		this.#shell = h;
	}
	onSessionEnd(h) {
		this.#sessionEnd = h;
	}
	// Emettitori usati dall'agente finto.
	startSession(session) {
		return this.#sessionStart?.(session);
	}
	toolCall(call, session) {
		return this.#toolCall(call, session);
	}
	toolResult(result, session) {
		return this.#toolResult(result, session);
	}
	shell(command, session) {
		return this.#shell(command, session);
	}
	endSession() {
		return this.#sessionEnd?.();
	}
}

const line = (s) => process.stdout.write(`${s}\n`);
const ok = (s) => line(`  \x1b[32m✓ allow\x1b[0m  ${s}`);
const no = (s, reason) => line(`  \x1b[31m✗ deny\x1b[0m   ${s}\n            ↳ ${reason}`);

async function main() {
	const dataDir = mkdtempSync(join(tmpdir(), "harness-example-cp-"));
	const clientDir = mkdtempSync(join(tmpdir(), "harness-example-client-"));
	const store = new Store(dataDir);
	const service = new ControlPlaneService(store);

	// Questo esempio gira fuori da un container: disattiviamo la sandbox
	// obbligatoria (in produzione resta attiva ed è il vero confine di sicurezza).
	const admin = service.auth.bootstrapAdminToken("example-admin");
	const identity = service.auth.authenticateAdmin(admin);
	service.org.updateOrg(identity, { policyOverride: { sandbox: { required: false } } });

	const server = createControlPlaneServer(service);
	await new Promise((r) => server.listen(0, r));
	const baseUrl = `http://127.0.0.1:${server.address().port}`;
	line(`\n▶ Control plane in ascolto su ${baseUrl}`);

	// 1) Enrollment reale via HTTP (come farebbe l'agent-client).
	const groupId = service.org.overview(identity).groups[0].groupId;
	const enrollToken = service.devices.createEnrollToken(identity, groupId, 10);
	const enrollResp = await fetch(`${baseUrl}/api/enroll`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ enrollToken, deviceName: "mock-agent-1" }),
	});
	const enrollment = await enrollResp.json();
	line(`▶ Device arruolato: ${enrollment.deviceId}`);

	// 2) FleetState scarica e verifica il bundle firmato dal control plane.
	const config = {
		controlPlaneUrl: baseUrl,
		deviceId: enrollment.deviceId,
		deviceToken: enrollment.deviceToken,
		publicKeyPem: enrollment.publicKeyPem,
		bundleCachePath: join(clientDir, "bundle.jws"),
		syncIntervalSeconds: 3600,
		auditFlushSeconds: 3600,
	};
	const state = new FleetState(config, join(clientDir, "agent.json"));
	await state.initialLoad();
	line(`▶ Policy firmata applicata: config v${state.configVersion} — stato ${state.status}\n`);

	// 3) Aggancia il motore di enforcement all'adapter mock.
	const adapter = new MockAgentAdapter();
	attachEnforcement(adapter, state);

	const session = {
		cwd: "/workspace/progetto",
		hasUI: true,
		ui: { notify: (m) => line(`  [ui] ${m}`), setStatus: () => {} },
	};
	await adapter.startSession(session);

	// 4) L'agente finto emette una sequenza di azioni; il motore le giudica.
	line("▶ Sequenza di azioni dell'agente:\n");

	// Ogni azione porta la decisione ATTESA: così l'esempio non si limita a
	// stampare l'esito, ma lo verifica. Se una regressione del motore invertisse
	// una decisione (es. consentisse `rm -rf /` o smettesse di negare l'eval
	// inline), l'assert fallirebbe e la CI diventerebbe rossa — è la prova del
	// disaccoppiamento, non solo una demo.
	const actions = [
		["toolCall", { toolName: "read", callId: "1", input: { path: "src/app.ts" } }, "read src/app.ts", true],
		[
			"toolCall",
			{ toolName: "read", callId: "2", input: { path: "/etc/passwd" } },
			"read /etc/passwd (fuori workspace)",
			false,
		],
		["toolCall", { toolName: "bash", callId: "3", input: { command: "rm -rf /" } }, "bash: rm -rf /", false],
		["shell", { command: "ls -la | sort", cwd: session.cwd }, "shell utente: ls -la | sort", true],
		[
			"shell",
			{ command: 'node -e \'require("child_process").exec("id")\'', cwd: session.cwd },
			"shell utente: node -e (eval inline)",
			false,
		],
	];
	for (const [kind, payload, label, expectAllow] of actions) {
		const gate = kind === "toolCall" ? await adapter.toolCall(payload, session) : await adapter.shell(payload, session);
		if (gate.allow) ok(label);
		else no(label, gate.reason);
		assert.equal(gate.allow, expectAllow, `decisione di policy inattesa per «${label}»: atteso allow=${expectAllow}`);
	}

	// Redaction: un risultato con un segreto viene riscritto prima di tornare all'agente.
	const rewrite = await adapter.toolResult(
		{
			toolName: "read",
			callId: "4",
			input: { path: ".env" },
			content: [{ type: "text", text: "TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789 fine" }],
			isError: false,
		},
		session,
	);
	line("");
	if (rewrite) line(`  \x1b[33m✎ redaction\x1b[0m  .env → ${JSON.stringify(rewrite.content[0].text)}`);
	assert.ok(rewrite, "un risultato contenente un segreto deve essere riscritto");
	assert.ok(
		!rewrite.content[0].text.includes("ghp_abcdefghijklmnopqrstuvwxyz0123456789"),
		"il token GitHub deve essere redatto dal risultato",
	);

	await adapter.endSession();

	// 5) L'audit prodotto è finito nel control plane.
	const events = await service.auditLog.readDeviceAudit(identity, enrollment.deviceId, 100);
	line(`\n▶ Eventi di audit registrati sul control plane: ${events.length}`);
	line(`  tipi: ${[...new Set(events.map((e) => e.type))].join(", ")}\n`);
	assert.ok(events.length > 0, "le decisioni di policy devono aver prodotto eventi di audit sul control plane");

	server.close();
	rmSync(dataDir, { recursive: true, force: true });
	rmSync(clientDir, { recursive: true, force: true });
	line("✔ Esempio completato: il motore ha applicato la stessa policy a un agente che NON è PI.\n");
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
