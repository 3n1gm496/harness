import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { ControlPlaneService, Store, createControlPlaneServer } from "@harness/control-plane";
import fleetExtension from "../index.js";
import type {
	ExtensionAPI,
	PiExtensionContext,
	ToolCallEvent,
	ToolCallHandlerResult,
	ToolResultEvent,
	ToolResultPatch,
	UserBashEvent,
	UserBashResult,
} from "../pi-types.js";

type Handler = (event: never, ctx: PiExtensionContext) => unknown;

/** Doppio di ExtensionAPI: registra gli handler per invocarli nei test. */
class FakePi implements ExtensionAPI {
	handlers = new Map<string, Handler[]>();
	on(event: string, handler: Handler): void {
		const list = this.handlers.get(event) ?? [];
		list.push(handler);
		this.handlers.set(event, list);
	}
	async emit<T>(event: string, payload: unknown, ctx: PiExtensionContext): Promise<T | undefined> {
		for (const handler of this.handlers.get(event) ?? []) {
			const result = await handler(payload as never, ctx);
			if (result !== undefined) return result as T;
		}
		return undefined;
	}
}

const ctx: PiExtensionContext = {
	cwd: "/workspace/progetto",
	hasUI: false,
	ui: { notify() {}, setStatus() {}, confirm: async () => true },
};

let dataDir: string;
let clientDir: string;
let server: ReturnType<typeof createControlPlaneServer>;
let service: ControlPlaneService;
let adminToken: string;
let deviceId: string;

before(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "harness-fleet-cp-"));
	clientDir = mkdtempSync(join(tmpdir(), "harness-fleet-cli-"));
	const store = new Store(dataDir);
	service = new ControlPlaneService(store);
	adminToken = service.auth.bootstrapAdminToken("test");
	server = createControlPlaneServer(service);
	await new Promise<void>((resolve) => server.listen(0, resolve));
	const baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

	// Enrollment reale via API, come farebbe l'agent-client.
	const identity = service.auth.authenticateAdmin(adminToken);
	const groupId = service.org.overview(identity).groups[0]?.groupId as string;
	const enrollToken = service.devices.createEnrollToken(identity, groupId, 10);
	const enrollResponse = await fetch(`${baseUrl}/api/enroll`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({ enrollToken, deviceName: "test-client" }),
	});
	const enrollment = (await enrollResponse.json()) as Record<string, string>;
	deviceId = enrollment.deviceId as string;

	const agentConfigPath = join(clientDir, "agent.json");
	writeFileSync(
		agentConfigPath,
		JSON.stringify({
			controlPlaneUrl: baseUrl,
			deviceId,
			deviceToken: enrollment.deviceToken,
			publicKeyPem: enrollment.publicKeyPem,
			bundleCachePath: join(clientDir, "bundle.jws"),
			auditFlushSeconds: 3600,
			syncIntervalSeconds: 3600,
		}),
		{ mode: 0o600 },
	);
	process.env.HARNESS_AGENT_CONFIG = agentConfigPath;

	// La maggior parte dei test verifica l'enforcement della policy, non la
	// sandbox: la si disabilita via override org (il default richiede sandbox).
	service.org.updateOrg(identity, { policyOverride: { sandbox: { required: false } } });
});

after(async () => {
	await new Promise((resolve) => server.close(resolve));
	rmSync(dataDir, { recursive: true, force: true });
	rmSync(clientDir, { recursive: true, force: true });
});

test("estensione end-to-end contro un control plane reale", async (t) => {
	const pi = new FakePi();
	await fleetExtension(pi);

	await t.test("tool consentito dalla policy di default", async () => {
		const event: ToolCallEvent = { toolName: "read", toolCallId: "t1", input: { path: "src/app.ts" } };
		const result = await pi.emit<ToolCallHandlerResult>("tool_call", event, ctx);
		assert.equal(result, undefined);
	});

	await t.test("comando bash pericoloso bloccato", async () => {
		const event: ToolCallEvent = { toolName: "bash", toolCallId: "t2", input: { command: "rm -rf /" } };
		const result = await pi.emit<ToolCallHandlerResult>("tool_call", event, ctx);
		assert.equal(result?.block, true);
	});

	await t.test("path fuori workspace bloccato", async () => {
		const event: ToolCallEvent = { toolName: "read", toolCallId: "t3", input: { path: "/etc/passwd" } };
		const result = await pi.emit<ToolCallHandlerResult>("tool_call", event, ctx);
		assert.equal(result?.block, true);
	});

	await t.test("i segreti nei risultati vengono redatti", async () => {
		const event: ToolResultEvent = {
			toolName: "read",
			toolCallId: "t4",
			input: { path: ".env" },
			content: [{ type: "text", text: "API=ghp_abcdefghijklmnopqrstuvwxyz1234 fine" }],
			details: {},
			isError: false,
		};
		const patch = await pi.emit<ToolResultPatch>("tool_result", event, ctx);
		assert.ok(patch?.content);
		assert.ok(!JSON.stringify(patch.content).includes("ghp_abcdefghijklmnopqrstuvwxyz1234"));
	});

	await t.test("user bash segue la stessa policy", async () => {
		const event: UserBashEvent = { command: "sudo rm x", excludeFromContext: false, cwd: ctx.cwd };
		const result = await pi.emit<UserBashResult>("user_bash", event, ctx);
		assert.equal(result?.result.exitCode, 1);
		const allowedEvent: UserBashEvent = { command: "ls -la", excludeFromContext: false, cwd: ctx.cwd };
		const allowed = await pi.emit<UserBashResult>("user_bash", allowedEvent, ctx);
		assert.equal(allowed, undefined);
	});

	await t.test("il kill switch dal control plane blocca al sync successivo", async () => {
		const identity = service.auth.authenticateAdmin(adminToken);
		service.devices.updateDevice(identity, deviceId, { killSwitch: true });

		// Nuova istanza dell'estensione = nuovo sync (simula il refresh periodico).
		const pi2 = new FakePi();
		await fleetExtension(pi2);
		const event: ToolCallEvent = { toolName: "read", toolCallId: "t5", input: { path: "src/app.ts" } };
		const result = await pi2.emit<ToolCallHandlerResult>("tool_call", event, ctx);
		assert.equal(result?.block, true);
		assert.match(result?.reason ?? "", /kill switch/);

		service.devices.updateDevice(identity, deviceId, { killSwitch: false });
	});

	await t.test("l'audit arriva al control plane allo shutdown", async () => {
		await pi.emit("session_shutdown", {}, ctx);
		const identity = service.auth.authenticateAdmin(adminToken);
		const events = await service.auditLog.readDeviceAudit(identity, deviceId, 100);
		assert.ok(events.length > 0);
		const types = new Set(events.map((event) => event.type));
		assert.ok(types.has("policy_decision"));
		assert.ok(types.has("agent_start"));
	});
});

test("la revoca degrada subito a fail-closed, senza attendere la scadenza del bundle", async () => {
	const { FleetState } = await import("@harness/enforcement-core");
	const { loadAgentConfig } = await import("@harness/enforcement-core");
	const config = loadAgentConfig();

	// Primo load: bundle valido (con scadenza lontana) in cache.
	const state = new FleetState(config);
	await state.initialLoad();
	assert.equal(state.status, "ok");
	assert.equal(state.policy.killSwitch, false);

	// Il control plane ora risponde 403 (device revocato): la policy in cache
	// non deve più essere onorata.
	const denyingFetch: typeof fetch = async () => new Response("{}", { status: 403 });
	await state.refresh(denyingFetch);
	assert.equal(state.status, "fail-closed");
	assert.equal(state.policy.killSwitch, true);

	// Anche una nuova istanza non deve ripartire dalla cache locale.
	const restarted = new FleetState(config);
	await restarted.initialLoad(denyingFetch);
	assert.equal(restarted.status, "fail-closed");
	assert.equal(restarted.policy.killSwitch, true);

	// Un errore di rete transitorio invece NON butta via la config valida.
	const flaky = new FleetState(config);
	await flaky.initialLoad(); // ripopola la cache dal server reale
	assert.equal(flaky.status, "ok");
	const offlineFetch: typeof fetch = async () => {
		throw new Error("rete irraggiungibile");
	};
	await flaky.refresh(offlineFetch);
	assert.equal(flaky.status, "cached");
	assert.equal(flaky.policy.killSwitch, false);
});

test("dopo la revoca, la riabilitazione del device recupera dallo stato fail-closed", async () => {
	const { FleetState, loadAgentConfig } = await import("@harness/enforcement-core");
	const config = loadAgentConfig();
	const identity = service.auth.authenticateAdmin(adminToken);

	// Revoca → il client va fail-closed al refresh.
	service.devices.updateDevice(identity, deviceId, { revoked: true });
	const state = new FleetState(config);
	await state.initialLoad();
	assert.equal(state.status, "fail-closed");
	assert.equal(state.policy.killSwitch, true);

	// Riabilitazione → il refresh successivo recupera senza bisogno di re-enroll.
	service.devices.updateDevice(identity, deviceId, { revoked: false });
	await state.refresh();
	assert.equal(state.status, "ok");
	assert.equal(state.policy.killSwitch, false);
});

test("rotazione chiave di firma end-to-end: il client apprende B e sopravvive al ritiro di A", async () => {
	const { FleetState, loadAgentConfig } = await import("@harness/enforcement-core");
	const identity = service.auth.authenticateAdmin(adminToken);

	// Il client parte fidando solo la chiave A (quella dell'enrollment).
	const config = loadAgentConfig();
	config.publicKeyPems = [config.publicKeyPem];
	const state = new FleetState(config, process.env.HARNESS_AGENT_CONFIG);
	await state.initialLoad();
	assert.equal(state.status, "ok");

	// Fase 1 — add: nuova chiave B (non ancora firmante). Il client, al sync,
	// riceve un bundle ancora firmato con A che elenca anche B, e la apprende.
	const keyB = service.signingKeys.addSigningKey(identity);
	await state.refresh();
	assert.equal(state.status, "ok");
	assert.equal((config.publicKeyPems ?? []).length, 2);

	// Fase 2 — promote: B firma. Il client fida già B ⇒ resta ok.
	service.signingKeys.promoteSigningKey(identity, keyB.keyId);
	await state.refresh();
	assert.equal(state.status, "ok");

	// Fase 3 — retire A: i bundle sono firmati con B, il client resta ok.
	const keyAId = service.signingKeys.listSigningKeys(identity).find((k) => !k.active)?.keyId as string;
	service.signingKeys.retireSigningKey(identity, keyAId);
	await state.refresh();
	assert.equal(state.status, "ok");
	assert.equal((config.publicKeyPems ?? []).length, 1);
});

test("sandbox obbligatoria: senza marker tutto è bloccato, col marker si opera", async () => {
	const identity = service.auth.authenticateAdmin(adminToken);
	const markerPath = join(clientDir, "sandbox-marker");
	service.org.updateOrg(identity, {
		policyOverride: { sandbox: { required: true, markerPath, markerValue: "ok" } },
	});
	try {
		// Marker assente ⇒ ogni tool call è bloccata.
		const pi = new FakePi();
		await fleetExtension(pi);
		const blocked = await pi.emit<ToolCallHandlerResult>(
			"tool_call",
			{ toolName: "read", toolCallId: "s1", input: { path: "src/a.ts" } } satisfies ToolCallEvent,
			ctx,
		);
		assert.equal(blocked?.block, true);
		assert.match(blocked?.reason ?? "", /sandbox/);

		// Marker presente col valore atteso ⇒ enforcement normale (tool consentito).
		writeFileSync(markerPath, "ok\n");
		const pi2 = new FakePi();
		await fleetExtension(pi2);
		const allowed = await pi2.emit<ToolCallHandlerResult>(
			"tool_call",
			{ toolName: "read", toolCallId: "s2", input: { path: "src/a.ts" } } satisfies ToolCallEvent,
			ctx,
		);
		assert.equal(allowed, undefined);
	} finally {
		service.org.updateOrg(identity, { policyOverride: { sandbox: { required: false } } });
	}
});

test("anti-rollback: un bundle con configVersion inferiore viene rifiutato", async () => {
	const { FleetState, loadAgentConfig } = await import("@harness/enforcement-core");
	const { readFileSync: readSync } = await import("node:fs");
	const identity = service.auth.authenticateAdmin(adminToken);

	const config = loadAgentConfig();
	config.bundleCachePath = join(clientDir, "rollback-bundle.jws");
	delete config.minConfigVersion;

	// Accetta la versione corrente (vN) e cattura il token firmato.
	const state = new FleetState(config, process.env.HARNESS_AGENT_CONFIG);
	await state.initialLoad();
	assert.equal(state.status, "ok");
	const vOld = state.configVersion as number;
	const oldToken = readSync(state.bundleCachePath, "utf8").trim();

	// Il control plane avanza la versione; il client la accetta (vNew > vN).
	service.org.updateOrg(identity, { name: "org-bumped" });
	await state.refresh();
	const vNew = state.configVersion as number;
	assert.ok(vNew > vOld);

	// Attacco rollback: il server (o la cache) ripropone il vecchio bundle vN,
	// ancora firmato e non scaduto. Deve essere RIFIUTATO, restando su vNew.
	const rollbackFetch: typeof fetch = async () =>
		new Response(JSON.stringify({ token: oldToken }), { status: 200 });
	await state.refresh(rollbackFetch);
	assert.equal(state.configVersion, vNew);
	assert.match(state.lastError, /rollback/);

	// Anche via cache: una nuova istanza con minConfigVersion=vNew e cache=vN
	// non deve onorare il bundle più vecchio.
	writeFileSync(state.bundleCachePath, oldToken);
	const config2 = loadAgentConfig();
	config2.bundleCachePath = state.bundleCachePath;
	config2.minConfigVersion = vNew;
	const offline = new FleetState(config2, process.env.HARNESS_AGENT_CONFIG);
	const offlineFetch: typeof fetch = async () => {
		throw new Error("offline");
	};
	await offline.initialLoad(offlineFetch);
	assert.equal(offline.status, "fail-closed");
});

test("senza config del device l'estensione blocca tutto", async () => {
	const previous = process.env.HARNESS_AGENT_CONFIG;
	process.env.HARNESS_AGENT_CONFIG = join(clientDir, "inesistente.json");
	try {
		const pi = new FakePi();
		await fleetExtension(pi);
		const event: ToolCallEvent = { toolName: "read", toolCallId: "t6", input: { path: "a.ts" } };
		const result = await pi.emit<ToolCallHandlerResult>("tool_call", event, ctx);
		assert.equal(result?.block, true);
		assert.match(result?.reason ?? "", /non arruolato/);
	} finally {
		process.env.HARNESS_AGENT_CONFIG = previous;
	}
});
