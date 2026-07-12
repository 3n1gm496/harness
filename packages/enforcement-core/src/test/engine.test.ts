import assert from "node:assert/strict";
import { test } from "node:test";
import { defaultPolicy } from "@harness/shared";
import type {
	AgentAdapter,
	Gate,
	HostSession,
	ResultRewrite,
	ShellCommand,
	ToolCall,
	ToolResult,
} from "../adapter.js";
import { attachEnforcement } from "../engine.js";
import { FleetState, type AgentConfig } from "../fleet-state.js";

/**
 * Adapter mock che NON è PI: un host immaginario che espone gli stessi eventi
 * neutri. Dimostra che il motore è agent-agnostic — se funziona qui, PI è solo
 * uno degli adapter possibili.
 */
class MockAdapter implements AgentAdapter {
	private toolCall?: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>;
	private toolResult?: (result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>;
	private shell?: (command: ShellCommand, session: HostSession) => Gate | Promise<Gate>;
	private sessionStart?: (session: HostSession) => void | Promise<void>;
	private sessionEnd?: () => void | Promise<void>;

	onSessionStart(handler: (session: HostSession) => void | Promise<void>): void {
		this.sessionStart = handler;
	}
	onToolCall(handler: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>): void {
		this.toolCall = handler;
	}
	onToolResult(handler: (result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>): void {
		this.toolResult = handler;
	}
	onShellCommand(handler: (command: ShellCommand, session: HostSession) => Gate | Promise<Gate>): void {
		this.shell = handler;
	}
	onSessionEnd(handler: () => void | Promise<void>): void {
		this.sessionEnd = handler;
	}

	// Emettitori usati dai test per simulare l'agente ospite.
	emitSessionStart(session: HostSession): Promise<void> | void {
		return this.sessionStart?.(session);
	}
	emitToolCall(call: ToolCall, session: HostSession): Promise<Gate> {
		return Promise.resolve(this.toolCall?.(call, session) ?? { allow: true });
	}
	emitToolResult(result: ToolResult, session: HostSession): Promise<ResultRewrite> {
		return Promise.resolve(this.toolResult?.(result, session) ?? undefined);
	}
	emitShell(command: ShellCommand, session: HostSession): Promise<Gate> {
		return Promise.resolve(this.shell?.(command, session) ?? { allow: true });
	}
}

const session: HostSession = { cwd: "/workspace/progetto", hasUI: false };

/** Stato di flotta con una policy fissa iniettata, senza rete né control plane. */
function stateWithPolicy(policyPatch: Partial<ReturnType<typeof defaultPolicy>> = {}): FleetState {
	const config: AgentConfig = {
		controlPlaneUrl: "http://localhost:0",
		deviceId: "dev-test",
		deviceToken: "tok",
		publicKeyPem: "pem",
	};
	const state = new FleetState(config, "/dev/null");
	state.setPolicyForTesting({
		...defaultPolicy(),
		sandbox: { ...defaultPolicy().sandbox, required: false },
		...policyPatch,
	});
	return state;
}

test("il motore funziona su un adapter non-PI: tool consentito passa", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const gate = await adapter.emitToolCall(
		{ toolName: "read", callId: "t1", input: { path: "src/app.ts" } },
		session,
	);
	assert.deepEqual(gate, { allow: true });
});

test("il motore nega un comando pericoloso attraverso il contratto neutro", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const gate = await adapter.emitToolCall(
		{ toolName: "bash", callId: "t2", input: { command: "rm -rf /" } },
		session,
	);
	assert.equal(gate.allow, false);
	assert.match(gate.allow === false ? gate.reason : "", /policy aziendale/);
});

test("path fuori workspace negato", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const gate = await adapter.emitToolCall(
		{ toolName: "read", callId: "t3", input: { path: "/etc/passwd" } },
		session,
	);
	assert.equal(gate.allow, false);
});

test("redaction dei segreti nel risultato via ResultRewrite", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const rewrite = await adapter.emitToolResult(
		{
			toolName: "read",
			callId: "t4",
			input: { path: ".env" },
			content: [{ type: "text", text: "API=ghp_abcdefghijklmnopqrstuvwxyz1234 fine" }],
			isError: false,
		},
		session,
	);
	assert.ok(rewrite?.content);
	assert.ok(!JSON.stringify(rewrite.content).includes("ghp_abcdefghijklmnopqrstuvwxyz1234"));
});

test("comando shell utente segue la policy bash", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const denied = await adapter.emitShell({ command: "sudo rm x", cwd: session.cwd }, session);
	assert.equal(denied.allow, false);
	const allowed = await adapter.emitShell({ command: "ls -la", cwd: session.cwd }, session);
	assert.equal(allowed.allow, true);
});

test("kill switch nega ogni comando shell", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy({ killSwitch: true }));
	const gate = await adapter.emitShell({ command: "ls -la", cwd: session.cwd }, session);
	assert.equal(gate.allow, false);
	assert.match(gate.allow === false ? gate.reason : "", /kill switch/);
});

test("sandbox obbligatoria assente ⇒ ogni tool call bloccata", async () => {
	const adapter = new MockAdapter();
	const state = stateWithPolicy();
	state.setPolicyForTesting({
		...defaultPolicy(),
		sandbox: { required: true, markerPath: "/non/esiste/marker", markerValue: "x" },
	});
	attachEnforcement(adapter, state);
	const gate = await adapter.emitToolCall(
		{ toolName: "read", callId: "t5", input: { path: "src/a.ts" } },
		session,
	);
	assert.equal(gate.allow, false);
	assert.match(gate.allow === false ? gate.reason : "", /sandbox/);
});

test("session start aggancia la UI di stato dell'host", async () => {
	const adapter = new MockAdapter();
	attachEnforcement(adapter, stateWithPolicy());
	const statuses: Array<{ key: string; text: string | undefined }> = [];
	await adapter.emitSessionStart({
		cwd: session.cwd,
		hasUI: true,
		ui: {
			notify() {},
			setStatus(key, text) {
				statuses.push({ key, text });
			},
		},
	});
	assert.ok(statuses.some((s) => s.key === "harness-fleet"));
});
