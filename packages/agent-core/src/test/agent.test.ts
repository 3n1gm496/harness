import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { FleetState } from "@harness/enforcement-core";
import type { PolicyDocument } from "@harness/shared";
import type { AgentEvent } from "../agent.js";
import { Agent } from "../agent.js";
import { createEnforcedAgent } from "../factory.js";
import { LlmClient } from "../llm.js";

/** Policy di test: tool consentiti, bash in denylist, sandbox non richiesta, redaction attiva. */
function testPolicy(overrides: Partial<PolicyDocument> = {}): PolicyDocument {
	return {
		version: 1,
		killSwitch: false,
		tools: { defaultAction: "allow", allow: [], deny: [] },
		bash: { mode: "denylist", allow: [], deny: ["\\brm\\s+-rf\\b"], allowSubstitution: false },
		paths: { workspaceOnly: true, deny: ["/etc"], allow: [] },
		redaction: { enabled: true, patterns: [] },
		sandbox: { required: false, markerPath: "/run/harness-sandbox", markerValue: "" },
		...overrides,
	};
}

/** FleetState con identità fittizia e policy forzata (nessuna rete). */
function stateWith(policy: PolicyDocument): FleetState {
	const state = new FleetState(
		{
			controlPlaneUrl: "http://cp",
			deviceId: "dev_test",
			deviceToken: "dt",
			publicKeyPem: "pem",
			publicKeyPems: ["pem"],
		},
		join(tmpdir(), "harness-agent-test-config.json"),
	);
	state.setPolicyForTesting(policy);
	return state;
}

/**
 * Costruisce un LlmClient il cui `fetch` restituisce, in ordine, le risposte
 * scriptate (formato wire Anthropic non-streaming). Ogni chiamata consuma la
 * successiva.
 */
function scriptedLlm(responses: object[]): LlmClient {
	let i = 0;
	const fetchImpl = (async () => {
		const body = responses[Math.min(i, responses.length - 1)];
		i++;
		return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
	}) as typeof fetch;
	return new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl });
}

function textResp(text: string, stop = "end_turn"): object {
	return {
		model: "m",
		stop_reason: stop,
		usage: { input_tokens: 3, output_tokens: 3 },
		content: [{ type: "text", text }],
	};
}
function toolResp(name: string, input: object, id = "tu_1"): object {
	return {
		model: "m",
		stop_reason: "tool_use",
		usage: { input_tokens: 3, output_tokens: 3 },
		content: [{ type: "tool_use", id, name, input }],
	};
}

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "harness-agent-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

test("loop: modello chiede read_file, poi risponde — il tool viene eseguito e reiniettato", async () => {
	writeFileSync(join(dir, "hello.txt"), "contenuto-di-prova");
	const llm = scriptedLlm([
		toolResp("read_file", { path: "hello.txt" }),
		textResp("Il file contiene contenuto-di-prova."),
	]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	const result = await agent.run("Cosa c'è in hello.txt?");
	assert.equal(result.iterations, 2);
	assert.match(result.text, /contenuto-di-prova/);
	const toolResult = events.find((e) => e.type === "tool_result");
	assert.ok(toolResult && toolResult.type === "tool_result" && !toolResult.isError);
	assert.match((toolResult as { content: string }).content, /contenuto-di-prova/);
});

test("loop: una tool call negata dalla policy NON viene eseguita e torna errore al modello", async () => {
	// bash `rm -rf` è in denylist → deny. Il file esca deve restare.
	writeFileSync(join(dir, "keep.txt"), "vivo");
	const llm = scriptedLlm([
		toolResp("bash", { command: "rm -rf keep.txt" }),
		textResp("Non posso: comando bloccato dalla policy."),
	]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	const result = await agent.run("Cancella tutto");
	const denied = events.find((e) => e.type === "tool_denied");
	assert.ok(denied, "il tool avrebbe dovuto essere negato");
	assert.equal(readFileSync(join(dir, "keep.txt"), "utf8"), "vivo"); // non eseguito
	assert.match(result.text, /bloccato/);
});

test("loop: kill switch nega ogni tool call", async () => {
	writeFileSync(join(dir, "f.txt"), "x");
	const llm = scriptedLlm([toolResp("read_file", { path: "f.txt" }), textResp("ok")]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy({ killSwitch: true })), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	await agent.run("leggi f.txt");
	const denied = events.find((e) => e.type === "tool_denied");
	assert.ok(denied && denied.type === "tool_denied");
	assert.match((denied as { reason: string }).reason, /kill switch/i);
});

test("loop: la redaction riscrive i segreti nel risultato del tool", async () => {
	writeFileSync(join(dir, ".env"), "API_KEY=supersegretissimo1234");
	const llm = scriptedLlm([toolResp("read_file", { path: ".env" }), textResp("letto")]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	await agent.run("mostra .env");
	const toolResult = events.find((e) => e.type === "tool_result") as { content: string } | undefined;
	assert.ok(toolResult);
	assert.doesNotMatch(toolResult.content, /supersegretissimo1234/);
});

test("loop: tool sconosciuto → errore al modello, non crash", async () => {
	const llm = scriptedLlm([toolResp("inventato", {}), textResp("ok")]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	await agent.run("usa un tool che non esiste");
	const toolResult = events.find((e) => e.type === "tool_result") as { isError: boolean; content: string } | undefined;
	assert.ok(toolResult?.isError);
	assert.match(toolResult.content, /sconosciuto/);
});

test("loop: rispetta maxIterations (anti-loop) se il modello chiede tool all'infinito", async () => {
	writeFileSync(join(dir, "f.txt"), "x");
	// Il fetch scriptato ripete l'ultima risposta: tool_use per sempre.
	const llm = scriptedLlm([toolResp("read_file", { path: "f.txt" })]);
	const agent = createEnforcedAgent(stateWith(testPolicy()), { llm, model: "m", cwd: dir, maxIterations: 4 });
	const result = await agent.run("cicla");
	assert.equal(result.stoppedOnLimit, true);
	assert.equal(result.iterations, 4);
});

test("loop: usage aggregato su più turni", async () => {
	writeFileSync(join(dir, "f.txt"), "x");
	const llm = scriptedLlm([toolResp("read_file", { path: "f.txt" }), textResp("fatto")]);
	const agent = createEnforcedAgent(stateWith(testPolicy()), { llm, model: "m", cwd: dir });
	const result = await agent.run("leggi");
	assert.equal(result.usage.inputTokens, 6); // 3 + 3
	assert.equal(result.usage.outputTokens, 6);
});

test("agent diretto (senza factory) con adapter vuoto: nessun gate, esegue i tool", async () => {
	const { HarnessAgentAdapter } = await import("../adapter.js");
	writeFileSync(join(dir, "f.txt"), "ciao");
	const llm = scriptedLlm([toolResp("read_file", { path: "f.txt" }), textResp("visto")]);
	const agent = new Agent({ llm, model: "m", cwd: dir, adapter: new HarnessAgentAdapter() });
	const result = await agent.run("leggi f.txt");
	assert.match(result.text, /visto/);
});
