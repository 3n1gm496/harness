import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { FleetState } from "@harness/enforcement-core";
import type { PolicyDocument } from "@harness/shared";
import type { AgentEvent } from "../agent.js";
import { createEnforcedAgent } from "../factory.js";
import { LlmClient } from "../llm.js";

function testPolicy(overrides: Partial<PolicyDocument> = {}): PolicyDocument {
	return {
		version: 1,
		killSwitch: false,
		tools: { defaultAction: "allow", allow: [], deny: [] },
		bash: { mode: "denylist", allow: [], deny: [], allowSubstitution: false },
		paths: { workspaceOnly: true, deny: [], allow: [] },
		redaction: { enabled: true, patterns: [] },
		sandbox: { required: false, markerPath: "/x", markerValue: "" },
		...overrides,
	};
}
function stateWith(policy: PolicyDocument): FleetState {
	const state = new FleetState(
		{ controlPlaneUrl: "http://cp", deviceId: "d", deviceToken: "dt", publicKeyPem: "p", publicKeyPems: ["p"] },
		join(tmpdir(), "harness-sub-config.json"),
	);
	state.setPolicyForTesting(policy);
	return state;
}
function scriptedLlm(responses: object[]): LlmClient {
	let i = 0;
	const fetchImpl = (async () => {
		const body = responses[Math.min(i, responses.length - 1)];
		i++;
		return new Response(JSON.stringify(body), { status: 200 });
	}) as typeof fetch;
	return new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl });
}
function textResp(text: string): object {
	return {
		model: "m",
		stop_reason: "end_turn",
		usage: { input_tokens: 2, output_tokens: 2 },
		content: [{ type: "text", text }],
	};
}
function toolResp(name: string, input: object, id = "tu"): object {
	return {
		model: "m",
		stop_reason: "tool_use",
		usage: { input_tokens: 2, output_tokens: 2 },
		content: [{ type: "tool_use", id, name, input }],
	};
}

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "harness-sub-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

test("sub-agente: il padre delega via `task`, il figlio esegue e il padre riceve il risultato", async () => {
	writeFileSync(join(dir, "f.txt"), "IL-CONTENUTO");
	const llm = scriptedLlm([
		toolResp("task", { description: "leggi f", prompt: "leggi f.txt e riporta il contenuto" }, "t1"), // padre
		toolResp("read_file", { path: "f.txt" }, "t2"), // figlio
		textResp("Il contenuto è IL-CONTENUTO."), // figlio conclude
		textResp("Delega completata: IL-CONTENUTO."), // padre conclude
	]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		subAgents: true,
		onEvent: (e) => events.push(e),
	});
	const result = await agent.run("Delega la lettura di f.txt");
	assert.match(result.text, /Delega completata/);
	// Il figlio ha davvero eseguito read_file (evento presente e non in errore).
	const readEvent = events.find((e) => e.type === "tool_result" && e.name === "read_file");
	assert.ok(readEvent && readEvent.type === "tool_result" && !readEvent.isError);
	// L'evento del figlio è marcato con la profondità 1; quello del padre (task) con 0/assente.
	assert.equal((readEvent as { depth?: number }).depth, 1);
	const taskUse = events.find((e) => e.type === "tool_use" && e.name === "task") as { depth?: number } | undefined;
	assert.equal(taskUse?.depth ?? 0, 0);
	// Il tool `task` del padre ha restituito il risultato del figlio.
	const taskResult = events.find((e) => e.type === "tool_result" && e.name === "task") as
		| { content: string }
		| undefined;
	assert.ok(taskResult);
	assert.match(taskResult.content, /IL-CONTENUTO/);
	// A4: il testo del figlio è emesso UNA sola volta (nessun doppio evento).
	const childTexts = events.filter((e) => e.type === "assistant_text" && (e.depth ?? 0) === 1);
	assert.equal(childTexts.length, 1);
});

test("sub-agente: oltre la profondità massima il tool `task` non è disponibile", async () => {
	// maxDepth 0 → nessun tool task registrato: una richiesta `task` è tool sconosciuto.
	const llm = scriptedLlm([toolResp("task", { prompt: "x" }), textResp("ok")]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		subAgents: true,
		maxDepth: 0,
		onEvent: (e) => events.push(e),
	});
	await agent.run("prova a delegare");
	const taskResult = events.find((e) => e.type === "tool_result" && e.name === "task") as
		| { isError: boolean; content: string }
		| undefined;
	assert.ok(taskResult?.isError);
	assert.match(taskResult.content, /sconosciuto/);
});

test("sub-agente: senza subAgents il tool `task` non esiste", async () => {
	const llm = scriptedLlm([toolResp("task", { prompt: "x" }), textResp("ok")]);
	const events: AgentEvent[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		onEvent: (e) => events.push(e),
	});
	await agent.run("prova a delegare");
	const taskResult = events.find((e) => e.type === "tool_result" && e.name === "task") as
		| { isError: boolean }
		| undefined;
	assert.ok(taskResult?.isError);
});
