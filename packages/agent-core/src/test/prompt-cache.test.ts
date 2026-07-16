import assert from "node:assert/strict";
import { test } from "node:test";
import { LlmClient } from "../llm.js";
import type { LlmRequest } from "../types.js";

const req: LlmRequest = {
	model: "m",
	maxTokens: 64,
	system: "sei un agente",
	messages: [{ role: "user", content: "ciao" }],
	tools: [
		{ name: "a", description: "d", input_schema: { type: "object", properties: {} } },
		{ name: "b", description: "d", input_schema: { type: "object", properties: {} } },
	],
};

/** Cattura headers e body inviati a fetch. */
function captureClient(opts: { provider?: "anthropic" | "openai"; promptCache?: boolean }) {
	let headers: Record<string, string> = {};
	let body: Record<string, unknown> = {};
	const fetchImpl = (async (_url, init) => {
		headers = (init as RequestInit).headers as Record<string, string>;
		body = JSON.parse((init as RequestInit).body as string);
		return new Response(JSON.stringify({ content: [], stop_reason: "end_turn" }), { status: 200 });
	}) as typeof fetch;
	const client = new LlmClient({
		gatewayUrl: "http://gw",
		deviceToken: "dt",
		fetchImpl,
		...(opts.provider ? { provider: opts.provider } : {}),
		...(opts.promptCache ? { promptCache: true } : {}),
	});
	return { client, headers: () => headers, body: () => body };
}

test("promptCache off: nessun cache_control, nessun header beta", async () => {
	const cap = captureClient({});
	await cap.client.complete(req);
	assert.equal(cap.headers()["anthropic-beta"], undefined);
	assert.equal(typeof cap.body().system, "string");
});

test("promptCache on (anthropic): system e ultimo tool marcati, header beta presente", async () => {
	const cap = captureClient({ promptCache: true });
	await cap.client.complete(req);
	assert.match(cap.headers()["anthropic-beta"] ?? "", /prompt-caching/);
	// system diventa un array di blocchi con cache_control sull'ultimo.
	const system = cap.body().system as Array<{ type: string; cache_control?: unknown }>;
	assert.ok(Array.isArray(system));
	assert.deepEqual(system[0]?.cache_control, { type: "ephemeral" });
	// solo l'ultimo tool è marcato (il prefisso stabile termina lì).
	const tools = cap.body().tools as Array<{ cache_control?: unknown }>;
	assert.equal(tools[0]?.cache_control, undefined);
	assert.deepEqual(tools[1]?.cache_control, { type: "ephemeral" });
});

test("promptCache on (openai): l'hint è ignorato dal provider (nessun cache_control)", async () => {
	const cap = captureClient({ provider: "openai", promptCache: true });
	await cap.client.complete(req);
	// OpenAI mette in cache automaticamente: nessun marker nel body.
	assert.equal(JSON.stringify(cap.body()).includes("cache_control"), false);
});

test("promptCache unisce il beta dell'utente con quello del caching", async () => {
	let seen = "";
	const fetchImpl = (async (_u, init) => {
		seen = ((init as RequestInit).headers as Record<string, string>)["anthropic-beta"] ?? "";
		return new Response(JSON.stringify({ content: [] }), { status: 200 });
	}) as typeof fetch;
	const client = new LlmClient({
		gatewayUrl: "http://gw",
		deviceToken: "dt",
		fetchImpl,
		anthropicBeta: "token-efficient-tools-2025-02-19",
		promptCache: true,
	});
	await client.complete(req);
	assert.match(seen, /token-efficient-tools-2025-02-19/);
	assert.match(seen, /prompt-caching/);
});
