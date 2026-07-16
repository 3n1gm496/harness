import assert from "node:assert/strict";
import { test } from "node:test";
import { LlmClient } from "../llm.js";
import { assembleFromOpenAiSse, toOpenAiMessages } from "../providers/openai.js";
import type { LlmRequest, Message } from "../types.js";

function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
	const encoder = new TextEncoder();
	let i = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			if (i < chunks.length) controller.enqueue(encoder.encode(chunks[i++]));
			else controller.close();
		},
	});
}
function sseData(obj: object): string {
	return `data: ${JSON.stringify(obj)}\n\n`;
}

const req: LlmRequest = { model: "gpt-x", maxTokens: 128, messages: [{ role: "user", content: "ciao" }] };

test("openai complete: normalizza content + tool_calls + usage", async () => {
	let seenBody: { messages: unknown[]; tools?: unknown[]; max_tokens: number } | undefined;
	let seenAuth: string | undefined;
	const fetchImpl = (async (url, init) => {
		assert.match(String(url), /\/openai\/v1\/chat\/completions$/);
		seenAuth = ((init as RequestInit).headers as Record<string, string>).authorization;
		seenBody = JSON.parse((init as RequestInit).body as string);
		return new Response(
			JSON.stringify({
				model: "gpt-x",
				usage: { prompt_tokens: 11, completion_tokens: 4 },
				choices: [
					{
						finish_reason: "tool_calls",
						message: {
							content: "vediamo",
							tool_calls: [
								{ id: "call_1", type: "function", function: { name: "read_file", arguments: '{"path":"a"}' } },
							],
						},
					},
				],
			}),
			{ status: 200 },
		);
	}) as typeof fetch;

	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "tok", provider: "openai", fetchImpl });
	const res = await client.complete(req);
	assert.equal(seenAuth, "Bearer tok");
	assert.equal(res.usage.inputTokens, 11);
	assert.equal(res.usage.outputTokens, 4);
	assert.deepEqual(res.content[0], { type: "text", text: "vediamo" });
	assert.deepEqual(res.content[1], { type: "tool_use", id: "call_1", name: "read_file", input: { path: "a" } });
	// I tool sono stati tradotti in formato OpenAI (type: function).
	assert.equal(seenBody?.max_tokens, 128);
});

test("openai stream: accumula testo e tool_calls frammentati su più chunk", async () => {
	const chunks = [
		sseData({ choices: [{ delta: { content: "Ciao " } }] }),
		sseData({ choices: [{ delta: { content: "mondo" } }] }),
		sseData({ choices: [{ delta: { tool_calls: [{ index: 0, id: "c1", function: { name: "bash" } }] } }] }),
		sseData({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: '{"comm' } }] } }] }),
		sseData({ choices: [{ delta: { tool_calls: [{ index: 0, function: { arguments: 'and":"ls"}' } }] } }] }),
		sseData({ choices: [{ finish_reason: "tool_calls", delta: {} }] }),
		sseData({ choices: [], usage: { prompt_tokens: 7, completion_tokens: 9 } }),
		"data: [DONE]\n\n",
	];
	const deltas: string[] = [];
	const res = await assembleFromOpenAiSse(streamOf(chunks), (d) => deltas.push(d));
	assert.equal(deltas.join(""), "Ciao mondo");
	assert.equal(res.usage.inputTokens, 7);
	assert.equal(res.usage.outputTokens, 9);
	assert.deepEqual(res.content[0], { type: "text", text: "Ciao mondo" });
	assert.deepEqual(res.content[1], { type: "tool_use", id: "c1", name: "bash", input: { command: "ls" } });
});

test("toOpenAiMessages: assistant con tool_use → tool_calls; tool_result → ruolo tool", () => {
	const history: Message[] = [
		{ role: "user", content: "leggi a" },
		{ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "read_file", input: { path: "a" } }] },
		{ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "contenuto" }] },
		{ role: "assistant", content: [{ type: "text", text: "ecco" }] },
	];
	const out = toOpenAiMessages("SYS", history);
	assert.equal(out[0]?.role, "system");
	assert.equal(out[1]?.role, "user");
	assert.equal(out[2]?.role, "assistant");
	assert.deepEqual((out[2] as { tool_calls: unknown[] }).tool_calls, [
		{ id: "t1", type: "function", function: { name: "read_file", arguments: '{"path":"a"}' } },
	]);
	assert.equal(out[3]?.role, "tool");
	assert.equal((out[3] as { tool_call_id: string }).tool_call_id, "t1");
	assert.equal(out[4]?.role, "assistant");
});

test("openai: HTTP non-2xx → LlmError con status", async () => {
	const fetchImpl = (async () =>
		new Response(JSON.stringify({ error: { message: "modello sconosciuto" } }), { status: 404 })) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "t", provider: "openai", fetchImpl });
	await assert.rejects(() => client.complete(req), /modello sconosciuto/);
});
