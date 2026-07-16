import assert from "node:assert/strict";
import { test } from "node:test";
import { assembleFromSse, LlmClient, LlmError } from "../llm.js";
import type { LlmRequest } from "../types.js";

/** Costruisce un ReadableStream web da una lista di chunk stringa (UTF-8). */
function streamOf(chunks: string[]): ReadableStream<Uint8Array> {
	const encoder = new TextEncoder();
	let i = 0;
	return new ReadableStream<Uint8Array>({
		pull(controller) {
			if (i < chunks.length) {
				controller.enqueue(encoder.encode(chunks[i++]));
			} else {
				controller.close();
			}
		},
	});
}

function sse(events: object[]): string[] {
	return events.map((e) => `event: ${(e as { type: string }).type}\ndata: ${JSON.stringify(e)}\n\n`);
}

const baseRequest: LlmRequest = {
	model: "claude-test",
	maxTokens: 256,
	messages: [{ role: "user", content: "ciao" }],
};

test("complete: normalizza testo + tool_use + usage + stop_reason", async () => {
	const fetchImpl = (async (_url, init) => {
		const body = JSON.parse((init as RequestInit).body as string);
		assert.equal(body.stream, false);
		assert.equal(body.model, "claude-test");
		return new Response(
			JSON.stringify({
				model: "claude-test",
				stop_reason: "tool_use",
				usage: { input_tokens: 12, output_tokens: 7 },
				content: [
					{ type: "text", text: "penso..." },
					{ type: "tool_use", id: "tu_1", name: "read_file", input: { path: "a.txt" } },
				],
			}),
			{ status: 200, headers: { "content-type": "application/json" } },
		);
	}) as typeof fetch;

	const client = new LlmClient({ gatewayUrl: "http://gw:8081/", deviceToken: "dt", fetchImpl });
	const res = await client.complete(baseRequest);
	assert.equal(res.stopReason, "tool_use");
	assert.equal(res.usage.inputTokens, 12);
	assert.equal(res.usage.outputTokens, 7);
	assert.equal(res.content.length, 2);
	assert.deepEqual(res.content[0], { type: "text", text: "penso..." });
	assert.deepEqual(res.content[1], { type: "tool_use", id: "tu_1", name: "read_file", input: { path: "a.txt" } });
});

test("complete: endpoint e auth header sono corretti (x-api-key = device token)", async () => {
	let seenUrl = "";
	let seenHeaders: Record<string, string> = {};
	const fetchImpl = (async (url, init) => {
		seenUrl = String(url);
		seenHeaders = (init as RequestInit).headers as Record<string, string>;
		return new Response(JSON.stringify({ content: [], stop_reason: "end_turn" }), { status: 200 });
	}) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw:8081", deviceToken: "secret-token", fetchImpl });
	await client.complete(baseRequest);
	assert.equal(seenUrl, "http://gw:8081/anthropic/v1/messages");
	assert.equal(seenHeaders["x-api-key"], "secret-token");
	assert.equal(seenHeaders["anthropic-version"], "2023-06-01");
});

test("complete: HTTP non-2xx diventa LlmError con status e messaggio", async () => {
	const fetchImpl = (async () =>
		new Response(JSON.stringify({ error: { message: "rate limit superato" } }), { status: 429 })) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl });
	await assert.rejects(
		() => client.complete(baseRequest),
		(err: unknown) => {
			assert.ok(err instanceof LlmError);
			assert.equal(err.status, 429);
			assert.match(err.message, /rate limit superato/);
			return true;
		},
	);
});

test("stream: ricostruisce testo e tool_use da eventi SSE, con delta di testo", async () => {
	const events = [
		{ type: "message_start", message: { model: "claude-test", usage: { input_tokens: 5, output_tokens: 0 } } },
		{ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
		{ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "Ciao " } },
		{ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "mondo" } },
		{ type: "content_block_stop", index: 0 },
		{ type: "content_block_start", index: 1, content_block: { type: "tool_use", id: "tu_9", name: "bash" } },
		{ type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: '{"comm' } },
		{ type: "content_block_delta", index: 1, delta: { type: "input_json_delta", partial_json: 'and":"ls"}' } },
		{ type: "content_block_stop", index: 1 },
		{ type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 15 } },
		{ type: "message_stop" },
	];
	const deltas: string[] = [];
	const res = await assembleFromSse(streamOf(sse(events)), (d) => deltas.push(d));
	assert.equal(deltas.join(""), "Ciao mondo");
	assert.equal(res.stopReason, "tool_use");
	assert.equal(res.usage.outputTokens, 15);
	assert.equal(res.content.length, 2);
	assert.deepEqual(res.content[0], { type: "text", text: "Ciao mondo" });
	assert.deepEqual(res.content[1], { type: "tool_use", id: "tu_9", name: "bash", input: { command: "ls" } });
});

test("stream: robusto a un evento spezzato su più chunk di rete", async () => {
	const full = sse([
		{ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } },
		{ type: "content_block_delta", index: 0, delta: { type: "text_delta", text: "OK" } },
		{ type: "content_block_stop", index: 0 },
		{ type: "message_delta", delta: { stop_reason: "end_turn" } },
	]).join("");
	// Spezza il testo completo in chunk piccoli e arbitrari.
	const chunks: string[] = [];
	for (let i = 0; i < full.length; i += 7) chunks.push(full.slice(i, i + 7));
	const res = await assembleFromSse(streamOf(chunks));
	assert.equal(res.stopReason, "end_turn");
	assert.deepEqual(res.content[0], { type: "text", text: "OK" });
});

test("stream: un evento error nel flusso diventa LlmError", async () => {
	const chunks = sse([{ type: "error", error: { type: "overloaded_error", message: "sovraccarico" } }]);
	await assert.rejects(() => assembleFromSse(streamOf(chunks)), /sovraccarico/);
});

test("stream: input_json_delta vuoto produce input oggetto vuoto (nessun crash)", async () => {
	const chunks = sse([
		{ type: "content_block_start", index: 0, content_block: { type: "tool_use", id: "t", name: "list_dir" } },
		{ type: "content_block_stop", index: 0 },
		{ type: "message_delta", delta: { stop_reason: "tool_use" } },
	]);
	const res = await assembleFromSse(streamOf(chunks));
	assert.deepEqual(res.content[0], { type: "tool_use", id: "t", name: "list_dir", input: {} });
});
