import assert from "node:assert/strict";
import { test } from "node:test";
import { ContextManager } from "../context.js";
import { LlmClient } from "../llm.js";
import type { Message } from "../types.js";

function summarizerLlm(summary: string): LlmClient {
	const fetchImpl = (async () =>
		new Response(JSON.stringify({ content: [{ type: "text", text: summary }], stop_reason: "end_turn" }), {
			status: 200,
		})) as typeof fetch;
	return new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl });
}

test("estimateTokens cresce coi messaggi", () => {
	const ctx = new ContextManager({ budgetTokens: 1_000_000, keepRecentMessages: 4 });
	const before = ctx.estimateTokens();
	ctx.add({ role: "user", content: "x".repeat(400) });
	assert.ok(ctx.estimateTokens() > before);
});

test("maybeCompact: non fa nulla sotto budget", async () => {
	const ctx = new ContextManager({ budgetTokens: 1_000_000, keepRecentMessages: 2 });
	ctx.add({ role: "user", content: "ciao" });
	const removed = await ctx.maybeCompact(summarizerLlm("s"), "m");
	assert.equal(removed, 0);
	assert.equal(ctx.messages.length, 1);
});

test("maybeCompact: sopra budget comprime il prefisso in una sintesi", async () => {
	// keepRecentMessages basso e budget minuscolo per forzare la compaction.
	const ctx = new ContextManager({ budgetTokens: 10, keepRecentMessages: 2 });
	for (let i = 0; i < 8; i++) {
		ctx.add({ role: "user", content: `domanda ${i} ${"y".repeat(50)}` });
		ctx.add({ role: "assistant", content: [{ type: "text", text: `risposta ${i}` }] });
	}
	const lenBefore = ctx.messages.length;
	const removed = await ctx.maybeCompact(summarizerLlm("SINTESI-DEL-CONTESTO"), "m");
	assert.ok(removed > 0, "avrebbe dovuto comprimere");
	assert.ok(ctx.messages.length < lenBefore);
	// Il primo messaggio ora è la sintesi.
	const first = ctx.messages[0] as Message;
	assert.equal(first.role, "user");
	assert.match(first.content as string, /SINTESI-DEL-CONTESTO/);
});

test("maybeCompact: il taglio non spezza una coppia tool_use/tool_result", async () => {
	const ctx = new ContextManager({ budgetTokens: 10, keepRecentMessages: 1 });
	// user, assistant(tool_use), user(tool_result), assistant(text), user(fresh)
	ctx.add({ role: "user", content: "a".repeat(80) });
	ctx.add({ role: "assistant", content: [{ type: "tool_use", id: "t1", name: "read_file", input: {} }] });
	ctx.add({ role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: "risultato" }] });
	ctx.add({ role: "assistant", content: [{ type: "text", text: "ok" }] });
	ctx.add({ role: "user", content: "nuova domanda pulita" });
	await ctx.maybeCompact(summarizerLlm("S"), "m");
	// Nessun messaggio deve contenere un tool_result senza il tool_use precedente.
	for (let i = 0; i < ctx.messages.length; i++) {
		const m = ctx.messages[i] as Message;
		if (typeof m.content === "string") continue;
		const hasToolResult = m.content.some((b) => (b as { type: string }).type === "tool_result");
		if (hasToolResult) {
			const prev = ctx.messages[i - 1] as Message | undefined;
			assert.ok(
				prev &&
					typeof prev.content !== "string" &&
					prev.content.some((b) => (b as { type: string }).type === "tool_use"),
				"un tool_result è rimasto orfano dopo la compaction",
			);
		}
	}
});

test("maybeCompact: se la sintesi fallisce, non perde contesto (0 rimossi)", async () => {
	const failing = new LlmClient({
		gatewayUrl: "http://gw",
		deviceToken: "dt",
		fetchImpl: (async () => new Response("boom", { status: 500 })) as typeof fetch,
	});
	const ctx = new ContextManager({ budgetTokens: 10, keepRecentMessages: 1 });
	for (let i = 0; i < 6; i++) ctx.add({ role: "user", content: "z".repeat(80) });
	const lenBefore = ctx.messages.length;
	const removed = await ctx.maybeCompact(failing, "m");
	assert.equal(removed, 0);
	assert.equal(ctx.messages.length, lenBefore);
});
