import assert from "node:assert/strict";
import { test } from "node:test";
import { ContextManager } from "../context.js";
import { LlmClient } from "../llm.js";

/**
 * LLM finto che instrada per endpoint: `count_tokens` restituisce un conteggio
 * esatto configurabile; `messages` restituisce una sintesi. Conta anche quante
 * volte `count_tokens` è stato chiamato, per verificare l'ottimizzazione della
 * soglia (nessun round-trip quando la stima è lontana dal budget).
 */
function routedLlm(opts: { exactInputTokens?: number; summary?: string }): {
	llm: LlmClient;
	countCalls: () => number;
} {
	let calls = 0;
	const fetchImpl = (async (url) => {
		if (String(url).includes("count_tokens")) {
			calls++;
			return new Response(JSON.stringify({ input_tokens: opts.exactInputTokens ?? 0 }), { status: 200 });
		}
		return new Response(
			JSON.stringify({ content: [{ type: "text", text: opts.summary ?? "SINTESI" }], stop_reason: "end_turn" }),
			{ status: 200 },
		);
	}) as typeof fetch;
	return { llm: new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl }), countCalls: () => calls };
}

/** Riempie il contesto con turni utente "puliti" così esiste sempre un punto di taglio. */
function fill(ctx: ContextManager, count: number, chars: number): void {
	for (let i = 0; i < count; i++) ctx.add({ role: "user", content: `t${i} ${"z".repeat(chars)}` });
}

test("tokenCount: sotto l'80% del budget non chiama count_tokens (usa la stima)", async () => {
	const ctx = new ContextManager({ budgetTokens: 1_000_000, keepRecentMessages: 2 });
	fill(ctx, 3, 40);
	const { llm, countCalls } = routedLlm({ exactInputTokens: 999 });
	const tokens = await ctx.tokenCount(llm, "m");
	assert.equal(countCalls(), 0, "count_tokens non doveva essere chiamato lontano dal budget");
	// La stima usata per il budget include un margine di sicurezza (>= stima grezza).
	assert.ok(tokens >= ctx.estimateTokens());
});

test("tokenCount: vicino al budget usa il conteggio esatto del provider", async () => {
	const ctx = new ContextManager({ budgetTokens: 100, keepRecentMessages: 2 });
	fill(ctx, 6, 80); // stima ben oltre l'80% di 100
	const { llm, countCalls } = routedLlm({ exactInputTokens: 4242 });
	const tokens = await ctx.tokenCount(llm, "m");
	assert.equal(countCalls(), 1);
	assert.equal(tokens, 4242);
});

test("maybeCompact: il conteggio esatto è autoritativo e PREVIENE una compaction che l'euristica farebbe", async () => {
	const ctx = new ContextManager({ budgetTokens: 100, keepRecentMessages: 2 });
	fill(ctx, 8, 80); // stima >> 100 → l'euristica compatterebbe
	const before = ctx.messages.length;
	const { llm } = routedLlm({ exactInputTokens: 50 }); // esatto < budget → niente compaction
	const removed = await ctx.maybeCompact(llm, "m");
	assert.equal(removed, 0);
	assert.equal(ctx.messages.length, before);
});

test("maybeCompact: il conteggio esatto sopra budget innesca la compaction", async () => {
	const ctx = new ContextManager({ budgetTokens: 100, keepRecentMessages: 2 });
	fill(ctx, 8, 80);
	const before = ctx.messages.length;
	const { llm } = routedLlm({ exactInputTokens: 5000, summary: "RIASSUNTO-ESATTO" });
	const removed = await ctx.maybeCompact(llm, "m");
	assert.ok(removed > 0);
	assert.ok(ctx.messages.length < before);
	assert.match(ctx.messages[0]?.content as string, /RIASSUNTO-ESATTO/);
});

test("tokenCount: conteggio esatto 0 (provider senza supporto) ricade sulla stima", async () => {
	const ctx = new ContextManager({ budgetTokens: 100, keepRecentMessages: 2 });
	fill(ctx, 6, 80);
	const { llm } = routedLlm({ exactInputTokens: 0 });
	const tokens = await ctx.tokenCount(llm, "m");
	// Fallback sulla stima con margine di sicurezza.
	assert.equal(tokens, Math.ceil(ctx.estimateTokens() * 1.3));
});
