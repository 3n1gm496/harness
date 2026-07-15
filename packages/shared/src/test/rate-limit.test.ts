import assert from "node:assert/strict";
import { test } from "node:test";
import { SlidingWindowRateLimiter } from "../rate-limit.js";

test("finestra scorrevole: entro la soglia passa, oltre viene rifiutato", () => {
	const rl = new SlidingWindowRateLimiter(60_000);
	const t = 1_000_000_000_000; // istante fisso a inizio finestra
	const base = Math.floor(t / 60_000) * 60_000;
	let allowed = 0;
	for (let i = 0; i < 10; i += 1) if (rl.check("k", 5, base + 100)) allowed += 1;
	assert.equal(allowed, 5, "solo 5 richieste entro la soglia");
});

test("finestra scorrevole: nessun burst 2× al confine della finestra", () => {
	const rl = new SlidingWindowRateLimiter(60_000);
	const w0 = Math.floor(1_000_000_000_000 / 60_000) * 60_000;
	// Riempie la soglia nella finestra corrente, verso la fine (frazione ~0.98).
	let allowedW0 = 0;
	for (let i = 0; i < 5; i += 1) if (rl.check("k", 5, w0 + 59_000)) allowedW0 += 1;
	assert.equal(allowedW0, 5);
	// Subito dopo il confine (nuova finestra, frazione ~0.02): la finestra
	// precedente è ancora quasi tutta "in vista", quindi la stima resta alta e
	// NON si può fare un altro burst pieno. Con una finestra fissa passerebbero
	// altre 5 (burst 2×); qui ne passano molte meno.
	let allowedW1 = 0;
	for (let i = 0; i < 5; i += 1) if (rl.check("k", 5, w0 + 61_000)) allowedW1 += 1;
	assert.ok(allowedW1 < 5, `atteso < 5 subito dopo il confine, ottenuti ${allowedW1}`);
});

test("finestra scorrevole: dopo due finestre piene il conteggio riparte pulito", () => {
	const rl = new SlidingWindowRateLimiter(60_000);
	const w0 = Math.floor(1_000_000_000_000 / 60_000) * 60_000;
	assert.equal(rl.check("k", 1, w0 + 100), true);
	assert.equal(rl.check("k", 1, w0 + 200), false); // seconda nella stessa finestra
	// Due finestre dopo: nessuna sovrapposizione, riparte.
	assert.equal(rl.check("k", 1, w0 + 130_000), true);
});

test("overflow: eviction LRU, non un clear totale (no bypass generando molte chiavi)", () => {
	const rl = new SlidingWindowRateLimiter(60_000, 3); // max 3 chiavi
	const base = Math.floor(1_000_000_000_000 / 60_000) * 60_000;
	// Esaurisce la soglia della chiave "vittima".
	assert.equal(rl.check("victim", 1, base + 10), true);
	assert.equal(rl.check("victim", 1, base + 20), false);
	// Genera altre chiavi (accessi più recenti): "victim" è la meno recente e
	// viene evitta all'overflow, NON tutte le chiavi come farebbe un clear().
	rl.check("a", 10, base + 30);
	rl.check("b", 10, base + 40);
	rl.check("c", 10, base + 50); // ora size > 3 → evict LRU ("victim")
	// "victim" evitta → il suo conteggio riparte (accettata di nuovo). Questo è
	// il costo dell'eviction, ma limitato a UNA chiave vecchia, non a tutte.
	// Le chiavi recenti (a,b,c) restano: non sono state azzerate in massa.
	assert.equal(rl.check("a", 1, base + 60), false, "la chiave recente 'a' conserva il suo conteggio");
});
