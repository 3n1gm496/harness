import assert from "node:assert/strict";
import { test } from "node:test";
import { CHAIN_GENESIS, chainEntry, computeChainHash, verifyChain } from "../audit-chain.js";

function buildChain(entries: unknown[]): string[] {
	const lines: string[] = [];
	let prev = CHAIN_GENESIS;
	for (const entry of entries) {
		const chained = chainEntry(prev, entry);
		lines.push(JSON.stringify(chained));
		prev = chained.hash;
	}
	return lines;
}

test("una catena costruita correttamente è valida", () => {
	const lines = buildChain([{ a: 1 }, { b: 2 }, { c: 3 }]);
	const result = verifyChain(lines);
	assert.equal(result.valid, true);
	if (result.valid) assert.equal(result.entries, 3);
});

test("una catena vuota è valida", () => {
	assert.deepEqual(verifyChain([]), { valid: true, entries: 0 });
});

test("la prima riga deve agganciarsi al genesis", () => {
	const forged = JSON.stringify({ entry: { a: 1 }, prev: "ff".repeat(32), hash: computeChainHash("ff".repeat(32), { a: 1 }) });
	const result = verifyChain([forged]);
	assert.equal(result.valid, false);
	if (!result.valid) assert.equal(result.brokenAtLine, 1);
});

test("modificare il contenuto di una riga rompe la catena su quella riga", () => {
	const lines = buildChain([{ a: 1 }, { b: 2 }, { c: 3 }]);
	const tampered = JSON.parse(lines[1] as string) as { entry: { b: number }; prev: string; hash: string };
	tampered.entry.b = 999; // hash non ricalcolato
	lines[1] = JSON.stringify(tampered);
	const result = verifyChain(lines);
	assert.equal(result.valid, false);
	if (!result.valid) {
		assert.equal(result.brokenAtLine, 2);
		assert.equal(result.entries, 1); // la riga 1 era ancora valida
	}
});

test("rimuovere una riga in mezzo rompe l'aggancio della successiva", () => {
	const lines = buildChain([{ a: 1 }, { b: 2 }, { c: 3 }]);
	lines.splice(1, 1); // tolgo la riga 2
	const result = verifyChain(lines);
	assert.equal(result.valid, false);
	if (!result.valid) assert.equal(result.brokenAtLine, 2);
});

test("riordinare due righe rompe la catena", () => {
	const lines = buildChain([{ a: 1 }, { b: 2 }, { c: 3 }]);
	[lines[1], lines[2]] = [lines[2] as string, lines[1] as string];
	const result = verifyChain(lines);
	assert.equal(result.valid, false);
});

test("una riga non decodificabile è segnalata", () => {
	const lines = buildChain([{ a: 1 }]);
	lines.push("{ questo non è json valido");
	const result = verifyChain(lines);
	assert.equal(result.valid, false);
	if (!result.valid) assert.equal(result.brokenAtLine, 2);
});
