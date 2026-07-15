import { createHash } from "node:crypto";

/**
 * Hash chain per log di audit tamper-evident: ogni riga porta l'hash della
 * precedente, così la modifica o la rimozione di una riga invalida tutta la
 * catena successiva. Non impedisce la manomissione (serve un WORM storage o
 * un anchor esterno per quello), ma la rende sempre rilevabile.
 */

export const CHAIN_GENESIS = "0".repeat(64);

export interface ChainedEntry<T> {
	entry: T;
	prev: string;
	hash: string;
}

export function computeChainHash(prev: string, entry: unknown): string {
	return createHash("sha256").update(prev, "utf8").update(JSON.stringify(entry), "utf8").digest("hex");
}

export function chainEntry<T>(prev: string, entry: T): ChainedEntry<T> {
	return { entry, prev, hash: computeChainHash(prev, entry) };
}

export type ChainVerification =
	| { valid: true; entries: number }
	| { valid: false; entries: number; brokenAtLine: number; reason: string };

/**
 * Verifica una sequenza di righe JSONL incatenate. `genesis` permette di
 * verificare un segmento residuo dopo un pruning: se un prefisso della catena
 * è stato rimosso (già esportato su anchor esterno WORM prima della
 * rimozione), il segmento restante si verifica a partire dall'hash della
 * testa del prefisso rimosso invece che dal genesis assoluto — senza
 * riscrivere né ricalcolare nulla delle righe residue.
 */
export function verifyChain(lines: string[], genesis: string = CHAIN_GENESIS): ChainVerification {
	let prev = genesis;
	for (let i = 0; i < lines.length; i += 1) {
		let parsed: ChainedEntry<unknown>;
		try {
			parsed = JSON.parse(lines[i] as string) as ChainedEntry<unknown>;
		} catch {
			return { valid: false, entries: i, brokenAtLine: i + 1, reason: "riga non decodificabile" };
		}
		if (parsed.prev !== prev) {
			return { valid: false, entries: i, brokenAtLine: i + 1, reason: "aggancio alla riga precedente non valido" };
		}
		if (computeChainHash(parsed.prev, parsed.entry) !== parsed.hash) {
			return { valid: false, entries: i, brokenAtLine: i + 1, reason: "hash della riga non corrispondente" };
		}
		prev = parsed.hash;
	}
	return { valid: true, entries: lines.length };
}
