import assert from "node:assert/strict";
import { Readable, Writable } from "node:stream";
import { test } from "node:test";
import { type ReplRunner, runRepl } from "../cli-repl.js";

/** Runner che registra gli input ricevuti; opzionalmente lancia su un input dato. */
function recordingRunner(throwOn?: string): { runner: ReplRunner; calls: string[] } {
	const calls: string[] = [];
	const runner: ReplRunner = {
		async run(input: string) {
			calls.push(input);
			if (input === throwOn) throw new Error("boom");
		},
	};
	return { runner, calls };
}

/** Writable che accumula ciò che la REPL scrive. */
function collectingOutput(): { stream: Writable; text: () => string } {
	let buf = "";
	const stream = new Writable({
		write(chunk, _enc, cb) {
			buf += chunk.toString();
			cb();
		},
	});
	return { stream, text: () => buf };
}

test("repl: esegue una riga come turno, poi esce su `exit`", async () => {
	const { runner, calls } = recordingRunner();
	const out = collectingOutput();
	await runRepl(runner, { input: Readable.from(["fai una cosa\n", "exit\n"]), output: out.stream, prompt: "> " });
	assert.deepEqual(calls, ["fai una cosa"]);
});

test("repl: termina pulita alla fine dello stream (EOF) anche senza `exit`", async () => {
	const { runner, calls } = recordingRunner();
	const out = collectingOutput();
	// Nessun `exit`: lo stream finisce e la REPL deve comunque ritornare.
	await runRepl(runner, { input: Readable.from(["primo\n", "secondo\n"]), output: out.stream });
	assert.deepEqual(calls, ["primo", "secondo"]);
});

test("repl: le righe vuote sono ignorate", async () => {
	const { runner, calls } = recordingRunner();
	const out = collectingOutput();
	await runRepl(runner, { input: Readable.from(["\n", "   \n", "vero\n", "quit\n"]), output: out.stream });
	assert.deepEqual(calls, ["vero"]);
});

test("repl: un errore in un turno non interrompe la sessione", async () => {
	const { runner, calls } = recordingRunner("cattivo");
	const out = collectingOutput();
	await runRepl(runner, { input: Readable.from(["cattivo\n", "buono\n", "exit\n"]), output: out.stream });
	// Entrambe le righe sono state processate; l'errore è stato mostrato.
	assert.deepEqual(calls, ["cattivo", "buono"]);
	assert.match(out.text(), /errore: boom/);
});

test("repl: il banner viene scritto all'avvio", async () => {
	const { runner } = recordingRunner();
	const out = collectingOutput();
	await runRepl(runner, { input: Readable.from(["exit\n"]), output: out.stream, banner: "BENVENUTO\n" });
	assert.match(out.text(), /BENVENUTO/);
});
