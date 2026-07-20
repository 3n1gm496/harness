import { createInterface } from "node:readline";

/**
 * Ciclo REPL estratto dalla CLI e reso pilotabile (stream iniettabili) così da
 * essere testabile senza un TTY. Legge un compito per riga; `exit`/`quit`
 * terminano; la fine dello stream di input (EOF) termina anch'essa in modo
 * pulito. Un errore di un turno non interrompe la sessione: viene mostrato e si
 * prosegue.
 */

export interface ReplRunner {
	run(input: string): Promise<unknown>;
}

export interface ReplOptions {
	input?: NodeJS.ReadableStream;
	output?: NodeJS.WritableStream;
	prompt?: string;
	/** Reso iniettabile per i test; default: banner colorato. */
	banner?: string;
}

export async function runRepl(runner: ReplRunner, options: ReplOptions = {}): Promise<void> {
	const input = options.input ?? process.stdin;
	const output = options.output ?? process.stdout;
	const prompt = options.prompt ?? "› ";
	if (options.banner) output.write(options.banner);

	// L'iteratore asincrono di readline consegna OGNI riga e termina all'EOF
	// dello stream. È corretto sia in interattivo sia con input pipe: `rl.question`
	// in un loop perderebbe invece le righe già bufferizzate da uno stream veloce.
	const rl = createInterface({ input, output });
	try {
		output.write(prompt);
		for await (const line of rl) {
			const trimmed = line.trim();
			if (trimmed === "exit" || trimmed === "quit") break;
			if (trimmed !== "") {
				try {
					await runner.run(trimmed);
					output.write("\n");
				} catch (error) {
					output.write(`errore: ${error instanceof Error ? error.message : String(error)}\n`);
				}
			}
			output.write(prompt);
		}
	} finally {
		rl.close();
	}
}
