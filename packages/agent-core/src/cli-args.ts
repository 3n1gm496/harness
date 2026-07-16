/**
 * Parsing degli argomenti della CLI, estratto in un modulo puro (senza effetti
 * collaterali) così da essere testabile senza avviare `main()`.
 */

/** Flag che consumano il token successivo come valore. */
export const VALUE_FLAGS = new Set(["--gateway", "--model", "--cwd", "-p", "--prompt"]);

/** Valore di un flag `--nome valore` (undefined se assente o senza valore). */
export function flagValue(args: string[], flag: string): string | undefined {
	const index = args.indexOf(flag);
	if (index === -1 || index + 1 >= args.length) return undefined;
	return args[index + 1];
}

/** Ricostruisce il prompt dagli argomenti posizionali, saltando i flag e i loro valori. */
export function positionalPrompt(args: string[]): string | undefined {
	const out: string[] = [];
	for (let i = 0; i < args.length; i++) {
		const token = args[i] as string;
		if (token.startsWith("-")) {
			if (VALUE_FLAGS.has(token)) i++; // salta anche il valore del flag
			continue;
		}
		out.push(token);
	}
	const joined = out.join(" ").trim();
	return joined === "" ? undefined : joined;
}

export interface CliInvocation {
	/** true se il sottocomando è `tools`. */
	tools: boolean;
	/** true se è stata richiesta la sessione interattiva (`repl`). */
	forcedRepl: boolean;
	/** Prompt one-shot risolto (da -p/--prompt o dagli argomenti posizionali). */
	prompt: string | undefined;
	/** Argomenti senza il sottocomando iniziale (per estrarne i flag). */
	rest: string[];
}

/**
 * Interpreta l'invocazione: riconosce i sottocomandi `tools`/`run`/`repl`;
 * senza sottocomando gli argomenti posizionali sono il prompt (retro-compat).
 */
export function parseInvocation(args: string[]): CliInvocation {
	const sub = args[0];
	if (sub === "tools") return { tools: true, forcedRepl: false, prompt: undefined, rest: [] };
	const forcedRepl = sub === "repl";
	const rest = sub === "run" || sub === "repl" ? args.slice(1) : args;
	const prompt = flagValue(rest, "-p") ?? flagValue(rest, "--prompt") ?? positionalPrompt(rest);
	return { tools: false, forcedRepl, prompt, rest };
}
