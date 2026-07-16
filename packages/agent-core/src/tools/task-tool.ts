import type { ToolSchema } from "../types.js";
import { fail, type NativeTool, ok, optionalString, requireString } from "./types.js";

/**
 * Tool `task`: delega un sotto-compito a un agente FIGLIO. Il figlio ha un
 * contesto isolato (la sua esplorazione non ingombra il contesto del padre) ma
 * condivide lo stesso motore di enforcement — quindi la stessa policy firmata,
 * lo stesso audit, lo stesso fail-closed. Il padre riceve solo il risultato
 * finale del figlio. La profondità è limitata dall'agente (anti-ricorsione).
 *
 * La funzione di spawn è iniettata dall'Agent: il tool di per sé non sa costruire
 * un agente, evita così un import circolare col loop.
 */
export function createTaskTool(spawn: (description: string, prompt: string) => Promise<string>): NativeTool {
	const inputSchema: ToolSchema = {
		type: "object",
		properties: {
			description: { type: "string", description: "Descrizione breve del sotto-compito (3-6 parole)." },
			prompt: {
				type: "string",
				description:
					"Istruzione completa e autosufficiente per l'agente figlio: ha un contesto vuoto, non vede questa conversazione.",
			},
		},
		required: ["prompt"],
		additionalProperties: false,
	};

	return {
		name: "task",
		description:
			"Delega un sotto-compito circoscritto a un agente figlio con contesto isolato (ricerca, refactor locale, indagine). " +
			"Il figlio usa gli stessi tool e la stessa policy; tu ricevi solo il suo risultato finale. Usalo per non ingombrare il contesto principale.",
		inputSchema,
		async execute(input) {
			const prompt = requireString(input, "prompt");
			const description = optionalString(input, "description") ?? "sotto-compito";
			try {
				const result = await spawn(description, prompt);
				return ok(result === "" ? "(l'agente figlio non ha prodotto testo)" : result);
			} catch (error) {
				return fail(`agente figlio fallito: ${error instanceof Error ? error.message : String(error)}`);
			}
		},
	};
}
