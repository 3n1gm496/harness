import type { ToolDefinition } from "../types.js";
import { bashTool } from "./bash-tool.js";
import { editFileTool, listDirTool, readFileTool, writeFileTool } from "./fs-tools.js";
import { globTool, grepTool } from "./search-tools.js";
import type { NativeTool } from "./types.js";

/**
 * Registro dei tool nativi dell'agente. L'insieme è deliberatamente piccolo e
 * ortogonale (lettura, scrittura, modifica, elenco, ricerca, shell): copre il
 * lavoro di un coding-agent senza sovrapposizioni. Ogni tool è governato dalla
 * stessa policy firmata — la policy può negarne alcuni per-flotta (allowlist
 * dei tool) senza che l'agente cambi.
 */
export const DEFAULT_TOOLS: readonly NativeTool[] = Object.freeze([
	readFileTool,
	writeFileTool,
	editFileTool,
	listDirTool,
	grepTool,
	globTool,
	bashTool,
]);

/** Costruisce un registro (Map nome→tool) da una lista di tool. */
export class ToolRegistry {
	private readonly tools = new Map<string, NativeTool>();

	constructor(tools: Iterable<NativeTool> = DEFAULT_TOOLS) {
		for (const tool of tools) this.tools.set(tool.name, tool);
	}

	get(name: string): NativeTool | undefined {
		return this.tools.get(name);
	}

	has(name: string): boolean {
		return this.tools.has(name);
	}

	list(): NativeTool[] {
		return [...this.tools.values()];
	}

	/** Definizioni nel formato che il modello si aspetta (per il campo `tools` della richiesta). */
	definitions(): ToolDefinition[] {
		return this.list().map((tool) => ({
			name: tool.name,
			description: tool.description,
			input_schema: tool.inputSchema,
		}));
	}
}

export type { NativeTool } from "./types.js";
export { bashTool, editFileTool, globTool, grepTool, listDirTool, readFileTool, writeFileTool };
