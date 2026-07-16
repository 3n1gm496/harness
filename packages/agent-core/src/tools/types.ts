import type { ToolSchema } from "../types.js";

/** Contesto passato a ogni esecuzione di tool. */
export interface ToolContext {
	/** Directory di lavoro della sessione (i path relativi si risolvono qui). */
	cwd: string;
	/** Segnale di annullamento (l'utente interrompe, o timeout globale del turno). */
	signal?: AbortSignal;
}

/** Esito dell'esecuzione di un tool: testo per il modello + flag d'errore. */
export interface ToolExecutionResult {
	content: string;
	isError: boolean;
}

/**
 * Un tool nativo dell'agente. A differenza dell'enforcement (che decide
 * *se* eseguire), questo è l'esecuzione vera e propria, in-process. Il loop
 * dell'agente chiama `execute` solo DOPO che il gate di enforcement ha
 * autorizzato la chiamata.
 */
export interface NativeTool {
	readonly name: string;
	readonly description: string;
	readonly inputSchema: ToolSchema;
	execute(input: Record<string, unknown>, ctx: ToolContext): Promise<ToolExecutionResult>;
}

/** Risultato riuscito. */
export function ok(content: string): ToolExecutionResult {
	return { content, isError: false };
}

/** Risultato d'errore (il modello lo vede e può correggersi). */
export function fail(message: string): ToolExecutionResult {
	return { content: message, isError: true };
}

/** Estrae una stringa obbligatoria dall'input, con errore chiaro se assente. */
export function requireString(input: Record<string, unknown>, key: string): string {
	const value = input[key];
	if (typeof value !== "string" || value === "") {
		throw new ToolInputError(`parametro "${key}" mancante o non stringa`);
	}
	return value;
}

/** Estrae una stringa opzionale (undefined se assente). */
export function optionalString(input: Record<string, unknown>, key: string): string | undefined {
	const value = input[key];
	return typeof value === "string" ? value : undefined;
}

/** Estrae un intero opzionale non negativo. */
export function optionalInt(input: Record<string, unknown>, key: string): number | undefined {
	const value = input[key];
	if (value === undefined || value === null) return undefined;
	const n = typeof value === "number" ? value : Number(value);
	if (!Number.isFinite(n) || n < 0) throw new ToolInputError(`parametro "${key}" non è un intero non negativo`);
	return Math.floor(n);
}

/** Estrae un booleano opzionale. */
export function optionalBool(input: Record<string, unknown>, key: string): boolean | undefined {
	const value = input[key];
	return typeof value === "boolean" ? value : undefined;
}

/** Errore di validazione dell'input di un tool: il loop lo converte in un risultato d'errore. */
export class ToolInputError extends Error {
	constructor(message: string) {
		super(message);
		this.name = "ToolInputError";
	}
}
