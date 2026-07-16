import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import {
	fail,
	type NativeTool,
	ok,
	optionalBool,
	optionalInt,
	requireString,
	type ToolContext,
	type ToolExecutionResult,
} from "./types.js";

/**
 * Tool di filesystem nativi. Risolvono i path relativi contro la cwd della
 * sessione; NON re-applicano la policy dei percorsi (è il motore di enforcement
 * a decidere *prima* dell'esecuzione se un path è consentito — un doppio
 * controllo qui contraddirebbe gli `allow` espliciti fuori workspace).
 */

/** Tetto di byte letti da un file: protegge la finestra di contesto da file enormi. */
const MAX_READ_BYTES = 256 * 1024;
/** Numero massimo di righe restituite da una singola read senza `limit`. */
const DEFAULT_READ_LINES = 2000;
/** Numero massimo di voci elencate da list_dir. */
const MAX_DIR_ENTRIES = 1000;

function resolvePath(ctx: ToolContext, p: string): string {
	return isAbsolute(p) ? resolve(p) : resolve(ctx.cwd, p);
}

export const readFileTool: NativeTool = {
	name: "read_file",
	description:
		"Legge un file di testo dal filesystem. Restituisce le righe numerate (il numero è solo di visualizzazione). " +
		"Usa `offset` (riga di partenza, 1-based) e `limit` (numero di righe) per leggere una porzione di file grandi.",
	inputSchema: {
		type: "object",
		properties: {
			path: { type: "string", description: "Percorso del file (relativo alla workspace o assoluto)." },
			offset: { type: "integer", description: "Riga di partenza (1-based), opzionale." },
			limit: { type: "integer", description: "Numero massimo di righe da leggere, opzionale." },
		},
		required: ["path"],
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const path = resolvePath(ctx, requireString(input, "path"));
		const offset = optionalInt(input, "offset");
		const limit = optionalInt(input, "limit");
		if (!existsSync(path)) return fail(`file non trovato: ${input.path}`);
		const stat = statSync(path);
		if (stat.isDirectory()) return fail(`"${input.path}" è una directory (usa list_dir)`);

		let raw = readFileSync(path);
		let truncatedBytes = false;
		if (raw.length > MAX_READ_BYTES) {
			raw = raw.subarray(0, MAX_READ_BYTES);
			truncatedBytes = true;
		}
		const text = raw.toString("utf8");
		const allLines = text.split("\n");
		const start = offset && offset > 0 ? offset - 1 : 0;
		const maxLines = limit && limit > 0 ? limit : DEFAULT_READ_LINES;
		const slice = allLines.slice(start, start + maxLines);
		const numbered = slice.map((line, i) => `${start + i + 1}\t${line}`).join("\n");
		const notes: string[] = [];
		if (truncatedBytes) notes.push(`[troncato a ${MAX_READ_BYTES} byte]`);
		if (start + slice.length < allLines.length) {
			notes.push(`[mostrate righe ${start + 1}-${start + slice.length} di ${allLines.length}]`);
		}
		const suffix = notes.length > 0 ? `\n${notes.join(" ")}` : "";
		return ok(numbered === "" ? `[file vuoto]${suffix}` : `${numbered}${suffix}`);
	},
};

export const writeFileTool: NativeTool = {
	name: "write_file",
	description:
		"Scrive (creando o sovrascrivendo) un file di testo, creando le directory intermedie. " +
		"Per modifiche puntuali a file esistenti preferisci edit_file.",
	inputSchema: {
		type: "object",
		properties: {
			path: { type: "string", description: "Percorso del file da scrivere." },
			content: { type: "string", description: "Contenuto completo del file." },
		},
		required: ["path", "content"],
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const path = resolvePath(ctx, requireString(input, "path"));
		const content = requireString(input, "content");
		const tmp = `${path}.harness-tmp`;
		try {
			mkdirSync(dirname(path), { recursive: true });
			// Scrittura atomica: tmp + rename, così un crash a metà non lascia un file troncato.
			writeFileSync(tmp, content, "utf8");
			renameSync(tmp, path);
		} catch (error) {
			// Se il rename fallisce dopo la write, il tmp resterebbe orfano: si pulisce
			// best-effort (rmSync può a sua volta lanciare su path patologici).
			safeUnlink(tmp);
			return fail(`scrittura fallita: ${error instanceof Error ? error.message : String(error)}`);
		}
		const bytes = Buffer.byteLength(content, "utf8");
		return ok(`scritto ${input.path} (${bytes} byte)`);
	},
};

export const editFileTool: NativeTool = {
	name: "edit_file",
	description:
		"Sostituisce una stringa esatta in un file esistente. Per default `old_string` deve comparire una sola volta " +
		"(altrimenti errore); usa replace_all=true per sostituire tutte le occorrenze.",
	inputSchema: {
		type: "object",
		properties: {
			path: { type: "string", description: "Percorso del file da modificare." },
			old_string: { type: "string", description: "Testo esatto da cercare (deve essere unico salvo replace_all)." },
			new_string: { type: "string", description: "Testo con cui sostituirlo." },
			replace_all: { type: "boolean", description: "Sostituisci tutte le occorrenze (default false)." },
		},
		required: ["path", "old_string", "new_string"],
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const path = resolvePath(ctx, requireString(input, "path"));
		const oldString = requireString(input, "old_string");
		const newString = typeof input.new_string === "string" ? input.new_string : "";
		const replaceAll = optionalBool(input, "replace_all") ?? false;
		if (oldString === newString) return fail("old_string e new_string sono identici: nessuna modifica");
		if (!existsSync(path)) return fail(`file non trovato: ${input.path}`);

		const original = readFileSync(path, "utf8");
		const occurrences = countOccurrences(original, oldString);
		if (occurrences === 0) return fail(`old_string non trovato in ${input.path}`);
		if (occurrences > 1 && !replaceAll) {
			return fail(`old_string compare ${occurrences} volte in ${input.path}: rendilo unico o usa replace_all`);
		}
		const updated = replaceAll ? original.split(oldString).join(newString) : original.replace(oldString, newString);
		const tmp = `${path}.harness-tmp`;
		try {
			writeFileSync(tmp, updated, "utf8");
			renameSync(tmp, path);
		} catch (error) {
			safeUnlink(tmp);
			return fail(`modifica fallita: ${error instanceof Error ? error.message : String(error)}`);
		}
		return ok(`modificato ${input.path} (${occurrences} sostituzion${occurrences === 1 ? "e" : "i"})`);
	},
};

export const listDirTool: NativeTool = {
	name: "list_dir",
	description: "Elenca il contenuto di una directory. Le directory sono marcate con '/'.",
	inputSchema: {
		type: "object",
		properties: {
			path: { type: "string", description: "Directory da elencare (default: la workspace)." },
		},
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const rel = typeof input.path === "string" && input.path !== "" ? input.path : ".";
		const path = resolvePath(ctx, rel);
		if (!existsSync(path)) return fail(`directory non trovata: ${rel}`);
		if (!statSync(path).isDirectory()) return fail(`"${rel}" non è una directory`);
		const entries = await readdir(path, { withFileTypes: true });
		const sorted = entries
			.map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
			.sort((a, b) => a.localeCompare(b))
			.slice(0, MAX_DIR_ENTRIES);
		const header = relative(ctx.cwd, path) || ".";
		const overflow = entries.length > MAX_DIR_ENTRIES ? `\n[… ${entries.length - MAX_DIR_ENTRIES} voci in più]` : "";
		return ok(`${header}:\n${sorted.join("\n")}${overflow}`);
	},
};

/** Rimozione best-effort di un file temporaneo: non deve mai propagare un'eccezione. */
function safeUnlink(path: string): void {
	try {
		rmSync(path, { force: true });
	} catch {
		// path patologico (es. antenato non-directory): il tmp non esiste comunque
	}
}

function countOccurrences(haystack: string, needle: string): number {
	if (needle === "") return 0;
	let count = 0;
	let index = haystack.indexOf(needle);
	while (index !== -1) {
		count++;
		index = haystack.indexOf(needle, index + needle.length);
	}
	return count;
}

/** Esportato per riuso da grep/glob. */
export { join, resolvePath };
