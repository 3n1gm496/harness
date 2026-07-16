import { readFileSync, statSync } from "node:fs";
import { readdir } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import {
	fail,
	type NativeTool,
	ok,
	optionalString,
	requireString,
	type ToolContext,
	type ToolExecutionResult,
} from "./types.js";

/**
 * Tool di ricerca nativi (grep, glob) implementati in Node puro — nessuna
 * dipendenza da `rg`/`find` esterni, coerente con la filosofia zero-dep del
 * monorepo. Camminata della directory con ignore dei percorsi rumorosi e cap
 * su file/risultati per non far esplodere il contesto o il tempo.
 */

const IGNORED_DIRS = new Set([".git", "node_modules", "dist", ".next", "coverage", ".turbo", "vendor"]);
const MAX_FILES_WALKED = 20_000;
const MAX_MATCH_RESULTS = 200;
const MAX_FILE_BYTES = 1024 * 1024;
const MAX_GLOB_RESULTS = 500;
/** Byte NUL: euristica semplice per saltare i file binari senza dipendenze. */
const NUL = String.fromCharCode(0);

function resolvePath(ctx: ToolContext, p: string | undefined): string {
	if (!p || p === "") return resolve(ctx.cwd);
	return isAbsolute(p) ? resolve(p) : resolve(ctx.cwd, p);
}

/** Camminata ricorsiva; invoca `onFile` per ogni file regolare, rispettando il cap. */
async function walk(root: string, onFile: (absPath: string) => boolean | undefined): Promise<void> {
	let walked = 0;
	const stack: string[] = [root];
	while (stack.length > 0) {
		const dir = stack.pop() as string;
		let entries: import("node:fs").Dirent[];
		try {
			entries = await readdir(dir, { withFileTypes: true });
		} catch {
			continue; // directory non leggibile: salta
		}
		for (const entry of entries) {
			const abs = join(dir, entry.name);
			if (entry.isDirectory()) {
				if (!IGNORED_DIRS.has(entry.name)) stack.push(abs);
			} else if (entry.isFile()) {
				if (++walked > MAX_FILES_WALKED) return;
				if (onFile(abs) === false) return;
			}
		}
	}
}

export const grepTool: NativeTool = {
	name: "grep",
	description:
		"Cerca un pattern (espressione regolare) nel contenuto dei file, ricorsivamente. " +
		"Restituisce le righe che corrispondono nel formato file:riga:testo. Ignora .git/node_modules/dist.",
	inputSchema: {
		type: "object",
		properties: {
			pattern: { type: "string", description: "Espressione regolare da cercare (sintassi JavaScript)." },
			path: { type: "string", description: "Directory o file di partenza (default: la workspace)." },
			glob: { type: "string", description: "Filtro sul nome file, es. '*.ts' o '**/*.json' (opzionale)." },
			ignore_case: { type: "boolean", description: "Ricerca case-insensitive (default false)." },
		},
		required: ["pattern"],
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const patternSrc = requireString(input, "pattern");
		let regex: RegExp;
		try {
			regex = new RegExp(patternSrc, input.ignore_case === true ? "i" : "");
		} catch (error) {
			return fail(`pattern regex non valido: ${error instanceof Error ? error.message : String(error)}`);
		}
		const globFilter = optionalString(input, "glob");
		const globRe = globFilter ? globToRegExp(globFilter) : undefined;
		const start = resolvePath(ctx, optionalString(input, "path"));

		const results: string[] = [];
		let truncated = false;
		const consider = (abs: string): boolean | undefined => {
			if (globRe && !globRe.test(relativeSlash(ctx.cwd, abs))) return undefined;
			let content: string;
			try {
				if (statSync(abs).size > MAX_FILE_BYTES) return undefined;
				content = readFileSync(abs, "utf8");
			} catch {
				return undefined; // illeggibile: salta
			}
			if (content.includes(NUL)) return undefined; // euristica binario
			const lines = content.split("\n");
			for (let i = 0; i < lines.length; i++) {
				const line = lines[i] as string;
				regex.lastIndex = 0;
				if (regex.test(line)) {
					results.push(`${relativeSlash(ctx.cwd, abs)}:${i + 1}:${truncateLine(line)}`);
					if (results.length >= MAX_MATCH_RESULTS) {
						truncated = true;
						return false;
					}
				}
			}
			return undefined;
		};

		try {
			const stat = statSync(start);
			if (stat.isFile()) consider(start);
			else await walk(start, consider);
		} catch {
			return fail(`percorso non trovato: ${input.path ?? "."}`);
		}
		if (results.length === 0) return ok("nessuna corrispondenza");
		const suffix = truncated ? `\n[troncato a ${MAX_MATCH_RESULTS} risultati]` : "";
		return ok(`${results.join("\n")}${suffix}`);
	},
};

export const globTool: NativeTool = {
	name: "glob",
	description:
		"Trova i file il cui percorso corrisponde a un pattern glob (supporta **, *, ?). " +
		"Restituisce i percorsi relativi alla workspace. Ignora .git/node_modules/dist.",
	inputSchema: {
		type: "object",
		properties: {
			pattern: { type: "string", description: "Pattern glob, es. 'src/**/*.ts'." },
			path: { type: "string", description: "Directory di partenza (default: la workspace)." },
		},
		required: ["pattern"],
		additionalProperties: false,
	},
	async execute(input, ctx): Promise<ToolExecutionResult> {
		const pattern = requireString(input, "pattern");
		const globRe = globToRegExp(pattern);
		const start = resolvePath(ctx, optionalString(input, "path"));
		const matches: string[] = [];
		let truncated = false;
		await walk(start, (abs) => {
			const rel = relativeSlash(ctx.cwd, abs);
			if (globRe.test(rel)) {
				matches.push(rel);
				if (matches.length >= MAX_GLOB_RESULTS) {
					truncated = true;
					return false;
				}
			}
			return undefined;
		});
		if (matches.length === 0) return ok("nessun file corrisponde");
		matches.sort((a, b) => a.localeCompare(b));
		const suffix = truncated ? `\n[troncato a ${MAX_GLOB_RESULTS} file]` : "";
		return ok(`${matches.join("\n")}${suffix}`);
	},
};

function relativeSlash(cwd: string, abs: string): string {
	const rel = relative(cwd, abs);
	return rel.split(/[\\/]/).join("/");
}

function truncateLine(line: string): string {
	const trimmed = line.replace(/\s+$/, "");
	return trimmed.length > 300 ? `${trimmed.slice(0, 300)}…` : trimmed;
}

/**
 * Converte un pattern glob in RegExp ancorata. Supporta `**` (qualunque numero
 * di segmenti, inclusi zero), `*` (dentro un segmento), `?` (un carattere non
 * separatore). Il resto è escapato letteralmente. Se il pattern non contiene un
 * separatore di percorso, si intende "in qualunque directory" (match sul solo
 * nome file) prefissando la doppia stella.
 */
export function globToRegExp(glob: string): RegExp {
	const pattern = glob.includes("/") ? glob : `**/${glob}`;
	let re = "";
	for (let i = 0; i < pattern.length; i++) {
		const c = pattern[i] as string;
		if (c === "*") {
			if (pattern[i + 1] === "*") {
				// doppia stella → qualunque profondità; consuma anche un eventuale '/' seguente.
				i++;
				if (pattern[i + 1] === "/") i++;
				re += "(?:.*/)?";
			} else {
				re += "[^/]*";
			}
		} else if (c === "?") {
			re += "[^/]";
		} else if ("\\^$.|+()[]{}".includes(c)) {
			re += `\\${c}`;
		} else {
			re += c;
		}
	}
	return new RegExp(`^${re}$`);
}
