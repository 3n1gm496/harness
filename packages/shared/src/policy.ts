import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import type { BashPolicy, PathsPolicy, PolicyDecision, PolicyDocument, ToolCallRequest } from "./types.js";

/**
 * Motore di valutazione delle policy, invocato dall'estensione fleet
 * sull'evento `tool_call` di PI prima di ogni esecuzione.
 *
 * Nota di sicurezza: questo è defense-in-depth, non il confine di sicurezza.
 * Il parsing dei comandi bash è conservativo ma approssimato; il contenimento
 * reale di filesystem e rete spetta alla sandbox (container/micro-VM) in cui
 * gira il client.
 */
export function evaluateToolCall(policy: PolicyDocument, request: ToolCallRequest): PolicyDecision {
	if (policy.killSwitch) {
		return { action: "deny", reason: "kill switch attivo: agente sospeso dalla piattaforma amministrativa" };
	}

	const toolDecision = evaluateToolName(policy, request.toolName);
	if (toolDecision.action === "deny") return toolDecision;

	if (request.toolName === "bash") {
		const command = typeof request.input.command === "string" ? request.input.command : "";
		const bashDecision = evaluateBashCommand(policy.bash, command);
		if (bashDecision.action === "deny") return bashDecision;
	}

	const pathDecision = evaluatePathAccess(policy.paths, request);
	if (pathDecision.action === "deny") return pathDecision;

	return { action: "allow" };
}

function evaluateToolName(policy: PolicyDocument, toolName: string): PolicyDecision {
	if (policy.tools.deny.includes(toolName)) {
		return { action: "deny", reason: `tool "${toolName}" negato dalla policy` };
	}
	if (policy.tools.allow.includes(toolName)) return { action: "allow" };
	if (policy.tools.defaultAction === "allow") return { action: "allow" };
	return { action: "deny", reason: `tool "${toolName}" non presente nell'allowlist (default deny)` };
}

/**
 * Valuta un comando bash. Il comando viene spezzato nei suoi segmenti
 * (separatori `;`, `&&`, `||`, `|`, `&`, newline) e in modalità allowlist
 * ogni segmento deve corrispondere a un prefisso consentito. Le regex di
 * `deny` sono applicate sempre, sull'intero comando.
 */
export function evaluateBashCommand(policy: BashPolicy, command: string): PolicyDecision {
	const trimmed = command.trim();
	if (trimmed === "") return { action: "deny", reason: "comando vuoto" };

	if (policy.mode === "deny-all") {
		return { action: "deny", reason: "esecuzione bash disabilitata dalla policy" };
	}

	for (const pattern of policy.deny) {
		let regex: RegExp;
		try {
			regex = new RegExp(pattern, "i");
		} catch {
			// Una regex malformata in policy non deve mai aprire un varco.
			return { action: "deny", reason: `pattern di policy non valido: ${pattern}` };
		}
		if (regex.test(trimmed)) {
			return { action: "deny", reason: `comando corrisponde a pattern negato: ${pattern}` };
		}
	}

	if (policy.mode === "denylist") return { action: "allow" };

	// Modalità allowlist.
	if (!policy.allowSubstitution && /\$\(|`/.test(trimmed)) {
		return { action: "deny", reason: "command substitution non consentita dalla policy" };
	}

	const segments = splitCommandSegments(trimmed);
	if (segments.length === 0) return { action: "deny", reason: "comando non analizzabile" };

	for (const segment of segments) {
		if (!isSegmentAllowed(policy.allow, segment)) {
			return {
				action: "deny",
				reason: `segmento "${truncate(segment, 80)}" non corrisponde ad alcun prefisso consentito`,
			};
		}
	}
	return { action: "allow" };
}

function splitCommandSegments(command: string): string[] {
	// Le duplicazioni di file descriptor (2>&1, >&2, …) contengono `&` ma non
	// sono separatori di comando: vanno rimosse prima dello split, altrimenti
	// producono falsi segmenti ("1") che l'allowlist nega.
	const withoutFdRedirects = command.replaceAll(/\d*>{1,2}&\d*/g, " ");
	return withoutFdRedirects
		.split(/(?:\|\||&&|[;|&\n])+/)
		.map((segment) => segment.trim())
		// Ignora redirezioni pure e segmenti vuoti derivanti dallo split.
		.filter((segment) => segment !== "" && !/^[<>]/.test(segment));
}

function isSegmentAllowed(allow: string[], segment: string): boolean {
	// Rimuove assegnazioni di variabili d'ambiente in testa (FOO=bar cmd ...).
	let normalized = segment;
	for (;;) {
		const match = /^[A-Za-z_][A-Za-z0-9_]*=(?:"[^"]*"|'[^']*'|\S*)\s+/.exec(normalized);
		if (!match) break;
		normalized = normalized.slice(match[0].length);
	}
	if (normalized === "") return false;
	return allow.some((prefix) => {
		if (normalized === prefix) return true;
		if (!normalized.startsWith(prefix)) return false;
		// Il carattere successivo al prefisso deve essere un separatore di
		// argomento, così "git" non autorizza "gitx" e "npm run" non autorizza
		// "npm run-script-malizioso" solo se il prefisso finisce a metà parola.
		const next = normalized.charAt(prefix.length);
		return next === " " || next === "\t";
	});
}

/** Campi di input dei tool built-in di PI che contengono percorsi. */
const PATH_INPUT_KEYS = ["path", "file_path", "filePath", "directory", "dir"] as const;

export function evaluatePathAccess(policy: PathsPolicy, request: ToolCallRequest): PolicyDecision {
	const home = request.home ?? homedir();
	const paths: string[] = [];
	for (const key of PATH_INPUT_KEYS) {
		const value = request.input[key];
		if (typeof value === "string" && value.trim() !== "") paths.push(value);
	}
	if (paths.length === 0) return { action: "allow" };

	const denyPrefixes = policy.deny.map((p) => resolveReal(normalizePrefix(p, home, request.cwd)));
	const allowPrefixes = policy.allow.map((p) => resolveReal(normalizePrefix(p, home, request.cwd)));
	const workspace = resolveReal(resolve(request.cwd));

	for (const rawPath of paths) {
		const absolute = resolveReal(resolve(request.cwd, expandHome(rawPath, home)));
		if (denyPrefixes.some((prefix) => isWithin(prefix, absolute))) {
			return { action: "deny", reason: `accesso al percorso "${rawPath}" negato dalla policy` };
		}
		if (policy.workspaceOnly) {
			const inWorkspace = isWithin(workspace, absolute);
			const inAllowed = allowPrefixes.some((prefix) => isWithin(prefix, absolute));
			if (!inWorkspace && !inAllowed) {
				return {
					action: "deny",
					reason: `percorso "${rawPath}" fuori dalla workspace e non presente tra i prefissi consentiti`,
				};
			}
		}
	}
	return { action: "allow" };
}

function expandHome(value: string, home: string): string {
	if (value === "~") return home;
	if (value.startsWith("~/")) return home + value.slice(1);
	return value;
}

function normalizePrefix(prefix: string, home: string, cwd: string): string {
	const expanded = expandHome(prefix, home);
	return isAbsolute(expanded) ? resolve(expanded) : resolve(cwd, expanded);
}

/**
 * Risolve i symlink del percorso (o del suo antenato esistente più profondo,
 * per i path non ancora creati): un link dentro la workspace che punta fuori
 * deve essere valutato per la sua destinazione reale, non per il nome.
 */
function resolveReal(absolute: string): string {
	let current = absolute;
	let suffix = "";
	for (;;) {
		try {
			return suffix === "" ? realpathSync(current) : join(realpathSync(current), suffix);
		} catch {
			const parent = dirname(current);
			if (parent === current) return absolute; // nessun antenato esistente
			suffix = suffix === "" ? basename(current) : join(basename(current), suffix);
			current = parent;
		}
	}
}

function isWithin(prefix: string, target: string): boolean {
	if (target === prefix) return true;
	return target.startsWith(prefix.endsWith(sep) ? prefix : prefix + sep);
}

function truncate(value: string, max: number): string {
	return value.length <= max ? value : `${value.slice(0, max)}…`;
}
