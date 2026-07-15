import { realpathSync } from "node:fs";
import { homedir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { parseBashCommand, stripLeadingAssignments } from "./bash-parse.js";
import type { BashPolicy, PathsPolicy, PolicyDecision, PolicyDocument, ToolCallRequest } from "./types.js";

/** Tetto di lunghezza del testo testato contro i pattern `deny` admin (mitigazione ReDoS). */
const MAX_DENY_REGEX_INPUT = 16 * 1024;

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

	// I pattern `deny` sono forniti dall'admin ed eseguiti su testo (il comando)
	// influenzato dall'agente/utente: un pattern con backtracking catastrofico +
	// input lungo potrebbe appendere l'enforcement (ReDoS). Limitiamo la
	// lunghezza del testo testato: comandi oltre questa soglia sono già
	// patologici (nessun uso legittimo). Non è una garanzia completa contro il
	// backtracking esponenziale — la sandbox e il process guard restano il vero
	// confine — ma bonifica il caso realistico.
	const denyTarget = trimmed.length > MAX_DENY_REGEX_INPUT ? trimmed.slice(0, MAX_DENY_REGEX_INPUT) : trimmed;
	for (const pattern of policy.deny) {
		let regex: RegExp;
		try {
			regex = new RegExp(pattern, "i");
		} catch {
			// Una regex malformata in policy non deve mai aprire un varco.
			return { action: "deny", reason: `pattern di policy non valido: ${pattern}` };
		}
		if (regex.test(denyTarget)) {
			return { action: "deny", reason: `comando corrisponde a pattern negato: ${pattern}` };
		}
	}

	const parsed = parseBashCommand(trimmed);
	if (parsed.unbalanced) {
		return { action: "deny", reason: "comando non analizzabile (virgolette o parentesi sbilanciate)" };
	}
	if (parsed.commands.length === 0) return { action: "deny", reason: "comando non analizzabile" };

	// Regole per-comando sempre applicate (anche in denylist): bloccano
	// l'esecuzione di codice arbitrario via interpreti inline, wrapper e
	// sostituzioni, che nessun uso legittimo di un coding-agent richiede.
	for (const parsedCommand of parsed.commands) {
		if (parsedCommand.hasProcessSubstitution) {
			return { action: "deny", reason: "process substitution <(...)/>(...) non consentita" };
		}
		if (parsedCommand.hasCommandSubstitution && !policy.allowSubstitution) {
			return { action: "deny", reason: "command substitution $(...)/backtick non consentita" };
		}
		const argv = stripLeadingAssignments(parsedCommand.argv);
		const danger = dangerousInvocation(argv);
		if (danger) return { action: "deny", reason: danger };
	}

	if (policy.mode === "denylist") return { action: "allow" };

	// Modalità allowlist: ogni comando deve corrispondere a un prefisso.
	for (const parsedCommand of parsed.commands) {
		const argv = stripLeadingAssignments(parsedCommand.argv);
		if (argv.length === 0) continue; // solo assegnazioni/redirezioni: innocuo
		if (!isArgvAllowed(policy.allow, argv)) {
			return {
				action: "deny",
				reason: `comando "${truncate(argv.join(" "), 80)}" non corrisponde ad alcun prefisso consentito`,
			};
		}
	}
	return { action: "allow" };
}

/** Nome base del comando (senza percorso): `/usr/bin/node` → `node`. */
function commandName(argv: string[]): string {
	const first = argv[0] ?? "";
	const slash = first.lastIndexOf("/");
	return slash === -1 ? first : first.slice(slash + 1);
}

/**
 * Rileva invocazioni che eseguono codice arbitrario in modo diretto —
 * interpreti con eval inline, wrapper che rilanciano comandi, awk/find/sed nelle
 * forme che eseguono processi. NON blocca `node file.js`, `npm test`, `make`:
 * quelli sono esecuzione legittima di un coding-agent, contenuta dalla sandbox
 * (che è il vero confine). Chiude i bypass banali "one-liner".
 */
/** Normalizza il nome comando rimuovendo un suffisso di versione: `python3.11` → `python`, `node18` → `node`. */
function interpreterBase(cmd: string): string {
	return cmd.replace(/[0-9.]+$/, "");
}

/**
 * Vero se fra gli argomenti compare uno dei flag indicati, riconoscendo anche
 * le forme "attaccate" che un confronto esatto mancherebbe: `--eval=CODE`,
 * `-eCODE`, e i cluster di short flag (`-pe`). È il fix di sicurezza centrale:
 * `node --eval='...'`, `python3 -c'...'`, `perl -e'...'` producono un singolo
 * token argv che non è mai `=== "-e"`, e sfuggirebbero a un match esatto —
 * eseguendo codice arbitrario attraverso l'allowlist di default (node/python
 * sono prefissi consentiti). Sui cluster short il match è volutamente
 * conservativo (fail-closed): se la lettera-flag pericolosa compare, blocca.
 */
function hasFlag(args: string[], shortFlags: string[], longFlags: string[]): boolean {
	for (const a of args) {
		if (a === "-" || a === "--" || !a.startsWith("-")) continue;
		if (a.startsWith("--")) {
			const name = a.slice(2).split("=", 1)[0] as string;
			if (longFlags.includes(name)) return true;
		} else {
			const cluster = a.slice(1);
			if (shortFlags.some((f) => cluster.includes(f))) return true;
		}
	}
	return false;
}

export function dangerousInvocation(argv: string[]): string | null {
	if (argv.length === 0) return null;
	const cmd = commandName(argv);
	const base = interpreterBase(cmd);
	const args = argv.slice(1);
	const has = (...flags: string[]) => args.some((a) => flags.includes(a));

	// Shell: eseguono qualunque cosa.
	if (["sh", "bash", "zsh", "dash", "ksh", "ash"].includes(base)) {
		if (hasFlag(args, ["c"], ["command"]) || args.some((a) => a === "-"))
			return `shell inline (${cmd} -c) non consentita`;
		// `bash script.sh` esegue uno script del repo: exec arbitrario → deny.
		return `esecuzione di shell (${cmd}) non consentita: usa i tool dedicati`;
	}
	// Interpreti con valutazione inline (forme attaccate incluse, vedi hasFlag).
	if (
		["node", "nodejs", "bun", "deno"].includes(base) &&
		(hasFlag(args, ["e", "p"], ["eval", "print"]) || has("eval"))
	) {
		return `esecuzione inline (${cmd} -e/-p) non consentita`;
	}
	if (base === "python" && hasFlag(args, ["c"], [])) {
		return "esecuzione inline (python -c) non consentita";
	}
	if (base === "perl" && hasFlag(args, ["e", "E"], [])) return "esecuzione inline (perl -e) non consentita";
	if (base === "ruby" && hasFlag(args, ["e"], [])) return "esecuzione inline (ruby -e) non consentita";
	if (base === "php" && hasFlag(args, ["r"], [])) return "esecuzione inline (php -r) non consentita";
	// awk: system()/pipe eseguono comandi.
	if (["awk", "gawk", "mawk"].includes(base) && args.some((a) => /system\s*\(|\|\s*(&|getline|")/.test(a))) {
		return "awk con system()/pipe non consentito";
	}
	// find: azioni che eseguono comandi o scrivono file.
	if (base === "find" && has("-exec", "-execdir", "-ok", "-okdir", "-fprintf", "-fprint", "-delete")) {
		return "find con -exec/-delete non consentito";
	}
	// sed: comando `e` (shell), scrittura file, in-place.
	if (["sed", "gsed"].includes(base)) {
		if (has("-i", "--in-place") || args.some((a) => a.startsWith("-i"))) return "sed -i (in-place) non consentito";
		if (args.some((a) => /(^|;|\})\s*[ewW]\b/.test(a))) return "sed con comando e/w non consentito";
	}
	// Wrapper che rilanciano un comando arbitrario: `command`/`time`/`sudo`/…
	// permettevano di nascondere una shell bloccata dietro un primo token innocuo
	// (`command bash -c …`), aggirando l'intero guard che ispeziona solo argv[0].
	if (
		[
			"xargs",
			"env",
			"nice",
			"nohup",
			"timeout",
			"watch",
			"setsid",
			"stdbuf",
			"ionice",
			"chroot",
			"command",
			"time",
			"sudo",
			"doas",
			"runuser",
			"su",
			"busybox",
			"coproc",
			"setpriv",
			"unshare",
			"caffeinate",
			"proxychains",
		].includes(base)
	) {
		return `wrapper di esecuzione (${cmd}) non consentito`;
	}
	// eval/exec/source come primo token (se mai passassero come comando).
	if (["eval", "exec", "source", "."].includes(base)) return `costrutto "${cmd}" non consentito`;
	return null;
}

function isArgvAllowed(allow: string[], argv: string[]): boolean {
	const normalized = argv.join(" ");
	return allow.some((prefix) => {
		if (normalized === prefix) return true;
		if (!normalized.startsWith(prefix)) return false;
		// Il carattere dopo il prefisso deve essere un separatore di argomento,
		// così "git" non autorizza "gitx" e "npm run" non autorizza "npm runx".
		const next = normalized.charAt(prefix.length);
		return next === " " || next === "\t";
	});
}

/**
 * Nomi di campo (normalizzati: minuscoli, senza `_`/`-`) che contengono un
 * percorso. Il confronto è esatto sul nome normalizzato — non su sottostringa —
 * per non catturare falsi positivi come `profile`/`makefile` (che contengono
 * "file" ma non sono percorsi).
 */
const PATH_KEYS = new Set([
	"path",
	"paths",
	"filepath",
	"file",
	"files",
	"dir",
	"dirs",
	"directory",
	"directories",
	"dirname",
	"filename",
	"oldpath",
	"newpath",
	"sourcepath",
	"srcpath",
	"destpath",
	"destinationpath",
	"targetpath",
]);

/**
 * Estrae ricorsivamente i valori-percorso dall'input di un tool, non solo dalle
 * chiavi top-level: un tool con input `{edits:[{path:…}]}` o `{old_path,new_path}`
 * bypasserebbe altrimenti l'enforcement dei percorsi. Raccoglie le stringhe (o
 * gli array di stringhe) sotto una chiave path-like a qualunque profondità, con
 * limiti di profondità/quantità per non degenerare su input ostili.
 */
function collectPathInputs(input: Record<string, unknown>): string[] {
	const out: string[] = [];
	const visit = (obj: unknown, depth: number): void => {
		if (depth > 6 || out.length > 200 || obj === null || typeof obj !== "object") return;
		for (const [key, value] of Object.entries(obj)) {
			if (PATH_KEYS.has(key.toLowerCase().replace(/[_-]/g, ""))) {
				if (typeof value === "string" && value.trim() !== "") out.push(value);
				else if (Array.isArray(value)) {
					for (const item of value) if (typeof item === "string" && item.trim() !== "") out.push(item);
				}
			}
			if (value && typeof value === "object") visit(value, depth + 1);
		}
	};
	visit(input, 0);
	return out;
}

export function evaluatePathAccess(policy: PathsPolicy, request: ToolCallRequest): PolicyDecision {
	const home = request.home ?? homedir();
	const paths = collectPathInputs(request.input);
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
