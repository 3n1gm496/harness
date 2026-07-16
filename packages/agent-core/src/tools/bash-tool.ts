import { spawn } from "node:child_process";
import { fail, type NativeTool, ok, optionalInt, requireString } from "./types.js";

/**
 * Tool bash nativo. È l'unico tool che esegue codice arbitrario, ed è
 * precisamente quello che il motore di enforcement valuta più a fondo:
 * `evaluateToolCall` instrada `bash` verso `evaluateBashCommand` (allowlist di
 * prefissi / denylist, blocco degli interpreti inline, wrapper, substitution).
 * Quando arriviamo qui, la policy ha GIÀ autorizzato il comando — questo tool
 * si limita a eseguirlo in modo robusto: shell non interattiva, timeout, cap
 * sull'output, kill dell'intero process group alla scadenza o all'abort.
 */

/** Timeout di default (ms) di un comando bash. */
const DEFAULT_TIMEOUT_MS = 120_000;
const MAX_TIMEOUT_MS = 600_000;
/** Tetto di byte catturati da stdout+stderr (protegge il contesto). */
const MAX_OUTPUT_BYTES = 128 * 1024;

/**
 * Variabili d'ambiente passate ai comandi shell. Il comando è guidato dal
 * modello: passargli l'INTERO `process.env` esporrebbe eventuali segreti del
 * processo agente (token iniettati da CI, credenziali dell'operatore) a un
 * `printenv`/`env`. Si passa quindi solo un insieme minimo e non sensibile; chi
 * ha bisogno di variabili aggiuntive le abilita esplicitamente via
 * `HARNESS_BASH_ENV_PASSTHROUGH` (lista di nomi separati da virgola).
 */
const BASH_ENV_ALLOWLIST = [
	"PATH",
	"HOME",
	"USER",
	"LOGNAME",
	"SHELL",
	"LANG",
	"LANGUAGE",
	"LC_ALL",
	"LC_CTYPE",
	"TERM",
	"TZ",
	"TMPDIR",
	"PWD",
];

/** Costruisce l'ambiente ridotto per i comandi shell (allowlist + passthrough opt-in). */
export function buildBashEnv(source: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {};
	const extra = (source.HARNESS_BASH_ENV_PASSTHROUGH ?? "")
		.split(",")
		.map((k) => k.trim())
		.filter((k) => k !== "");
	for (const key of [...BASH_ENV_ALLOWLIST, ...extra]) {
		const value = source[key];
		if (typeof value === "string") env[key] = value;
	}
	return env;
}

export const bashTool: NativeTool = {
	name: "bash",
	description:
		"Esegue un comando shell nella workspace e restituisce stdout/stderr combinati e l'exit code. " +
		"I comandi sono soggetti alla policy aziendale (allowlist/denylist): un comando non consentito viene bloccato prima dell'esecuzione.",
	inputSchema: {
		type: "object",
		properties: {
			command: { type: "string", description: "Il comando shell da eseguire." },
			timeout_ms: { type: "integer", description: `Timeout in millisecondi (default ${DEFAULT_TIMEOUT_MS}).` },
		},
		required: ["command"],
		additionalProperties: false,
	},
	async execute(input, ctx) {
		const command = requireString(input, "command");
		const requested = optionalInt(input, "timeout_ms");
		const timeoutMs = Math.min(requested && requested > 0 ? requested : DEFAULT_TIMEOUT_MS, MAX_TIMEOUT_MS);

		return new Promise((resolve) => {
			// `detached` mette il figlio in un nuovo process group: alla scadenza si
			// uccide l'INTERO gruppo (`-pid`), non solo la shell — così i figli
			// (pipe, sottoprocessi) non restano orfani a girare.
			const child = spawn("bash", ["-c", command], {
				cwd: ctx.cwd,
				detached: true,
				stdio: ["ignore", "pipe", "pipe"],
				env: buildBashEnv(),
			});

			const chunks: Buffer[] = [];
			let bytes = 0;
			let truncated = false;
			const capture = (data: Buffer): void => {
				if (truncated) return;
				if (bytes + data.length > MAX_OUTPUT_BYTES) {
					chunks.push(data.subarray(0, MAX_OUTPUT_BYTES - bytes));
					truncated = true;
				} else {
					chunks.push(data);
					bytes += data.length;
				}
			};
			child.stdout.on("data", capture);
			child.stderr.on("data", capture);

			let settled = false;
			const killGroup = (signal: NodeJS.Signals): void => {
				if (child.pid === undefined) return;
				try {
					process.kill(-child.pid, signal);
				} catch {
					// il gruppo potrebbe essere già uscito
				}
			};

			const timer = setTimeout(() => {
				killGroup("SIGTERM");
				// grazia breve, poi SIGKILL
				setTimeout(() => killGroup("SIGKILL"), 2_000).unref();
			}, timeoutMs);

			const onAbort = (): void => {
				killGroup("SIGKILL");
			};
			ctx.signal?.addEventListener("abort", onAbort, { once: true });

			const finish = (summary: string, isError: boolean): void => {
				if (settled) return;
				settled = true;
				clearTimeout(timer);
				ctx.signal?.removeEventListener("abort", onAbort);
				const output = Buffer.concat(chunks).toString("utf8");
				const body = output.trim() === "" ? "[nessun output]" : output;
				const suffix = truncated ? `\n[output troncato a ${MAX_OUTPUT_BYTES} byte]` : "";
				resolve(isError ? fail(`${summary}\n${body}${suffix}`) : ok(`${body}${suffix}`));
			};

			child.on("error", (error) => finish(`avvio del comando fallito: ${error.message}`, true));
			child.on("close", (code, signal) => {
				if (signal === "SIGTERM" || signal === "SIGKILL") {
					finish(`comando terminato per timeout (${timeoutMs}ms) o interruzione`, true);
				} else if (code === 0) {
					finish("", false);
				} else {
					finish(`exit code ${code ?? "sconosciuto"}`, true);
				}
			});
		});
	},
};
