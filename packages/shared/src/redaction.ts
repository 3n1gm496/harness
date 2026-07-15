/**
 * Redaction di segreti dai risultati dei tool prima che rientrino nel
 * contesto del modello, nei log di sessione e nell'audit centralizzato.
 */

interface BuiltinPattern {
	label: string;
	regex: RegExp;
	/**
	 * Sostituzione per-match opzionale: riceve il match completo e i gruppi
	 * catturati e ritorna il testo con cui sostituire, oppure `null` per NON
	 * redigere questo match (whitelist di falsi positivi). Se assente, il match
	 * è sostituito interamente da `[REDACTED:label]`.
	 */
	replace?: (match: string, groups: string[]) => string | null;
}

const BUILTIN_PATTERNS: BuiltinPattern[] = [
	{ label: "anthropic-key", regex: /sk-ant-[A-Za-z0-9_-]{10,}/g },
	{ label: "openai-key", regex: /sk-(?:proj-)?[A-Za-z0-9_-]{20,}/g },
	{ label: "aws-access-key", regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
	{
		label: "aws-secret-key",
		regex: /\baws_secret_access_key\s*[=:]\s*["']?[A-Za-z0-9/+=]{30,}["']?/gi,
	},
	{ label: "github-token", regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b/g },
	{ label: "github-pat", regex: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },
	{ label: "slack-token", regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
	{ label: "google-api-key", regex: /\bAIza[0-9A-Za-z_-]{30,}\b/g },
	{ label: "jwt", regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g },
	// Token della piattaforma harness stessa (admin, device, enrollment, gateway):
	// non devono mai finire nel contesto del modello né nei log di sessione.
	{ label: "harness-token", regex: /\b(?:adm|dvt|enr|gwt)_[A-Za-z0-9_-]{20,}\b/g },
	{
		label: "private-key-block",
		regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
	},
	{
		label: "generic-assignment",
		regex: /\b(?:api[_-]?key|secret|password|passwd|token)\s*[=:]\s*["'][^"'\s]{8,}["']/gi,
	},
	// Coppia CHIAVE=VALORE *non quotata* con chiave sensibile: è lo scenario
	// più comune e finora scoperto — un `cat .env` / `printenv` che espone
	// `DB_PASSWORD=SuperSecret123`. Il pattern quotato sopra non lo cattura
	// (richiede le virgolette) e nessun pattern branded matcha un segreto
	// generico. La whitelist `SAFE_ASSIGNMENT_KEYS` evita di redigere
	// assegnazioni innocue con nomi che *contengono* una parola sensibile ma
	// non sono segreti (es. `PATH=`), gestita in `redactSecrets`.
	{
		label: "generic-assignment-unquoted",
		regex:
			/\b([A-Za-z0-9_]*(?:passwd|password|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth)[A-Za-z0-9_]*)(\s*[=:]\s*)(?!["'])(\S{8,})/gi,
		replace: (_match, groups) => {
			const key = (groups[0] ?? "").toLowerCase();
			if (SAFE_ASSIGNMENT_KEYS.has(key)) return null; // falso positivo (es. AUTHORS=…): non redigere
			// Mantiene la chiave e l'operatore, redige solo il valore.
			return `${groups[0]}${groups[1]}[REDACTED:generic-assignment-unquoted]`;
		},
	},
	{ label: "bearer-header", regex: /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/gi },
];

/**
 * Nomi di variabile che *contengono* una parola sensibile ma il cui valore non
 * è un segreto: non vanno redatti (falsi positivi che nasconderebbero output
 * legittimo). Confronto case-insensitive sul nome catturato prima di `=`.
 */
const SAFE_ASSIGNMENT_KEYS = new Set(["path", "authors", "author", "authority", "tokenizer", "tokens"]);

/** Tetto di lunghezza del testo su cui si applicano i pattern custom admin (mitigazione ReDoS). */
const MAX_CUSTOM_PATTERN_INPUT = 256 * 1024;

export interface RedactionResult {
	text: string;
	/** Etichette dei pattern che hanno prodotto almeno una sostituzione. */
	matches: string[];
}

export function redactSecrets(text: string, extraPatterns: string[] = []): RedactionResult {
	let result = text;
	const matches = new Set<string>();

	for (const { label, regex, replace } of BUILTIN_PATTERNS) {
		regex.lastIndex = 0;
		if (!regex.test(result)) continue;
		regex.lastIndex = 0;
		if (replace) {
			// Sostituzione per-match con whitelist: registra il label solo se
			// almeno un match è stato effettivamente redatto (non tutti whitelisted).
			let redactedAny = false;
			result = result.replace(regex, (match, ...rest) => {
				// `rest` = gruppi catturati + offset + stringa intera; teniamo i gruppi.
				const groups = rest.slice(0, -2) as string[];
				const replacement = replace(match, groups);
				if (replacement === null) return match;
				redactedAny = true;
				return replacement;
			});
			if (redactedAny) matches.add(label);
		} else {
			matches.add(label);
			result = result.replace(regex, `[REDACTED:${label}]`);
		}
	}

	for (const pattern of extraPatterns) {
		let regex: RegExp;
		try {
			regex = new RegExp(pattern, "g");
		} catch {
			continue; // una regex custom malformata non deve rompere il flusso
		}
		// ReDoS: i pattern custom sono forniti dall'admin ed eseguiti su testo
		// (output dei tool) controllato dall'attaccante. Un pattern con
		// backtracking catastrofico + testo lungo appenderebbe l'enforcement. Li
		// applichiamo solo a un prefisso limitato: la coda oltre il tetto non
		// passa dai pattern custom (i builtin, sicuri per costruzione, l'hanno
		// già coperta). Non è una garanzia completa contro il backtracking
		// esponenziale, ma bonifica il caso realistico.
		const bounded = result.length > MAX_CUSTOM_PATTERN_INPUT;
		const target = bounded ? result.slice(0, MAX_CUSTOM_PATTERN_INPUT) : result;
		if (regex.test(target)) {
			matches.add(`custom:${pattern}`);
			regex.lastIndex = 0;
			const redactedHead = target.replace(regex, "[REDACTED:custom]");
			result = bounded ? redactedHead + result.slice(MAX_CUSTOM_PATTERN_INPUT) : redactedHead;
		}
	}

	return { text: result, matches: [...matches] };
}
