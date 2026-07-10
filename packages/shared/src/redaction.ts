/**
 * Redaction di segreti dai risultati dei tool prima che rientrino nel
 * contesto del modello, nei log di sessione e nell'audit centralizzato.
 */

interface BuiltinPattern {
	label: string;
	regex: RegExp;
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
	{ label: "bearer-header", regex: /\bAuthorization:\s*Bearer\s+[A-Za-z0-9._~+/=-]{16,}/gi },
];

export interface RedactionResult {
	text: string;
	/** Etichette dei pattern che hanno prodotto almeno una sostituzione. */
	matches: string[];
}

export function redactSecrets(text: string, extraPatterns: string[] = []): RedactionResult {
	let result = text;
	const matches = new Set<string>();

	for (const { label, regex } of BUILTIN_PATTERNS) {
		regex.lastIndex = 0;
		if (regex.test(result)) {
			matches.add(label);
			regex.lastIndex = 0;
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
		if (regex.test(result)) {
			matches.add(`custom:${pattern}`);
			regex.lastIndex = 0;
			result = result.replace(regex, "[REDACTED:custom]");
		}
	}

	return { text: result, matches: [...matches] };
}
