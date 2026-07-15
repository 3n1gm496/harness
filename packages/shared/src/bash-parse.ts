/**
 * Tokenizer shell POSIX-lite per l'analisi di sicurezza dei comandi bash.
 *
 * Obiettivi (non è una shell completa):
 *  - separare i comandi sui *veri* operatori di controllo (`;`, `&&`, `||`,
 *    `|`, `&`, newline, subshell `(`/`)`) tenendo conto delle virgolette, così
 *    `git commit -m "a && b"` NON viene spezzato;
 *  - tokenizzare ogni comando in `argv` (nome + argomenti) rispettando
 *    virgolette singole/doppie ed escape, per applicare allowlist e regole
 *    per-comando sugli argomenti reali;
 *  - segnalare i costrutti che eseguono codice indirettamente: command
 *    substitution `$(...)`/backtick, process substitution `<(...)`/`>(...)`,
 *    here-doc.
 *
 * In caso di ambiguità (virgolette o parentesi sbilanciate) restituisce
 * `unbalanced: true`: il chiamante deve trattarlo come deny (fail-safe).
 */

export interface ParsedCommand {
	/** Parole del comando (nome + argomenti), al netto delle redirezioni fd. */
	argv: string[];
	hasCommandSubstitution: boolean;
	hasProcessSubstitution: boolean;
}

export interface BashParseResult {
	commands: ParsedCommand[];
	hasHeredoc: boolean;
	unbalanced: boolean;
}

const CONTROL_TWO = new Set(["&&", "||", ";;"]);

export function parseBashCommand(input: string): BashParseResult {
	const commands: ParsedCommand[] = [];
	let hasHeredoc = false;
	let unbalanced = false;

	let argv: string[] = [];
	let word = "";
	let wordStarted = false;
	let hasCmdSub = false;
	let hasProcSub = false;

	let inSingle = false;
	let inDouble = false;

	const pushWord = () => {
		if (wordStarted) {
			argv.push(word);
			word = "";
			wordStarted = false;
		}
	};
	const pushCommand = () => {
		pushWord();
		if (argv.length > 0 || hasCmdSub || hasProcSub) {
			commands.push({ argv, hasCommandSubstitution: hasCmdSub, hasProcessSubstitution: hasProcSub });
		}
		argv = [];
		hasCmdSub = false;
		hasProcSub = false;
	};
	const addChar = (ch: string) => {
		word += ch;
		wordStarted = true;
	};

	const n = input.length;
	for (let i = 0; i < n; i += 1) {
		const ch = input[i] as string;
		const next = i + 1 < n ? (input[i + 1] as string) : "";

		if (inSingle) {
			if (ch === "'") inSingle = false;
			else addChar(ch);
			continue;
		}
		if (inDouble) {
			if (ch === "\\" && (next === '"' || next === "\\" || next === "$" || next === "`")) {
				addChar(next);
				i += 1;
			} else if (ch === '"') {
				inDouble = false;
			} else {
				if (ch === "`") hasCmdSub = true;
				if (ch === "$" && next === "(") hasCmdSub = true;
				addChar(ch);
			}
			continue;
		}

		// Fuori dalle virgolette.
		// ANSI-C quoting: `$'...'` con decodifica degli escape (\xNN, \nnn ottale,
		// \uNNNN, \n, \t, ...). Senza decodifica, `$'\x62\x61\x73\x68'` verrebbe
		// letto come `$` + stringa letterale e il nome shell `bash` sfuggirebbe al
		// riconoscimento di sicurezza (bypass di dangerousInvocation).
		if (ch === "$" && next === "'") {
			let j = i + 2;
			let raw = "";
			while (j < n) {
				const c = input[j] as string;
				if (c === "\\" && j + 1 < n) {
					raw += c + (input[j + 1] as string);
					j += 2;
					continue;
				}
				if (c === "'") break;
				raw += c;
				j += 1;
			}
			if (j >= n) {
				unbalanced = true;
				break;
			}
			word += decodeAnsiC(raw);
			wordStarted = true;
			i = j; // punta al ' di chiusura
			continue;
		}
		if (ch === "'") {
			inSingle = true;
			wordStarted = true;
			continue;
		}
		if (ch === '"') {
			inDouble = true;
			wordStarted = true;
			continue;
		}
		if (ch === "\\") {
			if (next === "\n") {
				i += 1; // continuazione di riga
			} else if (next !== "") {
				addChar(next);
				i += 1;
			}
			continue;
		}
		if (ch === "`") {
			hasCmdSub = true;
			// Salta fino al backtick di chiusura.
			let j = i + 1;
			while (j < n && input[j] !== "`") j += 1;
			if (j >= n) {
				unbalanced = true;
				break;
			}
			wordStarted = true;
			i = j;
			continue;
		}
		// Sostituzione di comando o di processo: $( ... ), <( ... ), >( ... )
		if ((ch === "$" && next === "(") || ((ch === "<" || ch === ">") && next === "(")) {
			if (ch === "$") hasCmdSub = true;
			else hasProcSub = true;
			wordStarted = true;
			// Salta il gruppo bilanciato di parentesi.
			let depth = 0;
			let j = i + 1; // punta a '('
			for (; j < n; j += 1) {
				const c = input[j];
				if (c === "(") depth += 1;
				else if (c === ")") {
					depth -= 1;
					if (depth === 0) break;
				}
			}
			if (j >= n) {
				unbalanced = true;
				break;
			}
			i = j;
			continue;
		}
		// Here-doc.
		if (ch === "<" && next === "<") {
			hasHeredoc = true;
			i += 1;
			continue;
		}
		// Operatori di controllo a due caratteri.
		const two = ch + next;
		if (CONTROL_TWO.has(two)) {
			pushCommand();
			i += 1;
			continue;
		}
		if (ch === "|" && next === "|") {
			pushCommand();
			i += 1;
			continue;
		}
		// Operatori a un carattere.
		if (ch === ";" || ch === "|" || ch === "\n") {
			pushCommand();
			continue;
		}
		// `&>` / `&>>`: redirezione di stdout+stderr (non background).
		if (ch === "&" && next === ">") {
			pushWord();
			i += 1; // consuma '>'
			if (input[i + 1] === ">") i += 1;
			continue;
		}
		if (ch === "&") {
			pushCommand();
			continue;
		}
		if (ch === "(" || ch === ")") {
			// Subshell: confine di comando (l'interno è comunque valutato).
			pushCommand();
			continue;
		}
		// Redirezioni (>, >>, <, N>&M, >&): non fanno parte di argv. Un file
		// descriptor numerico in testa (es. "2" in 2>&1) va scartato.
		if (ch === ">" || ch === "<") {
			if (wordStarted && /^\d+$/.test(word)) {
				word = "";
				wordStarted = false;
			} else {
				pushWord();
			}
			let j = i + 1;
			if (input[j] === ">" || input[j] === "<") j += 1; // >> (<< già gestito come heredoc)
			if (input[j] === "&") {
				j += 1;
				while (j < n && (/[0-9]/.test(input[j] as string) || input[j] === "-")) j += 1;
			}
			i = j - 1;
			continue;
		}
		if (ch === " " || ch === "\t" || ch === "\r") {
			pushWord();
			continue;
		}
		addChar(ch);
	}

	if (inSingle || inDouble) unbalanced = true;
	pushCommand();

	return { commands, hasHeredoc, unbalanced };
}

/**
 * Decodifica gli escape ANSI-C dentro `$'...'` (bash): letterali (`\n`, `\t`,
 * …), esadecimali `\xNN`, ottali `\nnn`, unicode `\uNNNN`/`\UNNNNNNNN`. Serve
 * a smascherare i nomi comando offuscati (`$'\x62\x61\x73\x68'` → `bash`) prima
 * dei controlli di policy. In caso di sequenza non riconosciuta, mantiene il
 * carattere letterale (comportamento conservativo, non fa mai sparire testo).
 */
export function decodeAnsiC(s: string): string {
	let out = "";
	for (let i = 0; i < s.length; i += 1) {
		if (s[i] !== "\\") {
			out += s[i];
			continue;
		}
		const e = s[i + 1];
		if (e === undefined) {
			out += "\\";
			break;
		}
		const simple: Record<string, string> = {
			a: "\x07",
			b: "\b",
			e: "\x1b",
			E: "\x1b",
			f: "\f",
			n: "\n",
			r: "\r",
			t: "\t",
			v: "\v",
			"\\": "\\",
			"'": "'",
			'"': '"',
			"?": "?",
		};
		if (e in simple) {
			out += simple[e];
			i += 1;
			continue;
		}
		if (e === "x" || e === "u" || e === "U") {
			const width = e === "x" ? 2 : e === "u" ? 4 : 8;
			const m = new RegExp(`^[0-9a-fA-F]{1,${width}}`).exec(s.slice(i + 2));
			if (m) {
				const cp = parseInt(m[0], 16);
				if (e === "x") out += String.fromCharCode(cp);
				else if (cp <= 0x10ffff) out += String.fromCodePoint(cp);
				i += 1 + m[0].length;
				continue;
			}
			out += e;
			i += 1;
			continue;
		}
		// Ottale \nnn (1-3 cifre).
		const oct = /^[0-7]{1,3}/.exec(s.slice(i + 1));
		if (oct) {
			out += String.fromCharCode(parseInt(oct[0], 8) & 0xff);
			i += oct[0].length;
			continue;
		}
		out += e;
		i += 1;
	}
	return out;
}

/**
 * Rimuove le assegnazioni di variabili d'ambiente in testa (FOO=bar cmd ...)
 * e restituisce l'argv effettivo del comando.
 */
export function stripLeadingAssignments(argv: string[]): string[] {
	let i = 0;
	while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i] as string)) i += 1;
	return argv.slice(i);
}
