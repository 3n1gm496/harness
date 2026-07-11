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
 * Rimuove le assegnazioni di variabili d'ambiente in testa (FOO=bar cmd ...)
 * e restituisce l'argv effettivo del comando.
 */
export function stripLeadingAssignments(argv: string[]): string[] {
	let i = 0;
	while (i < argv.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(argv[i] as string)) i += 1;
	return argv.slice(i);
}
