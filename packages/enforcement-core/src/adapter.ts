/**
 * Contratto neutro fra il motore di enforcement e l'agente ospite.
 *
 * Il cuore del disaccoppiamento: il motore non conosce PI (o qualunque altro
 * coding agent). Conosce solo questa interfaccia. Un'integrazione concreta
 * (es. l'adapter PI in `@harness/fleet-extension`, o l'adapter mock negli
 * esempi) traduce gli eventi nativi dell'agente in queste primitive neutre e
 * riporta indietro le decisioni del motore nel formato che l'agente si aspetta.
 *
 * Aggiungere il supporto a un nuovo agente = scrivere un nuovo `AgentAdapter`,
 * senza toccare il motore.
 */

/** Superficie UI minima che un host può esporre (tutto opzionale). */
export interface HostUi {
	/** Mostra un messaggio all'operatore umano, se l'host ha una UI. */
	notify(message: string, level?: "info" | "warning" | "error"): void;
	/** Aggiorna un indicatore di stato persistente (chiave stabile). */
	setStatus(key: string, text: string | undefined): void;
}

/** Contesto di una sessione dell'agente ospite. */
export interface HostSession {
	/** Directory di lavoro corrente della sessione. */
	cwd: string;
	/** True se l'host può interagire con un umano (mostrare notifiche). */
	hasUI: boolean;
	/** UI dell'host, presente solo se `hasUI`. */
	ui?: HostUi;
}

/** Una chiamata a tool che l'agente sta per eseguire. */
export interface ToolCall {
	toolName: string;
	callId: string;
	/** Argomenti del tool (potenzialmente mutabili dall'host prima dell'uso). */
	input: Record<string, unknown>;
}

/** Blocco di contenuto neutro (strutturalmente compatibile con i vari agenti). */
export interface OutputBlock {
	type: string;
	text?: string;
	[key: string]: unknown;
}

/** Il risultato prodotto da un tool, prima di tornare all'agente. */
export interface ToolResult {
	toolName: string;
	callId: string;
	input: Record<string, unknown>;
	content: OutputBlock[];
	isError: boolean;
}

/** Un comando shell lanciato direttamente dall'utente (non dal modello). */
export interface ShellCommand {
	command: string;
	cwd: string;
}

/**
 * Decisione di gating del motore. `reason` è già il messaggio completo e
 * pronto da mostrare all'utente: l'adapter lo veicola così com'è.
 */
export type Gate = { allow: true } | { allow: false; reason: string };

/**
 * Riscrittura del risultato di un tool: se presente, l'host sostituisce il
 * contenuto (es. dopo redaction dei segreti); se `undefined`, nessuna modifica.
 */
export type ResultRewrite = { content: OutputBlock[] } | undefined;

/**
 * Contratto che ogni integrazione con un coding agent implementa. Il motore
 * chiama questi `on*` per registrare i propri handler; l'adapter li invoca
 * quando l'agente ospite emette l'evento corrispondente, traducendo avanti e
 * indietro i tipi nativi.
 *
 * Gli handler possono essere async: l'adapter deve attenderne l'esito prima di
 * lasciar proseguire l'agente (i gate sono barriere sincrone dal punto di
 * vista dell'agente).
 */
export interface AgentAdapter {
	/** Inizio sessione: il motore aggancia la UI di stato e le notifiche. */
	onSessionStart(handler: (session: HostSession) => void | Promise<void>): void;
	/** Prima di ogni tool call: il motore decide allow/deny. */
	onToolCall(handler: (call: ToolCall, session: HostSession) => Gate | Promise<Gate>): void;
	/** Dopo ogni tool result: il motore può riscriverne il contenuto. */
	onToolResult(handler: (result: ToolResult, session: HostSession) => ResultRewrite | Promise<ResultRewrite>): void;
	/** Prima di ogni comando shell dell'utente: il motore decide allow/deny. */
	onShellCommand(handler: (command: ShellCommand, session: HostSession) => Gate | Promise<Gate>): void;
	/** Fine sessione: il motore fa flush dell'audit e chiude i loop. */
	onSessionEnd(handler: () => void | Promise<void>): void;
}
