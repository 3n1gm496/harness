/**
 * Shim strutturale (solo compile-time) della Extension API di PI, allineato a
 * @earendil-works/pi-coding-agent v0.80.x (docs/extensions.md). A runtime PI
 * passa l'oggetto reale alla factory; il typing strutturale garantisce la
 * compatibilità senza dipendere dal pacchetto PI in fase di build.
 *
 * Se si aggiorna la versione di PI pinnata sui client, riverificare qui le
 * firme degli eventi usati: tool_call, tool_result, user_bash, session_start.
 */

export interface PiUi {
	notify(message: string, level?: "info" | "warning" | "error"): void;
	setStatus(key: string, text: string | undefined): void;
	confirm(title: string, message: string): Promise<boolean>;
}

export interface PiExtensionContext {
	ui: PiUi;
	cwd: string;
	hasUI: boolean;
}

export interface ToolCallEvent {
	toolName: string;
	toolCallId: string;
	/** Input del tool, mutabile prima dell'esecuzione. */
	input: Record<string, unknown>;
}

export type ToolCallHandlerResult = { block: true; reason?: string } | undefined;

export interface ContentBlock {
	type: string;
	text?: string;
	[key: string]: unknown;
}

export interface ToolResultEvent {
	toolName: string;
	toolCallId: string;
	input: Record<string, unknown>;
	content: ContentBlock[];
	details: unknown;
	isError: boolean;
}

export interface ToolResultPatch {
	content?: ContentBlock[];
	details?: unknown;
	isError?: boolean;
}

export interface UserBashEvent {
	command: string;
	excludeFromContext: boolean;
	cwd: string;
}

export interface UserBashResult {
	result: { output: string; exitCode: number; cancelled: boolean; truncated: boolean };
}

export interface SessionStartEvent {
	[key: string]: unknown;
}

export interface ExtensionAPI {
	on(
		event: "tool_call",
		handler: (event: ToolCallEvent, ctx: PiExtensionContext) => ToolCallHandlerResult | Promise<ToolCallHandlerResult>,
	): void;
	on(
		event: "tool_result",
		handler: (
			event: ToolResultEvent,
			ctx: PiExtensionContext,
		) => ToolResultPatch | undefined | Promise<ToolResultPatch | undefined>,
	): void;
	on(
		event: "user_bash",
		handler: (
			event: UserBashEvent,
			ctx: PiExtensionContext,
		) => UserBashResult | undefined | Promise<UserBashResult | undefined>,
	): void;
	on(
		event: "session_start",
		handler: (event: SessionStartEvent, ctx: PiExtensionContext) => void | Promise<void>,
	): void;
	on(event: "session_shutdown", handler: (event: unknown, ctx: PiExtensionContext) => void | Promise<void>): void;
}
