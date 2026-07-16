/**
 * `@harness/agent-core` — l'agente nativo di Harness.
 *
 * A differenza di `@harness/fleet-extension` (un adapter attorno a un coding
 * agent di terze parti), questo package È l'agente: possiede il loop
 * reason-act-observe, il runtime dei tool nativi e il client LLM. Ogni azione
 * dell'agente passa per `@harness/enforcement-core` — la stessa policy firmata
 * distribuita dal control plane che governa qualunque altro adapter.
 */

export type { LlmClientOptions } from "./llm.js";
export { assembleFromSse, LlmClient, LlmError } from "./llm.js";
export { DEFAULT_TOOLS, ToolRegistry } from "./tools/registry.js";
export { globToRegExp } from "./tools/search-tools.js";
export type { NativeTool, ToolContext, ToolExecutionResult } from "./tools/types.js";
export type {
	AssistantBlock,
	LlmRequest,
	LlmResponse,
	LlmUsage,
	Message,
	TextBlock,
	ToolDefinition,
	ToolResultBlock,
	ToolSchema,
	ToolUseBlock,
	UserBlock,
} from "./types.js";
