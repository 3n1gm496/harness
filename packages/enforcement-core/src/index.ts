/**
 * `@harness/enforcement-core` — motore di enforcement agent-agnostic.
 *
 * Espone il contratto neutro {@link AgentAdapter}, il motore che vi si aggancia
 * ({@link attachEnforcement} / {@link bootstrapEnforcement}) e la gestione
 * dello stato di flotta ({@link FleetState}). Nessun accoppiamento a PI o ad
 * alcun coding agent specifico: integrare un nuovo agente significa scrivere
 * un nuovo adapter che implementa `AgentAdapter`.
 */

export type {
	AgentAdapter,
	Gate,
	HostSession,
	HostUi,
	OutputBlock,
	ResultRewrite,
	ShellCommand,
	ToolCall,
	ToolResult,
} from "./adapter.js";
export { attachEnforcement, bootstrapEnforcement } from "./engine.js";
export type { AgentConfig, FleetStatus } from "./fleet-state.js";
export { defaultAgentConfigPath, FleetState, loadAgentConfig } from "./fleet-state.js";
