import { attachEnforcement, type FleetState } from "@harness/enforcement-core";
import { HarnessAgentAdapter } from "./adapter.js";
import { Agent, type AgentOptions } from "./agent.js";

/**
 * Costruisce un {@link Agent} già governato da uno {@link FleetState}: crea
 * l'adapter nativo, ci aggancia il motore di enforcement con la policy firmata
 * corrente, e restituisce l'agente pronto all'uso. È il modo canonico di
 * ottenere un agente "sotto governance" — nessun consumatore dovrebbe agganciare
 * l'enforcement a mano.
 */
export function createEnforcedAgent(state: FleetState, options: Omit<AgentOptions, "adapter">): Agent {
	const adapter = new HarnessAgentAdapter();
	attachEnforcement(adapter, state);
	return new Agent({ ...options, adapter });
}
