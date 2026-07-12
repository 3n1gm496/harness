import { bootstrapEnforcement } from "@harness/enforcement-core";
import type { ExtensionAPI } from "./pi-types.js";
import { PiAdapter } from "./pi-adapter.js";

// Riesporta lo stato di flotta e le utility di config dal core, così i
// consumatori (agent-client, test) mantengono l'import da questo pacchetto.
export { FleetState, loadAgentConfig, defaultAgentConfigPath } from "@harness/enforcement-core";
export type { AgentConfig, FleetStatus } from "@harness/enforcement-core";
export { PiAdapter } from "./pi-adapter.js";

/**
 * Estensione fleet per PI: adatta la Extension API di PI al motore di
 * enforcement agent-agnostic di `@harness/enforcement-core`. Tutta la logica
 * di policy, redaction, audit e sandbox vive nel core; qui resta solo il
 * collante specifico di PI.
 *
 * Caricata su ogni client gestito con `pi -e <percorso>/dist/index.js`.
 * L'identità del device (URL control plane, token, chiave pubblica pinnata)
 * viene letta da HARNESS_AGENT_CONFIG o ~/.harness/agent.json, scritto
 * dall'agent-client in fase di enrollment.
 */
export default async function fleetExtension(pi: ExtensionAPI): Promise<void> {
	await bootstrapEnforcement(new PiAdapter(pi));
}
