import { evaluateBashCommand, evaluateToolCall, redactSecrets } from "@harness/shared";
import type { ContentBlock, ExtensionAPI, PiExtensionContext } from "./pi-types.js";
import { FleetState, loadAgentConfig } from "./fleet-state.js";

export { FleetState, loadAgentConfig, defaultAgentConfigPath } from "./fleet-state.js";
export type { AgentConfig, FleetStatus } from "./fleet-state.js";

/**
 * Estensione fleet per PI: applica la policy distribuita dal control plane a
 * ogni tool call, redige i segreti dai risultati, instrada l'audit e degrada
 * fail-closed quando la configurazione firmata manca o è scaduta.
 *
 * Caricata su ogni client gestito con `pi -e <percorso>/dist/index.js`.
 * L'identità del device (URL control plane, token, chiave pubblica pinnata)
 * viene letta da HARNESS_AGENT_CONFIG o ~/.harness/agent.json, scritto
 * dall'agent-client in fase di enrollment.
 */
export default async function fleetExtension(pi: ExtensionAPI): Promise<void> {
	let state: FleetState;
	try {
		state = new FleetState(loadAgentConfig());
	} catch (error) {
		// Senza identità di device il client non è gestibile: blocco totale.
		const message = error instanceof Error ? error.message : String(error);
		pi.on("tool_call", () => ({
			block: true,
			reason: `client non arruolato nella piattaforma amministrativa (${message})`,
		}));
		pi.on("user_bash", () => ({
			result: { output: "client non arruolato: comando bloccato", exitCode: 1, cancelled: false, truncated: false },
		}));
		return;
	}

	state.onStatusChange = () => updateStatusWidget(state);
	let statusUi: PiExtensionContext["ui"] | undefined;

	function updateStatusWidget(current: FleetState): void {
		if (!statusUi) return;
		const version = current.configVersion === undefined ? "?" : `v${current.configVersion}`;
		const label =
			current.status === "ok"
				? `config ${version}`
				: current.status === "cached"
					? `config ${version} (cache${current.lastError ? `: ${current.lastError}` : ""})`
					: "FAIL-CLOSED";
		statusUi.setStatus("harness-fleet", `fleet: ${label}`);
	}

	await state.initialLoad();
	state.startLoops();
	state.pushAudit("agent_start", { cwd: process.cwd(), status: state.status });

	pi.on("session_start", (_event, ctx) => {
		statusUi = ctx.ui;
		updateStatusWidget(state);
		if (state.status === "fail-closed" && ctx.hasUI) {
			ctx.ui.notify(
				"Configurazione di flotta non disponibile o scaduta: l'agente è bloccato (fail-closed).",
				"error",
			);
		}
	});

	pi.on("tool_call", (event, ctx) => {
		const decision = evaluateToolCall(state.policy, {
			toolName: event.toolName,
			input: event.input,
			cwd: ctx.cwd,
		});
		state.pushAudit("policy_decision", {
			toolName: event.toolName,
			toolCallId: event.toolCallId,
			action: decision.action,
			reason: decision.action === "deny" ? decision.reason : undefined,
			input: summarizeInput(event.input),
			configVersion: state.configVersion,
		});
		if (decision.action === "deny") {
			return { block: true, reason: `[policy aziendale] ${decision.reason}` };
		}
		return undefined;
	});

	pi.on("tool_result", (event) => {
		const policy = state.policy;
		if (!policy.redaction.enabled || event.isError) return undefined;
		let changed = false;
		const redactedLabels = new Set<string>();
		const content: ContentBlock[] = event.content.map((block) => {
			if (block.type !== "text" || typeof block.text !== "string") return block;
			const result = redactSecrets(block.text, policy.redaction.patterns);
			if (result.matches.length === 0) return block;
			changed = true;
			for (const label of result.matches) redactedLabels.add(label);
			return { ...block, text: result.text };
		});
		if (!changed) return undefined;
		state.pushAudit("tool_result", {
			toolName: event.toolName,
			toolCallId: event.toolCallId,
			redacted: [...redactedLabels],
		});
		return { content };
	});

	// I comandi `!` dell'utente seguono la stessa policy bash dell'agente.
	pi.on("user_bash", (event) => {
		const policy = state.policy;
		const decision = policy.killSwitch
			? ({ action: "deny", reason: "kill switch attivo" } as const)
			: evaluateBashCommand(policy.bash, event.command);
		state.pushAudit("user_bash", {
			command: truncate(redactSecrets(event.command).text, 300),
			action: decision.action,
			reason: decision.action === "deny" ? decision.reason : undefined,
		});
		if (decision.action === "deny") {
			return {
				result: {
					output: `[policy aziendale] comando bloccato: ${decision.reason}`,
					exitCode: 1,
					cancelled: false,
					truncated: false,
				},
			};
		}
		return undefined;
	});

	pi.on("session_shutdown", async () => {
		state.pushAudit("agent_stop", {});
		await state.shutdown();
	});
}

/**
 * Sintesi dell'input di un tool per l'audit: JSON troncato e già passato
 * dalla redaction, per non spedire segreti al log centrale.
 */
function summarizeInput(input: Record<string, unknown>): string {
	let serialized: string;
	try {
		serialized = JSON.stringify(input);
	} catch {
		serialized = "[input non serializzabile]";
	}
	return truncate(redactSecrets(serialized).text, 500);
}

function truncate(value: string, max: number): string {
	return value.length <= max ? value : `${value.slice(0, max)}…`;
}
