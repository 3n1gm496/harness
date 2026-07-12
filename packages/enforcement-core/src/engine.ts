import { evaluateBashCommand, evaluateToolCall, isSandboxSatisfied, redactSecrets } from "@harness/shared";
import type { AgentAdapter, HostSession, HostUi, OutputBlock } from "./adapter.js";
import { FleetState, loadAgentConfig } from "./fleet-state.js";

/**
 * Motore di enforcement agent-agnostic. Applica la policy distribuita dal
 * control plane a ogni azione dell'agente ospite, redige i segreti dai
 * risultati, instrada l'audit e degrada fail-closed quando la configurazione
 * firmata manca o è scaduta.
 *
 * Non conosce PI né alcun agente specifico: opera esclusivamente sul contratto
 * neutro `AgentAdapter`. Un adapter concreto traduce gli eventi nativi
 * dell'agente in queste primitive e riporta indietro le decisioni.
 */

const POLICY_PREFIX = "[policy aziendale]";

/**
 * Aggancia il motore di enforcement a un adapter già costruito, usando uno
 * stato di flotta già inizializzato. Registra tutti gli handler ma non avvia
 * i loop di sync/flush (spetta al chiamante, o si usa {@link bootstrapEnforcement}).
 */
export function attachEnforcement(adapter: AgentAdapter, state: FleetState): void {
	let statusUi: HostUi | undefined;

	const updateStatusWidget = (): void => {
		if (!statusUi) return;
		const version = state.configVersion === undefined ? "?" : `v${state.configVersion}`;
		const label =
			state.status === "ok"
				? `config ${version}`
				: state.status === "cached"
					? `config ${version} (cache${state.lastError ? `: ${state.lastError}` : ""})`
					: "FAIL-CLOSED";
		statusUi.setStatus("harness-fleet", `fleet: ${label}`);
	};
	state.onStatusChange = updateStatusWidget;

	adapter.onSessionStart((session: HostSession) => {
		statusUi = session.ui;
		updateStatusWidget();
		if (state.status === "fail-closed" && session.hasUI && session.ui) {
			session.ui.notify(
				"Configurazione di flotta non disponibile o scaduta: l'agente è bloccato (fail-closed).",
				"error",
			);
		}
	});

	adapter.onToolCall((call, session) => {
		// Barriera sandbox: se la policy richiede il contenimento e il marker
		// dell'ambiente sanzionato non c'è, si blocca tutto (fail-closed).
		if (!isSandboxSatisfied(state.policy.sandbox)) {
			state.pushAudit("policy_decision", {
				toolName: call.toolName,
				toolCallId: call.callId,
				action: "deny",
				reason: "sandbox obbligatoria assente",
			});
			return {
				allow: false,
				reason: `${POLICY_PREFIX} l'agente deve girare dentro l'ambiente contenuto sanzionato (marker sandbox assente)`,
			};
		}
		const decision = evaluateToolCall(state.policy, {
			toolName: call.toolName,
			input: call.input,
			cwd: session.cwd,
		});
		state.pushAudit("policy_decision", {
			toolName: call.toolName,
			toolCallId: call.callId,
			action: decision.action,
			reason: decision.action === "deny" ? decision.reason : undefined,
			input: summarizeInput(call.input),
			configVersion: state.configVersion,
		});
		if (decision.action === "deny") {
			return { allow: false, reason: `${POLICY_PREFIX} ${decision.reason}` };
		}
		return { allow: true };
	});

	adapter.onToolResult((result) => {
		const policy = state.policy;
		if (!policy.redaction.enabled || result.isError) return undefined;
		let changed = false;
		const redactedLabels = new Set<string>();
		const content: OutputBlock[] = result.content.map((block) => {
			if (block.type !== "text" || typeof block.text !== "string") return block;
			const redaction = redactSecrets(block.text, policy.redaction.patterns);
			if (redaction.matches.length === 0) return block;
			changed = true;
			for (const label of redaction.matches) redactedLabels.add(label);
			return { ...block, text: redaction.text };
		});
		if (!changed) return undefined;
		state.pushAudit("tool_result", {
			toolName: result.toolName,
			toolCallId: result.callId,
			redacted: [...redactedLabels],
		});
		return { content };
	});

	// I comandi shell dell'utente seguono la stessa policy bash dell'agente.
	adapter.onShellCommand((command) => {
		const policy = state.policy;
		if (!isSandboxSatisfied(policy.sandbox)) {
			return { allow: false, reason: `${POLICY_PREFIX} comando bloccato: sandbox obbligatoria assente` };
		}
		const decision = policy.killSwitch
			? ({ action: "deny", reason: "kill switch attivo" } as const)
			: evaluateBashCommand(policy.bash, command.command);
		state.pushAudit("user_bash", {
			command: truncate(redactSecrets(command.command).text, 300),
			action: decision.action,
			reason: decision.action === "deny" ? decision.reason : undefined,
		});
		if (decision.action === "deny") {
			return { allow: false, reason: `${POLICY_PREFIX} comando bloccato: ${decision.reason}` };
		}
		return { allow: true };
	});

	adapter.onSessionEnd(async () => {
		state.pushAudit("agent_stop", {});
		await state.shutdown();
	});
}

/**
 * Punto di ingresso completo per un adapter: carica l'identità del device,
 * costruisce lo stato di flotta, aggancia l'enforcement, esegue il caricamento
 * iniziale della configurazione e avvia i loop di sync/flush.
 *
 * Se il device non è arruolato (nessuna identità), registra handler
 * fail-closed che bloccano ogni azione con un messaggio esplicito, senza
 * lanciare: l'agente parte ma è inibito finché non viene arruolato.
 */
export async function bootstrapEnforcement(adapter: AgentAdapter): Promise<void> {
	let state: FleetState;
	try {
		state = new FleetState(loadAgentConfig());
	} catch (error) {
		// Senza identità di device il client non è gestibile: blocco totale.
		const message = error instanceof Error ? error.message : String(error);
		const reason = `client non arruolato nella piattaforma amministrativa (${message})`;
		adapter.onToolCall(() => ({ allow: false, reason }));
		adapter.onShellCommand(() => ({ allow: false, reason: `client non arruolato: comando bloccato (${message})` }));
		return;
	}

	attachEnforcement(adapter, state);
	await state.initialLoad();
	state.startLoops();
	state.pushAudit("agent_start", { cwd: process.cwd(), status: state.status });
}

/**
 * Sintesi dell'input di un tool per l'audit: JSON troncato e già passato dalla
 * redaction, per non spedire segreti al log centrale.
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
