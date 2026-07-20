#!/usr/bin/env node
import { FleetState, loadAgentConfig } from "@harness/enforcement-core";
import { createLogger, installProcessGuards, isSandboxSatisfied } from "@harness/shared";
import type { AgentEvent } from "./agent.js";
import { flagValue, parseInvocation } from "./cli-args.js";
import { runRepl } from "./cli-repl.js";
import { createEnforcedAgent } from "./factory.js";
import { LlmClient } from "./llm.js";
import { ToolRegistry } from "./tools/registry.js";

/**
 * CLI dell'agente NATIVO di Harness. A differenza di `harness-agent run` (che
 * lancia il coding agent di terze parti PI con l'estensione fleet), questo
 * comando avvia il nostro loop di agente: modello via gateway, tool nativi,
 * ogni azione governata dalla policy firmata.
 *
 *   harness-agent-native run "<prompt>"   esecuzione singola (one-shot)
 *   harness-agent-native -p "<prompt>"    idem (forma con flag)
 *   harness-agent-native repl             sessione interattiva (REPL)
 *   harness-agent-native                  interattivo se su TTY, altrimenti richiede un prompt
 *   harness-agent-native tools            elenca i tool nativi
 *
 * Config via flag o ambiente:
 *   --gateway <url> | HARNESS_GATEWAY_URL   URL del gateway LLM (obbligatorio)
 *   --model <id>    | HARNESS_MODEL         modello (default claude-sonnet-5)
 *   --cwd <dir>                             workspace (default cwd corrente)
 */

const DEFAULT_MODEL = "claude-sonnet-5";
const DIM = "\x1b[2m";
const CYAN = "\x1b[36m";
const YELLOW = "\x1b[33m";
const RESET = "\x1b[0m";

async function main(): Promise<void> {
	const args = process.argv.slice(2);
	installProcessGuards(createLogger("harness-agent-native"));

	const invocation = parseInvocation(args);
	if (invocation.tools) {
		for (const tool of new ToolRegistry().list()) {
			process.stdout.write(`${CYAN}${tool.name}${RESET}  ${tool.description.split("\n")[0]}\n`);
		}
		return;
	}
	const { forcedRepl, prompt, rest } = invocation;

	const gatewayUrl = flagValue(rest, "--gateway") ?? process.env.HARNESS_GATEWAY_URL;
	if (!gatewayUrl) {
		fail("URL del gateway mancante: passa --gateway <url> o imposta HARNESS_GATEWAY_URL.");
	}
	const model = flagValue(rest, "--model") ?? process.env.HARNESS_MODEL ?? DEFAULT_MODEL;
	const cwd = flagValue(rest, "--cwd") ?? process.cwd();

	// Identità del device + configurazione firmata (policy) dal control plane.
	const config = loadAgentConfig();
	const state = new FleetState(config);
	await state.initialLoad();
	process.stderr.write(
		`${DIM}device ${config.deviceId} · config v${state.configVersion ?? "?"} · stato ${state.status}` +
			`${state.policy.killSwitch ? " · KILL SWITCH ATTIVO" : ""}${RESET}\n`,
	);
	if (state.status === "fail-closed") {
		fail("Nessuna configurazione valida: l'agente partirebbe bloccato (fail-closed). Verifica enrollment/rete.");
	}
	// Barriera sandbox: coerente con `harness-agent run`.
	if (!isSandboxSatisfied(state.policy.sandbox)) {
		fail(
			`La policy richiede l'esecuzione dentro l'ambiente contenuto sanzionato (marker "${state.policy.sandbox.markerPath}" assente).`,
		);
	}

	// Avvia i loop di sync/flush dell'audit: la policy resta aggiornata e l'audit
	// delle azioni dell'agente viene spedito al control plane.
	state.startLoops();

	const llm = new LlmClient({ gatewayUrl, deviceToken: config.deviceToken, promptCache: true });
	const interactive = forcedRepl || (!prompt && process.stdin.isTTY);

	const agent = createEnforcedAgent(state, {
		llm,
		model,
		cwd,
		stream: true,
		hasUI: true,
		subAgents: true,
		onText: (text) => process.stdout.write(text),
		onEvent: printEvent,
	});

	try {
		if (interactive) {
			await repl(agent);
		} else {
			if (!prompt) {
				fail(
					'Nessun prompt. Uso: harness-agent-native run "<prompt>"  (o -p "<prompt>", o `repl` per la sessione interattiva).',
				);
			}
			await runOnce(agent, prompt);
		}
	} finally {
		await agent.stop();
	}
}

async function runOnce(agent: ReturnType<typeof createEnforcedAgent>, prompt: string): Promise<void> {
	const result = await agent.run(prompt);
	process.stdout.write("\n");
	process.stderr.write(
		`${DIM}— ${result.iterations} iterazioni · ${result.usage.inputTokens}+${result.usage.outputTokens} token` +
			`${result.stoppedOnLimit ? " · fermato al limite di iterazioni" : ""}${RESET}\n`,
	);
}

function repl(agent: ReturnType<typeof createEnforcedAgent>): Promise<void> {
	return runRepl(agent, {
		prompt: `${CYAN}› ${RESET}`,
		banner: `${CYAN}Harness Agent${RESET} — sessione interattiva. Scrivi un compito; "exit" per uscire.\n`,
	});
}

function printEvent(event: AgentEvent): void {
	// Indentazione per profondità: l'attività dei sotto-agenti è rientrata.
	const pad = "  ".repeat(event.depth ?? 0);
	switch (event.type) {
		case "assistant_text":
			// Il testo dell'agente principale (depth 0) va già su stdout via onText;
			// qui si mostra solo quello dei sotto-agenti, indentato.
			if ((event.depth ?? 0) > 0) process.stderr.write(`${DIM}${pad}↳ ${firstLine(event.text)}${RESET}\n`);
			break;
		case "tool_use":
			process.stderr.write(`\n${DIM}${pad}⚙ ${event.name} ${compactJson(event.input)}${RESET}\n`);
			break;
		case "tool_denied":
			process.stderr.write(`${YELLOW}${pad}⛔ ${event.name} negato: ${event.reason}${RESET}\n`);
			break;
		case "tool_result":
			if (event.isError) process.stderr.write(`${YELLOW}${pad}  ↳ errore: ${firstLine(event.content)}${RESET}\n`);
			else process.stderr.write(`${DIM}${pad}  ↳ ok${RESET}\n`);
			break;
		case "compaction":
			process.stderr.write(`${DIM}${pad}ⓘ contesto compresso (${event.removedMessages} messaggi)${RESET}\n`);
			break;
		default:
			break;
	}
}

function compactJson(input: Record<string, unknown>): string {
	const json = JSON.stringify(input);
	return json.length > 120 ? `${json.slice(0, 120)}…` : json;
}

function firstLine(text: string): string {
	const line = text.split("\n")[0] ?? "";
	return line.length > 160 ? `${line.slice(0, 160)}…` : line;
}

function fail(message: string): never {
	process.stderr.write(`${YELLOW}${message}${RESET}\n`);
	process.exit(1);
}

main().catch((error) => {
	process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
	process.exit(1);
});
