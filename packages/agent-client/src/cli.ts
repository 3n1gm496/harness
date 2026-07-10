#!/usr/bin/env node
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { defaultAgentConfigPath, loadAgentConfig } from "@harness/fleet-extension";
import { verifyConfigBundleMulti } from "@harness/shared";
import { readFileSync } from "node:fs";
import { applyManagedPiSettings, buildPiArgs, enroll, maybeRotateToken, syncConfig } from "./client.js";

/**
 * CLI del client gestito.
 *
 *   harness-agent enroll --url <control-plane> --token <enroll-token> [--name <nome>]
 *   harness-agent sync                sincronizza config e applica i settings PI gestiti
 *   harness-agent status              stato locale (device, versione config)
 *   harness-agent run [-- <args pi>]  sync + lancio di pi con l'estensione fleet
 */
async function main(): Promise<void> {
	const args = process.argv.slice(2);
	const command = args[0];

	if (command === "enroll") {
		const url = flagValue(args, "--url");
		const token = flagValue(args, "--token");
		if (!url || !token) {
			console.error("Uso: harness-agent enroll --url <control-plane> --token <enroll-token> [--name <nome>]");
			process.exit(2);
		}
		const config = await enroll({
			controlPlaneUrl: url,
			enrollToken: token,
			deviceName: flagValue(args, "--name") ?? "",
		});
		console.log(`Device arruolato: ${config.deviceId}`);
		console.log(`Identità scritta in ${defaultAgentConfigPath()} (permessi 0600).`);
		return;
	}

	if (command === "rotate-token") {
		const config = loadAgentConfig();
		const rotated = await maybeRotateToken(config, defaultAgentConfigPath(), { force: true });
		console.log(rotated ? "Device token ruotato." : "Rotazione non riuscita (control plane irraggiungibile?).");
		process.exit(rotated ? 0 : 1);
	}

	if (command === "sync" || command === "status" || command === "run") {
		const config = loadAgentConfig();
		if (command !== "status") {
			const rotated = await maybeRotateToken(config, defaultAgentConfigPath());
			if (rotated) console.log("Device token ruotato automaticamente (rotazione periodica).");
		}
		const state = await syncConfig(config);
		console.log(`Device:  ${config.deviceId}`);
		console.log(`Stato:   ${state.status}${state.lastError ? ` (${state.lastError})` : ""}`);
		console.log(`Config:  v${state.configVersion ?? "?"} — kill switch: ${state.policy.killSwitch ? "ATTIVO" : "no"}`);

		if (command === "status") return;

		if (state.status === "fail-closed") {
			console.error("Nessuna configurazione valida disponibile: l'agente partirebbe bloccato (fail-closed).");
			if (command === "run") process.exit(1);
			return;
		}

		const cachedToken = readFileSync(state.bundleCachePath, "utf8").trim();
		const verified = verifyConfigBundleMulti(config.publicKeyPems ?? [config.publicKeyPem], cachedToken);
		if (verified.valid) {
			const settingsPath = applyManagedPiSettings(verified.payload);
			console.log(`Settings PI gestiti applicati a ${settingsPath}`);
		}

		if (command === "run") {
			const require = createRequire(import.meta.url);
			const extensionPath = require.resolve("@harness/fleet-extension");
			const separatorIndex = args.indexOf("--");
			const piArgs = buildPiArgs(extensionPath, separatorIndex === -1 ? [] : args.slice(separatorIndex + 1));
			console.log(`Avvio: pi ${piArgs.join(" ")}`);
			const child = spawn("pi", piArgs, {
				stdio: "inherit",
				env: { ...process.env, PI_SKIP_VERSION_CHECK: "1" },
			});
			child.on("error", (error: NodeJS.ErrnoException) => {
				if (error.code === "ENOENT") {
					console.error("`pi` non trovato nel PATH. Installa il coding agent:");
					console.error("  npm install -g --ignore-scripts @earendil-works/pi-coding-agent");
				} else {
					console.error(`avvio di pi fallito: ${error.message}`);
				}
				process.exit(1);
			});
			child.on("exit", (code) => process.exit(code ?? 0));
		}
		return;
	}

	console.error("Comandi: enroll | sync | status | run | rotate-token");
	process.exit(2);
}

function flagValue(args: string[], flag: string): string | undefined {
	const index = args.indexOf(flag);
	if (index === -1 || index + 1 >= args.length) return undefined;
	return args[index + 1];
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
});
