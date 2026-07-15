import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { AgentConfig } from "@harness/enforcement-core";
import { FleetState, defaultAgentConfigPath } from "@harness/enforcement-core";
import type { ConfigBundle } from "@harness/shared";
import { deepMerge, generateSigningKeyPair } from "@harness/shared";

/**
 * Operazioni del client gestito: enrollment presso il control plane,
 * sincronizzazione della configurazione firmata e applicazione dei settings
 * gestiti di PI.
 */

export interface EnrollOptions {
	controlPlaneUrl: string;
	enrollToken: string;
	deviceName: string;
	configPath?: string;
}

export async function enroll(options: EnrollOptions, fetchImpl: typeof fetch = fetch): Promise<AgentConfig> {
	// Coppia di chiavi Ed25519 propria del device, per firmare i batch di audit
	// (provenance): la privata resta solo in agent.json, mai trasmessa.
	const deviceSigningKeyPair = generateSigningKeyPair();

	const response = await fetchImpl(`${options.controlPlaneUrl}/api/enroll`, {
		method: "POST",
		headers: { "content-type": "application/json" },
		body: JSON.stringify({
			enrollToken: options.enrollToken,
			deviceName: options.deviceName,
			deviceSigningPublicKeyPem: deviceSigningKeyPair.publicKeyPem,
		}),
		signal: AbortSignal.timeout(15_000),
	});
	if (!response.ok) {
		const data = (await response.json().catch(() => ({}))) as { error?: string };
		throw new Error(`enrollment fallito: ${data.error ?? `HTTP ${response.status}`}`);
	}
	const enrollment = (await response.json()) as { deviceId: string; deviceToken: string; publicKeyPem: string };

	const config: AgentConfig = {
		controlPlaneUrl: options.controlPlaneUrl,
		deviceId: enrollment.deviceId,
		deviceToken: enrollment.deviceToken,
		publicKeyPem: enrollment.publicKeyPem,
		publicKeyPems: [enrollment.publicKeyPem],
		tokenIssuedAt: new Date().toISOString(),
		deviceSigningPrivateKeyPem: deviceSigningKeyPair.privateKeyPem,
	};
	writeAgentConfig(options.configPath ?? defaultAgentConfigPath(), config);
	return config;
}

function writeAgentConfig(path: string, config: AgentConfig): void {
	mkdirSync(dirname(path), { recursive: true });
	const tmpPath = `${path}.tmp`;
	writeFileSync(tmpPath, JSON.stringify(config, null, "\t"), { mode: 0o600 });
	renameSync(tmpPath, path);
}

/**
 * Ruota il device token se più vecchio di `rotateAfterDays` (default 30) o se
 * forzato. Il vecchio token smette immediatamente di valere sul control plane
 * e sul gateway; il nuovo viene persistito atomicamente in agent.json.
 */
export async function maybeRotateToken(
	config: AgentConfig,
	configPath: string,
	options: { force?: boolean } = {},
	fetchImpl: typeof fetch = fetch,
): Promise<boolean> {
	const maxAgeDays = config.rotateAfterDays ?? 30;
	const issuedAt = config.tokenIssuedAt ? Date.parse(config.tokenIssuedAt) : 0;
	const expired = Date.now() - issuedAt > maxAgeDays * 86_400_000;
	if (!options.force && !expired) return false;

	const response = await fetchImpl(`${config.controlPlaneUrl}/api/device/rotate-token`, {
		method: "POST",
		headers: { authorization: `Bearer ${config.deviceToken}` },
		signal: AbortSignal.timeout(15_000),
	});
	if (!response.ok) {
		// La rotazione è best-effort: un control plane irraggiungibile non deve
		// impedire l'avvio (la scadenza vera è governata dal bundle firmato).
		return false;
	}
	const data = (await response.json()) as { deviceToken?: string };
	if (typeof data.deviceToken !== "string") return false;

	config.deviceToken = data.deviceToken;
	config.tokenIssuedAt = new Date().toISOString();
	writeAgentConfig(configPath, config);
	return true;
}

/**
 * Scarica e verifica il bundle firmato. Restituisce lo stato della flotta con
 * la policy effettiva; lancia se non c'è alcuna configurazione applicabile.
 */
export async function syncConfig(config: AgentConfig, fetchImpl: typeof fetch = fetch): Promise<FleetState> {
	const state = new FleetState(config);
	await state.initialLoad(fetchImpl);
	return state;
}

/**
 * Applica i settings gestiti di PI a ~/.pi/agent/settings.json.
 * I settings esistenti dell'utente vengono preservati; i campi gestiti dal
 * control plane li sovrascrivono (i lockdown aziendali vincono sempre).
 */
export function applyManagedPiSettings(bundle: ConfigBundle, piAgentDir = join(homedir(), ".pi", "agent")): string {
	const settingsPath = join(piAgentDir, "settings.json");
	let existing: Record<string, unknown> = {};
	if (existsSync(settingsPath)) {
		try {
			existing = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
		} catch {
			existing = {}; // settings corrotti: si riparte dai soli valori gestiti
		}
	}
	const merged = deepMerge(existing, bundle.piSettings);
	mkdirSync(piAgentDir, { recursive: true });
	const tmpPath = `${settingsPath}.tmp`;
	writeFileSync(tmpPath, JSON.stringify(merged, null, "\t"), { mode: 0o600 });
	renameSync(tmpPath, settingsPath);
	return settingsPath;
}

/** Argomenti con cui lanciare PI con l'estensione fleet caricata. */
export function buildPiArgs(extensionPath: string, extraArgs: string[]): string[] {
	return ["-e", extensionPath, ...extraArgs];
}
