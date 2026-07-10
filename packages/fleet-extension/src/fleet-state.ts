import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import type { AuditEvent, ConfigBundle, PolicyDocument } from "@harness/shared";
import { failClosedPolicy, newId, verifyConfigBundleMulti } from "@harness/shared";

/** File di identità del device scritto dall'agent-client in fase di enrollment. */
export interface AgentConfig {
	controlPlaneUrl: string;
	deviceId: string;
	deviceToken: string;
	/** Chiave pubblica di firma pinnata all'enrollment (chiave iniziale). */
	publicKeyPem: string;
	/**
	 * Set di chiavi pubbliche fidate, aggiornato automaticamente dai bundle
	 * (`trustedPublicKeys`) per sostenere la rotazione della chiave di firma
	 * senza re-enrollment. Se assente si usa `publicKeyPem`.
	 */
	publicKeyPems?: string[];
	/** Intervallo di sync della configurazione in secondi (default 60). */
	syncIntervalSeconds?: number;
	/** Intervallo di flush dell'audit in secondi (default 10). */
	auditFlushSeconds?: number;
	/** Percorso della cache locale del bundle firmato. */
	bundleCachePath?: string;
	/** Data di emissione del device token corrente (per la rotazione). */
	tokenIssuedAt?: string;
	/** Giorni oltre i quali il client ruota automaticamente il device token (default 30). */
	rotateAfterDays?: number;
}

export function defaultAgentConfigPath(): string {
	return process.env.HARNESS_AGENT_CONFIG ?? join(homedir(), ".harness", "agent.json");
}

export function loadAgentConfig(path: string = defaultAgentConfigPath()): AgentConfig {
	if (!existsSync(path)) {
		throw new Error(
			`device non arruolato: nessuna configurazione in ${path}. Esegui prima "harness-agent enroll --url <control-plane> --token <enroll-token>".`,
		);
	}
	const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<AgentConfig>;
	for (const key of ["controlPlaneUrl", "deviceId", "deviceToken", "publicKeyPem"] as const) {
		if (typeof raw[key] !== "string" || raw[key] === "") {
			throw new Error(`config agent non valida: campo mancante "${key}" in ${path}`);
		}
	}
	return raw as AgentConfig;
}

export type FleetStatus = "ok" | "cached" | "fail-closed";

/**
 * Stato runtime dell'estensione fleet: policy corrente, sync del bundle
 * firmato con verifica della firma pinnata e fail-closed alla scadenza,
 * buffer dell'audit con spedizione batch.
 */
export class FleetState {
	readonly config: AgentConfig;
	private readonly configPath: string;
	private bundle: ConfigBundle | undefined;
	private policyOverride: PolicyDocument | undefined;
	private auditBuffer: AuditEvent[] = [];
	private timers: NodeJS.Timeout[] = [];
	status: FleetStatus = "fail-closed";
	lastError = "";
	onStatusChange: ((state: FleetState) => void) | undefined;

	constructor(config: AgentConfig, configPath: string = defaultAgentConfigPath()) {
		this.config = config;
		this.configPath = configPath;
		if (!this.config.publicKeyPems || this.config.publicKeyPems.length === 0) {
			this.config.publicKeyPems = [this.config.publicKeyPem];
		}
	}

	/** Insieme delle chiavi pubbliche attualmente fidate dal client. */
	private pinnedKeys(): string[] {
		return this.config.publicKeyPems && this.config.publicKeyPems.length > 0
			? this.config.publicKeyPems
			: [this.config.publicKeyPem];
	}

	/**
	 * Aggiorna il set di chiavi fidate dai `trustedPublicKeys` di un bundle già
	 * verificato e lo persiste, così la rotazione della chiave di firma non
	 * richiede re-enrollment. La chiave di enrollment resta sempre inclusa
	 * finché il server non la ritira.
	 */
	private updateTrustedKeys(bundle: ConfigBundle): void {
		if (!bundle.trustedPublicKeys || bundle.trustedPublicKeys.length === 0) return;
		const next = [...bundle.trustedPublicKeys];
		const current = this.pinnedKeys();
		if (next.length === current.length && next.every((k) => current.includes(k))) return;
		this.config.publicKeyPems = next;
		try {
			const tmp = `${this.configPath}.tmp`;
			mkdirSync(dirname(this.configPath), { recursive: true });
			writeFileSync(tmp, JSON.stringify(this.config, null, "\t"), { mode: 0o600 });
			renameSync(tmp, this.configPath);
		} catch {
			// La persistenza è best-effort: in memoria il set è comunque aggiornato.
		}
	}

	get policy(): PolicyDocument {
		if (this.policyOverride) return this.policyOverride;
		if (!this.bundle || Date.parse(this.bundle.expiresAt) < Date.now()) {
			// Bundle assente o scaduto tra un sync e l'altro: fail-closed.
			return failClosedPolicy();
		}
		return this.bundle.policy;
	}

	get configVersion(): number | undefined {
		return this.bundle?.configVersion;
	}

	get bundleCachePath(): string {
		return this.config.bundleCachePath ?? join(homedir(), ".harness", "config-bundle.jws");
	}

	/** Carica la cache locale (per partenza offline), poi tenta il refresh dal server. */
	async initialLoad(fetchImpl: typeof fetch = fetch): Promise<void> {
		this.loadFromCache();
		await this.refresh(fetchImpl);
	}

	private loadFromCache(): void {
		if (!existsSync(this.bundleCachePath)) return;
		const token = readFileSync(this.bundleCachePath, "utf8").trim();
		const verified = verifyConfigBundleMulti(this.pinnedKeys(), token);
		if (verified.valid && verified.payload.deviceId === this.config.deviceId) {
			this.bundle = verified.payload;
			this.updateTrustedKeys(verified.payload);
			this.setStatus("cached");
		}
	}

	async refresh(fetchImpl: typeof fetch = fetch): Promise<void> {
		try {
			const response = await fetchImpl(`${this.config.controlPlaneUrl}/api/device/config`, {
				headers: { authorization: `Bearer ${this.config.deviceToken}` },
				signal: AbortSignal.timeout(15_000),
			});
			if (response.status === 401 || response.status === 403) {
				// Rifiuto definitivo (token non valido o device revocato): il
				// bundle in cache non va più onorato, si degrada subito.
				this.bundle = undefined;
				this.dropCache();
				this.lastError = `device non autorizzato (HTTP ${response.status})`;
				this.setStatus("fail-closed");
				return;
			}
			if (!response.ok) throw new Error(`HTTP ${response.status}`);
			const data = (await response.json()) as { token?: string };
			if (typeof data.token !== "string") throw new Error("risposta senza token");

			const verified = verifyConfigBundleMulti(this.pinnedKeys(), data.token);
			if (!verified.valid) throw new Error(`bundle rifiutato: ${verified.error}`);
			if (verified.payload.deviceId !== this.config.deviceId) {
				throw new Error("bundle emesso per un altro device");
			}

			this.bundle = verified.payload;
			this.updateTrustedKeys(verified.payload);
			this.writeCache(data.token);
			this.lastError = "";
			this.setStatus("ok");
		} catch (error) {
			this.lastError = error instanceof Error ? error.message : String(error);
			// Il bundle corrente resta valido fino alla sua scadenza; oltre,
			// il getter `policy` degrada da solo a fail-closed.
			if (!this.bundle || Date.parse(this.bundle.expiresAt) < Date.now()) {
				this.setStatus("fail-closed");
			} else {
				this.setStatus("cached");
			}
		}
	}

	private writeCache(token: string): void {
		const path = this.bundleCachePath;
		mkdirSync(dirname(path), { recursive: true });
		const tmpPath = `${path}.tmp`;
		writeFileSync(tmpPath, token, { mode: 0o600 });
		renameSync(tmpPath, path);
	}

	private dropCache(): void {
		try {
			rmSync(this.bundleCachePath, { force: true });
		} catch {
			// la cache orfana verrà comunque rifiutata alla scadenza
		}
	}

	private setStatus(status: FleetStatus): void {
		this.status = status;
		this.onStatusChange?.(this);
	}

	// ---- Audit ---------------------------------------------------------------

	pushAudit(type: AuditEvent["type"], data: Record<string, unknown>): void {
		this.auditBuffer.push({
			eventId: newId("evt"),
			deviceId: this.config.deviceId,
			timestamp: new Date().toISOString(),
			type,
			data,
		});
		// Cap difensivo: in caso di control plane irraggiungibile a lungo si
		// scartano gli eventi più vecchi invece di esaurire la memoria.
		if (this.auditBuffer.length > 1000) {
			this.auditBuffer = this.auditBuffer.slice(-1000);
		}
	}

	async flushAudit(fetchImpl: typeof fetch = fetch): Promise<void> {
		if (this.auditBuffer.length === 0) return;
		const batch = this.auditBuffer.slice(0, 200);
		try {
			const response = await fetchImpl(`${this.config.controlPlaneUrl}/api/device/audit`, {
				method: "POST",
				headers: {
					authorization: `Bearer ${this.config.deviceToken}`,
					"content-type": "application/json",
				},
				body: JSON.stringify({ events: batch }),
				signal: AbortSignal.timeout(15_000),
			});
			if (!response.ok) throw new Error(`HTTP ${response.status}`);
			this.auditBuffer = this.auditBuffer.slice(batch.length);
		} catch {
			// Gli eventi restano nel buffer e verranno ritentati al prossimo flush.
		}
	}

	// ---- Cicli in background ---------------------------------------------------

	startLoops(fetchImpl: typeof fetch = fetch): void {
		const syncMs = (this.config.syncIntervalSeconds ?? 60) * 1000;
		const flushMs = (this.config.auditFlushSeconds ?? 10) * 1000;
		const syncTimer = setInterval(() => void this.refresh(fetchImpl), syncMs);
		const flushTimer = setInterval(() => void this.flushAudit(fetchImpl), flushMs);
		syncTimer.unref();
		flushTimer.unref();
		this.timers.push(syncTimer, flushTimer);
	}

	async shutdown(fetchImpl: typeof fetch = fetch): Promise<void> {
		for (const timer of this.timers) clearInterval(timer);
		this.timers = [];
		await this.flushAudit(fetchImpl);
	}

	/** Solo per i test: forza una policy specifica. */
	setPolicyForTesting(policy: PolicyDocument | undefined): void {
		this.policyOverride = policy;
	}
}
