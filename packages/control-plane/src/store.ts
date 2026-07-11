import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type {
	AdminRole,
	AuditEvent,
	ChainVerification,
	ChainedEntry,
	DeepPartial,
	Kek,
	PolicyDocument,
} from "@harness/shared";
import {
	CHAIN_GENESIS,
	chainEntry,
	generateSigningKeyPair,
	isSealed,
	newId,
	openPrivateKey,
	sealPrivateKey,
	verifyChain,
} from "@harness/shared";

export interface OrgRecord {
	orgId: string;
	name: string;
	/** Incrementato a ogni mutazione amministrativa; i device lo vedono nel bundle. */
	configVersion: number;
	killSwitch: boolean;
	/** Minuti di validità dei bundle firmati (finestra fail-closed). */
	configTtlMinutes: number;
	policyOverride: DeepPartial<PolicyDocument>;
	piSettingsOverride: Record<string, unknown>;
}

export interface GroupRecord {
	groupId: string;
	name: string;
	killSwitch: boolean;
	policyOverride: DeepPartial<PolicyDocument>;
	piSettingsOverride: Record<string, unknown>;
}

export interface DeviceRecord {
	deviceId: string;
	name: string;
	groupId: string;
	tokenHash: string;
	enrolledAt: string;
	lastSeenAt?: string;
	lastConfigVersion?: number;
	killSwitch: boolean;
	revoked: boolean;
	policyOverride: DeepPartial<PolicyDocument>;
	piSettingsOverride: Record<string, unknown>;
	/**
	 * Fingerprint SHA-256 (hex, senza separatori) del certificato client mTLS
	 * legato al device. Se presente, le richieste del device devono presentare
	 * quel certificato: un token rubato non basta senza la chiave privata.
	 */
	certFingerprint?: string;
}

export interface EnrollTokenRecord {
	groupId: string;
	createdAt: string;
	expiresAt: string;
	usedBy?: string;
}

export interface AdminTokenRecord {
	name: string;
	role: AdminRole;
	createdAt: string;
	/** Assente = senza scadenza (solo il token di bootstrap). */
	expiresAt?: string;
}

export interface GatewayTokenRecord {
	name: string;
	createdAt: string;
}

export interface ControlPlaneState {
	org: OrgRecord;
	groups: Record<string, GroupRecord>;
	devices: Record<string, DeviceRecord>;
	/** Chiave: sha256 esadecimale del token; il token in chiaro non viene mai persistito. */
	enrollTokens: Record<string, EnrollTokenRecord>;
	adminTokens: Record<string, AdminTokenRecord>;
	gatewayTokens: Record<string, GatewayTokenRecord>;
}

export interface AdminAuditEntry {
	timestamp: string;
	actor: string;
	action: string;
	detail: Record<string, unknown>;
}

export function hashToken(token: string): string {
	return createHash("sha256").update(token, "utf8").digest("hex");
}

/**
 * Persistenza su file JSON con scritture atomiche (tmp + rename) e audit su
 * file JSONL append-only. Interfaccia minima pensata per essere sostituita
 * da Postgres senza toccare il livello di servizio.
 */
export interface SigningKeyRecord {
	keyId: string;
	publicKeyPem: string;
	privateKeyPem: string;
	createdAt: string;
	/** La chiave attiva è quella usata per firmare i nuovi bundle. */
	active: boolean;
}

export class Store {
	readonly dataDir: string;
	private readonly statePath: string;
	private readonly auditDir: string;
	private readonly adminAuditPath: string;
	private readonly signingKeysPath: string;
	state: ControlPlaneState;
	private signingKeys: SigningKeyRecord[];
	/** Backend durevole opzionale (Postgres); il file resta cache locale. */
	private mirror: import("./state-store.js").DurableStateStore | undefined;
	/** Catena di persistenza write-behind verso il mirror. */
	private pending: Promise<void> = Promise.resolve();
	lastMirrorError = "";

	/** KEK per l'envelope encryption delle chiavi private a riposo (opzionale in file mode). */
	private readonly kek: Kek | undefined;

	constructor(dataDir: string, options: { kek?: Kek } = {}) {
		this.dataDir = dataDir;
		this.kek = options.kek;
		this.statePath = join(dataDir, "state.json");
		this.auditDir = join(dataDir, "audit");
		this.adminAuditPath = join(dataDir, "admin-audit.jsonl");
		this.signingKeysPath = join(dataDir, "keys", "signing-keys.json");
		mkdirSync(this.auditDir, { recursive: true });
		mkdirSync(join(dataDir, "keys"), { recursive: true });

		this.signingKeys = this.loadSigningKeys();
		if (!this.kek) {
			console.warn(
				"[control-plane] ATTENZIONE: HARNESS_SIGNING_KEK non impostata — le chiavi private di firma sono a riposo in chiaro (0600). Imponila in produzione.",
			);
		} else {
			// Migrazione: se le chiavi erano in chiaro, risigillale ora.
			this.persistSigningKeys(this.signingKeys);
		}

		this.state = existsSync(this.statePath)
			? (JSON.parse(readFileSync(this.statePath, "utf8")) as ControlPlaneState)
			: this.initialState();
		this.save();
	}

	/**
	 * Apre uno Store con un backend di stato durevole (es. Postgres). Se il
	 * backend contiene già uno snapshot, lo stato viene idratato da lì (fonte di
	 * verità); altrimenti lo stato locale corrente viene salvato nel backend.
	 * I salvataggi successivi sono write-behind: `save()` resta sincrono e
	 * mirror-a il backend in background; `flush()` ne attende il completamento.
	 */
	static async openWithBackend(
		dataDir: string,
		backend: import("./state-store.js").DurableStateStore,
		options: { kek?: Kek } = {},
	): Promise<Store> {
		if (!options.kek) {
			throw new Error(
				"backend Postgres richiede HARNESS_SIGNING_KEK: senza, le chiavi private finirebbero in chiaro nel database",
			);
		}
		const store = new Store(dataDir, { kek: options.kek });
		store.mirror = backend;
		const snapshot = await backend.load();
		if (snapshot) {
			store.state = snapshot.state;
			store.signingKeys = store.openKeys(snapshot.signingKeys);
		} else {
			await backend.save({ state: store.state, signingKeys: store.sealKeys(store.signingKeys) });
		}
		return store;
	}

	/** Sigilla le chiavi private per la persistenza (no-op se KEK assente). */
	private sealKeys(keys: SigningKeyRecord[]): SigningKeyRecord[] {
		if (!this.kek) return keys;
		const kek = this.kek;
		return keys.map((k) => ({
			...k,
			privateKeyPem: isSealed(k.privateKeyPem) ? k.privateKeyPem : sealPrivateKey(kek, k.privateKeyPem),
		}));
	}

	/** Apre le chiavi private lette da persistenza (decifra se sigillate). */
	private openKeys(keys: SigningKeyRecord[]): SigningKeyRecord[] {
		return keys.map((k) => {
			if (!isSealed(k.privateKeyPem)) return k;
			if (!this.kek) throw new Error("chiave di firma sigillata ma HARNESS_SIGNING_KEK non impostata");
			return { ...k, privateKeyPem: openPrivateKey(this.kek, k.privateKeyPem) };
		});
	}

	private mirrorNow(): void {
		if (!this.mirror) return;
		const backend = this.mirror;
		const snapshot = structuredClone({ state: this.state, signingKeys: this.sealKeys(this.signingKeys) });
		this.pending = this.pending
			.then(() => backend.save(snapshot))
			.then(() => {
				this.lastMirrorError = "";
			})
			.catch((error: unknown) => {
				this.lastMirrorError = error instanceof Error ? error.message : String(error);
			});
	}

	/** Attende il completamento delle scritture write-behind verso il backend. */
	async flush(): Promise<void> {
		await this.pending;
	}

	async close(): Promise<void> {
		await this.flush();
		if (this.mirror) await this.mirror.close();
	}

	// ---- Chiavi di firma -----------------------------------------------------

	private loadSigningKeys(): SigningKeyRecord[] {
		if (existsSync(this.signingKeysPath)) {
			const stored = JSON.parse(readFileSync(this.signingKeysPath, "utf8")) as SigningKeyRecord[];
			return this.openKeys(stored);
		}
		// Migrazione dalla chiave singola legacy, se presente.
		const legacyPriv = join(this.dataDir, "keys", "config-signing.key");
		const legacyPub = join(this.dataDir, "keys", "config-signing.pub");
		let key: SigningKeyRecord;
		if (existsSync(legacyPriv) && existsSync(legacyPub)) {
			key = {
				keyId: newId("key"),
				publicKeyPem: readFileSync(legacyPub, "utf8"),
				privateKeyPem: readFileSync(legacyPriv, "utf8"),
				createdAt: new Date().toISOString(),
				active: true,
			};
		} else {
			const generated = generateSigningKeyPair();
			key = {
				keyId: newId("key"),
				publicKeyPem: generated.publicKeyPem,
				privateKeyPem: generated.privateKeyPem,
				createdAt: new Date().toISOString(),
				active: true,
			};
		}
		const keys = [key];
		this.persistSigningKeys(keys);
		// Mantiene anche il .pub in chiaro per comodità operativa (pinning al primo enroll).
		writeFileSync(legacyPub, key.publicKeyPem, { mode: 0o644 });
		return keys;
	}

	private persistSigningKeys(keys: SigningKeyRecord[]): void {
		const tmp = `${this.signingKeysPath}.tmp`;
		// Sigilla le chiavi private prima di scriverle su disco.
		writeFileSync(tmp, JSON.stringify(this.sealKeys(keys), null, "\t"), { mode: 0o600 });
		renameSync(tmp, this.signingKeysPath);
		this.mirrorNow();
	}

	get activeSigningKey(): SigningKeyRecord {
		const active = this.signingKeys.find((k) => k.active);
		if (!active) throw new Error("nessuna chiave di firma attiva");
		return active;
	}

	/** Tutte le chiavi pubbliche attualmente valide per la verifica. */
	trustedPublicKeys(): string[] {
		return this.signingKeys.map((k) => k.publicKeyPem);
	}

	/** Chiave pubblica attiva, usata come pin al momento dell'enrollment. */
	get signingPublicKeyPem(): string {
		return this.activeSigningKey.publicKeyPem;
	}

	get signingPrivateKeyPem(): string {
		return this.activeSigningKey.privateKeyPem;
	}

	/**
	 * Fase 1 della rotazione: genera una nuova chiave e la aggiunge al set
	 * fidato SENZA renderla attiva. I bundle continuano a essere firmati con la
	 * chiave attiva (che i device già fidano) e ne elencano la nuova in
	 * `trustedPublicKeys`: così i client la apprendono prima che diventi attiva.
	 */
	addSigningKey(): SigningKeyRecord {
		const generated = generateSigningKeyPair();
		const fresh: SigningKeyRecord = {
			keyId: newId("key"),
			publicKeyPem: generated.publicKeyPem,
			privateKeyPem: generated.privateKeyPem,
			createdAt: new Date().toISOString(),
			active: false,
		};
		this.signingKeys.push(fresh);
		this.persistSigningKeys(this.signingKeys);
		return fresh;
	}

	/**
	 * Fase 2: promuove una chiave già presente ad attiva (usata per firmare).
	 * Va fatto solo dopo che i device hanno avuto tempo di apprenderla.
	 */
	promoteSigningKey(keyId: string): void {
		const target = this.signingKeys.find((k) => k.keyId === keyId);
		if (!target) throw new Error("chiave non trovata");
		for (const key of this.signingKeys) key.active = key.keyId === keyId;
		this.persistSigningKeys(this.signingKeys);
	}

	/** Fase 3: ritira una vecchia chiave (non più valida per la verifica). */
	retireSigningKey(keyId: string): void {
		const target = this.signingKeys.find((k) => k.keyId === keyId);
		if (!target) throw new Error("chiave non trovata");
		if (target.active) throw new Error("impossibile ritirare la chiave attiva");
		if (this.signingKeys.length <= 1) throw new Error("impossibile ritirare l'unica chiave rimasta");
		this.signingKeys = this.signingKeys.filter((k) => k.keyId !== keyId);
		this.persistSigningKeys(this.signingKeys);
	}

	listSigningKeys(): { keyId: string; createdAt: string; active: boolean }[] {
		return this.signingKeys.map((k) => ({ keyId: k.keyId, createdAt: k.createdAt, active: k.active }));
	}

	private initialState(): ControlPlaneState {
		const defaultGroup: GroupRecord = {
			groupId: newId("grp"),
			name: "default",
			killSwitch: false,
			policyOverride: {},
			piSettingsOverride: {},
		};
		return {
			org: {
				orgId: newId("org"),
				name: "organizzazione",
				configVersion: 1,
				killSwitch: false,
				configTtlMinutes: 60,
				policyOverride: {},
				piSettingsOverride: {},
			},
			groups: { [defaultGroup.groupId]: defaultGroup },
			devices: {},
			enrollTokens: {},
			adminTokens: {},
			gatewayTokens: {},
		};
	}

	save(): void {
		const tmpPath = `${this.statePath}.tmp`;
		writeFileSync(tmpPath, JSON.stringify(this.state, null, "\t"), { mode: 0o600 });
		renameSync(tmpPath, this.statePath);
		this.mirrorNow();
	}

	/** Ultimo hash della catena per file di audit, per l'append incrementale. */
	private chainTips = new Map<string, string>();

	appendDeviceAudit(deviceId: string, events: AuditEvent[]): void {
		if (events.length === 0) return;
		this.appendChained(this.deviceAuditPath(deviceId), events);
	}

	async readDeviceAudit(deviceId: string, limit: number): Promise<AuditEvent[]> {
		return (await this.readChained<AuditEvent>(this.deviceAuditPath(deviceId), limit)).map((line) => line.entry);
	}

	appendAdminAudit(entry: AdminAuditEntry): void {
		this.appendChained(this.adminAuditPath, [entry]);
	}

	async readAdminAudit(limit: number): Promise<AdminAuditEntry[]> {
		return (await this.readChained<AdminAuditEntry>(this.adminAuditPath, limit)).map((line) => line.entry);
	}

	/** Verifica l'integrità dell'intera catena di un log di audit. */
	async verifyDeviceAudit(deviceId: string): Promise<ChainVerification> {
		return this.verifyChainedFile(this.deviceAuditPath(deviceId));
	}

	async verifyAdminAudit(): Promise<ChainVerification> {
		return this.verifyChainedFile(this.adminAuditPath);
	}

	/**
	 * Teste delle catene di audit (admin + tutti i device): hash finale e numero
	 * di righe di ciascuna. Serve a costruire un anchor firmato da ancorare su
	 * storage esterno WORM: chi verifica in seguito confronta la catena con la
	 * testa ancorata e scopre qualunque troncamento o manomissione retroattiva.
	 */
	async auditHeads(): Promise<{
		admin: { head: string; entries: number };
		devices: { deviceId: string; head: string; entries: number }[];
	}> {
		const admin = await this.chainHeadAndCount(this.adminAuditPath);
		const devices: { deviceId: string; head: string; entries: number }[] = [];
		for (const deviceId of Object.keys(this.state.devices)) {
			const info = await this.chainHeadAndCount(this.deviceAuditPath(deviceId));
			devices.push({ deviceId, ...info });
		}
		return { admin, devices };
	}

	private async chainHeadAndCount(path: string): Promise<{ head: string; entries: number }> {
		if (!existsSync(path)) return { head: CHAIN_GENESIS, entries: 0 };
		const content = await readFile(path, "utf8");
		const lines = content.split("\n").filter((line) => line.trim() !== "");
		const last = lines.at(-1);
		let head = CHAIN_GENESIS;
		if (last) {
			try {
				head = (JSON.parse(last) as ChainedEntry<unknown>).hash;
			} catch {
				head = CHAIN_GENESIS;
			}
		}
		return { head, entries: lines.length };
	}

	private deviceAuditPath(deviceId: string): string {
		const safeId = deviceId.replaceAll(/[^A-Za-z0-9_-]/g, "_");
		return join(this.auditDir, `${safeId}.jsonl`);
	}

	private appendChained(path: string, entries: unknown[]): void {
		let prev = this.chainTip(path);
		const lines: string[] = [];
		for (const entry of entries) {
			const chained = chainEntry(prev, entry);
			lines.push(JSON.stringify(chained));
			prev = chained.hash;
		}
		appendFileSync(path, `${lines.join("\n")}\n`, { mode: 0o600 });
		this.chainTips.set(path, prev);
	}

	/** Recupera (o ricostruisce dall'ultima riga) la testa della catena di un file. */
	private chainTip(path: string): string {
		const cached = this.chainTips.get(path);
		if (cached !== undefined) return cached;
		if (!existsSync(path)) return CHAIN_GENESIS;
		const content = readFileSync(path, "utf8");
		const lines = content.split("\n").filter((line) => line.trim() !== "");
		const last = lines.at(-1);
		if (!last) return CHAIN_GENESIS;
		try {
			return (JSON.parse(last) as ChainedEntry<unknown>).hash;
		} catch {
			return CHAIN_GENESIS;
		}
	}

	private async readChained<T>(path: string, limit: number): Promise<ChainedEntry<T>[]> {
		if (!existsSync(path)) return [];
		const content = await readFile(path, "utf8");
		const lines = content.split("\n").filter((line) => line.trim() !== "");
		return lines.slice(-limit).map((line) => JSON.parse(line) as ChainedEntry<T>);
	}

	private async verifyChainedFile(path: string): Promise<ChainVerification> {
		if (!existsSync(path)) return { valid: true, entries: 0 };
		const content = await readFile(path, "utf8");
		const lines = content.split("\n").filter((line) => line.trim() !== "");
		return verifyChain(lines);
	}
}
