import { createHash } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import type { AdminRole, AuditEvent, ChainVerification, ChainedEntry, DeepPartial, PolicyDocument } from "@harness/shared";
import { CHAIN_GENESIS, chainEntry, generateSigningKeyPair, newId, verifyChain } from "@harness/shared";

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
export class Store {
	readonly dataDir: string;
	private readonly statePath: string;
	private readonly auditDir: string;
	private readonly adminAuditPath: string;
	state: ControlPlaneState;
	signingPrivateKeyPem: string;
	signingPublicKeyPem: string;

	constructor(dataDir: string) {
		this.dataDir = dataDir;
		this.statePath = join(dataDir, "state.json");
		this.auditDir = join(dataDir, "audit");
		this.adminAuditPath = join(dataDir, "admin-audit.jsonl");
		mkdirSync(this.auditDir, { recursive: true });
		mkdirSync(join(dataDir, "keys"), { recursive: true });

		const privateKeyPath = join(dataDir, "keys", "config-signing.key");
		const publicKeyPath = join(dataDir, "keys", "config-signing.pub");
		if (!existsSync(privateKeyPath)) {
			const keys = generateSigningKeyPair();
			writeFileSync(privateKeyPath, keys.privateKeyPem, { mode: 0o600 });
			writeFileSync(publicKeyPath, keys.publicKeyPem, { mode: 0o644 });
		}
		this.signingPrivateKeyPem = readFileSync(privateKeyPath, "utf8");
		this.signingPublicKeyPem = readFileSync(publicKeyPath, "utf8");

		this.state = existsSync(this.statePath)
			? (JSON.parse(readFileSync(this.statePath, "utf8")) as ControlPlaneState)
			: this.initialState();
		this.save();
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
