import type {
	AdminRole,
	AuditEvent,
	ConfigBundle,
	DeepPartial,
	DeviceInfo,
	GroupInfo,
	PolicyDocument,
} from "@harness/shared";
import { deepMerge, lockedPiSettings, newId, newSecretToken, resolvePolicy, signPayload } from "@harness/shared";
import type { AdminTokenRecord, DeviceRecord, GroupRecord, Store } from "./store.js";
import { hashToken } from "./store.js";

export class ServiceError extends Error {
	readonly status: number;
	constructor(status: number, message: string) {
		super(message);
		this.status = status;
	}
}

export interface AdminIdentity {
	name: string;
	role: AdminRole;
}

const ROLE_LEVEL: Record<AdminRole, number> = { viewer: 1, operator: 2, admin: 3 };

/**
 * Logica applicativa del control plane. Tutte le mutazioni passano da qui,
 * incrementano la versione di configurazione e finiscono nell'audit
 * amministrativo.
 */
export class ControlPlaneService {
	constructor(private readonly store: Store) {}

	// ---- Autenticazione -----------------------------------------------------

	authenticateAdmin(token: string | undefined): AdminIdentity {
		if (!token) throw new ServiceError(401, "token amministrativo mancante");
		const record: AdminTokenRecord | undefined = this.store.state.adminTokens[hashToken(token)];
		if (!record) throw new ServiceError(401, "token amministrativo non valido");
		return { name: record.name, role: record.role };
	}

	requireRole(identity: AdminIdentity, minimum: AdminRole): void {
		if (ROLE_LEVEL[identity.role] < ROLE_LEVEL[minimum]) {
			throw new ServiceError(403, `operazione riservata al ruolo ${minimum} o superiore`);
		}
	}

	authenticateDevice(token: string | undefined): DeviceRecord {
		if (!token) throw new ServiceError(401, "token device mancante");
		const tokenHash = hashToken(token);
		const device = Object.values(this.store.state.devices).find((d) => d.tokenHash === tokenHash);
		if (!device) throw new ServiceError(401, "token device non valido");
		if (device.revoked) throw new ServiceError(403, "device revocato");
		return device;
	}

	authenticateGateway(token: string | undefined): string {
		if (!token) throw new ServiceError(401, "token gateway mancante");
		const record = this.store.state.gatewayTokens[hashToken(token)];
		if (!record) throw new ServiceError(401, "token gateway non valido");
		return record.name;
	}

	// ---- Bootstrap ----------------------------------------------------------

	/** Crea il primo token admin. Consentito solo finché non ne esiste alcuno. */
	bootstrapAdminToken(name: string): string {
		if (Object.keys(this.store.state.adminTokens).length > 0) {
			throw new ServiceError(409, "bootstrap già eseguito: esiste già un token amministrativo");
		}
		const token = newSecretToken("adm");
		this.store.state.adminTokens[hashToken(token)] = {
			name,
			role: "admin",
			createdAt: new Date().toISOString(),
		};
		this.store.save();
		return token;
	}

	// ---- Enrollment e device ------------------------------------------------

	createEnrollToken(identity: AdminIdentity, groupId: string, ttlMinutes: number): string {
		this.requireRole(identity, "operator");
		this.requireGroup(groupId);
		const token = newSecretToken("enr");
		const now = Date.now();
		this.store.state.enrollTokens[hashToken(token)] = {
			groupId,
			createdAt: new Date(now).toISOString(),
			expiresAt: new Date(now + ttlMinutes * 60_000).toISOString(),
		};
		this.store.save();
		this.audit(identity.name, "enroll_token_created", { groupId, ttlMinutes });
		return token;
	}

	enrollDevice(enrollToken: string, deviceName: string): { deviceId: string; deviceToken: string; publicKeyPem: string } {
		const tokenHash = hashToken(enrollToken);
		const record = this.store.state.enrollTokens[tokenHash];
		if (!record) throw new ServiceError(401, "token di enrollment non valido");
		if (record.usedBy) throw new ServiceError(401, "token di enrollment già usato");
		if (Date.parse(record.expiresAt) < Date.now()) throw new ServiceError(401, "token di enrollment scaduto");

		const deviceId = newId("dev");
		const deviceToken = newSecretToken("dvt");
		const device: DeviceRecord = {
			deviceId,
			name: deviceName || deviceId,
			groupId: record.groupId,
			tokenHash: hashToken(deviceToken),
			enrolledAt: new Date().toISOString(),
			killSwitch: false,
			revoked: false,
			policyOverride: {},
			piSettingsOverride: {},
		};
		this.store.state.devices[deviceId] = device;
		record.usedBy = deviceId;
		this.store.save();
		this.audit("system", "device_enrolled", { deviceId, deviceName: device.name, groupId: record.groupId });
		return { deviceId, deviceToken, publicKeyPem: this.store.signingPublicKeyPem };
	}

	/** Costruisce e firma il bundle di configurazione effettivo per un device. */
	issueConfigBundle(device: DeviceRecord): string {
		const { org } = this.store.state;
		const group = this.requireGroup(device.groupId);

		const policy: PolicyDocument = resolvePolicy(org.policyOverride, group.policyOverride, device.policyOverride);
		policy.killSwitch = policy.killSwitch || org.killSwitch || group.killSwitch || device.killSwitch;

		let piSettings: Record<string, unknown> = {};
		piSettings = deepMerge(piSettings, org.piSettingsOverride);
		piSettings = deepMerge(piSettings, group.piSettingsOverride);
		piSettings = deepMerge(piSettings, device.piSettingsOverride);
		// I lockdown aziendali vincono sempre su qualunque override.
		piSettings = deepMerge(piSettings, lockedPiSettings());

		const now = Date.now();
		const bundle: ConfigBundle = {
			schema: "harness/config-bundle@1",
			bundleId: newId("bnd"),
			orgId: org.orgId,
			groupId: group.groupId,
			deviceId: device.deviceId,
			configVersion: org.configVersion,
			issuedAt: new Date(now).toISOString(),
			expiresAt: new Date(now + org.configTtlMinutes * 60_000).toISOString(),
			policy,
			piSettings,
		};

		device.lastSeenAt = new Date(now).toISOString();
		device.lastConfigVersion = org.configVersion;
		this.store.save();
		return signPayload(this.store.signingPrivateKeyPem, bundle);
	}

	ingestAudit(device: DeviceRecord, events: AuditEvent[]): number {
		const sanitized = events.slice(0, 500).map((event) => ({
			...event,
			deviceId: device.deviceId, // il device non può impersonarne un altro
		}));
		this.store.appendDeviceAudit(device.deviceId, sanitized);
		device.lastSeenAt = new Date().toISOString();
		this.store.save();
		return sanitized.length;
	}

	// ---- Amministrazione ----------------------------------------------------

	overview(identity: AdminIdentity): {
		org: { orgId: string; name: string; configVersion: number; killSwitch: boolean; configTtlMinutes: number };
		groups: GroupInfo[];
		devices: DeviceInfo[];
	} {
		this.requireRole(identity, "viewer");
		const { org, groups, devices } = this.store.state;
		return {
			org: {
				orgId: org.orgId,
				name: org.name,
				configVersion: org.configVersion,
				killSwitch: org.killSwitch,
				configTtlMinutes: org.configTtlMinutes,
			},
			groups: Object.values(groups).map((group) => ({
				groupId: group.groupId,
				name: group.name,
				killSwitch: group.killSwitch,
				policyOverride: group.policyOverride,
				piSettingsOverride: group.piSettingsOverride,
			})),
			devices: Object.values(devices).map((device) => this.toDeviceInfo(device)),
		};
	}

	getOrgConfig(identity: AdminIdentity): {
		policyOverride: DeepPartial<PolicyDocument>;
		piSettingsOverride: Record<string, unknown>;
	} {
		this.requireRole(identity, "viewer");
		return {
			policyOverride: this.store.state.org.policyOverride,
			piSettingsOverride: this.store.state.org.piSettingsOverride,
		};
	}

	updateOrg(
		identity: AdminIdentity,
		update: {
			name?: string;
			killSwitch?: boolean;
			configTtlMinutes?: number;
			policyOverride?: DeepPartial<PolicyDocument>;
			piSettingsOverride?: Record<string, unknown>;
		},
	): void {
		const changesPolicy = update.policyOverride !== undefined || update.piSettingsOverride !== undefined;
		this.requireRole(identity, changesPolicy || update.configTtlMinutes !== undefined ? "admin" : "operator");
		const { org } = this.store.state;
		if (update.name !== undefined) org.name = update.name;
		if (update.killSwitch !== undefined) org.killSwitch = update.killSwitch;
		if (update.configTtlMinutes !== undefined) {
			if (update.configTtlMinutes < 5 || update.configTtlMinutes > 24 * 60) {
				throw new ServiceError(400, "configTtlMinutes deve essere tra 5 e 1440");
			}
			org.configTtlMinutes = update.configTtlMinutes;
		}
		if (update.policyOverride !== undefined) org.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) org.piSettingsOverride = update.piSettingsOverride;
		this.bumpConfig();
		this.audit(identity.name, "org_updated", { update });
	}

	createGroup(identity: AdminIdentity, name: string): GroupRecord {
		this.requireRole(identity, "admin");
		if (!name.trim()) throw new ServiceError(400, "nome gruppo mancante");
		const group: GroupRecord = {
			groupId: newId("grp"),
			name: name.trim(),
			killSwitch: false,
			policyOverride: {},
			piSettingsOverride: {},
		};
		this.store.state.groups[group.groupId] = group;
		this.bumpConfig();
		this.audit(identity.name, "group_created", { groupId: group.groupId, name: group.name });
		return group;
	}

	updateGroup(
		identity: AdminIdentity,
		groupId: string,
		update: {
			name?: string;
			killSwitch?: boolean;
			policyOverride?: DeepPartial<PolicyDocument>;
			piSettingsOverride?: Record<string, unknown>;
		},
	): void {
		const changesPolicy = update.policyOverride !== undefined || update.piSettingsOverride !== undefined;
		this.requireRole(identity, changesPolicy ? "admin" : "operator");
		const group = this.requireGroup(groupId);
		if (update.name !== undefined) group.name = update.name;
		if (update.killSwitch !== undefined) group.killSwitch = update.killSwitch;
		if (update.policyOverride !== undefined) group.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) group.piSettingsOverride = update.piSettingsOverride;
		this.bumpConfig();
		this.audit(identity.name, "group_updated", { groupId, update });
	}

	deleteGroup(identity: AdminIdentity, groupId: string): void {
		this.requireRole(identity, "admin");
		this.requireGroup(groupId);
		const inUse = Object.values(this.store.state.devices).some((device) => device.groupId === groupId);
		if (inUse) throw new ServiceError(409, "il gruppo ha device associati");
		delete this.store.state.groups[groupId];
		this.bumpConfig();
		this.audit(identity.name, "group_deleted", { groupId });
	}

	updateDevice(
		identity: AdminIdentity,
		deviceId: string,
		update: {
			name?: string;
			groupId?: string;
			killSwitch?: boolean;
			revoked?: boolean;
			policyOverride?: DeepPartial<PolicyDocument>;
			piSettingsOverride?: Record<string, unknown>;
		},
	): void {
		const changesPolicy = update.policyOverride !== undefined || update.piSettingsOverride !== undefined;
		this.requireRole(identity, changesPolicy ? "admin" : "operator");
		const device = this.store.state.devices[deviceId];
		if (!device) throw new ServiceError(404, "device non trovato");
		if (update.groupId !== undefined) {
			this.requireGroup(update.groupId);
			device.groupId = update.groupId;
		}
		if (update.name !== undefined) device.name = update.name;
		if (update.killSwitch !== undefined) device.killSwitch = update.killSwitch;
		if (update.revoked !== undefined) device.revoked = update.revoked;
		if (update.policyOverride !== undefined) device.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) device.piSettingsOverride = update.piSettingsOverride;
		this.bumpConfig();
		this.audit(identity.name, "device_updated", { deviceId, update });
	}

	/** Anteprima della policy effettiva di un device, come la vedrebbe il client. */
	effectivePolicy(identity: AdminIdentity, deviceId: string): PolicyDocument {
		this.requireRole(identity, "viewer");
		const device = this.store.state.devices[deviceId];
		if (!device) throw new ServiceError(404, "device non trovato");
		const group = this.requireGroup(device.groupId);
		const { org } = this.store.state;
		const policy = resolvePolicy(org.policyOverride, group.policyOverride, device.policyOverride);
		policy.killSwitch = policy.killSwitch || org.killSwitch || group.killSwitch || device.killSwitch;
		return policy;
	}

	async readDeviceAudit(identity: AdminIdentity, deviceId: string, limit: number): Promise<AuditEvent[]> {
		this.requireRole(identity, "viewer");
		return this.store.readDeviceAudit(deviceId, Math.min(Math.max(limit, 1), 1000));
	}

	async readAdminAudit(identity: AdminIdentity, limit: number): Promise<unknown[]> {
		this.requireRole(identity, "viewer");
		return this.store.readAdminAudit(Math.min(Math.max(limit, 1), 1000));
	}

	createAdminToken(identity: AdminIdentity, name: string, role: AdminRole): string {
		this.requireRole(identity, "admin");
		if (!["admin", "operator", "viewer"].includes(role)) throw new ServiceError(400, "ruolo non valido");
		const token = newSecretToken("adm");
		this.store.state.adminTokens[hashToken(token)] = { name, role, createdAt: new Date().toISOString() };
		this.store.save();
		this.audit(identity.name, "admin_token_created", { name, role });
		return token;
	}

	createGatewayToken(identity: AdminIdentity, name: string): string {
		this.requireRole(identity, "admin");
		const token = newSecretToken("gwt");
		this.store.state.gatewayTokens[hashToken(token)] = { name, createdAt: new Date().toISOString() };
		this.store.save();
		this.audit(identity.name, "gateway_token_created", { name });
		return token;
	}

	/** Introspezione dei device token per il gateway LLM. */
	introspectDeviceToken(deviceToken: string): { active: boolean; deviceId?: string; groupId?: string } {
		const tokenHash = hashToken(deviceToken);
		const device = Object.values(this.store.state.devices).find((d) => d.tokenHash === tokenHash);
		if (!device || device.revoked) return { active: false };
		const killSwitch =
			device.killSwitch || this.store.state.org.killSwitch || this.store.state.groups[device.groupId]?.killSwitch;
		if (killSwitch) return { active: false };
		return { active: true, deviceId: device.deviceId, groupId: device.groupId };
	}

	// ---- Interni ------------------------------------------------------------

	private toDeviceInfo(device: DeviceRecord): DeviceInfo {
		const info: DeviceInfo = {
			deviceId: device.deviceId,
			name: device.name,
			groupId: device.groupId,
			enrolledAt: device.enrolledAt,
			killSwitch: device.killSwitch,
			revoked: device.revoked,
		};
		if (device.lastSeenAt !== undefined) info.lastSeenAt = device.lastSeenAt;
		if (device.lastConfigVersion !== undefined) info.lastConfigVersion = device.lastConfigVersion;
		return info;
	}

	private requireGroup(groupId: string): GroupRecord {
		const group = this.store.state.groups[groupId];
		if (!group) throw new ServiceError(404, `gruppo non trovato: ${groupId}`);
		return group;
	}

	private bumpConfig(): void {
		this.store.state.org.configVersion += 1;
		this.store.save();
	}

	private audit(actor: string, action: string, detail: Record<string, unknown>): void {
		this.store.appendAdminAudit({ timestamp: new Date().toISOString(), actor, action, detail });
	}
}
