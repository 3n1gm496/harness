import type { AuditEvent, ConfigBundle, DeepPartial, PolicyDocument } from "@harness/shared";
import { deepMerge, lockedPiSettings, newId, newSecretToken, resolvePolicy, signPayload, verifyToken } from "@harness/shared";
import type { DeviceRecord } from "../store.js";
import { hashToken } from "../store.js";
import { type AdminIdentity, ServiceContext, ServiceError, normalizeFingerprint, requireRole } from "./context.js";
import { sanitizeAuditEvent } from "./audit-event.js";

/**
 * Ciclo di vita dei device: emissione dei token di enrollment, arruolamento,
 * emissione del bundle di configurazione firmato, ingest dell'audit dai
 * client, aggiornamento e anteprima della policy effettiva.
 */
export class DeviceService {
	private readonly lastSeenPersist = new Map<string, number>();

	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	/**
	 * Rate limit sull'endpoint di enrollment (non autenticato): condiviso tra
	 * istanze se il backend è Postgres, altrimenti in-memory (vedi
	 * `Store.checkEnrollRateLimit`).
	 */
	async checkEnrollRateLimit(ip: string): Promise<boolean> {
		return this.store.checkEnrollRateLimit(ip);
	}

	createEnrollToken(identity: AdminIdentity, groupId: string, ttlMinutes: number): string {
		requireRole(identity, "operator");
		this.ctx.requireGroup(groupId);
		this.pruneEnrollTokens();
		const token = newSecretToken("enr");
		const now = Date.now();
		this.store.state.enrollTokens[hashToken(token)] = {
			groupId,
			createdAt: new Date(now).toISOString(),
			expiresAt: new Date(now + ttlMinutes * 60_000).toISOString(),
		};
		this.store.save();
		this.ctx.audit(identity.name, "enroll_token_created", { groupId, ttlMinutes });
		return token;
	}

	enrollDevice(
		enrollToken: string,
		deviceName: string,
		certFingerprint?: string,
		deviceSigningPublicKeyPem?: string,
	): { deviceId: string; deviceToken: string; publicKeyPem: string } {
		const tokenHash = hashToken(enrollToken);
		const record = this.store.state.enrollTokens[tokenHash];
		if (!record) throw new ServiceError(401, "token di enrollment non valido");
		if (record.usedBy) throw new ServiceError(401, "token di enrollment già usato");
		if (Date.parse(record.expiresAt) < Date.now()) throw new ServiceError(401, "token di enrollment scaduto");

		if (this.store.state.org.requireDeviceCert && !normalizeFingerprint(certFingerprint)) {
			throw new ServiceError(400, "questa organizzazione richiede un certificato client all'enrollment (mTLS)");
		}
		const deviceId = newId("dev");
		const deviceToken = newSecretToken("dvt");
		const device: DeviceRecord = {
			deviceId,
			name: deviceName || deviceId,
			groupId: record.groupId,
			tokenHash: hashToken(deviceToken),
			tokenIssuedAt: new Date().toISOString(),
			enrolledAt: new Date().toISOString(),
			killSwitch: false,
			revoked: false,
			policyOverride: {},
			piSettingsOverride: {},
		};
		const boundFp = normalizeFingerprint(certFingerprint);
		if (boundFp) device.certFingerprint = boundFp;
		// Chiave di firma propria del device (provenance dei batch di audit): il
		// client la genera all'enrollment e ne consegna solo la pubblica; la
		// privata non lascia mai il device.
		if (deviceSigningPublicKeyPem) device.deviceSigningPublicKeyPem = deviceSigningPublicKeyPem;
		this.store.state.devices[deviceId] = device;
		record.usedBy = deviceId;
		this.store.save();
		this.ctx.audit("system", "device_enrolled", { deviceId, deviceName: device.name, groupId: record.groupId });
		return { deviceId, deviceToken, publicKeyPem: this.store.signingPublicKeyPem };
	}

	/** Costruisce e firma il bundle di configurazione effettivo per un device. */
	issueConfigBundle(device: DeviceRecord): string {
		const { org } = this.store.state;
		const group = this.ctx.requireGroup(device.groupId);

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
			trustedPublicKeys: this.store.trustedPublicKeys(),
		};

		device.lastSeenAt = new Date(now).toISOString();
		device.lastConfigVersion = org.configVersion;
		// Il heartbeat (lastSeenAt/lastConfigVersion) è persistito con throttling
		// per non amplificare le scritture a ogni poll di ogni device.
		this.touchDevice(device.deviceId);
		return signPayload(this.store.signingPrivateKeyPem, bundle);
	}

	/**
	 * Ingest dell'audit di un device. Se il device ha una chiave di firma
	 * propria registrata (`deviceSigningPublicKeyPem`), il batch deve arrivare
	 * firmato con quella chiave (provenance "signed"): un device token rubato
	 * non basta più per iniettare eventi falsi, serve anche la chiave privata
	 * che non lascia mai il device. I device pre-esistenti senza chiave
	 * restano garantiti dal solo device token (provenance "token-only"),
	 * per retrocompatibilità.
	 */
	ingestAudit(device: DeviceRecord, events: unknown[], signature?: string): number {
		let rawEvents: unknown[] = events;
		let provenance: AuditEvent["provenance"] = "token-only";

		if (device.deviceSigningPublicKeyPem) {
			if (!signature) {
				throw new ServiceError(400, "firma del batch richiesta: il device ha una chiave di firma registrata");
			}
			const verified = verifyToken<{ deviceId: string; events: unknown[] }>(
				device.deviceSigningPublicKeyPem,
				signature,
			);
			if (!verified.valid) {
				throw new ServiceError(400, `firma del batch di audit non valida: ${verified.error}`);
			}
			if (verified.payload.deviceId !== device.deviceId) {
				throw new ServiceError(400, "firma del batch emessa per un altro device");
			}
			if (!Array.isArray(verified.payload.events)) {
				throw new ServiceError(400, "payload firmato senza un array di eventi valido");
			}
			rawEvents = verified.payload.events;
			provenance = "signed";
		}

		const sanitized: AuditEvent[] = [];
		for (const raw of rawEvents.slice(0, 500)) {
			const event = sanitizeAuditEvent(raw, device.deviceId);
			if (event) {
				event.provenance = provenance;
				sanitized.push(event);
			}
		}
		this.store.appendDeviceAudit(device.deviceId, sanitized);
		device.lastSeenAt = new Date().toISOString();
		this.touchDevice(device.deviceId);
		return sanitized.length;
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
		requireRole(identity, changesPolicy ? "admin" : "operator");
		const device = this.store.state.devices[deviceId];
		if (!device) throw new ServiceError(404, "device non trovato");
		if (update.groupId !== undefined) {
			this.ctx.requireGroup(update.groupId);
			device.groupId = update.groupId;
		}
		if (update.name !== undefined) device.name = update.name;
		if (update.killSwitch !== undefined) device.killSwitch = update.killSwitch;
		if (update.revoked !== undefined) device.revoked = update.revoked;
		if (update.policyOverride !== undefined) device.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) device.piSettingsOverride = update.piSettingsOverride;
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "device_updated", { deviceId, update });
	}

	/**
	 * Elimina definitivamente un device (retention). Non tocca il suo log di
	 * audit: resta consultabile per stream id e soggetto alla stessa retention
	 * generale (`Store.pruneAudit`), indipendentemente dal ciclo di vita del
	 * device stesso.
	 */
	deleteDevice(identity: AdminIdentity, deviceId: string): void {
		requireRole(identity, "admin");
		const device = this.store.state.devices[deviceId];
		if (!device) throw new ServiceError(404, "device non trovato");
		delete this.store.state.devices[deviceId];
		this.lastSeenPersist.delete(deviceId);
		this.store.save();
		this.ctx.audit(identity.name, "device_deleted", { deviceId, name: device.name });
	}

	/** Anteprima della policy effettiva di un device, come la vedrebbe il client. */
	effectivePolicy(identity: AdminIdentity, deviceId: string): PolicyDocument {
		requireRole(identity, "viewer");
		const device = this.store.state.devices[deviceId];
		if (!device) throw new ServiceError(404, "device non trovato");
		const group = this.ctx.requireGroup(device.groupId);
		const { org } = this.store.state;
		const policy = resolvePolicy(org.policyOverride, group.policyOverride, device.policyOverride);
		policy.killSwitch = policy.killSwitch || org.killSwitch || group.killSwitch || device.killSwitch;
		return policy;
	}

	/** Persiste l'aggiornamento di heartbeat di un device al più ogni 30s. */
	private touchDevice(deviceId: string): void {
		const now = Date.now();
		const last = this.lastSeenPersist.get(deviceId) ?? 0;
		if (now - last < 30_000) return;
		this.lastSeenPersist.set(deviceId, now);
		this.store.save();
	}

	/** Rimuove i token di enrollment scaduti o usati da più di 24 ore. */
	private pruneEnrollTokens(): void {
		const cutoff = Date.now() - 24 * 3_600_000;
		for (const [hash, record] of Object.entries(this.store.state.enrollTokens)) {
			if (Date.parse(record.expiresAt) < cutoff) delete this.store.state.enrollTokens[hash];
		}
	}
}
