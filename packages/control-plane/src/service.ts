import type { AdminRole, AuditEvent, ChainVerification, DeepPartial, PolicyDocument } from "@harness/shared";
import type { DeviceRecord, GroupRecord, Store } from "./store.js";
import { type AdminIdentity, type OidcConfig, ServiceContext, ServiceError } from "./services/context.js";
import { AuthService } from "./services/auth-service.js";
import { DeviceService } from "./services/device-service.js";
import { GroupService } from "./services/group-service.js";
import { OrgService } from "./services/org-service.js";
import { SigningKeyService } from "./services/signing-key-service.js";
import { AuditService } from "./services/audit-service.js";

export { ServiceError } from "./services/context.js";
export type { AdminIdentity, OidcConfig } from "./services/context.js";

/**
 * Facciata del control plane: compone i servizi di dominio focalizzati
 * ({@link AuthService}, {@link DeviceService}, {@link GroupService},
 * {@link OrgService}, {@link SigningKeyService}, {@link AuditService}) su un
 * contesto condiviso e delega. I servizi sono anche esposti come proprietà
 * (`service.auth`, `service.devices`, …) per l'uso diretto; i metodi qui sotto
 * restano per retrocompatibilità dei chiamanti esistenti.
 *
 * Tutte le mutazioni passano dai servizi, incrementano la versione di
 * configurazione e finiscono nell'audit amministrativo.
 */
export class ControlPlaneService {
	readonly auth: AuthService;
	readonly devices: DeviceService;
	readonly groups: GroupService;
	readonly org: OrgService;
	readonly signingKeys: SigningKeyService;
	readonly auditLog: AuditService;

	constructor(store: Store, options: { oidc?: OidcConfig } = {}) {
		const ctx = new ServiceContext(store, options.oidc);
		this.auth = new AuthService(ctx);
		this.devices = new DeviceService(ctx);
		this.groups = new GroupService(ctx);
		this.org = new OrgService(ctx);
		this.signingKeys = new SigningKeyService(ctx);
		this.auditLog = new AuditService(ctx);
	}

	// ---- Autenticazione (AuthService) ---------------------------------------

	authenticateAdmin(token: string | undefined): AdminIdentity {
		return this.auth.authenticateAdmin(token);
	}
	authenticateDevice(token: string | undefined, presentedFingerprint?: string): DeviceRecord {
		return this.auth.authenticateDevice(token, presentedFingerprint);
	}
	authenticateGateway(token: string | undefined): string {
		return this.auth.authenticateGateway(token);
	}
	bindDeviceCertificate(device: DeviceRecord, presentedFingerprint: string | undefined): void {
		this.auth.bindDeviceCertificate(device, presentedFingerprint);
	}
	bootstrapAdminToken(name: string): string {
		return this.auth.bootstrapAdminToken(name);
	}
	createAdminToken(identity: AdminIdentity, name: string, role: AdminRole, ttlDays = 90): string {
		return this.auth.createAdminToken(identity, name, role, ttlDays);
	}
	listAdminTokens(identity: AdminIdentity): { id: string; name: string; role: AdminRole; createdAt: string; expiresAt?: string }[] {
		return this.auth.listAdminTokens(identity);
	}
	revokeAdminToken(identity: AdminIdentity, id: string): void {
		this.auth.revokeAdminToken(identity, id);
	}
	createGatewayToken(identity: AdminIdentity, name: string): string {
		return this.auth.createGatewayToken(identity, name);
	}
	rotateDeviceToken(device: DeviceRecord): string {
		return this.auth.rotateDeviceToken(device);
	}
	introspectDeviceToken(
		deviceToken: string,
		presentedFingerprint?: string,
	): { active: boolean; deviceId?: string; groupId?: string } {
		return this.auth.introspectDeviceToken(deviceToken, presentedFingerprint);
	}

	// ---- Device (DeviceService) ---------------------------------------------

	createEnrollToken(identity: AdminIdentity, groupId: string, ttlMinutes: number): string {
		return this.devices.createEnrollToken(identity, groupId, ttlMinutes);
	}
	enrollDevice(
		enrollToken: string,
		deviceName: string,
		certFingerprint?: string,
	): { deviceId: string; deviceToken: string; publicKeyPem: string } {
		return this.devices.enrollDevice(enrollToken, deviceName, certFingerprint);
	}
	issueConfigBundle(device: DeviceRecord): string {
		return this.devices.issueConfigBundle(device);
	}
	ingestAudit(device: DeviceRecord, events: unknown[]): number {
		return this.devices.ingestAudit(device, events);
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
		this.devices.updateDevice(identity, deviceId, update);
	}
	effectivePolicy(identity: AdminIdentity, deviceId: string): PolicyDocument {
		return this.devices.effectivePolicy(identity, deviceId);
	}

	// ---- Gruppi (GroupService) ----------------------------------------------

	createGroup(identity: AdminIdentity, name: string): GroupRecord {
		return this.groups.createGroup(identity, name);
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
		this.groups.updateGroup(identity, groupId, update);
	}
	deleteGroup(identity: AdminIdentity, groupId: string): void {
		this.groups.deleteGroup(identity, groupId);
	}

	// ---- Organizzazione (OrgService) ----------------------------------------

	overview(identity: AdminIdentity): ReturnType<OrgService["overview"]> {
		return this.org.overview(identity);
	}
	getOrgConfig(identity: AdminIdentity): ReturnType<OrgService["getOrgConfig"]> {
		return this.org.getOrgConfig(identity);
	}
	updateOrg(identity: AdminIdentity, update: Parameters<OrgService["updateOrg"]>[1]): void {
		this.org.updateOrg(identity, update);
	}

	// ---- Chiavi di firma (SigningKeyService) --------------------------------

	listSigningKeys(identity: AdminIdentity): { keyId: string; createdAt: string; active: boolean }[] {
		return this.signingKeys.listSigningKeys(identity);
	}
	addSigningKey(identity: AdminIdentity): { keyId: string } {
		return this.signingKeys.addSigningKey(identity);
	}
	promoteSigningKey(identity: AdminIdentity, keyId: string): void {
		this.signingKeys.promoteSigningKey(identity, keyId);
	}
	retireSigningKey(identity: AdminIdentity, keyId: string): void {
		this.signingKeys.retireSigningKey(identity, keyId);
	}

	// ---- Audit (AuditService) -----------------------------------------------

	async readDeviceAudit(identity: AdminIdentity, deviceId: string, limit: number): Promise<AuditEvent[]> {
		return this.auditLog.readDeviceAudit(identity, deviceId, limit);
	}
	async readAdminAudit(identity: AdminIdentity, limit: number): Promise<unknown[]> {
		return this.auditLog.readAdminAudit(identity, limit);
	}
	async verifyAudit(identity: AdminIdentity, deviceId?: string): Promise<ChainVerification> {
		return this.auditLog.verifyAudit(identity, deviceId);
	}
	async exportAuditAnchor(identity: AdminIdentity): Promise<{ anchor: string; publicKeyPem: string }> {
		return this.auditLog.exportAuditAnchor(identity);
	}
}
