import type { AuditAnchor, AuditEvent, ChainVerification } from "@harness/shared";
import { signPayload } from "@harness/shared";
import { type AdminIdentity, requireRole, type ServiceContext } from "./context.js";

/** Lettura, verifica e ancoraggio esterno delle catene di audit. */
export class AuditService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	async readDeviceAudit(identity: AdminIdentity, deviceId: string, limit: number): Promise<AuditEvent[]> {
		requireRole(identity, "viewer");
		return this.store.readDeviceAudit(deviceId, Math.min(Math.max(limit, 1), 1000));
	}

	async readAdminAudit(identity: AdminIdentity, limit: number): Promise<unknown[]> {
		requireRole(identity, "viewer");
		return this.store.readAdminAudit(Math.min(Math.max(limit, 1), 1000));
	}

	async verifyAudit(identity: AdminIdentity, deviceId?: string): Promise<ChainVerification> {
		requireRole(identity, "viewer");
		return deviceId ? this.store.verifyDeviceAudit(deviceId) : this.store.verifyAdminAudit();
	}

	/**
	 * Produce un anchor di audit firmato (JWS) con le teste di tutte le catene.
	 * Va esportato periodicamente su storage WORM esterno; la firma usa la
	 * chiave attiva del control plane, verificabile con `trustedPublicKeys`.
	 */
	async exportAuditAnchor(identity: AdminIdentity): Promise<{ anchor: string; publicKeyPem: string }> {
		requireRole(identity, "viewer");
		const heads = await this.store.auditHeads();
		const anchor: AuditAnchor = {
			schema: "harness/audit-anchor@1",
			orgId: this.store.state.org.orgId,
			generatedAt: new Date().toISOString(),
			admin: heads.admin,
			devices: heads.devices,
		};
		this.ctx.audit(identity.name, "audit_anchor_exported", {
			adminEntries: heads.admin.entries,
			deviceCount: heads.devices.length,
		});
		return {
			anchor: signPayload(this.store.signingPrivateKeyPem, anchor),
			publicKeyPem: this.store.signingPublicKeyPem,
		};
	}
}
