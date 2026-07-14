import type { AdminRole, DeepPartial, DeviceInfo, GroupInfo, PolicyDocument } from "@harness/shared";
import { type AdminIdentity, ServiceContext, ServiceError, requireRole, toDeviceInfo } from "./context.js";

/** Organizzazione: panoramica della flotta e configurazione a livello org. */
export class OrgService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	overview(identity: AdminIdentity): {
		role: AdminRole;
		org: { orgId: string; name: string; configVersion: number; killSwitch: boolean; configTtlMinutes: number };
		groups: GroupInfo[];
		devices: DeviceInfo[];
	} {
		requireRole(identity, "viewer");
		const { org, groups, devices } = this.store.state;
		return {
			role: identity.role,
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
			devices: Object.values(devices).map((device) => toDeviceInfo(device)),
		};
	}

	getOrgConfig(identity: AdminIdentity): {
		policyOverride: DeepPartial<PolicyDocument>;
		piSettingsOverride: Record<string, unknown>;
	} {
		requireRole(identity, "viewer");
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
			deviceTokenMaxAgeDays?: number;
			requireDeviceCert?: boolean;
			allowCertTofu?: boolean;
		},
	): void {
		const changesPolicy =
			update.policyOverride !== undefined ||
			update.piSettingsOverride !== undefined ||
			update.requireDeviceCert !== undefined ||
			update.allowCertTofu !== undefined;
		requireRole(identity, changesPolicy || update.configTtlMinutes !== undefined ? "admin" : "operator");
		const { org } = this.store.state;
		if (update.name !== undefined) org.name = update.name;
		if (update.killSwitch !== undefined) org.killSwitch = update.killSwitch;
		if (update.configTtlMinutes !== undefined) {
			if (update.configTtlMinutes < 5 || update.configTtlMinutes > 24 * 60) {
				throw new ServiceError(400, "configTtlMinutes deve essere tra 5 e 1440");
			}
			org.configTtlMinutes = update.configTtlMinutes;
		}
		if (update.deviceTokenMaxAgeDays !== undefined) {
			if (update.deviceTokenMaxAgeDays < 1 || update.deviceTokenMaxAgeDays > 3650) {
				throw new ServiceError(400, "deviceTokenMaxAgeDays deve essere tra 1 e 3650");
			}
			org.deviceTokenMaxAgeDays = update.deviceTokenMaxAgeDays;
		}
		if (update.requireDeviceCert !== undefined) org.requireDeviceCert = update.requireDeviceCert;
		if (update.allowCertTofu !== undefined) org.allowCertTofu = update.allowCertTofu;
		if (update.policyOverride !== undefined) org.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) org.piSettingsOverride = update.piSettingsOverride;
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "org_updated", { update });
	}
}
