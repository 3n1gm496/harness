import type { AdminRole, DeepPartial, DeviceInfo, GroupInfo, PolicyDocument } from "@harness/shared";
import { type AdminIdentity, ServiceContext, ServiceError, requireRole, toDeviceInfo } from "./context.js";
import { type DeviceState, deviceState } from "./fleet-view.js";

/** Organizzazione: panoramica della flotta e configurazione a livello org. */
export class OrgService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	/**
	 * Panoramica aggregata: org, gruppi (con conteggio device) e ruolo. Non
	 * include più l'elenco device completo — su una flotta grande obbligava a
	 * trasferire l'intera lista a ogni refresh della dashboard. Usa
	 * `listDevices` (paginato/filtrato) e `fleetSummary` (contatori) per quello.
	 */
	overview(identity: AdminIdentity): {
		role: AdminRole;
		org: { orgId: string; name: string; configVersion: number; killSwitch: boolean; configTtlMinutes: number };
		groups: GroupInfo[];
	} {
		requireRole(identity, "viewer");
		const { org, groups, devices } = this.store.state;
		const deviceList = Object.values(devices);
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
				deviceCount: deviceList.filter((d) => d.groupId === group.groupId).length,
			})),
		};
	}

	/**
	 * Elenco device paginato e filtrato lato server: `q` cerca su
	 * nome/id/gruppo, `filter` su stato calcolato (active/stale/suspended).
	 * `offset`/`limit` sono l'unica paginazione reale (quella della UI prima
	 * di questo endpoint era solo client-side, sull'elenco completo).
	 */
	listDevices(
		identity: AdminIdentity,
		options: { offset?: number; limit?: number; q?: string; filter?: DeviceState | "all" },
	): { devices: (DeviceInfo & { state: DeviceState })[]; total: number } {
		requireRole(identity, "viewer");
		const { org, groups, devices } = this.store.state;
		const groupName = (groupId: string): string => groups[groupId]?.name ?? groupId;
		const q = (options.q ?? "").trim().toLowerCase();
		const filter = options.filter ?? "all";

		let list = Object.values(devices).map((device) => ({ ...toDeviceInfo(device), state: deviceState(device, org) }));
		if (q) {
			list = list.filter(
				(d) =>
					d.name.toLowerCase().includes(q) ||
					d.deviceId.toLowerCase().includes(q) ||
					groupName(d.groupId).toLowerCase().includes(q),
			);
		}
		if (filter !== "all") list = list.filter((d) => d.state === filter);

		const total = list.length;
		const offset = Math.max(0, options.offset ?? 0);
		const limit = Math.min(Math.max(1, options.limit ?? 25), 200);
		return { devices: list.slice(offset, offset + limit), total };
	}

	/** Contatori aggregati di flotta per la dashboard e per `/metrics`. */
	fleetSummary(identity: AdminIdentity): {
		total: number;
		active: number;
		stale: number;
		suspended: number;
		configVersion: number;
		killSwitch: boolean;
	} {
		requireRole(identity, "viewer");
		const { org, devices } = this.store.state;
		let active = 0;
		let stale = 0;
		let suspended = 0;
		const deviceList = Object.values(devices);
		for (const device of deviceList) {
			const state = deviceState(device, org);
			if (state === "active") active += 1;
			else if (state === "stale") stale += 1;
			else suspended += 1;
		}
		return { total: deviceList.length, active, stale, suspended, configVersion: org.configVersion, killSwitch: org.killSwitch };
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
