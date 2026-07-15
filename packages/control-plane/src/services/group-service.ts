import type { DeepPartial, PolicyDocument } from "@harness/shared";
import { newId } from "@harness/shared";
import type { GroupRecord } from "../store.js";
import { type AdminIdentity, requireRole, type ServiceContext, ServiceError } from "./context.js";

/** Gestione dei gruppi (tenant logici che raggruppano i device per policy). */
export class GroupService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	createGroup(identity: AdminIdentity, name: string): GroupRecord {
		requireRole(identity, "admin");
		if (!name.trim()) throw new ServiceError(400, "nome gruppo mancante");
		const group: GroupRecord = {
			groupId: newId("grp"),
			name: name.trim(),
			killSwitch: false,
			policyOverride: {},
			piSettingsOverride: {},
		};
		this.store.state.groups[group.groupId] = group;
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "group_created", { groupId: group.groupId, name: group.name });
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
		requireRole(identity, changesPolicy ? "admin" : "operator");
		const group = this.ctx.requireGroup(groupId);
		if (update.name !== undefined) group.name = update.name;
		if (update.killSwitch !== undefined) group.killSwitch = update.killSwitch;
		if (update.policyOverride !== undefined) group.policyOverride = update.policyOverride;
		if (update.piSettingsOverride !== undefined) group.piSettingsOverride = update.piSettingsOverride;
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "group_updated", { groupId, update });
	}

	deleteGroup(identity: AdminIdentity, groupId: string): void {
		requireRole(identity, "admin");
		this.ctx.requireGroup(groupId);
		const inUse = Object.values(this.store.state.devices).some((device) => device.groupId === groupId);
		if (inUse) throw new ServiceError(409, "il gruppo ha device associati");
		delete this.store.state.groups[groupId];
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "group_deleted", { groupId });
	}
}
