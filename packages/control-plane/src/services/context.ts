import type { AdminRole, DeviceInfo, JwtVerifyKey } from "@harness/shared";
import type { DeviceRecord, GroupRecord, Store } from "../store.js";

/** Errore applicativo con status HTTP: il server lo mappa direttamente. */
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

/**
 * Configurazione OIDC opzionale: se presente, il control plane accetta anche
 * JWT firmati dal provider aziendale come credenziali amministrative, mappando
 * un claim al ruolo.
 */
export interface OidcConfig {
	issuer: string;
	audience: string;
	keys: JwtVerifyKey[];
	/** Claim che porta il ruolo (default "harness_role"). Valore: admin|operator|viewer. */
	roleClaim?: string;
	/** Claim usato come nome dell'identità nell'audit (default "email", poi "sub"). */
	nameClaim?: string;
}

const ROLE_LEVEL: Record<AdminRole, number> = { viewer: 1, operator: 2, admin: 3 };

/** Impone il ruolo minimo su un'identità amministrativa. */
export function requireRole(identity: AdminIdentity, minimum: AdminRole): void {
	if (ROLE_LEVEL[identity.role] < ROLE_LEVEL[minimum]) {
		throw new ServiceError(403, `operazione riservata al ruolo ${minimum} o superiore`);
	}
}

/** Normalizza un fingerprint (rimuove i due-punti, minuscolo) per confronto stabile. */
export function normalizeFingerprint(fingerprint: string | undefined): string | undefined {
	if (!fingerprint) return undefined;
	const normalized = fingerprint.replaceAll(":", "").trim().toLowerCase();
	return normalized === "" ? undefined : normalized;
}

/** Proiezione pubblica di un device (senza segreti) per la UI/API. */
export function toDeviceInfo(device: DeviceRecord): DeviceInfo {
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

/**
 * Contesto condiviso dai servizi del control plane: accesso allo store,
 * configurazione OIDC e le primitive trasversali (audit, bump della versione,
 * lookup di gruppo). Sostituisce lo stato privato che prima viveva nel
 * God-class `ControlPlaneService`.
 */
export class ServiceContext {
	constructor(
		readonly store: Store,
		readonly oidc: OidcConfig | undefined,
	) {}

	requireGroup(groupId: string): GroupRecord {
		const group = this.store.state.groups[groupId];
		if (!group) throw new ServiceError(404, `gruppo non trovato: ${groupId}`);
		return group;
	}

	/** Incrementa la versione di configurazione e persiste (invalida i bundle). */
	bumpConfig(): void {
		this.store.state.org.configVersion += 1;
		this.store.save();
	}

	audit(actor: string, action: string, detail: Record<string, unknown>): void {
		this.store.appendAdminAudit({ timestamp: new Date().toISOString(), actor, action, detail });
	}
}
