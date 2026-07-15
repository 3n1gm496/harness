import type { ControlPlaneState, DeviceRecord, OrgRecord } from "../store.js";

/**
 * Stato operativo di un device dal punto di vista di un operatore: non è
 * persistito, è calcolato al volo da `killSwitch`/`revoked`/`lastSeenAt`.
 * Condiviso fra l'endpoint di elenco device, il riepilogo di flotta e le
 * metriche Prometheus (`/metrics`), così la stessa definizione di "stale"
 * vale ovunque nel sistema.
 */
export type DeviceState = "active" | "stale" | "suspended";

/**
 * Finestra oltre la quale un device senza contatti è considerato stale: il
 * doppio della TTL di configurazione (il bundle firmato che ha in cache può
 * essere scaduto, quindi l'agente potrebbe già essere in fail-closed), con un
 * minimo di 10 minuti per organizzazioni con TTL molto brevi.
 */
export function staleWindowMs(configTtlMinutes: number): number {
	return Math.max(2 * (configTtlMinutes || 60), 10) * 60_000;
}

export function isDeviceStale(device: DeviceRecord, configTtlMinutes: number): boolean {
	if (device.revoked) return false;
	const last = device.lastSeenAt ? Date.parse(device.lastSeenAt) : Date.parse(device.enrolledAt);
	if (Number.isNaN(last)) return false;
	return Date.now() - last > staleWindowMs(configTtlMinutes);
}

export function deviceState(device: DeviceRecord, org: OrgRecord): DeviceState {
	if (device.revoked) return "suspended";
	if (device.killSwitch || org.killSwitch) return "suspended";
	if (isDeviceStale(device, org.configTtlMinutes)) return "stale";
	return "active";
}

/**
 * Contatori aggregati di flotta per stato: unica fonte di verità condivisa da
 * `OrgService.fleetSummary` (dashboard/API, con auth) e da `/metrics`
 * (Prometheus, senza auth) — la stessa definizione di "stale"/"suspended"
 * vale in entrambi, invece di due calcoli che potrebbero divergere.
 */
export function fleetCounts(state: ControlPlaneState): {
	total: number;
	active: number;
	stale: number;
	suspended: number;
} {
	const { org, devices } = state;
	let active = 0;
	let stale = 0;
	let suspended = 0;
	const deviceList = Object.values(devices);
	for (const device of deviceList) {
		const s = deviceState(device, org);
		if (s === "active") active += 1;
		else if (s === "stale") stale += 1;
		else suspended += 1;
	}
	return { total: deviceList.length, active, stale, suspended };
}
