import type { DeviceRecord, OrgRecord } from "../store.js";

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
