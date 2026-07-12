import type { AuditEvent } from "@harness/shared";
import { newId } from "@harness/shared";

const AUDIT_EVENT_TYPES = new Set<string>([
	"policy_decision",
	"tool_call",
	"tool_result",
	"user_bash",
	"config_applied",
	"config_error",
	"agent_start",
	"agent_stop",
	"error",
]);

/**
 * Valida e delimita un evento di audit proveniente da un device: il device è
 * autenticato ma non fidato — l'evento deve avere una shape nota, il deviceId
 * viene sempre forzato e il payload viene troncato per proteggere lo storage.
 */
export function sanitizeAuditEvent(raw: unknown, deviceId: string): AuditEvent | undefined {
	if (typeof raw !== "object" || raw === null || Array.isArray(raw)) return undefined;
	const candidate = raw as Record<string, unknown>;
	if (typeof candidate.type !== "string" || !AUDIT_EVENT_TYPES.has(candidate.type)) return undefined;

	let data: Record<string, unknown> = {};
	if (typeof candidate.data === "object" && candidate.data !== null && !Array.isArray(candidate.data)) {
		data = candidate.data as Record<string, unknown>;
		try {
			const serialized = JSON.stringify(data);
			if (serialized.length > 8192) {
				data = { truncated: true, preview: serialized.slice(0, 2048) };
			}
		} catch {
			data = { truncated: true, preview: "[dati non serializzabili]" };
		}
	}

	const event: AuditEvent = {
		eventId: typeof candidate.eventId === "string" ? candidate.eventId.slice(0, 64) : newId("evt"),
		deviceId, // il device non può impersonarne un altro
		timestamp:
			typeof candidate.timestamp === "string" && !Number.isNaN(Date.parse(candidate.timestamp))
				? candidate.timestamp
				: new Date().toISOString(),
		type: candidate.type as AuditEvent["type"],
		data,
	};
	if (typeof candidate.sessionId === "string") event.sessionId = candidate.sessionId.slice(0, 64);
	return event;
}
