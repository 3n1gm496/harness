/**
 * Merge profondo per la stratificazione della configurazione
 * (default → org → gruppo → device). Gli array vengono sostituiti, non
 * concatenati: un override che specifica una lista la ridefinisce per intero,
 * così un gruppo può restringere ciò che l'org consente.
 */
/** Chiavi che non devono mai essere attraversate dal merge (prototype pollution). */
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

export function deepMerge<T extends object>(base: T, override: object): T {
	const result: Record<string, unknown> = { ...(base as Record<string, unknown>) };
	for (const [key, value] of Object.entries(override)) {
		if (value === undefined || FORBIDDEN_KEYS.has(key)) continue;
		const current = result[key];
		if (isPlainObject(current) && isPlainObject(value)) {
			result[key] = deepMerge(current, value);
		} else {
			result[key] = value;
		}
	}
	return result as T;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}
