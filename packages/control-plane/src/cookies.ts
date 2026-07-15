import type { IncomingMessage } from "node:http";

/** Nome del cookie di sessione della UI amministrativa (vedi `services/auth-service.ts`). */
const SESSION_COOKIE_NAME = "harness_session";

/** Estrae il valore di un cookie dall'header `Cookie` grezzo. */
export function parseCookie(header: string | undefined, name: string): string | undefined {
	if (!header) return undefined;
	for (const part of header.split(";")) {
		const eq = part.indexOf("=");
		if (eq === -1) continue;
		if (part.slice(0, eq).trim() !== name) continue;
		return decodeURIComponent(part.slice(eq + 1).trim());
	}
	return undefined;
}

/** Legge il cookie di sessione dalla richiesta. */
export function sessionCookieValue(req: IncomingMessage): string | undefined {
	return parseCookie(req.headers.cookie, SESSION_COOKIE_NAME);
}

/**
 * Una connessione è considerata sicura (per l'attributo `Secure` del cookie)
 * se è TLS diretto o se un reverse proxy FIDATO davanti dichiara
 * `x-forwarded-proto: https`. L'header è fidato solo dietro
 * `HARNESS_TRUST_PROXY=1` (stesso gate di `clientIp`): senza, sarebbe
 * spoofabile da un client diretto per far marcare `Secure` un cookie su una
 * connessione in chiaro (o viceversa). In molti deploy il TLS termina a monte
 * del processo Node (`options.tls` di `server.ts` resta comunque supportato).
 */
export function isSecureRequest(req: IncomingMessage): boolean {
	if ((req.socket as { encrypted?: boolean }).encrypted) return true;
	if (process.env.HARNESS_TRUST_PROXY === "1") return req.headers["x-forwarded-proto"] === "https";
	return false;
}

/** Costruisce l'header `Set-Cookie` per aprire una sessione. */
export function buildSessionCookie(sessionId: string, maxAgeSeconds: number, secure: boolean): string {
	const attrs = [
		`${SESSION_COOKIE_NAME}=${sessionId}`,
		"Path=/",
		"HttpOnly",
		"SameSite=Strict",
		`Max-Age=${maxAgeSeconds}`,
	];
	if (secure) attrs.push("Secure");
	return attrs.join("; ");
}

/** Costruisce l'header `Set-Cookie` che cancella la sessione (logout). */
export function clearSessionCookie(secure: boolean): string {
	const attrs = [`${SESSION_COOKIE_NAME}=`, "Path=/", "HttpOnly", "SameSite=Strict", "Max-Age=0"];
	if (secure) attrs.push("Secure");
	return attrs.join("; ");
}
