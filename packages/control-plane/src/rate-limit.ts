import type { IncomingMessage } from "node:http";

/**
 * Rate limit per-IP sull'enrollment: i token hanno 256 bit di entropia e sono
 * monouso, quindi il brute force è impraticabile, ma un endpoint di
 * autenticazione non va comunque lasciato senza freni.
 */
const ENROLL_RATE_LIMIT_PER_MINUTE = 20;
const enrollBuckets = new Map<string, { windowStart: number; count: number }>();

/**
 * IP del client per il rate limit: dietro un reverse proxy fidato
 * (HARNESS_TRUST_PROXY=1) usa il primo hop di X-Forwarded-For, altrimenti
 * l'IP del socket (evita lo spoofing di XFF quando non c'è un proxy fidato).
 */
export function clientIp(req: IncomingMessage): string {
	if (process.env.HARNESS_TRUST_PROXY === "1") {
		const xff = req.headers["x-forwarded-for"];
		const value = Array.isArray(xff) ? xff[0] : xff;
		const first = value?.split(",")[0]?.trim();
		if (first) return first;
	}
	return req.socket.remoteAddress ?? "sconosciuto";
}

export function checkEnrollRateLimit(ip: string): boolean {
	const now = Date.now();
	if (enrollBuckets.size > 10_000) enrollBuckets.clear(); // cap difensivo
	const bucket = enrollBuckets.get(ip);
	if (!bucket || now - bucket.windowStart >= 60_000) {
		enrollBuckets.set(ip, { windowStart: now, count: 1 });
		return true;
	}
	bucket.count += 1;
	return bucket.count <= ENROLL_RATE_LIMIT_PER_MINUTE;
}
