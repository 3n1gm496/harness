import type { IncomingMessage } from "node:http";

/**
 * IP del client per il rate limit: dietro un reverse proxy fidato
 * (HARNESS_TRUST_PROXY=1) usa il primo hop di X-Forwarded-For, altrimenti
 * l'IP del socket (evita lo spoofing di XFF quando non c'è un proxy fidato).
 *
 * Il rate limit vero e proprio (conteggio, finestra, soglia) vive in
 * `rate-limiter.ts` / `Store.checkEnrollRateLimit`: condiviso su Postgres tra
 * istanze, in-memory a singola istanza in file-mode.
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
