/**
 * Rate limit a finestra fissa (60s), condivisibile tra istanze. Un limiter
 * per-istanza sotto un backend multi-istanza applica N×soglia invece della
 * soglia dichiarata (ogni istanza tiene il proprio conteggio in memoria): con
 * un backend Postgres l'implementazione condivisa (`PostgresRateLimiter`)
 * chiude questo problema con un upsert atomico sulla stessa tabella.
 */
export interface RateLimiter {
	/** true se la richiesta è entro la soglia (ed è stata conteggiata). */
	check(key: string, limitPerWindow: number): Promise<boolean>;
}

const WINDOW_MS = 60_000;

/** Limiter in-memory: corretto solo a singola istanza (file-mode, sviluppo). */
export class InMemoryRateLimiter implements RateLimiter {
	private readonly buckets = new Map<string, { windowStart: number; count: number }>();

	async check(key: string, limitPerWindow: number): Promise<boolean> {
		const now = Date.now();
		if (this.buckets.size > 10_000) this.buckets.clear(); // cap difensivo
		const bucket = this.buckets.get(key);
		if (!bucket || now - bucket.windowStart >= WINDOW_MS) {
			this.buckets.set(key, { windowStart: now, count: 1 });
			return true;
		}
		bucket.count += 1;
		return bucket.count <= limitPerWindow;
	}
}
