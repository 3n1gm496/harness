import { SlidingWindowRateLimiter } from "@harness/shared";

/**
 * Rate limit condivisibile tra istanze. Un limiter per-istanza sotto un backend
 * multi-istanza applica N×soglia invece della soglia dichiarata (ogni istanza
 * tiene il proprio conteggio in memoria): con un backend Postgres
 * l'implementazione condivisa (`PostgresStateStore.checkRateLimit`) chiude il
 * problema con un upsert atomico sulla stessa tabella. Entrambe usano una
 * finestra **scorrevole** (weighted two-window), che non lascia passare il
 * burst 2× al confine della finestra fissa.
 */
export interface RateLimiter {
	/** true se la richiesta è entro la soglia (ed è stata conteggiata). */
	check(key: string, limitPerWindow: number): Promise<boolean>;
}

/** Limiter in-memory a finestra scorrevole: corretto solo a singola istanza (file-mode, sviluppo). */
export class InMemoryRateLimiter implements RateLimiter {
	private readonly limiter = new SlidingWindowRateLimiter();

	async check(key: string, limitPerWindow: number): Promise<boolean> {
		return this.limiter.check(key, limitPerWindow);
	}
}
