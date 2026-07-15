/**
 * Rate limiter a **finestra scorrevole** (weighted two-window), in memoria e
 * senza dipendenze. Rispetto alla finestra fissa — che azzera il conteggio al
 * confine e lascia così passare fino a 2× la soglia a cavallo di due finestre —
 * questa stima il traffico dell'ultimo `windowMs` pesando la finestra
 * precedente per la frazione ancora "in vista":
 *
 *   stima = conteggio_corrente + conteggio_precedente × (1 − frazione_trascorsa)
 *
 * È l'approssimazione standard usata dai rate limiter di produzione: niente
 * log per-richiesta (memoria O(chiavi)), niente burst al bordo.
 *
 * L'overflow è gestito con eviction LRU (non un `clear()` totale, che azzererebbe
 * il conteggio di *tutti* — un bypass se si generano molte chiavi distinte).
 */

interface Bucket {
	/** Inizio (ms epoch, allineato) della finestra corrente. */
	windowStart: number;
	count: number;
	prevCount: number;
}

export class SlidingWindowRateLimiter {
	private readonly buckets = new Map<string, Bucket>();

	constructor(
		private readonly windowMs = 60_000,
		private readonly maxKeys = 10_000,
	) {}

	/**
	 * Conteggia la richiesta e ritorna true se la stima scorrevole resta entro
	 * `limit`. Le richieste rifiutate contano comunque (scoraggia il martellamento
	 * e mantiene la semantica identica alla variante Postgres atomica).
	 */
	check(key: string, limit: number, now: number = Date.now()): boolean {
		const windowStart = Math.floor(now / this.windowMs) * this.windowMs;
		let bucket = this.buckets.get(key);
		if (!bucket || bucket.windowStart < windowStart - this.windowMs) {
			// Nessuna sovrapposizione con le due finestre correnti: riparte pulito.
			bucket = { windowStart, count: 0, prevCount: 0 };
		} else if (bucket.windowStart === windowStart - this.windowMs) {
			// La finestra memorizzata è quella immediatamente precedente: ruota.
			bucket = { windowStart, count: 0, prevCount: bucket.count };
		}
		// altrimenti bucket.windowStart === windowStart: stessa finestra, si prosegue.
		bucket.count += 1;

		const elapsedFraction = (now - windowStart) / this.windowMs;
		const estimate = bucket.count + bucket.prevCount * (1 - elapsedFraction);

		// LRU: ri-inserisce in coda; su overflow elimina la chiave più vecchia.
		this.buckets.delete(key);
		this.buckets.set(key, bucket);
		if (this.buckets.size > this.maxKeys) {
			const oldest = this.buckets.keys().next().value;
			if (oldest !== undefined) this.buckets.delete(oldest);
		}

		return estimate <= limit;
	}
}
