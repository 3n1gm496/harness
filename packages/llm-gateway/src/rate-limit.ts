import { SlidingWindowRateLimiter } from "@harness/shared";

/**
 * Rate limit del gateway. Di default è per-istanza (in memoria): sotto scaling
 * orizzontale ogni istanza applica la propria soglia (N×soglia effettiva).
 * Con un `DATABASE_URL` (lo stesso Postgres del control plane) il conteggio è
 * **condiviso** tra tutte le istanze del gateway usando la stessa tabella
 * `cp_rate_buckets` a finestra scorrevole. Entrambe le varianti usano la
 * finestra scorrevole (weighted two-window): niente burst 2× al confine.
 */
export interface GatewayRateLimiter {
	/** true se la richiesta è entro la soglia al minuto (ed è stata conteggiata). */
	check(key: string, limitPerMinute: number): Promise<boolean>;
	close(): Promise<void>;
}

/** Limiter per-istanza (default): corretto a singola istanza; documentato come tale. */
export class InMemoryGatewayRateLimiter implements GatewayRateLimiter {
	private readonly limiter = new SlidingWindowRateLimiter();
	async check(key: string, limitPerMinute: number): Promise<boolean> {
		return this.limiter.check(key, limitPerMinute);
	}
	async close(): Promise<void> {}
}

/**
 * Limiter condiviso su Postgres (stessa `cp_rate_buckets` del control plane).
 * La tabella è creata idempotentemente all'init, così il gateway non dipende
 * dall'ordine di avvio rispetto al control plane. Richiede la dipendenza
 * opzionale `pg` (import lazy).
 */
export class PostgresGatewayRateLimiter implements GatewayRateLimiter {
	// biome-ignore lint/suspicious/noExplicitAny: il tipo del pool arriva da pg (dipendenza opzionale)
	private pool: any;
	private initPromise: Promise<void> | undefined;

	constructor(private readonly connectionString: string) {}

	private ensureReady(): Promise<void> {
		if (this.initPromise) return this.initPromise;
		this.initPromise = (async () => {
			const pg = (await import("pg")).default as unknown as {
				Pool: new (config: { connectionString: string; max: number }) => unknown;
			};
			const pool = new pg.Pool({ connectionString: this.connectionString, max: 4 });
			(pool as { on(event: string, cb: (err: unknown) => void): void }).on("error", () => {});
			this.pool = pool;
			// Idempotente: la stessa forma che il control plane crea con le migrazioni
			// 4 e 7. Così il gateway funziona anche se avviato prima del control plane.
			await this.pool.query(`CREATE TABLE IF NOT EXISTS cp_rate_buckets (
				bucket_key text PRIMARY KEY,
				window_start timestamptz NOT NULL,
				count int NOT NULL,
				prev_count int NOT NULL DEFAULT 0)`);
			await this.pool.query("ALTER TABLE cp_rate_buckets ADD COLUMN IF NOT EXISTS prev_count int NOT NULL DEFAULT 0");
		})().catch((error) => {
			this.initPromise = undefined;
			throw error;
		});
		return this.initPromise;
	}

	async check(key: string, limitPerMinute: number): Promise<boolean> {
		await this.ensureReady();
		// Stessa finestra scorrevole atomica del control plane (state-store.ts).
		const result = (await this.pool.query(
			`INSERT INTO cp_rate_buckets (bucket_key, window_start, count, prev_count)
			 VALUES ($1, to_timestamp(floor(extract(epoch from now()) / 60) * 60), 1, 0)
			 ON CONFLICT (bucket_key) DO UPDATE SET
				prev_count = CASE
					WHEN cp_rate_buckets.window_start = to_timestamp(floor(extract(epoch from now()) / 60) * 60)
						THEN cp_rate_buckets.prev_count
					WHEN cp_rate_buckets.window_start = to_timestamp(floor(extract(epoch from now()) / 60) * 60 - 60)
						THEN cp_rate_buckets.count
					ELSE 0 END,
				count = CASE
					WHEN cp_rate_buckets.window_start = to_timestamp(floor(extract(epoch from now()) / 60) * 60)
						THEN cp_rate_buckets.count + 1
					ELSE 1 END,
				window_start = to_timestamp(floor(extract(epoch from now()) / 60) * 60)
			 RETURNING count, prev_count,
				extract(epoch from now()) - extract(epoch from window_start) AS elapsed_seconds`,
			[`gateway:${key}`],
		)) as { rows: { count: number; prev_count: number; elapsed_seconds: number }[] };
		const row = result.rows[0];
		const count = Number(row?.count ?? 1);
		const prevCount = Number(row?.prev_count ?? 0);
		const elapsedFraction = Math.min(1, Number(row?.elapsed_seconds ?? 60) / 60);
		return count + prevCount * (1 - elapsedFraction) <= limitPerMinute;
	}

	async close(): Promise<void> {
		if (this.pool) await this.pool.end();
	}
}
