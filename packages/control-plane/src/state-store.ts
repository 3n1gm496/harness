import type { ControlPlaneState, SigningKeyRecord } from "./store.js";

/**
 * Snapshot durevole dello stato del control plane: stato applicativo + chiavi
 * di firma. L'audit resta su file append-only (hash-chained, adatto a WORM) ed
 * è gestito separatamente.
 */
export interface StateSnapshot {
	state: ControlPlaneState;
	signingKeys: SigningKeyRecord[];
}

/**
 * Backend di persistenza dello stato, sostituibile: file (default, zero-dep),
 * in-memory (test) o Postgres (flotte grandi / alta disponibilità).
 */
export interface DurableStateStore {
	load(): Promise<StateSnapshot | null>;
	save(snapshot: StateSnapshot): Promise<void>;
	close(): Promise<void>;
}

/** Backend in memoria, per test e sviluppo. */
export class InMemoryStateStore implements DurableStateStore {
	private snapshot: StateSnapshot | null = null;
	async load(): Promise<StateSnapshot | null> {
		return this.snapshot ? structuredClone(this.snapshot) : null;
	}
	async save(snapshot: StateSnapshot): Promise<void> {
		this.snapshot = structuredClone(snapshot);
	}
	async close(): Promise<void> {}
}

/**
 * Backend Postgres. Lo stato è un'unica riga JSONB con una colonna `version`
 * per il locking ottimistico: due istanze che scrivono concorrentemente non si
 * sovrascrivono a vicenda silenziosamente (la seconda fallisce e ricarica).
 *
 * Richiede la dipendenza opzionale `pg` e un Postgres raggiungibile. Import
 * lazy per non appesantire il core quando si usa il backend a file.
 */
export class PostgresStateStore implements DurableStateStore {
	// biome-ignore lint/suspicious/noExplicitAny: il tipo del pool arriva da pg (dipendenza opzionale)
	private pool: any;
	private version = 0;
	private ready = false;

	constructor(private readonly connectionString: string) {}

	private async ensureReady(): Promise<void> {
		if (this.ready) return;
		const pg = (await import("pg")).default as unknown as {
			Pool: new (config: { connectionString: string }) => unknown;
		};
		this.pool = new pg.Pool({ connectionString: this.connectionString });
		await this.query(
			`CREATE TABLE IF NOT EXISTS control_plane_state (
				id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
				snapshot jsonb NOT NULL,
				version int NOT NULL DEFAULT 0
			)`,
		);
		this.ready = true;
	}

	private async query(text: string, params: unknown[] = []): Promise<{ rows: Record<string, unknown>[] }> {
		return this.pool.query(text, params) as Promise<{ rows: Record<string, unknown>[] }>;
	}

	async load(): Promise<StateSnapshot | null> {
		await this.ensureReady();
		const result = await this.query("SELECT snapshot, version FROM control_plane_state WHERE id = 1");
		if (result.rows.length === 0) return null;
		const row = result.rows[0] as { snapshot: StateSnapshot; version: number };
		this.version = row.version;
		return row.snapshot;
	}

	async save(snapshot: StateSnapshot): Promise<void> {
		await this.ensureReady();
		const next = this.version + 1;
		// Insert-or-update con controllo di versione: se un'altra istanza ha
		// scritto nel frattempo, la clausola WHERE non trova la riga attesa.
		const result = await this.query(
			`INSERT INTO control_plane_state (id, snapshot, version) VALUES (1, $1, $2)
			 ON CONFLICT (id) DO UPDATE SET snapshot = $1, version = $2
			 WHERE control_plane_state.version = $3
			 RETURNING version`,
			[JSON.stringify(snapshot), next, this.version],
		);
		if (result.rows.length === 0) {
			// Conflitto: un'altra istanza ha scritto. Ricarica per riallineare.
			await this.load();
			throw new Error("conflitto di versione sullo stato: un'altra istanza ha scritto (ricaricato)");
		}
		this.version = next;
	}

	async close(): Promise<void> {
		if (this.pool) await this.pool.end();
	}
}
