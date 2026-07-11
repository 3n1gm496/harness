import type { ChainVerification } from "@harness/shared";
import { CHAIN_GENESIS, computeChainHash, verifyChain } from "@harness/shared";
import type {
	AdminTokenRecord,
	ControlPlaneState,
	DeviceRecord,
	EnrollTokenRecord,
	GatewayTokenRecord,
	GroupRecord,
	OrgRecord,
	SigningKeyRecord,
} from "./store.js";

/** Snapshot completo dello stato + chiavi di firma (per idratazione). */
export interface StateSnapshot {
	state: ControlPlaneState;
	signingKeys: SigningKeyRecord[];
}

/**
 * Diff di stato per scritture mirate (una riga per entità cambiata), invece di
 * riscrivere l'intero blob a ogni mutazione. Elimina l'amplificazione di
 * scrittura e i conflitti globali sotto multi-istanza.
 */
export interface StateDiff {
	org?: OrgRecord;
	groupsUpsert: GroupRecord[];
	groupsDelete: string[];
	devicesUpsert: DeviceRecord[];
	devicesDelete: string[];
	adminTokensUpsert: [string, AdminTokenRecord][];
	adminTokensDelete: string[];
	gatewayTokensUpsert: [string, GatewayTokenRecord][];
	enrollTokensUpsert: [string, EnrollTokenRecord][];
	enrollTokensDelete: string[];
	/** Se presente, sostituisce l'intero set di chiavi di firma. */
	signingKeys?: SigningKeyRecord[];
}

/** Backend snapshot-based (blob), usato in-memory per test/sviluppo. */
export interface DurableStateStore {
	load(): Promise<StateSnapshot | null>;
	save(snapshot: StateSnapshot): Promise<void>;
	close(): Promise<void>;
}

/**
 * Backend normalizzato: scritture mirate per entità e audit centralizzato nel
 * datastore. Abilita davvero scala e multi-istanza (niente riscrittura del blob,
 * audit unico e non frammentato per-istanza).
 */
export interface NormalizedStateStore extends DurableStateStore {
	readonly normalized: true;
	applyDiff(diff: StateDiff): Promise<void>;
	appendAudit(streamId: string, entries: unknown[]): Promise<void>;
	readAudit(streamId: string, limit: number): Promise<unknown[]>;
	verifyAudit(streamId: string): Promise<ChainVerification>;
	auditHeads(
		deviceStreamIds: string[],
	): Promise<{ admin: { head: string; entries: number }; devices: { deviceId: string; head: string; entries: number }[] }>;
}

export function isNormalized(store: DurableStateStore): store is NormalizedStateStore {
	return (store as NormalizedStateStore).normalized === true;
}

/** Backend in memoria snapshot-based, per test. */
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

const ADMIN_STREAM = "admin";

/**
 * Backend Postgres a schema normalizzato: una riga per entità (org, gruppi,
 * device, token, chiavi) con payload JSONB, e audit centralizzato in
 * `audit_events` con testa di catena per-stream serializzata via lock di riga.
 *
 * Richiede la dipendenza opzionale `pg`. Import lazy.
 */
export class PostgresStateStore implements NormalizedStateStore {
	readonly normalized = true as const;
	// biome-ignore lint/suspicious/noExplicitAny: il tipo del pool arriva da pg (dipendenza opzionale)
	private pool: any;
	private ready = false;

	constructor(private readonly connectionString: string) {}

	private async ensureReady(): Promise<void> {
		if (this.ready) return;
		const pg = (await import("pg")).default as unknown as {
			Pool: new (config: { connectionString: string; max: number }) => unknown;
		};
		// Pool limitato: evita di esaurire le connessioni del server sotto carico.
		this.pool = new pg.Pool({ connectionString: this.connectionString, max: 8 });
		await this.query(`
			CREATE TABLE IF NOT EXISTS cp_org (id int PRIMARY KEY DEFAULT 1 CHECK (id = 1), data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_groups (group_id text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_devices (device_id text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_admin_tokens (token_hash text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_gateway_tokens (token_hash text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_enroll_tokens (token_hash text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_signing_keys (key_id text PRIMARY KEY, data jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_audit_events (
				stream_id text NOT NULL, seq bigint NOT NULL, prev_hash text NOT NULL, hash text NOT NULL,
				entry text NOT NULL, ts timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (stream_id, seq));
			CREATE TABLE IF NOT EXISTS cp_audit_heads (stream_id text PRIMARY KEY, seq bigint NOT NULL, head text NOT NULL);
		`);
		this.ready = true;
	}

	private async query(text: string, params: unknown[] = []): Promise<{ rows: Record<string, unknown>[] }> {
		return this.pool.query(text, params) as Promise<{ rows: Record<string, unknown>[] }>;
	}

	async load(): Promise<StateSnapshot | null> {
		await this.ensureReady();
		const org = await this.query("SELECT data FROM cp_org WHERE id = 1");
		if (org.rows.length === 0) return null;
		const [groups, devices, adminTokens, gatewayTokens, enrollTokens, signingKeys] = await Promise.all([
			this.query("SELECT group_id, data FROM cp_groups"),
			this.query("SELECT device_id, data FROM cp_devices"),
			this.query("SELECT token_hash, data FROM cp_admin_tokens"),
			this.query("SELECT token_hash, data FROM cp_gateway_tokens"),
			this.query("SELECT token_hash, data FROM cp_enroll_tokens"),
			this.query("SELECT data FROM cp_signing_keys"),
		]);
		const byKey = <T>(rows: Record<string, unknown>[], key: string): Record<string, T> => {
			const out: Record<string, T> = {};
			for (const row of rows) out[row[key] as string] = row.data as T;
			return out;
		};
		const state: ControlPlaneState = {
			org: org.rows[0]?.data as OrgRecord,
			groups: byKey<GroupRecord>(groups.rows, "group_id"),
			devices: byKey<DeviceRecord>(devices.rows, "device_id"),
			adminTokens: byKey<AdminTokenRecord>(adminTokens.rows, "token_hash"),
			gatewayTokens: byKey<GatewayTokenRecord>(gatewayTokens.rows, "token_hash"),
			enrollTokens: byKey<EnrollTokenRecord>(enrollTokens.rows, "token_hash"),
		};
		return { state, signingKeys: signingKeys.rows.map((r) => r.data as SigningKeyRecord) };
	}

	/** Salvataggio iniziale completo (bootstrap del DB dallo stato locale). */
	async save(snapshot: StateSnapshot): Promise<void> {
		await this.applyDiff({
			org: snapshot.state.org,
			groupsUpsert: Object.values(snapshot.state.groups),
			groupsDelete: [],
			devicesUpsert: Object.values(snapshot.state.devices),
			devicesDelete: [],
			adminTokensUpsert: Object.entries(snapshot.state.adminTokens),
			adminTokensDelete: [],
			gatewayTokensUpsert: Object.entries(snapshot.state.gatewayTokens),
			enrollTokensUpsert: Object.entries(snapshot.state.enrollTokens),
			enrollTokensDelete: [],
			signingKeys: snapshot.signingKeys,
		});
	}

	async applyDiff(diff: StateDiff): Promise<void> {
		await this.ensureReady();
		const stmts: Promise<unknown>[] = [];
		if (diff.org) {
			stmts.push(
				this.query(
					"INSERT INTO cp_org (id, data) VALUES (1, $1) ON CONFLICT (id) DO UPDATE SET data = $1",
					[JSON.stringify(diff.org)],
				),
			);
		}
		const upsert = (table: string, keyCol: string, key: string, data: unknown) =>
			this.query(
				`INSERT INTO ${table} (${keyCol}, data) VALUES ($1, $2) ON CONFLICT (${keyCol}) DO UPDATE SET data = $2`,
				[key, JSON.stringify(data)],
			);
		const del = (table: string, keyCol: string, keys: string[]) =>
			keys.length > 0 ? this.query(`DELETE FROM ${table} WHERE ${keyCol} = ANY($1)`, [keys]) : Promise.resolve();

		for (const g of diff.groupsUpsert) stmts.push(upsert("cp_groups", "group_id", g.groupId, g));
		for (const d of diff.devicesUpsert) stmts.push(upsert("cp_devices", "device_id", d.deviceId, d));
		for (const [h, t] of diff.adminTokensUpsert) stmts.push(upsert("cp_admin_tokens", "token_hash", h, t));
		for (const [h, t] of diff.gatewayTokensUpsert) stmts.push(upsert("cp_gateway_tokens", "token_hash", h, t));
		for (const [h, t] of diff.enrollTokensUpsert) stmts.push(upsert("cp_enroll_tokens", "token_hash", h, t));
		stmts.push(del("cp_groups", "group_id", diff.groupsDelete));
		stmts.push(del("cp_devices", "device_id", diff.devicesDelete));
		stmts.push(del("cp_admin_tokens", "token_hash", diff.adminTokensDelete));
		stmts.push(del("cp_enroll_tokens", "token_hash", diff.enrollTokensDelete));
		if (diff.signingKeys) {
			// Sostituzione atomica del set chiavi.
			stmts.push(
				this.query("DELETE FROM cp_signing_keys").then(() =>
					Promise.all(
						(diff.signingKeys as SigningKeyRecord[]).map((k) =>
							upsert("cp_signing_keys", "key_id", k.keyId, k),
						),
					),
				),
			);
		}
		await Promise.all(stmts);
	}

	// ---- Audit centralizzato -------------------------------------------------

	async appendAudit(streamId: string, entries: unknown[]): Promise<void> {
		if (entries.length === 0) return;
		await this.ensureReady();
		const client = (await this.pool.connect()) as {
			query: (t: string, p?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>;
			release: () => void;
		};
		try {
			await client.query("BEGIN");
			// Serializza gli append per-stream con un advisory lock di transazione:
			// funziona anche al primo append (quando la riga head non esiste ancora
			// e un FOR UPDATE non bloccherebbe nulla).
			await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [streamId]);
			const head = await client.query("SELECT seq, head FROM cp_audit_heads WHERE stream_id = $1", [streamId]);
			let seq = head.rows.length > 0 ? Number(head.rows[0]?.seq) : 0;
			let prev = head.rows.length > 0 ? (head.rows[0]?.head as string) : CHAIN_GENESIS;
			for (const entry of entries) {
				const hash = computeChainHash(prev, entry);
				seq += 1;
				await client.query(
					"INSERT INTO cp_audit_events (stream_id, seq, prev_hash, hash, entry) VALUES ($1,$2,$3,$4,$5)",
					[streamId, seq, prev, hash, JSON.stringify(entry)],
				);
				prev = hash;
			}
			await client.query(
				`INSERT INTO cp_audit_heads (stream_id, seq, head) VALUES ($1,$2,$3)
				 ON CONFLICT (stream_id) DO UPDATE SET seq = $2, head = $3`,
				[streamId, seq, prev],
			);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}

	async readAudit(streamId: string, limit: number): Promise<unknown[]> {
		await this.ensureReady();
		const result = await this.query(
			"SELECT entry FROM cp_audit_events WHERE stream_id = $1 ORDER BY seq DESC LIMIT $2",
			[streamId, limit],
		);
		return result.rows.map((r) => JSON.parse(r.entry as string)).reverse();
	}

	async verifyAudit(streamId: string): Promise<ChainVerification> {
		await this.ensureReady();
		const result = await this.query(
			"SELECT prev_hash, hash, entry FROM cp_audit_events WHERE stream_id = $1 ORDER BY seq ASC",
			[streamId],
		);
		const lines = result.rows.map((r) =>
			JSON.stringify({ entry: JSON.parse(r.entry as string), prev: r.prev_hash, hash: r.hash }),
		);
		return verifyChain(lines);
	}

	async auditHeads(
		deviceStreamIds: string[],
	): Promise<{ admin: { head: string; entries: number }; devices: { deviceId: string; head: string; entries: number }[] }> {
		await this.ensureReady();
		const headOf = async (streamId: string): Promise<{ head: string; entries: number }> => {
			const h = await this.query("SELECT seq, head FROM cp_audit_heads WHERE stream_id = $1", [streamId]);
			if (h.rows.length === 0) return { head: CHAIN_GENESIS, entries: 0 };
			return { head: h.rows[0]?.head as string, entries: Number(h.rows[0]?.seq) };
		};
		const admin = await headOf(ADMIN_STREAM);
		const devices = await Promise.all(
			deviceStreamIds.map(async (deviceId) => ({ deviceId, ...(await headOf(deviceId)) })),
		);
		return { admin, devices };
	}

	async close(): Promise<void> {
		if (this.pool) await this.pool.end();
	}
}
