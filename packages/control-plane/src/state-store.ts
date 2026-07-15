import type { ChainVerification } from "@harness/shared";
import { CHAIN_GENESIS, computeChainHash, verifyChain } from "@harness/shared";
import { runMigrations } from "./pg-migrations.js";
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
	/** Applica un diff mirato e ritorna il cursore del changelog dopo la scrittura. */
	applyDiff(diff: StateDiff): Promise<number>;
	appendAudit(streamId: string, entries: unknown[]): Promise<void>;
	readAudit(streamId: string, limit: number): Promise<unknown[]>;
	verifyAudit(streamId: string): Promise<ChainVerification>;
	auditHeads(deviceStreamIds: string[]): Promise<{
		admin: { head: string; entries: number };
		devices: { deviceId: string; head: string; entries: number }[];
	}>;
	/**
	 * Elimina le righe di uno stream di audit più vecchie di `olderThanDays`,
	 * registrando il confine (seq, hash) in `cp_audit_prune_state` così
	 * `verifyAudit` continua a verificare il segmento residuo senza riscrivere
	 * né ricalcolare nulla.
	 */
	pruneAudit(streamId: string, olderThanDays: number): Promise<{ prunedRows: number }>;
	/**
	 * Rate limit a finestra fissa (60s) condiviso tra tutte le istanze che
	 * puntano allo stesso database (`cp_rate_buckets`, upsert atomico): ritorna
	 * true se `key` è ancora entro `limitPerWindow` in questa finestra.
	 */
	checkRateLimit(key: string, limitPerWindow: number): Promise<boolean>;
}

/**
 * Backend con sincronizzazione incrementale: invece di ricaricare l'intero
 * snapshot, le istanze applicano solo i delta dal changelog e vengono svegliate
 * via LISTEN/NOTIFY. Riduce drasticamente l'I/O di convergenza multi-istanza.
 */
export interface IncrementalStateStore extends NormalizedStateStore {
	readonly incremental: true;
	/** Ultimo id del changelog (cursore iniziale, per non riapplicare la storia). */
	changelogCursor(): Promise<number>;
	/**
	 * Delta accumulato dopo `sinceId`, come StateDiff pronto da fondere in
	 * memoria. Lancia `ChangelogPrunedError` se `sinceId` precede la soglia di
	 * pruning del changelog: il chiamante deve ricaricare l'intero snapshot
	 * invece di fidarsi di un delta parziale.
	 */
	pullDelta(sinceId: number): Promise<{ cursor: number; diff: StateDiff }>;
	/** Registra un handler svegliato dagli eventi NOTIFY; ritorna l'unsubscribe. */
	onChange(handler: () => void): Promise<() => Promise<void>>;
	/**
	 * Elimina le righe di changelog più vecchie mantenendo solo le ultime
	 * `keepLastN`, registrando la soglia (`cp_changelog_prune_floor`) così un
	 * replica troppo indietro viene rilevata da `pullDelta` invece di
	 * convergere silenziosamente su un delta incompleto.
	 */
	pruneChangelog(keepLastN: number): Promise<{ prunedRows: number }>;
}

/**
 * Lanciato da `pullDelta` quando il cursore richiesto precede la soglia di
 * pruning del changelog: il delta sarebbe incompleto (mancherebbero le
 * modifiche cancellate), quindi il chiamante deve ricaricare l'intero
 * snapshot invece di convergere su uno stato silenziosamente sbagliato.
 */
export class ChangelogPrunedError extends Error {
	constructor(
		readonly sinceId: number,
		readonly floor: number,
	) {
		super(`changelog troncato dal pruning: il cursore ${sinceId} precede la soglia ${floor}; serve un resync completo`);
		this.name = "ChangelogPrunedError";
	}
}

export function isNormalized(store: DurableStateStore): store is NormalizedStateStore {
	return (store as NormalizedStateStore).normalized === true;
}

export function isIncremental(store: DurableStateStore): store is IncrementalStateStore {
	return (store as IncrementalStateStore).incremental === true;
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
const CHANGE_CHANNEL = "cp_changes";

/** Entità del changelog (per la sincronizzazione incrementale). */
type EntityKind = "org" | "group" | "device" | "admin_token" | "gateway_token" | "enroll_token" | "signing_keys";

// biome-ignore lint/suspicious/noExplicitAny: righe grezze da pg
type Row = Record<string, any>;

/** Converte un valore timestamptz (Date o stringa) in ISO, o undefined se null. */
function iso(value: unknown): string | undefined {
	if (value === null || value === undefined) return undefined;
	if (value instanceof Date) return value.toISOString();
	return String(value);
}

// ---- Mappatura record ⇄ colonne tipizzate ---------------------------------

function orgToParams(o: OrgRecord): unknown[] {
	return [
		o.orgId,
		o.name,
		o.configVersion,
		o.killSwitch,
		o.configTtlMinutes,
		o.deviceTokenMaxAgeDays,
		o.requireDeviceCert,
		JSON.stringify(o.policyOverride),
		JSON.stringify(o.piSettingsOverride),
		o.allowCertTofu,
	];
}
function rowToOrg(r: Row): OrgRecord {
	return {
		orgId: r.org_id,
		name: r.name,
		configVersion: Number(r.config_version),
		killSwitch: r.kill_switch,
		configTtlMinutes: Number(r.config_ttl_minutes),
		deviceTokenMaxAgeDays: Number(r.device_token_max_age_days),
		requireDeviceCert: r.require_device_cert,
		policyOverride: r.policy_override,
		piSettingsOverride: r.pi_settings_override,
		allowCertTofu: r.allow_cert_tofu ?? false,
	};
}

function rowToGroup(r: Row): GroupRecord {
	return {
		groupId: r.group_id,
		name: r.name,
		killSwitch: r.kill_switch,
		policyOverride: r.policy_override,
		piSettingsOverride: r.pi_settings_override,
	};
}

function rowToDevice(r: Row): DeviceRecord {
	const d: DeviceRecord = {
		deviceId: r.device_id,
		name: r.name,
		groupId: r.group_id,
		tokenHash: r.token_hash,
		enrolledAt: iso(r.enrolled_at) as string,
		killSwitch: r.kill_switch,
		revoked: r.revoked,
		policyOverride: r.policy_override,
		piSettingsOverride: r.pi_settings_override,
	};
	const tokenIssuedAt = iso(r.token_issued_at);
	if (tokenIssuedAt) d.tokenIssuedAt = tokenIssuedAt;
	const lastSeenAt = iso(r.last_seen_at);
	if (lastSeenAt) d.lastSeenAt = lastSeenAt;
	if (r.last_config_version !== null && r.last_config_version !== undefined) {
		d.lastConfigVersion = Number(r.last_config_version);
	}
	if (r.cert_fingerprint) d.certFingerprint = r.cert_fingerprint;
	if (r.device_signing_public_key_pem) d.deviceSigningPublicKeyPem = r.device_signing_public_key_pem;
	return d;
}

function rowToEnroll(r: Row): EnrollTokenRecord {
	const e: EnrollTokenRecord = {
		groupId: r.group_id,
		createdAt: iso(r.created_at) as string,
		expiresAt: iso(r.expires_at) as string,
	};
	if (r.used_by) e.usedBy = r.used_by;
	return e;
}

function rowToAdmin(r: Row): AdminTokenRecord {
	const a: AdminTokenRecord = { name: r.name, role: r.role, createdAt: iso(r.created_at) as string };
	const expiresAt = iso(r.expires_at);
	if (expiresAt) a.expiresAt = expiresAt;
	return a;
}

function rowToGateway(r: Row): GatewayTokenRecord {
	return { name: r.name, createdAt: iso(r.created_at) as string };
}

function rowToSigningKey(r: Row): SigningKeyRecord {
	return {
		keyId: r.key_id,
		publicKeyPem: r.public_key_pem,
		privateKeyPem: r.private_key_pem,
		createdAt: iso(r.created_at) as string,
		active: r.active,
	};
}

/**
 * Backend Postgres a schema normalizzato REALE: una tabella per entità con
 * colonne tipizzate, chiavi esterne e indici (i JSONB restano solo per i
 * sotto-documenti di policy, genuinamente schemaless). L'audit è centralizzato
 * in `cp_audit_events` con testa di catena per-stream serializzata via advisory
 * lock. Un changelog + LISTEN/NOTIFY abilitano la sincronizzazione incrementale
 * multi-istanza senza ricaricare l'intero stato.
 *
 * Richiede la dipendenza opzionale `pg`. Import lazy.
 */
export class PostgresStateStore implements IncrementalStateStore {
	readonly normalized = true as const;
	readonly incremental = true as const;
	// biome-ignore lint/suspicious/noExplicitAny: il tipo del pool arriva da pg (dipendenza opzionale)
	private pool: any;
	// biome-ignore lint/suspicious/noExplicitAny: client dedicato per LISTEN/NOTIFY
	private listenClient: any;
	private ready = false;

	constructor(private readonly connectionString: string) {}

	private async ensureReady(): Promise<void> {
		if (this.ready) return;
		const pg = (await import("pg")).default as unknown as {
			Pool: new (config: { connectionString: string; max: number }) => unknown;
		};
		// Pool limitato: evita di esaurire le connessioni del server sotto carico.
		this.pool = new pg.Pool({ connectionString: this.connectionString, max: 8 });
		// Migrazioni versionate (packages/control-plane/src/pg-migrations.ts): un
		// database già popolato converge allo schema atteso applicando solo le
		// migrazioni mancanti, invece del solo CREATE TABLE IF NOT EXISTS (che non
		// fa nulla se la tabella esiste già con una forma diversa).
		await runMigrations(this.pool, (text, params) => this.query(text, params));
		this.ready = true;
	}

	private async query(text: string, params: unknown[] = []): Promise<{ rows: Row[] }> {
		return this.pool.query(text, params) as Promise<{ rows: Row[] }>;
	}

	async load(): Promise<StateSnapshot | null> {
		await this.ensureReady();
		const org = await this.query("SELECT * FROM cp_org WHERE id = 1");
		if (org.rows.length === 0) return null;
		const [groups, devices, adminTokens, gatewayTokens, enrollTokens, signingKeys] = await Promise.all([
			this.query("SELECT * FROM cp_groups"),
			this.query("SELECT * FROM cp_devices"),
			this.query("SELECT * FROM cp_admin_tokens"),
			this.query("SELECT * FROM cp_gateway_tokens"),
			this.query("SELECT * FROM cp_enroll_tokens"),
			this.query("SELECT * FROM cp_signing_keys"),
		]);
		const index = <T>(rows: Row[], key: string, map: (r: Row) => T): Record<string, T> => {
			const out: Record<string, T> = {};
			for (const row of rows) out[row[key] as string] = map(row);
			return out;
		};
		const state: ControlPlaneState = {
			org: rowToOrg(org.rows[0] as Row),
			groups: index(groups.rows, "group_id", rowToGroup),
			devices: index(devices.rows, "device_id", rowToDevice),
			adminTokens: index(adminTokens.rows, "token_hash", rowToAdmin),
			gatewayTokens: index(gatewayTokens.rows, "token_hash", rowToGateway),
			enrollTokens: index(enrollTokens.rows, "token_hash", rowToEnroll),
		};
		return { state, signingKeys: signingKeys.rows.map(rowToSigningKey) };
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

	/**
	 * Applica un diff in un'unica transazione, con ordine consapevole delle FK
	 * (gruppi prima dei device negli upsert, device prima dei gruppi nelle
	 * cancellazioni), registra il changelog e sveglia le altre istanze con
	 * NOTIFY. Ritorna il cursore del changelog dopo la scrittura.
	 */
	async applyDiff(diff: StateDiff): Promise<number> {
		await this.ensureReady();
		const client = await this.connect();
		try {
			await client.query("BEGIN");
			const changes: [EntityKind, string, "upsert" | "delete"][] = [];

			if (diff.org) {
				await client.query(
					`INSERT INTO cp_org (id, org_id, name, config_version, kill_switch, config_ttl_minutes,
						device_token_max_age_days, require_device_cert, policy_override, pi_settings_override,
						allow_cert_tofu)
					 VALUES (1,$1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
					 ON CONFLICT (id) DO UPDATE SET org_id=$1, name=$2, config_version=$3, kill_switch=$4,
						config_ttl_minutes=$5, device_token_max_age_days=$6, require_device_cert=$7,
						policy_override=$8, pi_settings_override=$9, allow_cert_tofu=$10`,
					orgToParams(diff.org),
				);
				changes.push(["org", "", "upsert"]);
			}
			// Gruppi upsert prima dei device (FK device.group_id → groups).
			for (const g of diff.groupsUpsert) {
				await client.query(
					`INSERT INTO cp_groups (group_id, name, kill_switch, policy_override, pi_settings_override)
					 VALUES ($1,$2,$3,$4,$5)
					 ON CONFLICT (group_id) DO UPDATE SET name=$2, kill_switch=$3, policy_override=$4, pi_settings_override=$5`,
					[g.groupId, g.name, g.killSwitch, JSON.stringify(g.policyOverride), JSON.stringify(g.piSettingsOverride)],
				);
				changes.push(["group", g.groupId, "upsert"]);
			}
			for (const d of diff.devicesUpsert) {
				await client.query(
					`INSERT INTO cp_devices (device_id, name, group_id, token_hash, token_issued_at, enrolled_at,
						last_seen_at, last_config_version, kill_switch, revoked, cert_fingerprint,
						policy_override, pi_settings_override, device_signing_public_key_pem)
					 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)
					 ON CONFLICT (device_id) DO UPDATE SET name=$2, group_id=$3, token_hash=$4, token_issued_at=$5,
						enrolled_at=$6, last_seen_at=$7, last_config_version=$8, kill_switch=$9, revoked=$10,
						cert_fingerprint=$11, policy_override=$12, pi_settings_override=$13,
						device_signing_public_key_pem=$14`,
					[
						d.deviceId,
						d.name,
						d.groupId,
						d.tokenHash,
						d.tokenIssuedAt ?? null,
						d.enrolledAt,
						d.lastSeenAt ?? null,
						d.lastConfigVersion ?? null,
						d.killSwitch,
						d.revoked,
						d.certFingerprint ?? null,
						JSON.stringify(d.policyOverride),
						JSON.stringify(d.piSettingsOverride),
						d.deviceSigningPublicKeyPem ?? null,
					],
				);
				changes.push(["device", d.deviceId, "upsert"]);
			}
			for (const [h, t] of diff.adminTokensUpsert) {
				await client.query(
					`INSERT INTO cp_admin_tokens (token_hash, name, role, created_at, expires_at)
					 VALUES ($1,$2,$3,$4,$5)
					 ON CONFLICT (token_hash) DO UPDATE SET name=$2, role=$3, created_at=$4, expires_at=$5`,
					[h, t.name, t.role, t.createdAt, t.expiresAt ?? null],
				);
				changes.push(["admin_token", h, "upsert"]);
			}
			for (const [h, t] of diff.gatewayTokensUpsert) {
				await client.query(
					`INSERT INTO cp_gateway_tokens (token_hash, name, created_at) VALUES ($1,$2,$3)
					 ON CONFLICT (token_hash) DO UPDATE SET name=$2, created_at=$3`,
					[h, t.name, t.createdAt],
				);
				changes.push(["gateway_token", h, "upsert"]);
			}
			for (const [h, t] of diff.enrollTokensUpsert) {
				await client.query(
					`INSERT INTO cp_enroll_tokens (token_hash, group_id, created_at, expires_at, used_by)
					 VALUES ($1,$2,$3,$4,$5)
					 ON CONFLICT (token_hash) DO UPDATE SET group_id=$2, created_at=$3, expires_at=$4, used_by=$5`,
					[h, t.groupId, t.createdAt, t.expiresAt, t.usedBy ?? null],
				);
				changes.push(["enroll_token", h, "upsert"]);
			}
			// Cancellazioni: device prima dei gruppi (FK).
			for (const key of diff.devicesDelete) {
				await client.query("DELETE FROM cp_devices WHERE device_id = $1", [key]);
				changes.push(["device", key, "delete"]);
			}
			for (const key of diff.adminTokensDelete) {
				await client.query("DELETE FROM cp_admin_tokens WHERE token_hash = $1", [key]);
				changes.push(["admin_token", key, "delete"]);
			}
			for (const key of diff.enrollTokensDelete) {
				await client.query("DELETE FROM cp_enroll_tokens WHERE token_hash = $1", [key]);
				changes.push(["enroll_token", key, "delete"]);
			}
			for (const key of diff.groupsDelete) {
				await client.query("DELETE FROM cp_groups WHERE group_id = $1", [key]);
				changes.push(["group", key, "delete"]);
			}
			if (diff.signingKeys) {
				await client.query("DELETE FROM cp_signing_keys");
				for (const k of diff.signingKeys) {
					await client.query(
						`INSERT INTO cp_signing_keys (key_id, public_key_pem, private_key_pem, created_at, active)
						 VALUES ($1,$2,$3,$4,$5)`,
						[k.keyId, k.publicKeyPem, k.privateKeyPem, k.createdAt, k.active],
					);
				}
				changes.push(["signing_keys", "", "upsert"]);
			}

			let cursor = 0;
			if (changes.length > 0) {
				const values: string[] = [];
				const params: unknown[] = [];
				changes.forEach((c, i) => {
					values.push(`($${i * 3 + 1}, $${i * 3 + 2}, $${i * 3 + 3})`);
					params.push(c[0], c[1], c[2]);
				});
				const inserted = await client.query(
					`INSERT INTO cp_changelog (entity, entity_key, op) VALUES ${values.join(",")} RETURNING id`,
					params,
				);
				cursor = Math.max(...inserted.rows.map((r) => Number(r.id)));
				await client.query(`NOTIFY ${CHANGE_CHANNEL}`);
			} else {
				const max = await client.query("SELECT COALESCE(MAX(id),0) AS id FROM cp_changelog");
				cursor = Number(max.rows[0]?.id ?? 0);
			}
			await client.query("COMMIT");
			return cursor;
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}

	// ---- Sincronizzazione incrementale --------------------------------------

	async changelogCursor(): Promise<number> {
		await this.ensureReady();
		const max = await this.query("SELECT COALESCE(MAX(id),0) AS id FROM cp_changelog");
		return Number(max.rows[0]?.id ?? 0);
	}

	async pullDelta(sinceId: number): Promise<{ cursor: number; diff: StateDiff }> {
		await this.ensureReady();
		const floorRow = await this.query("SELECT floor_id FROM cp_changelog_prune_floor WHERE id = 1");
		const floor = floorRow.rows.length > 0 ? Number(floorRow.rows[0]!.floor_id) : 0;
		if (floor > 0 && sinceId < floor) throw new ChangelogPrunedError(sinceId, floor);
		const diff: StateDiff = {
			groupsUpsert: [],
			groupsDelete: [],
			devicesUpsert: [],
			devicesDelete: [],
			adminTokensUpsert: [],
			adminTokensDelete: [],
			gatewayTokensUpsert: [],
			enrollTokensUpsert: [],
			enrollTokensDelete: [],
		};
		const rows = (
			await this.query("SELECT id, entity, entity_key, op FROM cp_changelog WHERE id > $1 ORDER BY id ASC", [sinceId])
		).rows;
		if (rows.length === 0) return { cursor: sinceId, diff };

		// Ultima operazione per (entità, chiave): comprime i cambi ripetuti.
		const latest = new Map<string, { entity: EntityKind; key: string; op: string }>();
		let cursor = sinceId;
		for (const r of rows) {
			cursor = Math.max(cursor, Number(r.id));
			latest.set(`${r.entity} ${r.entity_key}`, { entity: r.entity, key: r.entity_key, op: r.op });
		}

		const upsertKeys: Record<string, string[]> = {
			group: [],
			device: [],
			admin_token: [],
			gateway_token: [],
			enroll_token: [],
		};
		let orgChanged = false;
		let signingChanged = false;
		for (const { entity, key, op } of latest.values()) {
			if (entity === "org") orgChanged = true;
			else if (entity === "signing_keys") signingChanged = true;
			else if (op === "delete") {
				if (entity === "group") diff.groupsDelete.push(key);
				else if (entity === "device") diff.devicesDelete.push(key);
				else if (entity === "admin_token") diff.adminTokensDelete.push(key);
				else if (entity === "enroll_token") diff.enrollTokensDelete.push(key);
			} else {
				upsertKeys[entity]?.push(key);
			}
		}

		if (orgChanged) {
			const org = await this.query("SELECT * FROM cp_org WHERE id = 1");
			if (org.rows[0]) diff.org = rowToOrg(org.rows[0]);
		}
		if (signingChanged) {
			const keys = await this.query("SELECT * FROM cp_signing_keys");
			diff.signingKeys = keys.rows.map(rowToSigningKey);
		}
		if (upsertKeys.group!.length > 0) {
			const r = await this.query("SELECT * FROM cp_groups WHERE group_id = ANY($1)", [upsertKeys.group]);
			diff.groupsUpsert = r.rows.map(rowToGroup);
		}
		if (upsertKeys.device!.length > 0) {
			const r = await this.query("SELECT * FROM cp_devices WHERE device_id = ANY($1)", [upsertKeys.device]);
			diff.devicesUpsert = r.rows.map(rowToDevice);
		}
		if (upsertKeys.admin_token!.length > 0) {
			const r = await this.query("SELECT * FROM cp_admin_tokens WHERE token_hash = ANY($1)", [upsertKeys.admin_token]);
			diff.adminTokensUpsert = r.rows.map((row) => [row.token_hash as string, rowToAdmin(row)]);
		}
		if (upsertKeys.gateway_token!.length > 0) {
			const r = await this.query("SELECT * FROM cp_gateway_tokens WHERE token_hash = ANY($1)", [
				upsertKeys.gateway_token,
			]);
			diff.gatewayTokensUpsert = r.rows.map((row) => [row.token_hash as string, rowToGateway(row)]);
		}
		if (upsertKeys.enroll_token!.length > 0) {
			const r = await this.query("SELECT * FROM cp_enroll_tokens WHERE token_hash = ANY($1)", [
				upsertKeys.enroll_token,
			]);
			diff.enrollTokensUpsert = r.rows.map((row) => [row.token_hash as string, rowToEnroll(row)]);
		}
		return { cursor, diff };
	}

	async onChange(handler: () => void): Promise<() => Promise<void>> {
		await this.ensureReady();
		const client = await this.connect();
		this.listenClient = client;
		client.on("notification", () => handler());
		// Se la connessione dedicata cade, non deve abbattere il processo: il poll
		// periodico del chiamante resta come rete di sicurezza.
		client.on("error", () => {});
		await client.query(`LISTEN ${CHANGE_CHANNEL}`);
		return async () => {
			try {
				await client.query(`UNLISTEN ${CHANGE_CHANNEL}`);
			} finally {
				client.release();
				this.listenClient = undefined;
			}
		};
	}

	private async connect(): Promise<{
		query: (t: string, p?: unknown[]) => Promise<{ rows: Row[] }>;
		on: (event: string, cb: (...args: unknown[]) => void) => void;
		release: () => void;
	}> {
		await this.ensureReady();
		return this.pool.connect();
	}

	// ---- Audit centralizzato -------------------------------------------------

	async appendAudit(streamId: string, entries: unknown[]): Promise<void> {
		if (entries.length === 0) return;
		await this.ensureReady();
		const client = await this.connect();
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
		const pruneState = await this.query("SELECT pruned_up_to_hash FROM cp_audit_prune_state WHERE stream_id = $1", [
			streamId,
		]);
		const genesis = pruneState.rows.length > 0 ? (pruneState.rows[0]!.pruned_up_to_hash as string) : CHAIN_GENESIS;
		const result = await this.query(
			"SELECT prev_hash, hash, entry FROM cp_audit_events WHERE stream_id = $1 ORDER BY seq ASC",
			[streamId],
		);
		const lines = result.rows.map((r) =>
			JSON.stringify({ entry: JSON.parse(r.entry as string), prev: r.prev_hash, hash: r.hash }),
		);
		return verifyChain(lines, genesis);
	}

	/**
	 * Elimina dallo stream le righe più vecchie di `olderThanDays`, registrando
	 * in `cp_audit_prune_state` il confine (seq, hash) della riga più recente
	 * eliminata: `verifyAudit` verifica poi il segmento residuo a partire da
	 * quell'hash come genesis, invece che dal genesis assoluto, senza toccare
	 * né ricalcolare le righe conservate.
	 */
	async pruneAudit(streamId: string, olderThanDays: number): Promise<{ prunedRows: number }> {
		await this.ensureReady();
		const client = await this.connect();
		try {
			await client.query("BEGIN");
			// Stesso advisory lock usato da appendAudit: evita di potare mentre un
			// append concorrente sta ancora scrivendo la testa della catena.
			await client.query("SELECT pg_advisory_xact_lock(hashtext($1))", [streamId]);
			// La riga più recente tra quelle più vecchie della soglia: ts cresce
			// monotonamente con seq (append sequenziale), quindi tutte e sole le
			// righe con seq <= questa sono più vecchie della soglia.
			const boundary = await client.query(
				`SELECT seq, hash FROM cp_audit_events
				 WHERE stream_id = $1 AND ts < now() - ($2 || ' days')::interval
				 ORDER BY seq DESC LIMIT 1`,
				[streamId, olderThanDays],
			);
			if (boundary.rows.length === 0) {
				// Nessuna riga più vecchia della soglia: nulla da potare.
				await client.query("COMMIT");
				return { prunedRows: 0 };
			}
			const boundarySeq = Number(boundary.rows[0]!.seq);
			const boundaryHash = boundary.rows[0]!.hash as string;
			const deleted = await client.query(
				"DELETE FROM cp_audit_events WHERE stream_id = $1 AND seq <= $2 RETURNING seq",
				[streamId, boundarySeq],
			);
			await client.query(
				`INSERT INTO cp_audit_prune_state (stream_id, pruned_up_to_seq, pruned_up_to_hash)
				 VALUES ($1,$2,$3)
				 ON CONFLICT (stream_id) DO UPDATE SET pruned_up_to_seq = $2, pruned_up_to_hash = $3`,
				[streamId, boundarySeq, boundaryHash],
			);
			await client.query("COMMIT");
			return { prunedRows: deleted.rows.length };
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}

	/**
	 * Elimina le righe di changelog più vecchie mantenendo solo le ultime
	 * `keepLastN`, registrando la soglia in `cp_changelog_prune_floor` così
	 * `pullDelta` può rilevare un cursore troppo indietro invece di convergere
	 * silenziosamente su un delta incompleto.
	 */
	async pruneChangelog(keepLastN: number): Promise<{ prunedRows: number }> {
		await this.ensureReady();
		const client = await this.connect();
		try {
			await client.query("BEGIN");
			const boundary = await client.query("SELECT id FROM cp_changelog ORDER BY id DESC OFFSET $1 LIMIT 1", [
				keepLastN,
			]);
			if (boundary.rows.length === 0) {
				await client.query("COMMIT");
				return { prunedRows: 0 };
			}
			const boundaryId = Number(boundary.rows[0]!.id);
			const deleted = await client.query("DELETE FROM cp_changelog WHERE id <= $1 RETURNING id", [boundaryId]);
			await client.query(
				`INSERT INTO cp_changelog_prune_floor (id, floor_id) VALUES (1, $1)
				 ON CONFLICT (id) DO UPDATE SET floor_id = GREATEST(cp_changelog_prune_floor.floor_id, $1)`,
				[boundaryId],
			);
			await client.query("COMMIT");
			return { prunedRows: deleted.rows.length };
		} catch (error) {
			await client.query("ROLLBACK");
			throw error;
		} finally {
			client.release();
		}
	}

	async auditHeads(deviceStreamIds: string[]): Promise<{
		admin: { head: string; entries: number };
		devices: { deviceId: string; head: string; entries: number }[];
	}> {
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

	/**
	 * Upsert atomico su `cp_rate_buckets`: o crea il bucket (prima richiesta
	 * nella finestra) o avanza il conteggio, resettando la finestra se è scaduta
	 * (60s) — un solo round-trip, senza lock espliciti, così N istanze che
	 * condividono il DB condividono anche il conteggio invece di applicare
	 * ciascuna la propria soglia in memoria (N×soglia effettiva).
	 */
	async checkRateLimit(key: string, limitPerWindow: number): Promise<boolean> {
		await this.ensureReady();
		const result = await this.query(
			`INSERT INTO cp_rate_buckets (bucket_key, window_start, count)
			 VALUES ($1, now(), 1)
			 ON CONFLICT (bucket_key) DO UPDATE SET
				count = CASE WHEN cp_rate_buckets.window_start < now() - interval '60 seconds'
					THEN 1 ELSE cp_rate_buckets.count + 1 END,
				window_start = CASE WHEN cp_rate_buckets.window_start < now() - interval '60 seconds'
					THEN now() ELSE cp_rate_buckets.window_start END
			 RETURNING count`,
			[key],
		);
		const count = Number(result.rows[0]?.count ?? 1);
		return count <= limitPerWindow;
	}

	async close(): Promise<void> {
		if (this.listenClient) {
			try {
				this.listenClient.release();
			} catch {
				// la connessione potrebbe essere già chiusa
			}
			this.listenClient = undefined;
		}
		if (this.pool) await this.pool.end();
	}
}
