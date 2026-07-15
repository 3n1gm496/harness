/**
 * Migrazioni di schema Postgres, versionate e ordinali. Ogni voce è applicata
 * in una transazione singola e la sua versione viene registrata in
 * `cp_schema_version`; al riavvio si applicano solo le migrazioni con
 * `version` superiore all'ultima registrata. Questo è ciò che rende sicuro
 * evolvere lo schema su un database già popolato (aggiungere una colonna,
 * un indice, una tabella) senza il rischio del solo `CREATE TABLE IF NOT
 * EXISTS`, che non fa nulla se la tabella esiste già con una forma diversa.
 *
 * Regole per aggiungere una migrazione:
 *   - mai modificare una migrazione già rilasciata: aggiungerne una nuova;
 *   - il `version` è l'intero successivo al più alto esistente;
 *   - preferire `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` per le colonne, così
 *     una migrazione resta idempotente anche se ri-applicata manualmente.
 */
export interface Migration {
	version: number;
	description: string;
	sql: string;
}

export const MIGRATIONS: Migration[] = [
	{
		version: 1,
		description: "schema iniziale: org, gruppi, device, token, chiavi di firma, audit centralizzato, changelog",
		sql: `
			CREATE TABLE IF NOT EXISTS cp_org (
				id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
				org_id text NOT NULL,
				name text NOT NULL,
				config_version int NOT NULL,
				kill_switch boolean NOT NULL,
				config_ttl_minutes int NOT NULL,
				device_token_max_age_days int NOT NULL,
				require_device_cert boolean NOT NULL,
				policy_override jsonb NOT NULL,
				pi_settings_override jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_groups (
				group_id text PRIMARY KEY,
				name text NOT NULL,
				kill_switch boolean NOT NULL,
				policy_override jsonb NOT NULL,
				pi_settings_override jsonb NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_devices (
				device_id text PRIMARY KEY,
				name text NOT NULL,
				group_id text NOT NULL REFERENCES cp_groups(group_id),
				token_hash text NOT NULL UNIQUE,
				token_issued_at timestamptz,
				enrolled_at timestamptz NOT NULL,
				last_seen_at timestamptz,
				last_config_version int,
				kill_switch boolean NOT NULL,
				revoked boolean NOT NULL,
				cert_fingerprint text,
				policy_override jsonb NOT NULL,
				pi_settings_override jsonb NOT NULL);
			CREATE INDEX IF NOT EXISTS cp_devices_group_id_idx ON cp_devices(group_id);
			CREATE TABLE IF NOT EXISTS cp_admin_tokens (
				token_hash text PRIMARY KEY,
				name text NOT NULL,
				role text NOT NULL,
				created_at timestamptz NOT NULL,
				expires_at timestamptz);
			CREATE TABLE IF NOT EXISTS cp_gateway_tokens (
				token_hash text PRIMARY KEY,
				name text NOT NULL,
				created_at timestamptz NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_enroll_tokens (
				token_hash text PRIMARY KEY,
				group_id text NOT NULL,
				created_at timestamptz NOT NULL,
				expires_at timestamptz NOT NULL,
				used_by text);
			CREATE INDEX IF NOT EXISTS cp_enroll_expires_idx ON cp_enroll_tokens(expires_at);
			CREATE TABLE IF NOT EXISTS cp_signing_keys (
				key_id text PRIMARY KEY,
				public_key_pem text NOT NULL,
				private_key_pem text NOT NULL,
				created_at timestamptz NOT NULL,
				active boolean NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_audit_events (
				stream_id text NOT NULL, seq bigint NOT NULL, prev_hash text NOT NULL, hash text NOT NULL,
				entry text NOT NULL, ts timestamptz NOT NULL DEFAULT now(), PRIMARY KEY (stream_id, seq));
			CREATE TABLE IF NOT EXISTS cp_audit_heads (stream_id text PRIMARY KEY, seq bigint NOT NULL, head text NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_changelog (
				id bigserial PRIMARY KEY, entity text NOT NULL, entity_key text NOT NULL, op text NOT NULL,
				ts timestamptz NOT NULL DEFAULT now());
		`,
	},
	{
		version: 2,
		description: "provenance audit device: chiave pubblica di firma propria del device",
		sql: `ALTER TABLE cp_devices ADD COLUMN IF NOT EXISTS device_signing_public_key_pem text;`,
	},
	{
		version: 3,
		description: "org.allowCertTofu: disabilita di default il trust-on-first-use del certificato",
		sql: `ALTER TABLE cp_org ADD COLUMN IF NOT EXISTS allow_cert_tofu boolean NOT NULL DEFAULT false;`,
	},
	{
		version: 4,
		description: "rate limit condiviso multi-istanza (bucket per chiave logica)",
		sql: `
			CREATE TABLE IF NOT EXISTS cp_rate_buckets (
				bucket_key text PRIMARY KEY,
				window_start timestamptz NOT NULL,
				count int NOT NULL);
		`,
	},
	{
		version: 5,
		description: "retention: stato di pruning per audit (genesis del segmento residuo) e changelog",
		sql: `
			CREATE TABLE IF NOT EXISTS cp_audit_prune_state (
				stream_id text PRIMARY KEY,
				pruned_up_to_seq bigint NOT NULL,
				pruned_up_to_hash text NOT NULL);
			CREATE TABLE IF NOT EXISTS cp_changelog_prune_floor (
				id int PRIMARY KEY DEFAULT 1 CHECK (id = 1),
				floor_id bigint NOT NULL);
		`,
	},
];

/** Query minimale richiesta dal migration runner (sottoinsieme del client pg). */
export interface MigrationQueryable {
	query(text: string, params?: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

/**
 * Applica in ordine le migrazioni non ancora registrate, ciascuna nella
 * propria transazione. `connect` apre una connessione dedicata (serve una
 * connessione singola per BEGIN/COMMIT coerenti, non il pool condiviso).
 */
export async function runMigrations(
	pool: { connect(): Promise<MigrationQueryable & { release(): void }> },
	query: (text: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }>,
): Promise<void> {
	await query(`
		CREATE TABLE IF NOT EXISTS cp_schema_version (
			version int PRIMARY KEY,
			description text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now());
	`);
	const current = await query("SELECT COALESCE(MAX(version), 0) AS v FROM cp_schema_version");
	const currentVersion = Number(current.rows[0]?.v ?? 0);
	const pending = MIGRATIONS.filter((m) => m.version > currentVersion).sort((a, b) => a.version - b.version);

	for (const migration of pending) {
		const client = await pool.connect();
		try {
			await client.query("BEGIN");
			await client.query(migration.sql);
			await client.query("INSERT INTO cp_schema_version (version, description) VALUES ($1, $2)", [
				migration.version,
				migration.description,
			]);
			await client.query("COMMIT");
		} catch (error) {
			await client.query("ROLLBACK");
			throw new Error(
				`migrazione ${migration.version} (${migration.description}) fallita: ${
					error instanceof Error ? error.message : String(error)
				}`,
			);
		} finally {
			client.release();
		}
	}
}
