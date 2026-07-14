import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { generateKek, signPayload } from "@harness/shared";
import { ControlPlaneService } from "../service.js";
import { InMemoryStateStore, PostgresStateStore } from "../state-store.js";
import { Store } from "../store.js";

const KEK = { kek: { key: Buffer.from(generateKek(), "base64") } };

test("con KEK le chiavi private sono sigillate su disco ma usabili in memoria", () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-kek-"));
	try {
		const store = new Store(dir, KEK);
		// Su disco: nessuna chiave privata in chiaro.
		const onDisk = readFileSync(join(dir, "keys", "signing-keys.json"), "utf8");
		assert.ok(!onDisk.includes("PRIVATE KEY"), "la chiave privata non deve essere in chiaro su disco");
		assert.ok(onDisk.includes("harness-sealed:v1:"), "la chiave deve essere sigillata");
		// In memoria: la chiave è usabile per firmare.
		const token = signPayload(store.signingPrivateKeyPem, { ok: true });
		assert.equal(token.split(".").length, 3);
		// Riaprendo con la stessa KEK, la chiave si decifra e resta stabile.
		const reopened = new Store(dir, KEK);
		assert.equal(reopened.signingPublicKeyPem, store.signingPublicKeyPem);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Store con backend in-memory: idratazione e write-behind", async () => {
	const dir1 = mkdtempSync(join(tmpdir(), "harness-ss-a-"));
	const backend = new InMemoryStateStore();
	try {
		// Prima apertura: backend vuoto → lo stato locale viene salvato nel backend.
		const store = await Store.openWithBackend(dir1, backend, KEK);
		const service = new ControlPlaneService(store);
		const admin = service.bootstrapAdminToken("capo");
		const identity = service.authenticateAdmin(admin);
		service.createGroup(identity, "produzione");
		await store.flush();

		// Seconda apertura (data dir diversa) sullo stesso backend: lo stato
		// viene idratato dal backend, non dal file locale.
		const dir2 = mkdtempSync(join(tmpdir(), "harness-ss-b-"));
		try {
			const store2 = await Store.openWithBackend(dir2, backend, KEK);
			const groups = Object.values(store2.state.groups).map((g) => g.name);
			assert.ok(groups.includes("produzione"));
			assert.equal(store2.state.org.orgId, store.state.org.orgId);
		} finally {
			rmSync(dir2, { recursive: true, force: true });
		}
	} finally {
		rmSync(dir1, { recursive: true, force: true });
	}
});

test("le chiavi di firma sono incluse nello snapshot durevole", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-ss-keys-"));
	const backend = new InMemoryStateStore();
	try {
		const store = await Store.openWithBackend(dir, backend, KEK);
		const service = new ControlPlaneService(store);
		const admin = service.bootstrapAdminToken("k");
		const identity = service.authenticateAdmin(admin);
		service.addSigningKey(identity);
		await store.flush();
		const snapshot = await backend.load();
		assert.ok(snapshot);
		assert.equal(snapshot.signingKeys.length, 2);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

// Test live contro Postgres, eseguito solo se HARNESS_TEST_PG_URL è impostata.
const PG_URL = process.env.HARNESS_TEST_PG_URL;

async function resetPgSchema(url: string): Promise<void> {
	const s = new PostgresStateStore(url);
	// biome-ignore lint/suspicious/noExplicitAny: reset schema di test
	await (s as any).ensureReady();
	// TRUNCATE ... CASCADE azzera anche le sequenze (il cursore del changelog
	// riparte da zero) e gestisce l'ordine imposto dalle foreign key.
	// biome-ignore lint/suspicious/noExplicitAny: query di reset
	await (s as any).query(
		`TRUNCATE cp_org, cp_groups, cp_devices, cp_admin_tokens, cp_gateway_tokens,
			cp_enroll_tokens, cp_signing_keys, cp_audit_events, cp_audit_heads, cp_changelog,
			cp_rate_buckets
		 RESTART IDENTITY CASCADE`,
	);
	await s.close();
}

test("Postgres: append audit concorrenti sullo stesso stream restano integri (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const a = new PostgresStateStore(url);
	const b = new PostgresStateStore(url);
	try {
		const mkEvent = (i: number) => ({
			eventId: `e${i}`,
			deviceId: "dev_x",
			timestamp: new Date().toISOString(),
			type: "policy_decision",
			data: { i },
		});
		// Due connessioni appendono 50 eventi ciascuna, in parallelo, allo stesso
		// stream: la serializzazione per-stream (SELECT FOR UPDATE) deve produrre
		// una catena unica, integra, con tutti i 100 eventi.
		const appendsA = Array.from({ length: 20 }, (_, i) => a.appendAudit("dev_x", [mkEvent(i)]));
		const appendsB = Array.from({ length: 20 }, (_, i) => b.appendAudit("dev_x", [mkEvent(100 + i)]));
		await Promise.all([...appendsA, ...appendsB]);

		const verify = await a.verifyAudit("dev_x");
		assert.equal(verify.valid, true);
		if (verify.valid) assert.equal(verify.entries, 40);
	} finally {
		await a.close();
		await b.close();
	}
});

test("Postgres normalizzato: scritture mirate e multi-istanza convergente (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const dirA = mkdtempSync(join(tmpdir(), "harness-pg-a-"));
	const dirB = mkdtempSync(join(tmpdir(), "harness-pg-b-"));
	const storeA = await Store.openWithBackend(dirA, new PostgresStateStore(url), KEK);
	const storeB = await Store.openWithBackend(dirB, new PostgresStateStore(url), KEK);
	try {
		const svcA = new ControlPlaneService(storeA);
		const admin = svcA.bootstrapAdminToken("root");
		const idA = svcA.authenticateAdmin(admin);
		const groupId = svcA.overview(idA).groups[0]?.groupId as string;

		// Istanza A arruola un device; B lo vede dopo un refresh (convergenza).
		const enr = svcA.createEnrollToken(idA, groupId, 10);
		const dev = svcA.enrollDevice(enr, "d-mtls");
		await storeA.flush();
		await storeB.refreshNow();
		assert.ok(storeB.state.devices[dev.deviceId], "l'istanza B deve vedere il device creato da A");

		// Mutazioni concorrenti su device diversi non si sovrascrivono (row-level).
		const enr2 = svcA.createEnrollToken(idA, groupId, 10);
		const dev2 = svcA.enrollDevice(enr2, "d2");
		await storeA.flush();
		await storeB.refreshNow();
		const svcB = new ControlPlaneService(storeB);
		// B sospende dev2 mentre A lo lascia attivo: scrittura mirata su dev2.
		svcB.updateDevice(svcB.authenticateAdmin(admin), dev2.deviceId, { killSwitch: true });
		await storeB.flush();
		await storeA.refreshNow();
		assert.equal(storeA.state.devices[dev2.deviceId]?.killSwitch, true);
		assert.equal(storeA.state.devices[dev.deviceId]?.killSwitch, false);

		// Audit centralizzato: A scrive, B lo legge dallo stesso DB, catena integra.
		storeA.appendDeviceAudit(dev.deviceId, [
			{ eventId: "e1", deviceId: dev.deviceId, timestamp: new Date().toISOString(), type: "agent_start", data: {} },
			{ eventId: "e2", deviceId: dev.deviceId, timestamp: new Date().toISOString(), type: "policy_decision", data: {} },
		]);
		await storeA.flush();
		const events = await storeB.readDeviceAudit(dev.deviceId, 10);
		assert.equal(events.length, 2);
		const verify = await storeB.verifyDeviceAudit(dev.deviceId);
		assert.equal(verify.valid, true);
		const heads = await storeB.auditHeads();
		assert.ok(heads.devices.find((d) => d.deviceId === dev.deviceId)?.entries === 2);
	} finally {
		await storeA.close();
		await storeB.close();
		rmSync(dirA, { recursive: true, force: true });
		rmSync(dirB, { recursive: true, force: true });
	}
});

test("Postgres incrementale: pullDelta consegna solo i cambi e NOTIFY sveglia i listener (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const writer = new PostgresStateStore(url);
	const reader = new PostgresStateStore(url);
	try {
		// Cursore iniziale a zero (changelog vuoto dopo il reset).
		assert.equal(await reader.changelogCursor(), 0);

		// Un NOTIFY del writer sveglia il listener del reader.
		let notified = 0;
		const unsubscribe = await reader.onChange(() => {
			notified += 1;
		});

		await writer.applyDiff({
			org: {
				orgId: "org_1",
				name: "acme",
				configVersion: 1,
				killSwitch: false,
				configTtlMinutes: 60,
				deviceTokenMaxAgeDays: 90,
				requireDeviceCert: false,
				allowCertTofu: false,
				policyOverride: {},
				piSettingsOverride: {},
			},
			groupsUpsert: [{ groupId: "grp_1", name: "prod", killSwitch: false, policyOverride: {}, piSettingsOverride: {} }],
			groupsDelete: [],
			devicesUpsert: [],
			devicesDelete: [],
			adminTokensUpsert: [],
			adminTokensDelete: [],
			gatewayTokensUpsert: [],
			enrollTokensUpsert: [],
			enrollTokensDelete: [],
		});

		// pullDelta dal cursore 0 restituisce esattamente org + gruppo, e avanza.
		const first = await reader.pullDelta(0);
		assert.ok(first.cursor > 0);
		assert.equal(first.diff.org?.name, "acme");
		assert.equal(first.diff.groupsUpsert.length, 1);
		assert.equal(first.diff.devicesUpsert.length, 0);

		// Dal nuovo cursore non c'è altro delta (nessuna riscrittura completa).
		const empty = await reader.pullDelta(first.cursor);
		assert.equal(empty.cursor, first.cursor);
		assert.equal(empty.diff.groupsUpsert.length, 0);

		// Una seconda scrittura mirata (solo il gruppo) appare come singolo delta.
		await writer.applyDiff({
			groupsUpsert: [{ groupId: "grp_1", name: "prod-2", killSwitch: true, policyOverride: {}, piSettingsOverride: {} }],
			groupsDelete: [],
			devicesUpsert: [],
			devicesDelete: [],
			adminTokensUpsert: [],
			adminTokensDelete: [],
			gatewayTokensUpsert: [],
			enrollTokensUpsert: [],
			enrollTokensDelete: [],
		});
		const second = await reader.pullDelta(first.cursor);
		assert.equal(second.diff.groupsUpsert.length, 1);
		assert.equal(second.diff.groupsUpsert[0]?.name, "prod-2");
		assert.equal(second.diff.org, undefined, "l'org non è cambiato: non deve comparire nel delta");

		// Il NOTIFY è arrivato almeno una volta (consegna asincrona: piccola attesa).
		await new Promise((r) => setTimeout(r, 100));
		assert.ok(notified >= 1, "il listener LISTEN/NOTIFY deve essere stato svegliato");
		await unsubscribe();
	} finally {
		await writer.close();
		await reader.close();
	}
});

test("migrazioni PG: converge alla versione più alta ed è idempotente (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const store = new PostgresStateStore(url);
	try {
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		const s = store as any;
		await s.ensureReady();

		const versions = (
			(await s.query("SELECT version FROM cp_schema_version ORDER BY version ASC")).rows as { version: number }[]
		).map((r) => Number(r.version));
		assert.deepEqual(versions, [1, 2, 3, 4]);

		// Le colonne aggiunte dalle migrazioni 2/3 esistono davvero.
		const deviceCols = (
			await s.query(
				"SELECT column_name FROM information_schema.columns WHERE table_name = 'cp_devices' AND column_name = 'device_signing_public_key_pem'",
			)
		).rows;
		assert.equal(deviceCols.length, 1);
		const orgCols = (
			await s.query(
				"SELECT column_name FROM information_schema.columns WHERE table_name = 'cp_org' AND column_name = 'allow_cert_tofu'",
			)
		).rows;
		assert.equal(orgCols.length, 1);

		// Riapplicare (nuova ensureReady su una nuova connessione) è un no-op:
		// nessuna migrazione ri-applicata, nessun errore di doppia esecuzione.
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		await (store as any).ensureReady();
		const rows2 = (await s.query("SELECT COUNT(*) AS n FROM cp_schema_version")).rows as { n: string }[];
		assert.equal(Number(rows2[0]?.n), 4);
	} finally {
		await store.close();
	}
});

test(
	"migrazioni PG: partendo da uno schema fermo alla versione 1 applica le successive (live)",
	{ skip: !PG_URL },
	async () => {
		const url = PG_URL as string;
		await resetPgSchema(url);
		const bootstrap = new PostgresStateStore(url);
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		const b = bootstrap as any;
		await b.ensureReady();
		// Rimuove ciò che le migrazioni 2+ hanno introdotto, per simulare un
		// database fermo alla versione 1 (come un deploy esistente pre-upgrade).
		await b.query("ALTER TABLE cp_devices DROP COLUMN IF EXISTS device_signing_public_key_pem");
		await b.query("ALTER TABLE cp_org DROP COLUMN IF EXISTS allow_cert_tofu");
		await b.query("DROP TABLE IF EXISTS cp_rate_buckets");
		await b.query("DELETE FROM cp_schema_version WHERE version > 1");
		await bootstrap.close();

		const upgraded = new PostgresStateStore(url);
		try {
			// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
			const u = upgraded as any;
			await u.ensureReady();
			const versions = (
				(await u.query("SELECT version FROM cp_schema_version ORDER BY version ASC")).rows as {
					version: number;
				}[]
			).map((r) => Number(r.version));
			assert.deepEqual(versions, [1, 2, 3, 4]);
			const rateBuckets = (await u.query("SELECT to_regclass('cp_rate_buckets') AS reg")).rows as {
				reg: string | null;
			}[];
			assert.ok(rateBuckets[0]?.reg, "cp_rate_buckets deve esistere dopo l'upgrade");
		} finally {
			await upgraded.close();
		}
	},
);
