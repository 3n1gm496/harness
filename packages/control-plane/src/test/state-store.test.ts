import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { generateKek, signPayload } from "@harness/shared";
import { ControlPlaneService } from "../service.js";
import { ChangelogPrunedError, InMemoryStateStore, PostgresStateStore } from "../state-store.js";
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

test("Store.rekey ruota la KEK: la nuova apre, la vecchia no, la chiave pubblica resta stabile", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-rekey-"));
	try {
		const store = new Store(dir, KEK);
		const publicKeyBefore = store.signingPublicKeyPem;

		const newKek = { kek: { key: Buffer.from(generateKek(), "base64") } }.kek;
		await store.rekey(newKek);

		// La chiave pubblica (identità di firma) non cambia con la rotazione.
		assert.equal(store.signingPublicKeyPem, publicKeyBefore);
		const token = signPayload(store.signingPrivateKeyPem, { ok: true });
		assert.equal(token.split(".").length, 3);

		// Su disco: sigillata con la nuova KEK, non più apribile con la vecchia.
		const reopenedWithNewKek = new Store(dir, { kek: newKek });
		assert.equal(reopenedWithNewKek.signingPublicKeyPem, publicKeyBefore);
		assert.throws(() => new Store(dir, KEK));
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Store.rekey senza una KEK corrente viene rifiutato", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-rekey-nokek-"));
	try {
		const store = new Store(dir); // nessuna KEK: chiavi in chiaro
		await assert.rejects(store.rekey({ key: Buffer.from(generateKek(), "base64") }), /nessuna KEK corrente/);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("Store.deviceByTokenHash: indice O(1) coerente dopo enroll, rotate e revoke", () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-token-index-"));
	try {
		const store = new Store(dir);
		const service = new ControlPlaneService(store);
		const admin = service.auth.bootstrapAdminToken("root");
		const identity = service.auth.authenticateAdmin(admin);
		const groupId = service.org.overview(identity).groups[0]?.groupId as string;

		// Enroll: il device è subito risolvibile dall'indice.
		const enr = service.devices.createEnrollToken(identity, groupId, 10);
		const dev = service.devices.enrollDevice(enr, "d1");
		assert.equal(service.auth.authenticateDevice(dev.deviceToken).deviceId, dev.deviceId);

		// Rotate: il vecchio token sparisce dall'indice, il nuovo compare.
		const device = store.state.devices[dev.deviceId];
		if (!device) throw new Error("device non trovato");
		const rotated = service.auth.rotateDeviceToken(device);
		assert.throws(() => service.auth.authenticateDevice(dev.deviceToken), /non valido/);
		assert.equal(service.auth.authenticateDevice(rotated).deviceId, dev.deviceId);

		// Un secondo device non deve interferire con l'indice del primo.
		const enr2 = service.devices.createEnrollToken(identity, groupId, 10);
		const dev2 = service.devices.enrollDevice(enr2, "d2");
		assert.equal(service.auth.authenticateDevice(rotated).deviceId, dev.deviceId);
		assert.equal(service.auth.authenticateDevice(dev2.deviceToken).deviceId, dev2.deviceId);

		// Revoca: il token resta nell'indice (mapping tokenHash→deviceId) ma
		// l'autenticazione deve comunque fallire (device.revoked).
		service.devices.updateDevice(identity, dev2.deviceId, { revoked: true });
		assert.throws(() => service.auth.authenticateDevice(dev2.deviceToken), /revocato/);
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
		const admin = service.auth.bootstrapAdminToken("capo");
		const identity = service.auth.authenticateAdmin(admin);
		service.groups.createGroup(identity, "produzione");
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

test("durabilità cache file (F2.6): con mirror che fallisce, save() forza la scrittura del file entro il throttle", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-ss-durab-"));
	let failWrites = false;
	// Backend snapshot-based il cui save() può fallire su richiesta.
	const backend: import("../state-store.js").DurableStateStore = {
		async load() {
			return null;
		},
		async save() {
			if (failWrites) throw new Error("mirror giù");
		},
		async close() {},
	};
	try {
		const store = await Store.openWithBackend(dir, backend, KEK);
		await store.flush();
		// Il mirror va giù. Prima mutazione: la write-behind fallisce → lastMirrorError.
		failWrites = true;
		store.state.org.name = "durante-outage-1";
		store.save();
		await store.flush();
		// Seconda mutazione ENTRO la finestra di throttle (30s): con il mirror in
		// errore, save() deve forzare comunque la scrittura del file, altrimenti un
		// kill -9 perderebbe la mutazione da entrambe le parti.
		store.state.org.name = "durante-outage-2";
		store.save();
		const onDisk = readFileSync(join(dir, "state.json"), "utf8");
		assert.match(onDisk, /durante-outage-2/, "la mutazione durante l'outage del mirror deve essere sul file");
		await store.close();
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("le chiavi di firma sono incluse nello snapshot durevole", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-ss-keys-"));
	const backend = new InMemoryStateStore();
	try {
		const store = await Store.openWithBackend(dir, backend, KEK);
		const service = new ControlPlaneService(store);
		const admin = service.auth.bootstrapAdminToken("k");
		const identity = service.auth.authenticateAdmin(admin);
		service.signingKeys.addSigningKey(identity);
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
			cp_rate_buckets, cp_audit_prune_state, cp_changelog_prune_floor, cp_sessions
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
		const admin = svcA.auth.bootstrapAdminToken("root");
		const idA = svcA.auth.authenticateAdmin(admin);
		const groupId = svcA.org.overview(idA).groups[0]?.groupId as string;

		// Istanza A arruola un device; B lo vede dopo un refresh (convergenza).
		const enr = svcA.devices.createEnrollToken(idA, groupId, 10);
		const dev = svcA.devices.enrollDevice(enr, "d-mtls");
		await storeA.flush();
		await storeB.refreshNow();
		assert.ok(storeB.state.devices[dev.deviceId], "l'istanza B deve vedere il device creato da A");
		// L'indice tokenHash→deviceId converge insieme allo stato: B deve poter
		// autenticare il device via il proprio service, non solo vederlo in state.
		assert.equal(svcA.auth.authenticateDevice(dev.deviceToken).deviceId, dev.deviceId);
		const svcBForAuth = new ControlPlaneService(storeB);
		assert.equal(svcBForAuth.auth.authenticateDevice(dev.deviceToken).deviceId, dev.deviceId);

		// Mutazioni concorrenti su device diversi non si sovrascrivono (row-level).
		const enr2 = svcA.devices.createEnrollToken(idA, groupId, 10);
		const dev2 = svcA.devices.enrollDevice(enr2, "d2");
		await storeA.flush();
		await storeB.refreshNow();
		const svcB = new ControlPlaneService(storeB);
		// B sospende dev2 mentre A lo lascia attivo: scrittura mirata su dev2.
		svcB.devices.updateDevice(svcB.auth.authenticateAdmin(admin), dev2.deviceId, { killSwitch: true });
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

test("Postgres incrementale: pullDelta consegna solo i cambi e NOTIFY sveglia i listener (live)", {
	skip: !PG_URL,
}, async () => {
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
			groupsUpsert: [
				{ groupId: "grp_1", name: "prod-2", killSwitch: true, policyOverride: {}, piSettingsOverride: {} },
			],
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
		assert.deepEqual(versions, [1, 2, 3, 4, 5, 6, 7]);

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
		assert.equal(Number(rows2[0]?.n), 7);
	} finally {
		await store.close();
	}
});

test("migrazioni PG: due istanze in cold-start concorrente non vanno in race (advisory lock, live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	// DB davvero vuoto: elimina anche cp_schema_version, così entrambe le istanze
	// partono dovendo applicare TUTTE le migrazioni insieme (lo scenario di race).
	const cleaner = new PostgresStateStore(url);
	// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
	const c = cleaner as any;
	await c.ensureReady();
	await c.query(`DROP TABLE IF EXISTS cp_org, cp_groups, cp_devices, cp_admin_tokens,
		cp_gateway_tokens, cp_enroll_tokens, cp_signing_keys, cp_audit_events, cp_audit_heads,
		cp_changelog, cp_rate_buckets, cp_audit_prune_state, cp_changelog_prune_floor,
		cp_schema_version CASCADE`);
	await cleaner.close();

	const a = new PostgresStateStore(url);
	const b = new PostgresStateStore(url);
	try {
		// Senza l'advisory lock, questi due ensureReady applicherebbero le stesse
		// migrazioni insieme e uno crasherebbe sul conflitto di PK.
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		await Promise.all([(a as any).ensureReady(), (b as any).ensureReady()]);
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		const res = await (a as any).query("SELECT version FROM cp_schema_version ORDER BY version");
		const versions = (res.rows as { version: number }[]).map((r) => Number(r.version));
		assert.deepEqual(versions, [1, 2, 3, 4, 5, 6, 7]);
	} finally {
		await a.close();
		await b.close();
	}
});

test("migrazioni PG: partendo da uno schema fermo alla versione 1 applica le successive (live)", {
	skip: !PG_URL,
}, async () => {
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
		assert.deepEqual(versions, [1, 2, 3, 4, 5, 6, 7]);
		const rateBuckets = (await u.query("SELECT to_regclass('cp_rate_buckets') AS reg")).rows as {
			reg: string | null;
		}[];
		assert.ok(rateBuckets[0]?.reg, "cp_rate_buckets deve esistere dopo l'upgrade");
	} finally {
		await upgraded.close();
	}
});

test("Postgres: pruneAudit elimina le righe più vecchie mantenendo la catena verificabile (live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const store = new PostgresStateStore(url);
	try {
		const streamId = "dev_prune";
		const mkEvent = (i: number) => ({
			eventId: `e${i}`,
			deviceId: streamId,
			timestamp: new Date().toISOString(),
			type: "policy_decision",
			data: { i },
		});
		for (let i = 0; i < 5; i += 1) await store.appendAudit(streamId, [mkEvent(i)]);

		// Retrodata le prime 3 righe di 400 giorni, come se fossero fuori dalla
		// finestra di retention di un anno.
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per il test
		await (store as any).query(
			"UPDATE cp_audit_events SET ts = now() - interval '400 days' WHERE stream_id = $1 AND seq <= 3",
			[streamId],
		);

		const result = await store.pruneAudit(streamId, 365);
		assert.equal(result.prunedRows, 3);

		// Il segmento residuo verifica integro a partire dal nuovo genesis
		// (l'hash dell'ultima riga eliminata), senza riscrivere nulla.
		const verify = await store.verifyAudit(streamId);
		assert.equal(verify.valid, true);
		if (verify.valid) assert.equal(verify.entries, 2);

		const remaining = await store.readAudit(streamId, 10);
		assert.equal(remaining.length, 2);

		// Ripetere il pruning senza altre righe vecchie è un no-op sicuro.
		const again = await store.pruneAudit(streamId, 365);
		assert.equal(again.prunedRows, 0);
	} finally {
		await store.close();
	}
});

test("Postgres: pruneChangelog registra una soglia e pullDelta rifiuta un cursore troppo indietro (live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const store = new PostgresStateStore(url);
	try {
		const groupDiff = (name: string) => ({
			groupsUpsert: [{ groupId: "grp_1", name, killSwitch: false, policyOverride: {}, piSettingsOverride: {} }],
			groupsDelete: [],
			devicesUpsert: [],
			devicesDelete: [],
			adminTokensUpsert: [],
			adminTokensDelete: [],
			gatewayTokensUpsert: [],
			enrollTokensUpsert: [],
			enrollTokensDelete: [],
		});
		await store.applyDiff(groupDiff("a0"));
		const earlyCursor = await store.changelogCursor();
		for (let i = 1; i <= 5; i += 1) await store.applyDiff(groupDiff(`a${i}`));
		const latestCursor = await store.changelogCursor();
		assert.ok(latestCursor > earlyCursor);

		// Mantiene solo l'ultima riga di changelog: la soglia finisce ben oltre earlyCursor.
		const pruned = await store.pruneChangelog(1);
		assert.ok(pruned.prunedRows > 0);

		await assert.rejects(store.pullDelta(earlyCursor), (error: unknown) => error instanceof ChangelogPrunedError);

		// Un cursore alla testa (o oltre la soglia) continua a funzionare.
		const ok = await store.pullDelta(latestCursor - 1);
		assert.equal(ok.cursor, latestCursor);
	} finally {
		await store.close();
	}
});

test("Postgres: checkRateLimit condivide il conteggio tra istanze diverse (chiude B5, live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const a = new PostgresStateStore(url);
	const b = new PostgresStateStore(url);
	try {
		// Soglia 5: le prime 5 richieste (su entrambe le istanze insieme) sono
		// entro soglia, la sesta no — un limiter per-istanza lascerebbe passare
		// 5 richieste *per ciascuna* istanza (10 in tutto), il bug che questo
		// backend condiviso chiude.
		const key = "enroll:203.0.113.9";
		const results: boolean[] = [];
		for (let i = 0; i < 5; i += 1) results.push(await a.checkRateLimit(key, 5));
		for (let i = 0; i < 5; i += 1) results.push(await b.checkRateLimit(key, 5));
		assert.equal(results.filter(Boolean).length, 5, "solo le prime 5 richieste, condivise tra le due istanze, passano");

		// Chiavi diverse hanno bucket indipendenti.
		assert.equal(await a.checkRateLimit("enroll:203.0.113.10", 5), true);
	} finally {
		await a.close();
		await b.close();
	}
});

test("Postgres: le sessioni UI sono durevoli, condivise multi-istanza e revocabili per token (live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const a = new PostgresStateStore(url);
	const b = new PostgresStateStore(url);
	try {
		const now = Date.now();
		await a.createSession({
			sessionHash: "sess_hash_1",
			name: "mario",
			role: "admin",
			csrfToken: "csrf_1",
			sourceTokenHash: "tok_abc",
			expiresAt: now + 3_600_000,
		});
		// Un'altra istanza (b) vede la sessione: è condivisa via DB, non in memoria.
		const fromB = await b.getSession("sess_hash_1");
		assert.equal(fromB?.name, "mario");
		assert.equal(fromB?.csrfToken, "csrf_1");
		assert.equal(fromB?.sourceTokenHash, "tok_abc");

		// Una sessione scaduta non viene restituita (filtro server-side).
		await a.createSession({
			sessionHash: "sess_expired",
			name: "x",
			role: "viewer",
			csrfToken: "c",
			expiresAt: now - 1000,
		});
		assert.equal(await b.getSession("sess_expired"), undefined);

		// Revoca per token sorgente: la sessione legata a tok_abc sparisce.
		await b.deleteSessionsByToken("tok_abc");
		assert.equal(await a.getSession("sess_hash_1"), undefined);

		// Prune elimina le scadute e ritorna il conteggio.
		const pruned = await a.pruneSessions();
		assert.ok(pruned >= 1);
	} finally {
		await a.close();
		await b.close();
	}
});

test("Postgres: un'istanza rimasta indietro converge con un resync completo dopo il pruning del changelog (live)", {
	skip: !PG_URL,
}, async () => {
	const url = PG_URL as string;
	await resetPgSchema(url);
	const dirA = mkdtempSync(join(tmpdir(), "harness-pg-prune-a-"));
	const dirB = mkdtempSync(join(tmpdir(), "harness-pg-prune-b-"));
	const storeA = await Store.openWithBackend(dirA, new PostgresStateStore(url), KEK);
	try {
		const svcA = new ControlPlaneService(storeA);
		const admin = svcA.auth.bootstrapAdminToken("root");
		const idA = svcA.auth.authenticateAdmin(admin);

		// B si connette e cattura il cursore corrente, poi resta indietro.
		const storeB = await Store.openWithBackend(dirB, new PostgresStateStore(url), KEK);
		try {
			for (let i = 0; i < 5; i += 1) svcA.groups.createGroup(idA, `g${i}`);
			await storeA.flush();

			// Pota il changelog condiviso ben oltre il cursore fermo di B.
			const pruner = new PostgresStateStore(url);
			try {
				await pruner.pruneChangelog(1);
			} finally {
				await pruner.close();
			}

			// B converge comunque: niente eccezione visibile, resync interno.
			await storeB.refreshNow();
			for (let i = 0; i < 5; i += 1) {
				assert.ok(
					Object.values(storeB.state.groups).some((g) => g.name === `g${i}`),
					`storeB deve avere convergito sul gruppo g${i}`,
				);
			}
		} finally {
			await storeB.close();
		}
	} finally {
		await storeA.close();
		rmSync(dirA, { recursive: true, force: true });
		rmSync(dirB, { recursive: true, force: true });
	}
});
