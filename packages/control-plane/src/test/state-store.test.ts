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
	for (const t of [
		"cp_org",
		"cp_groups",
		"cp_devices",
		"cp_admin_tokens",
		"cp_gateway_tokens",
		"cp_enroll_tokens",
		"cp_signing_keys",
		"cp_audit_events",
		"cp_audit_heads",
	]) {
		// biome-ignore lint/suspicious/noExplicitAny: query di reset
		await (s as any).query(`DELETE FROM ${t}`);
	}
	await s.close();
}

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
