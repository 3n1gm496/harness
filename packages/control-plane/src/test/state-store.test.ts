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
test("PostgresStateStore: round-trip e locking ottimistico (live)", { skip: !PG_URL }, async () => {
	const url = PG_URL as string;
	const a = new PostgresStateStore(url);
	try {
		// Pulizia iniziale della riga singleton.
		// biome-ignore lint/suspicious/noExplicitAny: accesso interno per reset di test
		await (a as any).ensureReady();
		// biome-ignore lint/suspicious/noExplicitAny: query di reset
		await (a as any).query("DELETE FROM control_plane_state");
		// biome-ignore lint/suspicious/noExplicitAny: reset del contatore di versione in memoria
		(a as any).version = 0;

		assert.equal(await a.load(), null);

		const snap = {
			state: { marker: "uno" } as unknown as import("../store.js").ControlPlaneState,
			signingKeys: [],
		};
		await a.save(snap);
		const loaded = await a.load();
		assert.deepEqual((loaded?.state as unknown as { marker: string }).marker, "uno");

		// Locking ottimistico: una seconda connessione che ha una versione
		// obsoleta deve fallire lo save, non sovrascrivere silenziosamente.
		const b = new PostgresStateStore(url);
		try {
			await b.load(); // b legge version corrente
			await a.save({ ...snap, state: { marker: "due" } as never }); // a avanza la versione
			await assert.rejects(
				b.save({ ...snap, state: { marker: "tre" } as never }),
				/conflitto di versione/,
			);
			// Dopo il conflitto b si è riallineato e può riscrivere.
			await b.save({ ...snap, state: { marker: "quattro" } as never });
			const final = await a.load();
			assert.equal((final?.state as unknown as { marker: string }).marker, "quattro");
		} finally {
			await b.close();
		}
	} finally {
		await a.close();
	}
});
