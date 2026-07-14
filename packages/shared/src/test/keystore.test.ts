import assert from "node:assert/strict";
import { test } from "node:test";
import {
	generateKek,
	generateSigningKeyPair,
	isSealed,
	loadKekFromEnv,
	openPrivateKey,
	resealAll,
	sealPrivateKey,
} from "../index.js";

function kek() {
	return { key: Buffer.from(generateKek(), "base64") };
}

test("seal/open roundtrip di una chiave privata PEM", () => {
	const k = kek();
	const { privateKeyPem } = generateSigningKeyPair();
	const sealed = sealPrivateKey(k, privateKeyPem);
	assert.ok(isSealed(sealed));
	assert.ok(!sealed.includes("PRIVATE KEY")); // niente chiaro nel blob
	assert.equal(openPrivateKey(k, sealed), privateKeyPem);
});

test("una KEK diversa non riesce ad aprire (AEAD)", () => {
	const { privateKeyPem } = generateSigningKeyPair();
	const sealed = sealPrivateKey(kek(), privateKeyPem);
	assert.throws(() => openPrivateKey(kek(), sealed));
});

test("un ciphertext manomesso viene rifiutato dal tag GCM", () => {
	const k = kek();
	const { privateKeyPem } = generateSigningKeyPair();
	const sealed = sealPrivateKey(k, privateKeyPem);
	const parts = sealed.split(":");
	const ct = Buffer.from(parts[4] as string, "base64url");
	ct[0] = ct[0] === 0 ? 1 : (ct[0] as number) ^ 1;
	parts[4] = ct.toString("base64url");
	assert.throws(() => openPrivateKey(k, parts.join(":")));
});

test("loadKekFromEnv accetta base64 e hex da 32 byte, rifiuta lunghezze errate", () => {
	assert.equal(loadKekFromEnv({}), undefined);
	const b64 = generateKek();
	assert.ok(loadKekFromEnv({ HARNESS_SIGNING_KEK: b64 }));
	const hex = Buffer.from(b64, "base64").toString("hex");
	assert.ok(loadKekFromEnv({ HARNESS_SIGNING_KEK: hex }));
	assert.throws(() => loadKekFromEnv({ HARNESS_SIGNING_KEK: "dHJvcHBvY29ydG8=" }));
});

test("loadKekFromEnv legge una variabile alternativa (rotazione)", () => {
	const b64 = generateKek();
	assert.equal(loadKekFromEnv({ HARNESS_SIGNING_KEK_NEW: b64 }, "HARNESS_SIGNING_KEK_NEW")?.key.length, 32);
	assert.equal(loadKekFromEnv({}, "HARNESS_SIGNING_KEK_NEW"), undefined);
});

test("resealAll ri-sigilla da una vecchia KEK a una nuova: la vecchia smette di aprire", () => {
	const oldKek = kek();
	const newKek = kek();
	const { privateKeyPem } = generateSigningKeyPair();
	const records = [{ keyId: "key_1", privateKeyPem: sealPrivateKey(oldKek, privateKeyPem), active: true }];

	const resealed = resealAll(oldKek, newKek, records);
	assert.equal(resealed.length, 1);
	assert.ok(isSealed(resealed[0]?.privateKeyPem as string));
	assert.equal(resealed[0]?.keyId, "key_1"); // altri campi preservati
	assert.equal(openPrivateKey(newKek, resealed[0]?.privateKeyPem as string), privateKeyPem);
	assert.throws(() => openPrivateKey(oldKek, resealed[0]?.privateKeyPem as string));
});
