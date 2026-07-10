import assert from "node:assert/strict";
import { test } from "node:test";
import {
	generateSigningKeyPair,
	signPayload,
	verifyConfigBundle,
	verifyConfigBundleMulti,
	verifyToken,
} from "../signing.js";
import type { ConfigBundle } from "../types.js";
import { defaultPolicy } from "../defaults.js";

function makeBundle(overrides: Partial<ConfigBundle> = {}): ConfigBundle {
	const now = Date.now();
	return {
		schema: "harness/config-bundle@1",
		bundleId: "bnd_test",
		orgId: "org_test",
		groupId: "grp_test",
		deviceId: "dev_test",
		configVersion: 1,
		issuedAt: new Date(now).toISOString(),
		expiresAt: new Date(now + 3_600_000).toISOString(),
		policy: defaultPolicy(),
		piSettings: {},
		...overrides,
	};
}

test("firma e verifica roundtrip", () => {
	const keys = generateSigningKeyPair();
	const token = signPayload(keys.privateKeyPem, { hello: "world" });
	const result = verifyToken<{ hello: string }>(keys.publicKeyPem, token);
	assert.equal(result.valid, true);
	if (result.valid) assert.equal(result.payload.hello, "world");
});

test("un payload manomesso viene rifiutato", () => {
	const keys = generateSigningKeyPair();
	const token = signPayload(keys.privateKeyPem, { role: "viewer" });
	const [header, , signature] = token.split(".") as [string, string, string];
	const forged = Buffer.from(JSON.stringify({ role: "admin" })).toString("base64url");
	const result = verifyToken(keys.publicKeyPem, `${header}.${forged}.${signature}`);
	assert.equal(result.valid, false);
});

test("una chiave diversa non verifica", () => {
	const a = generateSigningKeyPair();
	const b = generateSigningKeyPair();
	const token = signPayload(a.privateKeyPem, { x: 1 });
	const result = verifyToken(b.publicKeyPem, token);
	assert.equal(result.valid, false);
});

test("bundle valido entro la finestra temporale", () => {
	const keys = generateSigningKeyPair();
	const token = signPayload(keys.privateKeyPem, makeBundle());
	const result = verifyConfigBundle(keys.publicKeyPem, token);
	assert.equal(result.valid, true);
});

test("bundle scaduto viene rifiutato", () => {
	const keys = generateSigningKeyPair();
	const bundle = makeBundle({
		issuedAt: new Date(Date.now() - 7_200_000).toISOString(),
		expiresAt: new Date(Date.now() - 3_600_000).toISOString(),
	});
	const token = signPayload(keys.privateKeyPem, bundle);
	const result = verifyConfigBundle(keys.publicKeyPem, token);
	assert.equal(result.valid, false);
	if (!result.valid) assert.match(result.error, /scaduto/);
});

test("bundle con schema sconosciuto viene rifiutato", () => {
	const keys = generateSigningKeyPair();
	const bundle = { ...makeBundle(), schema: "harness/config-bundle@99" };
	const token = signPayload(keys.privateKeyPem, bundle);
	const result = verifyConfigBundle(keys.publicKeyPem, token);
	assert.equal(result.valid, false);
});

test("verifica multi-chiave: valida se una qualsiasi chiave fidata verifica", () => {
	const oldKey = generateSigningKeyPair();
	const newKey = generateSigningKeyPair();
	// Bundle firmato con la chiave nuova, verificato contro il set {vecchia, nuova}.
	const token = signPayload(newKey.privateKeyPem, makeBundle());
	const result = verifyConfigBundleMulti([oldKey.publicKeyPem, newKey.publicKeyPem], token);
	assert.equal(result.valid, true);
});

test("verifica multi-chiave: rifiuta se nessuna chiave fidata verifica", () => {
	const signer = generateSigningKeyPair();
	const a = generateSigningKeyPair();
	const b = generateSigningKeyPair();
	const token = signPayload(signer.privateKeyPem, makeBundle());
	const result = verifyConfigBundleMulti([a.publicKeyPem, b.publicKeyPem], token);
	assert.equal(result.valid, false);
});

test("verifica multi-chiave: set vuoto viene rifiutato", () => {
	const signer = generateSigningKeyPair();
	const token = signPayload(signer.privateKeyPem, makeBundle());
	assert.equal(verifyConfigBundleMulti([], token).valid, false);
});
