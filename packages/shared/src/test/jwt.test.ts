import assert from "node:assert/strict";
import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { type JwtAlg, verifyJwt } from "../jwt.js";

function makeJwt(privateKeyPem: string, alg: JwtAlg, claims: Record<string, unknown>, kid?: string): string {
	const header = { alg, typ: "JWT", ...(kid ? { kid } : {}) };
	const h = Buffer.from(JSON.stringify(header)).toString("base64url");
	const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
	const input = Buffer.from(`${h}.${p}`, "utf8");
	const nodeAlg = alg === "RS256" ? "RSA-SHA256" : "sha256";
	const key = alg === "ES256" ? { key: privateKeyPem, dsaEncoding: "ieee-p1363" as const } : privateKeyPem;
	const sig = cryptoSign(nodeAlg, input, key).toString("base64url");
	return `${h}.${p}.${sig}`;
}

const ISSUER = "https://sso.azienda.it";
const AUD = "harness-control-plane";

function rsaKeys() {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	return {
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
	};
}

function ecKeys() {
	const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
	return {
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
	};
}

test("JWT RS256 valido viene accettato con i claim corretti", () => {
	const keys = rsaKeys();
	const now = Math.floor(Date.now() / 1000);
	const token = makeJwt(keys.privateKeyPem, "RS256", {
		iss: ISSUER,
		aud: AUD,
		exp: now + 3600,
		harness_role: "admin",
		email: "mario@azienda.it",
	});
	const result = verifyJwt(token, {
		keys: [{ alg: "RS256", publicKeyPem: keys.publicKeyPem }],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, true);
	if (result.valid) {
		assert.equal(result.claims.harness_role, "admin");
		assert.equal(result.claims.email, "mario@azienda.it");
	}
});

test("JWT ES256 valido viene accettato", () => {
	const keys = ecKeys();
	const now = Math.floor(Date.now() / 1000);
	const token = makeJwt(keys.privateKeyPem, "ES256", { iss: ISSUER, aud: AUD, exp: now + 3600 });
	const result = verifyJwt(token, {
		keys: [{ alg: "ES256", publicKeyPem: keys.publicKeyPem }],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, true);
});

test("firma con chiave diversa viene rifiutata", () => {
	const signer = rsaKeys();
	const other = rsaKeys();
	const token = makeJwt(signer.privateKeyPem, "RS256", { iss: ISSUER, aud: AUD, exp: 9999999999 });
	const result = verifyJwt(token, {
		keys: [{ alg: "RS256", publicKeyPem: other.publicKeyPem }],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, false);
});

test("issuer o audience errati vengono rifiutati", () => {
	const keys = rsaKeys();
	const base = { exp: 9999999999 };
	const wrongIss = makeJwt(keys.privateKeyPem, "RS256", { ...base, iss: "https://evil", aud: AUD });
	const wrongAud = makeJwt(keys.privateKeyPem, "RS256", { ...base, iss: ISSUER, aud: "altro" });
	const opts = { keys: [{ alg: "RS256" as const, publicKeyPem: keys.publicKeyPem }], issuer: ISSUER, audience: AUD };
	assert.equal(verifyJwt(wrongIss, opts).valid, false);
	assert.equal(verifyJwt(wrongAud, opts).valid, false);
});

test("token scaduto viene rifiutato", () => {
	const keys = rsaKeys();
	const token = makeJwt(keys.privateKeyPem, "RS256", {
		iss: ISSUER,
		aud: AUD,
		exp: Math.floor(Date.now() / 1000) - 3600,
	});
	const result = verifyJwt(token, {
		keys: [{ alg: "RS256", publicKeyPem: keys.publicKeyPem }],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, false);
	if (!result.valid) assert.match(result.error, /scaduto/);
});

test("alg 'none' e algoritmi non supportati vengono rifiutati", () => {
	const keys = rsaKeys();
	const h = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
	const p = Buffer.from(JSON.stringify({ iss: ISSUER, aud: AUD })).toString("base64url");
	const result = verifyJwt(`${h}.${p}.`, {
		keys: [{ alg: "RS256", publicKeyPem: keys.publicKeyPem }],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, false);
});

test("il kid seleziona la chiave corretta", () => {
	const k1 = rsaKeys();
	const k2 = rsaKeys();
	const token = makeJwt(k2.privateKeyPem, "RS256", { iss: ISSUER, aud: AUD, exp: 9999999999 }, "k2");
	const result = verifyJwt(token, {
		keys: [
			{ kid: "k1", alg: "RS256", publicKeyPem: k1.publicKeyPem },
			{ kid: "k2", alg: "RS256", publicKeyPem: k2.publicKeyPem },
		],
		issuer: ISSUER,
		audience: AUD,
	});
	assert.equal(result.valid, true);
});
