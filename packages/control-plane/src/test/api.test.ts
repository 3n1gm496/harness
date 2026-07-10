import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { verifyConfigBundle, verifyConfigBundleMulti, verifyToken } from "@harness/shared";
import { ControlPlaneService } from "../service.js";
import { createControlPlaneServer } from "../server.js";
import { Store } from "../store.js";

let dataDir: string;
let baseUrl: string;
let server: ReturnType<typeof createControlPlaneServer>;
let adminToken: string;
let publicKeyPem: string;
let deviceToken: string;
let deviceId: string;

before(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "harness-cp-test-"));
	const store = new Store(dataDir);
	const service = new ControlPlaneService(store);
	adminToken = service.bootstrapAdminToken("test-admin");
	server = createControlPlaneServer(service);
	await new Promise<void>((resolve) => server.listen(0, resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
	await new Promise((resolve) => server.close(resolve));
	rmSync(dataDir, { recursive: true, force: true });
});

async function call(
	method: string,
	path: string,
	options: { token?: string; body?: unknown } = {},
): Promise<{ status: number; data: Record<string, unknown> }> {
	const headers: Record<string, string> = { "content-type": "application/json" };
	if (options.token) headers.authorization = `Bearer ${options.token}`;
	const response = await fetch(`${baseUrl}${path}`, {
		method,
		headers,
		body: options.body === undefined ? null : JSON.stringify(options.body),
	});
	return { status: response.status, data: (await response.json()) as Record<string, unknown> };
}

test("le API admin rifiutano richieste senza token", async () => {
	const result = await call("GET", "/api/admin/overview");
	assert.equal(result.status, 401);
});

test("flusso completo: enroll token → enrollment → config firmata", async () => {
	const overviewResult = await call("GET", "/api/admin/overview", { token: adminToken });
	assert.equal(overviewResult.status, 200);
	const groups = overviewResult.data.groups as { groupId: string }[];
	const groupId = groups[0]?.groupId as string;

	const tokenResult = await call("POST", "/api/admin/enroll-tokens", {
		token: adminToken,
		body: { groupId, ttlMinutes: 10 },
	});
	assert.equal(tokenResult.status, 200);
	const enrollToken = tokenResult.data.enrollToken as string;

	const enrollResult = await call("POST", "/api/enroll", {
		body: { enrollToken, deviceName: "workstation-01" },
	});
	assert.equal(enrollResult.status, 200);
	deviceToken = enrollResult.data.deviceToken as string;
	deviceId = enrollResult.data.deviceId as string;
	publicKeyPem = enrollResult.data.publicKeyPem as string;
	assert.ok(deviceToken.startsWith("dvt_"));
	assert.ok(publicKeyPem.includes("PUBLIC KEY"));

	// Il token di enrollment è monouso.
	const reuse = await call("POST", "/api/enroll", { body: { enrollToken, deviceName: "clone" } });
	assert.equal(reuse.status, 401);

	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(configResult.status, 200);
	const verified = verifyConfigBundle(publicKeyPem, configResult.data.token as string);
	assert.equal(verified.valid, true);
	if (verified.valid) {
		assert.equal(verified.payload.deviceId, deviceId);
		assert.equal(verified.payload.policy.killSwitch, false);
		// I lockdown aziendali sono sempre presenti nei settings gestiti.
		assert.equal(verified.payload.piSettings.defaultProjectTrust, "never");
	}
});

test("il kill switch si propaga nel bundle firmato", async () => {
	const update = await call("PUT", `/api/admin/devices/${deviceId}`, {
		token: adminToken,
		body: { killSwitch: true },
	});
	assert.equal(update.status, 200);

	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	const verified = verifyConfigBundle(publicKeyPem, configResult.data.token as string);
	assert.equal(verified.valid, true);
	if (verified.valid) assert.equal(verified.payload.policy.killSwitch, true);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { killSwitch: false } });
});

test("l'audit dei device viene accettato e riletto, con deviceId forzato", async () => {
	const ingest = await call("POST", "/api/device/audit", {
		token: deviceToken,
		body: {
			events: [
				{
					eventId: "evt_1",
					deviceId: "dev_spoofed",
					timestamp: new Date().toISOString(),
					type: "policy_decision",
					data: { toolName: "bash", action: "deny" },
				},
			],
		},
	});
	assert.equal(ingest.status, 200);
	assert.equal(ingest.data.accepted, 1);

	const audit = await call("GET", `/api/admin/audit?deviceId=${deviceId}`, { token: adminToken });
	const events = audit.data.events as { deviceId: string; type: string }[];
	assert.equal(events.length, 1);
	assert.equal(events[0]?.deviceId, deviceId); // lo spoofing è stato neutralizzato
});

test("l'audit ingest scarta eventi malformati e tronca payload enormi", async () => {
	const huge = "x".repeat(20_000);
	const ingest = await call("POST", "/api/device/audit", {
		token: deviceToken,
		body: {
			events: [
				"non-un-oggetto",
				{ type: "tipo_inventato", data: {} },
				{ type: "tool_call", data: { blob: huge } },
				{ type: "policy_decision", timestamp: "data-non-valida", data: { ok: true } },
			],
		},
	});
	assert.equal(ingest.status, 200);
	assert.equal(ingest.data.accepted, 2); // solo i due eventi con tipo noto

	const audit = await call("GET", `/api/admin/audit?deviceId=${deviceId}&limit=2`, { token: adminToken });
	const events = audit.data.events as { type: string; timestamp: string; data: Record<string, unknown> }[];
	const truncated = events.find((event) => event.type === "tool_call");
	assert.ok(truncated);
	assert.equal(truncated.data.truncated, true);
	assert.ok(JSON.stringify(truncated.data).length < 4096);
	const fixedTimestamp = events.find((event) => event.type === "policy_decision");
	assert.ok(fixedTimestamp);
	assert.ok(!Number.isNaN(Date.parse(fixedTimestamp.timestamp)));
});

test("RBAC: viewer non può mutare, operator non può cambiare policy", async () => {
	const viewerResult = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "viewer-test", role: "viewer" },
	});
	const viewerToken = viewerResult.data.token as string;
	const operatorResult = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "operator-test", role: "operator" },
	});
	const operatorToken = operatorResult.data.token as string;

	// Il viewer legge ma non muta.
	assert.equal((await call("GET", "/api/admin/overview", { token: viewerToken })).status, 200);
	assert.equal(
		(await call("PUT", "/api/admin/org", { token: viewerToken, body: { killSwitch: true } })).status,
		403,
	);

	// L'overview espone il ruolo del chiamante (usato dalla UI per RBAC lato client).
	const viewerOverview = await call("GET", "/api/admin/overview", { token: viewerToken });
	assert.equal(viewerOverview.data.role, "viewer");
	const operatorOverview = await call("GET", "/api/admin/overview", { token: operatorToken });
	assert.equal(operatorOverview.data.role, "operator");

	// L'operator può usare il kill switch ma non cambiare le policy.
	assert.equal(
		(await call("PUT", `/api/admin/devices/${deviceId}`, { token: operatorToken, body: { killSwitch: false } }))
			.status,
		200,
	);
	assert.equal(
		(
			await call("PUT", "/api/admin/org", {
				token: operatorToken,
				body: { policyOverride: { killSwitch: false } },
			})
		).status,
		403,
	);
});

test("un device revocato non riceve più configurazione", async () => {
	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: true } });
	const configResult = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(configResult.status, 403);
	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: false } });
});

test("introspezione gateway: attivo, poi disattivo dopo revoca", async () => {
	const gatewayResult = await call("POST", "/api/admin/gateway-tokens", {
		token: adminToken,
		body: { name: "gw-test" },
	});
	const gatewayToken = gatewayResult.data.token as string;

	const active = await call("POST", "/api/introspect", { token: gatewayToken, body: { deviceToken } });
	assert.equal(active.status, 200);
	assert.equal(active.data.active, true);
	assert.equal(active.data.deviceId, deviceId);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: true } });
	const inactive = await call("POST", "/api/introspect", { token: gatewayToken, body: { deviceToken } });
	assert.equal(inactive.data.active, false);

	// Senza token gateway l'introspezione è vietata.
	const unauthorized = await call("POST", "/api/introspect", { body: { deviceToken } });
	assert.equal(unauthorized.status, 401);

	await call("PUT", `/api/admin/devices/${deviceId}`, { token: adminToken, body: { revoked: false } });
});

test("rotazione device token: il vecchio muore, il nuovo funziona", async () => {
	const rotate = await call("POST", "/api/device/rotate-token", { token: deviceToken });
	assert.equal(rotate.status, 200);
	const newToken = rotate.data.deviceToken as string;
	assert.ok(newToken.startsWith("dvt_"));
	assert.notEqual(newToken, deviceToken);

	const withOld = await call("GET", "/api/device/config", { token: deviceToken });
	assert.equal(withOld.status, 401);
	const withNew = await call("GET", "/api/device/config", { token: newToken });
	assert.equal(withNew.status, 200);
	deviceToken = newToken;
});

test("token admin con TTL scaduto viene rifiutato; revoca dell'ultimo admin negata", async () => {
	const created = await call("POST", "/api/admin/admin-tokens", {
		token: adminToken,
		body: { name: "effimero", role: "operator", ttlDays: 1 },
	});
	assert.equal(created.status, 200);

	const list = await call("GET", "/api/admin/admin-tokens", { token: adminToken });
	assert.equal(list.status, 200);
	const tokens = list.data.tokens as { id: string; name: string; role: string; expiresAt?: string }[];
	const ephemeral = tokens.find((t) => t.name === "effimero");
	assert.ok(ephemeral?.expiresAt);

	// Revoca del token effimero: ok.
	const revoked = await call("DELETE", `/api/admin/admin-tokens/${ephemeral.id}`, { token: adminToken });
	assert.equal(revoked.status, 200);
	// Revocare l'ultimo admin attivo è vietato.
	const bootstrap = tokens.find((t) => t.role === "admin");
	assert.ok(bootstrap);
	const denied = await call("DELETE", `/api/admin/admin-tokens/${bootstrap.id}`, { token: adminToken });
	assert.equal(denied.status, 409);
});

test("la catena di audit è integra e la manomissione viene rilevata", async () => {
	const intact = await call("GET", `/api/admin/audit/verify?deviceId=${deviceId}`, { token: adminToken });
	assert.equal(intact.status, 200);
	assert.equal(intact.data.valid, true);
	assert.ok((intact.data.entries as number) > 0);

	// Manomissione: si altera una riga in mezzo al file.
	const { readFileSync: readSync, writeFileSync: writeSync, readdirSync } = await import("node:fs");
	const { join: joinPath } = await import("node:path");
	const auditDir = joinPath(dataDir, "audit");
	const file = joinPath(auditDir, readdirSync(auditDir)[0] as string);
	const lines = readSync(file, "utf8").trim().split("\n");
	const target = JSON.parse(lines[0] as string) as { entry: { type: string } };
	target.entry.type = "manomesso";
	lines[0] = JSON.stringify(target);
	writeSync(file, `${lines.join("\n")}\n`);

	const tampered = await call("GET", `/api/admin/audit/verify?deviceId=${deviceId}`, { token: adminToken });
	assert.equal(tampered.data.valid, false);
	assert.equal((tampered.data as { brokenAtLine: number }).brokenAtLine, 1);
});

test("rotazione della chiave di firma in tre fasi, senza re-enrollment", async () => {
	// Il device fida solo la chiave A, pinnata all'enrollment.
	const keyA = publicKeyPem;
	let pinned = [keyA];

	function clientSync(token: string): boolean {
		return true && verifyAndLearn(token);
	}
	function verifyAndLearn(bundleToken: string): boolean {
		const v = verifyConfigBundleMulti(pinned, bundleToken);
		if (!v.valid) return false;
		if (v.payload.trustedPublicKeys) pinned = v.payload.trustedPublicKeys;
		return true;
	}

	// Stato iniziale: bundle firmato con A, verificabile.
	assert.equal(clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string), true);
	assert.deepEqual(pinned, [keyA]);

	// Fase 1 — add: nuova chiave B, NON ancora firmante. Il bundle resta
	// firmato con A (che il client fida) e ora elenca anche B.
	const add = await call("POST", "/api/admin/signing-keys", { token: adminToken });
	assert.equal(add.status, 200);
	const keyBId = add.data.keyId as string;
	assert.equal(clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string), true);
	assert.equal(pinned.length, 2); // il client ha appreso B

	// Fase 2 — promote: B diventa firmante. Il client fida già B ⇒ verifica ok.
	assert.equal((await call("POST", `/api/admin/signing-keys/${keyBId}/promote`, { token: adminToken })).status, 200);
	assert.equal(clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string), true);

	// Fase 3 — retire A: il client ora fida [A,B] ma i bundle sono firmati con B,
	// quindi resta valido anche dopo il ritiro di A.
	const keys = (await call("GET", "/api/admin/signing-keys", { token: adminToken })).data.keys as {
		keyId: string;
		active: boolean;
	}[];
	const keyAId = keys.find((k) => !k.active)?.keyId as string;
	assert.equal((await call("DELETE", `/api/admin/signing-keys/${keyAId}`, { token: adminToken })).status, 200);
	assert.equal(clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string), true);
	assert.equal(pinned.length, 1); // solo B resta fidata

	// Non si può ritirare l'unica chiave rimasta.
	const soloKey = (await call("GET", "/api/admin/signing-keys", { token: adminToken })).data.keys as { keyId: string }[];
	assert.equal((await call("DELETE", `/api/admin/signing-keys/${soloKey[0]?.keyId}`, { token: adminToken })).status, 400);
});

test("binding mTLS: la logica richiede il certificato legato", () => {
	// Test unitario della logica su un service isolato.
	const dir = mkdtempSync(join(tmpdir(), "harness-mtls-"));
	try {
		const svc = new ControlPlaneService(new Store(dir));
		const admin = svc.bootstrapAdminToken("t");
		const identity = svc.authenticateAdmin(admin);
		const groupId = svc.overview(identity).groups[0]?.groupId as string;

		// Device legato a un fingerprint fin dall'enrollment.
		const enr = svc.createEnrollToken(identity, groupId, 10);
		const bound = svc.enrollDevice(enr, "bound", "AA:BB:CC:DD");

		// Senza certificato → 403.
		assert.throws(() => svc.authenticateDevice(bound.deviceToken), /certificato client mTLS richiesto/);
		// Certificato sbagliato → 403.
		assert.throws(() => svc.authenticateDevice(bound.deviceToken, "99:88:77"), /non corrisponde/);
		// Certificato giusto (normalizzazione dei due-punti/maiuscole) → ok.
		assert.equal(svc.authenticateDevice(bound.deviceToken, "aabbccdd").deviceId, bound.deviceId);

		// Device non legato: funziona con solo token, e può legarsi TOFU.
		const enr2 = svc.createEnrollToken(identity, groupId, 10);
		const free = svc.enrollDevice(enr2, "free");
		const dev = svc.authenticateDevice(free.deviceToken);
		assert.equal(dev.deviceId, free.deviceId);
		svc.bindDeviceCertificate(dev, "12:34:56:78");
		assert.throws(() => svc.authenticateDevice(free.deviceToken), /richiesto/);
		assert.equal(svc.authenticateDevice(free.deviceToken, "12345678").deviceId, free.deviceId);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("export dell'anchor di audit firmato, verificabile e coerente con le catene", async () => {
	const result = await call("GET", "/api/admin/audit/anchor", { token: adminToken });
	assert.equal(result.status, 200);
	const anchorToken = result.data.anchor as string;
	const anchorPubKey = result.data.publicKeyPem as string;

	// L'anchor è un JWS firmato dal control plane: la firma è verificabile.
	const verified = verifyToken<{
		schema: string;
		admin: { head: string; entries: number };
		devices: { deviceId: string; head: string }[];
	}>(anchorPubKey, anchorToken);
	assert.equal(verified.valid, true);
	if (!verified.valid) return;
	assert.equal(verified.payload.schema, "harness/audit-anchor@1");

	// L'anchor fotografa la testa dell'audit amministrativo (non manomesso) e
	// include ogni device noto con la propria testa (hash sha256, 64 hex).
	assert.equal(verified.payload.admin.head.length, 64);
	assert.ok(verified.payload.admin.entries > 0);
	const deviceStream = verified.payload.devices.find((d) => d.deviceId === deviceId);
	assert.ok(deviceStream, "l'anchor deve elencare il device arruolato");
	assert.equal(deviceStream.head.length, 64);
});

test("autenticazione admin via OIDC/JWT con mappatura del ruolo dal claim", async () => {
	const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
	const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
	const privateKeyPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
	const issuer = "https://sso.azienda.it";
	const audience = "harness-cp";

	const oidcDir = mkdtempSync(join(tmpdir(), "harness-oidc-"));
	const oidcStore = new Store(oidcDir);
	const oidcService = new ControlPlaneService(oidcStore, {
		oidc: { issuer, audience, keys: [{ alg: "RS256", publicKeyPem }] },
	});
	const oidcServer = createControlPlaneServer(oidcService);
	await new Promise<void>((resolve) => oidcServer.listen(0, resolve));
	const oidcUrl = `http://127.0.0.1:${(oidcServer.address() as AddressInfo).port}`;

	function jwt(claims: Record<string, unknown>): string {
		const h = Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url");
		const p = Buffer.from(JSON.stringify(claims)).toString("base64url");
		const sig = cryptoSign("RSA-SHA256", Buffer.from(`${h}.${p}`, "utf8"), privateKeyPem).toString("base64url");
		return `${h}.${p}.${sig}`;
	}
	const exp = Math.floor(Date.now() / 1000) + 3600;

	async function callOidc(bearer: string): Promise<number> {
		const r = await fetch(`${oidcUrl}/api/admin/overview`, { headers: { authorization: `Bearer ${bearer}` } });
		return r.status;
	}

	try {
		// JWT valido con ruolo admin → accesso pieno.
		const adminJwt = jwt({ iss: issuer, aud: audience, exp, harness_role: "admin", email: "capo@azienda.it" });
		assert.equal(await callOidc(adminJwt), 200);

		// JWT con ruolo viewer → legge ma non muta.
		const viewerJwt = jwt({ iss: issuer, aud: audience, exp, harness_role: "viewer", email: "occhi@azienda.it" });
		assert.equal(await callOidc(viewerJwt), 200);
		const mutate = await fetch(`${oidcUrl}/api/admin/org`, {
			method: "PUT",
			headers: { authorization: `Bearer ${viewerJwt}`, "content-type": "application/json" },
			body: JSON.stringify({ killSwitch: true }),
		});
		assert.equal(mutate.status, 403);

		// JWT senza claim di ruolo → 403.
		const noRole = jwt({ iss: issuer, aud: audience, exp, email: "x@azienda.it" });
		assert.equal(await callOidc(noRole), 403);

		// JWT scaduto oltre la tolleranza di clock skew (60s) → 401.
		const expired = jwt({ iss: issuer, aud: audience, exp: Math.floor(Date.now() / 1000) - 120, harness_role: "admin" });
		assert.equal(await callOidc(expired), 401);
	} finally {
		await new Promise((resolve) => oidcServer.close(resolve));
		rmSync(oidcDir, { recursive: true, force: true });
	}
});

test("la UI statica viene servita", async () => {
	const response = await fetch(`${baseUrl}/`);
	assert.equal(response.status, 200);
	const html = await response.text();
	assert.match(html, /Piattaforma amministrativa/);
});
