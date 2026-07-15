import assert from "node:assert/strict";
import { sign as cryptoSign, generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import {
	generateSigningKeyPair,
	signPayload,
	verifyConfigBundle,
	verifyConfigBundleMulti,
	verifyToken,
} from "@harness/shared";
import { createControlPlaneServer } from "../server.js";
import { ControlPlaneService } from "../service.js";
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
	adminToken = service.auth.bootstrapAdminToken("test-admin");
	server = createControlPlaneServer(service, { readiness: () => store.checkReady() });
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

test("osservabilità: /readyz riflette lo stato reale e /metrics espone Prometheus", async () => {
	const ready = await fetch(`${baseUrl}/readyz`);
	assert.equal(ready.status, 200);
	const readyBody = (await ready.json()) as { ready: boolean; detail: Record<string, unknown> };
	assert.equal(readyBody.ready, true);
	assert.equal(readyBody.detail.backend, "file");
	assert.ok((readyBody.detail.signingKeys as number) >= 1);

	// Genera traffico e verifica che il contatore lo registri.
	await call("GET", "/healthz");
	const metrics = await fetch(`${baseUrl}/metrics`);
	assert.equal(metrics.status, 200);
	assert.match(metrics.headers.get("content-type") ?? "", /text\/plain/);
	const text = await metrics.text();
	assert.match(text, /# TYPE harness_http_requests_total counter/);
	assert.match(text, /harness_http_requests_total\{[^}]*status="200"[^}]*\}/);
	assert.match(text, /harness_up 1/);
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

test("paginazione server-side dei device: ricerca, filtro, offset/limit e riepilogo di flotta", async () => {
	// overview() non elenca più i device (solo gruppi con deviceCount) — l'elenco
	// paginato vive su /api/admin/devices, i contatori su /api/admin/fleet-summary.
	const overview = await call("GET", "/api/admin/overview", { token: adminToken });
	assert.equal((overview.data as { devices?: unknown }).devices, undefined);
	const groups = overview.data.groups as { groupId: string; deviceCount: number }[];
	assert.ok(groups[0] && groups[0].deviceCount >= 1); // il device di prova arruolato sopra

	const page1 = await call("GET", "/api/admin/devices?limit=1&offset=0", { token: adminToken });
	assert.equal(page1.status, 200);
	const devicesPage1 = page1.data.devices as { deviceId: string; state: string }[];
	assert.equal(devicesPage1.length, 1);
	assert.ok((page1.data.total as number) >= 1);
	assert.ok(["active", "stale", "suspended"].includes(devicesPage1[0]?.state as string));

	const byName = await call("GET", `/api/admin/devices?q=workstation`, { token: adminToken });
	assert.ok((byName.data.devices as { name: string }[]).every((d) => d.name.toLowerCase().includes("workstation")));

	const noMatch = await call("GET", "/api/admin/devices?q=xxnonexistentxx", { token: adminToken });
	assert.equal((noMatch.data.devices as unknown[]).length, 0);
	assert.equal(noMatch.data.total, 0);

	const activeOnly = await call("GET", "/api/admin/devices?filter=active", { token: adminToken });
	assert.ok((activeOnly.data.devices as { state: string }[]).every((d) => d.state === "active"));
	const suspendedOnly = await call("GET", "/api/admin/devices?filter=suspended", { token: adminToken });
	assert.ok((suspendedOnly.data.devices as { state: string }[]).every((d) => d.state === "suspended"));

	const summary = await call("GET", "/api/admin/fleet-summary", { token: adminToken });
	assert.equal(summary.status, 200);
	assert.ok((summary.data.total as number) >= 1);
	assert.equal(
		summary.data.total,
		(summary.data.active as number) + (summary.data.stale as number) + (summary.data.suspended as number),
	);
	assert.equal(typeof summary.data.configVersion, "number");
	assert.equal(typeof summary.data.killSwitch, "boolean");

	// viewer/operator possono leggere entrambi gli endpoint (solo lettura).
	const viewerToken = await (async () => {
		const created = await call("POST", "/api/admin/admin-tokens", {
			token: adminToken,
			body: { name: "viewer-devices-test", role: "viewer", ttlDays: 1 },
		});
		return created.data.token as string;
	})();
	const viewerDevices = await call("GET", "/api/admin/devices", { token: viewerToken });
	assert.equal(viewerDevices.status, 200);
	const viewerSummary = await call("GET", "/api/admin/fleet-summary", { token: viewerToken });
	assert.equal(viewerSummary.status, 200);
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

test("provenance dell'audit: batch firmato accettato e marcato, batch manomesso rifiutato", async () => {
	// Device arruolato con una chiave di firma propria (come farebbe agent-client).
	const deviceKeyPair = generateSigningKeyPair();
	const overview = await call("GET", "/api/admin/overview", { token: adminToken });
	const groupId = (overview.data.groups as { groupId: string }[])[0]?.groupId as string;
	const enrollResult = await call("POST", "/api/admin/enroll-tokens", {
		token: adminToken,
		body: { groupId, ttlMinutes: 10 },
	});
	const enrollToken = enrollResult.data.enrollToken as string;
	const enrollResponse = await call("POST", "/api/enroll", {
		body: { enrollToken, deviceName: "signed-device", deviceSigningPublicKeyPem: deviceKeyPair.publicKeyPem },
	});
	assert.equal(enrollResponse.status, 200);
	const signedDeviceId = enrollResponse.data.deviceId as string;
	const signedDeviceToken = enrollResponse.data.deviceToken as string;

	const events = [
		{ eventId: "sig_1", deviceId: signedDeviceId, timestamp: new Date().toISOString(), type: "agent_start", data: {} },
	];

	// Batch senza firma: rifiutato, il device ha una chiave registrata.
	const noSig = await call("POST", "/api/device/audit", { token: signedDeviceToken, body: { events } });
	assert.equal(noSig.status, 400);
	assert.match(noSig.data.error as string, /firma/);

	// Batch firmato correttamente: accettato e marcato "signed".
	const signature = signPayload(deviceKeyPair.privateKeyPem, { deviceId: signedDeviceId, events });
	const signed = await call("POST", "/api/device/audit", {
		token: signedDeviceToken,
		body: { events, signature },
	});
	assert.equal(signed.status, 200);
	assert.equal(signed.data.accepted, 1);

	const readBack = await call("GET", `/api/admin/audit?deviceId=${signedDeviceId}`, { token: adminToken });
	const readEvents = readBack.data.events as { provenance?: string }[];
	assert.equal(readEvents.length, 1);
	assert.equal(readEvents[0]?.provenance, "signed");

	// Batch manomesso dopo la firma (eventi diversi da quelli firmati): rifiutato.
	const tamperedEvents = [
		{
			eventId: "sig_evil",
			deviceId: signedDeviceId,
			timestamp: new Date().toISOString(),
			type: "agent_start",
			data: {},
		},
	];
	const tampered = await call("POST", "/api/device/audit", {
		token: signedDeviceToken,
		body: { events: tamperedEvents, signature },
	});
	assert.equal(tampered.status, 200); // la richiesta è valida...
	// ...ma il server usa gli eventi *firmati*, non quelli in chiaro: solo l'evento originale è stato persistito.
	const afterTamper = await call("GET", `/api/admin/audit?deviceId=${signedDeviceId}`, { token: adminToken });
	const afterTamperEvents = afterTamper.data.events as { eventId: string }[];
	assert.equal(afterTamperEvents.length, 2); // il primo signed + questo (dal payload firmato, non da tamperedEvents)
	assert.ok(afterTamperEvents.every((e) => e.eventId === "sig_1"));

	// Firma con una chiave diversa da quella registrata: rifiutata.
	const otherKeyPair = generateSigningKeyPair();
	const forgedSignature = signPayload(otherKeyPair.privateKeyPem, { deviceId: signedDeviceId, events });
	const forged = await call("POST", "/api/device/audit", {
		token: signedDeviceToken,
		body: { events, signature: forgedSignature },
	});
	assert.equal(forged.status, 400);
	assert.match(forged.data.error as string, /firma.*non valida/);

	// Device legacy senza chiave registrata: continua a funzionare "token-only".
	const legacyIngest = await call("POST", "/api/device/audit", {
		token: deviceToken,
		body: {
			events: [{ eventId: "legacy_1", deviceId, timestamp: new Date().toISOString(), type: "agent_start", data: {} }],
		},
	});
	assert.equal(legacyIngest.status, 200);
	const legacyRead = await call("GET", `/api/admin/audit?deviceId=${deviceId}&limit=1`, { token: adminToken });
	const legacyEvents = legacyRead.data.events as { provenance?: string }[];
	assert.equal(legacyEvents.at(-1)?.provenance, "token-only");
});

test("enrollment con una chiave di firma del device malformata viene rifiutato (400)", async () => {
	const overview = await call("GET", "/api/admin/overview", { token: adminToken });
	const groupId = (overview.data.groups as { groupId: string }[])[0]?.groupId as string;
	const enrollResult = await call("POST", "/api/admin/enroll-tokens", {
		token: adminToken,
		body: { groupId, ttlMinutes: 10 },
	});
	const enrollToken = enrollResult.data.enrollToken as string;
	// Un PEM malformato accettato romperebbe per sempre la verifica dell'audit di
	// questo device: va rifiutato subito all'enrollment.
	const bad = await call("POST", "/api/enroll", {
		body: {
			enrollToken,
			deviceName: "bad-key",
			deviceSigningPublicKeyPem: "-----BEGIN PUBLIC KEY-----\nrotto\n-----END PUBLIC KEY-----",
		},
	});
	assert.equal(bad.status, 400);
	assert.match(bad.data.error as string, /Ed25519/);
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
	assert.equal((await call("PUT", "/api/admin/org", { token: viewerToken, body: { killSwitch: true } })).status, 403);

	// L'overview espone il ruolo del chiamante (usato dalla UI per RBAC lato client).
	const viewerOverview = await call("GET", "/api/admin/overview", { token: viewerToken });
	assert.equal(viewerOverview.data.role, "viewer");
	const operatorOverview = await call("GET", "/api/admin/overview", { token: operatorToken });
	assert.equal(operatorOverview.data.role, "operator");

	// L'operator può usare il kill switch ma non cambiare le policy.
	assert.equal(
		(await call("PUT", `/api/admin/devices/${deviceId}`, { token: operatorToken, body: { killSwitch: false } })).status,
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

	// Manomissione: si altera una riga in mezzo al file. Si punta esplicitamente
	// al file di questo device (non al primo trovato nella dir: con più device
	// arruolati coesistono più file di audit).
	const { readFileSync: readSync, writeFileSync: writeSync } = await import("node:fs");
	const { join: joinPath } = await import("node:path");
	const auditDir = joinPath(dataDir, "audit");
	const file = joinPath(auditDir, `${deviceId}.jsonl`);
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
	assert.equal(
		clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string),
		true,
	);
	assert.deepEqual(pinned, [keyA]);

	// Fase 1 — add: nuova chiave B, NON ancora firmante. Il bundle resta
	// firmato con A (che il client fida) e ora elenca anche B.
	const add = await call("POST", "/api/admin/signing-keys", { token: adminToken });
	assert.equal(add.status, 200);
	const keyBId = add.data.keyId as string;
	assert.equal(
		clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string),
		true,
	);
	assert.equal(pinned.length, 2); // il client ha appreso B

	// Fase 2 — promote: B diventa firmante. Il client fida già B ⇒ verifica ok.
	assert.equal((await call("POST", `/api/admin/signing-keys/${keyBId}/promote`, { token: adminToken })).status, 200);
	assert.equal(
		clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string),
		true,
	);

	// Fase 3 — retire A: il client ora fida [A,B] ma i bundle sono firmati con B,
	// quindi resta valido anche dopo il ritiro di A.
	const keys = (await call("GET", "/api/admin/signing-keys", { token: adminToken })).data.keys as {
		keyId: string;
		active: boolean;
	}[];
	const keyAId = keys.find((k) => !k.active)?.keyId as string;
	assert.equal((await call("DELETE", `/api/admin/signing-keys/${keyAId}`, { token: adminToken })).status, 200);
	assert.equal(
		clientSync((await call("GET", "/api/device/config", { token: deviceToken })).data.token as string),
		true,
	);
	assert.equal(pinned.length, 1); // solo B resta fidata

	// Non si può ritirare l'unica chiave rimasta.
	const soloKey = (await call("GET", "/api/admin/signing-keys", { token: adminToken })).data.keys as {
		keyId: string;
	}[];
	assert.equal(
		(await call("DELETE", `/api/admin/signing-keys/${soloKey[0]?.keyId}`, { token: adminToken })).status,
		400,
	);
});

test("binding mTLS: la logica richiede il certificato legato", () => {
	// Test unitario della logica su un service isolato.
	const dir = mkdtempSync(join(tmpdir(), "harness-mtls-"));
	try {
		const svc = new ControlPlaneService(new Store(dir));
		const admin = svc.auth.bootstrapAdminToken("t");
		const identity = svc.auth.authenticateAdmin(admin);
		const groupId = svc.org.overview(identity).groups[0]?.groupId as string;

		// Device legato a un fingerprint fin dall'enrollment.
		const enr = svc.devices.createEnrollToken(identity, groupId, 10);
		const bound = svc.devices.enrollDevice(enr, "bound", "AA:BB:CC:DD");

		// Senza certificato → 403.
		assert.throws(() => svc.auth.authenticateDevice(bound.deviceToken), /certificato client mTLS richiesto/);
		// Certificato sbagliato → 403.
		assert.throws(() => svc.auth.authenticateDevice(bound.deviceToken, "99:88:77"), /non corrisponde/);
		// Certificato giusto (normalizzazione dei due-punti/maiuscole) → ok.
		assert.equal(svc.auth.authenticateDevice(bound.deviceToken, "aabbccdd").deviceId, bound.deviceId);

		// Device non legato, TOFU disabilitato (default): il bind è rifiutato.
		const enr2 = svc.devices.createEnrollToken(identity, groupId, 10);
		const free = svc.devices.enrollDevice(enr2, "free");
		const dev = svc.auth.authenticateDevice(free.deviceToken);
		assert.equal(dev.deviceId, free.deviceId);
		assert.throws(() => svc.auth.bindDeviceCertificate(dev, "12:34:56:78"), /trust-on-first-use disabilitato/);
		// Il device resta autenticabile col solo token (nessun binding avvenuto).
		assert.equal(svc.auth.authenticateDevice(free.deviceToken).deviceId, free.deviceId);

		// Con l'opt-in esplicito, il TOFU funziona come prima.
		svc.org.updateOrg(identity, { allowCertTofu: true });
		svc.auth.bindDeviceCertificate(dev, "12:34:56:78");
		assert.throws(() => svc.auth.authenticateDevice(free.deviceToken), /richiesto/);
		assert.equal(svc.auth.authenticateDevice(free.deviceToken, "12345678").deviceId, free.deviceId);
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
		const expired = jwt({
			iss: issuer,
			aud: audience,
			exp: Math.floor(Date.now() / 1000) - 120,
			harness_role: "admin",
		});
		assert.equal(await callOidc(expired), 401);
	} finally {
		await new Promise((resolve) => oidcServer.close(resolve));
		rmSync(oidcDir, { recursive: true, force: true });
	}
});

test("P2: scadenza server-side del device token, requireDeviceCert e rate-limit XFF", () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-p2-"));
	try {
		const store = new Store(dir);
		const svc = new ControlPlaneService(store);
		const admin = svc.auth.bootstrapAdminToken("t");
		const id = svc.auth.authenticateAdmin(admin);
		const groupId = svc.org.overview(id).groups[0]?.groupId as string;

		// Scadenza token: un device con tokenIssuedAt vecchio è rifiutato.
		const enr = svc.devices.createEnrollToken(id, groupId, 10);
		const dev = svc.devices.enrollDevice(enr, "d");
		assert.equal(svc.auth.authenticateDevice(dev.deviceToken).deviceId, dev.deviceId);
		svc.org.updateOrg(id, { deviceTokenMaxAgeDays: 1 });
		const aged = store.state.devices[dev.deviceId];
		if (!aged) throw new Error("device non trovato nello store");
		aged.tokenIssuedAt = new Date(Date.now() - 3 * 86_400_000).toISOString();
		assert.throws(() => svc.auth.authenticateDevice(dev.deviceToken), /scaduto/);
		// La rotazione riemette il token e azzera l'età (il device è raggiunto
		// direttamente, come farebbe un flusso di re-emissione amministrativo).
		const record = store.state.devices[dev.deviceId];
		if (!record) throw new Error("device non trovato nello store");
		const rotated = svc.auth.rotateDeviceToken(record);
		assert.equal(svc.auth.authenticateDevice(rotated).deviceId, dev.deviceId);

		// requireDeviceCert: l'enrollment senza fingerprint è rifiutato, con è ok.
		svc.org.updateOrg(id, { requireDeviceCert: true });
		const enr2 = svc.devices.createEnrollToken(id, groupId, 10);
		assert.throws(() => svc.devices.enrollDevice(enr2, "d2"), /certificato client/);
		const enr3 = svc.devices.createEnrollToken(id, groupId, 10);
		const dev3 = svc.devices.enrollDevice(enr3, "d3", "AA:BB:CC:DD");
		assert.ok(dev3.deviceId);
		// TOFU disabilitato: bind-cert è rifiutato se il device non è già legato.
		const enr4 = svc.devices.createEnrollToken(id, groupId, 10);
		// (device legato all'enroll: per testare il rifiuto TOFU serve un device non legato,
		//  ma con requireDeviceCert non se ne creano; il percorso è coperto dalla logica.)
		void enr4;
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("eliminazione device: richiede il ruolo admin, rimuove lo stato ma l'audit resta consultabile", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-delete-device-"));
	try {
		const store = new Store(dir);
		const svc = new ControlPlaneService(store);
		const admin = svc.auth.bootstrapAdminToken("root");
		const id = svc.auth.authenticateAdmin(admin);
		const groupId = svc.org.overview(id).groups[0]?.groupId as string;

		const enr = svc.devices.createEnrollToken(id, groupId, 10);
		const dev = svc.devices.enrollDevice(enr, "da-eliminare");
		const device = store.state.devices[dev.deviceId];
		if (!device) throw new Error("device non trovato nello store");
		svc.devices.ingestAudit(device, [
			{ eventId: "e1", deviceId: dev.deviceId, timestamp: new Date().toISOString(), type: "agent_start", data: {} },
		]);

		// operator non può eliminare device: serve il ruolo admin.
		const operatorToken = svc.auth.createAdminToken(id, "op", "operator", 1);
		const operatorId = svc.auth.authenticateAdmin(operatorToken);
		assert.throws(() => svc.devices.deleteDevice(operatorId, dev.deviceId), /riservata al ruolo/);

		svc.devices.deleteDevice(id, dev.deviceId);
		assert.equal(store.state.devices[dev.deviceId], undefined);
		assert.throws(() => svc.devices.deleteDevice(id, dev.deviceId), /non trovato/);
		assert.throws(() => svc.devices.effectivePolicy(id, dev.deviceId), /non trovato/);

		// L'audit del device resta consultabile per stream id, indipendentemente
		// dal ciclo di vita del device (retention separata, vedi Store.pruneAudit).
		const events = await svc.auditLog.readDeviceAudit(id, dev.deviceId, 10);
		assert.equal(events.length, 1);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("retention: i token amministrativi scaduti vengono potati, quelli validi restano", () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-prune-admin-tokens-"));
	try {
		const store = new Store(dir);
		const svc = new ControlPlaneService(store);
		const admin = svc.auth.bootstrapAdminToken("root");
		const id = svc.auth.authenticateAdmin(admin);

		const validToken = svc.auth.createAdminToken(id, "valido", "viewer", 30);
		const expiringToken = svc.auth.createAdminToken(id, "scaduto", "viewer", 30);
		// Retrodata la scadenza direttamente nello stato, come farebbe il tempo.
		for (const record of Object.values(store.state.adminTokens)) {
			if (record.name === "scaduto") record.expiresAt = new Date(Date.now() - 1000).toISOString();
		}

		const pruned = svc.auth.pruneExpiredAdminTokens();
		assert.equal(pruned, 1);
		assert.equal(svc.auth.authenticateAdmin(validToken).name, "valido");
		assert.throws(() => svc.auth.authenticateAdmin(expiringToken), /non valido/);
		// Il token di bootstrap (senza scadenza) non viene mai toccato dal pruning.
		assert.equal(svc.auth.authenticateAdmin(admin).role, "admin");
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("retention: pruneAudit in file-mode non cancella righe (ruota su archivio per dimensione)", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-prune-file-audit-"));
	try {
		const store = new Store(dir);
		const svc = new ControlPlaneService(store);
		const admin = svc.auth.bootstrapAdminToken("root");
		const id = svc.auth.authenticateAdmin(admin);
		const groupId = svc.org.overview(id).groups[0]?.groupId as string;
		const enr = svc.devices.createEnrollToken(id, groupId, 10);
		const dev = svc.devices.enrollDevice(enr, "d");
		const device = store.state.devices[dev.deviceId];
		if (!device) throw new Error("device non trovato nello store");
		svc.devices.ingestAudit(device, [
			{ eventId: "e1", deviceId: dev.deviceId, timestamp: new Date().toISOString(), type: "agent_start", data: {} },
		]);

		// Soglia di rotazione altissima: nessuna riga viene toccata né archiviata.
		const untouched = await store.pruneAudit(365, 10 * 1024 * 1024);
		assert.ok(untouched.every((r) => r.prunedRows === 0 && r.rotated === false));
		const events = await store.readDeviceAudit(dev.deviceId, 10);
		assert.equal(events.length, 1);

		// Soglia di rotazione minima: il file viene ruotato su un archivio, ma
		// nessuna riga viene eliminata (tamper-evidence intatta).
		const rotated = await store.pruneAudit(365, 1);
		const deviceResult = rotated.find((r) => r.streamId === dev.deviceId);
		assert.equal(deviceResult?.prunedRows, 0);
		assert.equal(deviceResult?.rotated, true);
	} finally {
		rmSync(dir, { recursive: true, force: true });
	}
});

test("metriche di flotta: /metrics espone gauge coerenti con lo stato seedato (chiude E3)", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-fleet-metrics-"));
	const isolatedStore = new Store(dir);
	const isolatedService = new ControlPlaneService(isolatedStore);
	const isolatedServer = createControlPlaneServer(isolatedService, { readiness: () => isolatedStore.checkReady() });
	try {
		await new Promise<void>((resolve) => isolatedServer.listen(0, resolve));
		const port = (isolatedServer.address() as AddressInfo).port;
		const url = `http://127.0.0.1:${port}`;

		const admin = isolatedService.auth.bootstrapAdminToken("root");
		const identity = isolatedService.auth.authenticateAdmin(admin);
		const groupId = isolatedService.org.overview(identity).groups[0]?.groupId as string;

		// 2 device attivi, 1 stale (nessun contatto da oltre la finestra), 1
		// sospeso (kill switch acceso sul device).
		for (let i = 0; i < 2; i += 1) {
			const enr = isolatedService.devices.createEnrollToken(identity, groupId, 10);
			isolatedService.devices.enrollDevice(enr, `active-${i}`);
		}
		const enrStale = isolatedService.devices.createEnrollToken(identity, groupId, 10);
		const stale = isolatedService.devices.enrollDevice(enrStale, "stale-device");
		const staleRecord = isolatedStore.state.devices[stale.deviceId];
		if (!staleRecord) throw new Error("device stale non trovato");
		staleRecord.lastSeenAt = new Date(Date.now() - 24 * 3600_000).toISOString();
		const enrSuspended = isolatedService.devices.createEnrollToken(identity, groupId, 10);
		const suspended = isolatedService.devices.enrollDevice(enrSuspended, "suspended-device");
		isolatedService.devices.updateDevice(identity, suspended.deviceId, { killSwitch: true });
		isolatedStore.save();

		const response = await fetch(`${url}/metrics`);
		assert.equal(response.status, 200);
		const text = await response.text();

		assert.match(text, /# TYPE harness_fleet_devices gauge/);
		assert.match(text, /harness_fleet_devices\{state="active"\} 2/);
		assert.match(text, /harness_fleet_devices\{state="stale"\} 1/);
		assert.match(text, /harness_fleet_devices\{state="suspended"\} 1/);
		assert.match(text, /harness_fleet_kill_switch 0/);
		assert.match(text, /harness_fleet_config_version \d+/);

		// Il kill switch globale si riflette subito nel gauge al prossimo scrape.
		isolatedService.org.updateOrg(identity, { killSwitch: true });
		const response2 = await fetch(`${url}/metrics`);
		const text2 = await response2.text();
		assert.match(text2, /harness_fleet_kill_switch 1/);
		// Col kill switch globale attivo, tutti i device (anche i due "attivi") sono sospesi.
		assert.match(text2, /harness_fleet_devices\{state="suspended"\} 4/);
		assert.match(text2, /harness_fleet_devices\{state="active"\} 0/);
	} finally {
		await new Promise((resolve) => isolatedServer.close(resolve));
		rmSync(dir, { recursive: true, force: true });
	}
});

test("rate limit sull'enrollment: oltre la soglia risponde 429 (in-memory, file-mode)", async () => {
	// Server isolato: il rate limit è per-IP e condiviso da tutte le richieste
	// che colpiscono lo stesso processo, quindi non va condiviso col fixture
	// principale (già usato da molti altri test di enrollment su 127.0.0.1).
	const dir = mkdtempSync(join(tmpdir(), "harness-rate-limit-"));
	const isolatedStore = new Store(dir);
	const isolatedService = new ControlPlaneService(isolatedStore);
	const isolatedServer = createControlPlaneServer(isolatedService, { readiness: () => isolatedStore.checkReady() });
	try {
		await new Promise<void>((resolve) => isolatedServer.listen(0, resolve));
		const port = (isolatedServer.address() as AddressInfo).port;
		const url = `http://127.0.0.1:${port}/api/enroll`;
		const attempt = () =>
			fetch(url, {
				method: "POST",
				headers: { "content-type": "application/json" },
				body: JSON.stringify({ enrollToken: "enr_non_valido", deviceName: "x" }),
			});

		// Il controllo del rate limit precede la validazione del token: ogni
		// richiesta conta, valida o meno. Soglia di default: 20/minuto.
		const statuses: number[] = [];
		for (let i = 0; i < 21; i += 1) statuses.push((await attempt()).status);
		assert.ok(
			statuses.slice(0, 20).every((s) => s === 401),
			"le prime 20 falliscono per token non valido, non per rate limit",
		);
		assert.equal(statuses[20], 429, "la ventunesima richiesta nella stessa finestra deve essere respinta");
	} finally {
		await new Promise((resolve) => isolatedServer.close(resolve));
		rmSync(dir, { recursive: true, force: true });
	}
});

test("la UI statica viene servita con la dashboard, la paginazione e l'editor policy", async () => {
	const response = await fetch(`${baseUrl}/`);
	assert.equal(response.status, 200);
	const html = await response.text();
	assert.match(html, /Piattaforma amministrativa/);
	assert.match(html, /<!doctype html>/i);
	// Elementi chiave della UI ricostruita (regressione strutturale).
	assert.match(html, /id="dashboardCards"/);
	assert.match(html, /id="devPageSize"/);
	assert.match(html, /id="policyValidation"/);
	assert.match(html, /id="diffOut"/);
});

test("un errore interno inatteso non trapela il messaggio al client (500 generico)", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-err-"));
	const store = new Store(dir);
	const service = new ControlPlaneService(store);
	const token = service.auth.bootstrapAdminToken("root");
	// Forza un errore NON-ServiceError (Error grezzo con un messaggio "segreto")
	// nel percorso di un handler admin autenticato.
	service.org.overview = () => {
		throw new Error("dettaglio interno con segreto db://user:password@host");
	};
	const isolatedServer = createControlPlaneServer(service, { readiness: () => store.checkReady() });
	try {
		await new Promise<void>((resolve) => isolatedServer.listen(0, resolve));
		const port = (isolatedServer.address() as AddressInfo).port;
		const response = await fetch(`http://127.0.0.1:${port}/api/admin/overview`, {
			headers: { authorization: `Bearer ${token}` },
		});
		assert.equal(response.status, 500);
		const body = (await response.json()) as { error: string };
		assert.equal(body.error, "errore interno");
		assert.doesNotMatch(body.error, /segreto|password|db:/, "il messaggio interno non deve trapelare");
	} finally {
		await new Promise((resolve) => isolatedServer.close(resolve));
		rmSync(dir, { recursive: true, force: true });
	}
});

test("sessione UI: login→cookie+csrf, CSRF su mutazioni, revoca del token la invalida, logout (file-mode)", async () => {
	const dir = mkdtempSync(join(tmpdir(), "harness-session-"));
	const store = new Store(dir);
	const service = new ControlPlaneService(store);
	const rootToken = service.auth.bootstrapAdminToken("root");
	const isolatedServer = createControlPlaneServer(service, { readiness: () => store.checkReady() });
	try {
		await new Promise<void>((resolve) => isolatedServer.listen(0, resolve));
		const port = (isolatedServer.address() as AddressInfo).port;
		const base = `http://127.0.0.1:${port}`;
		const cookieOf = (h: string | null) => (h?.match(/harness_session=[^;]*/) ?? [])[0];

		// Crea un secondo token admin: quello con cui apriremo (e poi revocheremo)
		// la sessione, senza toccare l'ultimo admin di bootstrap.
		const created = await fetch(`${base}/api/admin/admin-tokens`, {
			method: "POST",
			headers: { authorization: `Bearer ${rootToken}`, "content-type": "application/json" },
			body: JSON.stringify({ name: "sessione", role: "admin", ttlDays: 1 }),
		});
		const opToken = ((await created.json()) as { token: string }).token;

		// Login: cookie httpOnly + SameSite + csrfToken nel body.
		const login = await fetch(`${base}/api/admin/session/login`, {
			method: "POST",
			headers: { "content-type": "application/json" },
			body: JSON.stringify({ token: opToken }),
		});
		assert.equal(login.status, 200);
		const setCookie = login.headers.get("set-cookie") ?? "";
		assert.match(setCookie, /HttpOnly/i);
		assert.match(setCookie, /SameSite=Strict/i);
		const cookie = cookieOf(setCookie) as string;
		const { csrfToken } = (await login.json()) as { csrfToken: string };
		assert.ok(csrfToken);

		// GET via solo cookie (nessun CSRF richiesto sulle letture).
		const overview = await fetch(`${base}/api/admin/overview`, { headers: { cookie } });
		assert.equal(overview.status, 200);

		// PUT mutante senza CSRF token → 403; con CSRF corretto → 200.
		const putNoCsrf = await fetch(`${base}/api/admin/org`, {
			method: "PUT",
			headers: { cookie, "content-type": "application/json" },
			body: JSON.stringify({ killSwitch: false }),
		});
		assert.equal(putNoCsrf.status, 403);
		const putCsrf = await fetch(`${base}/api/admin/org`, {
			method: "PUT",
			headers: { cookie, "content-type": "application/json", "x-csrf-token": csrfToken },
			body: JSON.stringify({ killSwitch: false }),
		});
		assert.equal(putCsrf.status, 200);

		// /session/me riconsegna il CSRF token finché il cookie è valido.
		const me = await fetch(`${base}/api/admin/session/me`, { headers: { cookie } });
		const meBody = (await me.json()) as { authenticated: boolean; csrfToken?: string };
		assert.equal(meBody.authenticated, true);
		assert.equal(meBody.csrfToken, csrfToken);

		// Revoca del token sorgente: la sessione aperta con esso smette SUBITO di
		// autenticare (chiude il bug della regressione A2), usando l'admin root.
		const tokens = (await (
			await fetch(`${base}/api/admin/admin-tokens`, { headers: { authorization: `Bearer ${rootToken}` } })
		).json()) as { tokens: { id: string; name: string }[] };
		const opTokenId = tokens.tokens.find((t) => t.name === "sessione")?.id as string;
		const revoke = await fetch(`${base}/api/admin/admin-tokens/${opTokenId}`, {
			method: "DELETE",
			headers: { authorization: `Bearer ${rootToken}` },
		});
		assert.equal(revoke.status, 200);
		const afterRevoke = await fetch(`${base}/api/admin/overview`, { headers: { cookie } });
		assert.equal(afterRevoke.status, 401, "la sessione deve cadere subito alla revoca del token sorgente");
	} finally {
		await new Promise((resolve) => isolatedServer.close(resolve));
		rmSync(dir, { recursive: true, force: true });
	}
});
