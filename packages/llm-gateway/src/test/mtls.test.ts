import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { Agent, request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { ControlPlaneService, createControlPlaneServer, Store } from "@harness/control-plane";
import { createGatewayServer } from "../gateway.js";
import { cleanupCa, makeCa, makeCert, openSslAvailable } from "./tls-fixtures.js";

const HAS_OPENSSL = openSslAvailable();

let dataDir: string;
let controlPlane: ReturnType<typeof createControlPlaneServer>;
let upstream: Server;
let gateway: ReturnType<typeof createGatewayServer>;
let gwPort: number;
let ca: ReturnType<typeof makeCa>;
let clientCert: { certPem: string; keyPem: string };
let deviceToken: string;

function fingerprint(certPem: string): string {
	return createHash("sha256").update(new X509Certificate(certPem).raw).digest("hex");
}

before(async () => {
	if (!HAS_OPENSSL) return;
	dataDir = mkdtempSync(join(tmpdir(), "harness-gw-mtls-"));
	ca = makeCa();
	const serverCert = makeCert(ca, "localhost");
	clientCert = makeCert(ca, "device-01");

	const store = new Store(dataDir);
	const service = new ControlPlaneService(store);
	const admin = service.auth.authenticateAdmin(service.auth.bootstrapAdminToken("t"));
	const groupId = service.org.overview(admin).groups[0]?.groupId as string;
	const enrollToken = service.devices.createEnrollToken(admin, groupId, 10);
	// Device legato al fingerprint del certificato client.
	const enrollment = service.devices.enrollDevice(enrollToken, "device-01", fingerprint(clientCert.certPem));
	deviceToken = enrollment.deviceToken;
	const gatewayToken = service.auth.createGatewayToken(admin, "gw");

	controlPlane = createControlPlaneServer(service);
	await new Promise<void>((r) => controlPlane.listen(0, r));
	const cpUrl = `http://127.0.0.1:${(controlPlane.address() as AddressInfo).port}`;

	upstream = createServer((_req, res) => {
		res.writeHead(200, { "content-type": "application/json" });
		res.end(JSON.stringify({ echo: true }));
	});
	await new Promise<void>((r) => upstream.listen(0, r));
	const upUrl = `http://127.0.0.1:${(upstream.address() as AddressInfo).port}`;

	gateway = createGatewayServer({
		controlPlaneUrl: cpUrl,
		gatewayToken,
		providers: { anthropic: { baseUrl: upUrl, apiKey: "k" } },
		tls: { cert: serverCert.certPem, key: serverCert.keyPem },
		introspectionTtlMs: 50,
		log: () => {},
	});
	await new Promise<void>((r) => gateway.listen(0, r));
	gwPort = (gateway.address() as AddressInfo).port;
});

after(async () => {
	if (!HAS_OPENSSL) return;
	for (const s of [gateway, upstream, controlPlane]) await new Promise((r) => s.close(r));
	cleanupCa(ca);
	rmSync(dataDir, { recursive: true, force: true });
});

function call(withClientCert: boolean): Promise<number> {
	return new Promise((resolve, reject) => {
		const agentOpts: ConstructorParameters<typeof Agent>[0] = { ca: ca.certPem };
		if (withClientCert) {
			agentOpts.cert = clientCert.certPem;
			agentOpts.key = clientCert.keyPem;
		}
		const r = httpsRequest(
			{
				hostname: "localhost",
				port: gwPort,
				path: "/anthropic/v1/messages",
				method: "POST",
				headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
				agent: new Agent(agentOpts),
			},
			(res) => {
				res.resume();
				resolve(res.statusCode ?? 0);
			},
		);
		r.on("error", reject);
		r.end("{}");
	});
}

test("device legato mTLS: inferenza solo col certificato client corretto", { skip: !HAS_OPENSSL }, async () => {
	// Con il certificato client giusto → 200 (inoltro all'upstream).
	assert.equal(await call(true), 200);
	await new Promise((r) => setTimeout(r, 60)); // oltre il TTL di introspezione
	// Token valido ma SENZA certificato → 401: il token rubato non basta.
	assert.equal(await call(false), 401);
});
