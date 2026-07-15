import assert from "node:assert/strict";
import { createHash, X509Certificate } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { Agent, request as httpsRequest } from "node:https";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { createControlPlaneServer } from "../server.js";
import { ControlPlaneService } from "../service.js";
import { Store } from "../store.js";
import { cleanupCa, makeCa, makeCert, openSslAvailable } from "./tls-fixtures.js";

const HAS_OPENSSL = openSslAvailable();

let dataDir: string;
let server: ReturnType<typeof createControlPlaneServer>;
let port: number;
let service: ControlPlaneService;
let ca: ReturnType<typeof makeCa>;
let serverCert: { certPem: string; keyPem: string };
let clientCert: { certPem: string; keyPem: string };
let clientFingerprint: string;

function fingerprintOf(certPem: string): string {
	const der = new X509Certificate(certPem).raw;
	return createHash("sha256").update(der).digest("hex");
}

before(async () => {
	if (!HAS_OPENSSL) return;
	dataDir = mkdtempSync(join(tmpdir(), "harness-mtls-int-"));
	ca = makeCa();
	serverCert = makeCert(ca, "localhost");
	clientCert = makeCert(ca, "device-01");
	clientFingerprint = fingerprintOf(clientCert.certPem);

	const store = new Store(dataDir);
	service = new ControlPlaneService(store);
	server = createControlPlaneServer(service, { tls: { cert: serverCert.certPem, key: serverCert.keyPem } });
	await new Promise<void>((resolve) => server.listen(0, resolve));
	port = (server.address() as AddressInfo).port;
});

after(async () => {
	if (!HAS_OPENSSL) return;
	await new Promise((resolve) => server.close(resolve));
	cleanupCa(ca);
	rmSync(dataDir, { recursive: true, force: true });
});

interface Resp {
	status: number;
	body: string;
}

function req(
	path: string,
	opts: { method?: string; token?: string; clientCert?: boolean; body?: string },
): Promise<Resp> {
	return new Promise((resolve, reject) => {
		const agentOpts: ConstructorParameters<typeof Agent>[0] = { ca: ca.certPem };
		if (opts.clientCert) {
			agentOpts.cert = clientCert.certPem;
			agentOpts.key = clientCert.keyPem;
		}
		const headers: Record<string, string> = { "content-type": "application/json" };
		if (opts.token) headers.authorization = `Bearer ${opts.token}`;
		const r = httpsRequest(
			{ hostname: "localhost", port, path, method: opts.method ?? "GET", headers, agent: new Agent(agentOpts) },
			(res) => {
				let data = "";
				res.on("data", (c) => {
					data += c;
				});
				res.on("end", () => resolve({ status: res.statusCode ?? 0, body: data }));
			},
		);
		r.on("error", reject);
		if (opts.body) r.write(opts.body);
		r.end();
	});
}

test("il server serve HTTPS e accetta connessioni con la CA di test", { skip: !HAS_OPENSSL }, async () => {
	const health = await req("/healthz", {});
	assert.equal(health.status, 200);
});

test("device legato mTLS: config solo col certificato client corretto", { skip: !HAS_OPENSSL }, async () => {
	// Bootstrap admin + enrollment del device legato al fingerprint del cert client.
	const admin = service.auth.bootstrapAdminToken("root");
	const identity = service.auth.authenticateAdmin(admin);
	const groupId = service.org.overview(identity).groups[0]?.groupId as string;
	const enrollToken = service.devices.createEnrollToken(identity, groupId, 10);
	const enrollment = service.devices.enrollDevice(enrollToken, "device-01", clientFingerprint);
	const deviceToken = enrollment.deviceToken;

	// Con il certificato client giusto → 200.
	const withCert = await req("/api/device/config", { token: deviceToken, clientCert: true });
	assert.equal(withCert.status, 200);

	// Con token valido ma SENZA certificato client → 403 (token rubato inutile).
	const withoutCert = await req("/api/device/config", { token: deviceToken, clientCert: false });
	assert.equal(withoutCert.status, 403);
});
