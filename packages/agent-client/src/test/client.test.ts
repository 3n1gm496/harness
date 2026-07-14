import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { AddressInfo } from "node:net";
import { after, before, test } from "node:test";
import { ControlPlaneService, Store, createControlPlaneServer } from "@harness/control-plane";
import { verifyConfigBundle } from "@harness/shared";
import { applyManagedPiSettings, buildPiArgs, enroll, maybeRotateToken, syncConfig } from "../client.js";

let dataDir: string;
let clientDir: string;
let server: ReturnType<typeof createControlPlaneServer>;
let baseUrl: string;
let service: ControlPlaneService;
let adminToken: string;
let enrollToken: string;

before(async () => {
	dataDir = mkdtempSync(join(tmpdir(), "harness-ac-cp-"));
	clientDir = mkdtempSync(join(tmpdir(), "harness-ac-cli-"));
	const store = new Store(dataDir);
	service = new ControlPlaneService(store);
	adminToken = service.bootstrapAdminToken("test");
	server = createControlPlaneServer(service);
	await new Promise<void>((resolve) => server.listen(0, resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
	const identity = service.authenticateAdmin(adminToken);
	const groupId = service.overview(identity).groups[0]?.groupId as string;
	enrollToken = service.createEnrollToken(identity, groupId, 10);
});

after(async () => {
	await new Promise((resolve) => server.close(resolve));
	rmSync(dataDir, { recursive: true, force: true });
	rmSync(clientDir, { recursive: true, force: true });
});

test("enroll scrive l'identità del device con permessi 0600", async () => {
	const configPath = join(clientDir, "agent.json");
	const config = await enroll({
		controlPlaneUrl: baseUrl,
		enrollToken,
		deviceName: "workstation-42",
		configPath,
	});
	assert.ok(config.deviceId.startsWith("dev_"));
	assert.ok(config.publicKeyPem.includes("PUBLIC KEY"));
	const mode = statSync(configPath).mode & 0o777;
	assert.equal(mode, 0o600);

	const persisted = JSON.parse(readFileSync(configPath, "utf8")) as { deviceToken: string };
	assert.equal(persisted.deviceToken, config.deviceToken);

	// Provenance: enroll genera una coppia di firma propria del device e la
	// privata (mai trasmessa) resta solo nel file locale.
	assert.ok(config.deviceSigningPrivateKeyPem?.includes("PRIVATE KEY"));
	const identity = service.authenticateAdmin(adminToken);
	const overview = service.overview(identity);
	const registeredDevice = overview.devices.find((d) => d.deviceId === config.deviceId);
	assert.ok(registeredDevice, "il device deve comparire nell'overview");
});

test("flusso completo enroll → audit: il batch viene firmato e riconosciuto come provenance verificata", async () => {
	const identity = service.authenticateAdmin(adminToken);
	const groupId = service.overview(identity).groups[0]?.groupId as string;
	const freshEnrollToken = service.createEnrollToken(identity, groupId, 10);
	const configPath = join(clientDir, "agent-signed.json");

	const config = await enroll({
		controlPlaneUrl: baseUrl,
		enrollToken: freshEnrollToken,
		deviceName: "signed-workstation",
		configPath,
	});
	config.bundleCachePath = join(clientDir, "agent-signed-bundle.jws");
	config.auditFlushSeconds = 3600;
	config.syncIntervalSeconds = 3600;

	const { FleetState } = await import("@harness/fleet-extension");
	const state = new FleetState(config, configPath);
	await state.initialLoad();
	assert.equal(state.status, "ok");

	state.pushAudit("agent_start", { cwd: "/workspace" });
	await state.flushAudit();

	const events = await service.readDeviceAudit(identity, config.deviceId, 10);
	assert.ok(events.length > 0);
	assert.ok(events.every((e) => e.provenance === "signed"), "tutti gli eventi devono essere provenance=signed");
});

test("syncConfig scarica e verifica il bundle, e applica i settings gestiti", async () => {
	const configPath = join(clientDir, "agent.json");
	const config = JSON.parse(readFileSync(configPath, "utf8")) as Parameters<typeof syncConfig>[0];
	config.bundleCachePath = join(clientDir, "bundle.jws");

	const state = await syncConfig(config);
	assert.equal(state.status, "ok");
	assert.equal(state.policy.killSwitch, false);

	const cachedToken = readFileSync(config.bundleCachePath, "utf8").trim();
	const verified = verifyConfigBundle(config.publicKeyPem, cachedToken);
	assert.equal(verified.valid, true);
	if (!verified.valid) return;

	// Settings esistenti dell'utente + settings gestiti: i gestiti vincono.
	const piAgentDir = join(clientDir, "pi-agent");
	const settingsPath = join(piAgentDir, "settings.json");
	writeFileSync(join(clientDir, "placeholder"), ""); // assicura la dir
	applyManagedPiSettings(verified.payload, piAgentDir);
	const settings = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
	assert.equal(settings.defaultProjectTrust, "never");
	assert.equal(settings.enableInstallTelemetry, false);

	// Un secondo apply preserva le personalizzazioni utente non gestite.
	const withUserPrefs = { ...settings, theme: "light" };
	writeFileSync(settingsPath, JSON.stringify(withUserPrefs));
	applyManagedPiSettings(verified.payload, piAgentDir);
	const merged = JSON.parse(readFileSync(settingsPath, "utf8")) as Record<string, unknown>;
	assert.equal(merged.theme, "light");
	assert.equal(merged.defaultProjectTrust, "never");
});

test("enrollment con token non valido fallisce", async () => {
	await assert.rejects(
		enroll({
			controlPlaneUrl: baseUrl,
			enrollToken: "enr_falso",
			deviceName: "x",
			configPath: join(clientDir, "mai-scritto.json"),
		}),
		/enrollment fallito/,
	);
});

test("maybeRotateToken ruota su richiesta e non ruota se il token è recente", async () => {
	const configPath = join(clientDir, "agent.json");
	const config = JSON.parse(readFileSync(configPath, "utf8")) as Parameters<typeof maybeRotateToken>[0];
	const oldToken = config.deviceToken;

	// Token appena emesso: nessuna rotazione spontanea.
	assert.equal(await maybeRotateToken(config, configPath), false);

	// Rotazione forzata: nuovo token persistito, il vecchio non vale più.
	assert.equal(await maybeRotateToken(config, configPath, { force: true }), true);
	assert.notEqual(config.deviceToken, oldToken);
	const persisted = JSON.parse(readFileSync(configPath, "utf8")) as { deviceToken: string; tokenIssuedAt: string };
	assert.equal(persisted.deviceToken, config.deviceToken);
	assert.ok(persisted.tokenIssuedAt);

	const state = await syncConfig({ ...config, bundleCachePath: join(clientDir, "bundle2.jws") });
	assert.equal(state.status, "ok");
});

test("loadAgentConfig senza file dà un messaggio d'aiuto, non un ENOENT grezzo", async () => {
	const { loadAgentConfig } = await import("@harness/fleet-extension");
	assert.throws(
		() => loadAgentConfig(join(clientDir, "non-esiste.json")),
		/device non arruolato.*harness-agent enroll/s,
	);
});

test("buildPiArgs carica l'estensione fleet e passa gli argomenti extra", () => {
	const args = buildPiArgs("/opt/harness/fleet/dist/index.js", ["--mode", "rpc"]);
	assert.deepEqual(args, ["-e", "/opt/harness/fleet/dist/index.js", "--mode", "rpc"]);
});
