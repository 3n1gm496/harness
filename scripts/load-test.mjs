// Load-test: arruola N device su un control plane reale (in-process) e
// simula il loro poll di configurazione + flush di audit concorrenti,
// misurando p50/p95/throughput. Prova prestazionale per l'indice O(1)
// token→device (P1.1): senza, il tempo per richiesta scalerebbe linearmente
// col numero di device invece di restare piatto.
//
// Usa il backend Postgres se HARNESS_TEST_PG_URL è impostata (scala reale,
// multi-riga), altrimenti il file store locale (comunque valido: l'indice è
// in-memory in entrambi i casi).
//
//   node scripts/load-test.mjs --devices 500 [--requests-per-device 5] [--concurrency 50]

import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ControlPlaneService, createControlPlaneServer, PostgresStateStore, Store } from "@harness/control-plane";
import { generateKek } from "@harness/shared";

/**
 * Il load-test presuppone un database dedicato/effimero e parte sempre da
 * zero: azzera lo schema (stessa tecnica dei test PG live) invece di
 * convivere con lo stato di sessioni precedenti (es. chiavi di firma sigillate
 * con una KEK diversa, che altrimenti farebbero fallire l'apertura dello Store).
 */
async function resetPgSchema(url) {
	const store = new PostgresStateStore(url);
	await store.ensureReady();
	await store.query(
		`TRUNCATE cp_org, cp_groups, cp_devices, cp_admin_tokens, cp_gateway_tokens,
			cp_enroll_tokens, cp_signing_keys, cp_audit_events, cp_audit_heads, cp_changelog,
			cp_rate_buckets, cp_audit_prune_state, cp_changelog_prune_floor
		 RESTART IDENTITY CASCADE`,
	);
	await store.close();
}

function flagValue(args, flag, fallback) {
	const index = args.indexOf(flag);
	if (index === -1 || index + 1 >= args.length) return fallback;
	return Number(args[index + 1]);
}

/** Limita la concorrenza effettiva su un elenco di task asincroni. */
async function runWithConcurrency(items, limit, worker) {
	const results = new Array(items.length);
	let next = 0;
	async function runNext() {
		while (true) {
			const i = next++;
			if (i >= items.length) return;
			results[i] = await worker(items[i], i);
		}
	}
	await Promise.all(Array.from({ length: Math.min(limit, items.length) }, runNext));
	return results;
}

function percentile(sortedMs, p) {
	if (sortedMs.length === 0) return 0;
	const index = Math.min(sortedMs.length - 1, Math.floor((p / 100) * sortedMs.length));
	return sortedMs[index];
}

function summarize(label, samplesMs, errors) {
	const sorted = [...samplesMs].sort((a, b) => a - b);
	const p50 = percentile(sorted, 50);
	const p95 = percentile(sorted, 95);
	const max = sorted.at(-1) ?? 0;
	console.log(
		`  ${label.padEnd(24)} n=${samplesMs.length.toString().padStart(6)}  p50=${p50.toFixed(1).padStart(7)}ms  ` +
			`p95=${p95.toFixed(1).padStart(7)}ms  max=${max.toFixed(1).padStart(7)}ms  errori=${errors}`,
	);
	return { p50, p95, max, errors };
}

async function main() {
	const args = process.argv.slice(2);
	const deviceCount = flagValue(args, "--devices", 200);
	const requestsPerDevice = flagValue(args, "--requests-per-device", 5);
	const concurrency = flagValue(args, "--concurrency", 50);
	// Soglie di regressione: un indice O(1) non deve degradare sensibilmente
	// all'aumentare della flotta. Generose apposta (l'ambiente CI è condiviso
	// e non isolato): l'obiettivo è cogliere una regressione O(n), non
	// misurare un SLA di produzione.
	const p95ThresholdMs = flagValue(args, "--p95-threshold-ms", 750);

	const pgUrl = process.env.HARNESS_TEST_PG_URL;
	const dataDir = mkdtempSync(join(tmpdir(), "harness-load-test-"));
	console.log(
		`▶ Load-test: ${deviceCount} device × ${requestsPerDevice} richieste (config+audit), concorrenza ${concurrency}`,
	);
	console.log(`  Backend: ${pgUrl ? "Postgres (HARNESS_TEST_PG_URL) — schema azzerato" : "file locale"}`);

	if (pgUrl) await resetPgSchema(pgUrl);
	const store = pgUrl
		? await Store.openWithBackend(dataDir, new PostgresStateStore(pgUrl), {
				kek: { key: Buffer.from(generateKek(), "base64") },
			})
		: new Store(dataDir);
	const service = new ControlPlaneService(store);
	const server = createControlPlaneServer(service, { readiness: () => store.checkReady() });
	await new Promise((resolve) => server.listen(0, resolve));
	const port = server.address().port;
	const baseUrl = `http://127.0.0.1:${port}`;

	try {
		const admin = service.auth.bootstrapAdminToken("load-test-admin");
		const identity = service.auth.authenticateAdmin(admin);
		const groupId = service.org.overview(identity).groups[0].groupId;

		console.log(`▶ Arruolamento di ${deviceCount} device…`);
		const enrollStart = performance.now();
		const devices = [];
		for (let i = 0; i < deviceCount; i += 1) {
			const enrollToken = service.devices.createEnrollToken(identity, groupId, 60);
			const enrolled = service.devices.enrollDevice(enrollToken, `load-device-${i}`);
			devices.push(enrolled);
		}
		await store.flush();
		console.log(`  fatto in ${(performance.now() - enrollStart).toFixed(0)}ms`);

		// Warm-up: qualche richiesta scartata dalle misure, per non contare il
		// costo una-tantum di JIT/inizializzazione crypto come se fosse lo stato
		// stazionario (altrimenti la coda delle percentili si gonfia per motivi
		// estranei all'indice token→device che il test vuole verificare).
		for (const device of devices.slice(0, Math.min(10, devices.length))) {
			await fetch(`${baseUrl}/api/device/config`, { headers: { authorization: `Bearer ${device.deviceToken}` } });
		}

		// Ogni device fa lo stesso ciclo di un client reale in produzione: poll
		// di config firmata, poi invio di un batch di audit. Le richieste vanno
		// su HTTP reale (non chiamate dirette al service): il percorso caldo
		// sotto test è authenticateDevice → deviceByTokenHash, sul server vero.
		const configSamples = [];
		const auditSamples = [];
		let configErrors = 0;
		let auditErrors = 0;

		const started = performance.now();
		const tasks = [];
		for (const device of devices) {
			for (let r = 0; r < requestsPerDevice; r += 1) tasks.push(device);
		}

		await runWithConcurrency(tasks, concurrency, async (device) => {
			const t0 = performance.now();
			try {
				const res = await fetch(`${baseUrl}/api/device/config`, {
					headers: { authorization: `Bearer ${device.deviceToken}` },
				});
				if (!res.ok) throw new Error(`HTTP ${res.status}`);
				await res.json();
				configSamples.push(performance.now() - t0);
			} catch {
				configErrors += 1;
			}

			const t1 = performance.now();
			try {
				const res = await fetch(`${baseUrl}/api/device/audit`, {
					method: "POST",
					headers: { authorization: `Bearer ${device.deviceToken}`, "content-type": "application/json" },
					body: JSON.stringify({
						events: [
							{
								eventId: `e-${Math.random()}`,
								deviceId: device.deviceId,
								timestamp: new Date().toISOString(),
								type: "policy_decision",
								data: {},
							},
						],
					}),
				});
				if (!res.ok) throw new Error(`HTTP ${res.status}`);
				await res.json();
				auditSamples.push(performance.now() - t1);
			} catch {
				auditErrors += 1;
			}
		});
		const totalMs = performance.now() - started;
		const totalRequests = configSamples.length + auditSamples.length + configErrors + auditErrors;

		console.log(
			`\n▶ Risultati (${totalMs.toFixed(0)}ms totali, ${((totalRequests / totalMs) * 1000).toFixed(1)} req/s):`,
		);
		const configStats = summarize("GET /api/device/config", configSamples, configErrors);
		const auditStats = summarize("POST /api/device/audit", auditSamples, auditErrors);

		const failures = [];
		if (configErrors > 0) failures.push(`${configErrors} errori su /api/device/config`);
		if (auditErrors > 0) failures.push(`${auditErrors} errori su /api/device/audit`);
		if (configStats.p95 > p95ThresholdMs)
			failures.push(`p95 config ${configStats.p95.toFixed(1)}ms oltre la soglia ${p95ThresholdMs}ms`);
		if (auditStats.p95 > p95ThresholdMs)
			failures.push(`p95 audit ${auditStats.p95.toFixed(1)}ms oltre la soglia ${p95ThresholdMs}ms`);

		if (failures.length > 0) {
			console.error(`\n✗ Load-test FALLITO:\n${failures.map((f) => `  - ${f}`).join("\n")}`);
			process.exitCode = 1;
		} else {
			console.log("\n✔ Load-test superato entro le soglie.");
		}
	} finally {
		server.close();
		await store.close();
		rmSync(dataDir, { recursive: true, force: true });
	}
}

main().catch((error) => {
	console.error(error);
	process.exit(1);
});
