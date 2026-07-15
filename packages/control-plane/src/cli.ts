#!/usr/bin/env node
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import type { Kek } from "@harness/shared";
import { createLogger, installProcessGuards, loadKekFromEnv } from "@harness/shared";
import { createControlPlaneServer } from "./server.js";
import { ControlPlaneService } from "./service.js";
import { Store } from "./store.js";

/**
 * CLI del control plane.
 *
 *   harness-cp init  [--data-dir <dir>]           genera chiavi e primo token admin
 *   harness-cp serve [--data-dir <dir>] [--port]  avvia il server
 */
async function main(): Promise<void> {
	const args = process.argv.slice(2);
	const command = args[0];
	const dataDir = resolve(flagValue(args, "--data-dir") ?? process.env.HARNESS_CP_DATA_DIR ?? ".data/control-plane");

	if (command === "init") {
		const store = new Store(dataDir, kekOptions());
		const service = new ControlPlaneService(store);
		let token: string;
		try {
			token = service.auth.bootstrapAdminToken(flagValue(args, "--name") ?? "founder");
		} catch {
			console.error(`Data dir già inizializzata (${dataDir}): esiste già un token amministrativo.`);
			console.error("Per crearne altri usa POST /api/admin/admin-tokens con un token admin esistente.");
			process.exit(1);
		}
		console.log("Control plane inizializzato.");
		console.log(`  Data dir:        ${dataDir}`);
		console.log(`  Chiave pubblica: ${dataDir}/keys/config-signing.pub`);
		console.log("");
		console.log("Token amministrativo (mostrato solo ora, conservalo in un secret manager):");
		console.log(`  ${token}`);
		return;
	}

	if (command === "serve") {
		const port = Number(flagValue(args, "--port") ?? process.env.PORT ?? "8787");
		const store = await openStore(dataDir);
		if (Object.keys(store.state.adminTokens).length === 0) {
			console.warn("[control-plane] ATTENZIONE: nessun token amministrativo. Esegui prima `harness-cp init`.");
		}
		const oidc = loadOidcFromEnv();
		if (oidc) await startJwksRefresh(oidc);
		const service = new ControlPlaneService(store, oidc ? { oidc } : {});
		if (oidc) console.log(`[control-plane] OIDC admin abilitato (issuer ${oidc.issuer})`);
		// Retention: i token amministrativi scaduti non si ripuliscono da soli
		// (nessuna route li elimina, solo `authenticateAdmin` li rifiuta): senza
		// questo timer resterebbero per sempre nello stato. Il pruning più
		// pesante (audit/changelog) resta un'azione esplicita (`harness-cp
		// prune`, schedulata via cron esterno), non automatica al boot. Le
		// sessioni della UI (A2) vivono solo in memoria di processo e scadono da
		// sole, ma vanno comunque liberate periodicamente per non trattenerle
		// oltre il TTL in caso di traffico di login sostenuto.
		service.auth.pruneExpiredAdminTokens();
		void service.auth.pruneExpiredSessions().catch(() => {});
		const adminTokenPruneTimer = setInterval(() => {
			service.auth.pruneExpiredAdminTokens();
			void service.auth.pruneExpiredSessions().catch(() => {});
		}, 6 * 3_600_000);
		adminTokenPruneTimer.unref();
		const tls = loadTlsFromEnv();
		const logger = createLogger("control-plane");
		// Ultima linea di difesa: un'eccezione non gestita logga ed esce ≠0 così
		// il supervisore riavvia pulito invece di proseguire in stato indefinito.
		installProcessGuards(logger);
		const options: Parameters<typeof createControlPlaneServer>[1] = {
			logger,
			readiness: () => store.checkReady(),
		};
		if (tls) options.tls = tls;
		const server = createControlPlaneServer(service, options);
		server.listen(port, () => {
			const scheme = tls ? "https" : "http";
			logger.info("listening", { url: `${scheme}://localhost:${port}`, dataDir });
			if (!tls) {
				logger.warn("plaintext_transport", {
					hint: "imposta HARNESS_TLS_CERT_FILE e HARNESS_TLS_KEY_FILE (o termina TLS su un reverse proxy)",
				});
			}
		});
		const shutdown = () => {
			clearInterval(adminTokenPruneTimer);
			server.close(() => {
				void store.close().finally(() => process.exit(0));
			});
		};
		process.on("SIGINT", shutdown);
		process.on("SIGTERM", shutdown);
		return;
	}

	if (command === "seed") {
		// Seeding idempotente per sviluppo/CI e per il primo avvio via compose:
		// garantisce un admin, un token di enrollment e un token gateway.
		const store = await openStore(dataDir);
		const service = new ControlPlaneService(store);
		let adminToken: string | undefined;
		try {
			adminToken = service.auth.bootstrapAdminToken(flagValue(args, "--name") ?? "seed-admin");
		} catch {
			// admin già presente: si procede con identità di sistema privilegiata.
		}
		const identity = { name: "seed-cli", role: "admin" as const };
		const groupId = service.org.overview(identity).groups[0]?.groupId as string;
		const ttlMinutes = Number(flagValue(args, "--ttl") ?? "60");
		const enrollToken = service.devices.createEnrollToken(identity, groupId, ttlMinutes);
		const gatewayToken = service.auth.createGatewayToken(identity, flagValue(args, "--gateway-name") ?? "seed-gateway");
		await store.flush();
		const credentials = {
			...(adminToken ? { adminToken } : { adminToken: "(già esistente: usa quello salvato)" }),
			groupId,
			enrollToken,
			gatewayToken,
			publicKeyPem: `${dataDir}/keys/config-signing.pub`,
		};

		const outFile = flagValue(args, "--out");
		if (outFile) {
			// Scrive i segreti solo su file (0600), mai su stdout: in un
			// container orchestrato, stdout finisce nei log centralizzati
			// (`docker logs`, aggregatori) — un posto sbagliato per un token
			// amministrativo o di enrollment.
			mkdirSync(dirname(resolve(outFile)), { recursive: true });
			const tmp = `${outFile}.tmp`;
			writeFileSync(tmp, JSON.stringify(credentials, null, 2), { mode: 0o600 });
			renameSync(tmp, outFile);
			console.log(`Credenziali di seed scritte in ${outFile} (0600).`);
			console.log(`  Data dir: ${dataDir}`);
			console.log(`  Gruppo:   ${groupId}`);
		} else {
			// Uso interattivo da terminale (come `init`): stampa le credenziali.
			process.stdout.write(`${JSON.stringify(credentials, null, 2)}\n`);
		}
		await store.close();
		return;
	}

	if (command === "verify-audit") {
		const store = new Store(dataDir, kekOptions());
		const deviceId = flagValue(args, "--device");
		void (deviceId ? store.verifyDeviceAudit(deviceId) : store.verifyAdminAudit()).then((result) => {
			if (result.valid) {
				console.log(`Catena di audit integra (${result.entries} righe).`);
			} else {
				console.error(
					`CATENA COMPROMESSA alla riga ${result.brokenAtLine} (${result.reason}); ${result.entries} righe valide prima della rottura.`,
				);
				process.exit(1);
			}
		});
		return;
	}

	if (command === "export-audit-anchor") {
		const store = new Store(dataDir, kekOptions());
		const service = new ControlPlaneService(store);
		// Identità di sistema locale: l'esecuzione della CLI è già un'operazione
		// privilegiata sul data dir.
		const anchor = await service.auditLog.exportAuditAnchor({ name: "cli", role: "admin" });
		process.stdout.write(`${anchor.anchor}\n`);
		return;
	}

	if (command === "rekey") {
		// Rotazione della KEK: la corrente viene da HARNESS_SIGNING_KEK (come
		// sempre), la nuova da HARNESS_SIGNING_KEK_NEW o --new-kek-file.
		const currentKek = loadKekFromEnv();
		if (!currentKek) {
			console.error("HARNESS_SIGNING_KEK (la KEK corrente) è obbligatoria per la rotazione.");
			process.exit(1);
		}
		const newKekFile = flagValue(args, "--new-kek-file");
		const newKek = newKekFile
			? loadKekFromEnv({ HARNESS_SIGNING_KEK_NEW: readFileSync(newKekFile, "utf8").trim() }, "HARNESS_SIGNING_KEK_NEW")
			: loadKekFromEnv(process.env, "HARNESS_SIGNING_KEK_NEW");
		if (!newKek) {
			console.error("Nuova KEK mancante: imposta HARNESS_SIGNING_KEK_NEW oppure passa --new-kek-file <path>.");
			process.exit(1);
		}
		const store = new Store(dataDir, { kek: currentKek });
		const keyCount = store.listSigningKeys().length;
		await store.rekey(newKek);
		await store.close();
		console.log(`Rotazione completata: ${keyCount} chiave/i di firma ri-sigillata/e con la nuova KEK.`);
		console.log("Aggiorna HARNESS_SIGNING_KEK con il valore usato come HARNESS_SIGNING_KEK_NEW e riavvia il servizio.");
		return;
	}

	if (command === "prune") {
		// Retention: token admin scaduti, log di audit più vecchi della soglia
		// (giorni), changelog di sincronizzazione oltre le ultime N righe. Va
		// schedulato (cron esterno); `serve` la esegue anche all'avvio e ogni 6h.
		const store = await openStore(dataDir);
		const service = new ControlPlaneService(store);
		const auditDays = Number(flagValue(args, "--audit-days") ?? "365");
		const changelogKeep = Number(flagValue(args, "--changelog-keep") ?? "100000");
		const prunedAdminTokens = service.auth.pruneExpiredAdminTokens();
		const prunedSessions = await service.auth.pruneExpiredSessions();
		const auditResults = await store.pruneAudit(auditDays);
		const changelogResult = await store.pruneChangelog(changelogKeep);
		await store.close();
		console.log(`Token amministrativi scaduti rimossi: ${prunedAdminTokens}`);
		console.log(`Sessioni UI scadute rimosse: ${prunedSessions}`);
		for (const r of auditResults) {
			if (r.prunedRows > 0) console.log(`  audit[${r.streamId}]: ${r.prunedRows} righe potate (oltre ${auditDays}gg)`);
			if (r.rotated) console.log(`  audit[${r.streamId}]: file ruotato su archivio (dimensione)`);
		}
		if (changelogResult)
			console.log(`Changelog: ${changelogResult.prunedRows} righe potate (oltre le ultime ${changelogKeep})`);
		return;
	}

	console.error(
		"Uso: harness-cp <init|seed|serve|verify-audit|export-audit-anchor|rekey|prune> [--data-dir <dir>] [--port <porta>] [--name <nome>] [--ttl <min>] [--device <id>] [--out <file>] [--new-kek-file <path>] [--audit-days <n>] [--changelog-keep <n>]",
	);
	process.exit(2);
}

function flagValue(args: string[], flag: string): string | undefined {
	const index = args.indexOf(flag);
	if (index === -1 || index + 1 >= args.length) return undefined;
	return args[index + 1];
}

/**
 * Apre lo Store, usando Postgres come backend durevole se DATABASE_URL è
 * impostata (per flotte grandi / alta disponibilità), altrimenti il file store
 * locale (default, zero dipendenze).
 */
function kekOptions(): { kek?: Kek } {
	const kek = loadKekFromEnv();
	return kek ? { kek } : {};
}

async function openStore(dataDir: string): Promise<Store> {
	const dbUrl = process.env.DATABASE_URL;
	if (!dbUrl) return new Store(dataDir, kekOptions());
	const { PostgresStateStore } = await import("./state-store.js");
	// Su stderr: lo stdout di `seed` deve restare JSON puro (viene parsato).
	console.error("[control-plane] backend di stato: Postgres (DATABASE_URL)");
	return Store.openWithBackend(dataDir, new PostgresStateStore(dbUrl), kekOptions());
}

function loadTlsFromEnv(): { cert: string; key: string } | undefined {
	const certFile = process.env.HARNESS_TLS_CERT_FILE;
	const keyFile = process.env.HARNESS_TLS_KEY_FILE;
	if (!certFile || !keyFile) return undefined;
	return { cert: readFileSync(certFile, "utf8"), key: readFileSync(keyFile, "utf8") };
}

/**
 * Config OIDC da ambiente:
 *   HARNESS_OIDC_ISSUER, HARNESS_OIDC_AUDIENCE   (obbligatorie per abilitare)
 *   HARNESS_OIDC_KEYS_FILE  JSON [{ kid?, alg: "RS256"|"ES256", publicKeyPem }]
 *   HARNESS_OIDC_ROLE_CLAIM (default "harness_role")
 *   HARNESS_OIDC_NAME_CLAIM (default "email")
 */
function loadOidcFromEnv(): import("./service.js").OidcConfig | undefined {
	const issuer = process.env.HARNESS_OIDC_ISSUER;
	const audience = process.env.HARNESS_OIDC_AUDIENCE;
	const keysFile = process.env.HARNESS_OIDC_KEYS_FILE;
	if (!issuer || !audience || !keysFile) return undefined;
	const keys = JSON.parse(readFileSync(keysFile, "utf8")) as import("@harness/shared").JwtVerifyKey[];
	const config: import("./service.js").OidcConfig = { issuer, audience, keys };
	if (process.env.HARNESS_OIDC_ROLE_CLAIM) config.roleClaim = process.env.HARNESS_OIDC_ROLE_CLAIM;
	if (process.env.HARNESS_OIDC_NAME_CLAIM) config.nameClaim = process.env.HARNESS_OIDC_NAME_CLAIM;
	return config;
}

/**
 * Se HARNESS_OIDC_JWKS_URI è impostata, scarica il JWKS del provider e ne
 * popola le chiavi (convertendo JWK→PEM), con refresh orario: così la rotazione
 * delle chiavi di firma dell'IdP non richiede aggiornamenti manuali.
 */
async function startJwksRefresh(oidc: import("./service.js").OidcConfig): Promise<void> {
	const uri = process.env.HARNESS_OIDC_JWKS_URI;
	if (!uri) return;
	const { createPublicKey } = await import("node:crypto");
	const refresh = async (): Promise<void> => {
		try {
			const res = await fetch(uri, { signal: AbortSignal.timeout(10_000) });
			if (!res.ok) throw new Error(`HTTP ${res.status}`);
			const jwks = (await res.json()) as { keys?: Record<string, unknown>[] };
			const keys: import("@harness/shared").JwtVerifyKey[] = [];
			for (const jwk of jwks.keys ?? []) {
				const alg = jwk.kty === "RSA" ? "RS256" : jwk.kty === "EC" ? "ES256" : undefined;
				if (!alg) continue;
				try {
					const publicKeyPem = createPublicKey({ key: jwk as never, format: "jwk" })
						.export({ type: "spki", format: "pem" })
						.toString();
					const entry: import("@harness/shared").JwtVerifyKey = { alg, publicKeyPem };
					if (typeof jwk.kid === "string") entry.kid = jwk.kid;
					keys.push(entry);
				} catch {
					// JWK non convertibile: saltata.
				}
			}
			if (keys.length > 0) {
				oidc.keys.length = 0;
				oidc.keys.push(...keys);
			}
		} catch (error) {
			console.warn(`[control-plane] refresh JWKS fallito: ${error instanceof Error ? error.message : String(error)}`);
		}
	};
	await refresh();
	const timer = setInterval(() => void refresh(), 3_600_000);
	timer.unref();
}

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
});
