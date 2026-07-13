#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Kek } from "@harness/shared";
import { createLogger, loadKekFromEnv } from "@harness/shared";
import { ControlPlaneService } from "./service.js";
import { createControlPlaneServer } from "./server.js";
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
			token = service.bootstrapAdminToken(flagValue(args, "--name") ?? "founder");
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
		const tls = loadTlsFromEnv();
		const logger = createLogger("control-plane");
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
		// garantisce un admin, un token di enrollment e un token gateway, e li
		// stampa come JSON su stdout. L'accesso al data dir è già privilegiato.
		const store = await openStore(dataDir);
		const service = new ControlPlaneService(store);
		let adminToken: string | undefined;
		try {
			adminToken = service.bootstrapAdminToken(flagValue(args, "--name") ?? "seed-admin");
		} catch {
			// admin già presente: si procede con identità di sistema privilegiata.
		}
		const identity = { name: "seed-cli", role: "admin" as const };
		const groupId = service.overview(identity).groups[0]?.groupId as string;
		const ttlMinutes = Number(flagValue(args, "--ttl") ?? "60");
		const enrollToken = service.createEnrollToken(identity, groupId, ttlMinutes);
		const gatewayToken = service.createGatewayToken(identity, flagValue(args, "--gateway-name") ?? "seed-gateway");
		await store.flush();
		process.stdout.write(
			`${JSON.stringify(
				{
					...(adminToken ? { adminToken } : { adminToken: "(già esistente: usa quello salvato)" }),
					groupId,
					enrollToken,
					gatewayToken,
					publicKeyPem: `${dataDir}/keys/config-signing.pub`,
				},
				null,
				2,
			)}\n`,
		);
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
		const anchor = await service.exportAuditAnchor({ name: "cli", role: "admin" });
		process.stdout.write(`${anchor.anchor}\n`);
		return;
	}

	console.error(
		"Uso: harness-cp <init|seed|serve|verify-audit|export-audit-anchor> [--data-dir <dir>] [--port <porta>] [--name <nome>] [--ttl <min>] [--device <id>]",
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
