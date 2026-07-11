#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import type { Kek } from "@harness/shared";
import { loadKekFromEnv } from "@harness/shared";
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
		const service = new ControlPlaneService(store, oidc ? { oidc } : {});
		if (oidc) console.log(`[control-plane] OIDC admin abilitato (issuer ${oidc.issuer})`);
		const tls = loadTlsFromEnv();
		const options: Parameters<typeof createControlPlaneServer>[1] = {
			log: (entry) => console.log(JSON.stringify(entry)),
		};
		if (tls) options.tls = tls;
		const server = createControlPlaneServer(service, options);
		server.listen(port, () => {
			const scheme = tls ? "https" : "http";
			console.log(`[control-plane] in ascolto su ${scheme}://localhost:${port} (data dir: ${dataDir})`);
			if (!tls) {
				console.warn(
					"[control-plane] in chiaro: imposta HARNESS_TLS_CERT_FILE e HARNESS_TLS_KEY_FILE (o termina TLS su un reverse proxy)",
				);
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
		"Uso: harness-cp <init|serve|verify-audit|export-audit-anchor> [--data-dir <dir>] [--port <porta>] [--name <nome>] [--device <id>]",
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
	console.log("[control-plane] backend di stato: Postgres (DATABASE_URL)");
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

main().catch((error) => {
	console.error(error instanceof Error ? error.message : String(error));
	process.exit(1);
});
