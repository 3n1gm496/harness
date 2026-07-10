#!/usr/bin/env node
import { resolve } from "node:path";
import { ControlPlaneService } from "./service.js";
import { createControlPlaneServer } from "./server.js";
import { Store } from "./store.js";

/**
 * CLI del control plane.
 *
 *   harness-cp init  [--data-dir <dir>]           genera chiavi e primo token admin
 *   harness-cp serve [--data-dir <dir>] [--port]  avvia il server
 */
function main(): void {
	const args = process.argv.slice(2);
	const command = args[0];
	const dataDir = resolve(flagValue(args, "--data-dir") ?? process.env.HARNESS_CP_DATA_DIR ?? ".data/control-plane");

	if (command === "init") {
		const store = new Store(dataDir);
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
		const store = new Store(dataDir);
		if (Object.keys(store.state.adminTokens).length === 0) {
			console.warn("[control-plane] ATTENZIONE: nessun token amministrativo. Esegui prima `harness-cp init`.");
		}
		const service = new ControlPlaneService(store);
		const server = createControlPlaneServer(service);
		server.listen(port, () => {
			console.log(`[control-plane] in ascolto su http://localhost:${port} (data dir: ${dataDir})`);
		});
		const shutdown = () => server.close(() => process.exit(0));
		process.on("SIGINT", shutdown);
		process.on("SIGTERM", shutdown);
		return;
	}

	console.error("Uso: harness-cp <init|serve> [--data-dir <dir>] [--port <porta>] [--name <nome>]");
	process.exit(2);
}

function flagValue(args: string[], flag: string): string | undefined {
	const index = args.indexOf(flag);
	if (index === -1 || index + 1 >= args.length) return undefined;
	return args[index + 1];
}

main();
