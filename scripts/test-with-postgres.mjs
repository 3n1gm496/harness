// Runner di test con Postgres effimero, per esercitare in locale gli adapter
// PG (che altrimenti si auto-saltano). Se HARNESS_TEST_PG_URL è già impostata,
// la usa; altrimenti avvia un container Postgres usa-e-getta via Docker e lo
// smonta alla fine. Senza Docker, esegue comunque i test (i test PG si saltano).
//
//   npm run test:pg

import { spawn, spawnSync } from "node:child_process";

const CONTAINER = "harness-test-pg";
const URL = "postgresql://harness:harness@127.0.0.1:55433/harness";

function run(cmd, args, opts = {}) {
	return new Promise((resolve) => {
		const child = spawn(cmd, args, { stdio: "inherit", ...opts });
		child.on("exit", (code) => resolve(code ?? 1));
		child.on("error", () => resolve(-1));
	});
}
function hasDocker() {
	const r = spawnSync("docker", ["--version"], { stdio: "ignore" });
	return r.status === 0;
}
function docker(args, opts = {}) {
	return spawnSync("docker", args, { encoding: "utf8", ...opts });
}

async function main() {
	if (process.env.HARNESS_TEST_PG_URL) {
		console.log(`[test:pg] uso HARNESS_TEST_PG_URL esistente`);
		process.exit(await run("npm", ["test"]));
	}
	if (!hasDocker()) {
		console.warn("[test:pg] Docker non disponibile: eseguo i test (gli adapter Postgres si salteranno).");
		console.warn("[test:pg] Per esercitarli, imposta HARNESS_TEST_PG_URL verso un Postgres raggiungibile.");
		process.exit(await run("npm", ["test"]));
	}

	console.log("[test:pg] avvio Postgres effimero…");
	docker(["rm", "-f", CONTAINER], { stdio: "ignore" });
	const up = docker([
		"run",
		"-d",
		"--name",
		CONTAINER,
		"-e",
		"POSTGRES_USER=harness",
		"-e",
		"POSTGRES_PASSWORD=harness",
		"-e",
		"POSTGRES_DB=harness",
		"-p",
		"55433:5432",
		"postgres:16",
	]);
	if (up.status !== 0) {
		console.error("[test:pg] impossibile avviare il container:", up.stderr);
		process.exit(1);
	}
	try {
		// Attende che Postgres accetti connessioni.
		let ready = false;
		for (let i = 0; i < 60; i++) {
			const r = docker(["exec", CONTAINER, "pg_isready", "-U", "harness"], { stdio: "ignore" });
			if (r.status === 0) {
				ready = true;
				break;
			}
			await new Promise((res) => setTimeout(res, 1000));
		}
		if (!ready) throw new Error("Postgres non è diventato pronto in tempo");
		console.log(`[test:pg] Postgres pronto su ${URL}`);
		const code = await run("npm", ["test"], { env: { ...process.env, HARNESS_TEST_PG_URL: URL } });
		process.exitCode = code;
	} finally {
		console.log("[test:pg] smonto il container…");
		docker(["rm", "-f", CONTAINER], { stdio: "ignore" });
	}
}

main().catch((error) => {
	console.error(error);
	docker(["rm", "-f", CONTAINER], { stdio: "ignore" });
	process.exit(1);
});
