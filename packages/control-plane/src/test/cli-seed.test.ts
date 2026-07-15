import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cliPath = join(dirname(fileURLToPath(import.meta.url)), "..", "cli.js");

test("harness-cp seed --out scrive i segreti solo su file (0600), mai su stdout", () => {
	const dataDir = mkdtempSync(join(tmpdir(), "harness-cli-seed-"));
	const outFile = join(dataDir, "seed.json");
	try {
		const result = spawnSync("node", [cliPath, "seed", "--data-dir", dataDir, "--out", outFile], {
			encoding: "utf8",
		});
		assert.equal(result.status, 0, result.stderr);

		// Nessun token in chiaro su stdout: solo un riassunto senza segreti.
		assert.ok(!/adm_|enr_|gwt_/.test(result.stdout), "stdout non deve contenere token");
		assert.match(result.stdout, /Credenziali di seed scritte in/);

		// Il file esiste, ha i permessi corretti e contiene i segreti attesi.
		assert.ok(existsSync(outFile));
		const mode = statSync(outFile).mode & 0o777;
		assert.equal(mode, 0o600);
		const credentials = JSON.parse(readFileSync(outFile, "utf8")) as {
			adminToken: string;
			enrollToken: string;
			gatewayToken: string;
		};
		assert.match(credentials.adminToken, /^adm_/);
		assert.match(credentials.enrollToken, /^enr_/);
		assert.match(credentials.gatewayToken, /^gwt_/);
	} finally {
		rmSync(dataDir, { recursive: true, force: true });
	}
});

test("harness-cp seed senza --out stampa le credenziali su stdout (uso interattivo)", () => {
	const dataDir = mkdtempSync(join(tmpdir(), "harness-cli-seed-stdout-"));
	try {
		const result = spawnSync("node", [cliPath, "seed", "--data-dir", dataDir], { encoding: "utf8" });
		assert.equal(result.status, 0, result.stderr);
		assert.match(result.stdout, /adm_/);
		assert.match(result.stdout, /enr_/);
	} finally {
		rmSync(dataDir, { recursive: true, force: true });
	}
});
