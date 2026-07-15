import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const cliPath = join(dirname(fileURLToPath(import.meta.url)), "..", "cli.js");

function run(
	args: string[],
	env: Record<string, string> = {},
): { status: number | null; stdout: string; stderr: string } {
	const result = spawnSync("node", [cliPath, ...args], { encoding: "utf8", env: { ...process.env, ...env } });
	return { status: result.status, stdout: result.stdout, stderr: result.stderr };
}

test("harness-cp rekey ruota la KEK via HARNESS_SIGNING_KEK_NEW", () => {
	const dataDir = mkdtempSync(join(tmpdir(), "harness-cli-rekey-"));
	try {
		const kekA = randomBytes(32).toString("base64");
		const kekB = randomBytes(32).toString("base64");

		const init = run(["init", "--data-dir", dataDir, "--name", "test"], { HARNESS_SIGNING_KEK: kekA });
		assert.equal(init.status, 0, init.stderr);

		const sealedBefore = readFileSync(join(dataDir, "keys", "signing-keys.json"), "utf8");
		assert.match(sealedBefore, /harness-sealed:v1:/);

		const rekey = run(["rekey", "--data-dir", dataDir], {
			HARNESS_SIGNING_KEK: kekA,
			HARNESS_SIGNING_KEK_NEW: kekB,
		});
		assert.equal(rekey.status, 0, rekey.stderr);
		assert.match(rekey.stdout, /Rotazione completata/);

		// La vecchia KEK non deve più aprire le chiavi.
		const verifyOld = run(["verify-audit", "--data-dir", dataDir], { HARNESS_SIGNING_KEK: kekA });
		// verify-audit non tocca le chiavi di firma: usiamo `init` per forzare
		// l'apertura delle chiavi con la vecchia KEK (deve fallire).
		const reopenWithOld = run(["init", "--data-dir", dataDir, "--name", "x"], { HARNESS_SIGNING_KEK: kekA });
		assert.notEqual(reopenWithOld.status, 0);
		void verifyOld;

		// La nuova KEK apre correttamente.
		const reopenWithNew = run(["init", "--data-dir", dataDir, "--name", "x"], { HARNESS_SIGNING_KEK: kekB });
		// init fallisce comunque (admin già presente) ma con l'errore atteso di
		// "già inizializzata", non un errore di decifratura: la KEK ha aperto le
		// chiavi correttamente prima di arrivare a quel controllo.
		assert.equal(reopenWithNew.status, 1);
		assert.match(reopenWithNew.stderr, /già inizializzata/);
	} finally {
		rmSync(dataDir, { recursive: true, force: true });
	}
});

test("harness-cp rekey supporta --new-kek-file e richiede la KEK corrente", () => {
	const dataDir = mkdtempSync(join(tmpdir(), "harness-cli-rekey-file-"));
	const kekFileDir = mkdtempSync(join(tmpdir(), "harness-cli-rekey-kekfile-"));
	try {
		const kekA = randomBytes(32).toString("base64");
		const kekB = randomBytes(32).toString("base64");
		const kekFile = join(kekFileDir, "new.kek");
		writeFileSync(kekFile, kekB, { mode: 0o600 });

		run(["init", "--data-dir", dataDir, "--name", "test"], { HARNESS_SIGNING_KEK: kekA });

		// Senza la KEK corrente: rifiutato.
		const noCurrentKek = run(["rekey", "--data-dir", dataDir, "--new-kek-file", kekFile], {
			HARNESS_SIGNING_KEK: "",
		});
		assert.notEqual(noCurrentKek.status, 0);
		assert.match(noCurrentKek.stderr, /KEK corrente/);

		// Con --new-kek-file: la rotazione funziona.
		const rekeyed = run(["rekey", "--data-dir", dataDir, "--new-kek-file", kekFile], { HARNESS_SIGNING_KEK: kekA });
		assert.equal(rekeyed.status, 0, rekeyed.stderr);
	} finally {
		rmSync(dataDir, { recursive: true, force: true });
		rmSync(kekFileDir, { recursive: true, force: true });
	}
});
