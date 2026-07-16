import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { parseInvocation, positionalPrompt } from "../cli-args.js";
import { LlmClient, LlmError } from "../llm.js";
import { bashTool, buildBashEnv } from "../tools/bash-tool.js";
import { editFileTool, writeFileTool } from "../tools/fs-tools.js";
import type { LlmRequest } from "../types.js";

let dir: string;
beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "harness-review-"));
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

// ---- A2: env ridotto per bash ----------------------------------------------

test("A2 buildBashEnv: allowlist include PATH/HOME, esclude i segreti", () => {
	const env = buildBashEnv({ PATH: "/usr/bin", HOME: "/home/x", MY_SECRET_TOKEN: "abc", AWS_SECRET_ACCESS_KEY: "z" });
	assert.equal(env.PATH, "/usr/bin");
	assert.equal(env.HOME, "/home/x");
	assert.equal(env.MY_SECRET_TOKEN, undefined);
	assert.equal(env.AWS_SECRET_ACCESS_KEY, undefined);
});

test("A2 buildBashEnv: passthrough opt-in via HARNESS_BASH_ENV_PASSTHROUGH", () => {
	const env = buildBashEnv({ HARNESS_BASH_ENV_PASSTHROUGH: "FOO, BAR", FOO: "1", BAR: "2", BAZ: "3" });
	assert.equal(env.FOO, "1");
	assert.equal(env.BAR, "2");
	assert.equal(env.BAZ, undefined);
});

test("A2 bash: un segreto nell'env del processo NON è visibile a printenv", async () => {
	process.env.HARNESS_REVIEW_SECRET = "supersegreto-non-esporre";
	try {
		const result = await bashTool.execute({ command: "printenv" }, { cwd: dir });
		assert.equal(result.isError, false);
		assert.doesNotMatch(result.content, /supersegreto-non-esporre/);
	} finally {
		process.env.HARNESS_REVIEW_SECRET = undefined;
	}
});

// ---- A3: retry/backoff ------------------------------------------------------

const req: LlmRequest = { model: "m", maxTokens: 16, messages: [{ role: "user", content: "x" }] };

test("A3 retry: 429 poi 200 → successo (retry trasparente)", async () => {
	let calls = 0;
	const fetchImpl = (async () => {
		calls++;
		if (calls === 1) return new Response("rate", { status: 429, headers: { "retry-after": "0" } });
		return new Response(JSON.stringify({ content: [{ type: "text", text: "ok" }], stop_reason: "end_turn" }), {
			status: 200,
		});
	}) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl, retryBaseMs: 1 });
	const res = await client.complete(req);
	assert.equal(calls, 2);
	assert.equal(res.content[0]?.type, "text");
});

test("A3 retry: 429 persistente → LlmError dopo maxRetries", async () => {
	let calls = 0;
	const fetchImpl = (async () => {
		calls++;
		return new Response("rate", { status: 429 });
	}) as typeof fetch;
	const client = new LlmClient({
		gatewayUrl: "http://gw",
		deviceToken: "dt",
		fetchImpl,
		retryBaseMs: 1,
		maxRetries: 2,
	});
	await assert.rejects(
		() => client.complete(req),
		(e: unknown) => e instanceof LlmError && e.status === 429,
	);
	assert.equal(calls, 3); // 1 iniziale + 2 retry
});

test("A3 retry: 400 NON viene ritentato (errore client)", async () => {
	let calls = 0;
	const fetchImpl = (async () => {
		calls++;
		return new Response(JSON.stringify({ error: { message: "bad" } }), { status: 400 });
	}) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl, retryBaseMs: 1 });
	await assert.rejects(
		() => client.complete(req),
		(e: unknown) => e instanceof LlmError && e.status === 400,
	);
	assert.equal(calls, 1);
});

test("A3 retry: errore di rete transitorio → ritentato", async () => {
	let calls = 0;
	const fetchImpl = (async () => {
		calls++;
		if (calls === 1) throw new TypeError("fetch failed");
		return new Response(JSON.stringify({ content: [], stop_reason: "end_turn" }), { status: 200 });
	}) as typeof fetch;
	const client = new LlmClient({ gatewayUrl: "http://gw", deviceToken: "dt", fetchImpl, retryBaseMs: 1 });
	await client.complete(req);
	assert.equal(calls, 2);
});

// ---- A5: parsing CLI --------------------------------------------------------

test("A5 positionalPrompt: salta i flag e i loro valori (non include l'URL del gateway)", () => {
	assert.equal(positionalPrompt(["--gateway", "http://gw", "fai", "una", "cosa"]), "fai una cosa");
	assert.equal(positionalPrompt(["--model", "m", "-p", "x"]), undefined);
});

test("A5 parseInvocation: `run` è sottocomando, il resto è prompt", () => {
	const inv = parseInvocation(["run", "--gateway", "http://gw", "sistema", "il", "bug"]);
	assert.equal(inv.tools, false);
	assert.equal(inv.forcedRepl, false);
	assert.equal(inv.prompt, "sistema il bug");
});

test("A5 parseInvocation: `repl` forza l'interattivo; `tools` è riconosciuto", () => {
	assert.equal(parseInvocation(["repl"]).forcedRepl, true);
	assert.equal(parseInvocation(["tools"]).tools, true);
	// -p ha precedenza come prompt
	assert.equal(parseInvocation(["-p", "ciao"]).prompt, "ciao");
});

// ---- A6: cleanup del tmp su fallimento del rename ---------------------------

test("A6 write_file: su errore non lascia il file .harness-tmp", async () => {
	// path che punta a una directory inesistente il cui parent è un FILE → mkdir fallisce.
	const filePath = join(dir, "afile");
	writeFileSync(filePath, "sono un file");
	const result = await writeFileTool.execute({ path: join("afile", "sub", "x.txt"), content: "x" }, { cwd: dir });
	assert.equal(result.isError, true);
	assert.equal(existsSync(`${join(dir, "afile", "sub", "x.txt")}.harness-tmp`), false);
});

test("A6 edit_file: modifica normale resta atomica e non lascia tmp", async () => {
	writeFileSync(join(dir, "e.txt"), "alfa");
	const result = await editFileTool.execute({ path: "e.txt", old_string: "alfa", new_string: "beta" }, { cwd: dir });
	assert.equal(result.isError, false);
	assert.equal(readFileSync(join(dir, "e.txt"), "utf8"), "beta");
	assert.equal(existsSync(join(dir, "e.txt.harness-tmp")), false);
});
