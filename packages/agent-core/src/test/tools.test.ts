import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import {
	bashTool,
	editFileTool,
	globTool,
	grepTool,
	listDirTool,
	readFileTool,
	writeFileTool,
} from "../tools/registry.js";
import { globToRegExp } from "../tools/search-tools.js";
import type { ToolContext } from "../tools/types.js";

let dir: string;
let ctx: ToolContext;

beforeEach(() => {
	dir = mkdtempSync(join(tmpdir(), "harness-tools-"));
	ctx = { cwd: dir };
});
afterEach(() => {
	rmSync(dir, { recursive: true, force: true });
});

test("write_file poi read_file: round-trip con numeri di riga", async () => {
	const w = await writeFileTool.execute({ path: "a/b.txt", content: "uno\ndue\ntre" }, ctx);
	assert.equal(w.isError, false);
	assert.equal(readFileSync(join(dir, "a/b.txt"), "utf8"), "uno\ndue\ntre");
	const r = await readFileTool.execute({ path: "a/b.txt" }, ctx);
	assert.equal(r.isError, false);
	assert.match(r.content, /1\tuno/);
	assert.match(r.content, /3\ttre/);
});

test("read_file: offset e limit selezionano una porzione", async () => {
	writeFileSync(join(dir, "big.txt"), Array.from({ length: 10 }, (_, i) => `riga${i + 1}`).join("\n"));
	const r = await readFileTool.execute({ path: "big.txt", offset: 3, limit: 2 }, ctx);
	assert.match(r.content, /3\triga3/);
	assert.match(r.content, /4\triga4/);
	assert.doesNotMatch(r.content, /riga5/);
	assert.match(r.content, /mostrate righe 3-4 di 10/);
});

test("read_file: file inesistente è un errore, non un'eccezione", async () => {
	const r = await readFileTool.execute({ path: "nope.txt" }, ctx);
	assert.equal(r.isError, true);
	assert.match(r.content, /non trovato/);
});

test("edit_file: sostituzione unica riuscita", async () => {
	writeFileSync(join(dir, "c.txt"), "hello world");
	const e = await editFileTool.execute({ path: "c.txt", old_string: "world", new_string: "harness" }, ctx);
	assert.equal(e.isError, false);
	assert.equal(readFileSync(join(dir, "c.txt"), "utf8"), "hello harness");
});

test("edit_file: old_string non unico senza replace_all è errore", async () => {
	writeFileSync(join(dir, "d.txt"), "x x x");
	const e = await editFileTool.execute({ path: "d.txt", old_string: "x", new_string: "y" }, ctx);
	assert.equal(e.isError, true);
	assert.match(e.content, /compare 3 volte/);
	// con replace_all riesce
	const e2 = await editFileTool.execute({ path: "d.txt", old_string: "x", new_string: "y", replace_all: true }, ctx);
	assert.equal(e2.isError, false);
	assert.equal(readFileSync(join(dir, "d.txt"), "utf8"), "y y y");
});

test("edit_file: old_string assente è errore", async () => {
	writeFileSync(join(dir, "e.txt"), "abc");
	const e = await editFileTool.execute({ path: "e.txt", old_string: "zzz", new_string: "q" }, ctx);
	assert.equal(e.isError, true);
	assert.match(e.content, /non trovato/);
});

test("list_dir: elenca file e directory (marcate con /)", async () => {
	writeFileSync(join(dir, "file.txt"), "x");
	await mkdir(join(dir, "sub"));
	const l = await listDirTool.execute({}, ctx);
	assert.equal(l.isError, false);
	assert.match(l.content, /file\.txt/);
	assert.match(l.content, /sub\//);
});

test("grep: trova le righe corrispondenti col numero", async () => {
	writeFileSync(join(dir, "src.ts"), "const a = 1;\nfunction target() {}\nconst b = 2;");
	const g = await grepTool.execute({ pattern: "function\\s+target" }, ctx);
	assert.equal(g.isError, false);
	assert.match(g.content, /src\.ts:2:function target/);
});

test("grep: filtro glob limita i file cercati", async () => {
	writeFileSync(join(dir, "a.ts"), "needle");
	writeFileSync(join(dir, "b.md"), "needle");
	const g = await grepTool.execute({ pattern: "needle", glob: "*.ts" }, ctx);
	assert.match(g.content, /a\.ts/);
	assert.doesNotMatch(g.content, /b\.md/);
});

test("grep: pattern regex non valido è errore pulito", async () => {
	const g = await grepTool.execute({ pattern: "(" }, ctx);
	assert.equal(g.isError, true);
	assert.match(g.content, /non valido/);
});

test("glob: trova i file per pattern, ignora node_modules", async () => {
	await mkdir(join(dir, "src"));
	writeFileSync(join(dir, "src", "x.ts"), "");
	await mkdir(join(dir, "node_modules"));
	writeFileSync(join(dir, "node_modules", "y.ts"), "");
	const g = await globTool.execute({ pattern: "**/*.ts" }, ctx);
	assert.match(g.content, /src\/x\.ts/);
	assert.doesNotMatch(g.content, /node_modules/);
});

test("globToRegExp: semantica di **, * e ?", () => {
	assert.ok(globToRegExp("src/**/*.ts").test("src/a/b/c.ts"));
	assert.ok(globToRegExp("src/**/*.ts").test("src/c.ts"));
	assert.ok(!globToRegExp("src/*.ts").test("src/a/b.ts"));
	assert.ok(globToRegExp("*.ts").test("deep/nested/file.ts")); // senza '/' → qualunque dir
	assert.ok(globToRegExp("a?c.txt").test("abc.txt"));
	assert.ok(!globToRegExp("a?c.txt").test("a/c.txt"));
});

test("bash: esegue un comando consentito e cattura stdout", async () => {
	const b = await bashTool.execute({ command: "echo harness-ok" }, ctx);
	assert.equal(b.isError, false);
	assert.match(b.content, /harness-ok/);
});

test("bash: exit code non-zero è segnalato come errore", async () => {
	const b = await bashTool.execute({ command: "exit 3" }, ctx);
	assert.equal(b.isError, true);
	assert.match(b.content, /exit code 3/);
});

test("bash: timeout termina il comando e segnala errore", async () => {
	const b = await bashTool.execute({ command: "sleep 30", timeout_ms: 300 }, ctx);
	assert.equal(b.isError, true);
	assert.match(b.content, /timeout/);
});
