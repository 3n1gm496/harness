import assert from "node:assert/strict";
import { test } from "node:test";
import { redactSecrets } from "../redaction.js";
import { deepMerge } from "../merge.js";
import { defaultPolicy, resolvePolicy } from "../defaults.js";

test("chiavi AWS e GitHub vengono redatte", () => {
	const input = "key AKIAIOSFODNN7EXAMPLE e token ghp_abcdefghijklmnopqrstuvwxyz1234";
	const result = redactSecrets(input);
	assert.ok(!result.text.includes("AKIAIOSFODNN7EXAMPLE"));
	assert.ok(!result.text.includes("ghp_abcdefghijklmnopqrstuvwxyz1234"));
	assert.ok(result.matches.includes("aws-access-key"));
	assert.ok(result.matches.includes("github-token"));
});

test("blocchi di chiavi private vengono redatti", () => {
	const input = "-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----";
	const result = redactSecrets(input);
	assert.ok(!result.text.includes("abc"));
	assert.ok(result.matches.includes("private-key-block"));
});

test("testo senza segreti resta invariato", () => {
	const input = "normale output di build, nessun segreto qui";
	const result = redactSecrets(input);
	assert.equal(result.text, input);
	assert.equal(result.matches.length, 0);
});

test("pattern custom vengono applicati", () => {
	const result = redactSecrets("codice-interno-XYZ-9999", ["codice-interno-[A-Z]+-\\d+"]);
	assert.ok(!result.text.includes("XYZ-9999"));
});

test("pattern custom malformati vengono ignorati", () => {
	const result = redactSecrets("testo", ["[malformata"]);
	assert.equal(result.text, "testo");
});

test("deepMerge sostituisce gli array invece di concatenarli", () => {
	const merged = deepMerge({ a: { list: [1, 2, 3], keep: true } }, { a: { list: [9] } });
	assert.deepEqual(merged.a.list, [9]);
	assert.equal(merged.a.keep, true);
});

test("resolvePolicy applica gli override in ordine", () => {
	const policy = resolvePolicy({ killSwitch: true }, { killSwitch: false, bash: { mode: "deny-all" } });
	assert.equal(policy.killSwitch, false);
	assert.equal(policy.bash.mode, "deny-all");
	// I campi non toccati restano quelli di default.
	assert.equal(policy.tools.defaultAction, defaultPolicy().tools.defaultAction);
});
