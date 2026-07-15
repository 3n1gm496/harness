import assert from "node:assert/strict";
import { test } from "node:test";
import { defaultPolicy, resolvePolicy } from "../defaults.js";
import { deepMerge } from "../merge.js";
import { redactSecrets } from "../redaction.js";

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

test("i token della piattaforma harness vengono redatti", () => {
	const input = "device token dvt_AbCdEfGhIjKlMnOpQrStUvWxYz123456 e admin adm_ZyXwVuTsRqPoNmLkJiHgFe987654";
	const result = redactSecrets(input);
	assert.ok(!result.text.includes("dvt_AbCdEfGhIjKlMnOpQrStUvWxYz123456"));
	assert.ok(!result.text.includes("adm_ZyXwVuTsRqPoNmLkJiHgFe987654"));
	assert.ok(result.matches.includes("harness-token"));
});

test("segreti in coppie CHIAVE=VALORE non quotate vengono redatti (cat .env / printenv)", () => {
	const input = [
		"DB_PASSWORD=SuperSecretValue123",
		"export API_KEY=abcdef1234567890ghijk",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY",
		"AUTH_TOKEN=ya29.a0AfB_verylongtokenvalue",
		"github_token: ghijklmnop1234567890",
	].join("\n");
	const result = redactSecrets(input);
	assert.ok(!result.text.includes("SuperSecretValue123"), "password non quotata deve essere redatta");
	assert.ok(!result.text.includes("abcdef1234567890ghijk"), "api key non quotata deve essere redatta");
	assert.ok(!result.text.includes("wJalrXUtnFEMI0K7MDENGbPxRfiCYEXAMPLEKEY"));
	assert.ok(!result.text.includes("ya29.a0AfB_verylongtokenvalue"));
	// La chiave resta visibile (solo il valore è redatto): utile per il debug.
	assert.ok(result.text.includes("DB_PASSWORD="));
	assert.ok(result.matches.includes("generic-assignment-unquoted"));
});

test("assegnazioni innocue non vengono redatte (nessun falso positivo)", () => {
	const input = ["PATH=/usr/local/bin:/usr/bin", "NODE_ENV=production", "AUTHORS=Mario Rossi", "TOKENS=42"].join("\n");
	const result = redactSecrets(input);
	assert.equal(result.text, input, "assegnazioni non sensibili devono restare invariate");
	assert.ok(!result.matches.includes("generic-assignment-unquoted"));
});

test("deepMerge non attraversa __proto__ (prototype pollution)", () => {
	const malicious = JSON.parse('{"__proto__": {"polluted": true}, "constructor": {"x": 1}, "safe": 2}') as object;
	const merged = deepMerge({ a: 1 }, malicious) as Record<string, unknown>;
	assert.equal(merged.safe, 2);
	assert.equal(Object.getPrototypeOf(merged), Object.prototype);
	assert.equal((merged as { polluted?: boolean }).polluted, undefined);
	assert.equal(({} as { polluted?: boolean }).polluted, undefined);
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
