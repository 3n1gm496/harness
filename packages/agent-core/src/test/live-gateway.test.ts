import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { FleetState } from "@harness/enforcement-core";
import type { PolicyDocument } from "@harness/shared";
import { createEnforcedAgent } from "../factory.js";
import { LlmClient } from "../llm.js";

/**
 * Verifica end-to-end su HTTP reale (loopback): un server finge il gateway
 * `/anthropic/v1/messages` e risponde in streaming SSE. Esercita il percorso di
 * rete completo — header di auth, body, parsing SSE — non solo un fetch
 * iniettato. Dimostra che l'agente nativo guida davvero un compito: legge un
 * file e lo modifica, il tutto sotto enforcement.
 */

function testPolicy(): PolicyDocument {
	return {
		version: 1,
		killSwitch: false,
		tools: { defaultAction: "allow", allow: [], deny: [] },
		bash: { mode: "denylist", allow: [], deny: [], allowSubstitution: false },
		paths: { workspaceOnly: true, deny: [], allow: [] },
		redaction: { enabled: true, patterns: [] },
		sandbox: { required: false, markerPath: "/x", markerValue: "" },
	};
}

function stateWith(policy: PolicyDocument): FleetState {
	const state = new FleetState(
		{ controlPlaneUrl: "http://cp", deviceId: "d", deviceToken: "dt", publicKeyPem: "p", publicKeyPems: ["p"] },
		join(tmpdir(), "harness-live-config.json"),
	);
	state.setPolicyForTesting(policy);
	return state;
}

/** Serializza un evento SSE. */
function sse(event: object): string {
	return `event: ${(event as { type: string }).type}\ndata: ${JSON.stringify(event)}\n\n`;
}

/** Stream SSE: un blocco tool_use `edit_file`. */
function toolUseStream(id: string, name: string, input: object): string {
	return [
		sse({ type: "message_start", message: { model: "m", usage: { input_tokens: 4, output_tokens: 0 } } }),
		sse({ type: "content_block_start", index: 0, content_block: { type: "tool_use", id, name } }),
		sse({
			type: "content_block_delta",
			index: 0,
			delta: { type: "input_json_delta", partial_json: JSON.stringify(input) },
		}),
		sse({ type: "content_block_stop", index: 0 }),
		sse({ type: "message_delta", delta: { stop_reason: "tool_use" }, usage: { output_tokens: 10 } }),
		sse({ type: "message_stop" }),
	].join("");
}

/** Stream SSE: testo finale. */
function textStream(text: string): string {
	return [
		sse({ type: "message_start", message: { model: "m", usage: { input_tokens: 6, output_tokens: 0 } } }),
		sse({ type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }),
		sse({ type: "content_block_delta", index: 0, delta: { type: "text_delta", text } }),
		sse({ type: "content_block_stop", index: 0 }),
		sse({ type: "message_delta", delta: { stop_reason: "end_turn" }, usage: { output_tokens: 8 } }),
		sse({ type: "message_stop" }),
	].join("");
}

let server: Server;
let baseUrl: string;
let dir: string;
let calls: number;
let seenApiKey: string | undefined;

beforeEach(async () => {
	dir = mkdtempSync(join(tmpdir(), "harness-live-"));
	calls = 0;
	server = createServer((req, res) => {
		assert.equal(req.url, "/anthropic/v1/messages");
		seenApiKey = typeof req.headers["x-api-key"] === "string" ? req.headers["x-api-key"] : undefined;
		// Consuma il body (necessario per non lasciare la connessione appesa).
		req.on("data", () => {});
		req.on("end", () => {
			res.writeHead(200, { "content-type": "text/event-stream" });
			// Primo giro: chiedi edit_file. Secondo: testo finale.
			if (calls === 0) {
				res.end(toolUseStream("tu1", "edit_file", { path: "code.txt", old_string: "vecchio", new_string: "nuovo" }));
			} else {
				res.end(textStream("Fatto: ho sostituito vecchio con nuovo."));
			}
			calls++;
		});
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
	rmSync(dir, { recursive: true, force: true });
	await new Promise<void>((resolve) => server.close(() => resolve()));
});

test("end-to-end HTTP: l'agente legge lo stream, esegue edit_file sotto enforcement e conclude", async () => {
	writeFileSync(join(dir, "code.txt"), "questo è il vecchio contenuto");
	const llm = new LlmClient({ gatewayUrl: baseUrl, deviceToken: "device-secret" });
	const streamed: string[] = [];
	const agent = createEnforcedAgent(stateWith(testPolicy()), {
		llm,
		model: "m",
		cwd: dir,
		stream: true,
		onText: (t) => streamed.push(t),
	});

	const result = await agent.run("Sostituisci vecchio con nuovo in code.txt");

	// Il device token è arrivato come x-api-key (mai le credenziali del provider).
	assert.equal(seenApiKey, "device-secret");
	// Il file è stato effettivamente modificato dal tool nativo.
	assert.equal(readFileSync(join(dir, "code.txt"), "utf8"), "questo è il nuovo contenuto");
	// Il testo finale è stato consegnato in streaming.
	assert.match(streamed.join(""), /Fatto/);
	assert.match(result.text, /Fatto/);
	assert.equal(result.iterations, 2);
});
