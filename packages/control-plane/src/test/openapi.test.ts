import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { test } from "node:test";
import { generateOpenApiDocument } from "../openapi.js";
import { buildRoutes } from "../routes.js";

test("l'OpenAPI generato è JSON valido ed elenca ogni route non-raw della tabella", () => {
	const doc = generateOpenApiDocument();
	// JSON valido: deve sopravvivere a un roundtrip di serializzazione.
	const roundtripped = JSON.parse(JSON.stringify(doc));
	assert.equal(roundtripped.openapi, "3.0.3");
	assert.equal(typeof roundtripped.info.title, "string");

	const routes = buildRoutes().filter((r) => !r.raw);
	for (const route of routes) {
		const openApiPath = route.path.replace(/:([A-Za-z_]+)/g, "{$1}");
		const pathItem = doc.paths[openApiPath];
		assert.ok(pathItem, `path mancante nello spec: ${openApiPath}`);
		const operation = pathItem[route.method.toLowerCase()];
		assert.ok(operation, `operazione mancante: ${route.method} ${openApiPath}`);
		assert.equal(typeof operation.summary, "string");
		assert.ok(operation.summary.length > 0);
		assert.ok(operation.responses["200"], `manca la risposta 200 per ${route.method} ${openApiPath}`);
		// Le route autenticate documentano anche gli esiti di errore, così il
		// contratto pubblicato non promette solo il caso felice.
		if (route.auth !== "none") {
			assert.ok(operation.responses["401"], `manca la risposta 401 per ${route.method} ${openApiPath}`);
			assert.ok(operation.responses["403"], `manca la risposta 403 per ${route.method} ${openApiPath}`);
		}

		// Ogni parametro `:id` del path dichiarativo deve comparire come parametro path richiesto.
		const paramNames = [...route.path.matchAll(/:([A-Za-z_]+)/g)].map((m) => m[1]);
		for (const name of paramNames) {
			const declared = (operation.parameters ?? []).find((p: { name: string }) => p.name === name);
			assert.ok(declared, `parametro path non dichiarato: ${name} in ${route.method} ${openApiPath}`);
			assert.equal(declared.in, "path");
			assert.equal(declared.required, true);
		}

		// Lo schema di sicurezza dichiarato deve esistere in components.securitySchemes.
		if (route.auth !== "none") {
			assert.ok(
				operation.security,
				`manca il requisito di sicurezza per ${route.method} ${openApiPath} (auth: ${route.auth})`,
			);
			const schemeName = Object.keys(operation.security[0])[0] as string;
			assert.ok(doc.components.securitySchemes[schemeName], `schema di sicurezza non dichiarato: ${schemeName}`);
		} else {
			assert.equal(operation.security, undefined);
		}
	}

	// Endpoint documentati a mano (fuori dalla tabella di route).
	assert.ok(doc.paths["/metrics"]?.get);
	assert.ok(doc.paths["/readyz"]?.get);

	// Le tre modalità di autenticazione mappano su schemi distinti (non intercambiabili).
	assert.deepEqual(Object.keys(doc.components.securitySchemes).sort(), ["adminAuth", "deviceAuth", "gatewayAuth"]);
});

test("GET /api/openapi.json risponde con lo stesso documento generato, senza autenticazione", async () => {
	const { mkdtempSync, rmSync } = await import("node:fs");
	const { tmpdir } = await import("node:os");
	const { join } = await import("node:path");
	const { Store } = await import("../store.js");
	const { ControlPlaneService } = await import("../service.js");
	const { createControlPlaneServer } = await import("../server.js");

	const dir = mkdtempSync(join(tmpdir(), "harness-openapi-"));
	const store = new Store(dir);
	const service = new ControlPlaneService(store);
	const server = createControlPlaneServer(service, { readiness: () => store.checkReady() });
	try {
		await new Promise<void>((resolve) => server.listen(0, resolve));
		const port = (server.address() as AddressInfo).port;
		const response = await fetch(`http://127.0.0.1:${port}/api/openapi.json`);
		assert.equal(response.status, 200);
		const body = (await response.json()) as { openapi: string; paths: Record<string, unknown> };
		assert.equal(body.openapi, "3.0.3");
		assert.ok(body.paths["/api/enroll"]);
	} finally {
		await new Promise((resolve) => server.close(resolve));
		rmSync(dir, { recursive: true, force: true });
	}
});
