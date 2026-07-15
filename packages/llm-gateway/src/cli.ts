#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createLogger, installProcessGuards } from "@harness/shared";
import { createGatewayServer, type GatewayOptions } from "./gateway.js";
import { type GatewayRateLimiter, PostgresGatewayRateLimiter } from "./rate-limit.js";

/**
 * Avvio del gateway LLM. Configurazione via variabili d'ambiente:
 *
 *   PORT                     porta di ascolto (default 8788)
 *   CONTROL_PLANE_URL        URL del control plane (obbligatoria)
 *   GATEWAY_TOKEN            token gateway emesso dal control plane (obbligatoria)
 *   ANTHROPIC_API_KEY        chiave provider Anthropic (opzionale)
 *   ANTHROPIC_BASE_URL       default https://api.anthropic.com
 *   OPENAI_API_KEY           chiave provider OpenAI (opzionale)
 *   OPENAI_BASE_URL          default https://api.openai.com
 *   RATE_LIMIT_PER_MINUTE    richieste/minuto per device (default 60)
 *   UPSTREAM_TIMEOUT_MS      timeout della chiamata upstream in ms (default 120000)
 */
function main(): void {
	const controlPlaneUrl = process.env.CONTROL_PLANE_URL;
	const gatewayToken = process.env.GATEWAY_TOKEN;
	if (!controlPlaneUrl || !gatewayToken) {
		console.error("CONTROL_PLANE_URL e GATEWAY_TOKEN sono obbligatorie");
		process.exit(2);
	}

	const providers: GatewayOptions["providers"] = {};
	if (process.env.ANTHROPIC_API_KEY) {
		providers.anthropic = {
			baseUrl: process.env.ANTHROPIC_BASE_URL ?? "https://api.anthropic.com",
			apiKey: process.env.ANTHROPIC_API_KEY,
		};
	}
	if (process.env.OPENAI_API_KEY) {
		providers.openai = {
			baseUrl: process.env.OPENAI_BASE_URL ?? "https://api.openai.com",
			apiKey: process.env.OPENAI_API_KEY,
		};
	}
	if (!providers.anthropic && !providers.openai) {
		console.error("nessun provider configurato: impostare almeno ANTHROPIC_API_KEY o OPENAI_API_KEY");
		process.exit(2);
	}

	const logger = createLogger("llm-gateway");
	// Ultima linea di difesa: un'eccezione non gestita (es. un errore imprevisto
	// nel percorso di streaming) logga ed esce ≠0 così il supervisore riavvia
	// pulito, invece di lasciare il processo in uno stato indefinito.
	installProcessGuards(logger);
	const options: GatewayOptions = { controlPlaneUrl, gatewayToken, providers, logger };
	if (process.env.RATE_LIMIT_PER_MINUTE) {
		options.rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_MINUTE);
	}
	if (process.env.UPSTREAM_TIMEOUT_MS) {
		options.upstreamTimeoutMs = Number(process.env.UPSTREAM_TIMEOUT_MS);
	}
	// Rate limit condiviso multi-istanza: con DATABASE_URL (lo stesso Postgres del
	// control plane) il conteggio è condiviso tra le istanze del gateway; senza,
	// resta per-istanza (in memoria), documentato come tale.
	let gatewayRateLimiter: GatewayRateLimiter | undefined;
	if (process.env.DATABASE_URL) {
		gatewayRateLimiter = new PostgresGatewayRateLimiter(process.env.DATABASE_URL);
		options.rateLimiter = gatewayRateLimiter;
		logger.info("rate_limit_shared", { backend: "postgres" });
	}
	if (process.env.HARNESS_TLS_CERT_FILE && process.env.HARNESS_TLS_KEY_FILE) {
		options.tls = {
			cert: readFileSync(process.env.HARNESS_TLS_CERT_FILE, "utf8"),
			key: readFileSync(process.env.HARNESS_TLS_KEY_FILE, "utf8"),
		};
	}

	const port = Number(process.env.PORT ?? "8788");
	const server = createGatewayServer(options);
	server.listen(port, () => {
		logger.info("listening", { url: `${options.tls ? "https" : "http"}://localhost:${port}` });
	});
	const shutdown = () => {
		server.close(() => {
			void (gatewayRateLimiter?.close() ?? Promise.resolve()).finally(() => process.exit(0));
		});
	};
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}

main();
