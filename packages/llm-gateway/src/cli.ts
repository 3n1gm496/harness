#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { createLogger, installProcessGuards } from "@harness/shared";
import { createGatewayServer, type GatewayOptions, type ProviderCredential } from "./gateway.js";
import { type GatewayRateLimiter, PostgresGatewayRateLimiter } from "./rate-limit.js";

/**
 * Avvio del gateway LLM. Configurazione via variabili d'ambiente:
 *
 *   PORT                     porta di ascolto (default 8788)
 *   CONTROL_PLANE_URL        URL del control plane (obbligatoria)
 *   GATEWAY_TOKEN            token gateway emesso dal control plane (obbligatoria)
 *
 *   Credenziali provider — almeno una fonte per provider. In alternativa alla
 *   API key metered si può usare un token di account/sessione (OAuth):
 *   ANTHROPIC_API_KEY        chiave API Anthropic (fatturata a token)
 *   ANTHROPIC_AUTH_TOKEN     token OAuth/sessione Anthropic (Authorization: Bearer)
 *   ANTHROPIC_AUTH_TOKEN_FILE percorso da cui rileggere il token a ogni richiesta
 *   ANTHROPIC_AUTH_BETA      header anthropic-beta richiesto dal flusso OAuth (opz.)
 *   ANTHROPIC_BASE_URL       default https://api.anthropic.com
 *   OPENAI_API_KEY / OPENAI_AUTH_TOKEN / OPENAI_AUTH_TOKEN_FILE / OPENAI_BASE_URL
 *
 *   RATE_LIMIT_PER_MINUTE    richieste/minuto per device (default 60)
 *   UPSTREAM_TIMEOUT_MS      timeout della chiamata upstream in ms (default 120000)
 */
/**
 * Costruisce la credenziale di un provider dalle variabili d'ambiente
 * `${PREFIX}_API_KEY` / `_AUTH_TOKEN` / `_AUTH_TOKEN_FILE` / `_AUTH_BETA` /
 * `_BASE_URL`. Restituisce undefined se nessuna fonte di credenziale è presente.
 */
function buildProvider(prefix: string, defaultBaseUrl: string): ProviderCredential | undefined {
	const apiKey = process.env[`${prefix}_API_KEY`];
	const authToken = process.env[`${prefix}_AUTH_TOKEN`];
	const authTokenFile = process.env[`${prefix}_AUTH_TOKEN_FILE`];
	const noAuth = isTruthy(process.env[`${prefix}_NO_AUTH`]);
	// Keyless (modello locale/self-hosted) richiede solo un baseUrl esplicito.
	if (noAuth) {
		const baseUrl = process.env[`${prefix}_BASE_URL`];
		if (!baseUrl) {
			console.error(`${prefix}_NO_AUTH richiede ${prefix}_BASE_URL (es. un backend locale OpenAI-compatibile)`);
			process.exit(2);
		}
		return { baseUrl, noAuth: true };
	}
	if (!apiKey && !authToken && !authTokenFile) return undefined;
	const provider: ProviderCredential = { baseUrl: process.env[`${prefix}_BASE_URL`] ?? defaultBaseUrl };
	if (apiKey) provider.apiKey = apiKey;
	if (authToken) provider.authToken = authToken;
	if (authTokenFile) provider.authTokenFile = authTokenFile;
	const beta = process.env[`${prefix}_AUTH_BETA`];
	if (beta) provider.betaHeader = beta;
	return provider;
}

function isTruthy(value: string | undefined): boolean {
	return value === "1" || value === "true" || value === "yes";
}

function main(): void {
	const controlPlaneUrl = process.env.CONTROL_PLANE_URL;
	const gatewayToken = process.env.GATEWAY_TOKEN;
	if (!controlPlaneUrl || !gatewayToken) {
		console.error("CONTROL_PLANE_URL e GATEWAY_TOKEN sono obbligatorie");
		process.exit(2);
	}

	const providers: GatewayOptions["providers"] = {};
	const anthropic = buildProvider("ANTHROPIC", "https://api.anthropic.com");
	if (anthropic) providers.anthropic = anthropic;
	const openai = buildProvider("OPENAI", "https://api.openai.com");
	if (openai) providers.openai = openai;
	if (!providers.anthropic && !providers.openai) {
		console.error(
			"nessun provider configurato: impostare almeno una credenziale " +
				"(ANTHROPIC_API_KEY/ANTHROPIC_AUTH_TOKEN/ANTHROPIC_AUTH_TOKEN_FILE o l'equivalente OPENAI_*)",
		);
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
