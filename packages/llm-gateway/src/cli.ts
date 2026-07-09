#!/usr/bin/env node
import { createGatewayServer, type GatewayOptions } from "./gateway.js";

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

	const options: GatewayOptions = { controlPlaneUrl, gatewayToken, providers };
	if (process.env.RATE_LIMIT_PER_MINUTE) {
		options.rateLimitPerMinute = Number(process.env.RATE_LIMIT_PER_MINUTE);
	}

	const port = Number(process.env.PORT ?? "8788");
	const server = createGatewayServer(options);
	server.listen(port, () => {
		console.log(`[llm-gateway] in ascolto su http://localhost:${port}`);
	});
	const shutdown = () => server.close(() => process.exit(0));
	process.on("SIGINT", shutdown);
	process.on("SIGTERM", shutdown);
}

main();
