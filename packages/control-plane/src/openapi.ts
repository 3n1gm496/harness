import type { AuthMode, RouteDef } from "./http-router.js";
import { buildRoutes } from "./routes.js";

/**
 * Genera una specifica OpenAPI 3.0 dalla tabella di route dichiarativa
 * (`buildRoutes()`): metodo, path (`:id` → `{id}`) e schema di sicurezza sono
 * derivati meccanicamente dalla tabella, quindi non possono disallinearsi
 * dalle route realmente servite. Riepilogo/descrizione per route sono invece
 * curati a mano (nessun estrattore di JSON Schema dai tipi TS in un progetto
 * a zero dipendenze runtime): il documento resta comunque valido e completo
 * anche per una route non ancora arricchita, con uno schema generico.
 */

interface RouteDoc {
	summary: string;
	tags: string[];
	requestBody?: boolean;
}

const AUTH_SECURITY: Record<AuthMode, { name: string; requirement: Record<string, string[]>[] }> = {
	none: { name: "", requirement: [] },
	admin: { name: "adminAuth", requirement: [{ adminAuth: [] }] },
	device: { name: "deviceAuth", requirement: [{ deviceAuth: [] }] },
	gateway: { name: "gatewayAuth", requirement: [{ gatewayAuth: [] }] },
};

/** Documentazione curata per route (`"METODO path-con-:param"` → doc). Non obbligatoria: le route assenti da qui restano comunque nello spec, con un riepilogo generico. */
const ROUTE_DOCS: Record<string, RouteDoc> = {
	"POST /api/enroll": {
		summary: "Arruola un device con un token di enrollment monouso",
		tags: ["device"],
		requestBody: true,
	},
	"GET /api/device/config": {
		summary: "Scarica il bundle di configurazione firmato (Ed25519) per il device autenticato",
		tags: ["device"],
	},
	"POST /api/device/audit": {
		summary: "Ingest di un batch di eventi di audit dal device (firma opzionale del batch)",
		tags: ["device"],
		requestBody: true,
	},
	"POST /api/device/rotate-token": {
		summary: "Ruota il device token: il precedente smette immediatamente di valere",
		tags: ["device"],
	},
	"POST /api/device/bind-cert": {
		summary: "Lega il device al certificato client mTLS presentato (trust-on-first-use, disabilitato di default)",
		tags: ["device"],
	},
	"POST /api/introspect": {
		summary: "Introspezione di un device token per il gateway LLM (attivo/revocato/kill switch)",
		tags: ["gateway"],
		requestBody: true,
	},
	"GET /api/admin/overview": {
		summary: "Organizzazione e gruppi (con contatori device); l'elenco device è paginato altrove",
		tags: ["admin"],
	},
	"GET /api/admin/fleet-summary": {
		summary: "Contatori aggregati di flotta (attivi/stale/sospesi, kill switch, versione config)",
		tags: ["admin"],
	},
	"GET /api/admin/devices": {
		summary: "Elenco device paginato/filtrato/cercabile lato server",
		tags: ["admin"],
	},
	"GET /api/admin/org/config": { summary: "Policy e settings PI a livello di organizzazione", tags: ["admin"] },
	"PUT /api/admin/org": {
		summary: "Aggiorna l'organizzazione (kill switch, policy, allowCertTofu, …)",
		tags: ["admin"],
		requestBody: true,
	},
	"POST /api/admin/groups": { summary: "Crea un gruppo", tags: ["admin"], requestBody: true },
	"PUT /api/admin/groups/{id}": { summary: "Aggiorna un gruppo", tags: ["admin"], requestBody: true },
	"DELETE /api/admin/groups/{id}": { summary: "Elimina un gruppo (deve essere vuoto)", tags: ["admin"] },
	"POST /api/admin/enroll-tokens": {
		summary: "Genera un token di enrollment monouso per un gruppo",
		tags: ["admin"],
		requestBody: true,
	},
	"PUT /api/admin/devices/{id}": {
		summary: "Aggiorna un device (kill switch, revoca, gruppo, policy override)",
		tags: ["admin"],
		requestBody: true,
	},
	"DELETE /api/admin/devices/{id}": {
		summary: "Elimina definitivamente un device (l'audit resta consultabile per stream id)",
		tags: ["admin"],
	},
	"GET /api/admin/devices/{id}/effective-policy": {
		summary: "Policy effettiva di un device, come la applicherebbe il client",
		tags: ["admin"],
	},
	"GET /api/admin/signing-keys": { summary: "Elenca le chiavi di firma (pubbliche, attiva inclusa)", tags: ["admin"] },
	"POST /api/admin/signing-keys": {
		summary: "Fase 1 della rotazione: genera una nuova chiave, non ancora attiva",
		tags: ["admin"],
	},
	"POST /api/admin/signing-keys/{id}/promote": {
		summary: "Fase 2: promuove una chiave ad attiva (firma i nuovi bundle)",
		tags: ["admin"],
	},
	"DELETE /api/admin/signing-keys/{id}": { summary: "Fase 3: ritira una vecchia chiave", tags: ["admin"] },
	"GET /api/admin/audit/verify": {
		summary: "Verifica l'integrità della catena di audit (device o amministrativa)",
		tags: ["admin"],
	},
	"GET /api/admin/audit/anchor": {
		summary: "Esporta un anchor firmato con le teste delle catene di audit (per storage WORM esterno)",
		tags: ["admin"],
	},
	"GET /api/admin/audit": { summary: "Legge gli eventi di audit (device o amministrativo)", tags: ["admin"] },
	"GET /api/admin/admin-tokens": { summary: "Elenca i token amministrativi", tags: ["admin"] },
	"POST /api/admin/admin-tokens": {
		summary: "Crea un token amministrativo con ruolo e TTL",
		tags: ["admin"],
		requestBody: true,
	},
	"DELETE /api/admin/admin-tokens/{id}": {
		summary: "Revoca un token amministrativo (rifiutato se è l'ultimo admin attivo)",
		tags: ["admin"],
	},
	"POST /api/admin/gateway-tokens": {
		summary: "Crea un token per l'autenticazione del gateway LLM",
		tags: ["admin"],
		requestBody: true,
	},
	"GET /healthz": { summary: "Liveness: sempre 200 se il processo risponde", tags: ["osservabilità"] },
};

/** Converte `/api/admin/groups/:id` in `/api/admin/groups/{id}` (sintassi OpenAPI) e ne estrae i nomi dei parametri. */
function toOpenApiPath(path: string): { openApiPath: string; params: string[] } {
	const params: string[] = [];
	const openApiPath = path.replace(/:([A-Za-z_]+)/g, (_match, name: string) => {
		params.push(name);
		return `{${name}}`;
	});
	return { openApiPath, params };
}

// biome-ignore lint/suspicious/noExplicitAny: struttura OpenAPI eterogenea, non vale la pena tipizzarla per intero
type JsonRecord = Record<string, any>;

/** Genera il documento OpenAPI 3.0 completo dalla tabella di route corrente. */
export function generateOpenApiDocument(): JsonRecord {
	const routes: RouteDef[] = buildRoutes();
	const paths: JsonRecord = {};

	for (const route of routes) {
		if (route.raw) continue; // route non-JSON (serve HTML statico): fuori scopo per un'API spec
		const { openApiPath, params } = toOpenApiPath(route.path);
		const key = `${route.method} ${openApiPath}`;
		const doc = ROUTE_DOCS[key];
		const security = AUTH_SECURITY[route.auth];

		const operation: JsonRecord = {
			summary: doc?.summary ?? `${route.method} ${openApiPath}`,
			tags: doc?.tags ?? ["altro"],
			operationId: operationId(route.method, openApiPath),
			responses: {
				"200": { description: "Successo", content: { "application/json": { schema: { type: "object" } } } },
				"400": { description: "Richiesta non valida" },
				"401": { description: "Non autenticato" },
				"403": { description: "Non autorizzato" },
				"404": { description: "Non trovato" },
			},
		};
		if (params.length > 0) {
			operation.parameters = params.map((name) => ({
				name,
				in: "path",
				required: true,
				schema: { type: "string" },
			}));
		}
		if (doc?.requestBody) {
			operation.requestBody = {
				required: true,
				content: { "application/json": { schema: { type: "object" } } },
			};
		}
		if (security.requirement.length > 0) operation.security = security.requirement;

		paths[openApiPath] ??= {};
		paths[openApiPath][route.method.toLowerCase()] = operation;
	}

	// /metrics e /readyz sono gestiti fuori dalla tabella di route (dispatch
	// diretto in server.ts, per non passare dall'autenticazione applicativa):
	// documentati qui a mano, non derivati meccanicamente.
	paths["/metrics"] = {
		get: {
			summary: "Metriche Prometheus (HTTP + flotta): text/plain, formato di esposizione Prometheus",
			tags: ["osservabilità"],
			operationId: "getMetrics",
			responses: { "200": { description: "Successo", content: { "text/plain": { schema: { type: "string" } } } } },
		},
	};
	paths["/readyz"] = {
		get: {
			summary: "Readiness: backend raggiungibile e chiave di firma attiva presente",
			tags: ["osservabilità"],
			operationId: "getReadyz",
			responses: {
				"200": { description: "Pronto", content: { "application/json": { schema: { type: "object" } } } },
				"503": { description: "Non pronto", content: { "application/json": { schema: { type: "object" } } } },
			},
		},
	};

	return {
		openapi: "3.0.3",
		info: {
			title: "Harness Control Plane API",
			version: "0.1.0",
			description:
				"API del control plane: enrollment/config/audit dei device, introspezione per il gateway LLM, " +
				"amministrazione (gruppi, organizzazione, chiavi di firma, token). Generata da routes.ts: " +
				"metodo/path/sicurezza sono meccanici, riepiloghi e request body sono curati.",
		},
		servers: [{ url: "/" }],
		tags: [
			{ name: "device", description: "Endpoint chiamati dal client gestito" },
			{ name: "gateway", description: "Endpoint chiamati dal gateway LLM" },
			{ name: "admin", description: "API amministrative (RBAC: admin/operator/viewer)" },
			{ name: "osservabilità", description: "Liveness/readiness/metriche" },
			{ name: "altro", description: "Route senza documentazione curata" },
		],
		paths,
		components: {
			securitySchemes: {
				adminAuth: {
					type: "http",
					scheme: "bearer",
					description: "Token amministrativo statico (adm_...) o JWT OIDC, se configurato",
				},
				deviceAuth: { type: "http", scheme: "bearer", description: "Device token (dvt_...), emesso all'enrollment" },
				gatewayAuth: { type: "http", scheme: "bearer", description: "Token del gateway LLM (gwt_...)" },
			},
		},
	};
}

function operationId(method: string, openApiPath: string): string {
	const cleaned = openApiPath
		.replace(/[{}]/g, "")
		.split("/")
		.filter(Boolean)
		.map((seg, i) => (i === 0 ? seg : seg.charAt(0).toUpperCase() + seg.slice(1)))
		.join("");
	return `${method.toLowerCase()}${cleaned.charAt(0).toUpperCase()}${cleaned.slice(1)}`;
}
