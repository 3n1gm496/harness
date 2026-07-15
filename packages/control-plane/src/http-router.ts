import type { IncomingMessage, ServerResponse } from "node:http";
import type { ControlPlaneService } from "./service.js";
import type { AdminIdentity } from "./services/context.js";
import type { DeviceRecord } from "./store.js";

/** Modalità di autenticazione richiesta da una route, risolta dal dispatcher. */
export type AuthMode = "none" | "admin" | "device" | "gateway";

/** Contesto passato a ogni handler di route. */
export interface RouteContext {
	req: IncomingMessage;
	res: ServerResponse;
	url: URL;
	/** Parametri estratti dal pattern (es. `:id`). */
	params: Record<string, string>;
	bearer: string | undefined;
	/** Fingerprint del certificato client mTLS, se presente. */
	fp: string | undefined;
	service: ControlPlaneService;
	/** Identità admin, popolata quando `auth: "admin"`. */
	identity?: AdminIdentity;
	/** Device autenticato, popolato quando `auth: "device"`. */
	device?: DeviceRecord;
	/** Legge e valida il body JSON (una volta sola). */
	json(): Promise<Record<string, unknown>>;
}

/**
 * Handler di route: ritorna il payload da serializzare come JSON 200. Se la
 * route è `raw`, scrive direttamente su `ctx.res` e ritorna `undefined`.
 */
export type RouteHandler = (ctx: RouteContext) => unknown | Promise<unknown>;

export interface RouteDef {
	method: string;
	/** Pattern con segmenti letterali e parametri `:nome` (es. `/api/admin/groups/:id`). */
	path: string;
	auth: AuthMode;
	handler: RouteHandler;
	/** Se true l'handler scrive direttamente la risposta (es. HTML). */
	raw?: boolean;
}

export interface CompiledRoute {
	def: RouteDef;
	regex: RegExp;
	paramNames: string[];
}

/** Compila un pattern di path in una regex con cattura dei parametri. */
export function compileRoute(def: RouteDef): CompiledRoute {
	const paramNames: string[] = [];
	const segments = def.path.split("/").filter((s) => s.length > 0);
	const parts = segments.map((segment) => {
		if (segment.startsWith(":")) {
			paramNames.push(segment.slice(1));
			return "([^/]+)";
		}
		return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
	});
	const regex = new RegExp(`^/${parts.join("/")}/?$`);
	return { def, regex, paramNames };
}

export function compileRoutes(defs: RouteDef[]): CompiledRoute[] {
	return defs.map(compileRoute);
}

/**
 * Cerca la prima route che combacia per metodo e path, restituendo i parametri
 * decodificati. L'ordine di `routes` conta solo fra pattern che si
 * sovrappongono (qui non accade: i path sono disgiunti).
 */
export function matchRoute(
	routes: CompiledRoute[],
	method: string,
	path: string,
): { route: CompiledRoute; params: Record<string, string> } | undefined {
	for (const route of routes) {
		if (route.def.method !== method) continue;
		const match = route.regex.exec(path);
		if (!match) continue;
		const params: Record<string, string> = {};
		route.paramNames.forEach((name, index) => {
			params[name] = decodeURIComponent(match[index + 1] as string);
		});
		return { route, params };
	}
	return undefined;
}
