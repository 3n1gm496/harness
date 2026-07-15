import type { AdminRole } from "@harness/shared";
import { newSecretToken, verifyJwt } from "@harness/shared";
import type { AdminTokenRecord, DeviceRecord } from "../store.js";
import { hashToken } from "../store.js";
import {
	type AdminIdentity,
	normalizeFingerprint,
	type OidcConfig,
	requireRole,
	type ServiceContext,
	ServiceError,
} from "./context.js";

const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

interface AdminSessionRecord {
	name: string;
	role: AdminRole;
	csrfToken: string;
	expiresAt: number;
}

/**
 * Autenticazione (admin/device/gateway) e ciclo di vita dei token/credenziali:
 * bootstrap, token amministrativi, token gateway, binding e rotazione dei
 * device token, introspezione per il gateway, sessioni della UI.
 */
export class AuthService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

	/**
	 * Sessioni della UI amministrativa (cookie httpOnly al posto del bearer in
	 * `localStorage` — vedi `createAdminSession`). Vivono solo in memoria di
	 * processo, mai su file/PG: sono credenziali derivate ed effimere (TTL 12h,
	 * rinnovabili con un nuovo login), non dati di dominio che richiedono
	 * durabilità o convergenza multi-istanza come device o admin token — dietro
	 * un load balancer senza sticky session basta un nuovo login se si finisce
	 * su un'altra istanza, esattamente come ci si aspetta da una sessione web.
	 */
	private readonly sessions = new Map<string, AdminSessionRecord>();

	authenticateAdmin(token: string | undefined): AdminIdentity {
		if (!token) throw new ServiceError(401, "token amministrativo mancante");
		// I token statici hanno prefisso "adm_"; qualunque altra cosa è trattata
		// come JWT OIDC, se l'OIDC è configurato.
		if (!token.startsWith("adm_") && this.ctx.oidc) {
			return this.authenticateOidc(token);
		}
		const record: AdminTokenRecord | undefined = this.store.state.adminTokens[hashToken(token)];
		if (!record) throw new ServiceError(401, "token amministrativo non valido");
		if (record.expiresAt && Date.parse(record.expiresAt) < Date.now()) {
			throw new ServiceError(401, "token amministrativo scaduto");
		}
		return { name: record.name, role: record.role };
	}

	private authenticateOidc(token: string): AdminIdentity {
		const oidc = this.ctx.oidc as OidcConfig;
		const result = verifyJwt(token, { keys: oidc.keys, issuer: oidc.issuer, audience: oidc.audience });
		if (!result.valid) throw new ServiceError(401, `JWT non valido: ${result.error}`);
		const roleClaim = oidc.roleClaim ?? "harness_role";
		const roleValue = result.claims[roleClaim];
		if (roleValue !== "admin" && roleValue !== "operator" && roleValue !== "viewer") {
			throw new ServiceError(403, `claim "${roleClaim}" assente o non valido nel token`);
		}
		const nameClaim = oidc.nameClaim ?? "email";
		const name =
			(typeof result.claims[nameClaim] === "string" && (result.claims[nameClaim] as string)) ||
			(typeof result.claims.sub === "string" && result.claims.sub) ||
			"oidc-user";
		return { name, role: roleValue };
	}

	/**
	 * Autentica un device via token e, se il device è legato a un certificato
	 * mTLS, verifica che il fingerprint presentato combaci. `presentedFingerprint`
	 * è estratto dal server dal certificato client della connessione TLS.
	 */
	authenticateDevice(token: string | undefined, presentedFingerprint?: string): DeviceRecord {
		if (!token) throw new ServiceError(401, "token device mancante");
		const tokenHash = hashToken(token);
		const device = this.store.deviceByTokenHash(tokenHash);
		if (!device) throw new ServiceError(401, "token device non valido");
		if (device.revoked) throw new ServiceError(403, "device revocato");
		// Scadenza server-side del token: oltre l'età massima va ruotato.
		const maxAgeDays = this.store.state.org.deviceTokenMaxAgeDays ?? 90;
		if (device.tokenIssuedAt) {
			const ageMs = Date.now() - Date.parse(device.tokenIssuedAt);
			if (ageMs > maxAgeDays * 86_400_000) {
				throw new ServiceError(401, "token device scaduto: eseguire la rotazione (harness-agent rotate-token)");
			}
		}
		if (device.certFingerprint) {
			const presented = normalizeFingerprint(presentedFingerprint);
			if (!presented) throw new ServiceError(403, "certificato client mTLS richiesto per questo device");
			if (presented !== device.certFingerprint) {
				throw new ServiceError(403, "il certificato client non corrisponde a quello legato al device");
			}
		}
		return device;
	}

	/**
	 * Lega (o ri-lega) il device al certificato client presentato — trust on
	 * first use: da qui in poi le sue richieste richiedono quel certificato.
	 */
	bindDeviceCertificate(device: DeviceRecord, presentedFingerprint: string | undefined): void {
		if (!device.certFingerprint) {
			// Nessun certificato ancora legato: è un trust-on-first-use, per
			// natura vulnerabile a un token rubato usato prima del device
			// legittimo. requireDeviceCert=true lo vieta sempre (il binding deve
			// avvenire all'enrollment); altrimenti serve l'opt-in esplicito
			// allowCertTofu (default false: TOFU disabilitato out-of-the-box).
			if (this.store.state.org.requireDeviceCert) {
				throw new ServiceError(403, "trust-on-first-use disabilitato: il certificato va legato all'enrollment");
			}
			if (!this.store.state.org.allowCertTofu) {
				throw new ServiceError(
					403,
					"trust-on-first-use disabilitato: abilita org.allowCertTofu per legare un certificato dopo l'enrollment",
				);
			}
		}
		const presented = normalizeFingerprint(presentedFingerprint);
		if (!presented) throw new ServiceError(400, "nessun certificato client presentato da legare");
		device.certFingerprint = presented;
		this.store.save();
		this.ctx.audit("system", "device_cert_bound", { deviceId: device.deviceId });
	}

	authenticateGateway(token: string | undefined): string {
		if (!token) throw new ServiceError(401, "token gateway mancante");
		const record = this.store.state.gatewayTokens[hashToken(token)];
		if (!record) throw new ServiceError(401, "token gateway non valido");
		return record.name;
	}

	/** Crea il primo token admin. Consentito solo finché non ne esiste alcuno. */
	bootstrapAdminToken(name: string): string {
		if (Object.keys(this.store.state.adminTokens).length > 0) {
			throw new ServiceError(409, "bootstrap già eseguito: esiste già un token amministrativo");
		}
		const token = newSecretToken("adm");
		this.store.state.adminTokens[hashToken(token)] = {
			name,
			role: "admin",
			createdAt: new Date().toISOString(),
		};
		this.store.save();
		return token;
	}

	createAdminToken(identity: AdminIdentity, name: string, role: AdminRole, ttlDays = 90): string {
		requireRole(identity, "admin");
		if (!["admin", "operator", "viewer"].includes(role)) throw new ServiceError(400, "ruolo non valido");
		if (ttlDays < 1 || ttlDays > 365) throw new ServiceError(400, "ttlDays deve essere tra 1 e 365");
		const token = newSecretToken("adm");
		this.store.state.adminTokens[hashToken(token)] = {
			name,
			role,
			createdAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + ttlDays * 86_400_000).toISOString(),
		};
		this.store.save();
		this.ctx.audit(identity.name, "admin_token_created", { name, role, ttlDays });
		return token;
	}

	listAdminTokens(
		identity: AdminIdentity,
	): { id: string; name: string; role: AdminRole; createdAt: string; expiresAt?: string }[] {
		requireRole(identity, "admin");
		return Object.entries(this.store.state.adminTokens).map(([hash, record]) => {
			const item: { id: string; name: string; role: AdminRole; createdAt: string; expiresAt?: string } = {
				id: hash.slice(0, 12),
				name: record.name,
				role: record.role,
				createdAt: record.createdAt,
			};
			if (record.expiresAt !== undefined) item.expiresAt = record.expiresAt;
			return item;
		});
	}

	revokeAdminToken(identity: AdminIdentity, id: string): void {
		requireRole(identity, "admin");
		const match = Object.keys(this.store.state.adminTokens).find((hash) => hash.startsWith(id));
		if (!match) throw new ServiceError(404, "token amministrativo non trovato");
		const target = this.store.state.adminTokens[match] as AdminTokenRecord;
		const remainingAdmins = Object.entries(this.store.state.adminTokens).filter(
			([hash, record]) =>
				hash !== match && record.role === "admin" && (!record.expiresAt || Date.parse(record.expiresAt) > Date.now()),
		);
		if (target.role === "admin" && remainingAdmins.length === 0) {
			throw new ServiceError(409, "impossibile revocare l'ultimo token admin attivo");
		}
		delete this.store.state.adminTokens[match];
		this.store.save();
		this.ctx.audit(identity.name, "admin_token_revoked", { id, name: target.name, role: target.role });
	}

	/**
	 * Rimuove i token amministrativi scaduti da tempo (retention: senza questo,
	 * ogni token con TTL scaduto resta per sempre nello stato, anche se
	 * `authenticateAdmin` lo rifiuta già). Va chiamato all'avvio e
	 * periodicamente (vedi `harness-cp prune` e il timer in `cli.ts serve`).
	 */
	pruneExpiredAdminTokens(): number {
		const now = Date.now();
		let pruned = 0;
		for (const [hash, record] of Object.entries(this.store.state.adminTokens)) {
			if (record.expiresAt && Date.parse(record.expiresAt) < now) {
				delete this.store.state.adminTokens[hash];
				pruned += 1;
			}
		}
		if (pruned > 0) this.store.save();
		return pruned;
	}

	createGatewayToken(identity: AdminIdentity, name: string): string {
		requireRole(identity, "admin");
		const token = newSecretToken("gwt");
		this.store.state.gatewayTokens[hashToken(token)] = { name, createdAt: new Date().toISOString() };
		this.store.save();
		this.ctx.audit(identity.name, "gateway_token_created", { name });
		return token;
	}

	/** Rotazione del token di un device autenticato: il vecchio smette subito di valere. */
	rotateDeviceToken(device: DeviceRecord): string {
		const token = newSecretToken("dvt");
		device.tokenHash = hashToken(token);
		device.tokenIssuedAt = new Date().toISOString();
		device.lastSeenAt = new Date().toISOString();
		this.store.save();
		this.ctx.audit("system", "device_token_rotated", { deviceId: device.deviceId });
		return token;
	}

	/**
	 * Login della UI: valida il bearer token amministrativo esistente (statico
	 * o OIDC, stessa `authenticateAdmin` usata da API/CLI) e apre una sessione
	 * server-side. Il chiamante (route di login) mette `sessionId` in un cookie
	 * httpOnly+Secure+SameSite e ritorna `csrfToken` nel body: da qui in poi il
	 * bearer non tocca più il browser (né `localStorage` né altro storage JS).
	 */
	createAdminSession(token: string | undefined): { sessionId: string; csrfToken: string; identity: AdminIdentity } {
		const identity = this.authenticateAdmin(token);
		const sessionId = newSecretToken("ses");
		const csrfToken = newSecretToken("csrf");
		this.sessions.set(hashToken(sessionId), {
			name: identity.name,
			role: identity.role,
			csrfToken,
			expiresAt: Date.now() + SESSION_TTL_MS,
		});
		return { sessionId, csrfToken, identity };
	}

	/**
	 * Verifica "morbida" di una sessione (mai un errore, sempre 200): usata dopo
	 * un reload di pagina, quando il cookie httpOnly può ancora essere valido
	 * ma il CSRF token in memoria JS è andato perso. Deliberatamente non
	 * lancia su sessione assente/scaduta (il caso più comune: prima visita,
	 * nessun cookie) — altrimenti ogni caricamento di pagina produrrebbe un
	 * 401 "atteso" ma comunque loggato dal browser come errore di rete.
	 */
	probeSession(
		sessionId: string | undefined,
	): { authenticated: false } | { authenticated: true; name: string; role: AdminRole; csrfToken: string } {
		if (!sessionId) return { authenticated: false };
		const key = hashToken(sessionId);
		const record = this.sessions.get(key);
		if (!record || record.expiresAt < Date.now()) {
			if (record) this.sessions.delete(key);
			return { authenticated: false };
		}
		return { authenticated: true, name: record.name, role: record.role, csrfToken: record.csrfToken };
	}

	/**
	 * Autentica una richiesta della UI via cookie di sessione. Sulle richieste
	 * mutanti (`requireCsrf`) pretende anche l'header `x-csrf-token`: il cookie
	 * da solo verrebbe comunque allegato dal browser a una richiesta cross-site
	 * (mitigato da SameSite=Strict, ma in profondità), mentre il CSRF token è
	 * noto solo a chi ha già letto la risposta di login/`describeSession` sulla
	 * stessa origine.
	 */
	authenticateSession(
		sessionId: string | undefined,
		csrfToken: string | undefined,
		requireCsrf: boolean,
	): AdminIdentity {
		const record = this.lookupSession(sessionId);
		if (requireCsrf && (!csrfToken || csrfToken !== record.csrfToken)) {
			throw new ServiceError(403, "token CSRF mancante o non valido");
		}
		return { name: record.name, role: record.role };
	}

	private lookupSession(sessionId: string | undefined): AdminSessionRecord {
		if (!sessionId) throw new ServiceError(401, "sessione mancante");
		const key = hashToken(sessionId);
		const record = this.sessions.get(key);
		if (!record) throw new ServiceError(401, "sessione non valida o scaduta");
		if (record.expiresAt < Date.now()) {
			this.sessions.delete(key);
			throw new ServiceError(401, "sessione non valida o scaduta");
		}
		return record;
	}

	/** Logout: invalida la sessione lato server (il cookie va comunque cancellato dal chiamante). */
	destroySession(sessionId: string | undefined): void {
		if (!sessionId) return;
		this.sessions.delete(hashToken(sessionId));
	}

	/** Rimuove le sessioni scadute da tempo (retention in memoria — vedi `pruneExpiredAdminTokens`). */
	pruneExpiredSessions(): number {
		const now = Date.now();
		let pruned = 0;
		for (const [key, record] of this.sessions) {
			if (record.expiresAt < now) {
				this.sessions.delete(key);
				pruned += 1;
			}
		}
		return pruned;
	}

	/** Introspezione dei device token per il gateway LLM. */
	introspectDeviceToken(
		deviceToken: string,
		presentedFingerprint?: string,
	): { active: boolean; deviceId?: string; groupId?: string } {
		const tokenHash = hashToken(deviceToken);
		const device = this.store.deviceByTokenHash(tokenHash);
		if (!device || device.revoked) return { active: false };
		const killSwitch =
			device.killSwitch || this.store.state.org.killSwitch || this.store.state.groups[device.groupId]?.killSwitch;
		if (killSwitch) return { active: false };
		// Se il device è legato a un certificato mTLS, il fingerprint presentato
		// (estratto dal gateway dalla connessione col device) deve combaciare:
		// un token rubato senza la chiave privata non basta per l'inferenza.
		if (device.certFingerprint) {
			const presented = normalizeFingerprint(presentedFingerprint);
			if (!presented || presented !== device.certFingerprint) return { active: false };
		}
		return { active: true, deviceId: device.deviceId, groupId: device.groupId };
	}
}
