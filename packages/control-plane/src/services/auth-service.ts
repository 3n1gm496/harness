import type { AdminRole } from "@harness/shared";
import { newSecretToken, verifyJwt } from "@harness/shared";
import type { AdminTokenRecord, DeviceRecord } from "../store.js";
import { hashToken } from "../store.js";
import {
	type AdminIdentity,
	type OidcConfig,
	ServiceContext,
	ServiceError,
	normalizeFingerprint,
	requireRole,
} from "./context.js";

/**
 * Autenticazione (admin/device/gateway) e ciclo di vita dei token/credenziali:
 * bootstrap, token amministrativi, token gateway, binding e rotazione dei
 * device token, introspezione per il gateway.
 */
export class AuthService {
	constructor(private readonly ctx: ServiceContext) {}

	private get store() {
		return this.ctx.store;
	}

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
				hash !== match &&
				record.role === "admin" &&
				(!record.expiresAt || Date.parse(record.expiresAt) > Date.now()),
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
