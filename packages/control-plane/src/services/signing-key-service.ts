import { type AdminIdentity, requireRole, type ServiceContext, ServiceError } from "./context.js";

/**
 * Rotazione della chiave di firma in tre fasi, senza re-enrollment:
 *   add     → nuova chiave fidata ma non ancora firmante; viaggia nei bundle
 *             (`trustedPublicKeys`) firmati dalla chiave attuale, i device la apprendono
 *   promote → la nuova chiave diventa firmante (i device la fidano già)
 *   retire  → la vecchia chiave esce dal set fidato
 */
export class SigningKeyService {
	constructor(private readonly ctx: ServiceContext) {}

	listSigningKeys(identity: AdminIdentity): { keyId: string; createdAt: string; active: boolean }[] {
		requireRole(identity, "viewer");
		return this.ctx.store.listSigningKeys();
	}

	addSigningKey(identity: AdminIdentity): { keyId: string } {
		requireRole(identity, "admin");
		const key = this.ctx.store.addSigningKey();
		this.ctx.bumpConfig(); // ridistribuisce i bundle con la nuova chiave elencata
		this.ctx.audit(identity.name, "signing_key_added", { keyId: key.keyId });
		return { keyId: key.keyId };
	}

	promoteSigningKey(identity: AdminIdentity, keyId: string): void {
		requireRole(identity, "admin");
		try {
			this.ctx.store.promoteSigningKey(keyId);
		} catch (error) {
			throw new ServiceError(400, error instanceof Error ? error.message : "promozione chiave fallita");
		}
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "signing_key_promoted", { keyId });
	}

	retireSigningKey(identity: AdminIdentity, keyId: string): void {
		requireRole(identity, "admin");
		try {
			this.ctx.store.retireSigningKey(keyId);
		} catch (error) {
			throw new ServiceError(400, error instanceof Error ? error.message : "ritiro chiave fallito");
		}
		this.ctx.bumpConfig();
		this.ctx.audit(identity.name, "signing_key_retired", { keyId });
	}
}
