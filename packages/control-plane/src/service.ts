import { AuditService } from "./services/audit-service.js";
import { AuthService } from "./services/auth-service.js";
import { type OidcConfig, ServiceContext } from "./services/context.js";
import { DeviceService } from "./services/device-service.js";
import { GroupService } from "./services/group-service.js";
import { OrgService } from "./services/org-service.js";
import { SigningKeyService } from "./services/signing-key-service.js";
import type { Store } from "./store.js";

export type { AdminIdentity, OidcConfig } from "./services/context.js";
export { ServiceError } from "./services/context.js";

/**
 * Punto di composizione del control plane: costruisce il contesto condiviso
 * ({@link ServiceContext}) e i servizi di dominio focalizzati che vi operano
 * sopra — {@link AuthService}, {@link DeviceService}, {@link GroupService},
 * {@link OrgService}, {@link SigningKeyService}, {@link AuditService} — esposti
 * come proprietà (`service.auth`, `service.devices`, …). Nessuna logica vive
 * qui: ogni chiamante usa direttamente il sotto-servizio competente.
 *
 * Tutte le mutazioni passano dai servizi, incrementano la versione di
 * configurazione e finiscono nell'audit amministrativo.
 */
export class ControlPlaneService {
	readonly auth: AuthService;
	readonly devices: DeviceService;
	readonly groups: GroupService;
	readonly org: OrgService;
	readonly signingKeys: SigningKeyService;
	readonly auditLog: AuditService;

	constructor(store: Store, options: { oidc?: OidcConfig } = {}) {
		const ctx = new ServiceContext(store, options.oidc);
		this.auth = new AuthService(ctx);
		this.devices = new DeviceService(ctx);
		this.groups = new GroupService(ctx);
		this.org = new OrgService(ctx);
		this.signingKeys = new SigningKeyService(ctx);
		this.auditLog = new AuditService(ctx);
	}
}
