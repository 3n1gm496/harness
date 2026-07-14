/**
 * Tipi condivisi tra control plane, estensione fleet, gateway e client.
 */

/** Azione di policy per i tool non classificati. */
export type DefaultAction = "allow" | "deny";

export interface ToolsPolicy {
	/** Azione per i tool non presenti né in allow né in deny. Default: deny. */
	defaultAction: DefaultAction;
	/** Tool sempre consentiti (es. "read", "grep"). */
	allow: string[];
	/** Tool sempre negati; vince su allow. */
	deny: string[];
}

export type BashMode = "allowlist" | "denylist" | "deny-all";

export interface BashPolicy {
	/**
	 * allowlist: ogni segmento del comando deve iniziare con un prefisso in `allow`.
	 * denylist: tutto è permesso salvo match con `deny`.
	 * deny-all: il tool bash è bloccato.
	 */
	mode: BashMode;
	/** Prefissi di comando consentiti (match sul primo token o sull'intero prefisso). */
	allow: string[];
	/** Espressioni regolari negate, applicate sempre, in qualunque modalità. */
	deny: string[];
	/** Se false, blocca command substitution ($(...) e backtick) in modalità allowlist. */
	allowSubstitution: boolean;
}

export interface PathsPolicy {
	/** Se true, read/write/edit sono limitati alla workspace (cwd della sessione). */
	workspaceOnly: boolean;
	/** Prefissi di percorso sempre negati (supporta ~). Vince su tutto. */
	deny: string[];
	/** Prefissi esenti da workspaceOnly (supporta ~). */
	allow: string[];
}

export interface RedactionPolicy {
	enabled: boolean;
	/** Regex aggiuntive oltre ai pattern integrati. */
	patterns: string[];
}

export interface SandboxPolicy {
	/**
	 * Se true, l'agente si rifiuta di operare fuori da un ambiente contenuto
	 * sanzionato: verifica la presenza di un file marker scritto solo
	 * dall'immagine container ufficiale. Assente ⇒ fail-closed totale.
	 */
	required: boolean;
	/** Percorso del file marker (default `/run/harness-sandbox`). */
	markerPath: string;
	/**
	 * Valore atteso nel marker. Vuoto = basta l'esistenza del file. Un valore
	 * per-immagine rende più difficile falsificare il marker fuori dal container.
	 */
	markerValue: string;
}

export interface PolicyDocument {
	version: 1;
	/** Se true, ogni tool call è bloccata e l'agente è di fatto fermo. */
	killSwitch: boolean;
	tools: ToolsPolicy;
	bash: BashPolicy;
	paths: PathsPolicy;
	redaction: RedactionPolicy;
	sandbox: SandboxPolicy;
}

/** Bundle di configurazione firmato distribuito dal control plane ai device. */
export interface ConfigBundle {
	schema: "harness/config-bundle@1";
	bundleId: string;
	orgId: string;
	groupId: string;
	deviceId: string;
	configVersion: number;
	issuedAt: string;
	expiresAt: string;
	policy: PolicyDocument;
	/** Sottoinsieme gestito di settings di PI (defaultProvider, defaultModel, ecc.). */
	piSettings: Record<string, unknown>;
	/**
	 * Tutte le chiavi pubbliche di firma attualmente valide. Il client, dopo
	 * aver verificato il bundle con una chiave già fidata, aggiorna il proprio
	 * set pinnato con questo elenco: così una nuova chiave viene distribuita
	 * (cross-firmata dalla vecchia) prima che la vecchia sia ritirata, e la
	 * rotazione avviene senza re-enrollment. Opzionale per retrocompatibilità.
	 */
	trustedPublicKeys?: string[];
}

export type AuditEventType =
	| "policy_decision"
	| "tool_call"
	| "tool_result"
	| "user_bash"
	| "config_applied"
	| "config_error"
	| "agent_start"
	| "agent_stop"
	| "error";

export interface AuditEvent {
	eventId: string;
	deviceId: string;
	timestamp: string;
	type: AuditEventType;
	sessionId?: string;
	data: Record<string, unknown>;
	/**
	 * Provenienza del batch, assegnata dal server all'ingest (mai dal client):
	 * "signed" se il device ha una chiave di firma propria e il batch è stato
	 * verificato; "token-only" se il device non ne ha una (retrocompatibilità)
	 * — in tal caso l'evento è garantito solo dal possesso del device token.
	 */
	provenance?: "signed" | "token-only";
}

/**
 * Anchor di audit firmato: fotografia delle teste delle catene di audit in un
 * istante, firmata dal control plane. Ancorandolo su storage esterno WORM si
 * ottiene non-ripudiabilità: chi verifica in seguito confronta le catene con
 * le teste ancorate e rileva qualunque manomissione, anche da parte di chi ha
 * accesso in scrittura ai file di audit.
 */
export interface AuditAnchor {
	schema: "harness/audit-anchor@1";
	orgId: string;
	generatedAt: string;
	admin: { head: string; entries: number };
	devices: { deviceId: string; head: string; entries: number }[];
}

export type AdminRole = "admin" | "operator" | "viewer";

export interface DeviceInfo {
	deviceId: string;
	name: string;
	groupId: string;
	enrolledAt: string;
	lastSeenAt?: string;
	lastConfigVersion?: number;
	killSwitch: boolean;
	revoked: boolean;
}

export interface GroupInfo {
	groupId: string;
	name: string;
	killSwitch: boolean;
	policyOverride: DeepPartial<PolicyDocument>;
	piSettingsOverride: Record<string, unknown>;
}

export type DeepPartial<T> = T extends (infer U)[]
	? U[]
	: T extends object
		? { [K in keyof T]?: DeepPartial<T[K]> }
		: T;

/** Richiesta di valutazione di una tool call da parte del policy engine. */
export interface ToolCallRequest {
	toolName: string;
	input: Record<string, unknown>;
	/** Directory di lavoro della sessione (workspace). */
	cwd: string;
	/** Home directory per l'espansione di ~ nei prefissi. */
	home?: string;
}

export type PolicyDecision =
	| { action: "allow" }
	| { action: "deny"; reason: string };
