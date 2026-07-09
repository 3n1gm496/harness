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

export interface PolicyDocument {
	version: 1;
	/** Se true, ogni tool call è bloccata e l'agente è di fatto fermo. */
	killSwitch: boolean;
	tools: ToolsPolicy;
	bash: BashPolicy;
	paths: PathsPolicy;
	redaction: RedactionPolicy;
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
