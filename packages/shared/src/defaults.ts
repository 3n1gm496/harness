import { deepMerge } from "./merge.js";
import type { DeepPartial, PolicyDocument } from "./types.js";

/**
 * Policy di base: default-deny sui tool sconosciuti, bash in allowlist con i
 * soli comandi di sviluppo comuni, filesystem limitato alla workspace,
 * redaction attiva. È il punto di partenza su cui il control plane applica
 * gli override di org, gruppo e device.
 */
export function defaultPolicy(): PolicyDocument {
	return {
		version: 1,
		killSwitch: false,
		tools: {
			defaultAction: "deny",
			// Nomi dei tool di PI (read/write/edit/ls) e quelli dell'agente nativo
			// @harness/agent-core (read_file/write_file/edit_file/list_dir/glob):
			// la stessa policy di default governa entrambi gli agenti senza modifiche.
			allow: [
				"read",
				"grep",
				"find",
				"ls",
				"bash",
				"write",
				"edit",
				"read_file",
				"write_file",
				"edit_file",
				"list_dir",
				"glob",
			],
			deny: [],
		},
		bash: {
			mode: "allowlist",
			allow: [
				"ls",
				"cat",
				"head",
				"tail",
				"grep",
				"rg",
				"find",
				"wc",
				"diff",
				"git status",
				"git diff",
				"git log",
				"git show",
				"git add",
				"git commit",
				"git branch",
				"git checkout",
				"npm test",
				"npm run",
				"npm ci",
				"node",
				"npx tsc",
				"pytest",
				"python",
				"make",
				"cargo build",
				"cargo test",
				"go build",
				"go test",
				"mkdir",
				"touch",
				"mv",
				"cp",
				"pwd",
				"echo",
				"which",
				"sed",
				"awk",
				"sort",
				"uniq",
			],
			deny: [
				"\\brm\\s+-[a-z]*r[a-z]*f",
				"\\bsudo\\b",
				"\\bcurl\\b[^|]*\\|\\s*(ba)?sh",
				"\\bwget\\b[^|]*\\|\\s*(ba)?sh",
				"\\bchmod\\s+777\\b",
				"\\bmkfs\\b",
				"\\bdd\\s+if=",
				">\\s*/dev/sd",
				"\\bssh\\b",
				"\\bscp\\b",
				"\\bnc\\b",
				"\\bncat\\b",
				"\\.ssh/",
				"\\.aws/credentials",
				"/etc/shadow",
				"\\bshutdown\\b",
				"\\breboot\\b",
			],
			allowSubstitution: false,
		},
		paths: {
			workspaceOnly: true,
			deny: ["~/.ssh", "~/.aws", "~/.gnupg", "~/.pi/agent/auth.json", "~/.harness", "/etc/shadow", "/etc/sudoers"],
			allow: ["/tmp"],
		},
		redaction: {
			enabled: true,
			patterns: [],
		},
		sandbox: {
			required: true,
			markerPath: "/opt/harness/sandbox-marker",
			markerValue: "",
		},
	};
}

/**
 * Policy fail-closed applicata quando il bundle di configurazione manca, è
 * scaduto o ha firma non valida: blocca tutto.
 */
export function failClosedPolicy(): PolicyDocument {
	const policy = defaultPolicy();
	policy.killSwitch = true;
	policy.tools = { defaultAction: "deny", allow: [], deny: [] };
	policy.bash = { mode: "deny-all", allow: [], deny: [], allowSubstitution: false };
	return policy;
}

/**
 * Settings di PI imposti su ogni client gestito, non sovrascrivibili da org o
 * gruppo: niente trust automatico dei progetti, niente traffico verso pi.dev.
 */
export function lockedPiSettings(): Record<string, unknown> {
	return {
		defaultProjectTrust: "never",
		enableInstallTelemetry: false,
		enableAnalytics: false,
	};
}

/** Applica una catena di override parziali alla policy di base. */
export function resolvePolicy(...overrides: (DeepPartial<PolicyDocument> | undefined)[]): PolicyDocument {
	let policy: PolicyDocument = defaultPolicy();
	for (const override of overrides) {
		if (override) policy = deepMerge(policy, override);
	}
	return policy;
}
