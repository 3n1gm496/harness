// biome-ignore lint/suspicious/noRedundantUseStrict: caricato come <script src> classico (non type="module"), quindi non è già in strict mode di suo — Biome presume un contesto di modulo.
"use strict";
const $ = (id) => document.getElementById(id);
// Niente più bearer token in localStorage (A2): dopo il login la UI si
// autentica con un cookie di sessione httpOnly (mai letto da JS). L'unico
// segreto tenuto lato client è il CSRF token, valido solo insieme al cookie.
let csrfToken = "";
let overview = null;
let savedPolicy = {}; // override attualmente salvato (baseline del diff)
let policyModel = {}; // override in editing
let devPage = 0;
let pending = 0;

// ---- Feedback: barra di caricamento, toast, banner ------------------------
function setBusy(on) {
	pending += on ? 1 : -1;
	const bar = $("loadingBar");
	if (pending > 0) {
		bar.classList.add("active");
		bar.style.width = "70%";
	} else {
		bar.style.width = "100%";
		setTimeout(() => {
			bar.classList.remove("active");
			bar.style.width = "0";
		}, 250);
	}
}
function msg(text, isError) {
	const el = $("msg");
	el.textContent = text;
	el.style.borderColor = isError ? "var(--danger)" : "var(--border)";
	el.style.display = "block";
	setTimeout(() => {
		el.style.display = "none";
	}, 4200);
}
function banner(id, text) {
	const el = $(id);
	if (!el) return;
	if (text) {
		el.textContent = text;
		el.classList.add("show");
	} else {
		el.classList.remove("show");
	}
}
function esc(text) {
	const div = document.createElement("div");
	div.textContent = String(text);
	return div.innerHTML;
}
// Per inserire valori (arbitrari, es. nomi device) dentro un attributo HTML
// generato via innerHTML: esc() basta per testo, non per attributi (le
// virgolette andrebbero comunque escapate per non chiudere l'attributo).
function escAttr(text) {
	return String(text).replace(
		/[&<>"']/g,
		(c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c],
	);
}
function fmtDate(iso) {
	return iso ? new Date(iso).toLocaleString("it-IT") : "mai";
}
function killPill(on) {
	return `<span class="pill ${on ? 'on">ATTIVO' : 'off">spento'}</span>`;
}

async function api(method, path, body) {
	setBusy(true);
	try {
		const headers = { "content-type": "application/json" };
		// Allegato sulle richieste mutanti autenticate via cookie di sessione
		// (il server lo richiede per POST/PUT/DELETE, vedi server.ts); innocuo
		// da inviare anche sulle GET.
		if (csrfToken) headers["x-csrf-token"] = csrfToken;
		const res = await fetch(path, {
			method,
			headers,
			body: body === undefined ? undefined : JSON.stringify(body),
		});
		const data = await res.json().catch(() => ({}));
		if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
		return data;
	} finally {
		setBusy(false);
	}
}

// ---- Dashboard e device: server-side (paginazione, filtro, ricerca, riepilogo) ---
// Tutta la logica di stato/paginazione vive lato server (org-service.ts:
// listDevices/fleetSummary): su una flotta grande la UI non trasferisce più
// l'elenco device completo a ogni refresh.
function groupName(id) {
	return (overview.groups.find((g) => g.groupId === id) || { name: id }).name;
}
function stateLabel(d) {
	if (d.revoked) return '<span class="pill on">revocato</span>';
	if (d.state === "suspended") return '<span class="pill on">sospeso</span>';
	if (d.state === "stale") return '<span class="pill warn">stale</span>';
	return '<span class="pill off">attivo</span>';
}
async function renderDashboard() {
	const summary = await api("GET", "/api/admin/fleet-summary");
	const cards = [
		{ n: summary.total, l: "Device totali" },
		{ n: summary.active, l: "Attivi", cls: "ok" },
		{ n: summary.suspended, l: "Sospesi / revocati", cls: summary.suspended ? "alert" : "" },
		{ n: summary.stale, l: "Stale (rischio fail-closed)", cls: summary.stale ? "warn" : "" },
		{ n: `v${summary.configVersion}`, l: "Versione config" },
		{ n: summary.killSwitch ? "ON" : "off", l: "Kill switch globale", cls: summary.killSwitch ? "alert" : "ok" },
	];
	$("dashboardCards").innerHTML = cards
		.map(
			(c) =>
				`<div class="card ${c.cls || ""}"><div class="num">${esc(c.n)}</div><div class="lbl">${esc(c.l)}</div></div>`,
		)
		.join("");
}
async function renderDevices() {
	const size = Number($("devPageSize").value);
	const q = $("deviceSearch").value.trim();
	const filter = $("deviceFilter").value;
	const params = new URLSearchParams({ offset: String(devPage * size), limit: String(size), filter });
	if (q) params.set("q", q);
	const { devices, total } = await api("GET", `/api/admin/devices?${params.toString()}`);
	const pages = Math.max(1, Math.ceil(total / size));
	if (devPage >= pages) {
		devPage = pages - 1;
		return renderDevices();
	}

	$("devicesBody").innerHTML =
		devices
			.map(
				(d) =>
					"<tr><td>" +
					esc(d.name) +
					"</td>" +
					"<td>" +
					esc(groupName(d.groupId)) +
					"</td>" +
					"<td>" +
					stateLabel(d) +
					"</td>" +
					"<td>" +
					fmtDate(d.lastSeenAt) +
					"</td>" +
					"<td>" +
					(d.lastConfigVersion ?? "—") +
					"</td>" +
					"<td>" +
					killPill(d.killSwitch) +
					"</td>" +
					'<td class="row op-only">' +
					`<button class="secondary" data-action="toggle-kill" data-id="${escAttr(d.deviceId)}" data-current="${d.killSwitch}">${d.killSwitch ? "riattiva" : "sospendi"}</button>` +
					(d.revoked
						? ""
						: `<button class="danger" data-action="revoke-device" data-id="${escAttr(d.deviceId)}">revoca</button>`) +
					` <button class="danger admin-only" data-action="delete-device" data-id="${escAttr(d.deviceId)}" data-name="${escAttr(d.name)}">elimina</button>` +
					"</td></tr>",
			)
			.join("") || '<tr><td colspan="7" class="muted">Nessun device corrisponde ai filtri</td></tr>';
	$("devPageInfo").textContent = total ? `Pagina ${devPage + 1} di ${pages} · ${total} device` : "0 device";
	$("devPrev").disabled = devPage <= 0;
	$("devNext").disabled = devPage >= pages - 1;
}

// ---- Policy: modello, form, validazione, diff ------------------------------
const POLICY_SCHEMA = {
	version: { type: "const", value: 1 },
	killSwitch: { type: "boolean" },
	tools: {
		type: "object",
		fields: {
			defaultAction: { type: "enum", values: ["allow", "deny"] },
			allow: { type: "string[]" },
			deny: { type: "string[]" },
		},
	},
	bash: {
		type: "object",
		fields: {
			mode: { type: "enum", values: ["allowlist", "denylist", "deny-all"] },
			allow: { type: "string[]" },
			deny: { type: "string[]" },
			allowSubstitution: { type: "boolean" },
		},
	},
	paths: {
		type: "object",
		fields: { workspaceOnly: { type: "boolean" }, deny: { type: "string[]" }, allow: { type: "string[]" } },
	},
	redaction: { type: "object", fields: { enabled: { type: "boolean" }, patterns: { type: "string[]" } } },
	sandbox: {
		type: "object",
		fields: { required: { type: "boolean" }, markerPath: { type: "string" }, markerValue: { type: "string" } },
	},
};
function checkType(spec, val, path, errors) {
	if (spec.type === "boolean" && typeof val !== "boolean") errors.push(`${path}: deve essere booleano`);
	else if (spec.type === "string" && typeof val !== "string") errors.push(`${path}: deve essere stringa`);
	else if (spec.type === "const" && val !== spec.value) errors.push(`${path}: deve valere ${spec.value}`);
	else if (spec.type === "enum" && !spec.values.includes(val))
		errors.push(`${path}: deve essere uno di ${spec.values.join(", ")}`);
	else if (spec.type === "string[]") {
		if (!Array.isArray(val) || val.some((x) => typeof x !== "string"))
			errors.push(`${path}: deve essere un array di stringhe`);
	}
}
function validatePolicy(obj) {
	const errors = [],
		warnings = [];
	if (typeof obj !== "object" || obj === null || Array.isArray(obj)) {
		errors.push("La policy deve essere un oggetto JSON");
		return { errors, warnings };
	}
	for (const key of Object.keys(obj)) {
		const spec = POLICY_SCHEMA[key];
		if (!spec) {
			warnings.push(`Chiave sconosciuta "${key}" (possibile refuso: sarà ignorata dal client)`);
			continue;
		}
		if (spec.type === "object") {
			const sub = obj[key];
			if (typeof sub !== "object" || sub === null || Array.isArray(sub)) {
				errors.push(`${key}: deve essere un oggetto`);
				continue;
			}
			for (const sk of Object.keys(sub)) {
				const sspec = spec.fields[sk];
				if (!sspec) {
					warnings.push(`Chiave sconosciuta "${key}.${sk}"`);
					continue;
				}
				checkType(sspec, sub[sk], `${key}.${sk}`, errors);
			}
		} else checkType(spec, obj[key], key, errors);
	}
	return { errors, warnings };
}
function renderValidation(v) {
	const parts = [];
	if (v.errors.length === 0 && v.warnings.length === 0) parts.push('<span class="v-ok">✓ policy valida</span>');
	for (const e of v.errors) parts.push(`<div class="v-err">✗ ${esc(e)}</div>`);
	for (const w of v.warnings) parts.push(`<div class="v-warn">⚠ ${esc(w)}</div>`);
	$("policyValidation").innerHTML = parts.join("");
	$("btnSavePolicy").disabled = v.errors.length > 0;
}
function modelFromForm() {
	const m = {};
	const setBool = (id, path) => {
		const v = $(id).value;
		if (v === "") return;
		set(m, path, v === "true");
	};
	function set(obj, path, val) {
		const p = path.split(".");
		let o = obj;
		for (let i = 0; i < p.length - 1; i++) {
			o[p[i]] = o[p[i]] || {};
			o = o[p[i]];
		}
		o[p[p.length - 1]] = val;
	}
	setBool("pf_kill", "killSwitch");
	setBool("pf_sandbox", "sandbox.required");
	setBool("pf_redaction", "redaction.enabled");
	setBool("pf_workspaceOnly", "paths.workspaceOnly");
	if ($("pf_bashMode").value) set(m, "bash.mode", $("pf_bashMode").value);
	const allow = $("pf_bashAllow")
		.value.split("\n")
		.map((s) => s.trim())
		.filter(Boolean);
	if (allow.length) set(m, "bash.allow", allow);
	return m;
}
function formFromModel() {
	const g = (path) => {
		const p = path.split(".");
		let o = policyModel;
		for (const k of p) {
			if (o == null) return undefined;
			o = o[k];
		}
		return o;
	};
	const setSel = (id, val) => {
		$(id).value = val === true ? "true" : val === false ? "false" : "";
	};
	setSel("pf_kill", g("killSwitch"));
	setSel("pf_sandbox", g("sandbox.required"));
	setSel("pf_redaction", g("redaction.enabled"));
	setSel("pf_workspaceOnly", g("paths.workspaceOnly"));
	$("pf_bashMode").value = g("bash.mode") || "";
	$("pf_bashAllow").value = Array.isArray(g("bash.allow")) ? g("bash.allow").join("\n") : "";
}
function syncFromForm() {
	policyModel = modelFromForm();
	$("orgPolicy").value = JSON.stringify(policyModel, null, 2);
	afterModelChange();
}
function afterModelChange() {
	renderValidation(validatePolicy(policyModel));
	renderDiff();
}
function lineDiff(aStr, bStr) {
	const a = aStr.split("\n"),
		b = bStr.split("\n"),
		n = a.length,
		m = b.length;
	const dp = Array.from({ length: n + 1 }, () => new Array(m + 1).fill(0));
	for (let i = n - 1; i >= 0; i--)
		for (let j = m - 1; j >= 0; j--)
			dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
	const out = [];
	let i = 0,
		j = 0;
	while (i < n && j < m) {
		if (a[i] === b[j]) {
			out.push([" ", a[i]]);
			i++;
			j++;
		} else if (dp[i + 1][j] >= dp[i][j + 1]) {
			out.push(["-", a[i++]]);
		} else {
			out.push(["+", b[j++]]);
		}
	}
	while (i < n) out.push(["-", a[i++]]);
	while (j < m) out.push(["+", b[j++]]);
	return out;
}
function renderDiff() {
	const before = JSON.stringify(savedPolicy, null, 2);
	const after = JSON.stringify(policyModel, null, 2);
	if (before === after) {
		$("diffOut").innerHTML = '<span class="same">nessuna modifica rispetto alla policy salvata</span>';
		return;
	}
	$("diffOut").innerHTML = lineDiff(before, after)
		.map(([t, v]) => {
			const cls = t === "+" ? "add" : t === "-" ? "del" : "same";
			return `<span class="${cls}">${esc(`${t} ${v}`)}</span>`;
		})
		.join("\n");
}
function showPolicyTab(which) {
	$("policyForm").classList.toggle("hidden", which !== "form");
	$("policyJson").classList.toggle("hidden", which !== "json");
	$("policyDiff").classList.toggle("hidden", which !== "diff");
	for (const [id, w] of [
		["tabForm", "form"],
		["tabJson", "json"],
		["tabDiff", "diff"],
	])
		$(id).classList.toggle("active", w === which);
	if (which === "form") formFromModel();
	if (which === "json") $("orgPolicy").value = JSON.stringify(policyModel, null, 2);
	if (which === "diff") renderDiff();
}

// ---- Refresh principale ----------------------------------------------------
async function refresh() {
	overview = await api("GET", "/api/admin/overview");
	$("orgName").textContent = overview.org.name;
	$("configVersion").textContent = `config v${overview.org.configVersion} · ${overview.role}`;

	const canOperate = overview.role === "admin" || overview.role === "operator";
	const canAdmin = overview.role === "admin";
	document.body.classList.toggle("can-operate", canOperate);
	document.body.classList.toggle("can-admin", canAdmin);

	const kill = $("btnGlobalKill");
	kill.hidden = !canOperate;
	kill.textContent = overview.org.killSwitch ? "Disattiva kill switch globale" : "Kill switch globale";
	kill.className = overview.org.killSwitch ? "secondary" : "danger";
	$("btnRefresh").hidden = false;
	$("btnLogout").hidden = false;

	await renderDashboard();
	await renderDevices();

	$("groupsBody").innerHTML = overview.groups
		.map(
			(g) =>
				"<tr><td>" +
				esc(g.name) +
				"</td><td>" +
				g.deviceCount +
				"</td><td>" +
				killPill(g.killSwitch) +
				"</td>" +
				`<td class="op-only"><button class="secondary" data-action="toggle-group-kill" data-id="${escAttr(g.groupId)}" data-current="${g.killSwitch}">${g.killSwitch ? "riattiva" : "sospendi"}</button></td></tr>`,
		)
		.join("");

	$("enrollGroup").innerHTML = overview.groups
		.map((g) => `<option value="${g.groupId}">${esc(g.name)}</option>`)
		.join("");
	// Elenco per la select di audit: capped lato server (200) — su flotte
	// molto grandi va sostituito con una ricerca, non un'unica select.
	const auditDevices = (await api("GET", "/api/admin/devices?limit=200")).devices;
	$("auditDevice").innerHTML =
		'<option value="">— audit amministrativo —</option>' +
		auditDevices.map((d) => `<option value="${d.deviceId}">${esc(d.name)}</option>`).join("");

	for (const id of ["dashboardPanel", "devicesPanel", "groupsPanel", "enrollPanel", "auditPanel"]) $(id).hidden = false;
	$("loginPanel").hidden = true;

	if (canAdmin) {
		const orgConfig = await api("GET", "/api/admin/org/config");
		savedPolicy = orgConfig.policyOverride || {};
		policyModel = JSON.parse(JSON.stringify(savedPolicy));
		$("policyPanel").hidden = false;
		showPolicyTab("form");
		afterModelChange();
		await refreshTokens();
		await refreshSigningKeys();
	} else {
		$("policyPanel").hidden = true;
		$("tokensPanel").hidden = true;
		$("signingPanel").hidden = true;
	}
}

async function refreshSigningKeys() {
	try {
		const data = await api("GET", "/api/admin/signing-keys");
		$("signingBody").innerHTML = data.keys
			.map(
				(k) =>
					"<tr><td><code>" +
					esc(k.keyId) +
					"</code></td><td>" +
					fmtDate(k.createdAt) +
					"</td>" +
					"<td>" +
					(k.active ? '<span class="pill off">attiva (firma)</span>' : '<span class="muted">fidata</span>') +
					"</td>" +
					"<td>" +
					(k.active
						? ""
						: `<button class="secondary" data-action="promote-key" data-id="${escAttr(k.keyId)}">promuovi</button> <button class="danger" data-action="retire-key" data-id="${escAttr(k.keyId)}">ritira</button>`) +
					"</td></tr>",
			)
			.join("");
		$("signingPanel").hidden = false;
	} catch {
		$("signingPanel").hidden = true;
	}
}
async function refreshTokens() {
	const data = await api("GET", "/api/admin/admin-tokens");
	$("tokensBody").innerHTML = data.tokens
		.map(
			(t) =>
				"<tr><td>" +
				esc(t.name) +
				"</td><td>" +
				esc(t.role) +
				"</td><td>" +
				fmtDate(t.createdAt) +
				"</td>" +
				"<td>" +
				(t.expiresAt ? fmtDate(t.expiresAt) : '<span class="muted">mai (bootstrap)</span>') +
				"</td>" +
				`<td><button class="danger" data-action="revoke-token" data-id="${escAttr(t.id)}">revoca</button></td></tr>`,
		)
		.join("");
	$("tokensPanel").hidden = false;
}

// ---- Azioni ------------------------------------------------------------
// Non più globali (window.*): non servono più fuori da questo file, dato
// che l'HTML non le referenzia più da attributi onclick inline (rimossi per
// consentire una CSP script-src 'self' senza 'unsafe-inline' — vedi il
// dispatcher a delega d'eventi più sotto).
async function promoteKey(id) {
	if (!confirm("Promuovere questa chiave ad attiva? I device non sincronizzati andranno fail-closed.")) return;
	try {
		await api("POST", `/api/admin/signing-keys/${id}/promote`);
		await refreshSigningKeys();
		msg("Chiave promossa");
	} catch (e) {
		msg(e.message, true);
	}
}
async function retireKey(id) {
	if (!confirm("Ritirare questa chiave? I bundle firmati con essa non saranno più verificabili.")) return;
	try {
		await api("DELETE", `/api/admin/signing-keys/${id}`);
		await refreshSigningKeys();
		msg("Chiave ritirata");
	} catch (e) {
		msg(e.message, true);
	}
}
async function toggleDeviceKill(id, current) {
	try {
		await api("PUT", `/api/admin/devices/${id}`, { killSwitch: !current });
		await refresh();
		msg("Device aggiornato");
	} catch (e) {
		msg(e.message, true);
	}
}
async function revokeDevice(id) {
	if (!confirm("Revocare definitivamente il device? Il suo token smetterà di funzionare.")) return;
	try {
		await api("PUT", `/api/admin/devices/${id}`, { revoked: true });
		await refresh();
		msg("Device revocato");
	} catch (e) {
		msg(e.message, true);
	}
}
async function deleteDevice(id, name) {
	if (
		!confirm(
			`Eliminare definitivamente il device "${name}"? L'operazione non è reversibile (il suo log di audit resta consultabile separatamente).`,
		)
	)
		return;
	try {
		await api("DELETE", `/api/admin/devices/${id}`);
		await refresh();
		msg("Device eliminato");
	} catch (e) {
		msg(e.message, true);
	}
}
async function toggleGroupKill(id, current) {
	try {
		await api("PUT", `/api/admin/groups/${id}`, { killSwitch: !current });
		await refresh();
		msg("Gruppo aggiornato");
	} catch (e) {
		msg(e.message, true);
	}
}
async function revokeToken(id) {
	if (!confirm("Revocare il token amministrativo? Chi lo usa perderà subito l'accesso.")) return;
	try {
		await api("DELETE", `/api/admin/admin-tokens/${id}`);
		await refreshTokens();
		msg("Token revocato");
	} catch (e) {
		msg(e.message, true);
	}
}

// Dispatcher a delega d'eventi per i bottoni generati dinamicamente nelle
// righe delle tabelle (device/gruppi/chiavi/token): ognuno porta solo
// `data-action`/`data-id`/… invece di un `onclick="..."` inline, così la CSP
// può essere `script-src 'self'` (nessun 'unsafe-inline').
const ROW_ACTIONS = {
	"toggle-kill": (el) => toggleDeviceKill(el.dataset.id, el.dataset.current === "true"),
	"revoke-device": (el) => revokeDevice(el.dataset.id),
	"delete-device": (el) => deleteDevice(el.dataset.id, el.dataset.name),
	"toggle-group-kill": (el) => toggleGroupKill(el.dataset.id, el.dataset.current === "true"),
	"promote-key": (el) => promoteKey(el.dataset.id),
	"retire-key": (el) => retireKey(el.dataset.id),
	"revoke-token": (el) => revokeToken(el.dataset.id),
};
document.addEventListener("click", (event) => {
	const el = event.target.closest("[data-action]");
	if (!el) return;
	const action = ROW_ACTIONS[el.dataset.action];
	if (action) action(el);
});

$("btnGlobalKill").onclick = async () => {
	const target = !overview.org.killSwitch;
	if (target && !confirm("Attivare il kill switch GLOBALE? Tutti gli agenti verranno sospesi.")) return;
	try {
		await api("PUT", "/api/admin/org", { killSwitch: target });
		await refresh();
		msg("Organizzazione aggiornata");
	} catch (e) {
		msg(e.message, true);
	}
};
$("btnRefresh").onclick = () => refresh().catch((e) => msg(e.message, true));
$("btnCreateGroup").onclick = async () => {
	try {
		await api("POST", "/api/admin/groups", { name: $("newGroupName").value });
		$("newGroupName").value = "";
		await refresh();
		msg("Gruppo creato");
	} catch (e) {
		msg(e.message, true);
	}
};
$("btnEnrollToken").onclick = async () => {
	try {
		const data = await api("POST", "/api/admin/enroll-tokens", {
			groupId: $("enrollGroup").value,
			ttlMinutes: Number($("enrollTtl").value),
		});
		$("enrollResult").innerHTML = `Token (monouso, mostralo solo al device): <code>${esc(data.enrollToken)}</code>`;
	} catch (e) {
		msg(e.message, true);
	}
};

$("btnSavePolicy").onclick = async () => {
	const v = validatePolicy(policyModel);
	if (v.errors.length) {
		banner("policyErr", "Correggi gli errori di validazione prima di salvare.");
		return;
	}
	if (v.warnings.length && !confirm("Ci sono avvisi (chiavi sconosciute). Salvare comunque?")) return;
	banner("policyErr", "");
	try {
		await api("PUT", "/api/admin/org", { policyOverride: policyModel });
		await refresh();
		msg("Policy salvata e versionata");
	} catch (e) {
		banner("policyErr", e.message);
		msg(e.message, true);
	}
};
$("btnSyncJson").onclick = () => {
	try {
		policyModel = JSON.parse($("orgPolicy").value || "{}");
		banner("policyErr", "");
		formFromModel();
		afterModelChange();
		msg("JSON sincronizzato");
	} catch (e) {
		banner("policyErr", `JSON non valido: ${e.message}`);
	}
};
for (const pf of ["pf_kill", "pf_sandbox", "pf_redaction", "pf_workspaceOnly", "pf_bashMode", "pf_bashAllow"])
	$(pf).addEventListener("input", syncFromForm);
$("tabForm").onclick = () => showPolicyTab("form");
$("tabJson").onclick = () => showPolicyTab("json");
$("tabDiff").onclick = () => showPolicyTab("diff");

$("btnLoadAudit").onclick = async () => {
	try {
		const deviceId = $("auditDevice").value;
		const data = await api("GET", `/api/admin/audit?limit=100${deviceId ? `&deviceId=${deviceId}` : ""}`);
		$("auditOutput").textContent = data.events.map((e) => JSON.stringify(e)).join("\n") || "nessun evento";
	} catch (e) {
		msg(e.message, true);
	}
};
$("btnVerifyAudit").onclick = async () => {
	try {
		const deviceId = $("auditDevice").value;
		const data = await api("GET", `/api/admin/audit/verify${deviceId ? `?deviceId=${deviceId}` : ""}`);
		$("auditVerdict").innerHTML = data.valid
			? `<span class="pill off">catena integra · ${data.entries} righe</span>`
			: `<span class="pill on">COMPROMESSA alla riga ${data.brokenAtLine}</span>`;
	} catch (e) {
		msg(e.message, true);
	}
};
$("btnCreateToken").onclick = async () => {
	try {
		const data = await api("POST", "/api/admin/admin-tokens", {
			name: $("newTokenName").value,
			role: $("newTokenRole").value,
			ttlDays: Number($("newTokenTtl").value),
		});
		$("newTokenName").value = "";
		$("tokenResult").innerHTML = `Token (mostrato solo ora): <code>${esc(data.token)}</code>`;
		await refreshTokens();
	} catch (e) {
		msg(e.message, true);
	}
};
$("btnAddKey").onclick = async () => {
	try {
		const r = await api("POST", "/api/admin/signing-keys");
		await refreshSigningKeys();
		msg(`Chiave aggiunta: ${r.keyId}`);
	} catch (e) {
		msg(e.message, true);
	}
};

// ---- Sessione: login/logout via cookie httpOnly + CSRF token (A2) ---------
// Il bearer token amministrativo viene inviato UNA SOLA VOLTA, al login: il
// server lo scambia per un cookie httpOnly (mai letto da questo script) e un
// CSRF token, che resta solo in memoria JS (variabile `csrfToken`, non
// persistito). Un XSS può ancora esfiltrare il CSRF token corrente, ma non
// più il bearer token stesso né una credenziale a lunga scadenza.
$("btnLogin").onclick = async () => {
	const value = $("tokenInput").value.trim();
	banner("loginErr", "");
	try {
		const session = await api("POST", "/api/admin/session/login", { token: value });
		csrfToken = session.csrfToken;
		$("tokenInput").value = "";
		await refresh();
	} catch (e) {
		csrfToken = "";
		banner("loginErr", `Accesso fallito: ${e.message}`);
	}
};
$("btnLogout").onclick = async () => {
	try {
		await api("POST", "/api/admin/session/logout");
	} catch {
		/* sessione già scaduta lato server: nessun problema */
	}
	csrfToken = "";
	location.reload();
};

// Device pagination/filter listeners. La ricerca è server-side ora (ogni
// digitazione è una richiesta HTTP): debounce per non martellare il server.
let searchDebounce;
$("deviceSearch").addEventListener("input", () => {
	clearTimeout(searchDebounce);
	searchDebounce = setTimeout(() => {
		devPage = 0;
		renderDevices();
	}, 250);
});
$("deviceFilter").addEventListener("change", () => {
	devPage = 0;
	renderDevices();
});
$("devPageSize").addEventListener("change", () => {
	devPage = 0;
	renderDevices();
});
$("devPrev").onclick = () => {
	devPage--;
	renderDevices();
};
$("devNext").onclick = () => {
	devPage++;
	renderDevices();
};

// Al caricamento: il cookie httpOnly (se presente) sopravvive a un reload,
// ma il CSRF token in memoria no. `/api/admin/session/me` è un probe che non
// fallisce mai (200 anche senza sessione valida): il caso comune — prima
// visita, nessun cookie — resta così silenzioso, il pannello di accesso è
// già visibile di default nel markup.
(async () => {
	try {
		const session = await api("GET", "/api/admin/session/me");
		if (session.authenticated) {
			csrfToken = session.csrfToken;
			await refresh();
		}
	} catch (e) {
		banner("loginErr", `Impossibile contattare il control plane: ${e.message}`);
	}
})();
