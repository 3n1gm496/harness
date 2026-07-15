import assert from "node:assert/strict";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { createControlPlaneServer } from "../server.js";
import { ControlPlaneService } from "../service.js";
import { Store } from "../store.js";

/**
 * Verifica visiva reale della UI (playwright-core, guidato da node:test — non
 * @playwright/test, per non introdurre un secondo test runner). Skippa se non
 * trova un Chromium eseguibile, con lo stesso spirito dei test PG live
 * (skip: !HARNESS_TEST_PG_URL): attivo in CI dove Chromium è installato,
 * innocuo altrove.
 */
function findChromiumExecutable(): string | undefined {
	const candidates = [
		process.env.HARNESS_TEST_CHROMIUM_PATH,
		process.env.PLAYWRIGHT_BROWSERS_PATH ? join(process.env.PLAYWRIGHT_BROWSERS_PATH, "chromium") : undefined,
		"/opt/pw-browsers/chromium",
	].filter((p): p is string => Boolean(p));
	return candidates.find((p) => existsSync(p));
}

const chromiumPath = findChromiumExecutable();

let dataDir: string;
let server: ReturnType<typeof createControlPlaneServer>;
let baseUrl: string;
let adminToken: string;

before(async () => {
	if (!chromiumPath) return;
	dataDir = mkdtempSync(join(tmpdir(), "harness-ui-test-"));
	const store = new Store(dataDir);
	const service = new ControlPlaneService(store);
	adminToken = service.auth.bootstrapAdminToken("ui-test-admin");
	const identity = service.auth.authenticateAdmin(adminToken);
	const groupId = service.org.overview(identity).groups[0]?.groupId as string;
	service.groups.createGroup(identity, "produzione");

	// Arruola alcuni device: 4 attivi (i 0-3), 1 stale (i=4, nessun contatto
	// recente, senza kill switch), 1 sospeso (i=5, kill switch acceso ma
	// contatto recente — la sospensione vince sulla staleness in deviceState).
	for (let i = 0; i < 6; i += 1) {
		const enr = service.devices.createEnrollToken(identity, groupId, 10);
		const dev = service.devices.enrollDevice(enr, `ui-device-${i}`);
		const record = store.state.devices[dev.deviceId];
		if (!record) throw new Error("device non trovato nello store");
		record.lastSeenAt = i === 4 ? new Date(Date.now() - 5 * 3600_000).toISOString() : new Date().toISOString();
		record.lastConfigVersion = store.state.org.configVersion;
		if (i === 5) record.killSwitch = true;
	}
	store.save();

	server = createControlPlaneServer(service, { readiness: () => store.checkReady() });
	await new Promise<void>((resolve) => server.listen(0, resolve));
	baseUrl = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
	if (!chromiumPath) return;
	await new Promise((resolve) => server.close(resolve));
	rmSync(dataDir, { recursive: true, force: true });
});

test("UI: login, dashboard, filtro stale, editor policy con diff e validazione JSON — zero errori console (live browser)", {
	skip: !chromiumPath && "Chromium non trovato (imposta HARNESS_TEST_CHROMIUM_PATH o installa via Playwright)",
}, async () => {
	if (!chromiumPath) throw new Error("Chromium non trovato"); // già coperto da skip, restringe il tipo
	const { chromium } = await import("playwright-core");
	const browser = await chromium.launch({ executablePath: chromiumPath });
	const errors: string[] = [];
	try {
		const page = await browser.newPage({ viewport: { width: 1200, height: 1400 } });
		page.on("console", (m) => {
			if (m.type() === "error") errors.push(m.text());
		});
		page.on("pageerror", (e) => errors.push(`pageerror: ${e.message}`));
		// Le azioni distruttive (elimina, revoca, …) passano da un confirm()
		// nativo: senza un handler esplicito Playwright lo respinge di default.
		page.on("dialog", (dialog) => void dialog.accept());

		await page.goto(baseUrl);
		await page.fill("#tokenInput", adminToken);
		await page.click("#btnLogin");
		await page.waitForSelector("#dashboardCards .card");
		await page.waitForTimeout(300);

		// Dashboard: le card di riepilogo (totale, attivi, stale, sospesi, …)
		// devono comparire e riflettere lo stato seedato.
		const cardCount = await page.locator("#dashboardCards .card").count();
		assert.ok(cardCount >= 4, "la dashboard deve mostrare le card di riepilogo di flotta");
		const deviceRowsAll = await page.locator("#devicesBody tr").count();
		assert.equal(deviceRowsAll, 6, "tutti i device seedati devono comparire nella tabella");

		// Filtro stale (server-side): solo il device senza contatto recente.
		await page.selectOption("#deviceFilter", "stale");
		await page.waitForTimeout(300);
		const staleRows = await page.locator("#devicesBody tr").count();
		assert.equal(staleRows, 1, "il filtro stale deve isolare il device senza contatto recente");
		await page.selectOption("#deviceFilter", "all");
		await page.waitForTimeout(300);

		// Ricerca server-side (debounced).
		await page.fill("#deviceSearch", "ui-device-2");
		await page.waitForTimeout(500);
		const searchText = await page.locator("#devicesBody").textContent();
		assert.match(searchText ?? "", /ui-device-2/);
		await page.fill("#deviceSearch", "");
		await page.waitForTimeout(500);

		// Editor policy: attiva sandbox, verifica il diff.
		await page.selectOption("#pf_sandbox", "true");
		await page.click("#tabDiff");
		await page.waitForTimeout(200);
		const diffText = await page.locator("#diffOut").textContent();
		assert.match(diffText ?? "", /sandbox/);

		// JSON non valido nell'editor avanzato → banner d'errore, save disabilitato.
		await page.click("#tabJson");
		await page.fill("#orgPolicy", '{ "killSwitch": "non-booleano" }');
		await page.click("#btnSyncJson");
		await page.waitForTimeout(200);
		const validationHtml = await page.locator("#policyValidation").innerHTML();
		assert.match(validationHtml, /booleano/);
		assert.equal(await page.locator("#btnSavePolicy").isDisabled(), true);

		// Eliminazione device (P1.4): il bottone admin-only rimuove la riga.
		await page.click("#devicesBody button:has-text('elimina')");
		await page.waitForTimeout(300);
		const rowsAfter = await page.locator("#devicesBody tr").count();
		assert.equal(rowsAfter, 5, "il device eliminato non deve più comparire tra i 6 seedati");

		assert.deepEqual(errors, [], `nessun errore console atteso, trovati: ${JSON.stringify(errors)}`);
	} finally {
		await browser.close();
	}
});
