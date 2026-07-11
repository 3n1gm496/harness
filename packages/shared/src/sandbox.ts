import { readFileSync } from "node:fs";
import type { SandboxPolicy } from "./types.js";

/**
 * Verifica che l'agente stia girando dentro l'ambiente contenuto sanzionato,
 * controllando un file marker scritto solo dall'immagine container ufficiale.
 *
 * Nota di sicurezza: è una barriera contro esecuzioni *accidentali* non
 * sandboxate. Non è invalicabile per un utente locale con privilegi (che può
 * creare il marker) — quell'attore è fuori dal modello di minaccia (vedi
 * docs/threat-model.md). Il vero confine resta l'isolamento OS.
 */
export function isSandboxSatisfied(sandbox: SandboxPolicy): boolean {
	if (!sandbox.required) return true;
	try {
		const content = readFileSync(sandbox.markerPath, "utf8");
		if (sandbox.markerValue.trim() === "") return true;
		return content.trim() === sandbox.markerValue.trim();
	} catch {
		return false;
	}
}
