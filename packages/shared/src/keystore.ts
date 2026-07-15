import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

/**
 * Envelope encryption per le chiavi private (di firma) a riposo. Le chiavi non
 * vanno mai scritte in chiaro né su file né in database: qui si cifrano con una
 * Key-Encryption-Key (KEK) di 32 byte fornita dall'operatore via ambiente/KMS.
 *
 * Formato del blob sigillato: `harness-sealed:v1:<iv>:<tag>:<ciphertext>` (base64url).
 */

const PREFIX = "harness-sealed:v1:";

export interface Kek {
	key: Buffer; // 32 byte
}

/**
 * Carica una KEK da variabile d'ambiente (base64/hex, 32 byte). `varName`
 * permette di leggere una KEK "alternativa" con lo stesso formato — usato per
 * la rotazione, dove la nuova KEK viaggia in una variabile diversa
 * (`HARNESS_SIGNING_KEK_NEW`) da quella corrente.
 */
export function loadKekFromEnv(env: NodeJS.ProcessEnv = process.env, varName = "HARNESS_SIGNING_KEK"): Kek | undefined {
	const raw = env[varName];
	if (!raw) return undefined;
	const key = decodeKeyMaterial(raw);
	if (key.length !== 32) throw new Error(`${varName} deve essere di 32 byte (base64 o hex)`);
	return { key };
}

function decodeKeyMaterial(raw: string): Buffer {
	const trimmed = raw.trim();
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return Buffer.from(trimmed, "hex");
	return Buffer.from(trimmed, "base64");
}

/** Genera una KEK casuale (per bootstrap/rotazione); restituisce base64. */
export function generateKek(): string {
	return randomBytes(32).toString("base64");
}

export function isSealed(value: string): boolean {
	return value.startsWith(PREFIX);
}

export function sealPrivateKey(kek: Kek, plaintextPem: string): string {
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", kek.key, iv);
	const ciphertext = Buffer.concat([cipher.update(plaintextPem, "utf8"), cipher.final()]);
	const tag = cipher.getAuthTag();
	return `${PREFIX}${iv.toString("base64url")}:${tag.toString("base64url")}:${ciphertext.toString("base64url")}`;
}

export function openPrivateKey(kek: Kek, sealed: string): string {
	if (!isSealed(sealed)) throw new Error("blob non in formato sealed");
	const parts = sealed.slice(PREFIX.length).split(":");
	if (parts.length !== 3) throw new Error("blob sealed malformato");
	const [ivB64, tagB64, ctB64] = parts as [string, string, string];
	const decipher = createDecipheriv("aes-256-gcm", kek.key, Buffer.from(ivB64, "base64url"));
	decipher.setAuthTag(Buffer.from(tagB64, "base64url"));
	const plaintext = Buffer.concat([decipher.update(Buffer.from(ctB64, "base64url")), decipher.final()]);
	return plaintext.toString("utf8");
}

/**
 * Ri-sigilla un insieme di record con una privateKeyPem sigillata, passando
 * da una vecchia KEK a una nuova (rotazione della KEK). Generico sul tipo del
 * record per non accoppiare `shared` ai tipi di storage del control plane;
 * usabile anche offline su un export di `signing-keys.json`.
 */
export function resealAll<T extends { privateKeyPem: string }>(oldKek: Kek, newKek: Kek, sealed: readonly T[]): T[] {
	return sealed.map((record) => ({
		...record,
		privateKeyPem: sealPrivateKey(
			newKek,
			isSealed(record.privateKeyPem) ? openPrivateKey(oldKek, record.privateKeyPem) : record.privateKeyPem,
		),
	}));
}
