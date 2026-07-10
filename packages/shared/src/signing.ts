import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from "node:crypto";
import type { ConfigBundle } from "./types.js";

/**
 * Firma dei bundle di configurazione in formato compatto JWS-like:
 * base64url(header) "." base64url(payload) "." base64url(firma Ed25519).
 * Il client applica solo bundle con firma valida rispetto alla chiave
 * pubblica pinnata al momento dell'enrollment.
 */

const TOKEN_HEADER = { alg: "EdDSA", typ: "harness-config+jws" } as const;

export interface SigningKeyPair {
	publicKeyPem: string;
	privateKeyPem: string;
}

export function generateSigningKeyPair(): SigningKeyPair {
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	return {
		publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
		privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
	};
}

export function signPayload(privateKeyPem: string, payload: unknown): string {
	const header = base64url(JSON.stringify(TOKEN_HEADER));
	const body = base64url(JSON.stringify(payload));
	const signingInput = Buffer.from(`${header}.${body}`, "utf8");
	const key = createPrivateKey(privateKeyPem);
	const signature = sign(null, signingInput, key);
	return `${header}.${body}.${signature.toString("base64url")}`;
}

export type VerifyResult<T> =
	| { valid: true; payload: T }
	| { valid: false; error: string };

export function verifyToken<T = unknown>(publicKeyPem: string, token: string): VerifyResult<T> {
	const parts = token.split(".");
	if (parts.length !== 3) return { valid: false, error: "formato token non valido" };
	const [header, body, signature] = parts as [string, string, string];

	let parsedHeader: unknown;
	try {
		parsedHeader = JSON.parse(Buffer.from(header, "base64url").toString("utf8"));
	} catch {
		return { valid: false, error: "header non decodificabile" };
	}
	if (
		typeof parsedHeader !== "object" ||
		parsedHeader === null ||
		(parsedHeader as Record<string, unknown>).alg !== TOKEN_HEADER.alg ||
		(parsedHeader as Record<string, unknown>).typ !== TOKEN_HEADER.typ
	) {
		return { valid: false, error: "header non riconosciuto" };
	}

	const key = createPublicKey(publicKeyPem);
	const signingInput = Buffer.from(`${header}.${body}`, "utf8");
	let signatureOk = false;
	try {
		signatureOk = verify(null, signingInput, key, Buffer.from(signature, "base64url"));
	} catch {
		signatureOk = false;
	}
	if (!signatureOk) return { valid: false, error: "firma non valida" };

	try {
		return { valid: true, payload: JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as T };
	} catch {
		return { valid: false, error: "payload non decodificabile" };
	}
}

/**
 * Verifica firma, schema e finestra temporale di un bundle di configurazione.
 * `clockSkewMs` tollera piccole derive di orologio tra server e client.
 */
export function verifyConfigBundle(
	publicKeyPem: string,
	token: string,
	now: Date = new Date(),
	clockSkewMs = 60_000,
): VerifyResult<ConfigBundle> {
	const result = verifyToken<ConfigBundle>(publicKeyPem, token);
	if (!result.valid) return result;
	const bundle = result.payload;
	if (bundle.schema !== "harness/config-bundle@1") {
		return { valid: false, error: `schema non supportato: ${String(bundle.schema)}` };
	}
	const issuedAt = Date.parse(bundle.issuedAt);
	const expiresAt = Date.parse(bundle.expiresAt);
	if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
		return { valid: false, error: "date del bundle non valide" };
	}
	if (issuedAt - clockSkewMs > now.getTime()) {
		return { valid: false, error: "bundle emesso nel futuro" };
	}
	if (expiresAt + clockSkewMs < now.getTime()) {
		return { valid: false, error: "bundle scaduto" };
	}
	return { valid: true, payload: bundle };
}

/**
 * Verifica un bundle contro un insieme di chiavi pubbliche fidate: valido se
 * una qualunque di esse ne verifica la firma. Sostiene la rotazione della
 * chiave di firma, in cui vecchia e nuova coesistono per un periodo di grazia.
 */
export function verifyConfigBundleMulti(
	publicKeyPems: string[],
	token: string,
	now: Date = new Date(),
	clockSkewMs = 60_000,
): VerifyResult<ConfigBundle> {
	if (publicKeyPems.length === 0) return { valid: false, error: "nessuna chiave pubblica fidata" };
	let lastError = "nessuna chiave ha verificato la firma";
	for (const pem of publicKeyPems) {
		const result = verifyConfigBundle(pem, token, now, clockSkewMs);
		if (result.valid) return result;
		lastError = result.error;
	}
	return { valid: false, error: lastError };
}

function base64url(value: string): string {
	return Buffer.from(value, "utf8").toString("base64url");
}
