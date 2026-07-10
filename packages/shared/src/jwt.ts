import { createPublicKey, verify as cryptoVerify } from "node:crypto";

/**
 * Verifica di JWT firmati (RS256/ES256) per l'autenticazione degli
 * amministratori tramite un provider OIDC aziendale, in alternativa ai token
 * statici. Verifica firma, algoritmo, issuer, audience e scadenza contro un
 * insieme di chiavi pubbliche configurate (tipicamente il JWKS del provider,
 * fornito come PEM per evitare dipendenze di rete a runtime).
 */

export type JwtAlg = "RS256" | "ES256";

export interface JwtVerifyKey {
	/** Identificatore chiave; se presente deve combaciare con l'header `kid`. */
	kid?: string;
	alg: JwtAlg;
	publicKeyPem: string;
}

export interface JwtVerifyOptions {
	keys: JwtVerifyKey[];
	issuer: string;
	audience: string;
	now?: Date;
	clockSkewSec?: number;
}

export type JwtClaims = Record<string, unknown> & {
	iss?: string;
	aud?: string | string[];
	exp?: number;
	nbf?: number;
	sub?: string;
};

export type JwtResult =
	| { valid: true; claims: JwtClaims }
	| { valid: false; error: string };

const NODE_ALG: Record<JwtAlg, string> = { RS256: "RSA-SHA256", ES256: "sha256" };

export function verifyJwt(token: string, options: JwtVerifyOptions): JwtResult {
	const parts = token.split(".");
	if (parts.length !== 3) return { valid: false, error: "formato JWT non valido" };
	const [headerB64, payloadB64, signatureB64] = parts as [string, string, string];

	let header: { alg?: string; kid?: string; typ?: string };
	try {
		header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
	} catch {
		return { valid: false, error: "header JWT non decodificabile" };
	}
	if (header.alg !== "RS256" && header.alg !== "ES256") {
		return { valid: false, error: `algoritmo non supportato: ${String(header.alg)}` };
	}
	const alg = header.alg;

	const candidates = options.keys.filter(
		(k) => k.alg === alg && (k.kid === undefined || header.kid === undefined || k.kid === header.kid),
	);
	if (candidates.length === 0) return { valid: false, error: "nessuna chiave di verifica corrispondente" };

	const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, "utf8");
	const signature = Buffer.from(signatureB64, "base64url");
	const signatureOk = candidates.some((key) => {
		try {
			const publicKey = createPublicKey(key.publicKeyPem);
			return cryptoVerify(
				NODE_ALG[alg],
				signingInput,
				alg === "ES256" ? { key: publicKey, dsaEncoding: "ieee-p1363" } : publicKey,
				signature,
			);
		} catch {
			return false;
		}
	});
	if (!signatureOk) return { valid: false, error: "firma JWT non valida" };

	let claims: JwtClaims;
	try {
		claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8")) as JwtClaims;
	} catch {
		return { valid: false, error: "payload JWT non decodificabile" };
	}

	const skewMs = (options.clockSkewSec ?? 60) * 1000;
	const nowMs = (options.now ?? new Date()).getTime();
	if (claims.iss !== options.issuer) return { valid: false, error: "issuer non atteso" };
	const audiences = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
	if (!audiences.includes(options.audience)) return { valid: false, error: "audience non atteso" };
	if (typeof claims.exp === "number" && claims.exp * 1000 + skewMs < nowMs) {
		return { valid: false, error: "token scaduto" };
	}
	if (typeof claims.nbf === "number" && claims.nbf * 1000 - skewMs > nowMs) {
		return { valid: false, error: "token non ancora valido" };
	}
	return { valid: true, claims };
}
