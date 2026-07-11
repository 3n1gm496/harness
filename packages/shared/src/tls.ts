import type { IncomingMessage } from "node:http";
import type { TLSSocket } from "node:tls";

/**
 * Fingerprint SHA-256 (hex minuscolo, senza separatori) del certificato client
 * presentato nella connessione TLS, se presente. Usato per legare un device al
 * suo certificato mTLS sia sul control plane sia sul gateway LLM.
 */
export function peerCertFingerprint(req: IncomingMessage): string | undefined {
	const socket = req.socket as TLSSocket;
	if (typeof socket.getPeerCertificate !== "function") return undefined;
	const cert = socket.getPeerCertificate();
	if (!cert || Object.keys(cert).length === 0) return undefined;
	const fp = cert.fingerprint256;
	if (!fp) return undefined;
	return fp.replaceAll(":", "").toLowerCase();
}
