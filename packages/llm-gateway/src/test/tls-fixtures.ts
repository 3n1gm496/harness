import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Generazione di CA e certificati per i test mTLS, tramite openssl.
 * Solo per i test: se openssl non è disponibile, `openSslAvailable()` è false e
 * il test relativo si auto-salta.
 */

export interface Ca {
	certPem: string;
	keyPem: string;
	dir: string;
}

export interface CertPair {
	certPem: string;
	keyPem: string;
}

export function openSslAvailable(): boolean {
	try {
		execFileSync("openssl", ["version"], { stdio: "ignore" });
		return true;
	} catch {
		return false;
	}
}

function ossl(args: string[], cwd: string): void {
	execFileSync("openssl", args, { cwd, stdio: "ignore" });
}

export function makeCa(): Ca {
	const dir = mkdtempSync(join(tmpdir(), "harness-ca-"));
	ossl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", "ca.key"], dir);
	ossl(["req", "-x509", "-new", "-key", "ca.key", "-days", "1", "-subj", "/CN=Harness Test CA", "-out", "ca.crt"], dir);
	return {
		certPem: readFileSync(join(dir, "ca.crt"), "utf8"),
		keyPem: readFileSync(join(dir, "ca.key"), "utf8"),
		dir,
	};
}

export function makeCert(ca: Ca, cn: string): CertPair {
	const dir = ca.dir;
	const base = cn.replaceAll(/[^A-Za-z0-9_-]/g, "_");
	ossl(["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", `${base}.key`], dir);
	ossl(["req", "-new", "-key", `${base}.key`, "-subj", `/CN=${cn}`, "-out", `${base}.csr`], dir);
	writeFileSync(join(dir, `${base}.ext`), "subjectAltName=DNS:localhost,IP:127.0.0.1\n");
	ossl(
		[
			"x509",
			"-req",
			"-in",
			`${base}.csr`,
			"-CA",
			"ca.crt",
			"-CAkey",
			"ca.key",
			"-CAcreateserial",
			"-days",
			"1",
			"-extfile",
			`${base}.ext`,
			"-out",
			`${base}.crt`,
		],
		dir,
	);
	return {
		certPem: readFileSync(join(dir, `${base}.crt`), "utf8"),
		keyPem: readFileSync(join(dir, `${base}.key`), "utf8"),
	};
}

export function cleanupCa(ca: Ca): void {
	rmSync(ca.dir, { recursive: true, force: true });
}
