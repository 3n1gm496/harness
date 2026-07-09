import { randomBytes, randomUUID } from "node:crypto";

export function newId(prefix: string): string {
	return `${prefix}_${randomUUID().replaceAll("-", "")}`;
}

/** Token opachi ad alta entropia per device, enrollment e admin. */
export function newSecretToken(prefix: string): string {
	return `${prefix}_${randomBytes(32).toString("base64url")}`;
}
