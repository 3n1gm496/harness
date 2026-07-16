/**
 * Lettore SSE generico condiviso dai provider. Legge uno stream a righe,
 * accumula gli eventi separati da riga vuota, estrae le righe `data:` e le
 * consegna a `onData` già parsate da JSON. Robusto a eventi spezzati sui chunk
 * di rete. Le eccezioni lanciate da `onData` (es. un evento di errore del
 * provider) PROPAGANO — non vanno confuse con un parse fallito, che è ignorato.
 */
export async function readSseEvents(
	stream: ReadableStream<Uint8Array>,
	onData: (data: unknown) => void,
): Promise<void> {
	const reader = stream.getReader();
	const decoder = new TextDecoder();
	let buffer = "";
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			buffer += decoder.decode(value, { stream: true });
			buffer = drain(buffer, onData);
		}
		buffer += decoder.decode();
		drain(`${buffer}\n\n`, onData);
	} finally {
		reader.releaseLock();
	}
}

function drain(buffer: string, onData: (data: unknown) => void): string {
	let rest = buffer;
	for (;;) {
		const boundary = rest.indexOf("\n\n");
		if (boundary === -1) return rest;
		const rawEvent = rest.slice(0, boundary);
		rest = rest.slice(boundary + 2);
		const data = extractData(rawEvent);
		if (data === undefined || data === "[DONE]") continue;
		let parsed: unknown;
		try {
			parsed = JSON.parse(data);
		} catch {
			continue; // riga data non-JSON (commento/ping): ignorata
		}
		onData(parsed);
	}
}

/** Concatena i valori delle righe `data:` di un evento SSE. */
function extractData(rawEvent: string): string | undefined {
	let data = "";
	let seen = false;
	for (const line of rawEvent.split("\n")) {
		if (line.startsWith("data:")) {
			data += line.slice(5).replace(/^ /, "");
			seen = true;
		}
	}
	return seen ? data : undefined;
}
