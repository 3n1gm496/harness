/** Errore di comunicazione col gateway/provider, con lo status HTTP se disponibile. */
export class LlmError extends Error {
	constructor(
		message: string,
		readonly status: number,
	) {
		super(message);
		this.name = "LlmError";
	}
}
