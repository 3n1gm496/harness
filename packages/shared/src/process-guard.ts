import type { Logger } from "./logger.js";

/**
 * Rete di sicurezza a livello processo: cattura le eccezioni e i rejection
 * altrimenti non gestiti, li logga in modo strutturato ed esce con codice ≠0
 * per far ripartire il processo pulito sotto un supervisore (`restart:` del
 * compose, systemd, k8s). È l'ULTIMA linea di difesa — non un sostituto della
 * gestione errori localizzata: un processo che raggiunge questo punto è in uno
 * stato indefinito e va sostituito, non fatto proseguire.
 *
 * `unhandledRejection` è promosso a errore fatale (Node 15+ lo fa già di
 * default, ma renderlo esplicito lo rende osservabile via logger). Il valore di
 * ritorno permette di rimuovere i listener nei test.
 */
export function installProcessGuards(logger: Logger, exit: (code: number) => void = process.exit): () => void {
	const onUncaught = (error: unknown): void => {
		logger.error("uncaught_exception", {
			error: error instanceof Error ? (error.stack ?? error.message) : String(error),
		});
		exit(1);
	};
	const onRejection = (reason: unknown): void => {
		logger.error("unhandled_rejection", {
			error: reason instanceof Error ? (reason.stack ?? reason.message) : String(reason),
		});
		exit(1);
	};
	process.on("uncaughtException", onUncaught);
	process.on("unhandledRejection", onRejection);
	return () => {
		process.off("uncaughtException", onUncaught);
		process.off("unhandledRejection", onRejection);
	};
}
