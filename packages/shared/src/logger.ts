/**
 * Logger strutturato zero-dipendenze: emette una riga JSON per evento con
 * `ts`, `level`, `component`, `msg` e i campi contestuali. Il livello minimo si
 * imposta con `HARNESS_LOG_LEVEL` (debug|info|warn|error, default info).
 *
 * JSON su una riga = pronto per l'ingest da parte di qualunque collector
 * (Loki, Elastic, CloudWatch) senza parsing custom.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVELS: Record<LogLevel, number> = { debug: 10, info: 20, warn: 30, error: 40 };

export type LogFields = Record<string, unknown>;

export interface Logger {
	debug(msg: string, fields?: LogFields): void;
	info(msg: string, fields?: LogFields): void;
	warn(msg: string, fields?: LogFields): void;
	error(msg: string, fields?: LogFields): void;
	/** Deriva un logger figlio con campi di base ereditati (es. requestId). */
	child(bindings: LogFields): Logger;
}

export interface LoggerOptions {
	level?: LogLevel;
	/** Sink di output (default: stdout via console.log). Override utile nei test. */
	sink?: (line: string) => void;
	/** Campi di base uniti a ogni evento. */
	base?: LogFields;
}

function resolveLevel(explicit?: LogLevel): LogLevel {
	if (explicit) return explicit;
	const env = process.env.HARNESS_LOG_LEVEL as LogLevel | undefined;
	return env && env in LEVELS ? env : "info";
}

export function createLogger(component: string, options: LoggerOptions = {}): Logger {
	const level = resolveLevel(options.level);
	const threshold = LEVELS[level];
	const sink = options.sink ?? ((line: string) => console.log(line));
	const base = options.base ?? {};

	const emit = (lvl: LogLevel, msg: string, fields?: LogFields): void => {
		if (LEVELS[lvl] < threshold) return;
		const entry: Record<string, unknown> = {
			ts: new Date().toISOString(),
			level: lvl,
			component,
			msg,
			...base,
			...fields,
		};
		let line: string;
		try {
			line = JSON.stringify(entry);
		} catch {
			line = JSON.stringify({ ts: entry.ts, level: lvl, component, msg, error: "campi non serializzabili" });
		}
		sink(line);
	};

	return {
		debug: (msg, fields) => emit("debug", msg, fields),
		info: (msg, fields) => emit("info", msg, fields),
		warn: (msg, fields) => emit("warn", msg, fields),
		error: (msg, fields) => emit("error", msg, fields),
		child: (bindings) => createLogger(component, { ...options, level, base: { ...base, ...bindings } }),
	};
}
