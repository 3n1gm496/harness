import assert from "node:assert/strict";
import { test } from "node:test";
import { createLogger, MetricsRegistry } from "../index.js";

test("il logger emette JSON strutturato con livello, componente e campi", () => {
	const lines: string[] = [];
	const log = createLogger("test", { level: "debug", sink: (l) => lines.push(l) });
	log.info("ciao", { userId: 7 });
	const entry = JSON.parse(lines[0] as string) as Record<string, unknown>;
	assert.equal(entry.level, "info");
	assert.equal(entry.component, "test");
	assert.equal(entry.msg, "ciao");
	assert.equal(entry.userId, 7);
	assert.equal(typeof entry.ts, "string");
});

test("il logger rispetta la soglia di livello", () => {
	const lines: string[] = [];
	const log = createLogger("t", { level: "warn", sink: (l) => lines.push(l) });
	log.info("nascosto");
	log.warn("visibile");
	assert.equal(lines.length, 1);
	assert.match(lines[0] as string, /visibile/);
});

test("il logger figlio eredita i binding di base", () => {
	const lines: string[] = [];
	const log = createLogger("t", { level: "debug", sink: (l) => lines.push(l) }).child({ requestId: "r1" });
	log.info("x");
	assert.equal((JSON.parse(lines[0] as string) as Record<string, unknown>).requestId, "r1");
});

test("i campi non serializzabili non fanno crashare il logger", () => {
	const lines: string[] = [];
	const log = createLogger("t", { level: "debug", sink: (l) => lines.push(l) });
	const circular: Record<string, unknown> = {};
	circular.self = circular;
	log.info("loop", circular);
	assert.equal(lines.length, 1);
	assert.match(lines[0] as string, /non serializzabili/);
});

test("MetricsRegistry: counter e gauge con label in formato Prometheus", () => {
	const m = new MetricsRegistry();
	m.counter("reqs", "richieste");
	m.gauge("inflight", "in volo");
	m.incCounter("reqs", { method: "GET", status: "200" });
	m.incCounter("reqs", { method: "GET", status: "200" });
	m.incCounter("reqs", { method: "POST", status: "500" });
	m.setGauge("inflight", 3);
	const out = m.render();
	assert.match(out, /# TYPE reqs counter/);
	assert.match(out, /reqs\{method="GET",status="200"\} 2/);
	assert.match(out, /reqs\{method="POST",status="500"\} 1/);
	assert.match(out, /inflight 3/);
});

test("MetricsRegistry: histogram con bucket cumulativi, sum e count", () => {
	const m = new MetricsRegistry();
	m.histogram("dur", "durata", [0.1, 0.5, 1]);
	m.observe("dur", 0.05);
	m.observe("dur", 0.4);
	m.observe("dur", 2);
	const out = m.render();
	// 0.05 e 0.4 ≤ 0.5 ⇒ bucket le=0.5 conta 2; le=+Inf conta tutti e 3.
	assert.match(out, /dur_bucket\{le="0.1"\} 1/);
	assert.match(out, /dur_bucket\{le="0.5"\} 2/);
	assert.match(out, /dur_bucket\{le="\+Inf"\} 3/);
	assert.match(out, /dur_count 3/);
	assert.match(out, /dur_sum 2.45/);
});

test("addGauge accumula e può decrementare (in-flight)", () => {
	const m = new MetricsRegistry();
	m.gauge("g", "g");
	m.addGauge("g", 1);
	m.addGauge("g", 1);
	m.addGauge("g", -1);
	assert.match(m.render(), /g 1/);
});
