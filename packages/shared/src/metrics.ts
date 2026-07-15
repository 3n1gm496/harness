/**
 * Registro di metriche minimale in formato di esposizione Prometheus, senza
 * dipendenze. Supporta counter, gauge e histogram con label. `render()`
 * produce il testo `text/plain; version=0.0.4` da servire su `/metrics`.
 */
export type Labels = Record<string, string>;

/** Bucket di default per le durate delle richieste HTTP, in secondi. */
export const DEFAULT_DURATION_BUCKETS = [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10];

function serializeLabels(labels: Labels): string {
	const keys = Object.keys(labels).sort();
	if (keys.length === 0) return "";
	return keys.map((k) => `${k}="${escapeLabel(labels[k] as string)}"`).join(",");
}

function escapeLabel(value: string): string {
	return value.replace(/\\/g, "\\\\").replace(/\n/g, "\\n").replace(/"/g, '\\"');
}

interface CounterMetric {
	kind: "counter";
	help: string;
	values: Map<string, { labels: Labels; value: number }>;
}
interface GaugeMetric {
	kind: "gauge";
	help: string;
	values: Map<string, { labels: Labels; value: number }>;
}
interface HistogramMetric {
	kind: "histogram";
	help: string;
	buckets: number[];
	series: Map<string, { labels: Labels; counts: number[]; sum: number; count: number }>;
}
type Metric = CounterMetric | GaugeMetric | HistogramMetric;

export class MetricsRegistry {
	private metrics = new Map<string, Metric>();

	counter(name: string, help: string): void {
		if (!this.metrics.has(name)) this.metrics.set(name, { kind: "counter", help, values: new Map() });
	}
	gauge(name: string, help: string): void {
		if (!this.metrics.has(name)) this.metrics.set(name, { kind: "gauge", help, values: new Map() });
	}
	histogram(name: string, help: string, buckets: number[] = DEFAULT_DURATION_BUCKETS): void {
		if (!this.metrics.has(name)) {
			this.metrics.set(name, {
				kind: "histogram",
				help,
				buckets: [...buckets].sort((a, b) => a - b),
				series: new Map(),
			});
		}
	}

	incCounter(name: string, labels: Labels = {}, by = 1): void {
		const metric = this.metrics.get(name);
		if (metric?.kind !== "counter") return;
		const key = serializeLabels(labels);
		const entry = metric.values.get(key) ?? { labels, value: 0 };
		entry.value += by;
		metric.values.set(key, entry);
	}

	setGauge(name: string, value: number, labels: Labels = {}): void {
		const metric = this.metrics.get(name);
		if (metric?.kind !== "gauge") return;
		metric.values.set(serializeLabels(labels), { labels, value });
	}

	addGauge(name: string, delta: number, labels: Labels = {}): void {
		const metric = this.metrics.get(name);
		if (metric?.kind !== "gauge") return;
		const key = serializeLabels(labels);
		const entry = metric.values.get(key) ?? { labels, value: 0 };
		entry.value += delta;
		metric.values.set(key, entry);
	}

	observe(name: string, value: number, labels: Labels = {}): void {
		const metric = this.metrics.get(name);
		if (metric?.kind !== "histogram") return;
		const key = serializeLabels(labels);
		const entry = metric.series.get(key) ?? {
			labels,
			counts: new Array(metric.buckets.length).fill(0),
			sum: 0,
			count: 0,
		};
		metric.buckets.forEach((bound, i) => {
			if (value <= bound) entry.counts[i] = (entry.counts[i] as number) + 1;
		});
		entry.sum += value;
		entry.count += 1;
		metric.series.set(key, entry);
	}

	render(): string {
		const lines: string[] = [];
		for (const [name, metric] of this.metrics) {
			lines.push(`# HELP ${name} ${metric.help}`);
			lines.push(`# TYPE ${name} ${metric.kind}`);
			if (metric.kind === "counter" || metric.kind === "gauge") {
				for (const { labels, value } of metric.values.values()) {
					const l = serializeLabels(labels);
					lines.push(`${name}${l ? `{${l}}` : ""} ${value}`);
				}
			} else {
				for (const series of metric.series.values()) {
					let cumulative = 0;
					metric.buckets.forEach((bound, i) => {
						cumulative = series.counts[i] as number;
						const l = serializeLabels({ ...series.labels, le: String(bound) });
						lines.push(`${name}_bucket{${l}} ${cumulative}`);
					});
					const inf = serializeLabels({ ...series.labels, le: "+Inf" });
					lines.push(`${name}_bucket{${inf}} ${series.count}`);
					const base = serializeLabels(series.labels);
					lines.push(`${name}_sum${base ? `{${base}}` : ""} ${series.sum}`);
					lines.push(`${name}_count${base ? `{${base}}` : ""} ${series.count}`);
				}
			}
		}
		return `${lines.join("\n")}\n`;
	}
}
