type MetricType = "COUNTER" | "GAUGE" | "HISTOGRAM" | "SUMMARY";

interface BaseMetricItem {
  labels?: Record<string, string>;
}

interface ScalarMetricItem extends BaseMetricItem {
  value: number;
}

interface MetricBucket {
  cumulative_count: number;
  upper_bound: number;
}

interface HistogramMetricItem extends BaseMetricItem {
  buckets: MetricBucket[];
  sample_count: number;
  sample_sum: number;
}

interface SummaryMetricItem extends BaseMetricItem {
  sample_count: number;
  sample_sum: number;
}

type MetricItem = ScalarMetricItem | HistogramMetricItem | SummaryMetricItem;

interface MetricFamily<T extends MetricItem = MetricItem> {
  help?: string;
  type?: MetricType;
  metrics?: T[];
}

export type MetricsResponse = Record<string, MetricFamily> & {
  dns_top_domains?: MetricFamily<ScalarMetricItem>;
  dns_top_blocked_domains?: MetricFamily<ScalarMetricItem>;
};

export async function fetchMetrics(): Promise<MetricsResponse> {
  const response = await fetch("/api/metrics");
  if (!response.ok) {
    throw new Error("Failed to fetch metrics");
  }
  return await response.json();
}
