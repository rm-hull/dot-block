---
name: dns-metrics
description: >
  Fetches and analyses Prometheus metrics from an ad-blocking DNS server. Use this skill whenever
  the user asks to analyse, check, or report on their DNS server metrics, blocklist health, cache
  performance, top domains, latency, or anything related to their DNS ad-blocker telemetry. Trigger
  on phrases like "analyse my DNS metrics", "check my DNS server", "how's my ad blocker doing",
  "DNS report", or any mention of a METRICS_URL / prometheus DNS endpoint.
---

# DNS Metrics Analysis Skill

## Setup

Credentials are expected in a `.env` file (or already exported in the environment). The relevant
variables are:

```
METRICS_URL=https://your-dns-server/metrics
METRICS_USER_PASS=user:password   # basic-auth, colon-separated
```

## Workflow

### 1. Fetch metrics

```bash
source .env   # or however the user exposes their env
curl -s -u "$METRICS_USER_PASS" "$METRICS_URL"
```

Capture the raw Prometheus text output. If the curl fails (connection refused, auth error, etc.)
report the problem clearly before continuing.

### 2. Parse and analyse

Work through the five analysis areas below **in order**. For each area, extract the relevant
metric lines, compute the derived figures, and write a short plain-English summary with a
one-line verdict (✅ / ⚠️ / 🔴).

---

## Analysis Areas

### A. Cache Effectiveness

Relevant metrics: `dns_cache_stats{type="hits"}`, `…misses`, `…added`, `…evicted`, `…size`

Compute:
- **Hit rate** = hits / (hits + misses) × 100 %
- **Eviction pressure** = evicted / added × 100 %  (high → cache too small or TTLs too short)
- **Live cache size** vs hits+misses to see utilisation

Verdicts:
- Hit rate ≥ 20 % → ✅ reasonable; 5–20 % → ⚠️ low; < 5 % → 🔴 very low (cache may be too small or TTLs very short)
- Eviction pressure > 90 % → ⚠️ churn is high; report cache `size` and suggest tuning if applicable

### B. Top Domains — Adtech / Malware Check

Relevant metric: `dns_top_domains{hostname="…"}`  (allowed / non-blocked domains)

For each hostname, apply heuristic pattern matching to flag known adtech / tracking / telemetry
domains. Do **not** call external services — classify from the domain name alone using common
signals:

Known-adtech patterns (non-exhaustive, extend as needed):
- `doubleclick`, `googlesyndication`, `googleadservices`, `adsystem`
- `taboola`, `outbrain`, `revcontent`, `mgid`
- `facebook.net` (pixel/ads subdomains), `adnxs`, `criteo`, `rubiconproject`
- `scorecardresearch`, `quantserve`, `moatads`, `adform`
- Analytics/telemetry passing through unblocked: `google-analytics`, `analytics.`, `telemetry.`,
  `metrics.`, `stats.`, `tracking.`, `beacon.` (only flag if the base domain is adtech-adjacent)

For each flagged domain, note it and its request count.

Verdict: if any top allowed domains look like adtech/tracking, flag as ⚠️ with a note that the
blocklist may have gaps for those domains.

### C. False-Positive Check (Blocked Domains)

Relevant metric: `dns_top_blocked_domains{hostname="…"}`

Scan blocked domains for signs of **legitimate** services that are likely being over-blocked:

Signals of a potential false positive:
- Well-known CDNs: `cloudfront`, `fastly`, `akamai`, `cloudflare`, `edgekey`
- OS / platform essentials: `apple.com` (non-ad subdomains like `ocsp`, `configuration`,
  `xp.apple.com`), `microsoft.com`, `windows.com`, `windowsupdate`
- Developer tooling with no ad purpose: `sentry.io`, `github.com`, `collector.github.com`
- Payment / commerce infrastructure: `stripe.com`, `paypal.com`
- Error reporting (dual-use — note but don't automatically flag): `nr-data.net` (New Relic),
  `dynatrace.com`

For each likely false-positive domain, include its block count and a brief rationale.

Note: some domains are legitimately blocked even if they look legitimate (e.g. `app-measurement.com`
is Firebase Analytics, which is tracking). Use judgement and note ambiguous cases.

Verdict: list confirmed or likely false positives as ⚠️; if none found, ✅.

### D. Runtime Characteristics

Relevant metrics: Go runtime + process metrics

Extract and summarise:
| Metric | Value | Note |
|---|---|---|
| Uptime | derived from `process_start_time_seconds` (now − start) | |
| Goroutines | `go_goroutines` | flag if > 100 |
| Heap in use | `go_memstats_heap_inuse_bytes` (MB) | |
| Heap idle | `go_memstats_heap_idle_bytes` (MB) | |
| RSS (resident) | `process_resident_memory_bytes` (MB) | |
| GC pause p50/p75/p99 | from `go_gc_duration_seconds` quantiles (ms) | flag p99 > 10 ms |
| GC cycles | `go_gc_duration_seconds_count` | |
| CPU time | `process_cpu_seconds_total` | divide by uptime for avg CPU % |
| Upstream errors | `dns_error_count{category="upstream"}` | flag if > 0 |
| Blocklist age | `blocklist_age` (number of seconds) | flag if > 24 h |
| Blocklist size | `blocklist_size` | |

Verdict: flag anything anomalous (high GC pauses, high error count, stale blocklist, memory leaks
suggested by heap idle vs inuse ratio).

### E. Latency Outliers

Two histograms to analyse: `dns_request_latency` (end-to-end) and `dns_upstream_latency` (per
upstream server).

**Method for Prometheus histograms** — estimate percentiles from bucket counts:
- For each percentile P, find the first bucket `le` where `bucket_count / total_count ≥ P/100`.
  Interpolate linearly between the surrounding buckets for a better estimate.
- Derive p50, p90, p95, p99 for `dns_request_latency`.
- Derive p50 and p95 per upstream server from `dns_upstream_latency`.

Report:
- End-to-end latency percentiles in ms
- Mean latency = `dns_request_latency_sum / dns_request_latency_count` × 1000 ms
- Per-upstream mean = `sum / count` × 1000 ms; rank servers fastest → slowest
- Flag any bucket where more than 1 % of requests exceeded 100 ms (le="0.1" bucket gap vs total)

Verdict: ✅ if p99 < 50 ms; ⚠️ if p99 50–200 ms; 🔴 if p99 > 200 ms.

---

## Output Format

Produce a concise markdown report with this structure:

```
# DNS Server Health Report
_Fetched: <timestamp>_

## Summary
| Area | Verdict | One-liner |
|------|---------|-----------|
| Cache Effectiveness | ✅/⚠️/🔴 | … |
| Top Domains (adtech check) | ✅/⚠️/🔴 | … |
| False Positives | ✅/⚠️/🔴 | … |
| Runtime | ✅/⚠️/🔴 | … |
| Latency | ✅/⚠️/🔴 | … |

## Cache Effectiveness
…

## Top Domains — Adtech Check
…

## False-Positive Check
…

## Runtime
…

## Latency
…

## Recommendations
Bullet-point action items, most impactful first.
```

Keep each section tight — 3–8 sentences or a small table. No need to dump raw metric values unless
they are directly relevant.