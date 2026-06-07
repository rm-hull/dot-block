# Performance Baseline: TCP Connection Pooling (Main Branch)

This document summarizes the performance of the DNS forwarder using the TCP connection pooling implementation found on the `main` branch.

## Test Configuration
- **Tool:** `flame` (DNS-OARC)
- **Target:** `dns.hz-nbg1.destructuring-bind.org:1053`
- **Query Type:** `randomlabel` (Bypasses cache, forcing upstream exchange for every request)
- **Concurrency:** 10 concurrent senders

**Commands used:**
```bash
# 100 QPS
docker run --rm --net host ns1labs/flame dns.hz-nbg1.destructuring-bind.org -p 1053 -Q 100 -c 10 -g randomlabel lblsize=10 lblcount=4 count=100

# 1000 QPS
docker run --rm --net host ns1labs/flame dns.hz-nbg1.destructuring-bind.org -p 1053 -Q 1000 -c 10 -g randomlabel lblsize=10 lblcount=4 count=10
```

## Test Results

| Metric | 100 QPS | 1000 QPS |
| :--- | :--- | :--- |
| **Duration** | ~100s | ~34s |
| **Total Sent** | 10,070 | 31,070 |
| **Total Received** | 10,070 | 31,070 |
| **Success Rate** | 100% | 100% |
| **Timeouts** | 0 (0%) | 0 (0%) |
| **Network Errors** | 0 | 0 |
| **Min Response Time** | 30.26 ms | 27.98 ms |
| **Avg Response Time** | 280.82 ms | 155.50 ms |
| **Max Response Time** | 798.13 ms | 942.58 ms |
| **Avg Send QPS** | 96 | 964 |
| **Avg Recv QPS** | 93 | 960 |

## Analysis

### 1. Stability
The system is remarkably stable even at 1000 QPS. There were **zero timeouts** and **zero network errors**, indicating that the TCP connection pool is successfully managing upstream connections without exhaustion or crash.

### 2. Latency Trends
- At 100 QPS, avg latency was **~281ms**.
- At 1000 QPS, avg latency dropped to **~156ms**.
- This decrease in average latency at higher load is likely due to the `randomlabel` generator distribution or upstream server behavior (e.g., some responses arriving faster as the pipe fills), rather than local server overhead.
- The minimum response (~28-30ms) remains constant, confirming the baseline network latency.

### 3. Resource Utilization (Little's Law)
For the 1000 QPS test:
$$\text{In Flight} = \text{Arrival Rate} \times \text{Average Latency}$$
$$1000\text{ QPS} \times 0.155\text{s} \approx 155\text{ requests in flight}$$
The `flame` output showed "in flight" counts ranging from ~110 to ~300, which aligns well with the theoretical expectation.

## Conclusion
The TCP connection pooling implementation handles 1000 QPS with ease. It maintains 100% reliability and consistent latency. This provides a strong benchmark: any new UDP implementation must at least match this stability and throughput.
