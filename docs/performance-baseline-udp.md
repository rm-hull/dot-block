# Performance Baseline: UDP Simple Implementation (current branch)

This document summarizes the performance of the DNS forwarder using the "Simple" UDP implementation (`miekg/dns.Client.Exchange`) found on the `fix/revert-to-UDP` branch.

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
| **Duration** | ~68s | ~35s |
| **Total Sent** | 6,570 | 32,210 |
| **Total Received** | 6,570 | 32,210 |
| **Success Rate** | 100% | 100% |
| **Timeouts** | 0 (0%) | 0 (0%) |
| **Network Errors** | 0 | 0 |
| **Min Response Time** | 125.11 ms | 28.10 ms |
| **Avg Response Time** | 280.86 ms | 242.39 ms |
| **Max Response Time** | 1065.03 ms | 1033.80 ms |
| **Avg Send QPS** | 96 | 968 |
| **Avg Recv QPS** | 92 | 962 |

## Analysis

### 1. Stability
The "Simple" UDP implementation is remarkably stable across both load levels. Even at 1000 QPS, there were **zero timeouts** and **zero network errors**, matching the reliability of the previous TCP pooling baseline.

### 2. Latency Trends
- **Avg Response Time:** Stays consistent (~281ms at 100 QPS $\rightarrow$ ~242ms at 1000 QPS).
- **Min Response Time:** There is a surprising drop from ~125ms (100 QPS) to ~28ms (1000 QPS). While this might be an artifact of the load generator or upstream behavior, it shows that the local overhead is not increasing with load.
- **Max Response Time:** Remains stable around 1s, which is typical for public DNS transit.

### 3. Resource Utilization
For the 1000 QPS test, the "in flight" count averaged around 200-300.
$$\text{In Flight} = 1000\text{ QPS} \times 0.242\text{s} \approx 242\text{ requests in flight}$$
This closely matches the `flame` output, indicating the system is processing requests at a steady rate without accumulating a backlog.

## Conclusion
The "Simple" UDP implementation handles 1000 QPS with the same reliability as the TCP connection pool. The feared "socket churn" (CPU overhead and port exhaustion) is not apparent at this scale. For the target load of 1k QPS, the current implementation is sufficient.
