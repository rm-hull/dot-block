# Evaluating UDP Performance: Simple vs. Optimized

This document provides a guide on how to use the existing observability stack (Prometheus, Logs, and OpenTelemetry) to determine if the "Simple" UDP implementation (`miekg/dns.Client.Exchange`) is creating a performance bottleneck.

## Goal
Determine if the overhead of creating a new socket for every DNS query is significantly impacting latency or CPU utilization, and whether it is causing stability issues under load.

## 1. Prometheus Metrics
Prometheus provides the aggregate view. Look for correlations between request volume (QPS) and error rates.

### Key Metrics to Monitor:
- **Upstream Failure Rate:** 
    - Monitor `dns_upstream_failures_total` grouped by `upstream` and `reason`.
    - **Red Flag:** A spike in `network_error` or `timeout` reasons that correlates with increased QPS. This suggests the kernel is struggling to allocate sockets or handle the churn rate.
- **Request Latency:** 
    - Analyze the latency of requests that hit the upstream.
    - **Red Flag:** A steady increase in p99 latency as QPS increases, even if the upstream server's own response time remains constant.

## 2. OpenTelemetry (OTel) Tracing
Tracing allows us to see the "anatomy" of a single request.

### What to Look For:
- **Span Analysis:** Examine the span associated with the upstream DNS exchange.
- **Latency Breakdown:**
    - The span covers the time from `Exchange` start to finish. This includes:
        - `Socket creation` $\rightarrow$ `Packet send` $\rightarrow$ `Network Transit` $\rightarrow$ `Upstream Processing` $\rightarrow$ `Packet return`.
    - **Red Flag:** If you compare traces from a low-load period to a high-load period and see the "Upstream" span duration increasing significantly while the upstream server is healthy, the overhead is likely in the local socket management.

## 3. Log Analysis
Logs capture the specific errors that metrics might aggregate.

### Search Terms:
- Search for "upstream failure" or "network error".
- **Red Flag:** Errors like `cannot assign requested address` or `too many open files`. These are definitive indicators of ephemeral port exhaustion or file descriptor limits being hit due to high socket churn.

## 4. System-Level Observations (External to App)
Since the app only sees the *result* of a socket call, use OS tools to see the *cause*.

### Resource Monitoring:
- **CPU Utilization (`top` / `htop`):**
    - Check for high `%sys` (system) CPU usage. High system time relative to user time often indicates excessive system calls (like `socket()` and `close()`).
- **Socket State (`ss`):**
    - Run `ss -u -a` during a load test.
    - While UDP is stateless, checking the number of active sockets can reveal if the app is holding onto resources longer than expected.
- **Kernel Profiling (`perf`):**
    - Use `perf top` to see which kernel functions are consuming the most CPU.
    - **Red Flag:** High percentages in `tcp_v4_connect` (even for UDP if using `Dial`) or `unix_stream_connect` / `socket_create`.

## Decision Matrix: When to Optimize?

| Observation | Simple Solution is OK | Optimize to Persistent Sockets |
| :--- | :--- | :--- |
| **CPU Usage** | Low/Moderate `%sys` | High `%sys` during QPS spikes |
| **Latency** | Stable p99 regardless of load | p99 increases linearly with load |
| **Errors** | No network-level errors | `EADDRNOTAVAIL` or frequent `network_error` |
| **Scale** | < 1k QPS | > 5k QPS or strict latency requirements |

## Testing Strategy
To actually trigger these bottlenecks, run a load test using a tool like `dnsperf` or `flamethrower` against the server, gradually increasing the request rate until the "Red Flags" appear.
