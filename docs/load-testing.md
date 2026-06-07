# Load Testing the DNS Server

This document describes how to use `dnsperf` and `flamethrower` to stress test the DoT Block server and evaluate its performance.

## Testing Environment
To avoid network bottlenecks and latency noise, it is recommended to run the load testing tool on the same host or within the same Docker network as the server.

**Target:**
- **UDP Server (Dev Mode):** `127.0.0.1:8053`
- **Production Server:** `<your-server-ip>:53` (or 853 for DoT, though these tools primarily test UDP/TCP)

---

## 1. Using `dnsperf`

`dnsperf` is a classic tool for measuring the performance of DNS servers. It allows you to send a predefined list of queries and measures the response rate and latency.

### Installation
On macOS (via Homebrew):
```bash
brew install dnsperf
```
On Linux (Ubuntu/Debian):
```bash
sudo apt-get install dnsperf
```

### Usage
`dnsperf` requires a "query file" containing the domains you want to resolve.

#### Step 1: Create a query file (`queries.txt`)
Format: `domain type`
```text
google.com A
example.com A
microsoft.com A
github.com A
apple.com A
```

#### Step 2: Run the test
```bash
# -s: Server IP
# -p: Port
# -d: Query file
# -l: Duration in seconds
# -c: Number of concurrent clients
dnsperf -s 127.0.0.1 -p 8053 -d queries.txt -l 60 -c 20
```

---

## 2. Using `flame` (Flamethrower)

`flame` (by DNS-OARC) is a high-performance C++ DNS stress testing tool. It is extremely efficient and capable of saturating a network link or CPU to evaluate how a server handles extreme load.

### Installation
The easiest way to run `flame` is via Docker:
```bash
docker pull ns1labs/flame
# Run help to verify
docker run --rm ns1labs/flame --help
```

### Usage
The basic syntax is `flame <target> [options]`.

#### Random Query Stress Test
To test the "Simple" UDP implementation without cache interference, use the `randomlabel` generator. This ensures the server must perform an upstream exchange for every request.

```bash
# Target: 127.0.0.1, Port: 8053
# -p: Port
# -Q: Rate of queries per second (QPS)
# -c: Number of concurrent senders
# -g: Generator (randomlabel) with options (label size, count, and total queries)
docker run --rm --net host ns1labs/flame 127.0.0.1 -p 8053 -Q 1000 -c 10 -g randomlabel lblsize=10 lblcount=4 count=10000
```

#### Custom Query List
`flame` primarily uses generators. To use a specific list of queries, check `flame --help` for the `file` generator options.

#### Testing Other Protocols (TCP/DoT)
`flame` can also test the TCP and DoT interfaces:
```bash
# TCP
docker run --rm --net host ns1labs/flame 127.0.0.1 -p 8053 -P tcp

# DoT
docker run --rm --net host ns1labs/flame 127.0.0.1 -p 8853 -P dot
```

---

## Correlation with Observability

While running these tests, you should monitor the indicators defined in [evaluating-udp.md](evaluating-udp.md).

### Scenario A: Validating the "Simple" Solution
1. Start `flame` at 100 QPS.
2. Check Prometheus: `dns_upstream_failures_total` should be 0.
3. Check `htop`: `%sys` CPU should be negligible.
4. Gradually increase QPS to 1k, 5k, 10k.
5. **The "Breaking Point":** Note the QPS at which you see `network_error` in logs or a sharp spike in `%sys` CPU.

### Scenario B: Verifying the Optimization (after implementing Persistent Sockets)
1. Run the same test at the previous "Breaking Point" RPS.
2. **Expected Result:**
    - `%sys` CPU should be significantly lower.
    - p99 latency should be lower and more stable.
    - No `EADDRNOTAVAIL` or `network_error` related to socket churn.
