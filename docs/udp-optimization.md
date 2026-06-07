# UDP Upstream Communication Optimization

## Overview
The current implementation of `RoundRobinClient` uses `miekg/dns.Client.Exchange` for communicating with upstream DNS servers. While simple and thread-safe, this approach may introduce performance bottlenecks at high request volumes.

## The Problem
The `Exchange` method in the `miekg/dns` library is a high-level convenience function. For every call, it performs the following sequence:
1. `net.Dial` (creates a new socket)
2. `Write` (sends the DNS query)
3. `Read` (waits for the response)
4. `Close` (destroys the socket)

### Technical Impact
- **CPU Overhead:** Each query triggers multiple system calls (`socket`, `connect`, `sendto`, `recvfrom`, `close`). At thousands of queries per second, this adds significant CPU load.
- **Latency:** The overhead of socket creation and destruction adds a small but constant latency penalty to every request.
- **Socket Churn:** While UDP doesn't suffer from TCP's `TIME_WAIT` state, the high rate of socket creation can still put pressure on the OS kernel and potentially hit limits on the rate of ephemeral port allocation.

## Options for Improvement

### Option 1: Maintain Current "Simple" Approach
Continue using `Exchange`.
- **Pros:** 
    - Extremely simple implementation.
    - No need to manage state or match responses to requests.
    - Native thread-safety provided by the library.
- **Cons:** 
    - Suboptimal CPU usage.
    - Higher latency than persistent connections.

### Option 2: Persistent Sockets with Response Dispatcher (Industrial Approach)
Establish one persistent `net.UDPConn` per upstream server.
- **Implementation:**
    - Create a long-lived UDP socket for each upstream.
    - Implement a background **Dispatcher** goroutine that continuously reads from the socket.
    - Use the **DNS Transaction ID (TXID)** to match incoming responses to the original waiting requests using a concurrency-safe map of channels.
- **Pros:** 
    - Maximum performance and lowest latency.
    - Minimal system call overhead.
- **Cons:** 
    - Significant increase in complexity.
    - Must handle TXID collisions and timeout management manually.

### Option 3: Socket Pooling (Middle Ground)
Maintain a small pool of pre-allocated sockets per upstream.
- **Implementation:**
    - A pool (e.g., 10-50 sockets) is maintained for each upstream.
    - Requests lease a socket, use it for one exchange, and return it.
- **Pros:** 
    - Reduces socket churn and CPU overhead compared to Option 1.
    - Simpler than implementing a full dispatcher.
- **Cons:** 
    - Risk of pool exhaustion under extreme load.
    - Still involves some management overhead.

## Investigation Plan
To determine if the "Simple" solution is sufficient, we will perform a benchmark test:
1. **Load Test:** Generate a high volume of DNS queries (e.g., 1k-10k QPS).
2. **Metrics Collection:**
    - Monitor CPU utilization of the `dot-block` process.
    - Measure p99 latency of upstream requests.
    - Monitor system-level socket creation rates using `ss` or `netstat`.
3. **Analysis:** Compare results against the available hardware resources to see if the overhead is actually a bottleneck for the target use case.

## Implementation Notes (for Option 2)
If Option 2 is chosen:
- Use a `map[uint16]chan *dns.Msg` for the registry.
- Ensure a `sync.Mutex` or `sync.Map` protects the registry.
- Implement a "reaper" or use `time.After` on the channels to prevent memory leaks from unanswered queries.
