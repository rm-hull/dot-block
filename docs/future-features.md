# Future Features & Roadmap

This document outlines proposed enhancements for `dot-block` to evolve it from a secure DNS forwarder into a production-grade, hardened DNS gateway.

## 🔒 Privacy: Closing the "Last Mile" Gap
Currently, `dot-block` provides DNS-over-TLS (DoT) to the client, but forwards queries to upstream resolvers via plain UDP. This leaves the path between `dot-block` and the upstream resolver vulnerable to eavesdropping.

- **Upstream DoT/DoH Support:** 
  - Implement the ability to specify upstream resolvers using `tls://` or `https://` prefixes.
  - Use encrypted channels for all outbound queries, completing the end-to-end encryption chain.

## 🛡️ Security: Hardening and Resilience
To prevent the server from being abused or becoming a vector for DNS amplification attacks, the following security measures are proposed:

- **Per-IP Rate Limiting:** 
  - Implement token-bucket rate limiting in `HandleDNSRequest` to restrict the number of queries per second (QPS) from a single source IP.
- **Response Rate Limiting (RRL):** 
  - Implement RRL to mitigate the risk of the server being used in DNS amplification DDoS attacks.

## ⚡ Performance: Intelligent Steering
The `RoundRobinClient` uses latency-based routing to account for network conditions.

- **Proactive Health Management:** 
  - Move health checks to a dedicated background worker.
  - Maintain a "Healthy Pool" of upstreams to avoid the latency penalty of discovering a failed server during a live client request.

## 🚀 Features: Expanding the Ecosystem
Leveraging the existing HTTP infrastructure, `dot-block` can support a wider range of clients and configurations.

- **DNS-over-HTTPS (DoH) Support:** 
  - Add a `/dns-query` endpoint to the HTTP server.
  - Enable native browser support (Chrome, Firefox) for DoH without requiring system-wide DoT settings.
- **Advanced Blocklist Management:** 
  - **Allow-lists:** Implement a whitelist to override blocks for specific domains.
  - **Dynamic Updates:** Enhance the `/reload` API to allow updating blocklist URLs without requiring a restart.

---

## Summary Matrix

| Feature | Category | Effort | Priority | Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Upstream DoT/DoH** | Privacy | Medium | **High** | End-to-End Privacy |
| **Rate Limiting** | Security | Medium | **High** | Server Stability |
| **DoH Support** | Feature | Low | Medium | Client Versatility |
| **Proactive Health** | Performance | Low | Low | Reliable Failover |
