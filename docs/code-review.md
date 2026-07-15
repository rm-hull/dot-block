# Code Review: DoT Block (DNS-over-TLS Server)

**Date**: 2026-01-15
**Reviewer**: AI Assistant
**Status**: Production-Ready with Minor Improvements Needed (B+)

---

## Executive Summary

DoT Block is a well-architected DNS-over-TLS forwarder with strong foundations in Go. The codebase demonstrates solid understanding of concurrent patterns, DNS protocol handling, and production-grade observability. Key strengths include comprehensive test coverage, thoughtful error handling, and modern tooling integration.

**Overall Grade**: B+ (Production-Ready with Minor Improvements Needed)

---

## Architecture & Design

### Strengths

- **Clean Separation of Concerns**: Clear module boundaries (`forwarder`, `blocklist`, `http`, `metrics`, `logging`)
- **Good Use of Go Idioms**: `context.Context` propagation, `errgroup` for concurrent server management, `slog` for structured logging
- **Observability-First**: Integrated Sentry, Prometheus, OpenTelemetry tracing, and SSE for real-time metrics
- **TLS Security**: Proper TLS config with modern cipher suites and certmagic for ACME automation
- **DNS Protocol Handling**: Correct handling of multiple question types, ECS support, and DNS-SD short-circuiting

### Weaknesses & Recommendations

#### 1. TTL Handling Inconsistency ⚠️

**Location**: `main.go:99`, `dispatcher.go:258`

```go
// Current:
app.CacheTtlFloor, "cache-ttl-floor", 3600*time.Second, // 1-hour floor
```

**Issue**: 1-hour TTL floor is aggressive for DNS. Standard cache behavior allows shorter TTLs for dynamic content.

**Recommendation**: Reduce default to `30*time.Second` or make it configurable per-query-type. Consider:

```go
// dispatcher.go: update TTL logic
effectiveTTL := time.Duration(upstreamTTL) * time.Second
if !d.isFreshnessSensitive(&q) && effectiveTTL < d.ttlFloor {
    effectiveTTL = d.ttlFloor
}
// Add special case for high-frequency records (news, CDNs)
if d.shouldAllowShortTTL(q) {
    effectiveTTL = time.Duration(upstreamTTL) * time.Second
}
```

#### 2. Error Handling Gaps ⚠️

**Location**: `dispatcher.go:333`

```go
func (d *DNSDispatcher) reportError(...) {
    if d.noisefilter != nil {
        if d.noisefilter.ShouldSuppress(...) {
            requestCtx.snapshot.SetErrorCategory(errorCategory)
            return // ❌ Error classified but not logged/recorded
        }
    }
    if ShouldLog(err) {
        // ✅ Only logs if not suppressed
    }
}
```

**Issue**: Errors filtered by noise filter are still recorded in snapshots but not logged, creating "silent" error categories.

**Recommendation**: Add silent error tracking metrics:
```go
requestCtx.snapshot.SetErrorCategory(errorCategory)
d.metrics.SilencedErrors.WithLabelValues(errorCategory).Inc()
```

#### 3. Concurrency Safety ⚠️

**Location**: `cache.go:41`

```go
func (dc *DNSCache) Set(key string, values []dns.RR, ttl time.Duration) {
    select {
    case dc.updateCh <- cacheUpdate{...}:
    default:
        // ❌ Race condition: onDrop callback might access dropped data
        if dc.onDrop != nil {
            dc.onDrop()
        }
    }
}
```

**Issue**: `onDrop` callback executes after the default case but before the channel receive succeeds. If the callback checks cache state, it's a race.

**Recommendation**: Deferral pattern:
```go
func (dc *DNSCache) Set(...) {
    select {
    case dc.updateCh <- update:
        return
    default:
        dropped := true
        // Try to send with timeout?
        select {
        case dc.updateCh <- update:
            dropped = false
        case <-time.After(10 * time.Millisecond):
        }
        if dropped && dc.onDrop != nil {
            dc.onDrop()
        }
    }
}
```

---

## Testing Coverage

### Strengths

- **Excellent dispatcher tests**: 14+ test cases covering mixed blocked/upstream, cache behaviors, ECS injection
- **Mock-based testing**: Proper use of `testify/mock` for `dns.ResponseWriter`
- **Integration-style tests**: Real DNS servers started for end-to-end validation

### Gaps & Recommendations

#### 1. Missing Edge Cases

**Locations**: `dispatcher_test.go`, `cache_test.go`

**Issue**: No tests for:
- Concurrent cache eviction under load
- Noise filter update mid-request
- Blocklist reload during active queries
- GeoIP database rotation
- ECS with malformed client IPs

**Recommendation**: Add property-based tests for cache behavior:
```go
func TestCache_LRU_Eviction(t *testing.T) {
    cache := NewDNSCache(10, logger)
    // Fill cache to capacity
    // Verify LRU eviction order
    // Verify no data races under concurrent set/get
}
```

#### 2. Negative Testing Missing

**Issue**: Missing tests for:
- Upstream timeout handling
- Invalid DNS message format
- Malformed ECS options
- Blocklist Bloom filter false positives

**Recommendation**: Add explicit negative test cases in `dispatcher_test.go`.

---

## Security Review

### ✅ Strengths

- TLS 1.2/1.3 with modern cipher suites
- Certmagic for automated certificate management
- PROXY protocol support with whitelist policy
- No hardcoded credentials
- Proper input validation on DNS queries

### ⚠️ Concerns

#### 1. Trusted Proxies Bypass

**Location**: `app.go:344`

```go
if len(app.TrustedProxies) > 0 {
    // Whitelist policy: only trusted proxies can send client IP
} else if app.RequireProxyProtocol {
    // REQUIRE policy: all clients must send PROXY header
} else {
    // ❌ USE policy: optional, allows IP spoofing
    proxyListener = &proxyproto.Listener{
        Policy: func(upstream net.Addr) (proxyproto.Policy, error) {
            return proxyproto.USE, nil // Vulnerable to spoofing
        },
    }
}
```

**Issue**: Default USE policy allows clients to spoof their IP by sending arbitrary PROXY headers.

**Recommendation**: Default to REQUIRE in production, warn if USE is used without trusted proxies:
```go
if !app.RequireProxyProtocol && len(app.TrustedProxies) == 0 {
    app.Logger.Warn(
        "Running with optional PROXY protocol; spoofing risk",
        "recommendation", "set --require-proxy-protocol or --trusted-proxies"
    )
}
```

#### 2. Rate Limiting Missing

**Issue**: No visible rate limiting on HTTP/DoT endpoints for request thrashing protection.

**Recommendation**: Add Gin middleware for rate limiting:
```go
r.Use(limiters.New(&limiters.Options{
    RequestRate: 100, // req/s per IP
    BurstSize:   200,
}))
```

---

## Performance & Scalability

### Strengths

- Weighted round-robin with latency EMA (adaptive)
- Bloom filter for O(1) blocklist lookups
- Cache reaper cron job
- LRU cache eviction

### Recommendations

#### 1. DNS Query Parallelization

**Location**: `dispatcher.go:218`

```go
for _, q := range req.Question {
    answers, rcode, err := d.processQuestion(requestCtx, &q)
    // Sequential processing ❌
}
```

**Issue**: Multiple questions in one query processed sequentially.

**Recommendation**: Parallelize with worker pool:
```go
var wg sync.WaitGroup
answersChan := make(chan answerResult, len(req.Question))

for i := range req.Question {
    wg.Add(1)
    go func(q *dns.Question) {
        defer wg.Done()
        answers, rcode, err := d.processQuestion(requestCtx, q)
        answersChan <- answerResult{q: q, answers: answers, rcode: rcode, err: err}
    }(&req.Question[i])
}
wg.Wait()
close(answersChan)
```

#### 2. Memory Pressure Monitoring

**Issue**: No visible memory usage tracking or OOM protection.

**Recommendation**: Add runtime metrics:
```go
var memStats runtime.MemStats
runtime.ReadMemStats(&memStats)
metrics.MemoryUsage.Set(float64(memStats.Alloc))
```

---

## Code Quality & Style

### ✅ Strengths

- Consistent naming conventions
- Good use of interfaces (`GeoIpLookup`, `DNSClient`)
- Structured logging with context propagation
- Clear error messages with wrapping

### Recommendations

#### 1. TODO Comments

**Location**: `dispatcher.go:69`

```go
defaultTTL: 300, // TODO: pass in
```

**Action**: Convert to configurable flag or remove TODO with implementation.

#### 2. Magic Numbers

**Location**: `round_robin_client.go:95`

```go
if lat <= 0 {
    lat = int64(time.Millisecond) // ❌ Magic value
}
```

**Recommendation**: Define constant:
```go
const MinLatencyEstimate = time.Millisecond
// Usage:
if lat <= 0 {
    lat = int64(MinLatencyEstimate)
}
```

#### 3. Function Length

**Location**: `dispatcher.go:HandleDNSRequest` (180+ lines)

**Issue**: Handles multiple responsibilities (context creation, response building, sending).

**Recommendation**: Extract to smaller functions:
```go
func (d *DNSDispatcher) HandleDNSRequest(source DNSSource) DispatcherFunc {
    return func(writer dns.ResponseWriter, req *dns.Msg) {
        ctx := d.createRequestContext(writer, req, source)
        resp := d.buildResponse(ctx, req)
        d.sendResponse(ctx, writer, resp)
    }
}
```

---

## Build & CI/CD

### Strengths

- Comprehensive GitHub Actions workflows
- Dependabot for dependency updates
- GoReleaser for binary distribution
- Coverage reports in `test-reports/`

### Recommendations

#### 1. Benchmark Tests Missing

**Issue**: No benchmark tests for performance baseline.

**Add**:
```go
func BenchmarkDispatcher_ProcessBlocked(b *testing.B) {
    // Measure blocklist lookup performance
}
```

#### 2. Fuzzing Missing

**Issue**: No fuzzing for DNS parsing or blocklist operations.

**Recommendation**: Add Go 1.18+ fuzz tests:
```go
func FuzzBlocklist_IsBlocked(f *testing.F) {
    f.Fuzz(func(t *testing.T, domain string) {
        _, err := blockList.IsBlocked(domain)
        // Should not panic
    })
}
```

---

## Documentation

### Strengths

- Clear README with usage examples
- AGENTS.md for development workflow
- Generated API docs via web UI

### Gaps

#### 1. Missing Architecture Decision Records (ADRs)

**Issue**: No `docs/adr/` folder despite complex decisions (ECS, bloom filters, etc.)

**Recommendation**: Create ADRs for:
- ECS implementation choice
- Bloom filter vs traditional blocklist
- TLS certificate strategy
- Metrics sampling rate decisions

#### 2. Operational Runbook Missing

**Issue**: No deployment or troubleshooting guide.

**Recommendation**: Add `docs/operational-runbook.md`:
- How to rotate certificates
- Blocklist update troubleshooting
- Metrics tuning guide
- Incident response procedures

---

## Priority Action Items

### High Priority (Fix Now)

1. **Security**: Warn about USE PROXY protocol without trusted proxies
2. **Security**: Add rate limiting middleware
3. **Performance**: Add memory monitoring and OOM protection
4. **Testing**: Add benchmarks for hot paths

### Medium Priority (Next Sprint)

5. **Code Quality**: Extract `HandleDNSRequest` into smaller functions
6. **Testing**: Add fuzzing for DNS parsing
7. **Documentation**: Create ADRs for key decisions
8. **Performance**: Parallelize multi-question processing

### Low Priority (Backlog)

9. **Code Quality**: Replace TODO with configurable TTL
10. **Testing**: Add concurrency stress tests
11. **Documentation**: Add operational runbook
12. **Feature**: Consider per-query-type TTL policies

---

## Final Verdict

This is a **production-quality DNS forwarder** with excellent foundations. The code demonstrates mature Go practices, solid testing, and strong observability. The identified issues are mostly refinements rather than blockers.

**Priority Focus**: Security hardening (rate limiting, PROXY protocol defaults) and performance testing (benchmarks, fuzzing) should be addressed before production deployment.

**Estimated Time to Resolve**: 2-3 sprint cycles (assuming 2 developers)

---

## Appendix: Files Reviewed

- `main.go`
- `internal/app.go`
- `internal/forwarder/dispatcher.go`
- `internal/forwarder/dispatcher_test.go`
- `internal/forwarder/round_robin_client.go`
- `internal/forwarder/cache.go`
- `internal/forwarder/errors.go`
- `internal/blocklist/blocklist.go`
- `internal/metrics/dns_metrics.go`
- `.github/workflows/*.yml`

---

**Review completed by**: AI Assistant
**Reviewed on**: 2026-01-15