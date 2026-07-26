# Implementation Plan: Fix CNAME Chain Caching in DNS Dispatcher

## Goal
Restore high cache hit rates (~50-60%) by fixing answer filtering for upstream responses so that CNAME chains and their target records are correctly retained in cache entries, while still preventing multi-question response cross-contamination (Issue #225).

---

## Technical Design

When an upstream DNS response is received for a set of unanswered questions, we need to populate cache entries for each question (`q`) using a smarter filtering algorithm that follows CNAME chains.

### 1. CNAME Chain Resolution Algorithm per Question
For each question `q`:
1. **Initialize a set of target names/keys to collect**: Start with the question itself:
   - `targetName = dns.Fqdn(q.Name)`
   - `targetType = q.Qtype` (and also look for `dns.TypeCNAME` for any name in our chain).
2. **Iterate & Follow CNAMEs**:
   - Scan `upstreamResp.Answer` for any `CNAME` record where `dns.Fqdn(ans.Header().Name)` matches our current `targetName`.
   - If a matching `CNAME` is found:
     - Include the `CNAME` record in `qAnswers`.
     - Add the CNAME's target (`dns.Fqdn(cnameRec.Target)`) to our set of target names to inspect.
     - Repeat until no further CNAME records match or max recursion depth (e.g., 8 to prevent loops) is reached.
3. **Collect Final Matching Records**:
   - Include any records whose name matches any collected target name in our chain **and** whose type matches either the original query type (`q.Qtype`) or is a `CNAME`.
   - Also ensure we capture any additional glue/matching records associated with the final target names (e.g., `A` and `AAAA` records for the final CNAME target).

---

## Detailed Code Changes (`internal/forwarder/dispatcher.go`)

Replace the naive filtering block:

```go
// Process unanswered questions and cache the results
for _, q := range unansweredQuestions {
    cacheKey := getCacheKey(&q, requestCtx.subnet)
    qKey := dns.Fqdn(q.Name) + ":" + dns.TypeToString[q.Qtype]

    var qAnswers []dns.RR
    for _, ans := range upstreamResp.Answer {
        ansKey := dns.Fqdn(ans.Header().Name) + ":" + dns.TypeToString[ans.Header().Rrtype]
        if ansKey == qKey {
            qAnswers = append(qAnswers, ans)
        }
    }
    // ...
}
```

With a robust CNAME-aware extraction helper function:

```go
func extractAnswersForQuestion(q dns.Question, answers []dns.RR) []dns.RR {
    var qAnswers []dns.RR
    
    // Track names we are interested in for this question (starting with q.Name, expanding via CNAME targets)
    relevantNames := make(map[string]bool)
    currentName := dns.Fqdn(q.Name)
    relevantNames[currentName] = true

    // Build map of CNAME targets to follow chains
    cnameMap := make(map[string]string) // owner -> target
    for _, ans := range answers {
        if cname, ok := ans.(*dns.CNAME); ok {
            cnameMap[dns.Fqdn(cname.Hdr.Name)] = dns.Fqdn(cname.Target)
        }
    }

    // Follow CNAME chain up to max depth 8
    for i := 0; i < 8; i++ {
        target, exists := cnameMap[currentName]
        if !exists {
            break
        }
        currentName = target
        relevantNames[currentName] = true
    }

    // Collect all answers matching relevant names (CNAMEs, plus target A/AAAA records)
    for _, ans := range answers {
        ansName := dns.Fqdn(ans.Header().Name)
        if relevantNames[ansName] {
            // Include if it's a CNAME, or matches the query type, or if it's an A/AAAA record for a CNAME target
            if ans.Header().Rrtype == q.Qtype || ans.Header().Rrtype == dns.TypeCNAME {
                qAnswers = append(qAnswers, ans)
            } else if ansName != dns.Fqdn(q.Name) && (ans.Header().Rrtype == dns.TypeA || ans.Header().Rrtype == dns.TypeAAAA) {
                // Include A/AAAA records for CNAME targets
                qAnswers = append(qAnswers, ans)
            }
        }
    }

    return qAnswers
}
```

---

## Test Plan

1. **Add Unit Tests (`internal/forwarder/dispatcher_test.go`)**:
   - Test `TestResolveUpstreamCNAMECaching`:
     - Mock upstream returning a CNAME (`example.com -> cdn.example.com`) and an A record (`cdn.example.com -> 1.2.3.4`).
     - Verify that querying `example.com A` successfully caches the response including both the CNAME and the A record.
     - Verify subsequent cache hit returns both records correctly.
2. **Regression Testing**:
   - Run `go test ./...` to ensure `TestResolveUpstreamCacheKeyCollision` (for multi-question isolation) still passes successfully.
3. **Build & Lint Verification**:
   - Run `go build ./...`
   - Run `go vet ./...`
   - Run `go fmt ./...`
