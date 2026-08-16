// Package limiter provides per-client-IP rate limiting and abuse detection
// (NXDOMAIN/random-subdomain flood mitigation) shared across the UDP, TCP,
// DoT and DoH listeners.
//
// Design notes:
//   - Per-IP token buckets are stored in a bounded LRU so a distributed
//     "low and slow" flood from many source IPs can't grow memory without
//     limit (that would just be a different flavour of the same DoS the
//     feature is meant to prevent).
//   - RPS limiting and NXDOMAIN-flood detection are tracked separately.
//     A busy household with several devices can legitimately generate a
//     high query rate; that's not the same signal as a high proportion of
//     queries resolving to NXDOMAIN, which is characteristic of cache-buster
//     / random-subdomain attacks. Conflating the two either bans real users
//     or lets NXDOMAIN floods slip through under generous RPS limits.
//   - Bans are checked before the token bucket, so an already-banned IP is
//     rejected in a single map lookup rather than repeatedly failing (and
//     paying the cost of) a rate check.
//   - NXDOMAIN result recording is asynchronous: results are sent over a
//     buffered channel to a dedicated goroutine that owns the NX window
//     LRU. This keeps the per-request hot path (Allow → token bucket check)
//     free of mutex contention with flood-detection bookkeeping, mirroring
//     the async snapshot-worker pattern in the DNS dispatcher.
package limiter

import (
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/rm-hull/dot-block/internal/config"
	"golang.org/x/time/rate"
)

type Reason string

const (
	ReasonNone         Reason = ""
	ReasonExceededRPS  Reason = "exceeded_rps"
	ReasonNXDOMAIFlood Reason = "nxdomain_flood"
	ReasonBanned       Reason = "banned"
)

// Metrics is the minimal surface the limiter needs from a metrics backend.
// Implement this against Prometheus counters/gauges in internal/metrics;
// kept as an interface here so limiter package has no direct Prometheus
// dependency and stays easy to unit test.
type Metrics interface {
	IncRateLimited(reason Reason)
	SetTrackedIPs(n int)
}

// bucketEntry pairs a token bucket with a last-seen timestamp so the reaper
// can evict idle IPs without waiting for the LRU to fill up.
type bucketEntry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// nxEntry tracks a rolling count of total vs NXDOMAIN responses for one IP.
// A simple two-counter-with-window-reset scheme is used instead of a true
// sliding window: cheap, and precise enough for abuse detection (as opposed
// to, say, billing).
type nxEntry struct {
	windowStart time.Time
	total       int
	nxdomain    int
}

// nxResult is sent over nxResultCh to the background goroutine for
// asynchronous NXDOMAIN-flood detection. A non-zero flush field turns the
// entry into a flush sentinel (used by Flush for testing).
type nxResult struct {
	ip         string
	isNXDOMAIN bool
	flush      chan struct{} // non-nil → flush sentinel
}

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg     *config.RateLimitConfig
	metrics Metrics

	bucketsMu sync.Mutex
	buckets   *lru.Cache[string, *bucketEntry]

	// nxResultCh is a buffered channel for asynchronous NXDOMAIN result
	// processing. The processNxResults goroutine is the sole owner of the
	// nx LRU, so no mutex is needed for it.
	nxResultCh chan nxResult
	reapCh     chan struct{}

	bansMu sync.RWMutex
	bans   map[string]time.Time // ip -> ban expiry

	// closed is set to true once Close has been called.
	closed atomic.Bool
	done   chan struct{} // closed when the background goroutine exits
}

func New(cfg *config.RateLimitConfig, metrics Metrics) (*Limiter, error) {
	maxTrackedIPs := cfg.MaxTrackedIPs
	if maxTrackedIPs <= 0 {
		maxTrackedIPs = 10000
	}
	buckets, err := lru.New[string, *bucketEntry](maxTrackedIPs)
	if err != nil {
		return nil, err
	}

	l := &Limiter{
		cfg:        cfg,
		metrics:    metrics,
		buckets:    buckets,
		bans:       make(map[string]time.Time),
		done:       make(chan struct{}),
	}

	// Start the NX result processing goroutine only when NXDOMAIN flood
	// detection is enabled. The goroutine owns the nx LRU.
	if cfg.Enabled && cfg.NXDOMAINWindow > 0 {
		l.nxResultCh = make(chan nxResult, 4096)
		l.reapCh = make(chan struct{}, 1)
		go l.processNxResults(maxTrackedIPs)
	}

	return l, nil
}

// Allow reports whether a query from ip should proceed. Call this as early
// as possible in the request path — right after extracting the client IP,
// before any cache lookup or upstream dispatch — so rejected traffic costs
// as little as possible.
//
// ip should already have any port stripped (see ClientIP helper below).
func (l *Limiter) Allow(ip string) (bool, Reason) {
	if !l.cfg.Enabled {
		return true, ReasonNone
	}

	now := time.Now()

	// Cheapest check first: is this IP currently banned?
	if until, banned := l.isBanned(ip, now); banned {
		_ = until
		l.metrics.IncRateLimited(ReasonBanned)
		return false, ReasonBanned
	}

	if !l.tokenBucketFor(ip, now).AllowN(now, 1) {
		l.metrics.IncRateLimited(ReasonExceededRPS)
		return false, ReasonExceededRPS
	}

	return true, ReasonNone
}

// RetryAfter returns the suggested duration a client should wait before
// retrying after being rejected by Allow. For banned IPs, this is the
// remaining ban duration. For RPS exhaustion (token bucket empty), it is
// approximately 1/RequestsPerSecond, rounded up to at least 1 second.
func (l *Limiter) RetryAfter(ip string) time.Duration {
	if !l.cfg.Enabled {
		return 0
	}

	now := time.Now()

	if until, ok := l.isBanned(ip, now); ok {
		return time.Until(until)
	}

	// Token bucket exhausted — estimate the time until the next token.
	wait := time.Second
	if l.cfg.RequestsPerSecond > 0 {
		wait = time.Duration(float64(time.Second) / l.cfg.RequestsPerSecond)
	}
	if wait < time.Second {
		wait = time.Second
	}
	return wait
}

// RecordResult sends an NXDOMAIN result for asynchronous processing by the
// background goroutine. Non-blocking — if the channel is full the result is
// dropped, making flood detection slightly less precise under extreme load
// (acceptable: flood detection is defense-in-depth, not the primary rate
// gate). Skip this for DoH — the Gin middleware calls RecordResult
// directly after the resolver has produced the response.
func (l *Limiter) RecordResult(ip string, isNXDOMAIN bool) {
	if !l.cfg.Enabled || l.cfg.NXDOMAINWindow <= 0 || l.closed.Load() {
		return
	}

	select {
	case l.nxResultCh <- nxResult{ip: ip, isNXDOMAIN: isNXDOMAIN}:
	default:
		// Channel full — drop result. Under extreme flooding this only
		// makes NXDOMAIN flood detection slightly less precise.
	}
}

// Flush waits for all pending NXDOMAIN results to be processed.
// Intended for testing.
func (l *Limiter) Flush() {
	if l.nxResultCh == nil || l.closed.Load() {
		return
	}

	done := make(chan struct{})
	select {
	case l.nxResultCh <- nxResult{flush: done}:
	default:
		return
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}

// processNxResults is the sole owner of the nx LRU. It reads NXDOMAIN
// results from the channel and updates the flood-detection state.
func (l *Limiter) processNxResults(maxTrackedIPs int) {
	nx, err := lru.New[string, *nxEntry](maxTrackedIPs)
	if err != nil {
		close(l.done)
		return
	}

	for {
		select {
		case result, ok := <-l.nxResultCh:
			if !ok {
				close(l.done)
				return
			}
			if result.flush != nil {
				close(result.flush)
				continue
			}
			l.recordNxResult(nx, result.ip, result.isNXDOMAIN)
		case <-l.reapCh:
			l.reapNx(nx)
		}
	}
}

// recordNxResult is called by the background goroutine only.
func (l *Limiter) recordNxResult(nx *lru.Cache[string, *nxEntry], ip string, isNXDOMAIN bool) {
	now := time.Now()

	entry, ok := nx.Get(ip)
	if !ok || now.Sub(entry.windowStart) > l.cfg.NXDOMAINWindow {
		entry = &nxEntry{windowStart: now}
		nx.Add(ip, entry)
	}
	entry.total++
	if isNXDOMAIN {
		entry.nxdomain++
	}
	total, nxdomain := entry.total, entry.nxdomain

	if total < l.cfg.NXDOMAINMinQueries {
		return
	}
	ratio := float64(nxdomain) / float64(total)
	if ratio >= l.cfg.NXDOMAINThreshold {
		l.ban(ip, now)
		l.metrics.IncRateLimited(ReasonNXDOMAIFlood)
	}
}

// reapNx is called by the background goroutine only (via reapCh).
func (l *Limiter) reapNx(nx *lru.Cache[string, *nxEntry]) {
	now := time.Now()
	for _, ip := range nx.Keys() {
		entry, ok := nx.Peek(ip)
		if ok && now.Sub(entry.windowStart) > l.cfg.NXDOMAINWindow {
			nx.Remove(ip)
		}
	}
}

func (l *Limiter) tokenBucketFor(ip string, now time.Time) *rate.Limiter {
	l.bucketsMu.Lock()
	defer l.bucketsMu.Unlock()

	entry, ok := l.buckets.Get(ip)
	if !ok {
		entry = &bucketEntry{
			limiter: rate.NewLimiter(rate.Limit(l.cfg.RequestsPerSecond), l.cfg.Burst),
		}
		l.buckets.Add(ip, entry)
		l.metrics.SetTrackedIPs(l.buckets.Len())
	}
	entry.lastSeen = now
	return entry.limiter
}

func (l *Limiter) isBanned(ip string, now time.Time) (time.Time, bool) {
	l.bansMu.RLock()
	until, ok := l.bans[ip]
	l.bansMu.RUnlock()
	if !ok {
		return time.Time{}, false
	}
	if now.After(until) {
		// Expired — clean it up lazily rather than waiting for the reaper.
		l.bansMu.Lock()
		delete(l.bans, ip)
		l.bansMu.Unlock()
		return time.Time{}, false
	}
	return until, true
}

func (l *Limiter) ban(ip string, now time.Time) {
	l.bansMu.Lock()
	l.bans[ip] = now.Add(l.cfg.BanDuration)
	l.bansMu.Unlock()
}

// Reap evicts token-bucket, NXDOMAIN-window, and ban entries that have been
// idle longer than the configured thresholds. Call this periodically — in
// dot-block it is wired to the existing cron scheduler rather than running
// on its own goroutine.
func (l *Limiter) Reap() {
	now := time.Now()

	// Reap token buckets (directly — owns its own mutex).
	l.bucketsMu.Lock()
	for _, ip := range l.buckets.Keys() {
		entry, ok := l.buckets.Peek(ip)
		if ok && now.Sub(entry.lastSeen) > l.cfg.IdleTTL {
			l.buckets.Remove(ip)
		}
	}
	trackedIPs := l.buckets.Len()
	l.bucketsMu.Unlock()
	l.metrics.SetTrackedIPs(trackedIPs)

	// Reap bans (directly — owns its own RWMutex).
	l.bansMu.Lock()
	for ip, until := range l.bans {
		if now.After(until) {
			delete(l.bans, ip)
		}
	}
	l.bansMu.Unlock()

	// Signal the background goroutine to reap NX window entries.
	// Non-blocking: if a reap is already pending, skip.
	if l.reapCh != nil && !l.closed.Load() {
		select {
		case l.reapCh <- struct{}{}:
		default:
		}
	}
}

// Close stops the background goroutine and releases resources.
func (l *Limiter) Close() {
	if !l.closed.CompareAndSwap(false, true) {
		return // already closed
	}
	if l.nxResultCh != nil {
		close(l.nxResultCh)
		<-l.done
	}
}

// BannedIPs returns a snapshot of currently-banned IPs and the time their
// ban expires. The map is a copy — safe to iterate without holding the lock.
func (l *Limiter) BannedIPs() map[string]time.Time {
	l.bansMu.RLock()
	defer l.bansMu.RUnlock()

	out := make(map[string]time.Time, len(l.bans))
	for ip, until := range l.bans {
		out[ip] = until
	}
	return out
}
