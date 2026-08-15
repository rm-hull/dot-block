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
package limiter

import (
	"net"
	"sync"
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

type noopMetrics struct{}

func (noopMetrics) IncRateLimited(Reason) {}
func (noopMetrics) SetTrackedIPs(int)     {}

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

// Clock abstracts time so tests can run deterministically instead of
// depending on real sleeps.
type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Limiter is safe for concurrent use.
type Limiter struct {
	cfg     *config.RateLimitConfig
	clock   Clock
	metrics Metrics

	mu      sync.Mutex // guards buckets/nx maps only; bans has its own lock
	buckets *lru.Cache[string, *bucketEntry]
	nx      *lru.Cache[string, *nxEntry]

	bansMu sync.RWMutex
	bans   map[string]time.Time // ip -> ban expiry

	stopReaper chan struct{}
}

// Option configures optional dependencies (metrics, clock) at construction.
type Option func(*Limiter)

func WithMetrics(m Metrics) Option { return func(l *Limiter) { l.metrics = m } }
func WithClock(c Clock) Option     { return func(l *Limiter) { l.clock = c } }

func New(cfg *config.RateLimitConfig, opts ...Option) (*Limiter, error) {
	buckets, err := lru.New[string, *bucketEntry](cfg.MaxTrackedIPs)
	if err != nil {
		return nil, err
	}
	nx, err := lru.New[string, *nxEntry](cfg.MaxTrackedIPs)
	if err != nil {
		return nil, err
	}

	l := &Limiter{
		cfg:        cfg,
		clock:      realClock{},
		metrics:    noopMetrics{},
		buckets:    buckets,
		nx:         nx,
		bans:       make(map[string]time.Time),
		stopReaper: make(chan struct{}),
	}
	for _, opt := range opts {
		opt(l)
	}

	if cfg.Enabled && cfg.ReapInterval > 0 {
		go l.reapLoop()
	}
	return l, nil
}

func (l *Limiter) Close() {
	select {
	case <-l.stopReaper:
		// already closed
	default:
		close(l.stopReaper)
	}
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

	now := l.clock.Now()

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

// RecordResult should be called once the resolver/cache has produced a
// response, so NXDOMAIN-flood detection can be evaluated independently of
// the RPS gate above. rcode is the DNS response code (use dns.RcodeNameError
// from miekg/dns for NXDOMAIN).
//
// If this call causes the IP to trip the NXDOMAIN threshold, it is banned
// for cfg.BanDuration and the caller does not need to do anything further —
// subsequent Allow() calls will reject it.
func (l *Limiter) RecordResult(ip string, isNXDOMAIN bool) {
	if !l.cfg.Enabled || l.cfg.NXDOMAINWindow <= 0 {
		return
	}

	now := l.clock.Now()

	l.mu.Lock()
	entry, ok := l.nx.Get(ip)
	if !ok || now.Sub(entry.windowStart) > l.cfg.NXDOMAINWindow {
		entry = &nxEntry{windowStart: now}
		l.nx.Add(ip, entry)
	}
	entry.total++
	if isNXDOMAIN {
		entry.nxdomain++
	}
	total, nxdomain := entry.total, entry.nxdomain
	l.mu.Unlock()

	if total < l.cfg.NXDOMAINMinQueries {
		return
	}
	ratio := float64(nxdomain) / float64(total)
	if ratio >= l.cfg.NXDOMAINThreshold {
		l.ban(ip, now)
		l.metrics.IncRateLimited(ReasonNXDOMAIFlood)
	}
}

func (l *Limiter) tokenBucketFor(ip string, now time.Time) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

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

// reapLoop periodically evicts token-bucket and ban entries that have been
// idle longer than cfg.IdleTTL. This runs alongside dot-block's existing
// cron-based cache reaper rather than introducing a second scheduling
// mechanism — wire ReapInterval to the same `--cron-schedule` pattern if
// you'd rather drive it from the existing cron dispatcher instead of this
// goroutine.
func (l *Limiter) reapLoop() {
	ticker := time.NewTicker(l.cfg.ReapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-l.stopReaper:
			return
		case <-ticker.C:
			l.reapOnce(l.clock.Now())
		}
	}
}

func (l *Limiter) reapOnce(now time.Time) {
	l.mu.Lock()
	for _, ip := range l.buckets.Keys() {
		entry, ok := l.buckets.Peek(ip)
		if ok && now.Sub(entry.lastSeen) > l.cfg.IdleTTL {
			l.buckets.Remove(ip)
		}
	}
	for _, ip := range l.nx.Keys() {
		entry, ok := l.nx.Peek(ip)
		if ok && now.Sub(entry.windowStart) > l.cfg.NXDOMAINWindow {
			l.nx.Remove(ip)
		}
	}
	trackedIPs := l.buckets.Len()
	l.mu.Unlock()
	l.metrics.SetTrackedIPs(trackedIPs)

	l.bansMu.Lock()
	for ip, until := range l.bans {
		if now.After(until) {
			delete(l.bans, ip)
		}
	}
	l.bansMu.Unlock()
}

// ClientIP strips the port from a "host:port" address, which is what you'll
// typically get from net.Conn.RemoteAddr().String() or a UDP packet's
// source address. Falls back to returning the input unchanged if it's not
// in host:port form (e.g. already a bare IP).
func ClientIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
