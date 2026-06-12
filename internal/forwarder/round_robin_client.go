package forwarder

import (
	"context"
	"log/slog"
	rand "math/rand/v2"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/tavsec/gin-healthcheck/checks"
)

type upstreamServer struct {
	config  string
	addr    string
	latency *atomic.Int64 // nanoseconds, EMA
}

type RoundRobinClient struct {
	upstreams []upstreamServer
	logger    *slog.Logger
	metrics   *metrics.DnsMetrics
	client    *dns.Client
}

func resolveUpstream(logger *slog.Logger, upstream string) (string, error) {
	addr := upstream
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return "", errors.Wrapf(err, "failed to resolve upstream %s", addr)
	}

	resolvedAddr := udpAddr.String()
	if resolvedAddr != addr {
		logger.Info("Resolved upstream", "fqdn", upstream, "ip_addr", resolvedAddr)
	}

	return resolvedAddr, nil
}

func NewRoundRobinClient(metrics *metrics.DnsMetrics, readTimeout, writeTimeout, dialTimeout time.Duration, logger *slog.Logger, upstreams ...string) (*RoundRobinClient, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream servers configured")
	}

	client := &dns.Client{
		Net:          "udp",
		DialTimeout:  dialTimeout,
		ReadTimeout:  readTimeout,
		WriteTimeout: writeTimeout,
	}

	resolved := make([]upstreamServer, 0, len(upstreams))
	for _, config := range upstreams {
		addr, err := resolveUpstream(logger, config)
		if err != nil {
			return nil, err
		}
		server := upstreamServer{
			config:  config,
			addr:    addr,
			latency: new(atomic.Int64),
		}
		server.latency.Store(int64(100 * time.Millisecond))
		resolved = append(resolved, server)
	}

	return &RoundRobinClient{
		upstreams: resolved,
		logger:    logger,
		metrics:   metrics,
		client:    client,
	}, nil
}

func (r *RoundRobinClient) Exchange(msg *dns.Msg) (*dns.Msg, string, error) {
	n := len(r.upstreams)
	if n == 0 {
		return nil, "", errors.New("no upstreams available")
	}

	startIdx := r.selectUpstreamIndex()

	var lastErr error
	for i := 0; i < n; i++ {
		idx := (startIdx + i) % n
		server := &r.upstreams[idx]

		start := time.Now()
		resp, _, err := r.client.Exchange(msg, server.addr)
		duration := time.Since(start)

		if err == nil {
			r.recordSuccess(server, duration)
			return resp, server.config, nil
		}

		r.recordFailure(server, duration, err)
		lastErr = errors.Wrapf(err, "upstream %s failed", server.config)
	}
	return nil, "", errors.Wrap(lastErr, "all upstream servers failed")
}

func (r *RoundRobinClient) selectUpstreamIndex() int {
	n := len(r.upstreams)
	weights := make([]float64, n)
	var totalWeight float64
	for i := range r.upstreams {
		lat := r.upstreams[i].latency.Load()
		if lat <= 0 {
			lat = int64(time.Millisecond)
		}
		w := 1.0 / float64(lat)
		weights[i] = w
		totalWeight += w
	}

	randomVal := rand.Float64() * totalWeight
	for i, w := range weights {
		randomVal -= w
		if randomVal <= 0 {
			return i
		}
	}
	return n - 1
}

func (r *RoundRobinClient) recordSuccess(server *upstreamServer, duration time.Duration) {
	var newLat int64
	for {
		oldLat := server.latency.Load()
		newLat = int64(float64(oldLat)*0.7 + float64(duration)*0.3)
		if server.latency.CompareAndSwap(oldLat, newLat) {
			break
		}
	}

	r.metrics.UpstreamLatency.WithLabelValues(server.config).Observe(duration.Seconds())
	r.metrics.UpstreamEMA.WithLabelValues(server.config).Set(float64(newLat) / 1e9)
}

func (r *RoundRobinClient) recordFailure(server *upstreamServer, duration time.Duration, err error) {
	var newLat int64
	for {
		oldLat := server.latency.Load()
		newLat = min(oldLat+int64(500*time.Millisecond), int64(5*time.Second))
		if server.latency.CompareAndSwap(oldLat, newLat) {
			break
		}
	}

	reason := getFailureReason(err)
	r.metrics.UpstreamFailures.WithLabelValues(server.config, reason).Inc()
	r.metrics.UpstreamLatency.WithLabelValues(server.config).Observe(duration.Seconds())
	r.metrics.UpstreamEMA.WithLabelValues(server.config).Set(float64(newLat) / 1e9)
	r.logger.Warn("upstream failure", "upstream", server.config, "reason", reason, "error", err)
}

func getFailureReason(err error) string {
	if err == nil {
		return "none"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "deadline_exceeded"
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "connection_refused"
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return "connection_reset"
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network_error"
	}
	return "other"
}

func (r *RoundRobinClient) Healthchecks() []checks.Check {
	dnsChecks := make([]checks.Check, 0, len(r.upstreams))
	for _, server := range r.upstreams {
		dnsChecks = append(dnsChecks, &DNSCheck{
			client: r.client,
			addr:   server.addr,
			name:   server.config,
		})
	}

	return dnsChecks
}

type DNSCheck struct {
	client *dns.Client
	addr   string
	name   string
}

func (d *DNSCheck) Name() string {
	return "DNS server " + d.name
}

func (d *DNSCheck) Pass() bool {
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)

	_, _, err := d.client.Exchange(msg, d.addr)
	return err == nil
}
