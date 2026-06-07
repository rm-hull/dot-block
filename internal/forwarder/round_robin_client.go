package forwarder

import (
	"context"
	"log/slog"
	"net"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/tavsec/gin-healthcheck/checks"
)

type RoundRobinClient struct {
	upstreams         []string          // Original configuration strings
	resolvedUpstreams map[string]string // Mapping from config string to resolved IP:port
	counter           uint32
	logger            *slog.Logger
	metrics           *metrics.DnsMetrics
	client            *dns.Client
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

	resolved := make(map[string]string, len(upstreams))
	for _, upstream := range upstreams {
		addr, err := resolveUpstream(logger, upstream)
		if err != nil {
			return nil, err
		}
		resolved[upstream] = addr
	}

	return &RoundRobinClient{
		upstreams:         upstreams,
		resolvedUpstreams: resolved,
		logger:            logger,
		metrics:           metrics,
		client:            client,
	}, nil
}

func (r *RoundRobinClient) Exchange(msg *dns.Msg) (*dns.Msg, string, error) {
	n := uint32(len(r.upstreams))
	start := uint32(atomic.AddUint32(&r.counter, 1) - 1)

	var lastErr error
	for i := range n {
		upstream := r.upstreams[(start+i)%n]
		addr := r.resolvedUpstreams[upstream]

		resp, _, err := r.client.Exchange(msg, addr)
		if err == nil {
			return resp, upstream, nil
		}

		reason := getFailureReason(err)
		r.metrics.UpstreamFailures.WithLabelValues(upstream, reason).Inc()
		r.logger.Warn("upstream failure", "upstream", upstream, "reason", reason, "error", err)

		lastErr = errors.Wrapf(err, "upstream %s failed", upstream)
	}
	return nil, "", errors.Wrap(lastErr, "all upstream servers failed")
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
	for _, upstream := range r.upstreams {
		dnsChecks = append(dnsChecks, &DNSCheck{
			client: r.client,
			addr:   r.resolvedUpstreams[upstream],
			name:   upstream,
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
