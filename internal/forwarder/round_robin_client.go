package forwarder

import (
	"log/slog"
	"net"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/tavsec/gin-healthcheck/checks"
)

type RoundRobinClient struct {
	upstreams []string
	pools     map[string]*ConnPool
	counter   uint32
	logger    *slog.Logger
	metrics   *metrics.DnsMetrics
}

type pooledConn struct {
	conn       *dns.Conn
	returnedAt time.Time
}

type ConnPool struct {
	conns      chan *pooledConn
	addr       string
	client     *dns.Client
	metrics    *metrics.DnsMetrics
	maxIdleAge time.Duration
	dialTimeout time.Duration
}

func NewConnPool(metrics *metrics.DnsMetrics, addr string, client *dns.Client, poolSize int, dialTimeout time.Duration) *ConnPool {
	return &ConnPool{
		conns:      make(chan *pooledConn, poolSize),
		addr:       addr,
		client:     client,
		metrics:    metrics,
		maxIdleAge: 8 * time.Second, // Close connections idle for more than 8 seconds
		dialTimeout: dialTimeout,
	}
}

func (p *ConnPool) dial() (*dns.Conn, error) {
	d := net.Dialer{Timeout: p.dialTimeout}
	conn, err := d.Dial("tcp", p.addr)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to dial %s", p.addr)
	}
	return &dns.Conn{Conn: conn}, nil
}

func (p *ConnPool) acquire() (*dns.Conn, bool, error) {
	for {
		select {
		case pc := <-p.conns:
			if time.Since(pc.returnedAt) > p.maxIdleAge {
				_ = pc.conn.Close() // stale, discard and try next
				continue
			}
			return pc.conn, true, nil
		default:
			conn, err := p.dial()
			return conn, false, err
		}
	}
}

func (p *ConnPool) release(conn *dns.Conn) {
	select {
	case p.conns <- &pooledConn{conn: conn, returnedAt: time.Now()}:
	default:
		_ = conn.Close() // pool full, discard
		p.metrics.PoolEvictions.WithLabelValues(p.addr).Inc()
	}
}

func (p *ConnPool) Exchange(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	conn, reused, err := p.acquire()
	if err != nil {
		return nil, 0, err
	}

	resp, rtt, err := p.client.ExchangeWithConn(msg, conn)
	if err != nil {
		_ = conn.Close() // discard broken conn
		if reused {
			p.metrics.PooledConnDeaths.WithLabelValues(p.addr).Inc()
		}
		return nil, 0, err
	}

	p.release(conn)
	return resp, rtt, nil
}

func NewRoundRobinClient(metrics *metrics.DnsMetrics, readTimeout, dialTimeout time.Duration, poolSize int, logger *slog.Logger, upstreams ...string) (*RoundRobinClient, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream servers configured")
	}

	if poolSize < 0 {
		return nil, errors.New("connection pool size cannot be negative")
	}

	client := &dns.Client{Timeout: readTimeout, Net: "tcp"}
	pools := make(map[string]*ConnPool, len(upstreams))
	for _, upstream := range upstreams {
		pools[upstream] = NewConnPool(metrics, upstream, client, poolSize, dialTimeout)
	}
	return &RoundRobinClient{
		upstreams: upstreams,
		pools:     pools,
		logger:    logger,
		metrics:   metrics,
	}, nil
}

func (r *RoundRobinClient) Exchange(msg *dns.Msg) (*dns.Msg, string, error) {
	n := uint32(len(r.upstreams))
	start := uint32(atomic.AddUint32(&r.counter, 1) - 1)

	var lastErr error
	for i := range n {
		upstream := r.upstreams[(start+i)%n]
		resp, _, err := r.pools[upstream].Exchange(msg)
		if err == nil {
			return resp, upstream, nil
		}

		reason := getFailureReason(err)
		r.metrics.UpstreamFailures.WithLabelValues(upstream, reason).Inc()
		r.logger.Debug("upstream failure", "upstream", upstream, "reason", reason, "error", err)

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
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return "network_error"
	}
	return "other"
}

func (r *RoundRobinClient) Healthchecks() []checks.Check {
	dnsChecks := make([]checks.Check, 0, len(r.upstreams))
	for _, upstream := range r.upstreams {
		check := &DNSCheck{
			upstream: upstream,
			pool:     r.pools[upstream],
		}
		dnsChecks = append(dnsChecks, check)
	}

	return dnsChecks
}

type DNSCheck struct {
	upstream string
	pool     *ConnPool
}

func (d *DNSCheck) Name() string {
	return "DNS server " + d.upstream
}

func (d *DNSCheck) Pass() bool {
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)

	_, _, err := d.pool.Exchange(msg)
	return err == nil
}
