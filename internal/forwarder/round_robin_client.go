package forwarder

import (
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
}

type ConnPool struct {
	conns   chan *dns.Conn
	addr    string
	client  *dns.Client
	metrics *metrics.DnsMetrics
}

func NewConnPool(metrics *metrics.DnsMetrics, addr string, client *dns.Client, poolSize int) *ConnPool {
	return &ConnPool{
		conns:   make(chan *dns.Conn, poolSize),
		addr:    addr,
		client:  client,
		metrics: metrics,
	}
}

func (p *ConnPool) Exchange(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	var conn *dns.Conn
	select {
	case conn = <-p.conns:
		// Reuse existing connection
	default:
		// No available connection, create a new one
		var err error
		conn, err = p.client.Dial(p.addr)
		if err != nil {
			return nil, 0, errors.Wrapf(err, "failed to dial %s", p.addr)
		}
	}

	resp, rtt, err := p.client.ExchangeWithConn(msg, conn)
	if err != nil {
		_ = conn.Close() // Close the connection on error
		return nil, 0, err
	}

	// Return the connection to the pool if it's still healthy
	select {
	case p.conns <- conn:
	default:
		_ = conn.Close() // Pool is full, close the connection
		p.metrics.PoolEvictions.WithLabelValues(p.addr).Inc()
	}

	return resp, rtt, nil
}

func NewRoundRobinClient(metrics *metrics.DnsMetrics, timeout time.Duration, poolSize int, upstreams ...string) (*RoundRobinClient, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream servers configured")
	}
	client := &dns.Client{Timeout: timeout, Net: "tcp"}
	pools := make(map[string]*ConnPool, len(upstreams))
	for _, upstream := range upstreams {
		pools[upstream] = NewConnPool(metrics, upstream, client, poolSize)
	}
	return &RoundRobinClient{
		upstreams: upstreams,
		pools:     pools,
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
		lastErr = errors.Wrapf(err, "upstream %s failed", upstream)
	}
	return nil, "", errors.Wrap(lastErr, "all upstream servers failed")
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
