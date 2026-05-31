package forwarder

import (
	"net"
	"sync/atomic"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/tavsec/gin-healthcheck/checks"
)

type RoundRobinClient struct {
	client    *dns.Client
	upstreams []string
	counter   uint32
}

func NewRoundRobinClient(timeout time.Duration, upstreams ...string) (*RoundRobinClient, error) {
	if len(upstreams) == 0 {
		return nil, errors.New("no upstream servers configured")
	}
	return &RoundRobinClient{
		client:    &dns.Client{Timeout: timeout},
		upstreams: upstreams,
	}, nil
}

func (r *RoundRobinClient) Exchange(msg *dns.Msg) (*dns.Msg, string, error) {
	n := uint32(len(r.upstreams))
	start := uint32(atomic.AddUint32(&r.counter, 1) - 1)

	var lastErr error
	for i := range n {
		upstream := r.upstreams[(start+i)%n]
		resp, _, err := r.client.Exchange(msg, upstream)
		if err == nil {
			return resp, upstream, nil
		}

		// Only fall through to next upstream on network/timeout errors, not DNS errors
		if isTimeoutError(err) {
			lastErr = errors.Wrapf(err, "timeout from upstream %s", upstream)
			continue
		}
		return nil, "", errors.Wrapf(err, "DNS error from upstream %s", upstream)
	}
	return nil, "", errors.Wrap(lastErr, "all upstream servers failed")
}

func isTimeoutError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func (r *RoundRobinClient) Healthchecks() []checks.Check {
	dnsChecks := make([]checks.Check, 0, len(r.upstreams))
	for _, upstream := range r.upstreams {
		check := &DNSCheck{
			upstream: upstream,
			client:   &dns.Client{Timeout: 2 * time.Second},
		}
		dnsChecks = append(dnsChecks, check)
	}

	return dnsChecks
}

type DNSCheck struct {
	upstream string
	client   *dns.Client
}

func (d *DNSCheck) Name() string {
	return "DNS server " + d.upstream
}

func (d *DNSCheck) Pass() bool {
	msg := new(dns.Msg)
	msg.SetQuestion("google.com.", dns.TypeA)

	_, _, err := d.client.Exchange(msg, d.upstream)
	return err == nil
}
