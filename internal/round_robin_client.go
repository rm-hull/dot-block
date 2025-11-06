package internal

import (
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/tavsec/gin-healthcheck/checks"
)

type RoundRobinClient struct {
	client    *dns.Client
	upstreams []string
	counter   uint32
}

func NewRoundRobinClient(timeout time.Duration, upstreams ...string) *RoundRobinClient {
	return &RoundRobinClient{
		client:    &dns.Client{Timeout: timeout},
		upstreams: upstreams,
	}
}

func (r *RoundRobinClient) getNextUpstream() string {
	n := atomic.AddUint32(&r.counter, 1)
	return r.upstreams[(int(n)-1)%len(r.upstreams)]
}

func (r *RoundRobinClient) Exchange(msg *dns.Msg) (*dns.Msg, error) {
	upstream := r.getNextUpstream()
	resp, _, err := r.client.Exchange(msg, upstream)
	return resp, err
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
