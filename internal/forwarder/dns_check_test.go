package forwarder

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestDNSCheck_Pass_SOA_Root(t *testing.T) {
	// Create a local DNS server that responds to SOA queries for root zone
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		// Add an SOA record in the authority section
		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "a.root-servers.net.",
			Mbox:    "noc.root-servers.net.",
			Serial:  2024010101,
			Refresh: 18000,
			Retry:   2000,
			Expire:  1209600,
			Minttl:  3600,
		}
		m.Ns = append(m.Ns, soa)

		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	server := &dns.Server{
		PacketConn: l,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	addr := l.LocalAddr().String()

	client := &dns.Client{
		Net:          "udp",
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	check := &DNSCheck{
		client: client,
		addr:   addr,
		name:   "test-upstream",
	}

	assert.True(t, check.Pass(), "DNSCheck should pass when upstream responds with SOA for root zone")
}

func TestDNSCheck_Pass_Failure(t *testing.T) {
	// Create a local DNS server that returns SERVFAIL
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	server := &dns.Server{
		PacketConn: l,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	addr := l.LocalAddr().String()

	client := &dns.Client{
		Net:          "udp",
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	check := &DNSCheck{
		client: client,
		addr:   addr,
		name:   "test-upstream",
	}

	assert.False(t, check.Pass(), "DNSCheck should fail when upstream returns SERVFAIL")
}

func TestDNSCheck_Pass_Unreachable(t *testing.T) {
	client := &dns.Client{
		Net:          "udp",
		ReadTimeout:  500 * time.Millisecond,
		WriteTimeout: 500 * time.Millisecond,
	}

	check := &DNSCheck{
		client: client,
		addr:   "127.0.0.1:1", // Port 1 should be unreachable
		name:   "test-upstream",
	}

	assert.False(t, check.Pass(), "DNSCheck should fail when upstream is unreachable")
}

func TestDNSCheck_Name(t *testing.T) {
	check := &DNSCheck{
		client: &dns.Client{},
		addr:   "127.0.0.1:53",
		name:   "8.8.8.8",
	}

	assert.Equal(t, "DNS server 8.8.8.8", check.Name())
}

func TestDNSCheck_WithRoundRobinClient(t *testing.T) {
	logger := slog.Default()

	// Create a local DNS server that responds to SOA queries for root zone
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "a.root-servers.net.",
			Mbox:    "noc.root-servers.net.",
			Serial:  2024010101,
			Refresh: 18000,
			Retry:   2000,
			Expire:  1209600,
			Minttl:  3600,
		}
		m.Ns = append(m.Ns, soa)

		_ = w.WriteMsg(m)
	})

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	server := &dns.Server{
		PacketConn: l,
		Handler:    handler,
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	addr := l.LocalAddr().String()

	cache := NewDNSCache(100, logger)
	defer cache.Close()

	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)

	dnsMetrics, err := metrics.NewDNSMetrics(cache, mockGeo)
	if err != nil {
		t.Fatalf("failed to create DNS metrics: %v", err)
	}

	rrc, err := NewRoundRobinClient(
		dnsMetrics,
		2*time.Second,
		2*time.Second,
		2*time.Second,
		logger,
		addr,
	)
	if err != nil {
		t.Fatalf("failed to create round robin client: %v", err)
	}

	checks := rrc.Healthchecks()
	assert.Len(t, checks, 1)
	assert.True(t, checks[0].Pass(), "Healthcheck should pass with SOA root query")
}
