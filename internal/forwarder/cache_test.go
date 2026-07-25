package forwarder

import (
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
)

func TestDNSCache_Close_Idempotent(t *testing.T) {
	logger := slog.Default()
	dc := NewDNSCache(100, logger)

	// First close should not panic
	assert.NotPanics(t, func() {
		dc.Close()
	})

	// Second close should also not panic (idempotent)
	assert.NotPanics(t, func() {
		dc.Close()
	})

	// Third close for good measure
	assert.NotPanics(t, func() {
		dc.Close()
	})
}

func TestDNSCache_Set_AfterClose(t *testing.T) {
	logger := slog.Default()
	dc := NewDNSCache(100, logger)
	dc.Close()

	// Setting after close should not panic and should be a no-op
	assert.NotPanics(t, func() {
		dc.Set("example.com.", []dns.RR{}, 1*time.Minute)
	})
}

func TestDNSCache_Get(t *testing.T) {
	logger := slog.Default()
	dc := NewDNSCache(100, logger)
	defer dc.Close()

	// Test get on empty cache
	rrs, ok := dc.Get("nonexistent.com.")
	assert.False(t, ok)
	assert.Nil(t, rrs)

	// Test set and get
	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{
		Name:   "example.com.",
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	rr.A = net.ParseIP("1.2.3.4")

	dc.Set("example.com.", []dns.RR{rr}, 1*time.Minute)

	// Wait for update worker to process
	time.Sleep(100 * time.Millisecond)

	cached, ok := dc.Get("example.com.")
	assert.True(t, ok)
	assert.Len(t, cached, 1)
}

func TestDNSCache_Len(t *testing.T) {
	logger := slog.Default()
	dc := NewDNSCache(100, logger)
	defer dc.Close()

	assert.Equal(t, 0, dc.Len())

	rr := new(dns.A)
	rr.Hdr = dns.RR_Header{
		Name:   "example.com.",
		Rrtype: dns.TypeA,
		Class:  dns.ClassINET,
		Ttl:    300,
	}
	rr.A = net.ParseIP("1.2.3.4")

	dc.Set("example.com.", []dns.RR{rr}, 1*time.Minute)
	time.Sleep(100 * time.Millisecond)

	assert.Equal(t, 1, dc.Len())
}
