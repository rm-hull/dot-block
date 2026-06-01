package forwarder

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ip2location/ip2location-go/v9"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockGeoIpLookup is a mock implementation of GeoIPService.
type MockGeoIpLookup struct {
	mock.Mock
}

func (m *MockGeoIpLookup) GetAll(ipAddress string) (ip2location.IP2Locationrecord, error) {
	args := m.Called(ipAddress)
	return args.Get(0).(ip2location.IP2Locationrecord), args.Error(1)
}

func (m *MockGeoIpLookup) Reopen() error {
	return nil
}

// MockResponseWriter is a mock implementation of dns.ResponseWriter.
type MockResponseWriter struct {
	mock.Mock
	WrittenMsg *dns.Msg
}

func (m *MockResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("192.0.2.10"),
		Port: 8080,
	}
}

func (m *MockResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("192.0.2.10"),
		Port: 8080,
	}
}

func (m *MockResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.WrittenMsg = msg
	args := m.Called(msg)
	return args.Error(0)
}

func (m *MockResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *MockResponseWriter) Close() error {
	return nil
}

func (m *MockResponseWriter) TsigStatus() error {
	return nil
}

func (m *MockResponseWriter) TsigTimersOnly(b bool) {
}

func (m *MockResponseWriter) Hijack() {
}

func setupDispatcherTest(t *testing.T, upstream string) (*DNSDispatcher, *MockGeoIpLookup, *blocklist.BlockList, *slog.Logger) {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	blockList := blocklist.NewBlockList([]string{"ads.0xbt.net"}, 0.0001, logger)

	cache := NewDNSCache(100, logger)
	metrics, err := metrics.NewDNSMetrics(cache)
	require.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 1, logger, upstream)
	require.NoError(t, err)

	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(ip2location.IP2Locationrecord{}, nil)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, blockList, mockGeo, 1*time.Minute, logger)
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)

	return dispatcher, mockGeo, blockList, logger
}

func TestDNSDispatcher_HandleDNSRequest_MixedBlockedAndUpstream(t *testing.T) {
	// A server that answers for google.com and fails or times out for others?
	// Or just a standard server. Let's make it a standard one.
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)

		if r.Question[0].Name == "google.com." {
			aRecord := &dns.A{
				Hdr: dns.RR_Header{
					Name:   dns.Fqdn("google.com."),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: []byte{142, 251, 29, 101},
			}
			m.Answer = append(m.Answer, aRecord)
		}

		_ = w.WriteMsg(m)
	})

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "ads.0xbt.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET}, // Blocked
	}

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Should have 2 answers: google.com A record and ads.0xbt.net SOA record
	assert.Len(t, writer.WrittenMsg.Answer, 2)

	foundA := false
	foundSOA := false
	for _, rr := range writer.WrittenMsg.Answer {
		if _, ok := rr.(*dns.A); ok {
			foundA = true
		} else if _, ok := rr.(*dns.SOA); ok {
			foundSOA = true
		}
	}
	assert.True(t, foundA, "A record for google.com. not found")
	assert.True(t, foundSOA, "SOA record for ads.0xbt.net. not found")
}

func TestDNSDispatcher_HandleDNSRequest_Allowed(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("google.com.", dns.TypeA, []byte{142, 251, 29, 101}))
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	// Assert that the response writer was called with a non-nil message
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
}

func TestDNSDispatcher_HandleDNSRequest_Blocked(t *testing.T) {
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		// shouldn't call upstream
		t.Fail()
	})

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	// Assert that the response has an RcodeSuccess Rcode
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
	assert.Len(t, writer.WrittenMsg.Answer, 1, "should have one answer")
	assert.Len(t, writer.WrittenMsg.Ns, 0, "should have no NS record")

	soa, ok := writer.WrittenMsg.Answer[0].(*dns.SOA)
	assert.True(t, ok, "should be a SOA record")
	assert.Equal(t, "ns.blocked.local.", soa.Ns, "unexpected Ns name")
}

func TestDNSDispatcher_HandleDNSRequest_MultipleQuestions(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("google.com.", dns.TypeA, []byte{142, 251, 29, 101}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "ads.0xbt.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	// Assert that the response writer was called with a non-nil message
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
	assert.Len(t, writer.WrittenMsg.Answer, 2)
	assert.Len(t, writer.WrittenMsg.Question, 2)

	// Verify that the blocked domain has a SOA record in the answer section
	foundSOA := false
	for _, rr := range writer.WrittenMsg.Answer {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Hdr.Name == "ads.0xbt.net." {
				assert.Equal(t, "ns.blocked.local.", soa.Ns, "unexpected Ns name for blocked domain")
				foundSOA = true
				break
			}
		}
	}
	assert.True(t, foundSOA, "SOA record for ads.0xbt.net. not found in answers")
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("example.com.", dns.TypeA, []byte{93, 184, 216, 34}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request: should be a cache miss and populate the cache
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Reset mock for the second request
	writer = new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Ensure the cache item is actually retrievable
	cacheKey := getCacheKey(&req.Question[0])
	assert.Eventually(t, func() bool {
		_, ok := dispatcher.cache.Get(cacheKey)
		return ok // Wait until Get actually finds the item
	}, 5*time.Second, 50*time.Millisecond, "Cache item not found after first request")

	// Second request: should be a cache hit
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
}

func TestDNSDispatcher_ResolveUpstream_BadRCode(t *testing.T) {
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)                   // Set reply based on the request
		m.SetRcode(r, dns.RcodeRefused) // Respond with REFUSED for other queries
		_ = w.WriteMsg(m)
	})

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeRefused, writer.WrittenMsg.Rcode)
}

func TestDNSDispatcher_NegativeCacheTtlFloor(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	blockList := blocklist.NewBlockList([]string{"ads.0xbt.net"}, 0.0001, logger)

	cache := NewDNSCache(100, logger)
	metrics, err := metrics.NewDNSMetrics(cache)
	assert.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 1, logger, "8.8.8.8:53")
	assert.NoError(t, err)
	mockGeo := new(MockGeoIpLookup)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, blockList, mockGeo, -1*time.Second, logger)
	assert.Error(t, err)
	assert.Nil(t, dispatcher)
	assert.Contains(t, err.Error(), "TTL floor cannot be negative")
}

func TestDNSDispatcher_HandleDNSRequest_DNSSD_NXDOMAIN(t *testing.T) {
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		// This should not be called
		t.Errorf("Upstream DNS was called for blocked DNS-SD request: %s", m.Question[0].Name)
	})

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream)

	req := new(dns.Msg)
	req.SetQuestion("db._dns-sd._udp.0.68.168.192.in-addr.arpa.", dns.TypePTR)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	// Assert that the response has NXDOMAIN
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeNameError, writer.WrittenMsg.Rcode, "should return NXDOMAIN")
}
func TestDNSDispatcher_HandleDNSRequest_UpstreamNXDOMAIN_NoLogError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	blockList := blocklist.NewBlockList([]string{}, 0.0001, logger)
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		_ = w.WriteMsg(m)
	})
	defer func() {
		_ = server.Shutdown()
	}()

	cache := NewDNSCache(100, logger)
	metrics, err := metrics.NewDNSMetrics(cache)
	require.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 1, logger, upstream)
	require.NoError(t, err)

	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(ip2location.IP2Locationrecord{}, nil)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, blockList, mockGeo, 1*time.Minute, logger)
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeNameError, writer.WrittenMsg.Rcode)

	// Verify that no ERROR log was written
	assert.Empty(t, logBuf.String(), "should not log NXDOMAIN as ERROR")
}

func TestDNSDispatcher_HandleDNSRequest_UpstreamSERVFAIL_LogError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	blockList := blocklist.NewBlockList([]string{}, 0.0001, logger)
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeServerFailure) // SERVFAIL
		_ = w.WriteMsg(m)
	})
	defer func() {
		_ = server.Shutdown()
	}()

	cache := NewDNSCache(100, logger)
	metrics, err := metrics.NewDNSMetrics(cache)
	require.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 1, logger, upstream)
	require.NoError(t, err)

	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(ip2location.IP2Locationrecord{}, nil)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, blockList, mockGeo, 1*time.Minute, logger)
	require.NoError(t, err)
	t.Cleanup(dispatcher.Close)

	req := new(dns.Msg)
	req.SetQuestion("error.example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeServerFailure, writer.WrittenMsg.Rcode)

	// Verify that an ERROR log was written
	assert.Contains(t, logBuf.String(), "level=ERROR", "should log SERVFAIL as ERROR")
}

func dnsRecord(addr string, rrtype uint16, ip []byte) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn(addr),
				Rrtype: rrtype,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: ip,
		}

		m.Answer = append(m.Answer, aRecord)

		_ = w.WriteMsg(m)
	}
}

func probeDecorator(probeName string, handler dns.HandlerFunc) dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {

		// Check if it's the probe query from waitForPort
		if len(r.Question) > 0 && r.Question[0].Name == probeName {
			m := new(dns.Msg)
			m.SetReply(r)                   // Set reply based on the request
			m.SetRcode(r, dns.RcodeSuccess) // Respond with success for the probe
			_ = w.WriteMsg(m)
		} else {
			handler(w, r)
		}
	}
}

func startLocalDNS(t *testing.T, handler dns.HandlerFunc) (*dns.Server, string) {
	t.Helper()
	probeName := fmt.Sprintf("%s.dns-probe.local.", uuid.New().String())

	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := l.Addr().String()

	server := &dns.Server{
		Listener: l,
		Net:      "tcp",
		Handler:  probeDecorator(probeName, handler),
	}

	started := make(chan struct{})
	server.NotifyStartedFunc = func() {
		close(started)
	}

	go func() {
		err := server.ActivateAndServe()
		if err != nil {
			// If it's already closed, don't fail the test
			return
		}
	}()

	select {
	case <-started:
		t.Logf("Mock DNS server listening on: %s", addr)
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for mock DNS server to become ready")
	}

	waitForPort(t, addr, probeName, 5*time.Second)
	return server, addr
}

func waitForPort(t *testing.T, addr, probeName string, timeout time.Duration) {
	t.Helper()
	deadline := deadline(t, timeout)
	client := dns.Client{DialTimeout: 100 * time.Millisecond, Net: "tcp"}
	req := new(dns.Msg)
	req.SetQuestion(probeName, dns.TypeA)

	for time.Now().Before(deadline) {
		t.Logf("Testing server for: %s", probeName)
		_, _, err := client.Exchange(req, addr)
		if err == nil {
			return
		}
		t.Logf("waitForPort: client.Exchange error: %v\n", err)
		time.Sleep(50 * time.Millisecond)
	}

	t.Fatalf("server not ready at %s", addr)
}

func deadline(t *testing.T, timeout time.Duration) time.Time {
	t.Helper()
	if d, ok := t.Deadline(); ok {
		return d.Add(-time.Second)
	}
	return time.Now().Add(timeout)
}

func TestDNSDispatcher_ReservedTLDs(t *testing.T) {
	dispatcher, _, _, _ := setupDispatcherTest(t, "127.0.0.1:53")

	tests := []struct {
		name     string
		expected int // Expected Rcode
	}{
		{"example.invalid.", dns.RcodeNameError},
		{"localhost.", dns.RcodeSuccess},
		{"test.local.", dns.RcodeNameError},
		{"my.test.", dns.RcodeNameError},
		{"my.example.", dns.RcodeNameError},
		{"my.internal.", dns.RcodeNameError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := new(dns.Msg)
			req.Question = []dns.Question{
				{Name: tt.name, Qtype: dns.TypeA, Qclass: dns.ClassINET},
			}

			writer := new(MockResponseWriter)
			writer.On("WriteMsg", mock.Anything).Return(nil)

			dispatcher.HandleDNSRequest("test")(writer, req)

			assert.NotNil(t, writer.WrittenMsg)
			assert.Equal(t, tt.expected, writer.WrittenMsg.Rcode, "Rcode mismatch for %s", tt.name)

			if tt.name == "localhost." {
				assert.Len(t, writer.WrittenMsg.Answer, 1)
				a := writer.WrittenMsg.Answer[0].(*dns.A)
				assert.Equal(t, "127.0.0.1", a.A.String())
			} else {
				assert.Len(t, writer.WrittenMsg.Answer, 0)
			}
		})
	}
}
