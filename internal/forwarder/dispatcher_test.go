package forwarder

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/limiter"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/noisefilter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockGeoIpLookup is a mock implementation of GeoIPService.
type MockGeoIpLookup struct {
	mock.Mock
}

func (m *MockGeoIpLookup) GetAll(ipAddr string) (*geoblock.GeoData, error) {
	args := m.Called(ipAddr)
	return new(args.Get(0).(geoblock.GeoData)), args.Error(1)
}

func (m *MockGeoIpLookup) Reopen() error {
	return nil
}

func (m *MockGeoIpLookup) IsValid(ipAddr string) bool {
	return true
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

// newTestLimiter creates a disabled limiter for use in tests where rate
// limiting should not interfere with DNS processing.
func newTestLimiter(t *testing.T) *limiter.Limiter {
	t.Helper()
	l, err := limiter.New(&config.RateLimitConfig{Enabled: false})
	require.NoError(t, err)
	t.Cleanup(l.Close)
	return l
}

func setupDispatcherTest(t *testing.T, upstream string, logger *slog.Logger, enableECS bool) (*DNSDispatcher, *MockGeoIpLookup, *blocklist.BlockList, *slog.Logger) {
	t.Helper()
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	source := &config.BlocklistSource{Name: "dispatcher_test", URL: "http://dummy.url"}
	blockList := blocklist.NewBlockList(source, 0.0001, logger)
	blockList.Load([]string{"ads.0xbt.net"})

	cache := NewDNSCache(100, logger)
	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)

	metrics, err := metrics.NewDNSMetrics(cache, mockGeo, metrics.DefaultTopKConfig())
	require.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 2*time.Second, 2*time.Second, logger, upstream)
	require.NoError(t, err)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, []*blocklist.BlockList{blockList}, noisefilter.NewNoiseFilter(), sse.NewBroadcaster(logger, metrics.DroppedSSEEvents), 1*time.Minute, logger, enableECS, newTestLimiter(t))
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

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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

	// The upstream answer should stay in the answer section, and the blocked domain should be returned as authority data.
	assert.Len(t, writer.WrittenMsg.Answer, 1, "should have one upstream answer")
	assert.Len(t, writer.WrittenMsg.Ns, 1, "should have one blocked authority record")

	foundA := false
	foundSOA := false
	for _, rr := range writer.WrittenMsg.Answer {
		if _, ok := rr.(*dns.A); ok {
			foundA = true
		}
	}
	for _, rr := range writer.WrittenMsg.Ns {
		if _, ok := rr.(*dns.SOA); ok {
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

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	// Assert that the response has an RcodeSuccess Rcode
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
	assert.Len(t, writer.WrittenMsg.Answer, 0, "should have no answers")
	assert.Len(t, writer.WrittenMsg.Ns, 1, "should have one authority record")
	assert.Len(t, writer.WrittenMsg.Extra, 0, "should have no OPT record without EDNS")

	soa, ok := writer.WrittenMsg.Ns[0].(*dns.SOA)
	assert.True(t, ok, "should be a SOA record in the authority section")
	assert.Equal(t, "ns.blocked.local.", soa.Ns, "unexpected Ns name")
}

func TestDNSDispatcher_HandleDNSRequest_BlockedIncludesEDE(t *testing.T) {
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, m *dns.Msg) {
		t.Fail()
	})

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)
	req.SetEdns0(1232, false)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	dispatcher.HandleDNSRequest("test")(writer, req)

	require.NotNil(t, writer.WrittenMsg)
	require.Len(t, writer.WrittenMsg.Ns, 1)
	require.Len(t, writer.WrittenMsg.Extra, 1)

	opt, ok := writer.WrittenMsg.Extra[0].(*dns.OPT)
	require.True(t, ok, "expected an OPT record to carry EDE")
	require.Len(t, opt.Option, 1)

	ede, ok := opt.Option[0].(*dns.EDNS0_EDE)
	require.True(t, ok, "expected EDE option")
	assert.Equal(t, dns.ExtendedErrorCodeBlocked, ede.InfoCode)
	assert.Contains(t, ede.ExtraText, "Blocked by: dispatcher_test")
}

func TestDNSDispatcher_HandleDNSRequest_MultipleQuestions(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("google.com.", dns.TypeA, []byte{142, 251, 29, 101}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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
	assert.Len(t, writer.WrittenMsg.Answer, 1)
	assert.Len(t, writer.WrittenMsg.Ns, 1)
	assert.Len(t, writer.WrittenMsg.Question, 2)

	// Verify that the blocked domain has a SOA record in the authority section
	foundSOA := false
	for _, rr := range writer.WrittenMsg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			if soa.Hdr.Name == "ads.0xbt.net." {
				assert.Equal(t, "ns.blocked.local.", soa.Ns, "unexpected Ns name for blocked domain")
				foundSOA = true
				break
			}
		}
	}
	assert.True(t, foundSOA, "SOA record for ads.0xbt.net. not found in authority section")
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("example.com.", dns.TypeA, []byte{93, 184, 216, 34}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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
	cacheKey := getCacheKey(&req.Question[0], "")
	assert.Eventually(t, func() bool {
		_, ok := dispatcher.cache.Get(cacheKey)
		return ok // Wait until Get actually finds the item
	}, 5*time.Second, 50*time.Millisecond, "Cache item not found after first request")

	// Second request: should be a cache hit
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit_ECS(t *testing.T) {
	server, upstream := startLocalDNS(t, dnsRecord("example.com.", dns.TypeA, []byte{93, 184, 216, 34}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, true)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := &mockIPResponseWriter{
		ip:   "1.2.3.4",
		port: 12345,
		Mock: mock.Mock{},
	}
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request: should be a cache miss and populate the cache
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Ensure the cache item is actually retrievable
	cacheKey := getCacheKey(&req.Question[0], "1.2.3.0")
	assert.Eventually(t, func() bool {
		_, ok := dispatcher.cache.Get(cacheKey)
		return ok // Wait until Get actually finds the item
	}, 5*time.Second, 50*time.Millisecond, "Cache item not found after first request with ECS")

	// Second request: should be a cache hit
	writer = &mockIPResponseWriter{
		ip:   "1.2.3.4",
		port: 12345,
		Mock: mock.Mock{},
	}
	writer.On("WriteMsg", mock.Anything).Return(nil)

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

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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
	source := &config.BlocklistSource{Name: "dispatcher_test", URL: "http://dummy.url"}
	blockList := blocklist.NewBlockList(source, 0.0001, logger)
	blockList.Load([]string{"ads.0xbt.net"})

	cache := NewDNSCache(100, logger)
	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)

	metrics, err := metrics.NewDNSMetrics(cache, mockGeo, metrics.DefaultTopKConfig())
	assert.NoError(t, err)

	dnsClient, err := NewRoundRobinClient(metrics, 2*time.Second, 2*time.Second, 2*time.Second, logger, "8.8.8.8:53")
	assert.NoError(t, err)

	dispatcher, err := NewDNSDispatcher(cache, metrics, dnsClient, []*blocklist.BlockList{blockList}, noisefilter.NewNoiseFilter(), sse.NewBroadcaster(logger, metrics.DroppedSSEEvents), -1*time.Second, logger, false, newTestLimiter(t))
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

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

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

	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		_ = w.WriteMsg(m)
	})
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, logger, false)

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

func TestDNSDispatcher_HandleDNSRequest_UpstreamNOTIMP_NoLogError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeNotImplemented) // NOTIMP
		_ = w.WriteMsg(m)
	})
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, logger, false)

	req := new(dns.Msg)
	req.SetQuestion("notimp.example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest("test")(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeNotImplemented, writer.WrittenMsg.Rcode)

	// Verify that no ERROR log was written
	assert.Empty(t, logBuf.String(), "should not log NOTIMP as ERROR")
}

func TestDNSDispatcher_HandleDNSRequest_UpstreamSERVFAIL_LogError(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeServerFailure) // SERVFAIL
		_ = w.WriteMsg(m)
	})
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, logger, false)

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

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	addr := l.LocalAddr().String()

	server := &dns.Server{
		PacketConn: l,
		Handler:    probeDecorator(probeName, handler),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	waitForPort(t, addr, probeName, 5*time.Second)
	return server, addr
}

func waitForPort(t *testing.T, addr, probeName string, timeout time.Duration) {
	t.Helper()
	deadline := deadline(t, timeout)
	client := dns.Client{DialTimeout: 100 * time.Millisecond, Net: "udp"}
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
	dispatcher, _, _, _ := setupDispatcherTest(t, "127.0.0.1:53", nil, false)

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

func TestDNSDispatcher_ECS_Injection(t *testing.T) {
	tests := []struct {
		name       string
		enableECS  bool
		clientIP   string
		expectECS  bool
		expectFam  uint16
		expectMask uint8
	}{
		{
			name:       "IPv4 Enabled",
			enableECS:  true,
			clientIP:   "1.2.3.4",
			expectECS:  true,
			expectFam:  1,
			expectMask: 24,
		},
		{
			name:      "IPv4 Disabled",
			enableECS: false,
			clientIP:  "1.2.3.4",
			expectECS: false,
		},
		{
			name:       "IPv6 Enabled",
			enableECS:  true,
			clientIP:   "2001:db8::1",
			expectECS:  true,
			expectFam:  2,
			expectMask: 48,
		},
		{
			name:      "Unknown IP",
			enableECS: true,
			clientIP:  "unknown",
			expectECS: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var capturedReq *dns.Msg
			done := make(chan struct{})
			server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
				capturedReq = r.Copy()
				m := new(dns.Msg)
				m.SetReply(r)
				m.SetRcode(r, dns.RcodeSuccess)
				_ = w.WriteMsg(m)
				close(done)
			})
			defer func() {
				err := server.Shutdown()
				assert.NoError(t, err)
			}()

			// Setup dispatcher with the specific enableECS setting
			logger := slog.New(slog.NewTextHandler(io.Discard, nil))
			source := &config.BlocklistSource{Name: "dispatcher_test", URL: "http://dummy.url"}
			blockList := blocklist.NewBlockList(source, 0.0001, logger)
			blockList.Load([]string{"ads.com"})

			cache := NewDNSCache(100, logger)
			mockGeo := new(MockGeoIpLookup)
			mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)
			metrics, _ := metrics.NewDNSMetrics(cache, mockGeo, metrics.DefaultTopKConfig())
			dnsClient, _ := NewRoundRobinClient(metrics, 2*time.Second, 2*time.Second, 2*time.Second, logger, upstream)

			dispatcher, _ := NewDNSDispatcher(cache, metrics, dnsClient, []*blocklist.BlockList{blockList}, noisefilter.NewNoiseFilter(), sse.NewBroadcaster(logger, metrics.DroppedSSEEvents), 1*time.Minute, logger, tt.enableECS, newTestLimiter(t))
			defer dispatcher.Close()

			// Mock ResponseWriter with the specific client IP
			writer := &mockIPResponseWriter{
				ip:   tt.clientIP,
				port: 12345,
				Mock: mock.Mock{},
			}
			writer.On("WriteMsg", mock.Anything).Return(nil)

			req := new(dns.Msg)
			req.SetQuestion("example.com.", dns.TypeA)

			dispatcher.HandleDNSRequest("test")(writer, req)

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("timed out waiting for upstream server to receive request")
			}

			require.NotNil(t, capturedReq)

			foundECS := false
			for _, rr := range capturedReq.Extra {
				if opt, ok := rr.(*dns.OPT); ok {
					for _, o := range opt.Option {
						if ecs, ok := o.(*dns.EDNS0_SUBNET); ok {
							foundECS = true
							assert.Equal(t, tt.expectFam, ecs.Family)
							assert.Equal(t, tt.expectMask, ecs.SourceNetmask)
						}
					}
				}
			}

			assert.Equal(t, tt.expectECS, foundECS, "ECS option presence mismatch")
		})
	}
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit_CNAME(t *testing.T) {
	// A server that returns a CNAME and an A record for the target
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		cname := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("www.netflix.com."),
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: dns.Fqdn("prod.ftl.netflix.com."),
		}
		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("prod.ftl.netflix.com."),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("1.2.3.4"),
		}

		m.Answer = []dns.RR{cname, aRecord}
		_ = w.WriteMsg(m)
	})

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("www.netflix.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request: should be a cache miss and populate the cache
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Verify we got both records back from the upstream
	assert.Len(t, writer.WrittenMsg.Answer, 2)

	// Give the cache worker time to process the set
	time.Sleep(100 * time.Millisecond)

	// Verify the cache entry exists and contains BOTH the CNAME and the A record
	// This is the core of the bug: the filtering logic only matches exact name+type,
	// so CNAME chains result in no cache entry being created.
	cacheKey := getCacheKey(&req.Question[0], "")
	cached, ok := dispatcher.cache.Get(cacheKey)
	require.True(t, ok, "cache entry should exist for CNAME query")
	require.Len(t, cached, 2, "cache entry should contain both CNAME and A record")

	// Verify the cached records are correct
	foundCNAME := false
	foundA := false
	for _, rr := range cached {
		switch rec := rr.(type) {
		case *dns.CNAME:
			assert.Equal(t, "www.netflix.com.", rec.Hdr.Name)
			assert.Equal(t, "prod.ftl.netflix.com.", rec.Target)
			foundCNAME = true
		case *dns.A:
			assert.Equal(t, "prod.ftl.netflix.com.", rec.Hdr.Name)
			assert.True(t, rec.A.Equal(net.ParseIP("1.2.3.4")), "A record IP mismatch")
			foundA = true
		}
	}
	assert.True(t, foundCNAME, "cached CNAME record not found")
	assert.True(t, foundA, "cached A record not found")

	// Shut down the upstream server to prove the second request is served from cache
	err := server.Shutdown()
	assert.NoError(t, err)

	// Second request: should be a cache hit (upstream is now shut down)
	writer2 := new(MockResponseWriter)
	writer2.On("WriteMsg", mock.Anything).Return(nil)

	dispatcher.HandleDNSRequest("test")(writer2, req)

	assert.NotNil(t, writer2.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer2.WrittenMsg.Rcode)
	assert.Len(t, writer2.WrittenMsg.Answer, 2, "Should have retrieved the cached CNAME chain from cache")
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit_MultiLevelCNAME(t *testing.T) {
	// A server that returns a multi-level CNAME chain: A -> B -> C -> IP
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true

		cname1 := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("www.example.com."),
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: dns.Fqdn("edge.example.net."),
		}
		cname2 := &dns.CNAME{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("edge.example.net."),
				Rrtype: dns.TypeCNAME,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Target: dns.Fqdn("cdn.provider.com."),
		}
		aRecord := &dns.A{
			Hdr: dns.RR_Header{
				Name:   dns.Fqdn("cdn.provider.com."),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			A: net.ParseIP("5.6.7.8"),
		}

		m.Answer = []dns.RR{cname1, cname2, aRecord}
		_ = w.WriteMsg(m)
	})

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("www.example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request: should be a cache miss and populate the cache
	dispatcher.HandleDNSRequest("test")(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
	assert.Len(t, writer.WrittenMsg.Answer, 3)

	// Give the cache worker time to process the set
	time.Sleep(100 * time.Millisecond)

	// Verify the cache entry exists and contains all three records
	cacheKey := getCacheKey(&req.Question[0], "")
	cached, ok := dispatcher.cache.Get(cacheKey)
	require.True(t, ok, "cache entry should exist for multi-level CNAME query")
	require.Len(t, cached, 3, "cache entry should contain both CNAMEs and the A record")

	// Shut down the upstream server to prove the second request is served from cache
	err := server.Shutdown()
	assert.NoError(t, err)

	// Second request: should be a cache hit (upstream is now shut down)
	writer2 := new(MockResponseWriter)
	writer2.On("WriteMsg", mock.Anything).Return(nil)

	dispatcher.HandleDNSRequest("test")(writer2, req)

	assert.NotNil(t, writer2.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer2.WrittenMsg.Rcode)
	assert.Len(t, writer2.WrittenMsg.Answer, 3, "Should have retrieved the cached multi-level CNAME chain from cache")
}

type mockIPResponseWriter struct {
	ip         string
	port       int
	WrittenMsg *dns.Msg
	mock.Mock
}

func (m *mockIPResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (m *mockIPResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(m.ip), Port: m.port}
}

func (m *mockIPResponseWriter) WriteMsg(msg *dns.Msg) error {
	m.WrittenMsg = msg
	args := m.Called(msg)
	return args.Error(0)
}

func (m *mockIPResponseWriter) Write(b []byte) (int, error) {
	return len(b), nil
}

func (m *mockIPResponseWriter) Close() error {
	return nil

}

func (m *mockIPResponseWriter) TsigStatus() error {
	return nil
}

func (m *mockIPResponseWriter) TsigTimersOnly(b bool) {

}

func (m *mockIPResponseWriter) Hijack() {

}

func TestResolveUpstreamCacheKeyCollision(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create a simple UDP server that handles multi-question requests
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := pc.LocalAddr().String()

	go func() {
		buf := make([]byte, 2048)
		for {
			n, raddr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			var req dns.Msg
			if err := req.Unpack(buf[:n]); err != nil {
				continue
			}
			m := new(dns.Msg)
			m.SetReply(&req)
			m.SetRcode(&req, dns.RcodeSuccess)
			m.Authoritative = true
			for _, q := range req.Question {
				m.Answer = append(m.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: q.Qtype, Class: dns.ClassINET, Ttl: 3600},
					A:   net.ParseIP("1.2.3.4"),
				})
			}
			respData, err := m.Pack()
			if err != nil {
				continue
			}
			if _, err := pc.WriteTo(respData, raddr); err != nil {
				continue
			}
		}
	}()
	defer func() { _ = pc.Close() }()

	dispatcher, _, _, _ := setupDispatcherTest(t, addr, logger, false)

	reqCtx := &RequestContext{
		ctx:      t.Context(),
		logger:   logger,
		snapshot: metrics.NewRequestSnapshot(time.Now(), "test", "127.0.0.1"),
		ipAddr:   "127.0.0.1",
	}

	// Simulate a multi-question request with two different domains
	questions := []dns.Question{
		{Name: "domainA.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "domainB.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	multiReq := new(dns.Msg)
	multiReq.Id = dns.Id()
	multiReq.RecursionDesired = true
	multiReq.Question = questions

	rcode, answers, err := dispatcher.resolveUpstream(reqCtx, questions, multiReq)
	assert.NoError(t, err)
	assert.Equal(t, dns.RcodeSuccess, rcode)
	assert.Len(t, answers, 2)

	// Give the cache update worker time to process the updates
	time.Sleep(100 * time.Millisecond)

	// Verify domainA.com cache entry only contains the answer for domainA.com
	keyA := getCacheKey(&questions[0], "")
	cachedA, okA := dispatcher.cache.Get(keyA)
	assert.True(t, okA, "domainA.com should be in cache")
	assert.Len(t, cachedA, 1, "domainA.com cache should only have 1 answer")
	if len(cachedA) > 0 {
		assert.Equal(t, "domainA.com.", cachedA[0].Header().Name,
			"domainA.com cache should only contain domainA.com answer, not domainB.com")
	}

	// Verify domainB.com cache entry only contains the answer for domainB.com
	keyB := getCacheKey(&questions[1], "")
	cachedB, okB := dispatcher.cache.Get(keyB)
	assert.True(t, okB, "domainB.com should be in cache")
	assert.Len(t, cachedB, 1, "domainB.com cache should only have 1 answer")
	if len(cachedB) > 0 {
		assert.Equal(t, "domainB.com.", cachedB[0].Header().Name,
			"domainB.com cache should only contain domainB.com answer, not domainA.com")
	}
}

func TestDNSDispatcher_reportError_OddAdditionalFields(t *testing.T) {
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelError}))

	dispatcher, _, _, _ := setupDispatcherTest(t, "127.0.0.1:53", logger, false)

	reqCtx := &RequestContext{
		ctx:      t.Context(),
		logger:   logger,
		snapshot: metrics.NewRequestSnapshot(time.Now(), "test", "127.0.0.1"),
		ipAddr:   "127.0.0.1",
	}

	// Passing an odd number of additional fields must NOT panic; slog
	// tolerates this by logging the trailing value under the "!BADKEY" key.
	err := fmt.Errorf("simulated upstream failure")

	assert.NotPanics(t, func() {
		dispatcher.reportError(reqCtx, "upstream", err, "example.com.", "qtype", "A", "extra")
	})

	// The error should still be logged.
	assert.Contains(t, logBuf.String(), "level=ERROR", "should log error")
	assert.Contains(t, logBuf.String(), "DNS error", "should log DNS error message")
	// Standard fields must be correctly paired even with odd-length
	// additionalFields, since they are appended first.
	assert.Contains(t, logBuf.String(), "category=upstream", "category should be correctly paired")
	assert.Contains(t, logBuf.String(), `error="simulated upstream failure"`, "error should be correctly paired")
	assert.Contains(t, logBuf.String(), "latency=", "latency should be correctly paired")
	// slog logs the unpaired trailing value under the "!BADKEY" key.
	assert.Contains(t, logBuf.String(), "!BADKEY", "should log unpaired value under !BADKEY key")
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit_NODATA(t *testing.T) {
	// This test verifies that NOERROR responses with 0 answers (NODATA) are cached.
	// This is particularly important for HTTPS/SVCB queries where a domain may not have
	// an HTTPS record, and the NODATA response should be cached to avoid repeated
	// upstream queries.
	var upstreamCallCount int64
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt64(&upstreamCallCount, 1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeSuccess // NOERROR
		m.Authoritative = true
		m.Answer = nil // No answers = NODATA
		_ = w.WriteMsg(m)
	})
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeHTTPS)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request - should be a cache miss and hit upstream
	dispatcher.HandleDNSRequest("test")(writer, req)
	require.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
	assert.Len(t, writer.WrittenMsg.Answer, 0, "Should have 0 answers (NODATA)")

	firstCallCount := atomic.LoadInt64(&upstreamCallCount)

	// Wait for the cache to be populated (cache updates are async)
	cacheKey := getCacheKey(&req.Question[0], "")
	assert.Eventually(t, func() bool {
		cached, ok := dispatcher.cache.Get(cacheKey)
		return ok && len(cached) == 0
	}, 500*time.Millisecond, 10*time.Millisecond, "NODATA should be cached")

	// Second request - should be served from cache (not hitting upstream)
	writer2 := new(MockResponseWriter)
	writer2.On("WriteMsg", mock.Anything).Return(nil)

	dispatcher.HandleDNSRequest("test")(writer2, req)
	require.NotNil(t, writer2.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer2.WrittenMsg.Rcode)
	assert.Len(t, writer2.WrittenMsg.Answer, 0, "Should have 0 answers from cache (NODATA)")

	secondCallCount := atomic.LoadInt64(&upstreamCallCount)
	assert.Equal(t, firstCallCount, secondCallCount,
		"NODATA response should have been cached - upstream should not be called again")
}

func TestDNSDispatcher_HandleDNSRequest_CacheHit_NXDOMAIN(t *testing.T) {
	var upstreamCallCount int64
	server, upstream := startLocalDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		atomic.AddInt64(&upstreamCallCount, 1)
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeNameError) // NXDOMAIN
		m.Authoritative = true

		// Add SOA in authority section (standard for NXDOMAIN)
		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns:      "ns1.example.com.",
			Mbox:    "hostmaster.example.com.",
			Serial:  2024073001,
			Refresh: 10000,
			Retry:   2400,
			Expire:  604800,
			Minttl:  3600,
		}
		m.Ns = append(m.Ns, soa)
		_ = w.WriteMsg(m)
	})
	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, _, _, _ := setupDispatcherTest(t, upstream, nil, false)

	req := new(dns.Msg)
	req.SetQuestion("nonexistent.example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request - should hit upstream and get NXDOMAIN
	dispatcher.HandleDNSRequest("test")(writer, req)
	require.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeNameError, writer.WrittenMsg.Rcode)
	firstCallCount := atomic.LoadInt64(&upstreamCallCount)

	// Wait for cache to be populated
	cacheKey := getCacheKey(&req.Question[0], "")
	assert.Eventually(t, func() bool {
		cached, ok := dispatcher.cache.Get(cacheKey)
		return ok && len(cached) > 0 // Cached NXDOMAIN has SOA record
	}, 500*time.Millisecond, 10*time.Millisecond, "NXDOMAIN should be cached")

	// Second request - should be served from cache
	writer2 := new(MockResponseWriter)
	writer2.On("WriteMsg", mock.Anything).Return(nil)

	dispatcher.HandleDNSRequest("test")(writer2, req)
	require.NotNil(t, writer2.WrittenMsg)
	assert.Equal(t, dns.RcodeNameError, writer2.WrittenMsg.Rcode, "Should return NXDOMAIN from cache")
	secondCallCount := atomic.LoadInt64(&upstreamCallCount)
	assert.Equal(t, firstCallCount, secondCallCount,
		"NXDOMAIN response should have been cached - upstream should not be called again")
}
