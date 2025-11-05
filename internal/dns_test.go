package internal

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

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

func TestDNSDispatcher_HandleDNSRequest_Allowed(t *testing.T) {
	blockList := NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
	server, upstream := startLocalDNS(t, dnsRecord("google.com.", dns.TypeA, []byte{142, 251, 29, 101}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, err := NewDNSDispatcher(upstream, blockList, 100)
	assert.NoError(t, err)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest(writer, req)

	// Assert that the response writer was called with a non-nil message
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)
}

func TestDNSDispatcher_HandleDNSRequest_Blocked(t *testing.T) {
	blockList := NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
	server, upstream := startLocalDNS(t,
		func(w dns.ResponseWriter, m *dns.Msg) {
			// shouldn't call upstream
			t.Fail()
		},
	)

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()
	dispatcher, err := NewDNSDispatcher(upstream, blockList, 100)
	assert.NoError(t, err)

	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest(writer, req)

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
	blockList := NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
	server, upstream := startLocalDNS(t, dnsRecord("google.com.", dns.TypeA, []byte{142, 251, 29, 101}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, err := NewDNSDispatcher(upstream, blockList, 100)
	assert.NoError(t, err)

	req := new(dns.Msg)
	req.Question = []dns.Question{
		{Name: "google.com.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		{Name: "ads.0xbt.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest(writer, req)

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
	blockList := NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
	server, upstream := startLocalDNS(t, dnsRecord("example.com.", dns.TypeA, []byte{93, 184, 216, 34}))

	defer func() {
		err := server.Shutdown()
		assert.NoError(t, err)
	}()

	dispatcher, err := NewDNSDispatcher(upstream, blockList, 100)
	assert.NoError(t, err)

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// First request: should be a cache miss and populate the cache
	dispatcher.HandleDNSRequest(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Assert cache stats
	stats := dispatcher.cache.Stat()
	assert.Equal(t, 0, stats.Hits, "Expected 0 cache hit")
	assert.Equal(t, 1, stats.Misses, "Expected 1 cache miss")

	// Reset mock for the second request
	writer = new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Second request: should be a cache hit
	dispatcher.HandleDNSRequest(writer, req)
	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeSuccess, writer.WrittenMsg.Rcode)

	// Assert cache stats
	stats = dispatcher.cache.Stat()
	assert.Equal(t, 1, stats.Hits, "Expected 1 cache hit")
	assert.Equal(t, 1, stats.Misses, "Expected 1 cache miss")
}

func TestDNSDispatcher_ResolveUpstream_BadRCode(t *testing.T) {
	blockList := NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
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

	dispatcher, err := NewDNSDispatcher(upstream, blockList, 100)
	require.NoError(t, err)

	req := new(dns.Msg)
	req.SetQuestion("google.com.", dns.TypeA)

	writer := new(MockResponseWriter)
	writer.On("WriteMsg", mock.Anything).Return(nil)

	// Call the method under test
	dispatcher.HandleDNSRequest(writer, req)

	assert.NotNil(t, writer.WrittenMsg)
	assert.Equal(t, dns.RcodeRefused, writer.WrittenMsg.Rcode)
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
	server := &dns.Server{
		Addr:    ":0", // Use dynamic port
		Net:     "udp",
		Handler: probeDecorator(probeName, handler),
	}

	go func() {
		err := server.ListenAndServe()
		require.NoError(t, err)
	}()

	// Wait for the server's PacketConn to be initialized and get its address
	// This loop is necessary because ListenAndServe blocks, but PacketConn
	// is populated once the listener is active.
	var upstream string
	serverReady := make(chan struct{})
	for range 10 {
		if server.PacketConn != nil {
			upstream = server.PacketConn.LocalAddr().String()
			t.Logf("Mock DNS server listening on: %s", upstream)
			close(serverReady)
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	select {
	case <-serverReady: // Server is ready, continue
	case <-time.After(5 * time.Second):
		t.Fatal("Timed out waiting for mock DNS server to become ready")
	}

	waitForPort(t, upstream, probeName, 5*time.Second)
	return server, upstream
}

func waitForPort(t *testing.T, addr, probeName string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	client := dns.Client{DialTimeout: 100 * time.Millisecond}
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
