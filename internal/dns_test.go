package internal

import (
	"net"
	"testing"

	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
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

var blockList = NewBlockList([]string{"ads.0xbt.net"}, 0.0001)
var upstream = "8.8.8.8:53"

func TestDNSDispatcher_HandleDNSRequest_Allowed(t *testing.T) {
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
	assert.Len(t, writer.WrittenMsg.Answer, 7)
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
