package forwarder

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/noisefilter"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// benchResponseWriter is a minimal dns.ResponseWriter for benchmarks.
type benchResponseWriter struct {
	ip   string
	port int
}

func (w *benchResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080}
}

func (w *benchResponseWriter) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP(w.ip), Port: w.port}
}

func (w *benchResponseWriter) WriteMsg(msg *dns.Msg) error { return nil }
func (w *benchResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (w *benchResponseWriter) Close() error                { return nil }
func (w *benchResponseWriter) TsigStatus() error           { return nil }
func (w *benchResponseWriter) TsigTimersOnly(b bool)       {}
func (w *benchResponseWriter) Hijack()                     {}

// setupDispatcherBench creates a DNSDispatcher for benchmarking.
func setupDispatcherBench(b *testing.B, upstream string, enableECS bool) *DNSDispatcher {
	b.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	blockList := blocklist.NewBlockList("bench", "http://dummy.url", 0.0001, logger)
	blockList.Load([]string{"ads.0xbt.net", "tracker.example.com"})

	cache := NewDNSCache(10000, logger)
	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)

	dnsMetrics, err := metrics.NewDNSMetrics(cache, mockGeo)
	require.NoError(b, err)

	dnsClient, err := NewRoundRobinClient(dnsMetrics, 2*time.Second, 2*time.Second, 2*time.Second, logger, upstream)
	require.NoError(b, err)

	dispatcher, err := NewDNSDispatcher(
		cache, dnsMetrics, dnsClient,
		[]*blocklist.BlockList{blockList},
		noisefilter.NewNoiseFilter(),
		sse.NewBroadcaster(logger, dnsMetrics.DroppedSSEEvents),
		1*time.Minute, logger, enableECS,
	)
	require.NoError(b, err)
	b.Cleanup(dispatcher.Close)

	return dispatcher
}

// startLocalDNSBench starts a local DNS server for benchmarking.
func startLocalDNSBench(b *testing.B, handler dns.HandlerFunc) (*dns.Server, string) {
	b.Helper()
	probeName := fmt.Sprintf("probe-%d.local.", time.Now().UnixNano())

	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(b, err)
	addr := l.LocalAddr().String()

	server := &dns.Server{
		PacketConn: l,
		Handler:    probeDecorator(probeName, handler),
	}

	go func() {
		_ = server.ActivateAndServe()
	}()

	client := dns.Client{DialTimeout: 100 * time.Millisecond, Net: "udp"}
	req := new(dns.Msg)
	req.SetQuestion(probeName, dns.TypeA)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _, err := client.Exchange(req, addr)
		if err == nil {
			return server, addr
		}
		time.Sleep(50 * time.Millisecond)
	}
	b.Fatalf("server not ready at %s", addr)
	return nil, ""
}

// anyRecordHandler responds to any query with a success A record.
func anyRecordHandler() dns.HandlerFunc {
	return func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.SetRcode(r, dns.RcodeSuccess)
		m.Authoritative = true
		for _, q := range r.Question {
			m.Answer = append(m.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: q.Qtype,
					Class:  dns.ClassINET,
					Ttl:    3600,
				},
				A: []byte{1, 2, 3, 4},
			})
		}
		_ = w.WriteMsg(m)
	}
}

// prePopulateCache populates the dispatcher cache with a single record.
func prePopulateCache(b *testing.B, dispatcher *DNSDispatcher, domain string, ip []byte) {
	b.Helper()
	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   dns.Fqdn(domain),
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: ip,
	}
	cacheKey := getCacheKey(&dns.Question{
		Name:   dns.Fqdn(domain),
		Qtype:  dns.TypeA,
		Qclass: dns.ClassINET,
	}, "")

	dispatcher.cache.Set(cacheKey, []dns.RR{aRecord}, 3600*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := dispatcher.cache.Get(cacheKey); ok {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	b.Fatalf("cache not populated for %s", domain)
}

func BenchmarkDNSDispatcher(b *testing.B) {
	b.Run("CacheHit", benchmarkCacheHit)
	b.Run("CacheMiss", benchmarkCacheMiss)
	b.Run("Blocked", benchmarkBlocked)
	b.Run("BlockedWithEDE", benchmarkBlockedWithEDE)
	b.Run("DNSSD", benchmarkDNSSD)
	b.Run("ReservedTLD", benchmarkReservedTLD)
	b.Run("MultipleQuestions", benchmarkMultipleQuestions)
	b.Run("ECS", benchmarkECS)
}

func benchmarkCacheHit(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	dispatcher := setupDispatcherBench(b, upstream, false)
	prePopulateCache(b, dispatcher, "example.com.", []byte{93, 184, 216, 34})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	for b.Loop() {
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func benchmarkCacheMiss(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	dispatcher := setupDispatcherBench(b, upstream, false)

	i := 0
	for b.Loop() {
		req := new(dns.Msg)
		req.SetQuestion(fmt.Sprintf("host%d.example.com.", i), dns.TypeA)
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
		i++
	}
}

func benchmarkBlocked(b *testing.B) {
	dispatcher := setupDispatcherBench(b, "127.0.0.1:53", false)
	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)

	for b.Loop() {
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func benchmarkBlockedWithEDE(b *testing.B) {
	dispatcher := setupDispatcherBench(b, "127.0.0.1:53", false)
	req := new(dns.Msg)
	req.SetQuestion("ads.0xbt.net.", dns.TypeA)
	req.SetEdns0(1232, false)

	for b.Loop() {
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func benchmarkDNSSD(b *testing.B) {
	dispatcher := setupDispatcherBench(b, "127.0.0.1:53", false)
	req := new(dns.Msg)
	req.SetQuestion("db._dns-sd._udp.0.68.168.192.in-addr.arpa.", dns.TypePTR)

	for b.Loop() {
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func benchmarkReservedTLD(b *testing.B) {
	dispatcher := setupDispatcherBench(b, "127.0.0.1:53", false)
	req := new(dns.Msg)
	req.SetQuestion("example.invalid.", dns.TypeA)

	for b.Loop() {
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func benchmarkMultipleQuestions(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	dispatcher := setupDispatcherBench(b, upstream, false)

	i := 0
	for b.Loop() {
		req := new(dns.Msg)
		req.Question = []dns.Question{
			{Name: fmt.Sprintf("host%d.example.com.", i), Qtype: dns.TypeA, Qclass: dns.ClassINET},
			{Name: "ads.0xbt.net.", Qtype: dns.TypeA, Qclass: dns.ClassINET},
		}
		writer := &benchResponseWriter{}
		dispatcher.HandleDNSRequest("test")(writer, req)
		i++
	}
}

func benchmarkECS(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	dispatcher := setupDispatcherBench(b, upstream, true)
	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	for b.Loop() {
		writer := &benchResponseWriter{ip: "1.2.3.4", port: 12345}
		dispatcher.HandleDNSRequest("test")(writer, req)
	}
}

func BenchmarkDNSDispatcherConcurrent(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	dispatcher := setupDispatcherBench(b, upstream, false)
	prePopulateCache(b, dispatcher, "example.com.", []byte{93, 184, 216, 34})

	req := new(dns.Msg)
	req.SetQuestion("example.com.", dns.TypeA)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		writer := &benchResponseWriter{}
		for pb.Next() {
			dispatcher.HandleDNSRequest("test")(writer, req)
		}
	})
}

func BenchmarkDNSCache(b *testing.B) {
	b.Run("Get", benchmarkDNSCacheGet)
	b.Run("Set", benchmarkDNSCacheSet)
}

func benchmarkDNSCacheGet(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewDNSCache(10000, logger)
	b.Cleanup(cache.Close)

	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: []byte{93, 184, 216, 34},
	}
	cacheKey := "example.com.:A"
	cache.Set(cacheKey, []dns.RR{aRecord}, 3600*time.Second)

	// Wait for cache to be populated
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := cache.Get(cacheKey); ok {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	for b.Loop() {
		_, _ = cache.Get(cacheKey)
	}
}

func benchmarkDNSCacheSet(b *testing.B) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewDNSCache(10000, logger)
	b.Cleanup(cache.Close)

	aRecord := &dns.A{
		Hdr: dns.RR_Header{
			Name:   "example.com.",
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    3600,
		},
		A: []byte{1, 2, 3, 4},
	}

	i := 0
	for b.Loop() {
		cacheKey := fmt.Sprintf("host%d.com.:A", i)
		cache.Set(cacheKey, []dns.RR{aRecord}, 3600*time.Second)
		i++
	}
}

func BenchmarkRoundRobinClient(b *testing.B) {
	server, upstream := startLocalDNSBench(b, anyRecordHandler())
	defer func() { _ = server.Shutdown() }()

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cache := NewDNSCache(100, logger)
	b.Cleanup(cache.Close)

	mockGeo := new(MockGeoIpLookup)
	mockGeo.On("GetAll", mock.Anything).Return(geoblock.GeoData{}, nil)
	dnsMetrics, err := metrics.NewDNSMetrics(cache, mockGeo)
	require.NoError(b, err)

	client, err := NewRoundRobinClient(dnsMetrics, 2*time.Second, 2*time.Second, 2*time.Second, logger, upstream)
	require.NoError(b, err)

	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	for b.Loop() {
		_, _, err := client.Exchange(msg)
		if err != nil {
			b.Fatalf("Exchange failed: %v", err)
		}
	}
}
