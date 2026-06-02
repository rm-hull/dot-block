package metrics

import (
	"fmt"
	"math"
	"sync"

	"github.com/axiomhq/hyperloglog"
	"github.com/cockroachdb/errors"
	cache "github.com/go-pkgz/expirable-cache/v3"

	"github.com/prometheus/client_golang/prometheus"
)

const TOP_K = 50

type QueryCountInfo struct {
	QueryType string
	Blocked   bool
}

type UpstreamTTLInfo struct {
	QueryType string
	TTL       float64
}

type TelemetryData struct {
	blockedDomains  []string
	domains         []string
	queryCounts     []QueryCountInfo
	upstreamTTL     *UpstreamTTLInfo
	errorCategory   string
	requestTypes    []string
	upstream        string
	upstreamLatency float64
	rcode           string
}

func (t *TelemetryData) AddBlockedDomain(domain string) {
	t.blockedDomains = append(t.blockedDomains, domain)
}

func (t *TelemetryData) AddDomain(domain string) {
	t.domains = append(t.domains, domain)
}

func (t *TelemetryData) AddQueryCount(queryType string, blocked bool) {
	t.queryCounts = append(t.queryCounts, QueryCountInfo{QueryType: queryType, Blocked: blocked})
}

func (t *TelemetryData) SetUpstreamTTL(queryType string, ttl float64) {
	t.upstreamTTL = &UpstreamTTLInfo{QueryType: queryType, TTL: ttl}
}

func (t *TelemetryData) SetErrorCategory(category string) {
	t.errorCategory = category
}

func (t *TelemetryData) AddRequestType(requestType string) {
	t.requestTypes = append(t.requestTypes, requestType)
}

func (t *TelemetryData) SetUpstream(upstream string, latency float64) {
	t.upstream = upstream
	t.upstreamLatency = latency
}

func (t *TelemetryData) SetRcode(rcode string) {
	t.rcode = rcode
}

// GeoIpLookup is an interface for looking up geolocation information.
type GeoIpLookup interface {
	GetAll(ipAddress string) (string, error)
}

type SafeSketch struct {
	mu     sync.Mutex
	sketch *hyperloglog.Sketch
}

func (s *SafeSketch) Insert(data []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sketch.Insert(data)
}

func (s *SafeSketch) Estimate() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sketch.Estimate()
}

func (m *DnsMetrics) RecordTelemetry(data *TelemetryData, latency float64, source string, ipAddr string) {
	m.RequestLatency.Observe(latency)
	m.RequestCounts.WithLabelValues("total", source).Inc()

	if ipAddr != "" && ipAddr != "unknown" {
		m.TopClients.Add(ipAddr)
		m.UniqueClients.Insert([]byte(ipAddr))

		if m.geoIpLookup != nil {
			if countryCode, err := m.geoIpLookup.GetAll(ipAddr); err == nil && countryCode != "" {
				m.CountryCounts.WithLabelValues(countryCode).Inc()
			}
		}
	}

	for _, qc := range data.queryCounts {
		m.QueryCounts.WithLabelValues(qc.QueryType, fmt.Sprintf("%t", qc.Blocked)).Inc()
	}
	for _, domain := range data.blockedDomains {
		m.TopBlockedDomains.Add(domain)
	}
	for _, domain := range data.domains {
		m.TopDomains.Add(domain)
	}
	if data.upstreamTTL != nil {
		m.UpstreamTTLs.WithLabelValues(data.upstreamTTL.QueryType).Observe(data.upstreamTTL.TTL)
	}
	if data.errorCategory != "" {
		m.ErrorCounts.WithLabelValues(data.errorCategory).Inc()
	}
	for _, rt := range data.requestTypes {
		m.RequestCounts.WithLabelValues(rt, source).Inc()
	}
	if data.upstream != "" {
		m.UpstreamLatency.WithLabelValues(data.upstream).Observe(data.upstreamLatency)
	}
	if data.rcode != "" {
		m.ReplyCounts.WithLabelValues(data.rcode).Inc()
	}
}

type DnsMetrics struct {
	RequestLatency      prometheus.Histogram
	ErrorCounts         *prometheus.CounterVec
	RequestCounts       *prometheus.CounterVec
	QueryCounts         *prometheus.CounterVec
	ReplyCounts         *prometheus.CounterVec
	CountryCounts       *prometheus.CounterVec
	UniqueClients       *SafeSketch
	TopClients          *SpaceSaver
	TopDomains          *SpaceSaver
	TopBlockedDomains   *SpaceSaver
	UpstreamTTLs        *prometheus.HistogramVec
	UpstreamLatency     *prometheus.HistogramVec
	CacheReaperCalls    prometheus.Counter
	DroppedCacheUpdates prometheus.Counter
	DroppedTelemetry    prometheus.Counter
	PoolEvictions       *prometheus.CounterVec
	UpstreamFailures    *prometheus.CounterVec
	PooledConnDeaths    *prometheus.CounterVec
	geoIpLookup         GeoIpLookup
}

var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025,
	0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, math.Inf(1),
}

type Cache interface {
	Stat() cache.Stats
	Len() int
	OnDrop(func())
}

func NewDNSMetrics(cache Cache, geoIpLookup GeoIpLookup) (*DnsMetrics, error) {
	uniqueClients := &SafeSketch{sketch: hyperloglog.New14()}
	topClients := NewSpaceSaver(TOP_K)
	topDomains := NewSpaceSaver(TOP_K)
	topBlockedDomains := NewSpaceSaver(TOP_K)

	cacheStats := NewStatsCollector("dns_cache_stats", "type",
		"Statistics about the cache internals (cache effectiveness: hits & misses, sizing: added & evicted)",
		func() map[string]int {
			stats := cache.Stat()
			return map[string]int{
				"added":   stats.Added,
				"evicted": stats.Evicted,
				"hits":    stats.Hits,
				"misses":  stats.Misses,
				"size":    cache.Len(),
			}
		})

	topDomainsStats := NewStatsCollector("dns_top_domains", "hostname",
		fmt.Sprintf("Shows the top %d most requested (non-blocked) domains (estimate based on count - error)", TOP_K),
		newSpaceSaverStatsCallback(topDomains, TOP_K),
	)

	topBlockedDomainsStats := NewStatsCollector("dns_top_blocked_domains", "hostname",
		fmt.Sprintf("Shows the top %d blocked domains (estimate based on count - error)", TOP_K),
		newSpaceSaverStatsCallback(topBlockedDomains, TOP_K),
	)

	topClientsStats := NewStatsCollector("dns_top_clients", "ip_addr",
		fmt.Sprintf("Shows the top %d most active clients (estimate based on count - error)", TOP_K),
		newSpaceSaverStatsCallback(topClients, TOP_K),
	)

	requestLatency := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_request_latency",
			Help:    "Duration of DNS requests",
			Buckets: latencyBuckets,
		})

	errorCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_error_count",
		Help: "Counts the number of errors broken down by category",
	}, []string{"category"})

	requestCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_request_count",
		Help: "Counts the number of DNS requests, broken down by type (total, errored, forwarded) and source (UDP, TCP, DoT)",
	}, []string{"type", "source"})

	queryCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_query_count",
		Help: "Counts the number of DNS questions, broken down by record_type (A, CNAME, MX, etc) and whether blocked (true/false)",
	}, []string{"record_type", "blocked"})

	replyCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_reply_count",
		Help: "Counts the number of DNS replies, broken down by response code",
	}, []string{"rcode"})

	countryCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_country_count",
		Help: "Counts the number of DNS requests, broken down by country code (ISO 3166-1 alpha-2)",
	}, []string{"iso_code"})

	uniqueClientsCount := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "dns_unique_clients",
		Help: "Estimates the number of unique clients (relative error ≈ 1.04%)",
	}, func() float64 {
		return float64(uniqueClients.Estimate())
	})

	upstreamTTLs := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name: "dns_upstream_ttl_seconds",
		Help: "Observed upstream DNS TTL values (in seconds), broken down by record_type (A, CNAME, MX, etc)",
		Buckets: []float64{
			30, 60, 120, 300, 600, 900, 1800, 3600,
			7200, 14400, 28800, 43200, 86400, 172800, 604800,
		},
	}, []string{"record_type"},
	)

	upstreamLatency := prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "dns_upstream_latency",
		Help:    "Duration of upstream DNS requests, broken down by upstream server",
		Buckets: latencyBuckets,
	}, []string{"ip_addr"})

	cacheReaperCalls := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_reaper_calls",
		Help: "The number of times the cache reaper has been called",
	})

	droppedCacheUpdates := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_dropped_updates_total",
		Help: "Total number of cache updates dropped because the update channel was full",
	})

	droppedTelemetry := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_dropped_telemetry_total",
		Help: "Total number of telemetry events dropped because the worker channel was full",
	})

	poolEvictions := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_pool_evictions_total",
		Help: "Total number of connections evicted from the pool due to it being full, broken down by upstream server",
	}, []string{"ip_addr"})

	upstreamFailures := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_upstream_failures_total",
		Help: "Total number of upstream server failures, broken down by server and reason",
	}, []string{"ip_addr", "reason"})

	pooledConnDeaths := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_pooled_connection_deaths_total",
		Help: "Total number of pooled connections found to be dead during acquisition, broken down by upstream server",
	}, []string{"ip_addr"})

	if err := shouldRegister(
		requestLatency,
		errorCounts,
		cacheStats,
		requestCounts,
		queryCounts,
		replyCounts,
		countryCounts,
		uniqueClientsCount,
		topClientsStats,
		topDomainsStats,
		topBlockedDomainsStats,
		upstreamTTLs,
		upstreamLatency,
		cacheReaperCalls,
		droppedCacheUpdates,
		droppedTelemetry,
		poolEvictions,
		upstreamFailures,
		pooledConnDeaths,
	); err != nil {
		return nil, errors.Wrap(err, "failed to register DNS metrics")
	}

	cache.OnDrop(func() { droppedCacheUpdates.Inc() })

	return &DnsMetrics{
		RequestLatency:      requestLatency,
		ErrorCounts:         errorCounts,
		RequestCounts:       requestCounts,
		QueryCounts:         queryCounts,
		ReplyCounts:         replyCounts,
		CountryCounts:       countryCounts,
		UniqueClients:       uniqueClients,
		TopClients:          topClients,
		TopDomains:          topDomains,
		TopBlockedDomains:   topBlockedDomains,
		UpstreamTTLs:        upstreamTTLs,
		UpstreamLatency:     upstreamLatency,
		CacheReaperCalls:    cacheReaperCalls,
		DroppedCacheUpdates: droppedCacheUpdates,
		DroppedTelemetry:    droppedTelemetry,
		PoolEvictions:       poolEvictions,
		UpstreamFailures:    upstreamFailures,
		PooledConnDeaths:    pooledConnDeaths,
		geoIpLookup:         geoIpLookup,
	}, nil
}

func newSpaceSaverStatsCallback(ss *SpaceSaver, topK int) func() map[string]int {
	return func() map[string]int {
		results := make(map[string]int, topK)
		for _, entry := range ss.TopN(topK) {
			results[entry.Key] = entry.Count - entry.Error
		}
		return results
	}
}
