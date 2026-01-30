package metrics

import (
	"fmt"
	"math"

	"github.com/axiomhq/hyperloglog"
	"github.com/cockroachdb/errors"
	cache "github.com/go-pkgz/expirable-cache/v3"

	"github.com/prometheus/client_golang/prometheus"
)

const TOP_K = 50

type DnsMetrics struct {
	RequestLatency    prometheus.Histogram
	ErrorCounts       *prometheus.CounterVec
	RequestCounts     *prometheus.CounterVec
	QueryCounts       *prometheus.CounterVec
	ReplyCounts       *prometheus.CounterVec
	CountryCounts     *prometheus.CounterVec
	UniqueClients     *hyperloglog.Sketch
	TopClients        *SpaceSaver
	TopDomains        *SpaceSaver
	TopBlockedDomains *SpaceSaver
	UpstreamTTLs      *prometheus.HistogramVec
	UpstreamLatency   *prometheus.HistogramVec
	CacheReaperCalls  prometheus.Counter
}

var latencyBuckets = []float64{
	0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025,
	0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, math.Inf(1),
}

func NewDNSMetrics[K comparable, V any](cache cache.Cache[K, V]) (*DnsMetrics, error) {
	uniqueClients := hyperloglog.New14()
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
		fmt.Sprintf("Shows the top %d most requested (non-blocked) domains", TOP_K),
		newSpaceSaverStatsCallback(topDomains, TOP_K),
	)

	topBlockedDomainsStats := NewStatsCollector("dns_top_blocked_domains", "hostname",
		fmt.Sprintf("Shows the top %d blocked domains", TOP_K),
		newSpaceSaverStatsCallback(topBlockedDomains, TOP_K),
	)

	topClientsStats := NewStatsCollector("dns_top_clients", "ip_addr",
		fmt.Sprintf("Shows the top %d most active clients", TOP_K),
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
		Help: "Counts the number of DNS requests, broken down by type (total, errored, forwarded)",
	}, []string{"type"})

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
		Help:    "Duration of upstream DNS requests, broken down by server",
		Buckets: latencyBuckets,
	}, []string{"ip_addr"})

	cacheReaperCalls := prometheus.NewCounter(prometheus.CounterOpts{
		Name: "dns_cache_reaper_calls",
		Help: "The number of times the cache reaper has been called",
	})

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
	); err != nil {
		return nil, errors.Wrap(err, "failed to register DNS metrics")
	}

	return &DnsMetrics{
		RequestLatency:    requestLatency,
		ErrorCounts:       errorCounts,
		RequestCounts:     requestCounts,
		QueryCounts:       queryCounts,
		ReplyCounts:       replyCounts,
		CountryCounts:     countryCounts,
		UniqueClients:     uniqueClients,
		TopClients:        topClients,
		TopDomains:        topDomains,
		TopBlockedDomains: topBlockedDomains,
		UpstreamTTLs:      upstreamTTLs,
		UpstreamLatency:   upstreamLatency,
		CacheReaperCalls:  cacheReaperCalls,
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
