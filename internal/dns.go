package internal

import (
	"log"
	"math"
	"time"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type DNSDispatcher struct {
	upstream         string
	defaultTTL       float64
	cache            cache.Cache[string, *dns.Msg]
	latencyHistogram prometheus.Histogram
	upstreamErrors   *prometheus.CounterVec
	cacheStats       *prometheus.GaugeVec
}

func NewDNSDispatcher(upstream string, maxSize int) *DNSDispatcher {
	latencyHistogram := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_request_latency",
			Help:    "Duration of DNS requests",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, math.Inf(1)},
		},
	)

	upstreamErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_upstream_errors",
		Help: "DNS upstream errors",
	}, []string{"error"},
	)

	cacheStats := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_cache_stats",
		Help: "DNS cache stats",
	}, []string{"type"})

	prometheus.MustRegister(latencyHistogram, upstreamErrors, cacheStats)

	return &DNSDispatcher{
		upstream:         upstream,
		defaultTTL:       300, // TODO: pass in
		cache:            cache.NewCache[string, *dns.Msg]().WithMaxKeys(maxSize).WithLRU(),
		latencyHistogram: latencyHistogram,
		upstreamErrors:   upstreamErrors,
		cacheStats:       cacheStats,
	}
}

func (d *DNSDispatcher) HandleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		d.latencyHistogram.Observe(duration)

		stats := d.cache.Stat()
		d.cacheStats.WithLabelValues("added").Set(float64(stats.Added))
		d.cacheStats.WithLabelValues("evicted").Set(float64(stats.Evicted))
		d.cacheStats.WithLabelValues("hits").Set(float64(stats.Hits))
		d.cacheStats.WithLabelValues("misses").Set(float64(stats.Misses))
	}()

	for _, q := range r.Question {
		log.Printf("Query for %s %s", q.Name, dns.TypeToString[q.Qtype])
		cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
		if msg, ok := d.cache.Get(cacheKey); ok {
			log.Printf("Serving from cache: %s", q.Name)
			msg.Id = r.Id
			w.WriteMsg(msg)
			return
		}
	}

	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	resp, err := d.forwardQuery(r)
	if err != nil {
		log.Printf("Upstream error: %v", err)
		dns.HandleFailed(w, r)
		d.upstreamErrors.WithLabelValues(err.Error()).Inc()
		return
	}

	for index, q := range r.Question {
		cacheKey := q.Name + ":" + dns.TypeToString[q.Qtype]
		ttl := d.defaultTTL
		if index < len(resp.Answer) {
			ttl = float64(resp.Answer[index].Header().Ttl)
		}
		d.cache.Set(cacheKey, resp, time.Duration(ttl)*time.Second)
	}

	w.WriteMsg(resp)
}

func (d *DNSDispatcher) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	in, _, err := c.Exchange(r, d.upstream)
	return in, err
}
