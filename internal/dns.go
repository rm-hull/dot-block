package internal

import (
	"fmt"
	"log"
	"math"
	"net"
	"time"

	"github.com/axiomhq/hyperloglog"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

type DNSDispatcher struct {
	upstream         string
	defaultTTL       float64
	cache            cache.Cache[string, *dns.Msg]
	blockList        *BlockList
	latencyHistogram prometheus.Histogram
	errorCounts      *prometheus.CounterVec
	cacheStats       *prometheus.GaugeVec
	requestCounts    *prometheus.CounterVec
	uniqueClientsHLL *hyperloglog.Sketch
}

func NewDNSDispatcher(upstream string, blockList *BlockList, maxSize int) *DNSDispatcher {
	latencyHistogram := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_request_latency",
			Help:    "Duration of DNS requests",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, math.Inf(1)},
		})

	errorCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_error_count",
		Help: "DNS error count",
	}, []string{"error"})

	cacheStats := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "dns_cache_stats",
		Help: "DNS cache stats",
	}, []string{"type"})

	requestCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_request_count",
		Help: "Counts the number of DNS requests, broken down by type: total, allowed, blocked, errored",
	}, []string{"type"})

	sketch := hyperloglog.New14()
	uniqueClientsCount := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "dns_unique_clients",
		Help: "Estimates the number of unique clients (relative error ≈ 1.04%)",
	}, func() float64 {
		return float64(sketch.Estimate())
	})

	prometheus.MustRegister(latencyHistogram, errorCounts, cacheStats, requestCounts, uniqueClientsCount)

	return &DNSDispatcher{
		upstream:         upstream,
		defaultTTL:       300, // TODO: pass in
		cache:            cache.NewCache[string, *dns.Msg]().WithMaxKeys(maxSize).WithLRU(),
		blockList:        blockList,
		latencyHistogram: latencyHistogram,
		errorCounts:      errorCounts,
		cacheStats:       cacheStats,
		requestCounts:    requestCounts,
		uniqueClientsHLL: sketch,
	}
}

func (d *DNSDispatcher) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		d.latencyHistogram.Observe(duration)

		stats := d.cache.Stat()
		d.cacheStats.WithLabelValues("added").Set(float64(stats.Added))
		d.cacheStats.WithLabelValues("evicted").Set(float64(stats.Evicted))
		d.cacheStats.WithLabelValues("hits").Set(float64(stats.Hits))
		d.cacheStats.WithLabelValues("misses").Set(float64(stats.Misses))

		d.requestCounts.WithLabelValues("total").Inc()
	}()

	if err := d.updateClientCount(writer); err != nil {
		log.Println(err)
	}

	// FIXME: what happens if there is more than one question here?
	for _, q := range req.Question {
		log.Printf("Query for %s %s", q.Name, dns.TypeToString[q.Qtype])

		isBlocked, err := d.blockList.IsBlocked(q.Name)
		if err != nil {
			d.handleError(fmt.Errorf("blocklist error: %w", err), writer, req)
			return
		}

		if isBlocked {
			log.Printf("Domain %s is BLOCKED", q.Name)
			if err := d.sendNXDOMAIN(writer, req); err != nil {
				d.handleError(fmt.Errorf("send NXDOMAIN failed: %w", err), writer, req)
				return
			}
			d.requestCounts.WithLabelValues("blocked").Inc()
			return
		}

		if cachedResp, ok := d.cache.Get(getCacheKey(&q)); ok {
			cachedResp.Id = req.Id
			d.sendResponse(writer, cachedResp, req)
			return
		}
	}

	resp, err := d.forwardQuery(req)
	if err != nil {
		d.handleError(fmt.Errorf("upstream error: %w", err), writer, req)
		return
	}

	for index, q := range req.Question {
		cacheTTL := d.defaultTTL
		if index < len(resp.Answer) {
			cacheTTL = math.Max(cacheTTL, float64(resp.Answer[index].Header().Ttl))
		}
		d.cache.Set(getCacheKey(&q), resp, time.Duration(cacheTTL)*time.Second)
	}

	d.sendResponse(writer, resp, req)
}

func (d *DNSDispatcher) updateClientCount(writer dns.ResponseWriter) error {
	remoteAddr := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to parse host:port from %s: %w", remoteAddr, err)
	}

	d.uniqueClientsHLL.Insert([]byte(host))
	return nil
}

func getCacheKey(q *dns.Question) string {
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func (d *DNSDispatcher) handleError(err error, w dns.ResponseWriter, r *dns.Msg) {
	log.Println(err.Error())
	dns.HandleFailed(w, r)
	d.errorCounts.WithLabelValues(err.Error()).Inc()
	d.requestCounts.WithLabelValues("errored").Inc()
}

func (d *DNSDispatcher) forwardQuery(r *dns.Msg) (*dns.Msg, error) {
	c := new(dns.Client)
	c.Timeout = 3 * time.Second
	in, _, err := c.Exchange(r, d.upstream)
	return in, err
}

func (d *DNSDispatcher) sendNXDOMAIN(w dns.ResponseWriter, r *dns.Msg) error {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true
	m.Rcode = dns.RcodeNameError // NXDOMAIN

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   r.Question[0].Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    60,
		},
		Ns:      "ns.blocked.local.", // fake authoritative name server
		Mbox:    "hostmaster.blocked.local.",
		Serial:  1,
		Refresh: 3600,
		Retry:   600,
		Expire:  86400,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	if err := w.WriteMsg(m); err != nil {
		return fmt.Errorf("failed to send NXDOMAIN: %w", err)
	}

	return nil
}

func (d *DNSDispatcher) sendResponse(writer dns.ResponseWriter, msg *dns.Msg, req *dns.Msg) {
	if err := writer.WriteMsg(msg); err != nil {
		d.handleError(fmt.Errorf("failed to send response: %w", err), writer, req)
		return
	}
	d.requestCounts.WithLabelValues("allowed").Inc()
}
