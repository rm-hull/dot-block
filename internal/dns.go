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
	dnsClient        *dns.Client
	upstream         string
	defaultTTL       float64
	cache            cache.Cache[string, []dns.RR]
	blockList        *BlockList
	latencyHistogram prometheus.Histogram
	errorCounts      *prometheus.CounterVec
	requestCounts    *prometheus.CounterVec
	uniqueClientsHLL *hyperloglog.Sketch
}

func NewDNSDispatcher(upstream string, blockList *BlockList, maxSize int) *DNSDispatcher {

	cache := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()
	sketch := hyperloglog.New14()
	dnsClient := dns.Client{
		Timeout: 3 * time.Second,
	}

	cacheStats := NewStatsCollector("dns_cache_stats",
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

	latencyHistogram := prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "dns_request_latency",
			Help:    "Duration of DNS requests",
			Buckets: []float64{0.0001, 0.00025, 0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, math.Inf(1)},
		})

	errorCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_error_count",
		Help: "Counts the number of errors broken down by type",
	}, []string{"error"})

	requestCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_request_count",
		Help: "Counts the number of DNS requests, broken down by type: total, allowed, blocked, errored",
	}, []string{"type"})

	uniqueClientsCount := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "dns_unique_clients",
		Help: "Estimates the number of unique clients (relative error ≈ 1.04%)",
	}, func() float64 {
		return float64(sketch.Estimate())
	})

	prometheus.MustRegister(latencyHistogram, errorCounts, cacheStats, requestCounts, uniqueClientsCount)

	return &DNSDispatcher{
		dnsClient:        &dnsClient,
		upstream:         upstream,
		defaultTTL:       300, // TODO: pass in
		cache:            cache,
		blockList:        blockList,
		latencyHistogram: latencyHistogram,
		errorCounts:      errorCounts,
		requestCounts:    requestCounts,
		uniqueClientsHLL: sketch,
	}
}

func (d *DNSDispatcher) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		d.latencyHistogram.Observe(duration)
		d.requestCounts.WithLabelValues("total").Inc()
	}()

	if err := d.updateClientCount(writer); err != nil {
		log.Println(err)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)

	unansweredQuestions := make([]dns.Question, 0, len(req.Question))
	allBlocked := true

	for _, q := range req.Question {
		log.Printf("Query for %s %s", q.Name, dns.TypeToString[q.Qtype])

		isBlocked, err := d.blockList.IsBlocked(q.Name)
		if err != nil {
			d.handleError("blocklist", err)
			resp.Rcode = dns.RcodeServerFailure
			d.sendResponse(writer, resp)
			return
		}

		if isBlocked {
			log.Printf("Domain %s is BLOCKED", q.Name)
			d.requestCounts.WithLabelValues("blocked").Inc()
			continue
		}

		allBlocked = false

		if cachedRRs, ok := d.cache.Get(getCacheKey(&q)); ok {
			resp.Answer = append(resp.Answer, cachedRRs...)
		} else {
			unansweredQuestions = append(unansweredQuestions, q)
		}
	}

	if allBlocked {
		resp.Rcode = dns.RcodeNameError
	} else if len(unansweredQuestions) > 0 {
		upstreamReq := new(dns.Msg)
		upstreamReq.SetQuestion(dns.Fqdn(unansweredQuestions[0].Name), unansweredQuestions[0].Qtype)
		upstreamResp, err := d.forwardQuery(upstreamReq)
		if err != nil {
			d.handleError("upstream", err)
			resp.Rcode = dns.RcodeServerFailure
			d.sendResponse(writer, resp)
			return
		}

		resp.Answer = append(resp.Answer, upstreamResp.Answer...)

		for _, q := range unansweredQuestions {
			// Find answers for this specific question in the upstream response
			var answersForQuestion []dns.RR
			for _, ans := range upstreamResp.Answer {
				if ans.Header().Name == dns.Fqdn(q.Name) && ans.Header().Rrtype == q.Qtype {
					answersForQuestion = append(answersForQuestion, ans)
				}
			}

			if len(answersForQuestion) > 0 {
				cacheTTL := d.defaultTTL
				if answersForQuestion[0].Header().Ttl > 0 {
					cacheTTL = math.Max(cacheTTL, float64(answersForQuestion[0].Header().Ttl))
				}
				d.cache.Set(getCacheKey(&q), answersForQuestion, time.Duration(cacheTTL)*time.Second)
			}
		}
	}

	d.sendResponse(writer, resp)
}

func (d *DNSDispatcher) updateClientCount(writer dns.ResponseWriter) error {
	remoteAddr := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to parse `host:port` from %s: %w", remoteAddr, err)
	}

	d.uniqueClientsHLL.Insert([]byte(host))
	return nil
}

func getCacheKey(q *dns.Question) string {
	return q.Name + ":" + dns.TypeToString[q.Qtype]
}

func (d *DNSDispatcher) handleError(errorCategory string, err error) {
	log.Printf("%s error: %v", errorCategory, err)
	d.errorCounts.WithLabelValues(errorCategory).Inc()
	d.requestCounts.WithLabelValues("errored").Inc()
}

func (d *DNSDispatcher) forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	in, _, err := d.dnsClient.Exchange(req, d.upstream)
	return in, err
}

func (d *DNSDispatcher) sendResponse(writer dns.ResponseWriter, msg *dns.Msg) {
	if err := writer.WriteMsg(msg); err != nil {
		d.handleError("response", err)
		return
	}
	d.requestCounts.WithLabelValues("allowed").Inc()
}
