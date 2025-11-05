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

const TOP_K = 20

type DNSDispatcher struct {
	dnsClient        *dns.Client
	upstream         string
	defaultTTL       float64
	cache            cache.Cache[string, []dns.RR]
	blockList        *BlockList
	latencyHistogram prometheus.Histogram
	errorCounts      *prometheus.CounterVec
	requestCounts    *prometheus.CounterVec
	queryCounts      *prometheus.CounterVec
	uniqueClientsHLL *hyperloglog.Sketch
	topClients       *SpaceSaver
	topDomains       *SpaceSaver
}

func NewDNSDispatcher(upstream string, blockList *BlockList, maxSize int) (*DNSDispatcher, error) {

	cache := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()
	sketch := hyperloglog.New14()
	dnsClient := dns.Client{Timeout: 3 * time.Second}
	topClients := NewSpaceSaver(TOP_K)
	topDomains := NewSpaceSaver(TOP_K)

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
		fmt.Sprintf("Shows the top %d most requested domains", TOP_K),
		func() map[string]int {
			results := make(map[string]int)
			for _, entry := range topDomains.TopN(TOP_K) {
				results[entry.Key] = entry.Count
			}
			return results
		})

	topClientsStats := NewStatsCollector("dns_top_clients", "ip_addr",
		fmt.Sprintf("Shows the top %d most active clients", TOP_K),
		func() map[string]int {
			results := make(map[string]int)
			for _, entry := range topClients.TopN(TOP_K) {
				results[entry.Key] = entry.Count
			}
			return results
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
		Help: "Counts the number of DNS requests, broken down by type: total, errored, forwarded",
	}, []string{"type"})

	queryCounts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "dns_query_count",
		Help: "Counts the number of DNS questions, broken down by type (A, CNAME, MX, etc) and whether blocked (true/false)",
	}, []string{"type", "blocked"})

	uniqueClientsCount := prometheus.NewCounterFunc(prometheus.CounterOpts{
		Name: "dns_unique_clients",
		Help: "Estimates the number of unique clients (relative error ≈ 1.04%)",
	}, func() float64 {
		return float64(sketch.Estimate())
	})

	if err := shouldRegister(
		latencyHistogram,
		errorCounts,
		cacheStats,
		requestCounts,
		queryCounts,
		uniqueClientsCount,
		topClientsStats,
		topDomainsStats,
	); err != nil {
		return nil, fmt.Errorf("failed to register: %w", err)
	}

	return &DNSDispatcher{
		dnsClient:        &dnsClient,
		upstream:         upstream,
		defaultTTL:       300, // TODO: pass in
		cache:            cache,
		blockList:        blockList,
		latencyHistogram: latencyHistogram,
		errorCounts:      errorCounts,
		requestCounts:    requestCounts,
		queryCounts:      queryCounts,
		uniqueClientsHLL: sketch,
		topClients:       topClients,
		topDomains:       topDomains,
	}, nil
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
	resp.Question = req.Question

	unansweredQuestions := make([]dns.Question, 0, len(req.Question))

	for _, q := range req.Question {
		answers, err := d.processQuestion(q)
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
			d.sendResponse(writer, resp)
			return
		}

		if len(answers) > 0 {
			resp.Answer = append(resp.Answer, answers...)
		} else {
			unansweredQuestions = append(unansweredQuestions, q)
		}
	}

	if len(unansweredQuestions) > 0 {
		rcode, answers, err := d.resolveUpstream(unansweredQuestions, req)
		if err != nil {
			resp.Rcode = rcode
			d.reportError("upstream", err)
			d.sendResponse(writer, resp)
			return
		}

		resp.Answer = append(resp.Answer, answers...)
	}

	if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
		resp.Rcode = dns.RcodeNameError
	}

	d.sendResponse(writer, resp)
}

func (d *DNSDispatcher) processQuestion(q dns.Question) ([]dns.RR, error) {
	queryType := dns.TypeToString[q.Qtype]
	log.Printf("Query for %s %s", q.Name, queryType)
	d.topDomains.Add(q.Name)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		d.reportError("blocklist", err)
		return nil, err
	}

	if isBlocked {
		log.Printf("Domain %s is BLOCKED", q.Name)
		d.queryCounts.WithLabelValues(queryType, "true").Inc()

		soa := &dns.SOA{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeSOA,
				Class:  dns.ClassINET,
				Ttl:    uint32(d.defaultTTL),
			},
			Ns:   "ns.blocked.local.",
			Mbox: "hostmaster.blocked.local.", Serial: 1,
			Refresh: 3600,
			Retry:   900,
			Expire:  604800,
			Minttl:  uint32(d.defaultTTL),
		}
		return []dns.RR{soa}, nil
	}

	d.queryCounts.WithLabelValues(queryType, "false").Inc()
	if cachedRRs, ok := d.cache.Get(getCacheKey(&q)); ok {
		return cachedRRs, nil
	}

	return nil, nil
}

func (d *DNSDispatcher) resolveUpstream(unansweredQuestions []dns.Question, req *dns.Msg) (int, []dns.RR, error) {
	upstreamReq := new(dns.Msg)
	upstreamReq.Id = dns.Id()
	upstreamReq.RecursionDesired = req.RecursionDesired
	upstreamReq.Question = unansweredQuestions

	upstreamResp, err := d.forwardQuery(upstreamReq)
	if err != nil {
		return dns.RcodeServerFailure, nil, err
	}

	if upstreamResp.Rcode != dns.RcodeSuccess {
		// Propagate the upstream response Rcode if not successful
		return upstreamResp.Rcode, nil, fmt.Errorf("resolver returned a non-success Rcode: %s", dns.RcodeToString[upstreamResp.Rcode])
	}

	// Group answers by question for efficient lookup
	answerMap := make(map[string][]dns.RR)
	for _, ans := range upstreamResp.Answer {
		key := dns.Fqdn(ans.Header().Name) + ":" + dns.TypeToString[ans.Header().Rrtype]
		answerMap[key] = append(answerMap[key], ans)
	}

	// Process unanswered questions and cache the results
	for _, q := range unansweredQuestions {
		key := getCacheKey(&q)
		if answersForQuestion, ok := answerMap[key]; ok {
			cacheTTL := answersForQuestion[0].Header().Ttl
			d.cache.Set(key, answersForQuestion, time.Duration(cacheTTL)*time.Second)
		}
	}

	return upstreamReq.Rcode, upstreamResp.Answer, nil
}

func (d *DNSDispatcher) updateClientCount(writer dns.ResponseWriter) error {
	remoteAddr := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return fmt.Errorf("failed to parse `host:port` from %s: %w", remoteAddr, err)
	}

	d.topClients.Add(host)
	d.uniqueClientsHLL.Insert([]byte(host))
	return nil
}

func (d *DNSDispatcher) reportError(errorCategory string, err error) {
	log.Printf("%s error: %v", errorCategory, err)
	d.errorCounts.WithLabelValues(errorCategory).Inc()
	d.requestCounts.WithLabelValues("errored").Inc()
}

func (d *DNSDispatcher) forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	d.requestCounts.WithLabelValues("forwarded").Inc()
	in, _, err := d.dnsClient.Exchange(req, d.upstream)
	return in, err
}

func (d *DNSDispatcher) sendResponse(writer dns.ResponseWriter, msg *dns.Msg) {
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError("response", err)
		return
	}
}

func getCacheKey(q *dns.Question) string {
	return dns.Fqdn(q.Name) + ":" + dns.TypeToString[q.Qtype]
}
