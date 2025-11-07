package internal

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/rm-hull/dot-block/internal/metrics"

	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
)

type DNSDispatcher struct {
	dnsClient  *RoundRobinClient
	defaultTTL float64
	cache      cache.Cache[string, []dns.RR]
	blockList  *BlockList
	metrics    *metrics.DnsMetrics
}

func NewDNSDispatcher(dnsClient *RoundRobinClient, blockList *BlockList, maxSize int) (*DNSDispatcher, error) {

	cache := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()
	metrics, err := metrics.NewDNSMetrics(cache)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize: %w", err)
	}

	return &DNSDispatcher{
		dnsClient:  dnsClient,
		defaultTTL: 300, // TODO: pass in
		cache:      cache,
		blockList:  blockList,
		metrics:    metrics,
	}, nil
}

func (d *DNSDispatcher) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	startTime := time.Now()
	defer func() {
		duration := time.Since(startTime).Seconds()
		d.metrics.LatencyHistogram.Observe(duration)
		d.metrics.RequestCounts.WithLabelValues("total").Inc()
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
	d.metrics.TopDomains.Add(q.Name)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		d.reportError("blocklist", err)
		return nil, err
	}

	if isBlocked {
		log.Printf("Domain %s is BLOCKED", q.Name)
		d.metrics.QueryCounts.WithLabelValues(queryType, "true").Inc()

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

	d.metrics.QueryCounts.WithLabelValues(queryType, "false").Inc()
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

	d.metrics.TopClients.Add(host)
	d.metrics.UniqueClients.Insert([]byte(host))
	return nil
}

func (d *DNSDispatcher) reportError(errorCategory string, err error) {
	log.Printf("%s error: %v", errorCategory, err)
	d.metrics.ErrorCounts.WithLabelValues(errorCategory).Inc()
	d.metrics.RequestCounts.WithLabelValues("errored").Inc()
}

func (d *DNSDispatcher) forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	d.metrics.RequestCounts.WithLabelValues("forwarded").Inc()
	in, err := d.dnsClient.Exchange(req)
	return in, err
}

func (d *DNSDispatcher) sendResponse(writer dns.ResponseWriter, msg *dns.Msg) {
	d.metrics.ReplyCounts.WithLabelValues(dns.RcodeToString[msg.Rcode]).Inc()
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError("response", err)
		return
	}
}

func getCacheKey(q *dns.Question) string {
	return dns.Fqdn(q.Name) + ":" + dns.TypeToString[q.Qtype]
}
