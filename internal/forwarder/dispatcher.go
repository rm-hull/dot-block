package forwarder

import (
	"log/slog"
	"net"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/getsentry/sentry-go"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/metrics"
)

type DNSDispatcher struct {
	dnsClient  *RoundRobinClient
	defaultTTL float64
	cache      cache.Cache[string, []dns.RR]
	blockList  *blocklist.BlockList
	metrics    *metrics.DnsMetrics
	logger     *slog.Logger
}

func NewDNSDispatcher(dnsClient *RoundRobinClient, blockList *blocklist.BlockList, maxSize int, logger *slog.Logger) (*DNSDispatcher, error) {

	cache := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()
	metrics, err := metrics.NewDNSMetrics(cache)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize")
	}

	return &DNSDispatcher{
		dnsClient:  dnsClient,
		defaultTTL: 300, // TODO: pass in
		cache:      cache,
		blockList:  blockList,
		metrics:    metrics,
		logger:     logger,
	}, nil
}

func (d *DNSDispatcher) HandleDNSRequest(writer dns.ResponseWriter, req *dns.Msg) {
	startTime := time.Now()
	remoteAddr := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		d.logger.Warn("failed to parse client IP from remote address", "remote_addr", remoteAddr, "error", err)
		host = "unknown" // Fallback to "unknown" if IP parsing fails
	}

	requestLogger := d.logger.With("clientIP", host, "requestId", req.Id)

	defer func() {
		duration := time.Since(startTime).Seconds()
		d.metrics.RequestLatency.Observe(duration)
		d.metrics.RequestCounts.WithLabelValues("total").Inc()
	}()

	if err := d.updateClientCount(writer); err != nil {
		requestLogger.Warn("failed to update client count", "error", err)
	}

	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Question = req.Question

	unansweredQuestions := make([]dns.Question, 0, len(req.Question))

	for _, q := range req.Question {
		answers, err := d.processQuestion(requestLogger, &q)
		if err != nil {
			resp.Rcode = dns.RcodeServerFailure
			d.sendResponse(requestLogger, writer, resp)
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
			d.reportError(requestLogger, "upstream", err)
			d.sendResponse(requestLogger, writer, resp)
			return
		}

		resp.Answer = append(resp.Answer, answers...)
	}

	if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
		resp.Rcode = dns.RcodeNameError
	}

	d.sendResponse(requestLogger, writer, resp)
}

func (d *DNSDispatcher) processQuestion(requestLogger *slog.Logger, q *dns.Question) ([]dns.RR, error) {
	queryType := getQueryType(q)
	requestLogger.Info("Query received", "name", q.Name, "type", queryType)
	d.metrics.TopDomains.Add(q.Name)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		d.reportError(requestLogger, "blocklist", err)
		return nil, err
	}

	if isBlocked {
		requestLogger.Info("Domain blocked", "name", q.Name)
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
	if cachedRRs, ok := d.cache.Get(getCacheKey(q)); ok {
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
		return upstreamResp.Rcode, nil, errors.Newf("resolver returned a non-success Rcode: %s", dns.RcodeToString[upstreamResp.Rcode])
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
			upstreamTTL := answersForQuestion[0].Header().Ttl
			d.cache.Set(key, answersForQuestion, time.Duration(upstreamTTL)*time.Second)
			d.metrics.UpstreamTTLs.WithLabelValues(getQueryType(&q)).Observe(float64(upstreamTTL))
		}
	}

	return upstreamReq.Rcode, upstreamResp.Answer, nil
}

func (d *DNSDispatcher) updateClientCount(writer dns.ResponseWriter) error {
	remoteAddr := writer.RemoteAddr().String()
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return errors.Wrapf(err, "failed to parse `host:port` from %s", remoteAddr)
	}

	d.metrics.TopClients.Add(host)
	d.metrics.UniqueClients.Insert([]byte(host))
	return nil
}

func (d *DNSDispatcher) reportError(requestLogger *slog.Logger, errorCategory string, err error) {
	requestLogger.Error("DNS error", "category", errorCategory, "error", err)
	d.metrics.ErrorCounts.WithLabelValues(errorCategory).Inc()
	d.metrics.RequestCounts.WithLabelValues("errored").Inc()
	sentry.CaptureException(err)
}

func (d *DNSDispatcher) forwardQuery(req *dns.Msg) (*dns.Msg, error) {
	startTime := time.Now()
	d.metrics.RequestCounts.WithLabelValues("forwarded").Inc()
	in, upstream, err := d.dnsClient.Exchange(req)

	duration := time.Since(startTime).Seconds()
	d.metrics.UpstreamLatency.WithLabelValues(upstream).Observe(duration)
	return in, err
}

func (d *DNSDispatcher) sendResponse(requestLogger *slog.Logger, writer dns.ResponseWriter, msg *dns.Msg) {
	d.metrics.ReplyCounts.WithLabelValues(dns.RcodeToString[msg.Rcode]).Inc()
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError(requestLogger, "response", err)
		return
	}
}

func getCacheKey(q *dns.Question) string {
	return dns.Fqdn(q.Name) + ":" + getQueryType(q)
}

func getQueryType(q *dns.Question) string {
	return dns.TypeToString[q.Qtype]
}
