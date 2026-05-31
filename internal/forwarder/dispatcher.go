package forwarder

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/getsentry/sentry-go"
	cache "github.com/go-pkgz/expirable-cache/v3"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/metrics"
)

type DNSSource string

const (
	SourceUDP DNSSource = "UDP"
	SourceTCP DNSSource = "TCP"
	SourceDoT DNSSource = "DoT"
)

type RequestContext struct {
	Logger    *slog.Logger
	Source    DNSSource
	StartTime time.Time
}

type DispatcherFunc func(writer dns.ResponseWriter, req *dns.Msg)

type DNSDispatcher struct {
	dnsClient     *RoundRobinClient
	defaultTTL    float64
	cacheTtlFloor time.Duration
	cache         cache.Cache[string, []dns.RR]
	blockList     *blocklist.BlockList
	geoIpLookup   geoblock.GeoIpLookup
	metrics       *metrics.DnsMetrics
	logger        *slog.Logger
}

func NewDNSDispatcher(
	dnsClient *RoundRobinClient,
	blockList *blocklist.BlockList,
	geoIpLookup geoblock.GeoIpLookup,
	maxSize int,
	cacheTtlFloor time.Duration,
	logger *slog.Logger,
) (*DNSDispatcher, error) {

	if cacheTtlFloor < 0 {
		return nil, errors.New("cacheTtlFloor cannot be negative")
	}

	cache := cache.NewCache[string, []dns.RR]().WithMaxKeys(maxSize).WithLRU()
	metrics, err := metrics.NewDNSMetrics(cache)
	if err != nil {
		return nil, errors.Wrap(err, "failed to initialize")
	}

	return &DNSDispatcher{
		dnsClient:     dnsClient,
		defaultTTL:    300, // TODO: pass in
		cacheTtlFloor: cacheTtlFloor,
		cache:         cache,
		blockList:     blockList,
		geoIpLookup:   geoIpLookup,
		metrics:       metrics,
		logger:        logger,
	}, nil
}

func (d *DNSDispatcher) HandleDNSRequest(source DNSSource) DispatcherFunc {
	return func(writer dns.ResponseWriter, req *dns.Msg) {
		remoteAddr := writer.RemoteAddr().String()
		ipAddr, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			d.logger.Warn("failed to parse client IP from remote address",
				"remote_addr", remoteAddr,
				"source", source,
				"error", err)

			ipAddr = "unknown" // Fallback to "unknown" if IP parsing fails
		} else {
			d.metrics.TopClients.Add(ipAddr)
			d.metrics.UniqueClients.Insert([]byte(ipAddr))
		}

		ctx := &RequestContext{
			Logger:    d.logger.With("clientIP", ipAddr, "requestId", req.Id, "source", source),
			Source:    source,
			StartTime: time.Now(),
		}

		defer func() {
			duration := time.Since(ctx.StartTime).Seconds()
			d.metrics.RequestLatency.Observe(duration)
			d.metrics.RequestCounts.WithLabelValues("total", string(source)).Inc()

			if ipAddr == "unknown" {
				return // Skip geolocation if IP is unknown
			}

			loc, err := d.geoIpLookup.GetAll(ipAddr)
			if err != nil {
				ctx.Logger.Warn("failed to get geolocation for client IP", "error", err)
			} else {
				d.metrics.CountryCounts.WithLabelValues(loc.Country_short).Inc()
			}
		}()

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Question = req.Question

		unansweredQuestions := make([]dns.Question, 0, len(req.Question))

		for _, q := range req.Question {
			answers, err := d.processQuestion(ctx, &q)
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
				d.sendResponse(ctx, writer, resp)
				return
			}

			if len(answers) > 0 {
				resp.Answer = append(resp.Answer, answers...)
			} else {
				unansweredQuestions = append(unansweredQuestions, q)
			}
		}

		if len(unansweredQuestions) > 0 {
			rcode, answers, err := d.resolveUpstream(ctx, unansweredQuestions, req)
			if err != nil {
				resp.Rcode = rcode
				d.reportError(ctx, "upstream", err, "qtype", getQueryType(&unansweredQuestions[0]))
				d.sendResponse(ctx, writer, resp)
				return
			}

			resp.Answer = append(resp.Answer, answers...)
		}

		if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
			resp.Rcode = dns.RcodeNameError
		}

		d.sendResponse(ctx, writer, resp)
	}
}

func (d *DNSDispatcher) processQuestion(ctx *RequestContext, q *dns.Question) ([]dns.RR, error) {
	queryType := getQueryType(q)
	ctx.Logger.Debug("Query received",
		"name", q.Name,
		"type", queryType)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		d.reportError(ctx, "blocklist", err, "qtype", queryType)
		return nil, err
	}

	if isBlocked {
		ctx.Logger.Debug("Domain blocked", "name", q.Name)
		d.metrics.TopBlockedDomains.Add(q.Name)
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

	d.metrics.TopDomains.Add(q.Name)
	d.metrics.QueryCounts.WithLabelValues(queryType, "false").Inc()
	if cachedRRs, ok := d.cache.Get(getCacheKey(q)); ok {
		return cachedRRs, nil
	}

	return nil, nil
}

func (d *DNSDispatcher) resolveUpstream(ctx *RequestContext, unansweredQuestions []dns.Question, req *dns.Msg) (int, []dns.RR, error) {
	upstreamReq := new(dns.Msg)
	upstreamReq.Id = dns.Id()
	upstreamReq.RecursionDesired = req.RecursionDesired
	upstreamReq.Question = unansweredQuestions

	upstreamResp, upstream, err := d.forwardQuery(ctx, upstreamReq)
	if err != nil {
		return dns.RcodeServerFailure, nil, err
	}

	if upstreamResp.Rcode != dns.RcodeSuccess {
		// Propagate the upstream response Rcode if not successful
		return upstreamResp.Rcode, nil, errors.NewWithDepthf(0,
			"upstream resolver (%s) returned Rcode: %s for query: %s",
			upstream, dns.RcodeToString[upstreamResp.Rcode], unansweredQuestions[0].Name,
		)
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
			effectiveTTL := time.Duration(upstreamTTL) * time.Second

			if !d.isFreshnessSensitive(&q) && effectiveTTL < d.cacheTtlFloor {
				effectiveTTL = d.cacheTtlFloor
			}

			d.cache.Set(key, answersForQuestion, effectiveTTL)
			d.metrics.UpstreamTTLs.WithLabelValues(getQueryType(&q)).Observe(float64(upstreamTTL))
		}
	}

	return upstreamReq.Rcode, upstreamResp.Answer, nil
}

func (d *DNSDispatcher) isFreshnessSensitive(q *dns.Question) bool {
	// Check query type
	switch q.Qtype {
	case dns.TypeSOA, dns.TypeTXT:
		return true
	}

	// Check name patterns
	lower := strings.ToLower(q.Name)
	for _, pattern := range freshnessSensitive {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

var freshnessSensitive = []string{"ocsp", "crl", "pki"}

func (d *DNSDispatcher) reportError(ctx *RequestContext, errorCategory string, err error, additionalFields ...any) {
	args := append(additionalFields, "category", errorCategory, "error", err)
	ctx.Logger.Error("DNS error", args...)
	d.metrics.ErrorCounts.WithLabelValues(errorCategory).Inc()
	d.metrics.RequestCounts.WithLabelValues("errored", string(ctx.Source)).Inc()
	sentry.CaptureException(err)
}

func (d *DNSDispatcher) forwardQuery(ctx *RequestContext, req *dns.Msg) (*dns.Msg, string, error) {
	startTime := time.Now()
	d.metrics.RequestCounts.WithLabelValues("forwarded", string(ctx.Source)).Inc()
	in, upstream, err := d.dnsClient.Exchange(req)

	duration := time.Since(startTime).Seconds()
	d.metrics.UpstreamLatency.WithLabelValues(upstream).Observe(duration)
	return in, upstream, err
}

func (d *DNSDispatcher) sendResponse(ctx *RequestContext, writer dns.ResponseWriter, msg *dns.Msg) {
	d.metrics.ReplyCounts.WithLabelValues(dns.RcodeToString[msg.Rcode]).Inc()
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError(ctx, "response", err)
		return
	}
}

func getCacheKey(q *dns.Question) string {
	return dns.Fqdn(q.Name) + ":" + getQueryType(q)
}

func getQueryType(q *dns.Question) string {
	return dns.TypeToString[q.Qtype]
}
