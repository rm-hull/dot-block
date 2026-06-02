package forwarder

import (
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/getsentry/sentry-go"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/metrics"
)

const NUM_WORKERS = 4
const TELEMETRY_BUFFER_SIZE = 1024

type DNSSource string

const (
	SourceUDP DNSSource = "UDP"
	SourceTCP DNSSource = "TCP"
	SourceDoT DNSSource = "DoT"
)

type queryCountInfo struct {
	queryType string
	blocked   bool
}

type upstreamTTLInfo struct {
	queryType string
	ttl       float64
}

type RequestContext struct {
	Logger    *slog.Logger
	Source    DNSSource
	StartTime time.Time
	IpAddr    string

	// Metrics collection
	telemetry *metrics.TelemetryData
}

type TelemetryEvent struct {
	ctx     *RequestContext
	latency float64
}

type DispatcherFunc func(writer dns.ResponseWriter, req *dns.Msg)

type DNSDispatcher struct {
	dnsClient   *RoundRobinClient
	defaultTTL  float64
	ttlFloor    time.Duration
	cache       *DNSCache
	blockList   *blocklist.BlockList
	geoIpLookup geoblock.GeoIpLookup
	metrics     *metrics.DnsMetrics
	logger      *slog.Logger
	telemetryCh chan TelemetryEvent
	done        chan struct{}
}

func NewDNSDispatcher(
	cache *DNSCache,
	metrics *metrics.DnsMetrics,
	dnsClient *RoundRobinClient,
	blockList *blocklist.BlockList,
	geoIpLookup geoblock.GeoIpLookup,
	ttlFloor time.Duration,
	logger *slog.Logger,
) (*DNSDispatcher, error) {

	if ttlFloor < 0 {
		return nil, errors.New("TTL floor cannot be negative")
	}

	d := &DNSDispatcher{
		dnsClient:   dnsClient,
		defaultTTL:  300, // TODO: pass in
		ttlFloor:    ttlFloor,
		cache:       cache,
		blockList:   blockList,
		geoIpLookup: geoIpLookup,
		metrics:     metrics,
		logger:      logger,
		telemetryCh: make(chan TelemetryEvent, TELEMETRY_BUFFER_SIZE),
		done:        make(chan struct{}),
	}

	for range NUM_WORKERS {
		go d.telemetryWorker()
	}

	logger.Info("DNS dispatcher initialized", "num_telemetry_workers", NUM_WORKERS)
	return d, nil
}

func (d *DNSDispatcher) Close() {
	d.cache.Close()
	close(d.done)
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
		}

		ctx := &RequestContext{
			Logger:    d.logger.With("client_ip", ipAddr, "request_id", req.Id, "source", source),
			Source:    source,
			StartTime: time.Now(),
			IpAddr:    ipAddr,
			telemetry: &metrics.TelemetryData{},
		}

		defer func() {
			duration := time.Since(ctx.StartTime).Seconds()
			select {
			case d.telemetryCh <- TelemetryEvent{ctx: ctx, latency: duration}:
			default:
				d.metrics.DroppedTelemetry.Inc()
			}
		}()

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Question = req.Question

		unansweredQuestions := make([]dns.Question, 0, len(req.Question))

		for _, q := range req.Question {
			answers, rcode, err := d.processQuestion(ctx, &q)
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
				d.sendResponse(ctx, writer, resp)
				return
			}

			if rcode != dns.RcodeSuccess {
				resp.Rcode = rcode
				d.sendResponse(ctx, writer, resp)
				return
			}

			if len(answers) > 0 {
				resp.Answer = append(resp.Answer, answers...)
			} else if !isDNSSDQuery(q.Name) {
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

func (d *DNSDispatcher) telemetryWorker() {
	for {
		select {
		case event, ok := <-d.telemetryCh:
			if !ok {
				return
			}
			
			countryCode := ""
			if event.ctx.IpAddr != "unknown" && event.ctx.IpAddr != "" {
				loc, err := d.geoIpLookup.GetAll(event.ctx.IpAddr)
				if err != nil {
					event.ctx.Logger.Warn("failed to get geolocation for client IP", "error", err)
				} else {
					countryCode = loc.Country_short
				}
			}

			d.metrics.RecordTelemetry(event.ctx.telemetry, event.latency, string(event.ctx.Source), event.ctx.IpAddr, countryCode)
		case <-d.done:
			return
		}
	}
}

func (d *DNSDispatcher) recordTelemetry(ctx *RequestContext, latency float64) {
	// This method is no longer used.
}

func (d *DNSDispatcher) processQuestion(ctx *RequestContext, q *dns.Question) ([]dns.RR, int, error) {
	queryType := getQueryType(q)
	ctx.Logger.Debug("Query received",
		"name", q.Name,
		"type", queryType)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		d.reportError(ctx, "blocklist", err, "qtype", queryType)
		return nil, dns.RcodeServerFailure, err
	}

	if isBlocked {
		ctx.Logger.Debug("Domain blocked", "name", q.Name)
		ctx.telemetry.BlockedDomains = append(ctx.telemetry.BlockedDomains, q.Name)
		ctx.telemetry.QueryCounts = append(ctx.telemetry.QueryCounts, metrics.QueryCountInfo{QueryType: queryType, Blocked: true})

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
		return []dns.RR{soa}, dns.RcodeSuccess, nil
	}

	if isReservedLocalhost(q.Name) {
		ctx.Logger.Debug("Answering localhost loopback", "name", q.Name)
		a := &dns.A{
			Hdr: dns.RR_Header{
				Name:   q.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(d.defaultTTL),
			},
			A: net.ParseIP("127.0.0.1"),
		}
		return []dns.RR{a}, dns.RcodeSuccess, nil
	}

	if isReservedTLD(q.Name) {
		ctx.Logger.Debug("Blocking reserved TLD", "name", q.Name)
		return nil, dns.RcodeNameError, nil
	}

	if isDNSSDQuery(q.Name) {
		ctx.Logger.Debug("Short-circuiting DNS-SD query", "name", q.Name)
		ctx.telemetry.QueryCounts = append(ctx.telemetry.QueryCounts, metrics.QueryCountInfo{QueryType: queryType, Blocked: false})
		return nil, dns.RcodeNameError, nil
	}

	ctx.telemetry.Domains = append(ctx.telemetry.Domains, q.Name)
	ctx.telemetry.QueryCounts = append(ctx.telemetry.QueryCounts, metrics.QueryCountInfo{QueryType: queryType, Blocked: false})
	if cachedRRs, ok := d.cache.Get(getCacheKey(q)); ok {
		return cachedRRs, dns.RcodeSuccess, nil
	}

	return nil, dns.RcodeSuccess, nil
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
		err := errors.NewWithDepthf(0,
			"upstream resolver (%s) returned Rcode: %s for query: %s",
			upstream, dns.RcodeToString[upstreamResp.Rcode], unansweredQuestions[0].Name,
		)
		return upstreamResp.Rcode, nil, &RcodeError{Rcode: upstreamResp.Rcode, Err: err}
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

			if !d.isFreshnessSensitive(&q) && effectiveTTL < d.ttlFloor {
				effectiveTTL = d.ttlFloor
			}

			d.cache.Set(key, answersForQuestion, effectiveTTL)
			ctx.telemetry.UpstreamTTL = &metrics.UpstreamTTLInfo{QueryType: getQueryType(&q), TTL: float64(upstreamTTL)}
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
	if ShouldLog(err) {
		args := append(additionalFields, "category", errorCategory, "error", err)
		ctx.Logger.Error("DNS error", args...)
		sentry.CaptureException(err)
	}

	ctx.telemetry.ErrorCategory = errorCategory
	ctx.telemetry.RequestTypes = append(ctx.telemetry.RequestTypes, "errored")
}

func (d *DNSDispatcher) forwardQuery(ctx *RequestContext, req *dns.Msg) (*dns.Msg, string, error) {
	startTime := time.Now()
	ctx.telemetry.RequestTypes = append(ctx.telemetry.RequestTypes, "forwarded")
	in, upstream, err := d.dnsClient.Exchange(req)

	duration := time.Since(startTime).Seconds()
	ctx.telemetry.Upstream = upstream
	ctx.telemetry.UpstreamLatency = duration
	return in, upstream, err
}

func (d *DNSDispatcher) sendResponse(ctx *RequestContext, writer dns.ResponseWriter, msg *dns.Msg) {
	ctx.telemetry.Rcode = dns.RcodeToString[msg.Rcode]
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

func isDNSSDQuery(name string) bool {
	// RFC 6763: <service>._dns-sd._udp.<domain>
	// Common labels: b, db, r, dr, lb
	// We want to match: *. _dns-sd._udp.*
	// We want to avoid: _services._dns-sd._udp.*
	lower := strings.ToLower(name)
	if !strings.Contains(lower, "._dns-sd._udp.") {
		return false
	}
	return !strings.HasPrefix(lower, "_services.")
}

var reservedTLDs = []string{".invalid.", ".localhost.", ".local.", ".test.", ".example.", ".internal."}

func isReservedTLD(name string) bool {
	n := strings.ToLower(name)
	for _, tld := range reservedTLDs {
		if strings.HasSuffix(n, tld) {
			return true
		}
	}
	return false
}

func isReservedLocalhost(name string) bool {
	return strings.ToLower(name) == "localhost."
}
