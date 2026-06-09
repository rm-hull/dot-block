package forwarder

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/telemetry"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const (
	NUM_WORKERS          = 4
	SNAPSHOT_BUFFER_SIZE = 1024
)

type DNSSource string

const (
	SourceUDP DNSSource = "UDP"
	SourceTCP DNSSource = "TCP"
	SourceDoT DNSSource = "DoT"
	SourceDoH DNSSource = "DoH"
)

var (
	freshnessSensitive = []string{"ocsp", "crl", "pki"}
	reservedTLDs       = []string{".invalid.", ".localhost.", ".local.", ".test.", ".example.", ".internal."}
)

type RequestContext struct {
	ctx      context.Context
	snapshot *metrics.RequestSnapshot
	logger   *slog.Logger
	ipAddr   string
	subnet   string
}

type DispatcherFunc func(writer dns.ResponseWriter, req *dns.Msg)

type DNSDispatcher struct {
	dnsClient  *RoundRobinClient
	defaultTTL float64
	ttlFloor   time.Duration
	cache      *DNSCache
	blockList  *blocklist.BlockList
	metrics    *metrics.DnsMetrics
	logger     *slog.Logger
	enableECS  bool
	snapshotCh chan *metrics.RequestSnapshot
	done       chan struct{}
}

func NewDNSDispatcher(
	cache *DNSCache,
	dnsMetrics *metrics.DnsMetrics,
	dnsClient *RoundRobinClient,
	blockList *blocklist.BlockList,
	ttlFloor time.Duration,
	logger *slog.Logger,
	enableECS bool,
) (*DNSDispatcher, error) {

	if ttlFloor < 0 {
		return nil, errors.New("TTL floor cannot be negative")
	}

	d := &DNSDispatcher{
		dnsClient:  dnsClient,
		defaultTTL: 300, // TODO: pass in
		ttlFloor:   ttlFloor,
		cache:      cache,
		blockList:  blockList,
		metrics:    dnsMetrics,
		logger:     logger,
		enableECS:  enableECS,
		snapshotCh: make(chan *metrics.RequestSnapshot, SNAPSHOT_BUFFER_SIZE),
		done:       make(chan struct{}),
	}

	for range NUM_WORKERS {
		go d.snapshotWorker()
	}

	logger.Info("DNS dispatcher initialized", "num_snapshot_workers", NUM_WORKERS, "enable_ecs", enableECS)
	return d, nil
}

func (d *DNSDispatcher) Close() {
	d.cache.Close()
	close(d.done)
}

func (d *DNSDispatcher) HandleDNSRequest(source DNSSource) DispatcherFunc {
	return func(writer dns.ResponseWriter, req *dns.Msg) {

		if req == nil {
			d.logger.Warn("received nil DNS request", "source", source)
			return
		}

		remoteAddr := writer.RemoteAddr().String()
		ipAddr, _, err := net.SplitHostPort(remoteAddr)
		if err != nil {
			d.logger.Warn("failed to parse client IP from remote address",
				"remote_addr", remoteAddr,
				"source", source,
				"error", err)

			ipAddr = "unknown" // Fallback to "unknown" if IP parsing fails
		}

		// Start root span for the request
		tracer := telemetry.GetTracer("dns-dispatcher")
		ctx, span := tracer.Start(context.Background(), "HandleDNSRequest",
			trace.WithAttributes(
				attribute.String("client_ip", ipAddr),
				attribute.String("source", string(source)),
				attribute.Int("request_id", int(req.Id)),
			),
		)
		defer span.End()

		requestCtx := &RequestContext{
			ctx:      ctx,
			logger:   d.logger.With("client_ip", ipAddr, "request_id", req.Id, "source", source),
			snapshot: metrics.NewRequestSnapshot(time.Now(), string(source), ipAddr),
			ipAddr:   ipAddr,
			subnet:   d.computeSubnet(ipAddr),
		}

		defer func() {
			select {
			case d.snapshotCh <- requestCtx.snapshot.Finished():
			default:
				d.metrics.DroppedTelemetry.Inc()
			}
		}()

		resp := new(dns.Msg)
		resp.SetReply(req)
		resp.Question = req.Question

		unansweredQuestions := make([]dns.Question, 0, len(req.Question))

		for _, q := range req.Question {
			answers, rcode, err := d.processQuestion(requestCtx, &q)
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			if rcode != dns.RcodeSuccess {
				resp.Rcode = rcode
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			if len(answers) > 0 {
				resp.Answer = append(resp.Answer, answers...)
			} else if !isDNSSDQuery(q.Name) {
				unansweredQuestions = append(unansweredQuestions, q)
			}
		}

		if len(unansweredQuestions) > 0 {
			rcode, answers, err := d.resolveUpstream(requestCtx, unansweredQuestions, req)
			if err != nil {
				resp.Rcode = rcode
				d.reportError(requestCtx, "upstream", err, "qtype", getQueryType(&unansweredQuestions[0]))
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			resp.Answer = append(resp.Answer, answers...)
		}

		if len(resp.Answer) == 0 && len(resp.Ns) > 0 {
			resp.Rcode = dns.RcodeNameError
		}

		d.sendResponse(requestCtx, writer, resp)
	}
}

func (d *DNSDispatcher) snapshotWorker() {
	for {
		select {
		case snapshot, ok := <-d.snapshotCh:
			if !ok {
				return
			}
			snapshot.Record(d.metrics)
		case <-d.done:
			return
		}
	}
}

func (d *DNSDispatcher) processQuestion(requestCtx *RequestContext, q *dns.Question) ([]dns.RR, int, error) {
	tracer := telemetry.GetTracer("dns-dispatcher")
	_, span := tracer.Start(requestCtx.ctx, "processQuestion",
		trace.WithAttributes(
			attribute.String("dns.name", q.Name),
			attribute.String("dns.type", getQueryType(q)),
		),
	)
	defer span.End()

	queryType := getQueryType(q)
	requestCtx.logger.DebugContext(requestCtx.ctx, "Query received",
		"name", q.Name,
		"type", queryType)

	isBlocked, err := d.blockList.IsBlocked(q.Name)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		d.reportError(requestCtx, "blocklist", err, "qtype", queryType)
		return nil, dns.RcodeServerFailure, err
	}

	if isBlocked {
		requestCtx.logger.DebugContext(requestCtx.ctx, "Domain blocked", "name", q.Name)
		requestCtx.snapshot.AddBlockedDomain(q.Name)
		requestCtx.snapshot.AddQueryCount(queryType, true)
		span.SetAttributes(attribute.Bool("dns.blocked", true))

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
		requestCtx.logger.DebugContext(requestCtx.ctx, "Answering localhost loopback", "name", q.Name)
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
		requestCtx.logger.DebugContext(requestCtx.ctx, "Blocking reserved TLD", "name", q.Name)
		return nil, dns.RcodeNameError, nil
	}

	if isDNSSDQuery(q.Name) {
		requestCtx.logger.DebugContext(requestCtx.ctx, "Short-circuiting DNS-SD query", "name", q.Name)
		requestCtx.snapshot.AddQueryCount(queryType, false)
		return nil, dns.RcodeNameError, nil
	}

	requestCtx.snapshot.AddDomain(q.Name)
	requestCtx.snapshot.AddQueryCount(queryType, false)
	if cachedRRs, ok := d.cache.Get(getCacheKey(q, requestCtx.subnet)); ok {
		span.SetAttributes(attribute.Bool("dns.cache_hit", true))
		return cachedRRs, dns.RcodeSuccess, nil
	}

	return nil, dns.RcodeSuccess, nil
}

func (d *DNSDispatcher) resolveUpstream(requestCtx *RequestContext, unansweredQuestions []dns.Question, req *dns.Msg) (int, []dns.RR, error) {
	tracer := telemetry.GetTracer("dns-dispatcher")
	_, span := tracer.Start(requestCtx.ctx, "resolveUpstream",
		trace.WithAttributes(
			attribute.Int("dns.unanswered_count", len(unansweredQuestions)),
		),
	)
	defer span.End()

	upstreamReq := new(dns.Msg)
	upstreamReq.Id = dns.Id()
	upstreamReq.RecursionDesired = req.RecursionDesired
	upstreamReq.Question = unansweredQuestions

	for _, rr := range req.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			upstreamReq.Extra = append(upstreamReq.Extra, dns.Copy(opt))
			break
		}
	}

	d.applyECS(requestCtx, upstreamReq)

	upstreamResp, upstream, err := d.forwardQuery(requestCtx, upstreamReq)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		return dns.RcodeServerFailure, nil, err
	}

	if upstreamResp.Rcode != dns.RcodeSuccess {
		// Propagate the upstream response Rcode if not successful
		err := errors.NewWithDepthf(0,
			"upstream resolver (%s) returned Rcode: %s for query: %s",
			upstream, dns.RcodeToString[upstreamResp.Rcode], unansweredQuestions[0].Name,
		)
		span.SetAttributes(attribute.Int("dns.upstream_rcode", upstreamResp.Rcode))
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
		key := getCacheKey(&q, requestCtx.subnet)
		if answersForQuestion, ok := answerMap[key]; ok {
			upstreamTTL := answersForQuestion[0].Header().Ttl
			effectiveTTL := time.Duration(upstreamTTL) * time.Second

			if !d.isFreshnessSensitive(&q) && effectiveTTL < d.ttlFloor {
				effectiveTTL = d.ttlFloor
			}

			d.cache.Set(key, answersForQuestion, effectiveTTL)
			requestCtx.snapshot.AddUpstreamTTL(getQueryType(&q), float64(upstreamTTL))
		}
	}

	return upstreamReq.Rcode, upstreamResp.Answer, nil
}

func (d *DNSDispatcher) computeSubnet(ipAddr string) string {
	if !d.enableECS || ipAddr == "unknown" {
		return ""
	}

	ip := net.ParseIP(ipAddr)
	if ip == nil {
		return ""
	}

	if ip4 := ip.To4(); ip4 != nil {
		mask := net.CIDRMask(24, 32)
		return string(ip4.Mask(mask))
	}

	mask := net.CIDRMask(48, 128)
	return string(ip.Mask(mask))
}

func (d *DNSDispatcher) applyECS(requestCtx *RequestContext, upstreamReq *dns.Msg) {
	if !d.enableECS || requestCtx.ipAddr == "unknown" {
		return
	}

	ip := net.ParseIP(requestCtx.ipAddr)
	if ip == nil {
		return
	}

	var family uint16
	var prefixLen uint8
	if ip4 := ip.To4(); ip4 != nil {
		family = 1
		prefixLen = 24
		ip = ip4
	} else {
		family = 2
		prefixLen = 48
	}

	ecs := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        family,
		SourceNetmask: prefixLen,
		SourceScope:   0,
		Address:       ip,
	}

	found := false
	for _, rr := range upstreamReq.Extra {
		if opt, ok := rr.(*dns.OPT); ok {
			opt.Option = append(opt.Option, ecs)
			found = true
			break
		}
	}
	if !found {
		opt := &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
				Class:  dns.ClassINET,
				Ttl:    4096,
			},
			Option: []dns.EDNS0{ecs},
		}
		upstreamReq.Extra = append(upstreamReq.Extra, opt)
	}
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

func (d *DNSDispatcher) reportError(requestCtx *RequestContext, errorCategory string, err error, additionalFields ...any) {
	if ShouldLog(err) {
		args := append(additionalFields,
			"category", errorCategory,
			"error", err,
			"latency", requestCtx.snapshot.Latency().String())

		requestCtx.logger.ErrorContext(requestCtx.ctx, "DNS error", args...)
	}

	requestCtx.snapshot.SetErrorCategory(errorCategory)
}

func (d *DNSDispatcher) forwardQuery(requestCtx *RequestContext, req *dns.Msg) (*dns.Msg, string, error) {
	tracer := telemetry.GetTracer("dns-dispatcher")
	_, span := tracer.Start(requestCtx.ctx, "forwardQuery")
	defer span.End()

	startTime := time.Now()
	requestCtx.snapshot.Forwarded()
	in, upstream, err := d.dnsClient.Exchange(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	duration := time.Since(startTime).Seconds()
	requestCtx.snapshot.SetUpstream(upstream, duration)
	span.SetAttributes(attribute.String("dns.upstream", upstream))

	return in, upstream, err
}

func (d *DNSDispatcher) sendResponse(ctx *RequestContext, writer dns.ResponseWriter, msg *dns.Msg) {
	ctx.snapshot.SetRcode(dns.RcodeToString[msg.Rcode])
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError(ctx, "response", err)
		return
	}
}

func getCacheKey(q *dns.Question, subnet string) string {
	key := dns.Fqdn(q.Name) + ":" + getQueryType(q)
	if subnet != "" {
		key += ":" + subnet
	}
	return key
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
