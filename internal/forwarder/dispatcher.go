package forwarder

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/http/sse"
	"github.com/rm-hull/dot-block/internal/metrics"
	"github.com/rm-hull/dot-block/internal/noisefilter"
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
	req      *dns.Msg
	snapshot *metrics.RequestSnapshot
	logger   *slog.Logger
	ipAddr   string
	subnet   string
}

type DispatcherFunc func(writer dns.ResponseWriter, req *dns.Msg)

type DNSDispatcher struct {
	dnsClient   *RoundRobinClient
	defaultTTL  float64
	ttlFloor    time.Duration
	cache       *DNSCache
	blockLists  []*blocklist.BlockList
	metrics     *metrics.DnsMetrics
	logger      *slog.Logger
	noiseFilter *noisefilter.NoiseFilter
	broadcaster *sse.Broadcaster
	enableECS   bool
	snapshotCh  chan *metrics.RequestSnapshot
	done        chan struct{}
}

func NewDNSDispatcher(
	cache *DNSCache,
	dnsMetrics *metrics.DnsMetrics,
	dnsClient *RoundRobinClient,
	blockLists []*blocklist.BlockList,
	noiseFilter *noisefilter.NoiseFilter,
	broadcaster *sse.Broadcaster,
	ttlFloor time.Duration,
	logger *slog.Logger,
	enableECS bool,
) (*DNSDispatcher, error) {

	if ttlFloor < 0 {
		return nil, errors.New("TTL floor cannot be negative")
	}

	d := &DNSDispatcher{
		dnsClient:   dnsClient,
		defaultTTL:  300, // TODO: pass in
		ttlFloor:    ttlFloor,
		cache:       cache,
		blockLists:  blockLists,
		metrics:     dnsMetrics,
		logger:      logger,
		noiseFilter: noiseFilter,
		broadcaster: broadcaster,
		enableECS:   enableECS,
		snapshotCh:  make(chan *metrics.RequestSnapshot, SNAPSHOT_BUFFER_SIZE),
		done:        make(chan struct{}),
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

func (d *DNSDispatcher) GetBroadcaster() *sse.Broadcaster {
	return d.broadcaster
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
			req:      req,
			logger:   d.logger.With("client_ip", ipAddr, "request_id", req.Id, "source", source),
			snapshot: metrics.NewRequestSnapshot(time.Now(), string(source), ipAddr),
			ipAddr:   ipAddr,
			subnet:   d.computeSubnet(ipAddr),
		}
		if len(req.Question) > 0 {
			requestCtx.snapshot.SetPrimaryDomain(req.Question[0].Name)
			requestCtx.snapshot.SetQueryType(getQueryType(&req.Question[0]))
		}

		defer func() {
			select {
			case d.snapshotCh <- requestCtx.snapshot.Finished():
			default:
				d.metrics.DroppedTelemetry.Inc()
			}
		}()

		resp := d.newReply(req)

		unansweredQuestions := make([]dns.Question, 0, len(req.Question))

		for _, q := range req.Question {
			res, err := d.processQuestion(requestCtx, &q)
			if err != nil {
				resp.Rcode = dns.RcodeServerFailure
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			if res.rcode != dns.RcodeSuccess {
				resp.Rcode = res.rcode
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			if len(res.authority) > 0 {
				resp.Ns = append(resp.Ns, res.authority...)
			}

			if len(res.extra) > 0 {
				for _, rr := range res.extra {
					if opt, ok := rr.(*dns.OPT); ok {
						if existingOpt := resp.IsEdns0(); existingOpt != nil {
							existingOpt.Option = append(existingOpt.Option, opt.Option...)
						} else {
							resp.Extra = append(resp.Extra, opt)
						}
					} else {
						resp.Extra = append(resp.Extra, rr)
					}
				}
			}

			if len(res.answer) > 0 {
				resp.Answer = append(resp.Answer, res.answer...)
			} else if len(res.authority) == 0 && len(res.extra) == 0 && !isDNSSDQuery(q.Name) {
				unansweredQuestions = append(unansweredQuestions, q)
			}
		}

		if len(unansweredQuestions) > 0 {
			rcode, answers, err := d.resolveUpstream(requestCtx, unansweredQuestions, req)
			if err != nil {
				resp.Rcode = rcode
				d.reportError(requestCtx, "upstream", err, unansweredQuestions[0].Name, "qtype", getQueryType(&unansweredQuestions[0]))
				d.sendResponse(requestCtx, writer, resp)
				return
			}

			resp.Answer = append(resp.Answer, answers...)
		}

		d.sendResponse(requestCtx, writer, resp)
	}
}

func (d *DNSDispatcher) newReply(req *dns.Msg) *dns.Msg {
	resp := new(dns.Msg)
	resp.SetReply(req)
	resp.Question = req.Question
	return resp
}

func (d *DNSDispatcher) snapshotWorker() {
	for {
		select {
		case snapshot, ok := <-d.snapshotCh:
			if !ok {
				return
			}
			snapshot.Record(d.metrics)

			if d.broadcaster != nil {
				event := sse.Event{
					QueryType: snapshot.QueryType(),
					Domain:    snapshot.PrimaryDomain(),
					Result:    snapshot.Rcode(),
					ClientIP:  snapshot.IPAddr(),
					Source:    snapshot.Source(),
					Blocked:   snapshot.IsBlocked(),
					Cached:    snapshot.FromCache(),
					Timestamp: time.Now(),
				}

				d.broadcaster.Broadcast(event)
			}
		case <-d.done:
			return
		}
	}
}

type QuestionResolution struct {
	answer    []dns.RR
	authority []dns.RR
	extra     []dns.RR
	rcode     int
}

func (d *DNSDispatcher) processQuestion(requestCtx *RequestContext, q *dns.Question) (QuestionResolution, error) {

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

	isBlocked, cause, err := d.isBlocked(q.Name)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		d.reportError(requestCtx, "blocklist", err, q.Name, "qtype", queryType)
		return QuestionResolution{rcode: dns.RcodeServerFailure}, err
	}

	if isBlocked {
		return d.constructBlockedResponse(requestCtx, q, queryType, cause), nil
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
		return QuestionResolution{answer: []dns.RR{a}, rcode: dns.RcodeSuccess}, nil
	}

	if isReservedTLD(q.Name) {
		requestCtx.logger.DebugContext(requestCtx.ctx, "Blocking reserved TLD", "name", q.Name)
		return QuestionResolution{rcode: dns.RcodeNameError}, nil
	}

	if isDNSSDQuery(q.Name) {
		requestCtx.logger.DebugContext(requestCtx.ctx, "Short-circuiting DNS-SD query", "name", q.Name)
		requestCtx.snapshot.AddQueryCount(queryType, false)
		return QuestionResolution{rcode: dns.RcodeNameError}, nil
	}

	requestCtx.snapshot.AddDomain(q.Name)
	requestCtx.snapshot.AddQueryCount(queryType, false)
	if cachedRRs, ok := d.cache.Get(getCacheKey(q, requestCtx.subnet)); ok {
		span.SetAttributes(attribute.Bool("dns.cache_hit", true))
		requestCtx.snapshot.SetFromCache(true)
		return QuestionResolution{answer: cachedRRs, rcode: dns.RcodeSuccess}, nil
	}

	return QuestionResolution{rcode: dns.RcodeSuccess}, nil
}

func (d *DNSDispatcher) constructBlockedResponse(requestCtx *RequestContext, q *dns.Question, queryType string, cause *blocklist.BlockList) QuestionResolution {
	requestCtx.logger.DebugContext(requestCtx.ctx, "Domain blocked", "name", q.Name, "cause", cause.Name())
	requestCtx.snapshot.AddBlockedDomain(q.Name)
	requestCtx.snapshot.AddQueryCount(queryType, true)

	soa := &dns.SOA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeSOA,
			Class:  dns.ClassINET,
			Ttl:    uint32(d.defaultTTL),
		},
		Ns:      "ns.blocked.local.",
		Mbox:    "hostmaster.blocked.local.",
		Serial:  1,
		Refresh: 3600,
		Retry:   900,
		Expire:  604800,
		Minttl:  uint32(d.defaultTTL),
	}

	// Inject EDE for blocked domain
	ede := &dns.EDNS0_EDE{
		InfoCode:  dns.ExtendedErrorCodeBlocked,
		ExtraText: fmt.Sprintf("Blocked by: %s", cause.Name()),
	}

	var extra []dns.RR
	if optIn := requestCtx.req.IsEdns0(); optIn != nil {
		o := new(dns.OPT)
		o.Hdr.Name = "."
		o.Hdr.Rrtype = dns.TypeOPT
		o.SetUDPSize(optIn.UDPSize())
		o.SetVersion(optIn.Version())
		o.SetDo(optIn.Do())
		o.Option = append(o.Option, ede)
		extra = []dns.RR{o}
	}

	return QuestionResolution{authority: []dns.RR{soa}, extra: extra, rcode: dns.RcodeSuccess}
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
		cacheKey := getCacheKey(&q, requestCtx.subnet)

		// Cache the entire answer set for this query
		if len(upstreamResp.Answer) > 0 {
			upstreamTTL := upstreamResp.Answer[0].Header().Ttl
			for _, ans := range upstreamResp.Answer {
				if ans.Header().Ttl < upstreamTTL {
					upstreamTTL = ans.Header().Ttl
				}
			}

			effectiveTTL := time.Duration(upstreamTTL) * time.Second

			if !d.isFreshnessSensitive(&q) && effectiveTTL < d.ttlFloor {
				effectiveTTL = d.ttlFloor
			}

			d.cache.Set(cacheKey, upstreamResp.Answer, effectiveTTL)
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
		return ip4.Mask(mask).String()
	}

	mask := net.CIDRMask(48, 128)
	return ip.Mask(mask).String()
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
		ip = ip4.Mask(net.CIDRMask(24, 32))
	} else {
		family = 2
		prefixLen = 48
		ip = ip.Mask(net.CIDRMask(48, 128))
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
			found = true
			ecsIndex := -1
			for i, o := range opt.Option {
				if o.Option() == dns.EDNS0SUBNET {
					ecsIndex = i
					break
				}
			}

			if ecsIndex != -1 {
				opt.Option[ecsIndex] = ecs
			} else {
				opt.Option = append(opt.Option, ecs)
			}
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

func (d *DNSDispatcher) reportError(requestCtx *RequestContext, errorCategory string, err error, domain string, additionalFields ...any) {
	if d.noiseFilter != nil {
		rcodeStr := ""
		var rcodeErr *RcodeError
		if errors.As(err, &rcodeErr) {
			rcodeStr = dns.RcodeToString[rcodeErr.Rcode]
		}

		if d.noiseFilter.ShouldSuppress(errorCategory, rcodeStr, domain) {
			requestCtx.snapshot.SetErrorCategory(errorCategory)
			return
		}
	}

	if ShouldLog(err) {
		// Ensure args are in key-value pairs for slog
		if len(additionalFields)%2 != 0 {
			panic(fmt.Sprintf("additionalFields must be in key-value pairs: %v", additionalFields))
		}

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

	requestCtx.snapshot.Forwarded()
	in, upstream, err := d.dnsClient.Exchange(req)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}

	span.SetAttributes(attribute.String("dns.upstream", upstream))

	return in, upstream, err
}

func (d *DNSDispatcher) sendResponse(ctx *RequestContext, writer dns.ResponseWriter, msg *dns.Msg) {
	ctx.snapshot.SetRcode(dns.RcodeToString[msg.Rcode])
	if err := writer.WriteMsg(msg); err != nil {
		d.reportError(ctx, "response", err, "")
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

func (d *DNSDispatcher) isBlocked(fqdn string) (bool, *blocklist.BlockList, error) {
	for _, blockList := range d.blockLists {
		if isBlocked, err := blockList.IsBlocked(fqdn); isBlocked || err != nil {
			return isBlocked, blockList, err
		}
	}
	return false, nil, nil
}
