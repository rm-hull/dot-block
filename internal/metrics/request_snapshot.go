package metrics

import "time"

type queryCountInfo struct {
	queryType string
	blocked   bool
}

type upstreamTTLInfo struct {
	queryType string
	ttl       float64
}

type RequestSnapshot struct {
	source          string
	ipAddr          string
	startTime       time.Time
	blockedDomains  []string
	domains         []string
	queryCounts     []queryCountInfo
	upstreamTTLs    []upstreamTTLInfo
	errorCategory   string
	forwarded       bool
	upstream        string
	upstreamLatency float64
	requestLatency  float64
	rcode           string
}

func (t *RequestSnapshot) Finished() *RequestSnapshot {
	t.requestLatency = t.Latency().Seconds()
	return t
}

func (t *RequestSnapshot) Latency() time.Duration {
	return time.Since(t.startTime)
}

func NewRequestSnapshot(startTime time.Time, source string, ipAddr string) *RequestSnapshot {
	return &RequestSnapshot{
		startTime:      startTime,
		source:         source,
		ipAddr:         ipAddr,
		blockedDomains: []string{},
		domains:        []string{},
		queryCounts:    []queryCountInfo{},
		upstreamTTLs:   []upstreamTTLInfo{},
	}
}

func (t *RequestSnapshot) AddBlockedDomain(domain string) {
	t.blockedDomains = append(t.blockedDomains, domain)
}

func (t *RequestSnapshot) AddDomain(domain string) {
	t.domains = append(t.domains, domain)
}

func (t *RequestSnapshot) AddQueryCount(queryType string, blocked bool) {
	t.queryCounts = append(t.queryCounts, queryCountInfo{queryType: queryType, blocked: blocked})
}

func (t *RequestSnapshot) AddUpstreamTTL(queryType string, ttl float64) {
	t.upstreamTTLs = append(t.upstreamTTLs, upstreamTTLInfo{queryType: queryType, ttl: ttl})
}

func (t *RequestSnapshot) SetErrorCategory(category string) {
	t.errorCategory = category
}

func (t *RequestSnapshot) Forwarded() {
	t.forwarded = true
}

func (t *RequestSnapshot) SetUpstream(upstream string, latency float64) {
	t.upstream = upstream
	t.upstreamLatency = latency
}

func (t *RequestSnapshot) SetRcode(rcode string) {
	t.rcode = rcode
}

func (t *RequestSnapshot) Record(metrics *DnsMetrics) {
	metrics.RequestLatency.Observe(t.requestLatency)
	metrics.RequestCounts.WithLabelValues("total", t.source).Inc()
	if t.forwarded {
		metrics.RequestCounts.WithLabelValues("forwarded", t.source).Inc()
	}
	if t.errorCategory != "" {
		metrics.RequestCounts.WithLabelValues("errored", t.source).Inc()
		metrics.ErrorCounts.WithLabelValues(t.errorCategory).Inc()
	}

	if t.ipAddr != "" && t.ipAddr != "unknown" {
		metrics.TopClients.Add(t.ipAddr)
		metrics.UniqueClients.Insert([]byte(t.ipAddr))

		if metrics.geoIpLookup != nil {
			if record, err := metrics.geoIpLookup.GetAll(t.ipAddr); err == nil && record.Country_short != "" {
				metrics.CountryCounts.WithLabelValues(record.Country_short).Inc()
			}
		}
	}

	for _, qc := range t.queryCounts {
		isBlocked := "false"
		if qc.blocked {
			isBlocked = "true"
		}
		metrics.QueryCounts.WithLabelValues(qc.queryType, isBlocked).Inc()
	}
	for _, domain := range t.blockedDomains {
		metrics.TopBlockedDomains.Add(domain)
	}
	for _, domain := range t.domains {
		metrics.TopDomains.Add(domain)
	}
	for _, upstreamTTL := range t.upstreamTTLs {
		metrics.UpstreamTTLs.WithLabelValues(upstreamTTL.queryType).Observe(upstreamTTL.ttl)
	}
	if t.upstream != "" {
		metrics.UpstreamLatency.WithLabelValues(t.upstream).Observe(t.upstreamLatency)
	}
	if t.rcode != "" {
		metrics.ReplyCounts.WithLabelValues(t.rcode).Inc()
	}
}
