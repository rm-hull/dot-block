package metrics

import "time"

type QueryCountInfo struct {
	QueryType string
	Blocked   bool
}

type UpstreamTTLInfo struct {
	QueryType string
	TTL       float64
}

type TelemetryData struct {
	source          string
	ipAddr          string
	startTime       time.Time
	blockedDomains  []string
	domains         []string
	queryCounts     []QueryCountInfo
	upstreamTTLs    []UpstreamTTLInfo
	errorCategory   string
	requestTypes    []string
	upstream        string
	upstreamLatency float64
	requestLatency  float64
	rcode           string
}

func (t *TelemetryData) Finished() *TelemetryData {
	t.requestLatency = time.Since(t.startTime).Seconds()
	return t
}

func NewTelemetryData(startTime time.Time, source string, ipAddr string) *TelemetryData {
	return &TelemetryData{
		startTime:      startTime,
		source:         source,
		ipAddr:         ipAddr,
		blockedDomains: []string{},
		domains:        []string{},
		queryCounts:    []QueryCountInfo{},
		upstreamTTLs:   []UpstreamTTLInfo{},
		requestTypes:   []string{},
	}
}

func (t *TelemetryData) AddBlockedDomain(domain string) {
	t.blockedDomains = append(t.blockedDomains, domain)
}

func (t *TelemetryData) AddDomain(domain string) {
	t.domains = append(t.domains, domain)
}

func (t *TelemetryData) AddQueryCount(queryType string, blocked bool) {
	t.queryCounts = append(t.queryCounts, QueryCountInfo{QueryType: queryType, Blocked: blocked})
}

func (t *TelemetryData) AddUpstreamTTL(queryType string, ttl float64) {
	t.upstreamTTLs = append(t.upstreamTTLs, UpstreamTTLInfo{QueryType: queryType, TTL: ttl})
}

func (t *TelemetryData) SetErrorCategory(category string) {
	t.errorCategory = category
}

func (t *TelemetryData) AddRequestType(requestType string) {
	t.requestTypes = append(t.requestTypes, requestType)
}

func (t *TelemetryData) SetUpstream(upstream string, latency float64) {
	t.upstream = upstream
	t.upstreamLatency = latency
}

func (t *TelemetryData) SetRcode(rcode string) {
	t.rcode = rcode
}

func (t *TelemetryData) Record(metrics *DnsMetrics) {
	metrics.RequestLatency.Observe(t.requestLatency)
	metrics.RequestCounts.WithLabelValues("total", t.source).Inc()

	if t.ipAddr != "" && t.ipAddr != "unknown" {
		metrics.TopClients.Add(t.ipAddr)
		metrics.UniqueClients.Insert([]byte(t.ipAddr))

		if record, err := metrics.geoIpLookup.GetAll(t.ipAddr); err == nil && record.Country_short != "" {
			metrics.CountryCounts.WithLabelValues(record.Country_short).Inc()
		}
	}

	for _, qc := range t.queryCounts {
		isBlocked := "false"
		if qc.Blocked {
			isBlocked = "true"
		}
		metrics.QueryCounts.WithLabelValues(qc.QueryType, isBlocked).Inc()
	}
	for _, domain := range t.blockedDomains {
		metrics.TopBlockedDomains.Add(domain)
	}
	for _, domain := range t.domains {
		metrics.TopDomains.Add(domain)
	}
	for _, upstreamTTL := range t.upstreamTTLs {
		metrics.UpstreamTTLs.WithLabelValues(upstreamTTL.QueryType).Observe(upstreamTTL.TTL)
	}
	if t.errorCategory != "" {
		metrics.ErrorCounts.WithLabelValues(t.errorCategory).Inc()
	}
	for _, rt := range t.requestTypes {
		metrics.RequestCounts.WithLabelValues(rt, t.source).Inc()
	}
	if t.upstream != "" {
		metrics.UpstreamLatency.WithLabelValues(t.upstream).Observe(t.upstreamLatency)
	}
	if t.rcode != "" {
		metrics.ReplyCounts.WithLabelValues(t.rcode).Inc()
	}
}
