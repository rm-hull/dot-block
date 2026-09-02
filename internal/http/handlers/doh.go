package handlers

import (
	"encoding/base64"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
)

// jsonQuestion represents a single entry in the "Question" array of dns-json.
type jsonQuestion struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

// jsonResource represents a single resource record in the response.
type jsonResource struct {
	Name  string   `json:"name"`
	Type  uint16   `json:"type"`
	TTL   int      `json:"TTL"`
	Class string   `json:"class,omitempty"`
	Data  []string `json:"data,omitempty"`
}

// dnsJSONResponse represents the full JSON object returned for an
// application/dns-json request (see https://dns.org/src/ietf/draft-ietf-doh-dns-over-https/ ).
type dnsJSONResponse struct {
	Status     int            `json:"Status"`
	TC         bool           `json:"TC"`
	RD         bool           `json:"RD"`
	RA         bool           `json:"RA"`
	AD         bool           `json:"AD"`
	CD         bool           `json:"CD"`
	Question   []jsonQuestion `json:"Question"`
	Answer     []jsonResource `json:"Answer,omitempty"`
	Authority  []jsonResource `json:"Authority,omitempty"`
	Additional []jsonResource `json:"Additional,omitempty"`
	Comment    string         `json:"Comment,omitempty"`
}

// packRR converts a dns.RR into a jsonResource.
func packRR(rr dns.RR) jsonResource {
	hdr := rr.Header()

	var data []string
	switch v := rr.(type) {
	case *dns.A:
		data = []string{v.A.String()}
	case *dns.AAAA:
		data = []string{v.AAAA.String()}
	case *dns.NS:
		data = []string{v.Ns}
	case *dns.CNAME:
		data = []string{v.Target}
	case *dns.PTR:
		data = []string{v.Ptr}
	case *dns.TXT:
		data = v.Txt
	case *dns.MX:
		data = []string{v.Mx}
	case *dns.SRV:
		data = []string{v.Target}
		data = append(data, "priority:"+strconv.Itoa(int(v.Priority)), "weight:"+strconv.Itoa(int(v.Weight)), "port:"+strconv.Itoa(int(v.Port)))
	case *dns.SOA:
		data = []string{
			v.Ns, v.Mbox,
			"serial:" + strconv.Itoa(int(v.Serial)),
			"refresh:" + strconv.Itoa(int(v.Refresh)),
			"retry:" + strconv.Itoa(int(v.Retry)),
			"expire:" + strconv.Itoa(int(v.Expire)),
			"minimum:" + strconv.Itoa(int(v.Minttl)),
		}
	default:
		if s := rr.String(); s != "" {
			data = []string{s}
		}
	}

	return jsonResource{
		Name:  hdr.Name,
		Type:  hdr.Rrtype,
		TTL:   int(hdr.Ttl),
		Class: dns.ClassToString[hdr.Class],
		Data:  data,
	}
}

// parseTypeFromString converts common type strings into a dns.Type
func parseTypeFromString(s string) (uint16, bool) {
	switch strings.ToUpper(s) {
	case "A":
		return dns.TypeA, true
	case "AAAA":
		return dns.TypeAAAA, true
	case "NS":
		return dns.TypeNS, true
	case "CNAME":
		return dns.TypeCNAME, true
	case "PTR":
		return dns.TypePTR, true
	case "MX":
		return dns.TypeMX, true
	case "TXT":
		return dns.TypeTXT, true
	case "SOA":
		return dns.TypeSOA, true
	case "SRV":
		return dns.TypeSRV, true
	case "ANY":
		return dns.TypeANY, true
	default:
		t, ok := dns.StringToType[s]
		return t, ok
	}
}

func NewDoHHandler(handler dns.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		var raw []byte
		var err error

		accept := c.GetHeader("Accept")
		isJSONReq := strings.Contains(accept, "application/dns-json")

		// Handle JSON API style GET requests:
		//   /dns-query?name=example.com&type=A
		if c.Request.Method == http.MethodGet && isJSONReq {
			if _, ok := c.GetQuery("name"); ok {
				raw, err = buildJSONQuery(c.Query("name"), c.Query("type"))
				if err != nil {
					c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to build DNS query: " + err.Error()})
					return
				}
			}
		}

		// Fallback to wire-format handling
		if raw == nil {
			if c.Request.Method == http.MethodPost {
				if raw, err = c.GetRawData(); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Failed to read request body",
					})
					return
				}
			} else {
				encoded := c.Query("dns")
				if raw, err = base64.RawURLEncoding.DecodeString(encoded); err != nil {
					c.JSON(http.StatusBadRequest, gin.H{
						"error": "Failed to decode base64 DNS message: " + err.Error(),
					})
					return
				}
			}
		}

		msg := new(dns.Msg)
		if err := msg.Unpack(raw); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": "Failed to parse DNS message: " + err.Error(),
			})
			return
		}

		responseWriter, err := NewDoHResponseWriter(c.ClientIP())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to create response writer: " + err.Error(),
			})
			return
		}
		handler.ServeDNS(responseWriter, msg)

		// Stash the parsed DNS response on the context so the rate-limit
		// middleware (which wraps this handler) can record NXDOMAIN results
		// for flood detection.
		c.Set("dns_response", responseWriter.msg)

		if isJSONReq {
			c.JSON(http.StatusOK, toJsonResponse(responseWriter.msg))
			return
		}

		packed, err := responseWriter.msg.Pack()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "Failed to pack DNS response: " + err.Error(),
			})
			return
		}

		c.Data(http.StatusOK, "application/dns-message", packed)
	}
}

// buildJSONQuery creates a serialized DNS wire-format query from name / type
// query arguments. It returns the packed bytes ready for Unpack.
// It includes EDNS0 support to ensure upstream servers return Extended DNS
// Error (EDE) information in blocked responses.
func buildJSONQuery(name, typeStr string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("missing 'name' parameter")
	}

	// Ensure fully-qualified domain name (trailing dot)
	if !strings.HasSuffix(name, ".") {
		name += "."
	}

	qtype := uint16(dns.TypeA)
	if typeStr != "" {
		t, ok := parseTypeFromString(typeStr)
		if !ok {
			return nil, errors.Errorf("unknown query type: %s", typeStr)
		}
		qtype = t
	}

	msg := new(dns.Msg)
	msg.SetQuestion(name, qtype)

	// Include EDNS0 to request extended error information (EDE)
	// This ensures we get "Blocked by:" info from upstream
	msg.SetEdns0(4096, true)

	return msg.Pack()
}

// extractCommentFromEDE extracts the "Blocked by:" comment from EDNS0 Extended
// DNS Error (EDE) options in the response message's OPT record.
func extractCommentFromEDE(msg *dns.Msg) string {
	for _, rr := range msg.Extra {
		opt, ok := rr.(*dns.OPT)
		if !ok {
			continue
		}
		for _, edeOption := range opt.Option {
			if ede, ok := edeOption.(*dns.EDNS0_EDE); ok {
				if strings.HasPrefix(ede.ExtraText, "Blocked by:") {
					return ede.ExtraText
				}
			}
		}
	}
	return ""
}

// toJsonResponse converts a dns.Msg into a JSON-serializable structure
// following the application/dns-json convention.
func toJsonResponse(msg *dns.Msg) *dnsJSONResponse {
	resp := &dnsJSONResponse{
		Status:   int(msg.Rcode),
		TC:       msg.MsgHdr.Truncated,
		RD:       msg.RecursionDesired,
		RA:       msg.RecursionAvailable,
		AD:       msg.AuthenticatedData,
		CD:       msg.CheckingDisabled,
		Question: nil,
		Answer:   nil,
	}

	for _, q := range msg.Question {
		resp.Question = append(resp.Question, jsonQuestion{
			Name: q.Name,
			Type: q.Qtype,
		})
	}

	for _, rr := range msg.Answer {
		resp.Answer = append(resp.Answer, packRR(rr))
	}

	for _, rr := range msg.Ns {
		resp.Authority = append(resp.Authority, packRR(rr))
	}

	// Extract "Blocked by:" comment from EDNS0 EDE options and include in Additional
	// section as a meaningful JSON comment field
	if comment := extractCommentFromEDE(msg); comment != "" {
		resp.Comment = comment
	}

	// Add non-OPT records to Additional section
	for _, rr := range msg.Extra {
		if _, ok := rr.(*dns.OPT); ok {
			continue // Skip OPT records
		}
		resp.Additional = append(resp.Additional, packRR(rr))
	}

	return resp
}

type doHResponseWriter struct {
	msg        *dns.Msg
	remoteAddr net.Addr
}

func NewDoHResponseWriter(clientIP string) (*doHResponseWriter, error) {
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil, errors.Newf("failed to parse: %s", clientIP)
	}

	return &doHResponseWriter{
		msg:        &dns.Msg{},
		remoteAddr: &net.TCPAddr{IP: ip, Port: 0},
	}, nil
}

func (w *doHResponseWriter) Write(b []byte) (int, error) {
	// doHResponseWriter only supports WriteMsg; Write is unused by miekg/dns server ServeDNS
	// when responses are sent via WriteMsg. We return len(b) to satisfy io.Writer without unpacking.
	return len(b), nil
}

func (w *doHResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.IPv4zero,
		Port: 0,
	}
}

func (w *doHResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *doHResponseWriter) WriteMsg(m *dns.Msg) error {
	w.msg = m
	return nil
}

func (w *doHResponseWriter) TsigStatus() error {
	return nil
}

func (w *doHResponseWriter) TsigTimersOnly(bool) {

}

func (w *doHResponseWriter) Hijack() {

}

func (w *doHResponseWriter) Close() error {
	return nil
}
