package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTypeFromString(t *testing.T) {
	cases := []struct {
		input string
		want  uint16
		ok    bool
	}{
		{"A", dns.TypeA, true},
		{"AAAA", dns.TypeAAAA, true},
		{"NS", dns.TypeNS, true},
		{"CNAME", dns.TypeCNAME, true},
		{"PTR", dns.TypePTR, true},
		{"MX", dns.TypeMX, true},
		{"TXT", dns.TypeTXT, true},
		{"SOA", dns.TypeSOA, true},
		{"SRV", dns.TypeSRV, true},
		{"ANY", dns.TypeANY, true},
		{"a", dns.TypeA, true}, // case insensitive
		{"unknown", 0, false},
	}

	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			got, ok := parseTypeFromString(tc.input)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.ok, ok)
		})
	}
}

func TestBuildJSONQuery(t *testing.T) {
	t.Run("valid query", func(t *testing.T) {
		raw, err := buildJSONQuery("example.com.", "A")
		require.NoError(t, err)

		msg := new(dns.Msg)
		require.NoError(t, msg.Unpack(raw))
		require.Len(t, msg.Question, 1)
		assert.Equal(t, "example.com.", msg.Question[0].Name)
		assert.Equal(t, dns.TypeA, msg.Question[0].Qtype)
	})

	t.Run("default type when omitted", func(t *testing.T) {
		raw, err := buildJSONQuery("example.com.", "")
		require.NoError(t, err)

		msg := new(dns.Msg)
		require.NoError(t, msg.Unpack(raw))
		require.Len(t, msg.Question, 1)
		assert.Equal(t, dns.TypeA, msg.Question[0].Qtype)
	})

	t.Run("missing name", func(t *testing.T) {
		_, err := buildJSONQuery("", "A")
		assert.Error(t, err)
	})

	t.Run("invalid type", func(t *testing.T) {
		_, err := buildJSONQuery("example.com.", "NOPE")
		assert.Error(t, err)
	})
}

func TestToJSONResponse(t *testing.T) {
	// Build a mock DNS response
	resp := new(dns.Msg)
	resp.SetReply(new(dns.Msg))

	// Create a question
	resp.Question = []dns.Question{
		{
			Name:   "example.com.",
			Qtype:  dns.TypeA,
			Qclass: dns.ClassINET,
		},
	}

	// Add an answer (A record)
	rr, err := dns.NewRR("example.com.		300	IN	A	93.184.216.34")
	require.NoError(t, err)
	resp.Answer = []dns.RR{rr}
	resp.RecursionAvailable = true
	resp.RecursionDesired = true

	jsonResp := toJsonResponse(resp)

	assert.Equal(t, 0, jsonResp.Status) // NOERROR
	assert.NotEmpty(t, jsonResp.Question)
	assert.Equal(t, "example.com.", jsonResp.Question[0].Name)
	assert.Equal(t, uint16(dns.TypeA), jsonResp.Question[0].Type)
	require.Len(t, jsonResp.Answer, 1)
	assert.Equal(t, "example.com.", jsonResp.Answer[0].Name)
	assert.Equal(t, uint16(dns.TypeA), jsonResp.Answer[0].Type)
	assert.Equal(t, 300, jsonResp.Answer[0].TTL)
	assert.Equal(t, "93.184.216.34", jsonResp.Answer[0].Data[0])
}

func TestDoHHandler_JSONRequest(t *testing.T) {
	mockHandler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		// Simple A record response
		msg := new(dns.Msg)
		msg.SetReply(r)

		rr, err := dns.NewRR("example.com.		300	IN	A	93.184.216.34")
		if err != nil {
			panic(err)
		}
		msg.Answer = []dns.RR{rr}
		_ = w.WriteMsg(msg)
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dns-query", NewDoHHandler(mockHandler))

	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	req.Header.Set("Accept", "application/dns-json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var result dnsJSONResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &result))
	assert.Equal(t, 0, result.Status) // NOERROR
	require.Len(t, result.Question, 1)
	assert.Equal(t, "example.com.", result.Question[0].Name)
	assert.Equal(t, uint16(dns.TypeA), result.Question[0].Type)
	require.Len(t, result.Answer, 1)
	assert.Equal(t, "example.com.", result.Answer[0].Name)
	assert.Equal(t, uint16(dns.TypeA), result.Answer[0].Type)
	assert.Equal(t, "93.184.216.34", result.Answer[0].Data[0])
}
