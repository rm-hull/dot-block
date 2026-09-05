package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/miekg/dns"
	"github.com/rm-hull/dot-block/internal/config"
	"github.com/rm-hull/dot-block/internal/geoblock"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/rm-hull/dot-block/internal/limiter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type stubGeoIpLookup struct {
	valid   bool
	geoData *geoblock.GeoData
	err     error
}

func (s *stubGeoIpLookup) Reopen() error { return nil }
func (s *stubGeoIpLookup) GetAll(ipAddr string) (*geoblock.GeoData, error) {
	return s.geoData, s.err
}
func (s *stubGeoIpLookup) IsValid(ipAddr string) bool { return s.valid }

func TestAsnLookupHandlerReturnsNotFoundForEmptyGeoData(t *testing.T) {
	gin.SetMode(gin.TestMode)

	lookup := &stubGeoIpLookup{
		valid:   true,
		geoData: nil,
	}
	handler := asnLookupHandler(lookup)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/asn/8.8.8.8", nil)
	ctx.Params = gin.Params{{Key: "ip", Value: "8.8.8.8"}}

	handler(ctx)

	require.Equal(t, http.StatusNotFound, w.Code)
}

func TestDoH_CORS_OptionsPreflight(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rl, err := limiter.New(&config.RateLimitConfig{Enabled: false}, nil)
	require.NoError(t, err)

	dohHandler := handlers.NewDoHHandler(dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		_ = w.WriteMsg(resp)
	}))

	r := gin.New()
	NewPublicGroup(r, "localhost", rl, dohHandler, dohHandler)

	// Test OPTIONS preflight request
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/dns-query", nil)
	req.Header.Set("Origin", "https://my-domain.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	req.Header.Set("Access-Control-Request-Headers", "Accept")
	req.Host = "localhost"
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "GET")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "OPTIONS")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Accept")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Content-Type")
}

func TestDoH_CORS_GetRequestWithOrigin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rl, err := limiter.New(&config.RateLimitConfig{Enabled: false}, nil)
	require.NoError(t, err)

	dohHandler := handlers.NewDoHHandler(dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		resp := new(dns.Msg)
		resp.SetReply(r)
		rr, _ := dns.NewRR("example.com.\t300\tIN\tA\t93.184.216.34")
		resp.Answer = []dns.RR{rr}
		_ = w.WriteMsg(resp)
	}))

	r := gin.New()
	NewPublicGroup(r, "localhost", rl, dohHandler, dohHandler)

	// Test GET request with Origin header (cross-origin)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/dns-query?name=example.com&type=A", nil)
	req.Header.Set("Accept", "application/dns-json")
	req.Header.Set("Origin", "https://my-domain.com")
	req.Host = "localhost"
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "Content-Length", w.Header().Get("Access-Control-Expose-Headers"))
}
