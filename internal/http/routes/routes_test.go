package routes

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/geoblock"
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
