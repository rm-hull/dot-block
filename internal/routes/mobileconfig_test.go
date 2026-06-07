package routes

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/mobileconfig"
	"github.com/stretchr/testify/assert"
	"howett.net/plist"
)

func TestHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/.mobileconfig", NewMobileconfigHandler("localhost"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.mobileconfig", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-apple-aspen-config", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "dot-block.mobileconfig")

	var profile mobileconfig.Profile
	err := plist.NewDecoder(strings.NewReader(w.Body.String())).Decode(&profile)
	assert.NoError(t, err)

	assert.Equal(t, "localhost", profile.PayloadContent[0].DNSSettings.ServerName)
	assert.NotEmpty(t, profile.PayloadContent[0].DNSSettings.ServerAddresses, "ServerAddresses should not be empty")
}
