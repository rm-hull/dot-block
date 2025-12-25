package mobileconfig

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/.mobileconfig", NewHandler("dot.destructuring-bind.org"))

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.mobileconfig", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-apple-aspen-config", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "dot-block.mobileconfig")

var profile Profile
	err := plist.NewDecoder(w.Body).Decode(&profile)
	assert.NoError(t, err)

	assert.Equal(t, "dot.destructuring-bind.org", profile.PayloadContent[0].DNSSettings.ServerName)
	assert.NotEmpty(t, profile.PayloadContent[0].DNSSettings.ServerAddresses, "ServerAddresses should not be empty")
}
