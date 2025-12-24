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
	handler, _ := NewHandler("dot.destructuring-bind.org")
	r.GET("/.mobileconfig", handler)

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/.mobileconfig", nil)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/x-apple-aspen-config", w.Header().Get("Content-Type"))
	assert.Contains(t, w.Header().Get("Content-Disposition"), "dot-block.mobileconfig")

	body := w.Body.String()
	assert.Contains(t, body, "<key>ServerName</key>")
	assert.Contains(t, body, "<string>dot.destructuring-bind.org</string>")
	assert.Contains(t, body, "<key>ServerAddresses</key>")
	// We know it resolves to 192.241.203.173 currently, but let's just check it's not empty
	assert.Contains(t, body, "<array>")
	assert.Contains(t, body, "</array>")
}
