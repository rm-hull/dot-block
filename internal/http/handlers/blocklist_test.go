package handlers

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/stretchr/testify/assert"
)

func setupHandler(t *testing.T) (*BlocklistHandler, *slog.Logger) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	updater := blocklist.NewUpdater([]*blocklist.BlockList{}, 1*time.Minute)
	return NewBlocklistHandler(updater, logger), logger
}

func TestBlocklistHandler_Status(t *testing.T) {
	h, _ := setupHandler(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.Status(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBlocklistHandler_Disable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	payload := `{"name": "test", "duration": "1h"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/disable", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Disable(c)

	assert.Equal(t, http.StatusOK, w.Code)
	statusBody := w.Body.String()
	assert.Contains(t, statusBody, "disabled_until")
}

func TestBlocklistHandler_Disable_All(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	payload := `{"duration": "30m"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/disable", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Disable(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBlocklistHandler_Reenable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	// Pre-disable it
	bl.Disable(time.Hour)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/reenable", strings.NewReader("{}"))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Reenable(c)

	assert.Equal(t, http.StatusOK, w.Code)
	statusBody := w.Body.String()
	assert.NotContains(t, statusBody, "disabled_until")
}

func TestBlocklistHandler_Reload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://localhost:9999/does-not-exist", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h.Reload(c)

	assert.Equal(t, http.StatusAccepted, w.Code)
	assert.NotEmpty(t, w.Body.String())
}

func TestBlocklistHandler_CheckInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	updater := blocklist.NewUpdater([]*blocklist.BlockList{}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/check", strings.NewReader(`not json`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Check(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid JSON")
}

func TestBlocklistHandler_CheckTooManyDomains(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	updater := blocklist.NewUpdater([]*blocklist.BlockList{}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	// Create a JSON array with 101 items (limit is 100)
	var sb strings.Builder
	sb.WriteString("[")
	for i := 0; i < 101; i++ {
		if i > 0 {
			sb.WriteString(",")
		}
		sb.WriteString(`"example.com"`)
	}
	sb.WriteString("]")
	payload := sb.String()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/check", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Check(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Too many domains")
}

func TestBlocklistHandler_CheckInvalidDomain(t *testing.T) {
	h, _ := setupHandler(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/check", strings.NewReader(`[""]`))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Check(c)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid domain")
}
