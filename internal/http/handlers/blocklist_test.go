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

func TestBlocklistHandler_Status(t *testing.T) {
	gin.SetMode(gin.TestMode)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{})
	h := NewBlocklistHandler(updater, nil)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	h.Status(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBlocklistHandler_Disable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl})
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	payload := `{"name": "test", "duration": "1h"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/disable", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Disable(c)

	assert.Equal(t, http.StatusOK, w.Code)
	// Verify status reflects disabled state
	statusBody := w.Body.String()
	assert.Contains(t, statusBody, "disabled_until")
}

func TestBlocklistHandler_Disable_All(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl})
	h := NewBlocklistHandler(updater, logger)

	w := httptest.NewRecorder()
	// Empty name should disable all
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
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl})
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
