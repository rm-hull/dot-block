package handlers

import (
	"fmt"
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

func TestParseDuration(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    time.Duration
		wantErr bool
	}{
		// Go duration format
		{"Go duration - 1h", "1h", time.Hour, false},
		{"Go duration - 30m", "30m", 30 * time.Minute, false},
		{"Go duration - 90s", "90s", 90 * time.Second, false},
		{"Go duration - 1h30m", "1h30m", 90 * time.Minute, false},
		{"Go duration - 500ms", "500ms", 500 * time.Millisecond, false},

		// ISO 8601 duration format
		{"ISO8601 - PT1H", "PT1H", time.Hour, false},
		{"ISO8601 - PT30M", "PT30M", 30 * time.Minute, false},
		{"ISO8601 - PT90S", "PT90S", 90 * time.Second, false},
		{"ISO8601 - PT1H30M", "PT1H30M", 90 * time.Minute, false},
		{"ISO8601 - P1D", "P1D", 24 * time.Hour, false},
		{"ISO8601 - P1DT2H", "P1DT2H", 26 * time.Hour, false},
		// Note: iso8601duration library does not support fractional hours (PT0.5H returns 0s)

		// Invalid
		{"Invalid - empty", "", 0, true},
		{"Invalid - garbage", "not-a-duration", 0, true},
		// Note: bare "P" is accepted by the library as 0 duration (not an error)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDuration(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBlocklistHandler_Disable_ISO8601(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "http://example.com/list.txt", 0.001, logger)
	updater := blocklist.NewUpdater([]*blocklist.BlockList{bl}, 1*time.Minute)
	h := NewBlocklistHandler(updater, logger)

	tests := []struct {
		name        string
		duration    string
		expectCode  int
	}{
		{"ISO8601 PT1H", "PT1H", http.StatusOK},
		{"ISO8601 PT30M", "PT30M", http.StatusOK},
		{"ISO8601 P1D", "P1D", http.StatusOK},
		{"Go duration 1h", "1h", http.StatusOK},
		{"Go duration 30m", "30m", http.StatusOK},
		{"Invalid", "not-a-duration", http.StatusBadRequest},
		{"Zero", "0", http.StatusBadRequest},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Re-enable before each test
			bl.Reenable()

			w := httptest.NewRecorder()
			payload := fmt.Sprintf(`{"name": "test", "duration": "%s"}`, tt.duration)
			c, _ := gin.CreateTestContext(w)
			c.Request = httptest.NewRequest("POST", "/disable", strings.NewReader(payload))
			c.Request.Header.Set("Content-Type", "application/json")

			h.Disable(c)

			assert.Equal(t, tt.expectCode, w.Code)
		})
	}
}
