package handlers

import (
	"encoding/json"
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
	return NewBlocklistHandler([]*blocklist.BlockList{}, logger), logger
}

func TestBlocklistHandler_Status(t *testing.T) {
	h, _ := setupHandler(t)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	h.Status("")(c)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBlocklistHandler_Disable_Single(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "@every 19h", "http://example.com/list.txt", 0.001, logger)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl}, logger)

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
	bl := blocklist.NewBlockList("test", "@every 19h", "http://example.com/list.txt", 0.001, logger)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl}, logger)

	w := httptest.NewRecorder()
	payload := `{"duration": "30m"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/disable", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Disable(c)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestBlocklistHandler_Reenable_All(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "@every 19h", "http://example.com/list.txt", 0.001, logger)
	// Pre-disable it
	bl.Disable(time.Hour)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl}, logger)

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/reenable", strings.NewReader("{}"))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Reenable(c)

	assert.Equal(t, http.StatusOK, w.Code)
	statusBody := w.Body.String()
	assert.NotContains(t, statusBody, "disabled_until")
}

func TestBlocklistHandler_Reenable_Single(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl1 := blocklist.NewBlockList("test1", "@every 19h", "http://example.com/list1.txt", 0.001, logger)
	bl2 := blocklist.NewBlockList("test2", "@every 19h", "http://example.com/list2.txt", 0.001, logger)
	// Pre-disable both blocklists
	bl1.Disable(time.Hour)
	bl2.Disable(time.Hour)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl1, bl2}, logger)

	w := httptest.NewRecorder()
	// Re-enable only the blocklist named "test1"
	payload := `{"name": "test1"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/reenable", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Reenable(c)

	assert.Equal(t, http.StatusOK, w.Code)

	// Parse the response to verify each blocklist's individual status
	var statusPayload StatusPayload
	err := json.Unmarshal(w.Body.Bytes(), &statusPayload)
	assert.NoError(t, err)

	// test1 should be re-enabled (no disabled_until)
	assert.Equal(t, statusPayload.Blocklists[0].Name, "test1")
	assert.Nil(t, statusPayload.Blocklists[0].DisabledUntil,
		"test1 should have been re-enabled")

	// test2 should remain disabled
	assert.Equal(t, statusPayload.Blocklists[1].Name, "test2")
	assert.NotNil(t, statusPayload.Blocklists[1].DisabledUntil,
		"test2 should still be disabled")
}

func TestBlocklistHandler_Reload(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	bl := blocklist.NewBlockList("test", "@every 19h", "http://localhost:9999/does-not-exist", 0.001, logger)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl}, logger)

	w := httptest.NewRecorder()

	payload := `{"name": "test"}`
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest("POST", "/reload", strings.NewReader(payload))
	c.Request.Header.Set("Content-Type", "application/json")

	h.Reload(c)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	var statusPayload StatusPayload
	err := json.Unmarshal(w.Body.Bytes(), &statusPayload)
	assert.NoError(t, err)

	assert.Equal(t, statusPayload.Message, "Blocklist reloaded")
	assert.Contains(t, statusPayload.Errors[0], "failed to download blocklist")
}

func TestBlocklistHandler_CheckInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)
	logger := slog.Default()
	h := NewBlocklistHandler([]*blocklist.BlockList{}, logger)

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
	h := NewBlocklistHandler([]*blocklist.BlockList{}, logger)

	// Create a JSON array with 101 items (limit is 100)
	var sb strings.Builder
	sb.WriteString("[")
	for i := range 101 {
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
	bl := blocklist.NewBlockList("test", "@every 19h", "http://example.com/list.txt", 0.001, logger)
	h := NewBlocklistHandler([]*blocklist.BlockList{bl}, logger)

	tests := []struct {
		name       string
		duration   string
		expectCode int
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
