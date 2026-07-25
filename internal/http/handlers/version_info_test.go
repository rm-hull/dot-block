package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionInfoHandler_Info(t *testing.T) {
	gin.SetMode(gin.TestMode)

	startTime := time.Now().Add(-2 * time.Hour)
	handler := NewVersionInfoHandler(startTime)

	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/api/version-info", nil)

	handler.Info(ctx)

	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	assert.NotEmpty(t, resp["app_version"], "app_version should be non-empty")
	assert.NotEmpty(t, resp["go_version"], "go_version should be non-empty")

	uptime, ok := resp["uptime"].(float64)
	require.True(t, ok, "uptime should be a float64")
	assert.GreaterOrEqual(t, uptime, 7200.0, "uptime should be approximately 2 hours (7200 seconds)")
	assert.Less(t, uptime, 7201.0, "uptime should be less than 7201 seconds")
}
