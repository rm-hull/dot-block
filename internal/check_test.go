package internal

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/rm-hull/dot-block/internal/blocklist"
	"github.com/rm-hull/dot-block/internal/http/handlers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckHandler(t *testing.T) {
	type payload struct {
		Allowed []string          `json:"allowed"`
		Blocked map[string]string `json:"blocked"`
	}

	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a small blocklist for testing
	blockList := blocklist.NewBlockList("test", "@every 19h", "http://dummy.url", 0.0001, logger)
	blockList.Load([]string{"blocked.com", "ads.net"})

	handler := handlers.NewBlocklistHandler([]*blocklist.BlockList{blockList}, logger)

	tests := []struct {
		name           string
		contentType    string
		body           []byte
		expectedStatus int
		expectedBody   *payload
	}{
		{
			name:        "Plain text - mixed",
			contentType: "text/plain",
			body: []byte(`google.com
blocked.com

allowed.org
`),
			expectedStatus: http.StatusOK,
			expectedBody: &payload{
				Allowed: []string{"google.com", "allowed.org"},
				Blocked: map[string]string{"blocked.com": "test"},
			},
		},
		{
			name:           "JSON array - mixed",
			contentType:    "application/json",
			body:           []byte(`["google.com", "blocked.com", "ads.net", "allowed.org"]`),
			expectedStatus: http.StatusOK,
			expectedBody: &payload{
				Allowed: []string{"google.com", "allowed.org"},
				Blocked: map[string]string{"blocked.com": "test", "ads.net": "test"},
			},
		},
		{
			name:        "Plain text - all allowed",
			contentType: "text/plain",
			body: []byte(`google.com
allowed.org`),
			expectedStatus: http.StatusOK,
			expectedBody: &payload{
				Allowed: []string{"google.com", "allowed.org"},
				Blocked: map[string]string{},
			},
		},
		{
			name:        "Plain text - all blocked",
			contentType: "text/plain",
			body: []byte(`blocked.com
ads.net`),
			expectedStatus: http.StatusOK,
			expectedBody: &payload{
				Allowed: []string{},
				Blocked: map[string]string{"blocked.com": "test", "ads.net": "test"},
			},
		},
		{
			name:           "JSON array - empty",
			contentType:    "application/json",
			body:           []byte(`[]`),
			expectedStatus: http.StatusOK,
			expectedBody: &payload{
				Allowed: []string{},
				Blocked: map[string]string{},
			},
		},
		{
			name:           "JSON array - invalid",
			contentType:    "application/json",
			body:           []byte(`["invalid" json`),
			expectedStatus: http.StatusBadRequest,
			expectedBody:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			_, r := gin.CreateTestContext(w)

			r.POST("/check", handler.Check)

			req, _ := http.NewRequest("POST", "/check", bytes.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			r.ServeHTTP(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)

			if tt.expectedBody != nil {
				var response payload
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBody.Allowed, response.Allowed)
				assert.Equal(t, tt.expectedBody.Blocked, response.Blocked)
			}
		})
	}
}
