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
	"github.com/rm-hull/dot-block/internal/routes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	// Use a small blocklist for testing
	blockList := blocklist.NewBlockList([]string{"blocked.com", "ads.net"}, 0.0001, logger)
	updater := blocklist.NewBlocklistUpdater(blockList, []string{})

	handler := routes.NewBlocklistHandler(updater)

	tests := []struct {
		name           string
		contentType    string
		body           []byte
		expectedStatus int
		expectedBody   map[string][]string
	}{
		{
			name:        "Plain text - mixed",
			contentType: "text/plain",
			body:        []byte(`google.com
blocked.com

allowed.org
`),
			expectedStatus: http.StatusOK,
			expectedBody: map[string][]string{
				"allowed": {"google.com", "allowed.org"},
				"blocked": {"blocked.com"},
			},
		},
		{
			name:        "JSON array - mixed",
			contentType: "application/json",
			body:        []byte(`["google.com", "blocked.com", "ads.net", "allowed.org"]`),
			expectedStatus: http.StatusOK,
			expectedBody: map[string][]string{
				"allowed": {"google.com", "allowed.org"},
				"blocked": {"blocked.com", "ads.net"},
			},
		},
		{
			name:        "Plain text - all allowed",
			contentType: "text/plain",
			body:        []byte(`google.com
allowed.org`),
			expectedStatus: http.StatusOK,
			expectedBody: map[string][]string{
				"allowed": {"google.com", "allowed.org"},
				"blocked": {},
			},
		},
		{
			name:        "Plain text - all blocked",
			contentType: "text/plain",
			body:        []byte(`blocked.com
ads.net`),
			expectedStatus: http.StatusOK,
			expectedBody: map[string][]string{
				"allowed": {},
				"blocked": {"blocked.com", "ads.net"},
			},
		},
		{
			name:        "JSON array - empty",
			contentType: "application/json",
			body:        []byte(`[]`),
			expectedStatus: http.StatusOK,
			expectedBody: map[string][]string{
				"allowed": {},
				"blocked": {},
			},
		},
		{
			name:        "JSON array - invalid",
			contentType: "application/json",
			body:        []byte(`["invalid" json`),
			expectedStatus: http.StatusBadRequest,
			expectedBody: nil,
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
				var response map[string][]string
				err := json.Unmarshal(w.Body.Bytes(), &response)
				require.NoError(t, err)
				assert.Equal(t, tt.expectedBody["allowed"], response["allowed"])
				assert.Equal(t, tt.expectedBody["blocked"], response["blocked"])
			}
		})
	}
}
