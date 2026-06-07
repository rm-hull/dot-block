package logging

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceAttr_Source(t *testing.T) {
	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{
		AddSource:   true,
		ReplaceAttr: ReplaceAttr,
	})
	logger := slog.New(handler)

	logger.Info("test message")

	output := buf.String()
	t.Logf("Output: %s", output)

	assert.Contains(t, output, `"level":"INFO"`)
	assert.Contains(t, output, `"msg":"test message"`)
	assert.Contains(t, output, `"caller":"internal/logging/slog_helpers_test.go:19"`)
	assert.NotContains(t, output, `"source"`)
}
