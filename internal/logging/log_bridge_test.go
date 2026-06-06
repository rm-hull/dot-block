package logging

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testHandler struct {
	lastRecord slog.Record
}

func (h *testHandler) Enabled(ctx context.Context, level slog.Level) bool { return true }
func (h *testHandler) Handle(ctx context.Context, r slog.Record) error {
	h.lastRecord = r
	return nil
}
func (h *testHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *testHandler) WithGroup(name string) slog.Handler       { return h }

func TestBridgeStandardLog_SourceReporting(t *testing.T) {
	handler := &testHandler{}
	logger := slog.New(handler)

	writer := &slogWriter{logger: logger}
	writer.Write([]byte("test message\n"))

	record := handler.lastRecord
	assert.Equal(t, "test message", record.Message)

	var foundFile bool
	record.Attrs(func(a slog.Attr) bool {
		if a.Key == "source_file" {
			foundFile = true
		}
		return true
	})

	assert.True(t, foundFile, "source_file attribute missing")
}
