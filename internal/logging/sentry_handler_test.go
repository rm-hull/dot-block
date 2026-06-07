package logging

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExtractAttributes(t *testing.T) {
	tests := []struct {
		name          string
		level         slog.Level
		message       string
		attrs         []slog.Attr
		handlerAttrs  []slog.Attr
		wantExtraKeys []string
		wantException bool
		checkDuration bool
	}{
		{
			name:         "Simple error",
			level:        slog.LevelError,
			message:      "something went wrong",
			attrs:        nil,
			handlerAttrs: nil,
		},
		{
			name:    "Error with exception",
			level:   slog.LevelError,
			message: "db failure",
			attrs: []slog.Attr{
				slog.String("category", "database"),
				slog.Any("error", errors.New("connection timeout")),
			},
			handlerAttrs:  nil,
			wantExtraKeys: []string{"category", "error"},
			wantException: true,
		},
		{
			name:    "Error with duration",
			level:   slog.LevelError,
			message: "slow request",
			attrs: []slog.Attr{
				slog.Duration("latency", 500*time.Millisecond),
			},
			handlerAttrs:  nil,
			wantExtraKeys: []string{"latency"},
			checkDuration: true,
		},
		{
			name:         "Level above Error",
			level:        slog.Level(100),
			message:      "critical failure",
			attrs:        nil,
			handlerAttrs: nil,
		},
		{
			name:    "Attributes from handler",
			level:   slog.LevelError,
			message: "system failure",
			attrs:   []slog.Attr{slog.String("local", "attr")},
			handlerAttrs: []slog.Attr{
				slog.String("global", "attr"),
				slog.Int("version", 1),
			},
			wantExtraKeys: []string{"local", "global", "version"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a slog.Record
			r := slog.NewRecord(time.Now(), tt.level, tt.message, 0)
			r.AddAttrs(tt.attrs...)

			// Create a SentryHandler with the specified attributes
			h := &SentryHandler{attrs: tt.handlerAttrs}
			extra := h.extractAttributes(r)

			for _, key := range tt.wantExtraKeys {
				assert.Contains(t, extra, key)
			}

			if tt.wantException {
				val, ok := extra["error"]
				require.True(t, ok, "error key missing from extra")
				assert.Implements(t, (*error)(nil), val)
			}

			if tt.checkDuration {
				val, ok := extra["latency"]
				require.True(t, ok, "latency key missing from extra")
				assert.Equal(t, "500ms", val)
			}
		})
	}
}
