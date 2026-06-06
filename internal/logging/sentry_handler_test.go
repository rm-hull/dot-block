package logging

import (
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateSentryEvent(t *testing.T) {
	tests := []struct {
		name          string
		level         slog.Level
		message       string
		attrs         []slog.Attr
		handlerAttrs  []slog.Attr
		wantLevel     sentry.Level
		wantMsg       string
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
			wantLevel:    sentry.LevelError,
			wantMsg:      "something went wrong",
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
			wantLevel:     sentry.LevelError,
			wantMsg:       "db failure",
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
			wantLevel:     sentry.LevelError,
			wantMsg:       "slow request",
			wantExtraKeys: []string{"latency"},
			checkDuration: true,
		},
		{
			name:         "Level above Error",
			level:        slog.Level(100), // Simulate something higher than LevelError (which is 8)
			message:      "critical failure",
			attrs:        nil,
			handlerAttrs: nil,
			wantLevel:    sentry.LevelFatal,
			wantMsg:      "critical failure",
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
			wantLevel:     sentry.LevelError,
			wantMsg:       "system failure",
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
			event := h.createSentryEvent(r)

			assert.Equal(t, tt.wantLevel, event.Level)
			assert.Equal(t, tt.wantMsg, event.Message)

			extra, ok := event.Contexts["extra"]
			require.True(t, ok, "event.Contexts[\"extra\"] is missing")

			for _, key := range tt.wantExtraKeys {
				assert.Contains(t, extra, key)
			}

			if tt.wantException {
				assert.NotEmpty(t, event.Exception, "expected exception to be set")
			}

			if tt.checkDuration {
				val, ok := extra["latency"]
				require.True(t, ok, "latency key missing from extra")
				assert.Equal(t, "500ms", val)
			}
		})
	}
}
